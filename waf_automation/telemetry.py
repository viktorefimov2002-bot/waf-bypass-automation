from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl


VERDICT_NAMES = {
    0: "Allow",
    1: "ShadowWouldBlock",
    2: "Block",
    3: "Monitor",
    4: "Audit",
}


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_sequence(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(stripped)
            except (ValueError, SyntaxError, json.JSONDecodeError):
                continue
            if isinstance(parsed, (list, tuple)):
                return list(parsed)
        return [value]
    return [value]


def _load_security_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, list):
        rows = parsed
    elif isinstance(parsed, dict):
        rows = None
        for key in ("rows", "data", "result"):
            candidate = parsed.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        if rows is None:
            rows = [parsed]
    else:
        rows = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid security-log JSON at {path}:{line_number}: {exc}") from exc

    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("Security-log input must contain JSON objects")
    return list(rows)


def _normalize_verdict(value: Any) -> str | None:
    numeric = _int_or_none(value)
    if numeric in VERDICT_NAMES:
        return VERDICT_NAMES[numeric]
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    aliases = {name.lower(): name for name in VERDICT_NAMES.values()}
    return aliases.get(text.lower(), text)


def _normalize_matched_rules(row: dict[str, Any]) -> list[dict[str, Any]]:
    raw_details = _coerce_sequence(row.get("rule_details"))
    rules: list[dict[str, Any]] = []
    for item in raw_details:
        if isinstance(item, (list, tuple)) and item:
            rule_id = str(item[0]) if item[0] is not None else None
            score = _int_or_none(item[1]) if len(item) > 1 else None
            vendor = str(item[2]) if len(item) > 2 and item[2] is not None else None
            if rule_id:
                rules.append({"rule_id": rule_id, "score": score, "vendor": vendor})

    if rules:
        return rules

    rule_numbers = _coerce_sequence(row.get("rule_numbers"))
    scores = _coerce_sequence(row.get("scores"))
    vendors = _coerce_sequence(row.get("vendors"))
    for index, rule_number in enumerate(rule_numbers):
        if rule_number is None:
            continue
        rules.append({
            "rule_id": str(rule_number),
            "score": _int_or_none(scores[index]) if index < len(scores) else None,
            "vendor": str(vendors[index]) if index < len(vendors) and vendors[index] is not None else None,
        })
    return rules


def normalize_security_row(row: dict[str, Any]) -> dict[str, Any]:
    test_id = row.get("test_id")
    decision_source = [str(value) for value in _coerce_sequence(row.get("decision_source"))]
    matched_rules = _normalize_matched_rules(row)
    return {
        "test_id": str(test_id).strip() if test_id is not None else None,
        "waf_request_id": row.get("x_waf_request_id") or row.get("waf_request_id") or row.get("request_id"),
        "request_host": row.get("request_host"),
        "request_uri_redacted": row.get("request_uri_redacted"),
        "method": row.get("method"),
        "path_template": row.get("path_template"),
        "content_type_detected": row.get("content_type_detected"),
        "client_status": _int_or_none(row.get("client_status")),
        "origin_status": _int_or_none(row.get("origin_status")),
        "runtime_anomaly_threshold": _int_or_none(row.get("runtime_anomaly_threshold")),
        "anomaly_score": _int_or_none(row.get("anomaly_score")),
        "runtime_blocking_mode": row.get("runtime_blocking_mode"),
        "phase_terminated": row.get("phase_terminated"),
        "verdict": _normalize_verdict(row.get("verdict")),
        "decision_source": decision_source,
        "matched_rules": matched_rules,
        "raw_rule_details": row.get("rule_details"),
    }


def correlate_logs(replay_path: Path, security_log_path: Path, output_path: Path) -> dict[str, Any]:
    replay_records = read_jsonl(replay_path)
    raw_rows = _load_security_rows(security_log_path)
    security_rows = [normalize_security_row(row) for row in raw_rows]

    by_test_id: dict[str, list[dict[str, Any]]] = {}
    for row in security_rows:
        test_id = row.get("test_id")
        if test_id:
            by_test_id.setdefault(str(test_id), []).append(row)

    replay_test_ids = {str(record["test_id"]) for record in replay_records if record.get("test_id")}
    observations: list[dict[str, Any]] = []
    matched = 0
    missing = 0
    multiple = 0
    missing_replay_id = 0

    for record in replay_records:
        observation = dict(record)
        test_id = record.get("test_id")
        if not test_id:
            status = "MISSING_REPLAY_TEST_ID"
            matches: list[dict[str, Any]] = []
            missing_replay_id += 1
        else:
            matches = by_test_id.get(str(test_id), [])
            if not matches:
                status = "LOG_NOT_FOUND"
                missing += 1
            elif len(matches) == 1:
                status = "MATCHED"
                matched += 1
            else:
                status = "MULTIPLE_LOG_MATCHES"
                multiple += 1

        observation["correlation_status"] = status
        observation["security_log_match_count"] = len(matches)
        observation["security_log"] = matches[0] if len(matches) == 1 else None
        if len(matches) > 1:
            observation["security_log_matches"] = matches
        observations.append(observation)

    write_jsonl(output_path, observations)
    orphan_rows = sum(1 for row in security_rows if row.get("test_id") and str(row["test_id"]) not in replay_test_ids)
    rows_without_test_id = sum(1 for row in security_rows if not row.get("test_id"))
    return {
        "replay_records": len(replay_records),
        "security_log_rows": len(security_rows),
        "matched": matched,
        "log_not_found": missing,
        "multiple_log_matches": multiple,
        "missing_replay_test_id": missing_replay_id,
        "orphan_security_log_rows": orphan_rows,
        "security_log_rows_without_test_id": rows_without_test_id,
        "output": str(output_path),
    }

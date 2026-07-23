from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from openpyxl import Workbook

from .common import read_jsonl, stable_key, write_jsonl
from .recheck import recheck_records


def _fix_status(after: dict[str, Any]) -> str:
    verdict = after.get("final_verdict")
    if verdict == "BLOCKED_BY_WAF":
        return "FIXED"
    if verdict in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}:
        return "STILL_BYPASSED"
    if verdict == "CHECK_ERROR":
        return "ERROR"
    return "NEEDS_REVIEW"


def _load_rule_metadata(coverage_path: Path | None, manifest_path: Path | None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    coverage_by_key: dict[str, dict[str, Any]] = {}
    rules_by_id: dict[str, dict[str, Any]] = {}

    if coverage_path:
        if not coverage_path.exists():
            raise ValueError(f"Coverage file does not exist: {coverage_path}")
        with coverage_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                key = str(row.get("stable_key") or "")
                if key:
                    coverage_by_key[key] = row

    if manifest_path:
        if not manifest_path.exists():
            raise ValueError(f"Manifest file does not exist: {manifest_path}")
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        for rule in document.get("rules", []):
            rules_by_id[str(rule.get("rule_id"))] = rule

    return coverage_by_key, rules_by_id


def validate_fixes(
    before_path: Path,
    output_jsonl: Path,
    output_xlsx: Path,
    *,
    execute: bool,
    allow_host: str | None,
    group_id: int | None,
    limit: int | None,
    timeout: float,
    delay: float,
    coverage_path: Path | None = None,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    coverage_by_key, rules_by_id = _load_rule_metadata(coverage_path, manifest_path)

    replay_path = output_jsonl.with_suffix(".replayed.jsonl")
    recheck_records(
        before_path,
        replay_path,
        group_id=group_id,
        execute=execute,
        allow_host=allow_host,
        limit=limit,
        timeout=timeout,
        delay=delay,
        only_confirmed_bypasses=True,
    )

    before = {
        stable_key(record): record
        for record in read_jsonl(before_path)
        if record.get("final_verdict") in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}
    }
    after = {stable_key(record): record for record in read_jsonl(replay_path)}
    rows: list[dict[str, Any]] = []
    for key in sorted(after):
        old = before.get(key, {})
        new = after[key]
        coverage = coverage_by_key.get(key, {})
        rule_id = str(coverage.get("rule_id") or "")
        rule = rules_by_id.get(rule_id, {}) if rule_id else {}
        rule_mapping_status = "MAPPED" if rule_id else "NO_CANDIDATE_RULE"
        if rule_id and manifest_path and not rule:
            rule_mapping_status = "RULE_NOT_FOUND_IN_MANIFEST"

        rows.append({
            "stable_key": key,
            "payload_path": new.get("payload_path"),
            "variant": new.get("variant"),
            "zone": new.get("zone"),
            "encoding": new.get("encoding"),
            "group_id": new.get("group_id"),
            "group_name": new.get("group_name"),
            "status": _fix_status(new),
            "request_blocked_now": new.get("final_verdict") == "BLOCKED_BY_WAF",
            "before_code": old.get("http_code"),
            "before_server": old.get("server_header"),
            "after_code": new.get("http_code"),
            "after_server": new.get("server_header"),
            "after_verdict": new.get("final_verdict"),
            "duration_ms": new.get("duration_ms"),
            "rule_mapping_status": rule_mapping_status,
            "rule_id": int(rule_id) if rule_id.isdigit() else None,
            "rule_primitive": coverage.get("primitive") or rule.get("primitive"),
            "rule_target": coverage.get("rule_target") or rule.get("target"),
            "rule_pattern": rule.get("pattern"),
            "rule_transforms": ",".join(rule.get("transforms", [])) if rule else None,
            "curl": new.get("curl"),
        })

    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_jsonl, rows)
    wb = Workbook()
    ws = wb.active
    ws.title = "Fix validation"
    headers = list(rows[0]) if rows else ["stable_key", "status", "rule_mapping_status"]
    ws.append(headers)
    for row in rows:
        ws.append([row.get(header) for header in headers])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_xlsx)

    counts = Counter(row["status"] for row in rows)
    mapping_counts = Counter(row["rule_mapping_status"] for row in rows)
    return {
        "records": len(rows),
        "fixed": counts["FIXED"],
        "still_bypassed": counts["STILL_BYPASSED"],
        "needs_review": counts["NEEDS_REVIEW"],
        "errors": counts["ERROR"],
        "mapped_to_rule": mapping_counts["MAPPED"],
        "without_candidate_rule": mapping_counts["NO_CANDIDATE_RULE"],
        "missing_manifest_rule": mapping_counts["RULE_NOT_FOUND_IN_MANIFEST"],
        "output_jsonl": str(output_jsonl),
        "output_xlsx": str(output_xlsx),
        "replayed_jsonl": str(replay_path),
        "coverage": str(coverage_path) if coverage_path else None,
        "manifest": str(manifest_path) if manifest_path else None,
    }

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .common import read_jsonl, write_json, write_jsonl


HANDOFF_SCHEMA_VERSION = 1
DEFAULT_DIAGNOSES = {"DETECTION_GAP", "SCORING_GAP"}

WORKSTREAM_BY_DIAGNOSIS = {
    "DETECTION_GAP": "detection-design",
    "SCORING_GAP": "scoring-review",
    "WOULD_BLOCK": "policy-review",
    "BLOCKED": "regression-reference",
    "BLOCKED_OTHER_SOURCE": "decision-source-review",
    "LOG_NOT_FOUND": "telemetry-review",
    "ROUTE_MISMATCH": "routing-review",
    "CHECK_ERROR": "replay-review",
    "NEEDS_REVIEW": "manual-review",
}


def _compact_request(record: dict[str, Any], log: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": record.get("request_host") or log.get("request_host"),
        "method": record.get("request_method") or log.get("method"),
        "path": record.get("request_path"),
        "query": record.get("request_query"),
        "uri_redacted": log.get("request_uri_redacted"),
        "path_template": log.get("path_template"),
        "content_type_detected": log.get("content_type_detected"),
        "curl": record.get("curl"),
    }


def _compact_waf_evidence(log: dict[str, Any]) -> dict[str, Any]:
    return {
        "waf_request_id": log.get("waf_request_id"),
        "client_status": log.get("client_status"),
        "origin_status": log.get("origin_status"),
        "verdict": log.get("verdict"),
        "blocking_mode": log.get("runtime_blocking_mode"),
        "threshold": log.get("runtime_anomaly_threshold"),
        "anomaly_score": log.get("anomaly_score"),
        "phase_terminated": log.get("phase_terminated"),
        "decision_source": log.get("decision_source") or [],
        "matched_rules": log.get("matched_rules") or [],
    }


def build_handoff_case(record: dict[str, Any]) -> dict[str, Any]:
    diagnosis = str(record.get("diagnosis") or "NEEDS_REVIEW")
    log = record.get("security_log") or {}
    return {
        "handoff_schema_version": HANDOFF_SCHEMA_VERSION,
        "case_id": record.get("case_id"),
        "test_id": record.get("test_id"),
        "replay_run_id": record.get("replay_run_id"),
        "source": {
            "tool": "waf-bypass-automation",
            "report_file": record.get("report_file"),
            "payload_path": record.get("payload_path"),
            "variant": record.get("variant"),
            "category": record.get("category"),
            "group_id": record.get("group_id"),
            "group_name": record.get("group_name"),
        },
        "case_kind": "attack",
        "expected_outcome": "block",
        "diagnosis": diagnosis,
        "diagnosis_reason": record.get("diagnosis_reason"),
        "recommended_workstream": WORKSTREAM_BY_DIAGNOSIS.get(diagnosis, "manual-review"),
        "payload": {
            "zone": record.get("zone"),
            "encoding": record.get("encoding"),
            "raw": record.get("raw_payload"),
            "normalized": record.get("normalized_payload"),
            "component": record.get("payload_component"),
            "name": record.get("payload_name"),
            "normalization_steps": record.get("normalization_steps") or [],
            "normalization_layers": record.get("normalization_layers") or [],
            "normalization_complete": record.get("normalization_complete"),
            "normalization_stop_reason": record.get("normalization_stop_reason"),
        },
        "request": _compact_request(record, log),
        "replay": {
            "http_code": record.get("http_code"),
            "server_header": record.get("server_header"),
            "route_verdict": record.get("route_verdict"),
            "final_verdict": record.get("final_verdict"),
        },
        "waf_evidence": _compact_waf_evidence(log),
    }


def export_rule_engineering_corpus(
    input_path: Path,
    output_dir: Path,
    diagnoses: Iterable[str] | None = None,
) -> dict[str, Any]:
    records = read_jsonl(input_path)
    selected_diagnoses = {value.strip().upper() for value in (diagnoses or DEFAULT_DIAGNOSES) if value.strip()}
    if not selected_diagnoses:
        selected_diagnoses = set(DEFAULT_DIAGNOSES)

    selected: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    by_category: dict[str, Counter[str]] = defaultdict(Counter)

    for record in records:
        diagnosis = str(record.get("diagnosis") or "").upper()
        if diagnosis not in selected_diagnoses:
            continue
        case = build_handoff_case(record)
        selected.append(case)
        counts[diagnosis] += 1
        category = str((case.get("source") or {}).get("category") or "UNKNOWN")
        by_category[category][diagnosis] += 1

    output_dir.mkdir(parents=True, exist_ok=True)
    all_path = output_dir / "cases.jsonl"
    write_jsonl(all_path, selected)

    files: dict[str, str] = {"all": str(all_path)}
    for diagnosis in sorted(selected_diagnoses):
        diagnosis_records = [case for case in selected if case["diagnosis"] == diagnosis]
        if not diagnosis_records:
            continue
        path = output_dir / f"{diagnosis.lower().replace('_', '-')}.jsonl"
        write_jsonl(path, diagnosis_records)
        files[diagnosis] = str(path)

    manifest = {
        "handoff_schema_version": HANDOFF_SCHEMA_VERSION,
        "source": str(input_path),
        "selected_diagnoses": sorted(selected_diagnoses),
        "records": len(selected),
        "diagnoses": dict(sorted(counts.items())),
        "by_category": {
            category: dict(sorted(category_counts.items()))
            for category, category_counts in sorted(by_category.items())
        },
        "files": files,
        "consumer": "waf-rule-engineering",
        "policy": {
            "automatic_rule_generation": False,
            "detection_gap": "design or extend detection logic and add regression tests",
            "scoring_gap": "review scoring before changing detection patterns",
        },
    }
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, manifest)
    return {**manifest, "manifest": str(manifest_path)}

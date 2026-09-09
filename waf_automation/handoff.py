from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .common import read_jsonl, write_json, write_jsonl


HANDOFF_SCHEMA_VERSION = 3
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


def _compact_gap_analysis(record: dict[str, Any]) -> dict[str, Any] | None:
    analysis = record.get("gap_analysis")
    if not isinstance(analysis, dict):
        return None
    return {
        "cluster_id": analysis.get("cluster_id"),
        "evidence_status": analysis.get("evidence_status"),
        "cluster_flags": analysis.get("cluster_flags") or [],
        "recommended_workstreams": analysis.get("recommended_workstreams") or [],
        "primary_workstream": analysis.get("primary_workstream"),
        "score": analysis.get("score"),
        "threshold": analysis.get("threshold"),
        "matched_rule_ids": analysis.get("matched_rule_ids") or [],
    }


def _compact_payload_classification(record: dict[str, Any]) -> dict[str, Any] | None:
    classification = record.get("payload_classification")
    if not isinstance(classification, dict):
        return None
    return {
        "cluster_schema_version": classification.get("cluster_schema_version"),
        "attack_family": classification.get("attack_family"),
        "attack_family_source": classification.get("attack_family_source"),
        "detected_primitives": classification.get("detected_primitives") or [],
        "primary_primitive": classification.get("primary_primitive"),
        "structural_tags": classification.get("structural_tags") or [],
        "source_cluster_id": classification.get("source_cluster_id"),
        "semantic_cluster_id": classification.get("semantic_cluster_id"),
        "structural_cluster_id": classification.get("structural_cluster_id"),
        "semantic_payload": classification.get("semantic_payload"),
        "structure_signature": classification.get("structure_signature"),
        "techniques": classification.get("techniques") or [],
        "normalization_profile": classification.get("normalization_profile") or [],
        "placement": classification.get("placement"),
        "transport_encoding": classification.get("transport_encoding"),
    }


def build_handoff_case(record: dict[str, Any]) -> dict[str, Any]:
    diagnosis = str(record.get("diagnosis") or "NEEDS_REVIEW")
    log = record.get("security_log") or {}
    gap_analysis = _compact_gap_analysis(record)
    payload_classification = _compact_payload_classification(record)
    recommended_workstream = (
        gap_analysis.get("primary_workstream")
        if gap_analysis and gap_analysis.get("primary_workstream")
        else WORKSTREAM_BY_DIAGNOSIS.get(diagnosis, "manual-review")
    )
    case = {
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
        "recommended_workstream": recommended_workstream,
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
            "remote_ip": record.get("remote_ip"),
            "local_ip": record.get("local_ip"),
            "url_effective": record.get("url_effective"),
        },
        "waf_evidence": _compact_waf_evidence(log),
    }
    if gap_analysis:
        case["gap_analysis"] = gap_analysis
    if payload_classification:
        case["classification"] = payload_classification
    return case


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
    by_family: dict[str, Counter[str]] = defaultdict(Counter)
    by_primitive: dict[str, Counter[str]] = defaultdict(Counter)
    by_workstream: Counter[str] = Counter()
    source_clusters: set[str] = set()
    semantic_clusters: set[str] = set()
    structural_clusters: set[str] = set()

    for record in records:
        diagnosis = str(record.get("diagnosis") or "").upper()
        if diagnosis not in selected_diagnoses:
            continue
        case = build_handoff_case(record)
        selected.append(case)
        counts[diagnosis] += 1
        by_workstream[str(case.get("recommended_workstream") or "manual-review")] += 1
        category = str((case.get("source") or {}).get("category") or "UNKNOWN")
        by_category[category][diagnosis] += 1
        classification = case.get("classification") or {}
        family = str(classification.get("attack_family") or "unknown")
        primitive = str(classification.get("primary_primitive") or "unresolved_primitive")
        by_family[family][diagnosis] += 1
        by_primitive[primitive][diagnosis] += 1
        for key, target in (
            ("source_cluster_id", source_clusters),
            ("semantic_cluster_id", semantic_clusters),
            ("structural_cluster_id", structural_clusters),
        ):
            value = classification.get(key)
            if value:
                target.add(str(value))

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

    def _nested_counts(values: dict[str, Counter[str]]) -> dict[str, dict[str, int]]:
        return {key: dict(sorted(counter.items())) for key, counter in sorted(values.items())}

    manifest = {
        "handoff_schema_version": HANDOFF_SCHEMA_VERSION,
        "source": str(input_path),
        "selected_diagnoses": sorted(selected_diagnoses),
        "records": len(selected),
        "diagnoses": dict(sorted(counts.items())),
        "recommended_workstreams": dict(sorted(by_workstream.items())),
        "source_clusters": len(source_clusters),
        "semantic_clusters": len(semantic_clusters),
        "structural_clusters": len(structural_clusters),
        "by_category": _nested_counts(by_category),
        "by_attack_family": _nested_counts(by_family),
        "by_primary_primitive": _nested_counts(by_primitive),
        "files": files,
        "consumer": "waf-rule-engineering",
        "policy": {
            "automatic_rule_generation": False,
            "automatic_score_increase": False,
            "detection_gap": "design or extend detection logic and add regression tests",
            "scoring_gap": "treat as a preliminary diagnosis; use comparative gap analysis and rule metadata before changing score",
            "gap_analysis": "when present, preserve behavior-based cluster evidence and use its workstream before the coarse diagnosis label",
            "clustering": "source cluster tracks scanner testcase family; semantic/structural clusters, attack family and coarse primitive provide cross-transport grouping for rule engineering",
        },
    }
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, manifest)
    return {**manifest, "manifest": str(manifest_path)}

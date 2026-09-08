from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_json, write_jsonl


POSITIVE_EVIDENCE = {"WEAK_PARTIAL", "PARTIAL", "WOULD_BLOCK", "BLOCKED"}
UNUSABLE_DIAGNOSES = {"CHECK_ERROR", "LOG_NOT_FOUND", "ROUTE_MISMATCH"}


def _score(record: dict[str, Any]) -> int | None:
    value = (record.get("security_log") or {}).get("anomaly_score")
    return value if isinstance(value, int) else None


def _threshold(record: dict[str, Any]) -> int | None:
    value = (record.get("security_log") or {}).get("runtime_anomaly_threshold")
    return value if isinstance(value, int) else None


def _rule_ids(record: dict[str, Any]) -> list[str]:
    rules = (record.get("security_log") or {}).get("matched_rules") or []
    return sorted({str(rule.get("rule_id")) for rule in rules if rule.get("rule_id") is not None})


def evidence_status(record: dict[str, Any]) -> str:
    """Return a conservative behavior class without assuming rule relevance."""
    diagnosis = str(record.get("diagnosis") or "").upper()
    if diagnosis in UNUSABLE_DIAGNOSES:
        return "UNUSABLE"
    if diagnosis == "DETECTION_GAP":
        return "NO_DETECTION"
    if diagnosis == "SCORING_GAP":
        score = _score(record)
        if score is not None and score <= 2:
            return "WEAK_PARTIAL"
        return "PARTIAL"
    if diagnosis == "WOULD_BLOCK":
        return "WOULD_BLOCK"
    if diagnosis == "BLOCKED":
        return "BLOCKED"
    if diagnosis == "BLOCKED_OTHER_SOURCE":
        # A non-rule-engine block is not evidence that the relevant WAF detector
        # recognized the attack primitive.
        return "REVIEW"
    return "REVIEW"


def _cluster_id(payload_path: str) -> str:
    digest = hashlib.sha256(payload_path.encode("utf-8")).hexdigest()[:16]
    return f"wba-gap-{digest}"


def _normalized_payload(record: dict[str, Any]) -> str | None:
    value = record.get("normalized_payload")
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _contrast(
    records: list[dict[str, Any]],
    *,
    fixed_field: str,
    variable_field: str,
) -> list[dict[str, Any]]:
    """Find comparative detection contrasts for semantically equivalent cases.

    A payload_path alone is not sufficient proof that two replay variants expose
    the same value to the WAF. Different targets can introduce parameter names,
    URI prefixes, or extraction artifacts. Therefore a normalization/target
    contrast is emitted only when the compared cases also have the exact same
    normalized_payload.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if evidence_status(record) == "UNUSABLE":
            continue
        payload = _normalized_payload(record)
        if payload is None:
            continue
        fixed = str(record.get(fixed_field) or "UNKNOWN")
        grouped[(fixed, payload)].append(record)

    contrasts: list[dict[str, Any]] = []
    for (fixed_value, payload), group in sorted(grouped.items()):
        variable_values = {str(record.get(variable_field) or "UNKNOWN") for record in group}
        if len(variable_values) < 2:
            continue
        no_detection = sorted({
            str(record.get(variable_field) or "UNKNOWN")
            for record in group
            if evidence_status(record) == "NO_DETECTION"
        })
        positive = sorted({
            str(record.get(variable_field) or "UNKNOWN")
            for record in group
            if evidence_status(record) in POSITIVE_EVIDENCE
        })
        if no_detection and positive:
            contrasts.append({
                fixed_field: fixed_value,
                "normalized_payload": payload,
                f"{variable_field}_no_detection": no_detection,
                f"{variable_field}_positive_detection": positive,
            })
    return contrasts


def _workstreams(flags: set[str]) -> list[str]:
    ordered = [
        ("NORMALIZATION_GAP_CANDIDATE", "normalization-review"),
        ("TARGET_GAP_CANDIDATE", "target-review"),
        ("PURE_DETECTION_GAP", "detection-design"),
        ("PARTIAL_DETECTION_CANDIDATE", "partial-detection-review"),
        ("SCORING_REVIEW_CANDIDATE", "scoring-review"),
        ("REPLAY_ERROR_PRESENT", "replay-review"),
    ]
    return [workstream for flag, workstream in ordered if flag in flags]


def analyze_cluster(payload_path: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [evidence_status(record) for record in records]
    usable_statuses = [status for status in statuses if status != "UNUSABLE"]
    normalization_contrasts = _contrast(records, fixed_field="zone", variable_field="encoding")
    target_contrasts = _contrast(records, fixed_field="encoding", variable_field="zone")

    flags: set[str] = set()
    if normalization_contrasts:
        flags.add("NORMALIZATION_GAP_CANDIDATE")
    if target_contrasts:
        flags.add("TARGET_GAP_CANDIDATE")
    if "WEAK_PARTIAL" in usable_statuses:
        flags.add("PARTIAL_DETECTION_CANDIDATE")
    if "PARTIAL" in usable_statuses:
        flags.add("SCORING_REVIEW_CANDIDATE")
    if "UNUSABLE" in statuses:
        flags.add("REPLAY_ERROR_PRESENT")
    if usable_statuses and all(status == "NO_DETECTION" for status in usable_statuses):
        flags.add("PURE_DETECTION_GAP")
    if usable_statuses and all(status in {"WEAK_PARTIAL", "PARTIAL"} for status in usable_statuses):
        flags.add("CONSISTENT_PARTIAL_DETECTION")

    scores = [score for score in (_score(record) for record in records) if score is not None]
    thresholds = sorted({threshold for threshold in (_threshold(record) for record in records) if threshold is not None})
    matched_rule_ids = sorted({rule_id for record in records for rule_id in _rule_ids(record)})
    normalized_payloads = sorted({payload for payload in (_normalized_payload(record) for record in records) if payload is not None})
    workstreams = _workstreams(flags)

    return {
        "cluster_schema_version": 2,
        "cluster_id": _cluster_id(payload_path),
        "payload_path": payload_path,
        "category": records[0].get("category") if records else None,
        "case_count": len(records),
        "usable_case_count": sum(status != "UNUSABLE" for status in statuses),
        "diagnoses": dict(sorted(Counter(str(record.get("diagnosis") or "UNKNOWN") for record in records).items())),
        "evidence_statuses": dict(sorted(Counter(statuses).items())),
        "zones": sorted({str(record.get("zone") or "UNKNOWN") for record in records}),
        "encodings": sorted({str(record.get("encoding") or "UNKNOWN") for record in records}),
        "normalized_payload_variant_count": len(normalized_payloads),
        "score_min": min(scores) if scores else None,
        "score_max": max(scores) if scores else None,
        "thresholds": thresholds,
        "matched_rule_ids": matched_rule_ids,
        "flags": sorted(flags),
        "recommended_workstreams": workstreams,
        "primary_workstream": workstreams[0] if workstreams else "manual-review",
        "normalization_contrasts": normalization_contrasts,
        "target_contrasts": target_contrasts,
        "interpretation": {
            "normalization_gap_candidate": "Same source payload, target zone, and normalized payload has no detection for one encoding but positive detection for another. This is comparative evidence, not proof of a decoder defect.",
            "target_gap_candidate": "Same source payload, encoding, and normalized payload has no detection in one target zone but positive detection in another. This is comparative evidence, not proof that all zones should share identical rules.",
            "partial_detection_candidate": "A weak score (1-2) was observed. Do not raise its score automatically; first verify that the matched rule is relevant to the attack primitive.",
            "scoring_review_candidate": "A stronger below-threshold score was observed. Rule relevance still must be checked before treating this as a true scoring-only gap.",
        },
    }


def analyze_gap_clusters(input_path: Path, output_dir: Path) -> dict[str, Any]:
    records = read_jsonl(input_path)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        payload_path = str(record.get("payload_path") or "UNKNOWN")
        grouped[payload_path].append(record)

    clusters: list[dict[str, Any]] = []
    cluster_by_payload: dict[str, dict[str, Any]] = {}
    flag_counts: Counter[str] = Counter()
    evidence_counts: Counter[str] = Counter()
    diagnosis_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()

    for payload_path, group in sorted(grouped.items()):
        cluster = analyze_cluster(payload_path, group)
        clusters.append(cluster)
        cluster_by_payload[payload_path] = cluster
        flag_counts.update(cluster["flags"])
        evidence_counts.update(cluster["evidence_statuses"])
        diagnosis_counts.update(cluster["diagnoses"])
        for record in group:
            for rule_id in _rule_ids(record):
                rule_counts[rule_id] += 1

    enriched_cases: list[dict[str, Any]] = []
    for record in records:
        payload_path = str(record.get("payload_path") or "UNKNOWN")
        cluster = cluster_by_payload[payload_path]
        enriched = dict(record)
        enriched["gap_analysis"] = {
            "cluster_id": cluster["cluster_id"],
            "evidence_status": evidence_status(record),
            "cluster_flags": cluster["flags"],
            "recommended_workstreams": cluster["recommended_workstreams"],
            "primary_workstream": cluster["primary_workstream"],
            "score": _score(record),
            "threshold": _threshold(record),
            "matched_rule_ids": _rule_ids(record),
        }
        enriched_cases.append(enriched)

    output_dir.mkdir(parents=True, exist_ok=True)
    clusters_path = output_dir / "clusters.jsonl"
    cases_path = output_dir / "cases.jsonl"
    write_jsonl(clusters_path, clusters)
    write_jsonl(cases_path, enriched_cases)

    files: dict[str, str] = {
        "clusters": str(clusters_path),
        "cases": str(cases_path),
    }
    flag_files = {
        "NORMALIZATION_GAP_CANDIDATE": "normalization-gap-candidates.jsonl",
        "TARGET_GAP_CANDIDATE": "target-gap-candidates.jsonl",
        "PURE_DETECTION_GAP": "pure-detection-gap-clusters.jsonl",
        "PARTIAL_DETECTION_CANDIDATE": "partial-detection-candidates.jsonl",
        "SCORING_REVIEW_CANDIDATE": "scoring-review-candidates.jsonl",
        "REPLAY_ERROR_PRESENT": "replay-error-clusters.jsonl",
    }
    for flag, filename in flag_files.items():
        selected = [cluster for cluster in clusters if flag in cluster["flags"]]
        if not selected:
            continue
        path = output_dir / filename
        write_jsonl(path, selected)
        files[flag] = str(path)

    manifest = {
        "gap_analysis_schema_version": 2,
        "source": str(input_path),
        "cases": len(records),
        "clusters": len(clusters),
        "diagnoses": dict(sorted(diagnosis_counts.items())),
        "evidence_statuses": dict(sorted(evidence_counts.items())),
        "cluster_flags": dict(sorted(flag_counts.items())),
        "matched_rule_case_counts": dict(sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))),
        "files": files,
        "policy": {
            "comparison_unit": "payload_path",
            "comparative_gap_requires_equal_normalized_payload": True,
            "automatic_rule_generation": False,
            "automatic_score_increase": False,
            "normalization_and_target_labels_are_candidates": True,
            "rule_metadata_required_for_true_scoring_gap": True,
        },
    }
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, manifest)
    return {**manifest, "manifest": str(manifest_path)}

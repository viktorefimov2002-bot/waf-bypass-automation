from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl


CONFIRMED_BYPASS_VERDICTS = {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}
LEGACY_WAF_BLOCK_VERDICTS = {"BLOCKED_BY_WAF"}


def _decision_sources(log: dict[str, Any]) -> set[str]:
    values = log.get("decision_source") or []
    return {str(value).strip().lower() for value in values if str(value).strip()}


def diagnose_observation(observation: dict[str, Any]) -> tuple[str, str]:
    replay_verdict = observation.get("final_verdict")
    if replay_verdict == "CHECK_ERROR":
        return "CHECK_ERROR", "Replay itself failed, so WAF coverage cannot be evaluated reliably."
    if replay_verdict == "ROUTE_MISMATCH":
        return "ROUTE_MISMATCH", "Legacy replay response route did not match the expected WAF/origin path."

    correlation_status = observation.get("correlation_status")
    if correlation_status in {"LOG_NOT_FOUND", "MISSING_REPLAY_TEST_ID"}:
        return "LOG_NOT_FOUND", "No unique security-log row could be joined to this replay request."
    if correlation_status == "MULTIPLE_LOG_MATCHES":
        return "NEEDS_REVIEW", "Multiple security-log rows have the same test_id; correlation is ambiguous."
    if correlation_status != "MATCHED":
        return "NEEDS_REVIEW", f"Unsupported correlation status: {correlation_status!r}."

    log = observation.get("security_log") or {}
    verdict = str(log.get("verdict") or "").strip().lower()
    blocking_mode = str(log.get("runtime_blocking_mode") or "").strip().lower()
    anomaly_score = log.get("anomaly_score")
    threshold = log.get("runtime_anomaly_threshold")
    matched_rules = log.get("matched_rules") or []
    decision_sources = _decision_sources(log)
    rule_engine = "ruleengine" in decision_sources

    # Security telemetry is authoritative for the WAF decision. HTTP replay only
    # confirms that an origin signature was seen, or that a block-like status was
    # observed; it no longer infers WAF ownership from an absent Server header.
    if verdict == "block":
        if replay_verdict in CONFIRMED_BYPASS_VERDICTS:
            return "NEEDS_REVIEW", "Replay reached the origin, but the joined security log says Block."
        if replay_verdict == "ORIGIN_BLOCK_RESPONSE":
            return "NEEDS_REVIEW", "Replay response carries the origin signature, but the joined security log says Block."
        if decision_sources and not rule_engine:
            return "BLOCKED_OTHER_SOURCE", "The request was blocked, but RuleEngine is not listed as a decision source."
        return "BLOCKED", "The WAF blocked the request and the security log confirms the decision."

    if replay_verdict in LEGACY_WAF_BLOCK_VERDICTS and verdict in {"allow", "monitor", "audit"}:
        return "NEEDS_REVIEW", "Legacy replay reports a WAF block, but the joined security log does not."

    score_known = isinstance(anomaly_score, int)
    threshold_known = isinstance(threshold, int)

    if verdict == "shadowwouldblock":
        return "WOULD_BLOCK", "The WAF explicitly reported ShadowWouldBlock."

    if score_known and threshold_known and anomaly_score >= threshold:
        if blocking_mode == "block" and verdict == "allow":
            return "NEEDS_REVIEW", "Score reached the blocking threshold in block mode, but verdict is Allow."
        return "WOULD_BLOCK", "The anomaly score reached the threshold, but policy/mode did not enforce a block."

    if score_known and threshold_known and anomaly_score < threshold:
        if anomaly_score > 0 or matched_rules:
            return "SCORING_GAP", "Rules matched, but the accumulated anomaly score stayed below the blocking threshold."
        return "DETECTION_GAP", "No rule contributed score and the anomaly score remained zero."

    if matched_rules:
        known_rule_scores = [rule.get("score") for rule in matched_rules if isinstance(rule.get("score"), int)]
        derived_score = sum(known_rule_scores) if known_rule_scores else None
        if threshold_known and derived_score is not None and derived_score < threshold:
            return "SCORING_GAP", "Matched-rule scores imply detection below threshold, although anomaly_score is unavailable."
        return "NEEDS_REVIEW", "Rules matched, but score/threshold telemetry is incomplete."

    if score_known and anomaly_score == 0:
        return "DETECTION_GAP", "The security log reports anomaly_score=0 and no matched rules."

    return "NEEDS_REVIEW", "Telemetry is insufficient or internally inconsistent for a deterministic diagnosis."


def diagnose_observations(input_path: Path, output_path: Path) -> dict[str, Any]:
    observations = read_jsonl(input_path)
    diagnosed: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    by_category: dict[str, Counter[str]] = defaultdict(Counter)

    for observation in observations:
        diagnosis, reason = diagnose_observation(observation)
        record = dict(observation)
        record["diagnosis"] = diagnosis
        record["diagnosis_reason"] = reason
        diagnosed.append(record)
        counts[diagnosis] += 1
        category = str(observation.get("category") or "UNKNOWN")
        by_category[category][diagnosis] += 1

    write_jsonl(output_path, diagnosed)
    return {
        "records": len(diagnosed),
        "diagnoses": dict(sorted(counts.items())),
        "by_category": {
            category: dict(sorted(category_counts.items()))
            for category, category_counts in sorted(by_category.items())
        },
        "output": str(output_path),
    }

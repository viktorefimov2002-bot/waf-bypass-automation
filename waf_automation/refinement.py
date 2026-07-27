from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_json, write_jsonl
from .rules import _render_rule, _validate_pattern

COVERAGE_FIELDS = [
    "stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive",
    "zone", "encoding", "rule_target", "phase", "normalization_steps", "transform_profile",
    "grouped_rule", "generic_header_target", "normalized_payload",
]
UNRESOLVED_FIELDS = [
    "stable_key", "rule_id", "status", "reason", "primitive", "encoding", "curl",
]


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _load_manifest(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rules = {str(rule.get("rule_id")): dict(rule) for rule in document.get("rules", [])}
    return document, rules


def _load_coverage(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {str(row.get("stable_key")): row for row in csv.DictReader(handle) if row.get("stable_key")}


def _literal_backslash_u(codepoint: str) -> str:
    return rf"\x5cu{codepoint}"


def _encoded_fallback(row: dict[str, Any], rule: dict[str, Any]) -> tuple[str | None, str]:
    encoding = str(row.get("encoding") or "NONE").upper()
    primitive = str(row.get("rule_primitive") or rule.get("primitive") or "")
    pattern = str(rule.get("pattern") or "")
    if encoding != "UTF-16":
        return None, "NO_SAFE_REFINEMENT_STRATEGY"
    if primitive == "sensitive_local_file":
        slash = rf"(?:{_literal_backslash_u('002f')}|%u002f)"
        return f"(?:{pattern}|(?:{slash}etc{slash}passwd|{slash}proc{slash}self))", "ADD_UTF16_TRANSPORT_FALLBACK"
    if primitive == "template_expression":
        left = rf"(?:{_literal_backslash_u('007b')}|%u007b)"
        right = rf"(?:{_literal_backslash_u('007d')}|%u007d)"
        return f"(?:{pattern}|{left}{left}.{{1,256}}{right}{right})", "ADD_UTF16_TRANSPORT_FALLBACK"
    if primitive == "xss_execution_sink":
        encoded_alert = "".join(rf"(?:{_literal_backslash_u(cp)}|%u{cp})" for cp in ["0061", "006c", "0065", "0072", "0074"])
        opening_paren = rf"(?:{_literal_backslash_u('0028')}|%u0028)"
        return f"(?:{pattern}|{encoded_alert}.{{0,32}}{opening_paren})", "ADD_UTF16_TRANSPORT_FALLBACK"
    return None, "NO_SAFE_REFINEMENT_STRATEGY"


def _validate_refined_pattern(pattern: str) -> None:
    _validate_pattern(pattern)
    if re.search(r"\u[0-9a-fA-F]{4,8}", pattern):
        raise ValueError(f"Textual Unicode regex escape is not wirefilter-compatible: {pattern}")
    if "[\\]" in pattern:
        raise ValueError(f"Backslash-only character class is not legacy-compatible: {pattern}")


def _manual_row(row: dict[str, Any], status: str, reason: str, rule_id: str | None = None) -> dict[str, Any]:
    return {
        "stable_key": row.get("stable_key"),
        "rule_id": int(rule_id) if rule_id and rule_id.isdigit() else None,
        "status": status,
        "reason": reason,
        "primitive": row.get("rule_primitive"),
        "encoding": row.get("encoding"),
        "curl": row.get("curl"),
    }


def _phase_from_rule(rule: dict[str, Any]) -> int:
    if rule.get("phase") in {1, 2, "1", "2"}:
        return int(rule["phase"])
    return 2 if "REQUEST_BODY" in str(rule.get("target") or "") else 1


def refine_rules(validation_path: Path, manifest_path: Path, coverage_path: Path, output_dir: Path) -> dict[str, Any]:
    validation_rows = [row for row in read_jsonl(validation_path) if row.get("status") == "STILL_BYPASSED"]
    if not validation_rows:
        raise ValueError("No STILL_BYPASSED records found; refinement is not required")
    source_manifest, rules_by_id = _load_manifest(manifest_path)
    coverage_by_key = _load_coverage(coverage_path)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    manual_rows: list[dict[str, Any]] = []
    for row in validation_rows:
        rule_id = str(row.get("rule_id") or "")
        stable_key = str(row.get("stable_key") or "")
        coverage = coverage_by_key.get(stable_key)
        if not rule_id or rule_id not in rules_by_id:
            manual_rows.append(_manual_row(row, "MANUAL_REVIEW_REQUIRED", "MISSING_RULE_MAPPING", rule_id)); continue
        if not coverage or str(coverage.get("rule_id") or "") != rule_id:
            manual_rows.append(_manual_row(row, "MANUAL_REVIEW_REQUIRED", "COVERAGE_RULE_MISMATCH", rule_id)); continue
        grouped[rule_id].append(row)
    refined_rules: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    refined_rule_ids: set[str] = set()
    def _sort_rule(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, str]:
        rule_id = item[0]
        return (int(rule_id), rule_id) if rule_id.isdigit() else (2**31 - 1, rule_id)
    for rule_id, rows in sorted(grouped.items(), key=_sort_rule):
        old_rule = rules_by_id[rule_id]
        proposals: list[str] = []
        reasons: list[str] = []
        for row in rows:
            proposal, reason = _encoded_fallback(row, old_rule)
            if proposal:
                proposals.append(proposal); reasons.append(reason)
        unique = list(dict.fromkeys(proposals))
        if len(unique) != 1:
            for row in rows:
                manual_rows.append(_manual_row(row, "CANNOT_SAFELY_REFINE", "AMBIGUOUS_OR_UNSUPPORTED_REFINEMENT", rule_id))
            continue
        new_pattern = unique[0]
        _validate_refined_pattern(new_pattern)
        new_rule = dict(old_rule)
        old_revision = int(old_rule.get("revision") or 1)
        new_rule.update({
            "revision": old_revision + 1,
            "supersedes_revision": old_revision,
            "pattern": new_pattern,
            "phase": _phase_from_rule(old_rule),
            "coverage_status": "REFINED_NOT_VALIDATED",
            "review_status": "REVIEW_REQUIRED",
            "refinement_reason": reasons[0],
            "refined_payload_count": len(rows),
            "source_coverage_count": old_rule.get("coverage_count"),
            "coverage_count": len(rows),
        })
        refined_rules.append(new_rule)
        refined_rule_ids.add(rule_id)
        changes.append({
            "rule_id": int(rule_id) if rule_id.isdigit() else rule_id,
            "old_revision": old_revision,
            "new_revision": old_revision + 1,
            "reason": reasons[0],
            "old_pattern": old_rule.get("pattern"),
            "new_pattern": new_pattern,
            "affected_payloads": len(rows),
        })
    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "refined-rules.conf"
    conf_path.write_text(
        "# Auto-generated refined SecLang rules. DO NOT auto-load.\n"
        "# Replace only the listed rule IDs after manual review and converter validation.\n"
        "# Refined regexes follow the same legacy/wirefilter compatibility policy as suggest-rules.\n\n"
        + "\n".join(_render_rule(rule) for rule in refined_rules), encoding="utf-8")
    refined_manifest = dict(source_manifest)
    refined_manifest["rules"] = refined_rules
    refined_manifest["refinement"] = {
        "source_validation": str(validation_path),
        "source_manifest": str(manifest_path),
        "source_coverage": str(coverage_path),
        "still_bypassed": len(validation_rows),
        "refined_rules": len(refined_rules),
        "refined_payloads": sum(len(rows) for rule_id, rows in grouped.items() if rule_id in refined_rule_ids),
        "manual_review_records": len(manual_rows),
        "policy": {
            "mapped_rules_only": True,
            "coverage_mapping_required": True,
            "legacy_seclang_safe_regex": True,
            "wirefilter_textual_unicode_escapes": False,
            "backslash_character_class": False,
            "preserve_or_infer_request_phase": True,
            "automatic_deployment": False,
        },
    }
    manifest_out = output_dir / "manifest.json"; write_json(manifest_out, refined_manifest)
    coverage_rows: list[dict[str, Any]] = []
    for row in validation_rows:
        key = str(row.get("stable_key") or "")
        coverage = coverage_by_key.get(key, {})
        if str(row.get("rule_id") or "") in refined_rule_ids and coverage:
            coverage_rows.append(coverage)
    coverage_out = output_dir / "coverage.csv"; _write_csv(coverage_out, coverage_rows, COVERAGE_FIELDS)
    coverage_jsonl_out = output_dir / "coverage.jsonl"; write_jsonl(coverage_jsonl_out, coverage_rows)
    changes_out = output_dir / "changes.csv"
    _write_csv(changes_out, changes, ["rule_id", "old_revision", "new_revision", "reason", "old_pattern", "new_pattern", "affected_payloads"])
    changes_jsonl_out = output_dir / "changes.jsonl"; write_jsonl(changes_jsonl_out, changes)
    unresolved_out = output_dir / "unresolved.csv"; _write_csv(unresolved_out, manual_rows, UNRESOLVED_FIELDS)
    unresolved_jsonl_out = output_dir / "unresolved.jsonl"; write_jsonl(unresolved_jsonl_out, manual_rows)
    counts = Counter(row["status"] for row in manual_rows)
    return {
        "still_bypassed": len(validation_rows),
        "refined_rules": len(refined_rules),
        "refined_payloads": len(coverage_rows),
        "manual_review_required": counts["MANUAL_REVIEW_REQUIRED"],
        "cannot_safely_refine": counts["CANNOT_SAFELY_REFINE"],
        "output_dir": str(output_dir),
        "rules": str(conf_path),
        "manifest": str(manifest_out),
        "coverage": str(coverage_out),
        "coverage_jsonl": str(coverage_jsonl_out),
        "changes": str(changes_out),
        "changes_jsonl": str(changes_jsonl_out),
        "unresolved": str(unresolved_out),
        "unresolved_jsonl": str(unresolved_jsonl_out),
    }

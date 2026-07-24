from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_json
from .rules import _render_rule, _validate_pattern


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _load_manifest(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rules = {str(rule.get("rule_id")): dict(rule) for rule in document.get("rules", [])}
    return document, rules


def _load_coverage(path: Path) -> dict[str, dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {str(row.get("stable_key")): row for row in csv.DictReader(handle) if row.get("stable_key")}


def _encoded_fallback(row: dict[str, Any], rule: dict[str, Any]) -> tuple[str | None, str]:
    encoding = str(row.get("encoding") or "NONE").upper()
    primitive = str(row.get("rule_primitive") or rule.get("primitive") or "")
    pattern = str(rule.get("pattern") or "")

    if encoding == "UTF-16" and primitive == "sensitive_local_file":
        fallback = r"(?:[\\]u002fetc[\\]u002fpasswd|%u002fetc%u002fpasswd|[\\]u002fproc[\\]u002fself|%u002fproc%u002fself)"
        return f"(?:{pattern}|{fallback})", "ADD_ENCODED_FORM_FALLBACK"
    if encoding == "UTF-16" and primitive == "template_expression":
        fallback = r"(?:[\\]u007b[\\]u007b[\s\S]{1,256}[\\]u007d[\\]u007d|%u007b%u007b[\s\S]{1,256}%u007d%u007d)"
        return f"(?:{pattern}|{fallback})", "ADD_ENCODED_FORM_FALLBACK"
    if encoding == "UTF-16" and primitive == "xss_execution_sink":
        fallback = r"(?:[\\]u0061[\\]u006c[\\]u0065[\\]u0072[\\]u0074|%u0061%u006c%u0065%u0072%u0074)[\s\S]{0,32}(?:[\\]u0028|%u0028)"
        return f"(?:{pattern}|{fallback})", "ADD_ENCODED_FORM_FALLBACK"
    return None, "NO_SAFE_REFINEMENT_STRATEGY"


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
        if not rule_id or rule_id not in rules_by_id:
            manual_rows.append({
                "stable_key": row.get("stable_key"), "rule_id": rule_id or None,
                "status": "MANUAL_REVIEW_REQUIRED", "reason": "MISSING_RULE_MAPPING",
                "curl": row.get("curl"),
            })
            continue
        grouped[rule_id].append(row)

    refined_rules: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    refined_rule_ids: set[str] = set()

    for rule_id, rows in sorted(grouped.items(), key=lambda item: int(item[0])):
        old_rule = rules_by_id[rule_id]
        proposals = []
        reasons = []
        for row in rows:
            proposal, reason = _encoded_fallback(row, old_rule)
            if proposal:
                proposals.append(proposal)
                reasons.append(reason)
        unique = list(dict.fromkeys(proposals))
        if len(unique) != 1:
            for row in rows:
                manual_rows.append({
                    "stable_key": row.get("stable_key"), "rule_id": int(rule_id),
                    "status": "CANNOT_SAFELY_REFINE", "reason": "AMBIGUOUS_OR_UNSUPPORTED_REFINEMENT",
                    "curl": row.get("curl"),
                })
            continue

        new_pattern = unique[0]
        _validate_pattern(new_pattern)
        new_rule = dict(old_rule)
        old_revision = int(old_rule.get("revision") or 1)
        new_rule["revision"] = old_revision + 1
        new_rule["supersedes_revision"] = old_revision
        new_rule["pattern"] = new_pattern
        new_rule["coverage_status"] = "REFINED_NOT_VALIDATED"
        new_rule["review_status"] = "REVIEW_REQUIRED"
        new_rule["refinement_reason"] = reasons[0]
        new_rule["coverage_count"] = len(rows)
        refined_rules.append(new_rule)
        refined_rule_ids.add(rule_id)
        changes.append({
            "rule_id": int(rule_id), "old_revision": old_revision,
            "new_revision": old_revision + 1, "reason": reasons[0],
            "old_pattern": old_rule.get("pattern"), "new_pattern": new_pattern,
            "affected_payloads": len(rows),
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "refined-rules.conf"
    conf_path.write_text(
        "# Auto-generated refined SecLang rules. DO NOT auto-load.\n"
        "# Replace only the listed rule IDs after manual review.\n\n"
        + "\n".join(_render_rule(rule) for rule in refined_rules),
        encoding="utf-8",
    )

    refined_manifest = dict(source_manifest)
    refined_manifest["rules"] = refined_rules
    refined_manifest["refinement"] = {
        "source_validation": str(validation_path),
        "source_manifest": str(manifest_path),
        "source_coverage": str(coverage_path),
        "still_bypassed": len(validation_rows),
        "refined_rules": len(refined_rules),
        "manual_review_records": len(manual_rows),
    }
    manifest_out = output_dir / "manifest.json"
    write_json(manifest_out, refined_manifest)

    coverage_rows = []
    for row in validation_rows:
        key = str(row.get("stable_key") or "")
        coverage = coverage_by_key.get(key, {})
        if str(row.get("rule_id") or "") in refined_rule_ids and coverage:
            coverage_rows.append(coverage)
    coverage_out = output_dir / "coverage.csv"
    fieldnames = ["stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive", "zone", "encoding", "rule_target", "grouped_rule"]
    _write_csv(coverage_out, coverage_rows, fieldnames)

    changes_out = output_dir / "changes.csv"
    _write_csv(changes_out, changes, ["rule_id", "old_revision", "new_revision", "reason", "old_pattern", "new_pattern", "affected_payloads"])
    unresolved_out = output_dir / "unresolved.csv"
    _write_csv(unresolved_out, manual_rows, ["stable_key", "rule_id", "status", "reason", "curl"])

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
        "changes": str(changes_out),
        "unresolved": str(unresolved_out),
    }

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, stable_key, write_json

TARGETS = {
    "URL": "REQUEST_URI",
    "ARGS": "ARGS",
    "BODY": "REQUEST_BODY",
    "COOKIE": "REQUEST_COOKIES",
    "USER-AGENT": "REQUEST_HEADERS:User-Agent",
    "REFERER": "REQUEST_HEADERS:Referer",
    "HEADER": "REQUEST_HEADERS",
}

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "xss": [
        ("xss_event_handler", r"<[^>]{0,256}\bon[a-z]{2,32}\s*="),
        ("xss_javascript_scheme", r"java[\s\x00-\x20]*script\s*:"),
        ("xss_scriptable_tag", r"<\s*(?:script|svg|img|iframe|object|embed|audio|video|math|form|input)\b"),
        ("xss_execution_sink", r"(?:alert|prompt|confirm|eval|settimeout|setinterval|import)\s*(?:\(|`)"),
    ],
    "sqli": [
        ("sqli_union_select", r"\bunion\b[\s\S]{0,64}\bselect\b"),
        ("sqli_select_from", r"\bselect\b[\s\S]{0,96}\bfrom\b"),
        ("sqli_boolean", r"(?:\bor\b|\band\b)\s+['0-9][^\r\n]{0,32}(?:=|like)"),
    ],
    "command": [
        ("command_separator", r"(?:[;&|`]|\$\()\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b"),
        ("command_substitution", r"\$\([^\r\n)]{1,256}\)"),
    ],
    "lfi": [
        ("path_traversal", r"(?:\.\.(?:/|\x5c)){1,}"),
        ("sensitive_local_file", r"(?:/etc/passwd|/proc/self|windows(?:/|\x5c)win\.ini)"),
    ],
    "ssrf": [
        ("internal_url", r"\b(?:https?|gopher|file|dict|ftp)://(?:localhost|127\.|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"),
        ("non_http_scheme", r"\b(?:gopher|file|dict)://"),
    ],
    "nosqli": [("nosql_operator", r"\$(?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b")],
    "ldap": [("ldap_filter_injection", r"(?:\|\(|&\(|\)\(|\*\)\(|\(objectclass\s*=)")],
    "ssti": [("template_expression", r"(?:\{\{[\s\S]{1,256}\}\}|\$\{[\s\S]{1,256}\}|<%[\s\S]{1,256}%>)")],
    "ssi": [("ssi_directive", r"<!--\s*#(?:exec|include|echo|config|set)\b")],
    "redirect": [("redirect_parameter", r"(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//")],
}


def _family(record: dict[str, Any]) -> str:
    category = str(record.get("category", "")).upper()
    if category == "XSS": return "xss"
    if category == "SQLI": return "sqli"
    if category in {"CM", "RCE"}: return "command"
    if category == "LFI": return "lfi"
    if category == "SSRF": return "ssrf"
    if category == "NOSQLI": return "nosqli"
    if category == "LDAP": return "ldap"
    if category == "SSTI": return "ssti"
    if category == "SSI": return "ssi"
    if category == "OR": return "redirect"
    return "generic"


def _select_signature(record: dict[str, Any]) -> tuple[str, str, str] | None:
    family = _family(record)
    payload = str(record.get("normalized_payload") or record.get("raw_payload") or "").lower()
    for primitive, pattern in SIGNATURES.get(family, []):
        if re.search(pattern, payload):
            return family, primitive, pattern
    return None


def _transforms(encoding: str, family: str) -> tuple[str, ...]:
    result = ["t:none", "t:urlDecodeUni"]
    if encoding == "BASE64": result.append("t:base64DecodeExt")
    if encoding == "UTF-16" or family == "xss": result.append("t:jsDecode")
    if family == "xss": result.extend(["t:htmlEntityDecode", "t:cssDecode"])
    result.extend(["t:lowercase", "t:removeNulls"])
    return tuple(dict.fromkeys(result))


def _deduplicate_targets(targets: set[str]) -> list[str]:
    if "REQUEST_HEADERS" in targets:
        targets.discard("REQUEST_HEADERS:Referer")
        targets.discard("REQUEST_HEADERS:User-Agent")
    return sorted(targets)


def _validate_pattern(pattern: str) -> None:
    if "(?i)" in pattern or "(?s)" in pattern:
        raise ValueError(f"Inline regex flags are not allowed: {pattern}")
    if "[/\\\\]" in pattern or "[\\\\/]" in pattern:
        raise ValueError(f"Ambiguous slash/backslash character class is not allowed: {pattern}")
    re.compile(pattern)


def _render_rule(rule: dict[str, Any]) -> str:
    actions = [
        f"id:{rule['rule_id']}", "phase:2", "deny", *rule["transforms"],
        f"msg:'Candidate coverage for confirmed waf-bypass: {rule['primitive']}'",
        "tag:'waf-bypass-candidate'", "severity:'CRITICAL'", "setvar:tx.anomaly_score=+5",
    ]
    action_lines = ",\\\n    ".join(actions)
    return (
        f"# Covers {rule['coverage_count']} confirmed bypass variant(s); "
        f"targets={','.join(rule['targets'])}; encodings={','.join(rule['encodings'])}.\n"
        "# REVIEW REQUIRED: validate converter compatibility, coverage and false positives before production.\n"
        f"SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        f"    \"{action_lines}\"\n"
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
    records = [record for record in read_jsonl(input_path) if record.get("final_verdict") in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}]
    if not records:
        raise ValueError("No confirmed bypass records; run verify first")

    clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    signatures: dict[str, tuple[str, str, str]] = {}
    skipped_rows: list[dict[str, Any]] = []

    for record in records:
        signature = _select_signature(record)
        if signature is None:
            skipped_rows.append({
                "stable_key": stable_key(record), "payload_path": record.get("payload_path"),
                "variant": record.get("variant"), "group_id": record.get("group_id"),
                "category": record.get("category"), "zone": record.get("zone"),
                "encoding": record.get("encoding"), "reason": "NO_RECOGNIZED_PRIMITIVE",
            })
            continue
        family, primitive, pattern = signature
        _validate_pattern(pattern)
        transforms = _transforms(str(record.get("encoding", "NONE")), family)
        signature_key = f"{family}|{primitive}|{pattern}"
        signatures[signature_key] = (family, primitive, pattern)
        clusters[(record.get("group_id"), record.get("group_name"), signature_key, transforms)].append(record)

    if not clusters:
        raise ValueError("Confirmed bypasses were found, but none matched a supported exploit primitive")

    rules: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    for offset, (key, covered) in enumerate(sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))):
        group_id, group_name, signature_key, transforms = key
        family, primitive, pattern = signatures[signature_key]
        targets = _deduplicate_targets({TARGETS.get(str(record.get("zone")), "REQUEST_URI") for record in covered})
        encodings = sorted({str(record.get("encoding", "NONE")) for record in covered})
        target = "|".join(targets)
        rule = {
            "rule_id": id_start + offset, "group_id": group_id, "group_name": group_name,
            "target": target, "targets": targets, "encodings": encodings,
            "family": family, "primitive": primitive, "pattern": pattern,
            "transforms": list(transforms), "coverage_count": len(covered),
            "review_status": "REVIEW_REQUIRED", "coverage_status": "PROPOSED_NOT_VALIDATED",
        }
        rules.append(rule)
        for record in covered:
            coverage_rows.append({
                "stable_key": stable_key(record), "payload_path": record["payload_path"],
                "variant": record["variant"], "group_id": group_id, "rule_id": rule["rule_id"],
                "primitive": primitive, "zone": record.get("zone"), "encoding": record.get("encoding"),
                "rule_target": target, "grouped_rule": len(covered) > 1,
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "candidate-rules.conf"
    conf_path.write_text(
        "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n"
        "# Only recognized exploit primitives are emitted; fallback payload rules are skipped.\n\n"
        + "\n".join(_render_rule(rule) for rule in rules), encoding="utf-8"
    )
    coverage_path = output_dir / "coverage.csv"
    _write_csv(coverage_path, coverage_rows, ["stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive", "zone", "encoding", "rule_target", "grouped_rule"])
    skipped_path = output_dir / "skipped.csv"
    _write_csv(skipped_path, skipped_rows, ["stable_key", "payload_path", "variant", "group_id", "category", "zone", "encoding", "reason"])

    manifest_path = output_dir / "manifest.json"
    grouped_rules = sum(rule["coverage_count"] > 1 for rule in rules)
    covered_variants = len(coverage_rows)
    write_json(manifest_path, {
        "source": str(input_path), "confirmed_bypass_variants": len(records),
        "covered_variants": covered_variants, "skipped_variants": len(skipped_rows),
        "candidate_rules": len(rules), "grouped_rules": grouped_rules,
        "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
        "generation_policy": {
            "recognized_primitives_only": True, "family_fallbacks": False,
            "narrow_fallbacks": False, "inline_regex_flags": False,
            "deduplicate_generic_headers": True,
        },
        "rules": rules,
    })
    if covered_variants + len(skipped_rows) != len(records):
        raise RuntimeError("Each confirmed bypass must be covered or explicitly skipped")
    return {
        "confirmed_bypass_variants": len(records), "covered_variants": covered_variants,
        "skipped_variants": len(skipped_rows), "candidate_rules": len(rules),
        "grouped_rules": grouped_rules, "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
        "coverage": str(coverage_path), "skipped": str(skipped_path),
        "rules": str(conf_path), "manifest": str(manifest_path),
    }

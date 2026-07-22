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
        ("xss_event_handler", r"(?i)<[^>]{0,256}\bon[a-z]{2,32}\s*="),
        ("xss_javascript_scheme", r"(?i)java[\s\x00-\x20]*script\s*:"),
        ("xss_scriptable_tag", r"(?i)<\s*(?:script|svg|img|iframe|object|embed|audio|video|math|form|input)\b"),
        ("xss_execution_sink", r"(?i)(?:alert|prompt|confirm|eval|settimeout|setinterval|import)\s*(?:\(|`)"),
    ],
    "sqli": [
        ("sqli_union_select", r"(?i)\bunion\b.{0,64}\bselect\b"),
        ("sqli_select_from", r"(?i)\bselect\b.{0,96}\bfrom\b"),
        ("sqli_boolean", r"(?i)(?:\bor\b|\band\b)\s+['0-9][^\r\n]{0,32}(?:=|like)"),
    ],
    "command": [
        ("command_separator", r"(?i)(?:[;&|`]|\$\()\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b"),
        ("command_substitution", r"(?i)\$\([^\r\n)]{1,256}\)"),
    ],
    "lfi": [
        ("path_traversal", r"(?i)(?:\.\.[/\\]){1,}"),
        ("sensitive_local_file", r"(?i)(?:/etc/passwd|/proc/self|windows[/\\]win\.ini)"),
    ],
    "ssrf": [
        ("internal_url", r"(?i)\b(?:https?|gopher|file|dict|ftp)://(?:localhost|127\.|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"),
        ("non_http_scheme", r"(?i)\b(?:gopher|file|dict)://"),
    ],
    "nosqli": [("nosql_operator", r"(?i)\$(?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b")],
    "ldap": [("ldap_filter_injection", r"(?i)(?:\|\(|&\(|\)\(|\*\)\(|\(objectclass\s*=)")],
    "ssti": [("template_expression", r"(?s)(?:\{\{.{1,256}\}\}|\$\{.{1,256}\}|<%.{1,256}%>)")],
    "ssi": [("ssi_directive", r"(?i)<!--\s*#(?:exec|include|echo|config|set)\b")],
    "redirect": [("redirect_parameter", r"(?i)(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//")],
}

FAMILY_FALLBACKS = {
    "xss": r"(?i)(?:<[^>]{0,512}(?:script|on[a-z]{2,32}\s*=)|java[\s\x00-\x20]*script\s*:)",
    "sqli": r"(?i)(?:\b(?:select|union|insert|update|delete|drop|sleep|benchmark)\b|(?:--|/\*|\#))",
    "command": r"(?i)(?:[;&|`]|\$\().{0,64}\b(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b",
    "lfi": r"(?i)(?:(?:\.\.[/\\]){1,}|/etc/passwd|/proc/self|windows[/\\]win\.ini)",
    "ssrf": r"(?i)\b(?:https?|gopher|file|dict|ftp)://",
    "nosqli": r"(?i)\$(?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b",
    "ldap": r"(?i)(?:\|\(|&\(|\)\(|\*\)\(|\(objectclass\s*=)",
    "ssti": r"(?s)(?:\{\{.{1,512}\}\}|\$\{.{1,512}\}|<%.{1,512}%>)",
    "ssi": r"(?i)<!--\s*#(?:exec|include|echo|config|set)\b",
    "redirect": r"(?i)(?:redirect|redir|return|returnurl|next|continue|url).{0,32}(?:https?:)?//",
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


def _fallback_pattern(value: str) -> str:
    compact = re.sub(r"\s+", " ", value.strip().lower())[:96] or "__empty_payload__"
    return "(?i)" + re.escape(compact).replace(r"\ ", r"\s+").replace('"', r"\x22")


def _select_signature(record: dict[str, Any]) -> tuple[str, str, str]:
    family = _family(record)
    payload = str(record.get("normalized_payload") or record.get("raw_payload") or "")
    for primitive, pattern in SIGNATURES.get(family, []):
        if re.search(pattern, payload):
            return family, primitive, pattern
    if family in FAMILY_FALLBACKS:
        return family, f"{family}_family_fallback", FAMILY_FALLBACKS[family]
    return family, "narrow_fallback", _fallback_pattern(payload)


def _transforms(encoding: str, family: str) -> tuple[str, ...]:
    result = ["t:none", "t:urlDecodeUni"]
    if encoding == "BASE64": result.append("t:base64DecodeExt")
    if encoding == "UTF-16" or family == "xss": result.append("t:jsDecode")
    if family == "xss": result.extend(["t:htmlEntityDecode", "t:cssDecode"])
    result.extend(["t:lowercase", "t:removeNulls"])
    return tuple(dict.fromkeys(result))


def _render_rule(rule: dict[str, Any]) -> str:
    actions = [
        f"id:{rule['rule_id']}", "phase:2", "deny", "capture", *rule["transforms"],
        f"msg:'Candidate coverage for confirmed waf-bypass: {rule['primitive']}'",
        "tag:'waf-bypass-candidate'", "severity:'CRITICAL'", "setvar:tx.anomaly_score=+5",
    ]
    warning = "# REVIEW REQUIRED: validate syntax, coverage and false positives before production.\n"
    if rule["primitive"] == "narrow_fallback":
        warning += "# NARROW FALLBACK: generalize manually where possible.\n"
    elif rule["primitive"].endswith("_family_fallback"):
        warning += "# BROAD FAMILY FALLBACK: tune against benign traffic.\n"
    action_lines = ",\\\n    ".join(actions)
    return (
        f"# Covers {rule['coverage_count']} confirmed bypass variant(s); "
        f"targets={','.join(rule['targets'])}; encodings={','.join(rule['encodings'])}.\n"
        f"{warning}SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        f"    \"{action_lines}\"\n"
    )


def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
    records = [
        record for record in read_jsonl(input_path)
        if record.get("final_verdict") in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}
    ]
    if not records:
        raise ValueError("No confirmed bypass records; run verify first")

    clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    signatures: dict[str, tuple[str, str, str]] = {}
    for record in records:
        family, primitive, pattern = _select_signature(record)
        transforms = _transforms(str(record.get("encoding", "NONE")), family)
        signature_key = f"{family}|{primitive}|{pattern}"
        signatures[signature_key] = (family, primitive, pattern)
        clusters[(record.get("group_id"), record.get("group_name"), signature_key, transforms)].append(record)

    rules: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    for offset, (key, covered) in enumerate(sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))):
        group_id, group_name, signature_key, transforms = key
        family, primitive, pattern = signatures[signature_key]
        targets = sorted({TARGETS.get(str(record.get("zone")), "REQUEST_URI") for record in covered})
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
                "primitive": primitive, "zone": record.get("zone"),
                "encoding": record.get("encoding"), "rule_target": target,
                "grouped_rule": len(covered) > 1,
                "fallback": primitive == "narrow_fallback",
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "candidate-rules.conf"
    conf_path.write_text(
        "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n\n"
        + "\n".join(_render_rule(rule) for rule in rules), encoding="utf-8"
    )
    coverage_path = output_dir / "coverage.csv"
    with coverage_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(coverage_rows[0]))
        writer.writeheader(); writer.writerows(coverage_rows)
    manifest_path = output_dir / "manifest.json"
    grouped_rules = sum(rule["coverage_count"] > 1 for rule in rules)
    write_json(manifest_path, {
        "source": str(input_path), "confirmed_bypass_variants": len(records),
        "candidate_rules": len(rules), "grouped_rules": grouped_rules,
        "max_variants_per_rule": max(rule["coverage_count"] for rule in rules), "rules": rules,
    })
    if len(coverage_rows) != len(records):
        raise RuntimeError("Coverage matrix does not include every confirmed bypass variant")
    return {
        "confirmed_bypass_variants": len(records), "candidate_rules": len(rules),
        "grouped_rules": grouped_rules, "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
        "coverage": str(coverage_path), "rules": str(conf_path), "manifest": str(manifest_path),
    }

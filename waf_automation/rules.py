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

COLLECTION_TARGETS = {"ARGS", "REQUEST_COOKIES", "REQUEST_HEADERS"}


SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "xss": [
        ("xss_event_handler", r"(?i)<[^>]{0,256}\bon[a-z]{2,32}\s*="),
        ("xss_javascript_scheme", r"(?i)java[\s\x00-\x20]*script\s*:"),
        ("xss_scriptable_tag", r"(?i)<\s*(?:script|svg|img|iframe|object|embed|audio|video|math|form|input)\b"),
        ("xss_execution_sink", r"(?i)(?:alert|prompt|confirm|eval|settimeout|setinterval|import)\s*(?:\(|`)"),
        ("xss_dom_exfiltration", r"(?i)(?:document\s*(?:\.|\[)|location\s*=|cookie\b)"),
    ],
    "sqli": [
        ("sqli_union_select", r"(?i)\bunion\b.{0,64}\bselect\b"),
        ("sqli_select_from", r"(?i)\bselect\b.{0,96}\bfrom\b"),
        ("sqli_boolean", r"(?i)(?:\bor\b|\band\b)\s+['0-9][^\r\n]{0,32}(?:=|like)"),
        ("sqli_comment", r"(?i)(?:--[\s\x00]|/\*|\#)"),
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
        ("internal_url", r"(?i)\b(?:https?|gopher|file|dict|ftp)://(?:localhost|127(?:\.\d{1,3}){3}|169\.254\.169\.254|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})"),
        ("non_http_scheme", r"(?i)\b(?:gopher|file|dict)://"),
    ],
    "nosqli": [
        ("nosql_operator", r"(?i)\$(?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b"),
    ],
    "ldap": [
        ("ldap_filter_injection", r"(?i)(?:\|\(|&\(|\)\(|\*\)\(|\(objectclass\s*=)"),
    ],
    "ssti": [
        ("template_expression", r"(?s)(?:\{\{.{1,256}\}\}|\$\{.{1,256}\}|<%.{1,256}%>)"),
    ],
    "ssi": [
        ("ssi_directive", r"(?i)<!--\s*#(?:exec|include|echo|config|set)\b"),
    ],
    "graphql": [
        ("graphql_introspection", r"(?i)\b__(?:schema|type|typename)\b"),
    ],
    "redirect": [
        ("redirect_parameter", r"(?i)(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//"),
    ],
}


FAMILY_FALLBACKS = {
    "xss": r"(?i)(?:<[^>]{0,512}(?:script|on[a-z]{2,32}\s*=)|java[\s\x00-\x20]*script\s*:|(?:alert|prompt|confirm|eval|settimeout|setinterval|import)[^a-z0-9]{0,16}(?:\(|\[|`)|(?:document|location|cookie)[^a-z0-9]{0,16}(?:\.|\[|=))",
    "sqli": r"(?i)(?:\b(?:select|union|insert|update|delete|drop|sleep|benchmark)\b|(?:--|/\*|\#)|(?:\bor\b|\band\b).{0,32}=)",
    "command": r"(?i)(?:[;&|`]|\$\(|%0[ad]).{0,64}\b(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b",
    "lfi": r"(?i)(?:(?:\.\.[/\\]){1,}|/etc/passwd|/proc/self|windows[/\\]win\.ini)",
    "ssrf": r"(?i)\b(?:https?|gopher|file|dict|ftp)://(?:localhost|127\.|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|[^/\s]+)",
    "nosqli": r"(?i)(?:\$(?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b|\{\s*['\x22]?\$)",
    "ldap": r"(?i)(?:\|\(|&\(|\)\(|\*\)\(|\(objectclass\s*=)",
    "ssti": r"(?s)(?:\{\{.{1,512}\}\}|\$\{.{1,512}\}|<%.{1,512}%>)",
    "ssi": r"(?i)<!--\s*#(?:exec|include|echo|config|set)\b",
    "graphql": r"(?i)\b__(?:schema|type|typename)\b",
    "redirect": r"(?i)(?:redirect|redir|return|returnurl|next|continue|url).{0,32}(?:https?:)?//",
}


def _family(record: dict[str, Any]) -> str:
    category = str(record.get("category", "")).upper()
    group = str(record.get("group_name", "")).lower()
    if category == "XSS" or "xss" in group or "межсайтов" in group:
        return "xss"
    if category == "SQLI" or "sql" in group:
        return "sqli"
    if category in {"CM", "RCE"} or "команд" in group or "rce" in group:
        return "command"
    if category == "LFI" or "локальн" in group or "каталог" in group:
        return "lfi"
    if category in {"SSRF", "RFI"} or "ssrf" in group:
        return "ssrf"
    if category == "NOSQLI":
        return "nosqli"
    if category == "LDAP":
        return "ldap"
    if category == "SSTI":
        return "ssti"
    if category == "SSI":
        return "ssi"
    if category == "GRAPHQL":
        return "graphql"
    if category == "OR":
        return "redirect"
    return "generic"


def _fallback_pattern(value: str) -> str:
    compact = re.sub(r"\s+", " ", value.strip().lower())
    if len(compact) > 96:
        compact = compact[:96]
    if len(compact) < 4:
        compact = value.strip().lower() or "__empty_payload__"
    pattern = re.escape(compact).replace(r"\ ", r"\s+")
    return "(?i)" + pattern.replace('"', r"\x22")


def _select_signature(record: dict[str, Any]) -> tuple[str, str, str]:
    family = _family(record)
    payload = str(record.get("normalized_payload") or record.get("raw_payload") or "")
    for primitive, pattern in SIGNATURES.get(family, []):
        try:
            if re.search(pattern, payload):
                return family, primitive, pattern
        except re.error:
            continue
    if family in FAMILY_FALLBACKS:
        return family, f"{family}_family_fallback", FAMILY_FALLBACKS[family]
    return family, "narrow_fallback", _fallback_pattern(payload)


def _transforms(encoding: str, family: str) -> list[str]:
    transforms = ["t:none", "t:urlDecodeUni"]
    if encoding == "BASE64":
        transforms.append("t:base64DecodeExt")
    if encoding == "UTF-16" or family == "xss":
        transforms.append("t:jsDecode")
    if family == "xss":
        transforms.extend(["t:htmlEntityDecode", "t:cssDecode"])
    transforms.extend(["t:lowercase", "t:removeNulls"])
    result: list[str] = []
    for item in transforms:
        if item not in result:
            result.append(item)
    return result


def _tag(family: str) -> str:
    return {
        "xss": "attack-xss",
        "sqli": "attack-sqli",
        "command": "attack-rce",
        "lfi": "attack-lfi",
        "ssrf": "attack-ssrf",
        "nosqli": "attack-nosqli",
        "ldap": "attack-ldap-injection",
        "ssti": "attack-ssti",
        "ssi": "attack-ssi",
        "graphql": "attack-graphql",
        "redirect": "attack-open-redirect",
    }.get(family, "attack-generic")


def _render_rule(rule: dict[str, Any]) -> str:
    actions = [
        f"id:{rule['rule_id']}",
        "phase:2",
        "deny",
        "capture",
        *rule["transforms"],
        f"msg:'Candidate coverage for confirmed waf-bypass: {rule['primitive']}'",
        "tag:'application-multi'",
        f"tag:'{rule['tag']}'",
        "tag:'waf-bypass-candidate'",
        "severity:'CRITICAL'",
        "setvar:tx.anomaly_score=+5",
    ]
    if rule["family"] == "xss":
        actions.append("setvar:tx.xss_score=+5")
    action_lines = ",\\\n    ".join(actions)
    warning = ""
    if rule["target"] in COLLECTION_TARGETS and len(rule["transforms"]) > 1:
        warning = "# ENGINE REVIEW: collection target uses transforms; verify Pingora/CRS implementation support.\n"
    if rule["primitive"] == "narrow_fallback":
        warning += "# NARROW FALLBACK: exact-ish signature; generalize manually before production.\n"
    elif rule["primitive"].endswith("_family_fallback"):
        warning += "# BROAD FAMILY FALLBACK: tune against benign traffic before production.\n"
    return (
        f"# REVIEW REQUIRED. Covers {rule['coverage_count']} confirmed bypass variant(s).\n"
        f"{warning}"
        f"SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        f"    \"{action_lines}\"\n"
    )


def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
    records = [record for record in read_jsonl(input_path) if record.get("final_verdict") == "BYPASS_ORIGIN_CONFIRMED"]
    if not records:
        raise ValueError("No confirmed origin bypass records; run recheck first")

    clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    signatures: dict[str, tuple[str, str, str]] = {}
    for record in records:
        family, primitive, pattern = _select_signature(record)
        target = TARGETS.get(str(record.get("zone")), "REQUEST_URI")
        encoding = str(record.get("encoding", "NONE"))
        signature_key = f"{family}|{primitive}|{pattern}"
        signatures[signature_key] = (family, primitive, pattern)
        cluster_key = (record.get("group_id"), record.get("group_name"), target, encoding, signature_key)
        clusters[cluster_key].append(record)

    output_dir.mkdir(parents=True, exist_ok=True)
    rules: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    for offset, (key, covered) in enumerate(sorted(clusters.items(), key=lambda item: tuple(str(x) for x in item[0]))):
        group_id, group_name, target, encoding, signature_key = key
        family, primitive, pattern = signatures[signature_key]
        rule = {
            "rule_id": id_start + offset,
            "group_id": group_id,
            "group_name": group_name,
            "target": target,
            "encoding": encoding,
            "family": family,
            "primitive": primitive,
            "pattern": pattern,
            "transforms": _transforms(encoding, family),
            "tag": _tag(family),
            "coverage_count": len(covered),
            "review_status": "REVIEW_REQUIRED",
            "coverage_status": "PROPOSED_NOT_VALIDATED",
        }
        rules.append(rule)
        for record in covered:
            coverage_rows.append({
                "stable_key": stable_key(record),
                "payload_path": record["payload_path"],
                "variant": record["variant"],
                "group_id": group_id,
                "rule_id": rule["rule_id"],
                "primitive": primitive,
                "target": target,
                "encoding": encoding,
                "fallback": primitive == "narrow_fallback",
            })

    conf_path = output_dir / "candidate-rules.conf"
    with conf_path.open("w", encoding="utf-8") as handle:
        handle.write("# Auto-generated candidate SecLang rules. DO NOT auto-load.\n")
        handle.write("# Validate syntax, positive coverage and false positives before deployment.\n\n")
        for rule in rules:
            handle.write(_render_rule(rule))
            handle.write("\n")
    coverage_path = output_dir / "coverage.csv"
    with coverage_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(coverage_rows[0]))
        writer.writeheader()
        writer.writerows(coverage_rows)
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, {
        "source": str(input_path),
        "confirmed_bypass_variants": len(records),
        "candidate_rules": len(rules),
        "narrow_fallback_rules": sum(rule["primitive"] == "narrow_fallback" for rule in rules),
        "broad_family_fallback_rules": sum(rule["primitive"].endswith("_family_fallback") for rule in rules),
        "rules": rules,
    })
    if len(coverage_rows) != len(records):
        raise RuntimeError("Coverage matrix does not include every confirmed bypass variant")
    return {
        "confirmed_bypass_variants": len(records),
        "candidate_rules": len(rules),
        "coverage": str(coverage_path),
        "rules": str(conf_path),
        "manifest": str(manifest_path),
    }

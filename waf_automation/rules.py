from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, stable_key, write_json
from .curl_parser import STANDARD_HEADERS, extract_request

TARGETS = {
    "URL": "REQUEST_URI", "ARGS": "ARGS", "BODY": "REQUEST_BODY",
    "COOKIE": "REQUEST_COOKIES", "USER-AGENT": "REQUEST_HEADERS:User-Agent",
    "REFERER": "REQUEST_HEADERS:Referer",
}
SUPPORTED_ENCODINGS = {"NONE", "BASE64", "UTF-16", "HTML-ENTITY"}
SEPARATE_TARGET_ENCODINGS = {"BASE64", "UTF-16"}
DYNAMIC_HEADER_RE = re.compile(r"^(?:wbh|wbc)-[0-9a-f]+$", re.IGNORECASE)
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "xss": [
        ("xss_event_handler", r"<[^>]{0,256}\bon[a-z]{2,32}\s*="),
        ("xss_fragmented_event_handler", r"o(?:<[^>]{0,32}>)*n(?:<[^>]{0,32}>)*[a-z]{3,32}\s*="),
        ("xss_javascript_scheme", r"java[\s\x00-\x20]*script\s*:"),
        ("xss_scriptable_tag", r"<\s*(?:script|svg|img|iframe|object|embed|audio|video|math|form|input)\b"),
        ("xss_execution_sink", r"(?:alert|prompt|confirm|eval|settimeout|setinterval|import)\s*(?:[(]|`)"),
        ("xss_bracket_execution", r"\b(?:window|self|top)\s*\[[^]]{1,96}\]\s*[(]"),
    ],
    "sqli": [
        ("sqli_union_select", r"\bunion\b[\s\S]{0,64}\bselect\b"),
        ("sqli_union_select_comments", r"\bunion(?:\s|/[*][\s\S]{0,32}[*]/){1,8}select\b"),
        ("sqli_select_from", r"\bselect\b[\s\S]{0,96}\bfrom\b"),
        ("sqli_boolean", r"(?:\bor\b|\band\b)(?:\s|/[*][\s\S]{0,32}[*]/)+['0-9][^=]{0,32}(?:=|!=|<>|like)"),
        ("sqli_time_function", r"\b(?:sleep|benchmark|pg_sleep|waitfor)\s*[(]"),
    ],
    "command": [
        ("jndi_lookup", r"[$][{][\s\S]{0,192}j[\s\S]{0,48}n[\s\S]{0,48}d[\s\S]{0,48}i[\s\S]{0,48}:"),
        ("command_separator", r"(?:[;&|`]|[$][(])\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b"),
        ("command_substitution", r"[$][(][^)]{1,256}[)]"),
    ],
    "lfi": [
        ("path_traversal", r"(?:\.\.(?:/|\x5c)){1,}"),
        ("sensitive_local_file", r"(?:/etc/passwd|/proc/self|windows(?:/|\x5c)win\.ini)"),
        ("windows_sensitive_file", r"(?:[a-z]:)?(?:/|\x5c)(?:windows|winnt)(?:/|\x5c)(?:win\.ini|php\.ini|repair(?:/|\x5c)sam|system32(?:/|\x5c)config(?:/|\x5c)sam)"),
    ],
    "rfi": [
        ("php_wrapper", r"\bphp://(?:filter|input|memory|temp|fd|stdin|data)"),
        ("data_wrapper", r"\bdata:(?://)?(?:text|application)/[a-z0-9.+-]+[;,]"),
        ("remote_include_url", r"\b(?:https?|ftp)://[^\s]{1,256}\.(?:php|phtml|phar)(?:[?/#]|$)"),
    ],
    "ssrf": [
        ("internal_url", r"\b(?:https?|gopher|file|dict|ftp):/{1,3}(?:localhost|127\.|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"),
        ("non_http_scheme", r"\b(?:gopher|file|dict):/{1,3}"),
    ],
    "nosqli": [
        ("nosql_operator", r"[$](?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b"),
        ("nosql_javascript_predicate", r"\bthis\.[a-z_][a-z0-9_]*\.(?:match|test|includes)\s*[(]"),
    ],
    "ldap": [
        ("ldap_filter_injection", r"(?:\|[(]|&[(]|[)][(]|[*][)][(]|[(]objectclass\s*=|[*][)][)]|[*][(][)]|[)][|&][(])"),
    ],
    "ssti": [
        ("template_expression", r"(?:\{\{[\s\S]{1,256}\}\}|[$][{][\s\S]{1,256}\}|<%[\s\S]{1,256}%>)"),
        ("smarty_expression", r"\{[$][a-z_][a-z0-9_.]{0,128}\}"),
        ("spel_expression", r"[#]\{[\s\S]{1,256}\}"),
    ],
    "ssi": [("ssi_directive", r"<!--\s*#(?:exec|include|echo|config|set)\b")],
    "redirect": [
        ("redirect_parameter", r"(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//"),
        ("redirect_scheme_relative", r"^/{2,3}[a-z0-9.-]+(?:[/:?#]|$)"),
        ("redirect_userinfo", r"https?://[^/\s@]{1,128}@"),
        ("redirect_at_host", r"^@[a-z0-9.-]+(?:[/:?#]|$)"),
    ],
}


def _family(record: dict[str, Any]) -> str:
    category = str(record.get("category", "")).upper()
    if category == "XSS": return "xss"
    if category == "SQLI": return "sqli"
    if category in {"CM", "RCE"}: return "command"
    if category == "LFI": return "lfi"
    if category == "RFI": return "rfi"
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
    if encoding == "BASE64": result.extend(["t:base64DecodeExt", "t:urlDecodeUni"])
    if encoding == "UTF-16" or family == "xss": result.extend(["t:jsDecode", "t:urlDecodeUni"])
    if family == "xss": result.extend(["t:htmlEntityDecode", "t:cssDecode", "t:urlDecodeUni"])
    result.extend(["t:lowercase", "t:removeNulls"])
    return tuple(result)


def _header_names(record: dict[str, Any]) -> list[str]:
    command = str(record.get("curl") or "")
    if not command: return []
    try: headers = extract_request(command)["headers"]
    except (TypeError, ValueError): return []
    names: list[str] = []
    for header in headers:
        name, separator, _ = header.partition(":")
        normalized = name.strip()
        if not separator or normalized.lower() in STANDARD_HEADERS: continue
        if normalized not in names: names.append(normalized)
    return names


def _record_target(record: dict[str, Any]) -> tuple[str | None, str | None, bool]:
    zone = str(record.get("zone", "")).upper()
    if zone == "ARGS":
        component = str(record.get("payload_component") or "ARG_VALUE").upper()
        return ("ARGS_NAMES" if component == "ARG_NAME" else "ARGS"), None, False
    if zone != "HEADER":
        target = TARGETS.get(zone)
        return (target, None, False) if target else (None, "UNSUPPORTED_ZONE", False)
    names = _header_names(record)
    if len(names) != 1: return None, "AMBIGUOUS_OR_MISSING_HEADER_NAME", False
    name = names[0]
    if DYNAMIC_HEADER_RE.fullmatch(name): return "REQUEST_HEADERS", None, True
    if not HEADER_NAME_RE.fullmatch(name): return None, "INVALID_HEADER_NAME", False
    return f"REQUEST_HEADERS:{name}", None, False


def _deduplicate_targets(targets: set[str]) -> list[str]:
    if "REQUEST_HEADERS" in targets:
        targets = {target for target in targets if not target.startswith("REQUEST_HEADERS:")}
    return sorted(targets)


def _validate_pattern(pattern: str) -> None:
    if "(?i)" in pattern or "(?s)" in pattern: raise ValueError(f"Inline regex flags are not allowed: {pattern}")
    if "[/\\\\]" in pattern or "[\\\\/]" in pattern: raise ValueError(f"Ambiguous slash/backslash character class is not allowed: {pattern}")
    for escape in (r"\r", r"\n", r"\t"):
        if escape in pattern: raise ValueError(f"Legacy SecLang control escape is not allowed: {pattern}")
    if '"' in pattern: raise ValueError(f"Double quotes are not allowed in generated regex: {pattern}")
    re.compile(pattern)


def _render_rule(rule: dict[str, Any]) -> str:
    actions = [f"id:{rule['rule_id']}", "phase:2", "deny", *rule["transforms"],
               f"msg:'Candidate coverage for confirmed waf-bypass: {rule['primitive']}'",
               "tag:'waf-bypass-candidate'", "severity:'CRITICAL'", "setvar:tx.anomaly_score=+5"]
    warning = ""
    if rule.get("generic_header_target"):
        warning = ("# HIGH-RISK TARGET: REQUEST_HEADERS scans all request-header values. "
                   "This may increase false positives and per-request CPU cost; benchmark and tune before production.\n")
    return (
        f"# Covers {rule['coverage_count']} confirmed bypass variant(s); targets={','.join(rule['targets'])}; encodings={','.join(rule['encodings'])}.\n"
        + warning
        + "# REVIEW REQUIRED: validate converter compatibility, coverage and false positives before production.\n"
        + f"SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        + f"    \"{',\\\n    '.join(actions)}\"\n"
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)


def _skip_row(record: dict[str, Any], reason: str, detail: str, family: str | None = None) -> dict[str, Any]:
    normalized = str(record.get("normalized_payload") or "")
    return {
        "stable_key": stable_key(record), "payload_path": record.get("payload_path"),
        "variant": record.get("variant"), "group_id": record.get("group_id"),
        "category": record.get("category"), "family": family or _family(record),
        "zone": record.get("zone"), "encoding": record.get("encoding"),
        "payload_component": record.get("payload_component"), "payload_name": record.get("payload_name"),
        "normalization_complete": record.get("normalization_complete"),
        "normalization_steps": ">".join(record.get("normalization_steps") or []),
        "reason": reason, "detail": detail,
        "normalized_payload_preview": normalized[:240],
    }


def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
    records = [r for r in read_jsonl(input_path) if r.get("final_verdict") in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}]
    if not records: raise ValueError("No confirmed bypass records; run verify first")
    clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    signatures: dict[str, tuple[str, str, str]] = {}
    skipped_rows: list[dict[str, Any]] = []

    for record in records:
        encoding = str(record.get("encoding", "NONE")).upper()
        if encoding not in SUPPORTED_ENCODINGS:
            skipped_rows.append(_skip_row(record, "UNSUPPORTED_ENCODING", f"Encoding {encoding} has no supported transform profile")); continue
        target, target_error, generic_header = _record_target(record)
        if target_error:
            skipped_rows.append(_skip_row(record, target_error, "Request location cannot be mapped to a safe SecLang collection")); continue
        signature = _select_signature(record)
        if signature is None:
            family = _family(record)
            reason = "UNSUPPORTED_FAMILY" if family == "generic" else "KNOWN_FAMILY_MISSING_SIGNATURE"
            detail = "No primitive library exists for this category" if family == "generic" else "Normalized payload did not match any current primitive"
            if record.get("normalization_complete") is False:
                reason, detail = "NORMALIZATION_INCOMPLETE", "Normalization stopped before reaching a stable representation"
            skipped_rows.append(_skip_row(record, reason, detail, family)); continue
        family, primitive, pattern = signature
        _validate_pattern(pattern)
        transforms = _transforms(encoding, family)
        signature_key = f"{family}|{primitive}|{pattern}"
        signatures[signature_key] = signature
        target_partition = target if encoding in SEPARATE_TARGET_ENCODINGS else "MERGED"
        clusters[(record.get("group_id"), record.get("group_name"), signature_key, transforms, target_partition)].append(
            {**record, "_rule_target": target, "_generic_header_target": generic_header}
        )

    if not clusters: raise ValueError("Confirmed bypasses were found, but none matched a supported exploit primitive")
    rules: list[dict[str, Any]] = []; coverage_rows: list[dict[str, Any]] = []
    for offset, (key, covered) in enumerate(sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))):
        group_id, group_name, signature_key, transforms, _ = key
        family, primitive, pattern = signatures[signature_key]
        targets = _deduplicate_targets({str(r["_rule_target"]) for r in covered})
        encodings = sorted({str(r.get("encoding", "NONE")).upper() for r in covered})
        rule = {
            "rule_id": id_start + offset, "group_id": group_id, "group_name": group_name,
            "target": "|".join(targets), "targets": targets, "encodings": encodings,
            "family": family, "primitive": primitive, "pattern": pattern,
            "transforms": list(transforms), "coverage_count": len(covered),
            "generic_header_target": any(bool(r["_generic_header_target"]) for r in covered),
            "review_status": "REVIEW_REQUIRED", "coverage_status": "PROPOSED_NOT_VALIDATED",
        }
        rules.append(rule)
        for record in covered:
            coverage_rows.append({
                "stable_key": stable_key(record), "payload_path": record["payload_path"], "variant": record["variant"],
                "group_id": group_id, "rule_id": rule["rule_id"], "primitive": primitive,
                "zone": record.get("zone"), "encoding": record.get("encoding"), "rule_target": rule["target"],
                "grouped_rule": len(covered) > 1, "generic_header_target": bool(record["_generic_header_target"]),
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "candidate-rules.conf"
    conf_path.write_text(
        "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n"
        "# Dynamic scanner headers may map to REQUEST_HEADERS; such rules have explicit FP/load warnings.\n"
        "# Only recognized exploit primitives are emitted; fallback payload rules are skipped.\n\n"
        + "\n".join(_render_rule(rule) for rule in rules), encoding="utf-8")
    coverage_path = output_dir / "coverage.csv"
    _write_csv(coverage_path, coverage_rows, ["stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive", "zone", "encoding", "rule_target", "grouped_rule", "generic_header_target"])
    skipped_path = output_dir / "skipped.csv"
    skipped_fields = ["stable_key", "payload_path", "variant", "group_id", "category", "family", "zone", "encoding", "payload_component", "payload_name", "normalization_complete", "normalization_steps", "reason", "detail", "normalized_payload_preview"]
    _write_csv(skipped_path, skipped_rows, skipped_fields)

    grouped_rules = sum(rule["coverage_count"] > 1 for rule in rules)
    covered_variants = len(coverage_rows)
    reason_counts = dict(sorted(Counter(row["reason"] for row in skipped_rows).items()))
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, {
        "source": str(input_path), "confirmed_bypass_variants": len(records), "covered_variants": covered_variants,
        "skipped_variants": len(skipped_rows), "candidate_rules": len(rules), "grouped_rules": grouped_rules,
        "max_variants_per_rule": max(rule["coverage_count"] for rule in rules), "skip_reason_counts": reason_counts,
        "generation_policy": {
            "recognized_primitives_only": True, "family_fallbacks": False, "narrow_fallbacks": False,
            "dynamic_test_headers_target": "REQUEST_HEADERS", "generic_header_fp_risk": "HIGH",
            "generic_header_load_risk": "INCREASED", "split_targets_for_encodings": sorted(SEPARATE_TARGET_ENCODINGS),
            "supported_encodings": sorted(SUPPORTED_ENCODINGS), "legacy_seclang_safe_regex": True,
            "iterative_transport_decoding": True, "args_name_targeting": True,
        }, "rules": rules,
    })
    if covered_variants + len(skipped_rows) != len(records): raise RuntimeError("Each confirmed bypass must be covered or explicitly skipped")
    return {
        "confirmed_bypass_variants": len(records), "covered_variants": covered_variants, "skipped_variants": len(skipped_rows),
        "candidate_rules": len(rules), "grouped_rules": grouped_rules, "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
        "skip_reason_counts": reason_counts, "generic_header_rules": sum(bool(rule["generic_header_target"]) for rule in rules),
        "coverage": str(coverage_path), "skipped": str(skipped_path), "rules": str(conf_path), "manifest": str(manifest_path),
    }

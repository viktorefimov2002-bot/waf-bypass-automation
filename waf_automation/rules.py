from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, stable_key, write_json, write_jsonl
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
ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff"
_ZW = f"[{ZERO_WIDTH_CHARS}]*"

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "xss": [
        ("xss_event_handler", r"<[^>]{0,256}\bon[a-z]{2,32}\s*="),
        ("xss_fragmented_event_handler", r"o(?:<[^>]{0,32}>)*n(?:<[^>]{0,32}>)*[a-z]{3,32}\s*="),
        ("xss_javascript_scheme", r"java[\s\x00-\x20]*script\s*:"),
        ("xss_javascript_href", r"<a[^>]{0,256}\bhref\s*=\s*[^>]{0,96}java[\s\x00-\x20]*script\s*:"),
        ("xss_scriptable_tag", r"<\s*(?:script|svg|img|iframe|object|embed|audio|video|math|form|input)\b"),
        ("xss_namespaced_script", r"<[a-z][a-z0-9_-]*:script\b"),
        ("xss_bidi_script_tag", r"<[\u202a-\u202e\u2066-\u2069]*script\b"),
        ("xss_execution_sink", r"(?:alert|prompt|confirm|eval|settimeout|setinterval|import)\s*(?:[(]|`)"),
        ("xss_call_apply", r"\b(?:alert|confirm|prompt)\s*[.]\s*(?:call|apply)\s*[(]"),
        ("xss_array_callback", r"\[[^]]{1,96}\]\s*[.]\s*(?:map|find|sort|with)\s*[(][^)]{0,96}(?:alert|confirm|prompt)"),
        ("xss_function_tag", r"\b(?:function|constructor)\s*`"),
        ("xss_bracket_execution", r"\b(?:window|self|top)\s*\[[^]]{1,96}\]\s*[(]"),
        ("xss_location_assignment", r"\blocation\s*=\s*[a-z_][a-z0-9_]*\s*;"),
        ("xss_css_javascript_url", r"background-image\s*:\s*url\s*[(][^)]{0,256}javascript\s*:"),
        ("xss_concatenated_sink", r"(?:[\x22']a(?:le|l)[\x22']\s*[+]\s*[\x22'](?:rt|ert)[\x22']|[\x22']ale[\x22']\s*[+]\s*[\x22']rt[\x22'])\s*[(]"),
        ("xss_whitespace_sink", r"a\s+l\s+e\s+r\s+t\s*[(]"),
        ("xss_parenthesized_sink", r"[(]\s*(?:alert|confirm|prompt)\s*[)]\s*[(]"),
        ("xss_tagged_call", r"(?:alert|confirm|prompt)\s*[.]\s*(?:call|apply)\s*`"),
        ("xss_computed_window_call", r"\b(?:window|self|top)\s*\[[^]]{1,128}\]\s*[(]"),
        ("xss_constructor_chain", r"\bconstructor\s*\[[^]]{1,96}\]\s*[(]"),
    ],
    "sqli": [
        ("sqli_zero_width_union_select", rf"u{_ZW}n{_ZW}i{_ZW}o{_ZW}n[\s\S]{{0,64}}s{_ZW}e{_ZW}l{_ZW}e{_ZW}c{_ZW}t"),
        ("sqli_quoted_fragment_union_select", r"uni[\x22'][,]?[\x22']on\s+sel[\x22'][,]?[\x22']ect"),
        ("sqli_split_keyword_tokens", r"u(?:ni|n)[\x22'][,]?[\x22']on[\s\S]{0,32}s(?:el|e)[\x22'][,]?[\x22']ect"),
        ("sqli_fragmented_union_select", r"u(?:n|[\\][\x22'][,]?[\\][\x22']n)[\s\S]{0,24}ion[\s\S]{0,32}s(?:e|[\\][\x22'][,]?[\\][\x22']e)[\s\S]{0,24}lect"),
        ("sqli_union_select", r"\bunion\b[\s\S]{0,64}\bselect\b"),
        ("sqli_union_select_comments", r"\bunion(?:\s|/[*][\s\S]{0,32}[*]/){1,8}select\b"),
        ("sqli_select_from", r"\bselect\b[\s\S]{0,96}\bfrom\b"),
        ("sqli_boolean", r"(?:\bor\b|\band\b)(?:\s|/[*][\s\S]{0,32}[*]/)+['0-9][^=]{0,32}(?:=|!=|<>|like)"),
        ("sqli_time_function", r"\b(?:sleep|benchmark|pg_sleep|waitfor)\s*[(]"),
    ],
    "command": [
        ("jndi_lookup", r"[$][\\]?[{][\s\S]{0,192}j[\s\S]{0,48}n[\s\S]{0,48}d[\s\S]{0,48}i[\s\S]{0,48}:"),
        ("command_separator", r"(?:[;&|`]|[$][(])\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b"),
        ("command_substitution", r"[$][(][^)]{1,256}[)]"),
        ("command_obfuscated_cat", r"(?:^|[;&|])[\s\S]{0,96}c[^a-z0-9]{0,4}a[^a-z0-9]{0,4}t[\s\S]{0,96}(?:/etc/passwd|/e[^a-z0-9]{0,4}t[^a-z0-9]{0,4}c)"),
        ("command_parameter_chain", r"\bcmd\s*=\s*[^\s]{0,128}(?:[+ ]&&[+ ]|[+ ]\|[+ ])(?:ls|cat|id|whoami)\b"),
        ("command_backslash_split_cat", r"(?:^|[;&|])[^\x0d\x0a]{0,96}c(?:[\\][a-z0-9]?)*a(?:[\\][a-z0-9]?)*t[^\x0d\x0a]{0,96}/e(?:[\\][a-z0-9]?)*t(?:[\\][a-z0-9]?)*c/passwd"),
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
        ("remote_non_http_scheme", r"\b(?:sftp|tftp|ldap)://[^/\s:]+(?::[0-9]{1,5})?(?:/|$)"),
        ("obfuscated_file_uri", r"\bfile\s*:[\s\S]{0,96}/[^?\s]{1,256}(?:passwd|shadow|win\.ini)"),
    ],
    "nosqli": [
        ("nosql_operator", r"[$](?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b"),
        ("nosql_javascript_predicate", r"\bthis\.[a-z_][a-z0-9_]*\.(?:match|test|includes)\s*[(]"),
        ("nosql_return_predicate", r"(?:^|[;'\/])\s*return\s+[' ]{0,4}==\s*[' ]{0,4}"),
        ("nosql_duplicate_roles", r"[\x22']roles[\x22']\s*:[\s\S]{0,128}[\x22']roles[\x22']\s*:"),
    ],
    "ldap": [
        ("ldap_filter_injection", r"(?:\|[(]|&[(]|[)][(]|[*][)][(]|[(]objectclass\s*=|[*][)][)]|[*][(][)]|[)][|&][(])"),
        ("xpath_boolean_injection", r"[' ]\s+or\s+[a-z_][a-z0-9_-]*\s*[(][)]\s*=\s*[' ]"),
    ],
    "ssti": [
        ("template_expression", r"(?:\{\{[\s\S]{1,256}\}\}|[$][{][\s\S]{1,256}\}|<%[\s\S]{1,256}%>)"),
        ("smarty_expression", r"\{[$][a-z_][a-z0-9_.]{0,128}\}"),
        ("spel_expression", r"[#]\{[\s\S]{1,256}\}"),
        ("thymeleaf_expression", r"[*]\{[\s\S]{1,256}\}"),
        ("at_expression", r"@[(][\s\S]{1,128}[)]"),
    ],
    "ssi": [("ssi_directive", r"<!--\s*#(?:exec|include|echo|config|set)\b")],
    "redirect": [
        ("redirect_parameter", r"(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//"),
        ("redirect_scheme_relative", r"^/{2,3}[a-z0-9.-]+(?:[/:?#]|$)"),
        ("redirect_userinfo", r"https?://[^/\s@]{1,128}@"),
        ("redirect_at_host", r"^@[a-z0-9.-]+(?:[/:?#]|$)"),
        ("redirect_ipv6_literal", r"https?://\[(?:::ffff:)?[0-9a-f:.]+\]"),
        ("redirect_crlf_location", r"[\x0d\x0a]+[0-9]*location\s*:\s*https?://"),
    ],
    "graphql": [("graphql_introspection", r"(?:__schema\b|__type\s*[(]|fragment\s+fulltype\s+on\s+__type)")],
    "exposure": [
        ("exposed_vcs", r"^/[.]git(?:/|$)"),
        ("backup_archive", r"^/(?:[.]/)?(?:backup(?:/|[.])|backup/[^\s]{0,128}|[^/\s]*(?:backup|db)[^/\s]*[.](?:zip|gz|tgz|tar))(?:$|[?#])"),
        ("webshell_php_path", r"/(?:wso|do)[.]php(?:$|[;#.\x0a\x0d])"),
    ],
}

STEP_TO_TRANSFORM = {
    "percent": "t:urlDecodeUni",
    "base64": "t:base64DecodeExt",
    "js_unicode": "t:jsDecode",
    "html_entity": "t:htmlEntityDecode",
    "remove_nulls": "t:removeNulls",
}
ENCODING_FALLBACK_TRANSFORM = {
    "BASE64": "t:base64DecodeExt",
    "UTF-16": "t:jsDecode",
    "HTML-ENTITY": "t:htmlEntityDecode",
}


def _family(record: dict[str, Any]) -> str:
    category = str(record.get("category", "")).upper()
    return {
        "XSS": "xss", "SQLI": "sqli", "CM": "command", "RCE": "command",
        "LFI": "lfi", "RFI": "rfi", "SSRF": "ssrf", "NOSQLI": "nosqli",
        "LDAP": "ldap", "SSTI": "ssti", "SSI": "ssi", "OR": "redirect",
        "GRAPHQL": "graphql", "UWA": "exposure",
    }.get(category, "generic")


def _select_signature(record: dict[str, Any]) -> tuple[str, str, str] | None:
    family = _family(record)
    payload = str(record.get("normalized_payload") or record.get("raw_payload") or "").lower()
    for primitive, pattern in SIGNATURES.get(family, []):
        if re.search(pattern, payload):
            return family, primitive, pattern
    return None


def _normalization_steps(record: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(step).strip().lower() for step in (record.get("normalization_steps") or []) if str(step).strip())


def _transforms(record: dict[str, Any]) -> tuple[str, ...]:
    result = ["t:none"]
    steps = _normalization_steps(record)
    for step in steps:
        transform = STEP_TO_TRANSFORM.get(step)
        if transform:
            result.append(transform)
    if not steps:
        fallback = ENCODING_FALLBACK_TRANSFORM.get(str(record.get("encoding", "NONE")).upper())
        if fallback:
            result.append(fallback)
    result.append("t:lowercase")
    return tuple(result)


def _phase_for_record(record: dict[str, Any]) -> int:
    return 2 if str(record.get("zone", "")).upper() == "BODY" else 1


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
    actions = [f"id:{rule['rule_id']}", f"phase:{rule['phase']}", "deny", *rule["transforms"],
               f"msg:'Candidate coverage for confirmed waf-bypass: {rule['primitive']}'",
               "tag:'waf-bypass-candidate'", "severity:'CRITICAL'", "setvar:tx.anomaly_score=+5"]
    action_lines = ",\\\n    ".join(actions)
    warning = ""
    if rule.get("generic_header_target"):
        warning = ("# HIGH-RISK TARGET: REQUEST_HEADERS scans all request-header values. "
                   "This may increase false positives and per-request CPU cost; benchmark and tune before production.\n")
    return (
        f"# Covers {rule['coverage_count']} confirmed bypass variant(s); phase={rule['phase']}; targets={','.join(rule['targets'])}; encodings={','.join(rule['encodings'])}.\n"
        + warning
        + "# REVIEW REQUIRED: validate converter compatibility, coverage and false positives before production.\n"
        + f"SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        + f"    \"{action_lines}\"\n"
    )


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)


def _skip_row(record: dict[str, Any], reason: str, detail: str, family: str | None = None) -> dict[str, Any]:
    normalized = str(record.get("normalized_payload") or "")
    invisible = [f"U+{ord(ch):04X}" for ch in normalized if ch in ZERO_WIDTH_CHARS]
    return {
        "stable_key": stable_key(record), "payload_path": record.get("payload_path"),
        "variant": record.get("variant"), "group_id": record.get("group_id"),
        "category": record.get("category"), "family": family or _family(record),
        "zone": record.get("zone"), "encoding": record.get("encoding"),
        "payload_component": record.get("payload_component"), "payload_name": record.get("payload_name"),
        "normalization_complete": record.get("normalization_complete"),
        "normalization_steps": ">".join(record.get("normalization_steps") or []),
        "reason": reason, "detail": detail,
        "invisible_codepoints": ",".join(sorted(set(invisible))),
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
        transforms = _transforms(record)
        phase = _phase_for_record(record)
        signature_key = f"{family}|{primitive}|{pattern}"
        signatures[signature_key] = signature
        target_partition = target if encoding in SEPARATE_TARGET_ENCODINGS else "MERGED"
        clusters[(record.get("group_id"), record.get("group_name"), signature_key, transforms, phase, target_partition)].append(
            {**record, "_rule_target": target, "_generic_header_target": generic_header}
        )
    if not clusters: raise ValueError("Confirmed bypasses were found, but none matched a supported exploit primitive")
    rules: list[dict[str, Any]] = []; coverage_rows: list[dict[str, Any]] = []
    for offset, (key, covered) in enumerate(sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))):
        group_id, group_name, signature_key, transforms, phase, _ = key
        family, primitive, pattern = signatures[signature_key]
        targets = _deduplicate_targets({str(r["_rule_target"]) for r in covered})
        encodings = sorted({str(r.get("encoding", "NONE")).upper() for r in covered})
        step_profiles = sorted({">".join(_normalization_steps(r)) or "NONE" for r in covered})
        rule = {
            "rule_id": id_start + offset, "group_id": group_id, "group_name": group_name,
            "target": "|".join(targets), "targets": targets, "encodings": encodings,
            "family": family, "primitive": primitive, "pattern": pattern,
            "transforms": list(transforms), "phase": phase, "normalization_step_profiles": step_profiles,
            "coverage_count": len(covered),
            "generic_header_target": any(bool(r["_generic_header_target"]) for r in covered),
            "review_status": "REVIEW_REQUIRED", "coverage_status": "PROPOSED_NOT_VALIDATED",
        }
        rules.append(rule)
        for record in covered:
            coverage_rows.append({
                "stable_key": stable_key(record), "payload_path": record["payload_path"], "variant": record["variant"],
                "group_id": group_id, "rule_id": rule["rule_id"], "primitive": primitive,
                "zone": record.get("zone"), "encoding": record.get("encoding"), "rule_target": rule["target"],
                "phase": phase, "normalization_steps": ">".join(_normalization_steps(record)),
                "transform_profile": ">".join(transforms),
                "grouped_rule": len(covered) > 1, "generic_header_target": bool(record["_generic_header_target"]),
                "normalized_payload": record.get("normalized_payload"),
            })
    output_dir.mkdir(parents=True, exist_ok=True)
    conf_path = output_dir / "candidate-rules.conf"
    conf_path.write_text(
        "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n"
        "# Dynamic scanner headers may map to REQUEST_HEADERS; such rules have explicit FP/load warnings.\n"
        "# Transform profiles follow recorded normalization_steps; request phase follows the payload zone.\n"
        "# Only recognized exploit primitives are emitted; fallback payload rules are skipped.\n\n"
        + "\n".join(_render_rule(rule) for rule in rules), encoding="utf-8")
    coverage_fields = ["stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive", "zone", "encoding", "rule_target", "phase", "normalization_steps", "transform_profile", "grouped_rule", "generic_header_target", "normalized_payload"]
    coverage_path = output_dir / "coverage.csv"; _write_csv(coverage_path, coverage_rows, coverage_fields)
    coverage_jsonl_path = output_dir / "coverage.jsonl"; write_jsonl(coverage_jsonl_path, coverage_rows)
    skipped_fields = ["stable_key", "payload_path", "variant", "group_id", "category", "family", "zone", "encoding", "payload_component", "payload_name", "normalization_complete", "normalization_steps", "reason", "detail", "invisible_codepoints", "normalized_payload_preview"]
    skipped_path = output_dir / "skipped.csv"; _write_csv(skipped_path, skipped_rows, skipped_fields)
    skipped_jsonl_path = output_dir / "skipped.jsonl"; write_jsonl(skipped_jsonl_path, skipped_rows)
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
            "zero_width_sql_patterns": True, "csv_and_jsonl_indexes": True,
            "skipped_payload_revision": True, "quoted_fragment_patterns": True,
            "normalization_trace_driven_transforms": True, "phase_selected_by_request_zone": True,
        }, "rules": rules,
    })
    if covered_variants + len(skipped_rows) != len(records): raise RuntimeError("Each confirmed bypass must be covered or explicitly skipped")
    return {
        "confirmed_bypass_variants": len(records), "covered_variants": covered_variants, "skipped_variants": len(skipped_rows),
        "candidate_rules": len(rules), "grouped_rules": grouped_rules, "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
        "skip_reason_counts": reason_counts, "generic_header_rules": sum(bool(rule["generic_header_target"]) for rule in rules),
        "coverage": str(coverage_path), "coverage_jsonl": str(coverage_jsonl_path),
        "skipped": str(skipped_path), "skipped_jsonl": str(skipped_jsonl_path),
        "rules": str(conf_path), "manifest": str(manifest_path),
    }

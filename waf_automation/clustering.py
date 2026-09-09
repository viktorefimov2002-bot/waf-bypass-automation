from __future__ import annotations

import hashlib
import re
from typing import Any


ATTACK_FAMILY_BY_CATEGORY = {
    "XSS": "xss",
    "SQLI": "sqli",
    "CM": "command",
    "RCE": "command",
    "LFI": "lfi",
    "RFI": "rfi",
    "SSRF": "ssrf",
    "NOSQLI": "nosqli",
    "LDAP": "ldap",
    "SSTI": "ssti",
    "SSI": "ssi",
    "OR": "redirect",
    "GRAPHQL": "graphql",
    "UWA": "generic_web_attack",
}

# These are corpus-clustering primitives, not WAF rules. They intentionally use
# coarse semantic concepts so clusters remain stable while detection rules evolve.
PRIMITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("xss_event_handler", r"<[^>]{0,384}\bon[a-z]{2,32}\s*="),
    ("xss_scriptable_tag", r"<\s*(?:script|svg|img|iframe|object|embed|math|form|input)\b"),
    ("xss_javascript_scheme", r"j[\s\x00-\x20]*a[\s\x00-\x20]*v[\s\x00-\x20]*a[\s\x00-\x20]*s[\s\x00-\x20]*c[\s\x00-\x20]*r[\s\x00-\x20]*i[\s\x00-\x20]*p[\s\x00-\x20]*t\s*:"),
    ("xss_execution_sink", r"\b(?:alert|prompt|confirm|eval|settimeout|setinterval)\s*(?:[(]|`)"),
    ("sqli_union_select", r"\bunion\b[\s\S]{0,96}\bselect\b"),
    ("sqli_select_from", r"\bselect\b[\s\S]{0,128}\bfrom\b"),
    ("sqli_time_based", r"\b(?:sleep|benchmark|pg_sleep|waitfor)\s*(?:[(]|\b)"),
    ("command_separator", r"(?:[;|`]|&&|[$][(])\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|powershell|cmd)\b"),
    ("command_substitution", r"[$][(][^)]{1,256}[)]"),
    ("path_traversal", r"(?:\.\.(?:/|\\)){1,}"),
    ("sensitive_local_file", r"(?:/etc/passwd|/proc/self|windows(?:/|\\)win[.]ini)"),
    ("php_wrapper", r"\bphp://(?:filter|input|memory|temp|fd|stdin|data)"),
    ("remote_include_url", r"\b(?:https?|ftp)://[^\s]{1,256}[.](?:php|phtml|phar)(?:[?/#]|$)"),
    ("ssrf_internal_target", r"\b(?:https?|gopher|file|dict|ftp):/{1,3}(?:localhost|127[.]|169[.]254[.]|10[.]|192[.]168[.]|172[.](?:1[6-9]|2\d|3[01])[.])"),
    ("ssrf_non_http_scheme", r"\b(?:gopher|file|dict|ldap|sftp|tftp):/{1,3}"),
    ("nosql_operator", r"[$](?:where|ne|nin|gt|gte|lt|lte|regex|exists)\b"),
    ("ldap_filter_injection", r"(?:\|[(]|&[(]|[)][(]|[(]objectclass\s*=)"),
    ("template_expression", r"(?:\{\{[\s\S]{1,256}\}\}|[$][{][\s\S]{1,256}\}|<%[\s\S]{1,256}%>)"),
    ("ssi_directive", r"<!--\s*#(?:exec|include|echo|config|set)\b"),
    ("open_redirect", r"(?:redirect|redir|return|returnurl|next|continue|url)\s*=\s*(?:https?:)?//"),
    ("graphql_introspection", r"(?:__schema\b|__type\s*[(])"),
)


def attack_family(category: str, payload_path: str = "") -> tuple[str, str]:
    category_upper = str(category or "").upper()
    if category_upper in ATTACK_FAMILY_BY_CATEGORY:
        return ATTACK_FAMILY_BY_CATEGORY[category_upper], "category"
    prefix = str(payload_path or "").split("/", 1)[0].upper()
    if prefix in ATTACK_FAMILY_BY_CATEGORY:
        return ATTACK_FAMILY_BY_CATEGORY[prefix], "payload_path"
    return "unknown", "unclassified"


def detect_primitives(payload: str) -> list[str]:
    value = str(payload or "").lower()
    matches = [name for name, pattern in PRIMITIVE_PATTERNS if re.search(pattern, value, re.IGNORECASE)]
    return list(dict.fromkeys(matches))


def structural_tags(payload: str) -> list[str]:
    value = str(payload or "")
    tags: list[str] = []
    if re.search(r"https?://", value, re.IGNORECASE):
        tags.append("absolute_url")
    if "../" in value or "..\\" in value:
        tags.append("traversal")
    if re.search(r"<[a-z!/][^>]*>", value, re.IGNORECASE):
        tags.append("markup")
    if re.search(r"(?:%[0-9a-f]{2}){2,}", value, re.IGNORECASE):
        tags.append("percent_encoded_shape")
    if re.search(r"\\(?:u[0-9a-f]{4}|x[0-9a-f]{2})", value, re.IGNORECASE):
        tags.append("escaped_codepoints")
    if re.search(r"[$][{(]|\{\{|<%", value):
        tags.append("expression_syntax")
    if any(token in value for token in (";", "&&", "||", "`")):
        tags.append("command_or_statement_separator")
    return tags


def build_cluster_metadata(record: dict[str, Any]) -> dict[str, Any]:
    payload = str(record.get("normalized_payload") or record.get("raw_payload") or "")
    family, family_source = attack_family(str(record.get("category") or ""), str(record.get("payload_path") or ""))
    primitives = detect_primitives(payload)
    tags = structural_tags(payload)
    primary_primitive = primitives[0] if primitives else "unresolved_primitive"
    zone = str(record.get("zone") or "UNKNOWN").upper()
    component = str(record.get("payload_component") or "UNKNOWN").upper()
    encoding = str(record.get("encoding") or "NONE").upper()
    steps = tuple(sorted({str(step).lower() for step in record.get("normalization_steps") or []}))
    normalization_profile = "+".join(steps) if steps else "none"

    fingerprint_source = "|".join((family, primary_primitive, zone, component, encoding, normalization_profile))
    digest = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16]
    return {
        "attack_family": family,
        "attack_family_source": family_source,
        "detected_primitives": primitives,
        "primary_primitive": primary_primitive,
        "structural_tags": tags,
        "normalization_profile": normalization_profile,
        "cluster_key": f"{family}:{primary_primitive}:{zone}:{digest}",
        "cluster_basis": {
            "family": family,
            "primitive": primary_primitive,
            "zone": zone,
            "component": component,
            "encoding": encoding,
            "normalization_profile": normalization_profile,
        },
    }

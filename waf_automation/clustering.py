from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl
from .curl_parser import normalize_payload_details


CLUSTER_SCHEMA_VERSION = 2

_LONG_HEX_RE = re.compile(r"(?i)\b(?:0x)?[0-9a-f]{8,}\b")
_NUMBER_RE = re.compile(r"\b\d+\b")
_WHITESPACE_RE = re.compile(r"\s+")
_QUOTED_RE = re.compile(r"(['\"])(?:\\.|(?!\1).){1,96}\1")
_SCANNER_ASSIGNMENT_RE = re.compile(r"(?i)^(?:param[0-9a-f]{4,16}|url)=")

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

# Corpus-clustering primitives, intentionally coarser than WAF rules so they
# remain stable while rule implementations evolve.
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


def _hash(prefix: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"wba-{prefix}-{digest}"


def attack_family(category: str, payload_path: str = "") -> tuple[str, str]:
    category_upper = str(category or "").upper()
    if category_upper in ATTACK_FAMILY_BY_CATEGORY:
        return ATTACK_FAMILY_BY_CATEGORY[category_upper], "category"
    prefix = str(payload_path or "").split("/", 1)[0].upper()
    if prefix in ATTACK_FAMILY_BY_CATEGORY:
        return ATTACK_FAMILY_BY_CATEGORY[prefix], "payload_path"
    return "unknown", "unclassified"


def detect_primitives(payload: str) -> list[str]:
    value = str(payload or "")
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


def _transport_payload(record: dict[str, Any]) -> str:
    raw = str(record.get("raw_payload") or record.get("normalized_payload") or "").strip()
    zone = str(record.get("zone") or "").upper()

    if zone == "REFERER" and re.match(r"(?i)^https?://", raw) and "?" in raw:
        raw = raw.split("?", 1)[1]
    if zone == "URL" and raw.startswith("/"):
        raw = raw[1:]

    assignment = _SCANNER_ASSIGNMENT_RE.match(raw)
    if assignment:
        raw = raw[assignment.end():]
    return raw


def canonical_semantic_payload(record: dict[str, Any]) -> str:
    """Best-effort normalized payload after scanner transport wrappers are removed."""
    candidate = _transport_payload(record)
    encoding = str(record.get("encoding") or "NONE")
    try:
        normalized = normalize_payload_details(candidate, encoding)["value"]
    except Exception:
        normalized = candidate
    return unicodedata.normalize("NFKC", str(normalized or "")).strip()


def structural_signature(record: dict[str, Any]) -> str:
    text = canonical_semantic_payload(record).casefold()
    text = _LONG_HEX_RE.sub("<hex>", text)
    text = _NUMBER_RE.sub("<n>", text)
    text = _QUOTED_RE.sub(lambda match: f"{match.group(1)}<str>{match.group(1)}", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def classify_payload_techniques(record: dict[str, Any]) -> list[str]:
    raw = str(record.get("raw_payload") or "")
    normalized = canonical_semantic_payload(record)
    lower = normalized.casefold()
    techniques: set[str] = {
        f"normalization:{str(step).casefold()}"
        for step in (record.get("normalization_steps") or [])
        if str(step).strip()
    }

    if re.search(r"%[0-9a-fA-F]{2}", raw):
        techniques.add("obfuscation:percent-encoding")
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{2,3}", raw):
        techniques.add("obfuscation:escaped-codepoints")
    if re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);", raw):
        techniques.add("obfuscation:html-entity")
    if "/*" in normalized and "*/" in normalized:
        techniques.add("syntax:block-comment")
    if "--" in normalized or re.search(r"(^|\s)#[^\s]", normalized):
        techniques.add("syntax:line-comment")
    if any(token in normalized for token in ("'", '"', "`")):
        techniques.add("syntax:quoted-literal")
    if "[" in normalized and "]" in normalized:
        techniques.add("syntax:bracket-indexing")
    if "(" in normalized and ")" in normalized:
        techniques.add("syntax:function-call")
    if re.search(r"[+|&]{1,2}", normalized):
        techniques.add("syntax:operator-composition")
    if re.search(r"(?i)\b(?:https?|ftp|file|data|javascript):", normalized):
        techniques.add("syntax:uri-scheme")
    if "<" in normalized and ">" in normalized:
        techniques.add("syntax:markup")
    if re.search(r"(?:\.\./|\.\.\\){1,}", normalized):
        techniques.add("syntax:path-traversal")
    if re.search(r"(?:\$\{|\{\{|\{%|<%)", normalized):
        techniques.add("syntax:template-delimiter")
    if re.search(r"(?i)\b(?:union\s+select|select\s+.+\s+from|sleep\s*\(|benchmark\s*\()", lower):
        techniques.add("primitive:sql-expression")
    if re.search(r"(?i)(?:^|[;&|`])\s*(?:sh|bash|cmd|powershell|curl|wget|nc|ncat)\b", lower):
        techniques.add("primitive:command-expression")
    if re.search(r"(?i)(?:^|[^a-z])(?:o:\d+:|a:\d+:\{|ro0ab)", normalized):
        techniques.add("primitive:serialized-object")

    return sorted(techniques)


def build_payload_classification(record: dict[str, Any]) -> dict[str, Any]:
    semantic = canonical_semantic_payload(record)
    structure = structural_signature(record)
    category = str(record.get("category") or "UNKNOWN").upper()
    payload_path = str(record.get("payload_path") or "")
    family, family_source = attack_family(category, payload_path)
    primitives = detect_primitives(semantic)
    primary_primitive = primitives[0] if primitives else "unresolved_primitive"
    source_material = f"{category}\0{payload_path or record.get('case_id') or semantic}"
    return {
        "cluster_schema_version": CLUSTER_SCHEMA_VERSION,
        "attack_family": family,
        "attack_family_source": family_source,
        "detected_primitives": primitives,
        "primary_primitive": primary_primitive,
        "structural_tags": structural_tags(semantic),
        "source_cluster_id": _hash("src", source_material),
        "semantic_cluster_id": _hash("sem", f"{family}\0{semantic}"),
        "structural_cluster_id": _hash("str", f"{family}\0{structure}"),
        "semantic_payload": semantic,
        "structure_signature": structure,
        "techniques": classify_payload_techniques(record),
        "normalization_profile": sorted({str(step) for step in (record.get("normalization_steps") or [])}),
        "placement": str(record.get("zone") or "UNKNOWN"),
        "transport_encoding": str(record.get("encoding") or "NONE"),
    }


def annotate_record(record: dict[str, Any]) -> dict[str, Any]:
    updated = dict(record)
    updated["payload_classification"] = build_payload_classification(record)
    return updated


def cluster_records(input_path: Path, output_path: Path) -> dict[str, Any]:
    records = [annotate_record(record) for record in read_jsonl(input_path)]
    write_jsonl(output_path, records)

    source_counts: Counter[str] = Counter()
    semantic_counts: Counter[str] = Counter()
    structural_counts: Counter[str] = Counter()
    by_category: dict[str, set[str]] = defaultdict(set)
    by_family: dict[str, set[str]] = defaultdict(set)
    by_primitive: dict[str, set[str]] = defaultdict(set)
    by_diagnosis: dict[str, set[str]] = defaultdict(set)

    for record in records:
        info = record["payload_classification"]
        source_counts[info["source_cluster_id"]] += 1
        semantic_counts[info["semantic_cluster_id"]] += 1
        structural_counts[info["structural_cluster_id"]] += 1
        by_category[str(record.get("category") or "UNKNOWN")].add(info["source_cluster_id"])
        by_family[str(info.get("attack_family") or "unknown")].add(info["source_cluster_id"])
        by_primitive[str(info.get("primary_primitive") or "unresolved_primitive")].add(info["source_cluster_id"])
        diagnosis = str(record.get("diagnosis") or record.get("final_verdict") or "UNCLASSIFIED")
        by_diagnosis[diagnosis].add(info["source_cluster_id"])

    return {
        "records": len(records),
        "source_clusters": len(source_counts),
        "semantic_clusters": len(semantic_counts),
        "structural_clusters": len(structural_counts),
        "largest_source_cluster": max(source_counts.values(), default=0),
        "largest_semantic_cluster": max(semantic_counts.values(), default=0),
        "largest_structural_cluster": max(structural_counts.values(), default=0),
        "source_clusters_by_category": {key: len(value) for key, value in sorted(by_category.items())},
        "source_clusters_by_family": {key: len(value) for key, value in sorted(by_family.items())},
        "source_clusters_by_primitive": {key: len(value) for key, value in sorted(by_primitive.items())},
        "source_clusters_by_diagnosis": {key: len(value) for key, value in sorted(by_diagnosis.items())},
        "output": str(output_path),
    }

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl
from .curl_parser import normalize_payload_details


CLUSTER_SCHEMA_VERSION = 1

_LONG_HEX_RE = re.compile(r"(?i)\b(?:0x)?[0-9a-f]{8,}\b")
_NUMBER_RE = re.compile(r"\b\d+\b")
_WHITESPACE_RE = re.compile(r"\s+")
_QUOTED_RE = re.compile(r"(['\"])(?:\\.|(?!\1).){1,96}\1")
_SCANNER_ASSIGNMENT_RE = re.compile(r"(?i)^(?:param[0-9a-f]{4,16}|url)=")


def _hash(prefix: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"wba-{prefix}-{digest}"


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
    if "/\*" in normalized and "*/" in normalized:
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
    source_material = f"{category}\0{payload_path or record.get('case_id') or semantic}"
    return {
        "cluster_schema_version": CLUSTER_SCHEMA_VERSION,
        "source_cluster_id": _hash("src", source_material),
        "semantic_cluster_id": _hash("sem", f"{category}\0{semantic}"),
        "structural_cluster_id": _hash("str", f"{category}\0{structure}"),
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
    by_diagnosis: dict[str, set[str]] = defaultdict(set)

    for record in records:
        info = record["payload_classification"]
        source_counts[info["source_cluster_id"]] += 1
        semantic_counts[info["semantic_cluster_id"]] += 1
        structural_counts[info["structural_cluster_id"]] += 1
        by_category[str(record.get("category") or "UNKNOWN")].add(info["source_cluster_id"])
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
        "source_clusters_by_diagnosis": {key: len(value) for key, value in sorted(by_diagnosis.items())},
        "output": str(output_path),
    }

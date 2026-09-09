from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


FAMILY_TAG_ALIASES: dict[str, set[str]] = {
    "xss": {"xss"},
    "rce": {"rce", "command-injection", "command-execution"},
    "lfi": {"lfi", "path-traversal"},
    "rfi": {"rfi"},
    "php": {"php"},
    "ssrf": {"ssrf"},
    "java": {"java"},
    "xml": {"xml", "xxe", "xpath", "xpath-injection"},
    "ssti": {"ssti", "template-injection", "expression-injection"},
    "nosqli": {"nosql", "nosql-injection", "mongodb"},
    "ldap": {"ldap", "ldap-injection"},
    "deserialization": {"deserialization", "insecure-deserialization", "serialization"},
    "prototype-pollution": {"prototype-pollution"},
    "open-redirect": {"open-redirect", "url-manipulation"},
    "graphql": {"graphql"},
}

CATEGORY_ALIASES = {
    "nosql": "nosqli",
    "nosqli": "nosqli",
    "template": "ssti",
    "template-expression": "ssti",
    "template-expression-injection": "ssti",
    "xxe": "xml",
    "xpath": "xml",
    "path-traversal": "lfi",
}

WEAK_TAGS = {"weak-signal", "supporting-signal", "low-confidence"}
STRONG_TAGS = {"strong-signal", "high-confidence", "blocking-signal"}
CONTEXTUAL_TAGS = {"contextual-signal", "medium-signal"}


def _load_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _rules_from_document(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        return [rule for rule in document if isinstance(rule, dict)]
    if isinstance(document, dict):
        rules = document.get("rules")
        if isinstance(rules, list):
            return [rule for rule in rules if isinstance(rule, dict)]
        if "rule_id" in document or "id" in document:
            return [document]
    raise ValueError("Rule metadata input must be a YAML/JSON ruleset or JSONL rule objects")


def _normalize_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = [value]
    return sorted({str(item).strip().lower() for item in values if str(item).strip()})


def _canonical_family(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    return CATEGORY_ALIASES.get(text, text)


def _family_from_rule(rule: dict[str, Any], tags: list[str]) -> str | None:
    explicit = _canonical_family(rule.get("family") or rule.get("category"))
    if explicit:
        return explicit
    tag_set = set(tags)
    for family, aliases in FAMILY_TAG_ALIASES.items():
        if tag_set & aliases:
            return family
    name = str(rule.get("name") or "").lower()
    for family, aliases in FAMILY_TAG_ALIASES.items():
        if any(alias in name for alias in aliases):
            return family
    return None


def _confidence(tags: list[str], score: int | None) -> str:
    tag_set = set(tags)
    if tag_set & WEAK_TAGS:
        return "weak"
    if tag_set & STRONG_TAGS:
        return "strong"
    if tag_set & CONTEXTUAL_TAGS:
        return "contextual"
    if score is not None and score <= 2:
        return "weak"
    return "unspecified"


def normalize_deployed_rule(rule: dict[str, Any]) -> dict[str, Any]:
    rule_id = rule.get("id") if rule.get("id") is not None else rule.get("rule_id")
    if rule_id is None or str(rule_id).strip() == "":
        raise ValueError("Rule metadata entry has no id/rule_id")
    tags = _normalize_tags(rule.get("tags"))
    score = rule.get("score")
    if not isinstance(score, int):
        try:
            score = int(score) if score is not None and str(score).strip() else None
        except (TypeError, ValueError):
            score = None
    return {
        "rule_id": str(rule_id),
        "name": rule.get("name"),
        "family": _family_from_rule(rule, tags),
        "configured_score": score,
        "severity": rule.get("severity"),
        "action": rule.get("action"),
        "enforcement": rule.get("enforcement"),
        "tags": tags,
        "confidence": _confidence(tags, score),
    }


def load_deployed_rules(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for rule in _rules_from_document(_load_document(path)):
        normalized = normalize_deployed_rule(rule)
        rule_id = normalized["rule_id"]
        if rule_id in result:
            raise ValueError(f"Rule metadata input contains duplicate rule id: {rule_id}")
        result[rule_id] = normalized
    return result


def category_matches_rule(category: Any, metadata: dict[str, Any]) -> bool:
    category_family = _canonical_family(category)
    rule_family = _canonical_family(metadata.get("family"))
    return bool(category_family and rule_family and category_family == rule_family)

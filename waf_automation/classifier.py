from __future__ import annotations

from pathlib import Path
from typing import Any

from .clustering import attack_family
from .common import read_json


def load_groups(groups_path: Path, taxonomy_path: Path | None = None) -> dict[int, dict[str, Any]]:
    names = [line.strip() for line in groups_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    groups: dict[int, dict[str, Any]] = {
        index: {"id": index, "name": name, "source": "groups.txt"}
        for index, name in enumerate(names, 1)
    }
    if taxonomy_path:
        config = read_json(taxonomy_path)
        for item in config.get("additional_groups", []):
            group_id = int(item["id"])
            if group_id in groups:
                raise ValueError(f"Additional group id {group_id} conflicts with groups.txt")
            groups[group_id] = {
                "id": group_id,
                "name": str(item["name"]),
                "source": str(item.get("source", "local")),
            }
    return groups


def load_classification_config(
    taxonomy_path: Path | None,
    overrides_path: Path | None,
) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    """Load deterministic category mappings.

    Payload-level overrides are retained only for backward compatibility with
    existing invocations. The main group-classification path remains
    category -> group, while generic attack-family and clustering metadata is
    derived separately from the request itself.
    """
    category_defaults: dict[str, int] = {}
    if taxonomy_path:
        raw = read_json(taxonomy_path)
        category_defaults = {str(k): int(v) for k, v in raw.get("category_defaults", {}).items()}

    legacy_overrides: dict[str, dict[str, Any]] = {}
    if overrides_path and overrides_path.exists():
        raw_overrides = read_json(overrides_path)
        legacy_overrides = {str(k): dict(v) for k, v in raw_overrides.get("payloads", {}).items()}
    return category_defaults, legacy_overrides


def _family_metadata(category: str, payload_path: str) -> dict[str, str]:
    family, source = attack_family(category, payload_path)
    return {
        "attack_family": family,
        "attack_family_source": source,
    }


def classify(
    payload_path: str,
    category: str,
    groups: dict[int, dict[str, Any]],
    category_defaults: dict[str, int],
    overrides: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Classify taxonomy group while also exposing a generic attack family.

    Taxonomy assignment and request clustering are intentionally separate:
    category/group labels describe the source corpus, while attack_family is a
    stable semantic dimension that can be used across XSS, SQLi, RCE, SSRF and
    future payload sources.
    """
    family = _family_metadata(category, payload_path)
    group_id = category_defaults.get(category)
    if group_id is not None:
        group = groups.get(group_id)
        if not group:
            raise ValueError(f"Category {category} references missing group {group_id}")
        return {
            "group_id": group_id,
            "group_name": group["name"],
            "classification_type": "CATEGORY_DEFAULT",
            "classification_confidence": "HIGH",
            "classification_reason": f"Deterministic mapping for waf-bypass category {category}",
            "classification_source": "category_default",
            **family,
        }

    override = overrides.get(payload_path)
    if override is not None:
        override_group_id = override.get("group_id")
        if override_group_id not in (None, ""):
            override_group_id = int(override_group_id)
            group = groups.get(override_group_id)
            if not group:
                raise ValueError(f"Override for {payload_path} references missing group {override_group_id}")
            return {
                "group_id": override_group_id,
                "group_name": group["name"],
                "classification_type": "LEGACY_OVERRIDE",
                "classification_confidence": str(override.get("confidence", "HIGH")),
                "classification_reason": str(override.get("reason", "Legacy payload override")),
                "classification_source": "legacy_override",
                **family,
            }

    return {
        "group_id": None,
        "group_name": "ВНЕ ТАКСОНОМИИ / НУЖНА ПРОВЕРКА",
        "classification_type": "NO_GROUP",
        "classification_confidence": "LOW",
        "classification_reason": f"No deterministic mapping for category {category}",
        "classification_source": "unclassified",
        **family,
    }

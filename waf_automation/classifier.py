from __future__ import annotations

from pathlib import Path
from typing import Any

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


def load_classification_config(taxonomy_path: Path | None, overrides_path: Path | None) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    category_defaults: dict[str, int] = {}
    if taxonomy_path:
        raw = read_json(taxonomy_path)
        category_defaults = {str(k): int(v) for k, v in raw.get("category_defaults", {}).items()}
    overrides: dict[str, dict[str, Any]] = {}
    if overrides_path and overrides_path.exists():
        raw_overrides = read_json(overrides_path)
        overrides = {str(k): dict(v) for k, v in raw_overrides.get("payloads", {}).items()}
    return category_defaults, overrides


def classify(
    payload_path: str,
    category: str,
    groups: dict[int, dict[str, Any]],
    category_defaults: dict[str, int],
    overrides: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    override = overrides.get(payload_path)
    if override is not None:
        group_id = override.get("group_id")
        if group_id in (None, ""):
            return {
                "group_id": None,
                "group_name": str(override.get("group_name") or "ВНЕ ТАКСОНОМИИ"),
                "classification_type": "NO_GROUP",
                "classification_confidence": str(override.get("confidence", "HIGH")),
                "classification_reason": str(override.get("reason", "Manual override: no group")),
                "classification_source": "override",
            }
        group_id = int(group_id)
        group = groups.get(group_id)
        if not group:
            raise ValueError(f"Override for {payload_path} references missing group {group_id}")
        return {
            "group_id": group_id,
            "group_name": group["name"],
            "classification_type": str(override.get("match_type", "EXACT")),
            "classification_confidence": str(override.get("confidence", "HIGH")),
            "classification_reason": str(override.get("reason", "Manual payload override")),
            "classification_source": "override",
        }

    group_id = category_defaults.get(category)
    if group_id is not None:
        group = groups.get(group_id)
        if not group:
            raise ValueError(f"Category {category} references missing group {group_id}")
        return {
            "group_id": group_id,
            "group_name": group["name"],
            "classification_type": "CATEGORY_DEFAULT",
            "classification_confidence": "MEDIUM",
            "classification_reason": f"Default group for category {category}; analyst review required",
            "classification_source": "category_default",
        }

    return {
        "group_id": None,
        "group_name": "ВНЕ ТАКСОНОМИИ / НУЖНА ПРОВЕРКА",
        "classification_type": "NO_GROUP",
        "classification_confidence": "LOW",
        "classification_reason": "No override or deterministic category mapping",
        "classification_source": "unclassified",
    }


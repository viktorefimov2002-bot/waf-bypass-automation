from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl


def _index_unique(records: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records, start=1):
        value = record.get(key)
        if value is None or str(value).strip() == "":
            raise ValueError(f"{label} record {index} has no {key}")
        value_text = str(value)
        if value_text in indexed:
            raise ValueError(f"{label} contains duplicate {key}: {value_text}")
        indexed[value_text] = record
    return indexed


def merge_case_records(base_path: Path, updates_path: Path, output_path: Path, key: str = "case_id") -> dict[str, Any]:
    """Replace base records with newer records using a stable identity key.

    Base order is preserved. Update records whose key does not exist in base are
    appended in update-file order. Duplicate or missing keys are rejected rather
    than resolved silently.
    """
    base = read_jsonl(base_path)
    updates = read_jsonl(updates_path)
    base_index = _index_unique(base, key, "base")
    update_index = _index_unique(updates, key, "updates")

    merged: list[dict[str, Any]] = []
    replaced = 0
    used_updates: set[str] = set()
    for record in base:
        value = str(record[key])
        replacement = update_index.get(value)
        if replacement is not None:
            merged.append(replacement)
            replaced += 1
            used_updates.add(value)
        else:
            merged.append(record)

    appended = 0
    for record in updates:
        value = str(record[key])
        if value in used_updates or value in base_index:
            continue
        merged.append(record)
        appended += 1

    write_jsonl(output_path, merged)
    return {
        "key": key,
        "base_records": len(base),
        "update_records": len(updates),
        "replaced": replaced,
        "appended": appended,
        "output_records": len(merged),
        "output": str(output_path),
    }

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .common import read_jsonl, write_jsonl
from .rules import suggest_rules as _legacy_suggest_rules


def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
    records = read_jsonl(input_path)
    converted: list[dict[str, Any]] = []
    for record in records:
        item = dict(record)
        if item.get("final_verdict") == "BYPASS_CONFIRMED":
            item["final_verdict"] = "BYPASS_ORIGIN_CONFIRMED"
        converted.append(item)

    with tempfile.TemporaryDirectory(prefix="waf-rules-") as temp_dir:
        compatible_input = Path(temp_dir) / "verified.jsonl"
        write_jsonl(compatible_input, converted)
        result = _legacy_suggest_rules(compatible_input, output_dir, id_start)
    result["source"] = str(input_path)
    return result

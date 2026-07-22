from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def make_run_id(report_path: Path) -> str:
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()[:12]
    return f"{report_path.stem}-{digest}"


def curl_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def stable_key(record: dict[str, Any]) -> str:
    return f"{record['payload_path']}::{record['variant']}"


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


def parse_response_code(value: Any) -> int | None:
    match = re.search(r"\b(\d{3})\b", str(value or ""))
    return int(match.group(1)) if match else None


def normalize_block_codes(value: Any) -> list[int]:
    if value is None:
        return [403]
    if isinstance(value, (int, str)):
        value = [value]
    result: list[int] = []
    for item in value:
        try:
            code = int(item)
        except (TypeError, ValueError):
            continue
        if 100 <= code <= 599 and code not in result:
            result.append(code)
    return result or [403]


def code_verdict(code: int | None, block_codes: Iterable[int] | None = None) -> str:
    if code is None:
        return "UNKNOWN_CODE"
    blocked = set(normalize_block_codes(block_codes))
    return "BLOCKED_BY_CODE" if code in blocked else "BYPASS_BY_CODE"

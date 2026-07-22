from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook

from .common import read_jsonl, stable_key, write_jsonl


def _state(record: dict[str, Any] | None) -> str:
    if record is None:
        return "MISSING"
    final = record.get("final_verdict")
    if final in {"BLOCKED_WAF", "BLOCKED_ROUTE_MISMATCH"} or record.get("http_code") == 403:
        return "BLOCKED"
    if final == "CHECK_ERROR":
        return "ERROR"
    return "BYPASS"


def diff_runs(before_path: Path, after_path: Path, output_jsonl: Path, output_xlsx: Path) -> dict[str, Any]:
    before = {stable_key(record): record for record in read_jsonl(before_path)}
    after = {stable_key(record): record for record in read_jsonl(after_path)}
    rows: list[dict[str, Any]] = []
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        old_state, new_state = _state(old), _state(new)
        if old is None:
            status = "NEW"
        elif new is None:
            status = "REMOVED"
        elif old_state == "BYPASS" and new_state == "BLOCKED":
            status = "FIXED"
        elif old_state == "BLOCKED" and new_state == "BYPASS":
            status = "REGRESSION"
        elif "ERROR" in {old_state, new_state}:
            status = "ERROR"
        elif old.get("curl_hash") != new.get("curl_hash") or old.get("http_code") != new.get("http_code") or old.get("server_header") != new.get("server_header"):
            status = "CHANGED"
        else:
            status = "PERSISTENT"
        reference = new or old or {}
        rows.append({
            "stable_key": key,
            "payload_path": reference.get("payload_path"),
            "variant": reference.get("variant"),
            "group_id": reference.get("group_id"),
            "group_name": reference.get("group_name"),
            "status": status,
            "before_state": old_state,
            "after_state": new_state,
            "before_code": old.get("http_code") if old else None,
            "after_code": new.get("http_code") if new else None,
            "before_server": old.get("server_header") if old else None,
            "after_server": new.get("server_header") if new else None,
        })
    write_jsonl(output_jsonl, rows)
    wb = Workbook()
    ws = wb.active
    ws.title = "Diff"
    headers = list(rows[0]) if rows else ["stable_key", "status"]
    ws.append(headers)
    for row in rows:
        ws.append([row.get(header) for header in headers])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_xlsx)
    return {"records": len(rows), "output_jsonl": str(output_jsonl), "output_xlsx": str(output_xlsx)}

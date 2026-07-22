from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from openpyxl import Workbook

from .common import read_jsonl, stable_key, write_jsonl
from .recheck import recheck_records


def _fix_status(after: dict[str, Any]) -> str:
    verdict = after.get("final_verdict")
    if verdict == "BLOCKED_BY_WAF":
        return "FIXED"
    if verdict == "BYPASS_CONFIRMED":
        return "STILL_BYPASSED"
    if verdict == "CHECK_ERROR":
        return "ERROR"
    return "NEEDS_REVIEW"


def validate_fixes(
    before_path: Path,
    output_jsonl: Path,
    output_xlsx: Path,
    *,
    execute: bool,
    allow_host: str | None,
    group_id: int | None,
    limit: int | None,
    timeout: float,
    delay: float,
) -> dict[str, Any]:
    replay_path = output_jsonl.with_suffix(".replayed.jsonl")
    recheck_records(
        before_path,
        replay_path,
        group_id=group_id,
        execute=execute,
        allow_host=allow_host,
        limit=limit,
        timeout=timeout,
        delay=delay,
        only_confirmed_bypasses=True,
    )

    before = {stable_key(record): record for record in read_jsonl(before_path) if record.get("final_verdict") == "BYPASS_CONFIRMED"}
    after = {stable_key(record): record for record in read_jsonl(replay_path)}
    rows: list[dict[str, Any]] = []
    for key in sorted(after):
        old = before.get(key, {})
        new = after[key]
        rows.append({
            "stable_key": key,
            "payload_path": new.get("payload_path"),
            "variant": new.get("variant"),
            "group_id": new.get("group_id"),
            "group_name": new.get("group_name"),
            "status": _fix_status(new),
            "before_code": old.get("http_code"),
            "before_server": old.get("server_header"),
            "after_code": new.get("http_code"),
            "after_server": new.get("server_header"),
            "after_verdict": new.get("final_verdict"),
            "curl": new.get("curl"),
        })

    write_jsonl(output_jsonl, rows)
    wb = Workbook()
    ws = wb.active
    ws.title = "Fix validation"
    headers = list(rows[0]) if rows else ["stable_key", "status"]
    ws.append(headers)
    for row in rows:
        ws.append([row.get(header) for header in headers])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_xlsx)

    counts = Counter(row["status"] for row in rows)
    return {
        "records": len(rows),
        "fixed": counts["FIXED"],
        "still_bypassed": counts["STILL_BYPASSED"],
        "needs_review": counts["NEEDS_REVIEW"],
        "errors": counts["ERROR"],
        "output_jsonl": str(output_jsonl),
        "output_xlsx": str(output_xlsx),
        "replayed_jsonl": str(replay_path),
    }

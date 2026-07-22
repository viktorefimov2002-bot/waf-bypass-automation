from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

from .common import read_jsonl

HEADER_FILL = PatternFill("solid", fgColor="1F4E78")
HEADER_FONT = Font(color="FFFFFF", bold=True)


def _excel_value(value: Any) -> Any:
    if isinstance(value, str):
        value = ILLEGAL_CHARACTERS_RE.sub("", value)
        if value.startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def _append(ws, values: list[Any]) -> None:
    ws.append([_excel_value(value) for value in values])


def _style_sheet(ws, widths: dict[int, int] | None = None) -> None:
    ws.freeze_panes = "A2"
    ws.sheet_view.showGridLines = False
    for cell in ws[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    ws.auto_filter.ref = ws.dimensions
    for column in range(1, ws.max_column + 1):
        width = widths.get(column) if widths else None
        if width is None:
            width = min(60, max(10, max(len(str(ws.cell(row, column).value or "")) for row in range(1, min(ws.max_row, 200) + 1)) + 2))
        ws.column_dimensions[get_column_letter(column)].width = width
    if ws.max_row >= 2:
        table = Table(displayName=f"Table_{ws.title.replace(' ', '_')}", ref=f"A1:{get_column_letter(ws.max_column)}{ws.max_row}")
        table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True)
        ws.add_table(table)


def create_compact_report(input_path: Path, output_path: Path) -> dict[str, Any]:
    records = read_jsonl(input_path)
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"

    verdicts = Counter(str(record.get("final_verdict") or "NOT_VERIFIED") for record in records)
    _append(summary, ["Metric", "Value"])
    _append(summary, ["Variants", len(records)])
    _append(summary, ["Payload files", len({record.get('payload_path') for record in records})])
    _append(summary, ["Groups represented", len({record.get('group_id') for record in records if record.get('group_id') is not None})])
    for verdict, count in sorted(verdicts.items()):
        _append(summary, [verdict, count])
    _style_sheet(summary, {1: 34, 2: 18})

    results = wb.create_sheet("Results")
    headers = [
        "Group ID", "Group", "Payload", "Variant", "Zone", "Encoding",
        "HTTP code", "Server", "Verdict", "Normalized payload", "cURL",
    ]
    _append(results, headers)
    for record in records:
        _append(results, [
            record.get("group_id"), record.get("group_name"), record.get("payload_path"),
            record.get("variant"), record.get("zone"), record.get("encoding"),
            record.get("http_code"), record.get("server_header"), record.get("final_verdict"),
            record.get("normalized_payload"), record.get("curl"),
        ])
    _style_sheet(results, {1: 10, 2: 46, 3: 22, 4: 20, 5: 14, 6: 14, 7: 11, 8: 24, 9: 26, 10: 60, 11: 100})

    groups = wb.create_sheet("Groups")
    _append(groups, ["Group ID", "Group", "Payload files", "Variants", "Confirmed bypass", "Blocked by WAF", "Needs review", "Errors"])
    grouped: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[(record.get("group_id"), record.get("group_name"))].append(record)
    for (group_id, group_name), items in sorted(grouped.items(), key=lambda item: (str(item[0][0]), str(item[0][1]))):
        counts = Counter(item.get("final_verdict") for item in items)
        _append(groups, [
            group_id, group_name, len({item.get('payload_path') for item in items}), len(items),
            counts["BYPASS_CONFIRMED"], counts["BLOCKED_BY_WAF"],
            counts["BYPASS_UNCONFIRMED"] + counts["ROUTE_MISMATCH"], counts["CHECK_ERROR"],
        ])
    _style_sheet(groups, {1: 10, 2: 52, 3: 14, 4: 12, 5: 18, 6: 16, 7: 15, 8: 10})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_path)
    return {"output": str(output_path), "sheets": wb.sheetnames, "variants": len(records)}


def create_report(input_path: Path, groups_path: Path, output_path: Path, taxonomy_path: Path | None = None) -> dict[str, Any]:
    """Backward-compatible wrapper. Group metadata is already stored in JSONL."""
    return create_compact_report(input_path, output_path)

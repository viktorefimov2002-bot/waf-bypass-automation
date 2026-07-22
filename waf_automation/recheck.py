from __future__ import annotations

import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .common import code_verdict, normalize_block_codes, read_jsonl, stable_key, utc_now, write_jsonl
from .curl_parser import extract_request, split_curl


OUTPUT_OPTIONS_WITH_VALUE = {"-o", "--output", "-D", "--dump-header", "-w", "--write-out"}
SAFE_OPTIONS_WITH_VALUE = {
    "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "--cookie", "--user-agent", "--referer",
}
SAFE_FLAG_OPTIONS = {"--compressed", "-k", "--insecure", "--http1.1", "--http2", "--path-as-is"}


def _has_output_conflict(argv: list[str]) -> str | None:
    for item in argv[1:]:
        if item in OUTPUT_OPTIONS_WITH_VALUE or item in {"-i", "--include", "-I", "--head"}:
            return item
        if item.startswith("--output=") or item.startswith("--dump-header=") or item.startswith("--write-out="):
            return item.split("=", 1)[0]
    return None


def validate_replay_argv(argv: list[str]) -> None:
    conflict = _has_output_conflict(argv)
    if conflict:
        raise ValueError(f"cURL has conflicting output option: {conflict}")
    index = 1
    while index < len(argv):
        item = argv[index]
        if item.startswith(("http://", "https://")):
            index += 1
            continue
        if item in SAFE_OPTIONS_WITH_VALUE:
            if index + 1 >= len(argv):
                raise ValueError(f"cURL option {item} has no value")
            value = argv[index + 1]
            if item not in {"-X", "--request"} and value.startswith("@"):
                raise ValueError(f"cURL option {item} attempts to read a local file")
            index += 2
            continue
        if item in SAFE_FLAG_OPTIONS:
            index += 1
            continue
        if item in {"-L", "--location"}:
            raise ValueError("Redirect following is disabled for safe replay")
        if item.startswith("-"):
            raise ValueError(f"cURL option is not in the replay allowlist: {item}")
        raise ValueError(f"Unexpected positional cURL argument: {item}")


def _parse_final_headers(raw: bytes) -> tuple[str | None, int | None]:
    text = raw.decode("iso-8859-1", errors="replace")
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    selected: list[str] = []
    for block in blocks:
        lines = block.splitlines()
        if lines and lines[0].startswith("HTTP/"):
            selected = lines
    if not selected:
        return None, None
    status_match = re.match(r"HTTP/\S+\s+(\d{3})", selected[0])
    status = int(status_match.group(1)) if status_match else None
    server = None
    for line in selected[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "server":
            server = value.strip()
    return server, status


def verdict(http_code: int | None, server: str | None, block_codes: list[int] | None = None) -> tuple[str, str, str]:
    block_codes = normalize_block_codes(block_codes)
    server_lower = (server or "").lower()
    if "nginx" in server_lower or "ubuntu" in server_lower:
        route = "ORIGIN_CONFIRMED"
    elif "pingora" in server_lower:
        route = "WAF_CONFIRMED"
    elif server:
        route = "ROUTE_OTHER"
    else:
        route = "ROUTE_UNCONFIRMED"

    code = code_verdict(http_code, block_codes)
    if http_code is None:
        final = "CHECK_ERROR"
    elif http_code in block_codes and route == "WAF_CONFIRMED":
        final = "BLOCKED_BY_WAF"
    elif http_code not in block_codes and route == "ORIGIN_CONFIRMED":
        final = "BYPASS_CONFIRMED"
    elif http_code in block_codes:
        final = "ROUTE_MISMATCH"
    else:
        final = "BYPASS_UNCONFIRMED"
    return code, route, final


def _execute(record: dict[str, Any], timeout: float) -> dict[str, Any]:
    argv = split_curl(record["curl"])
    validate_replay_argv(argv)
    with tempfile.NamedTemporaryFile(prefix="waf-headers-", suffix=".txt") as header_file:
        command = argv + [
            "--silent", "--show-error", "--output", "/dev/null", "--dump-header", header_file.name,
            "--write-out", "%{http_code}", "--max-redirs", "0", "--max-time", str(timeout),
        ]
        started = time.monotonic()
        completed = subprocess.run(command, shell=False, capture_output=True, timeout=timeout + 5, check=False)
        duration_ms = round((time.monotonic() - started) * 1000)
        header_file.seek(0)
        header_bytes = header_file.read()
    stdout = completed.stdout.decode("ascii", errors="ignore").strip()
    http_code = int(stdout[-3:]) if re.fullmatch(r"\d{3}", stdout[-3:]) else None
    server, header_status = _parse_final_headers(header_bytes)
    if http_code is None:
        http_code = header_status
    if completed.returncode != 0 or http_code in (None, 0):
        code, route, final = "UNKNOWN_CODE", "ROUTE_UNCONFIRMED", "CHECK_ERROR"
    else:
        code, route, final = verdict(http_code, server, record.get("block_codes"))
    return {
        "checked_at": utc_now(), "http_code": http_code, "server_header": server,
        "code_verdict": code, "route_verdict": route, "final_verdict": final,
        "duration_ms": duration_ms, "curl_exit_code": completed.returncode,
        "stderr": completed.stderr.decode("utf-8", errors="replace").strip(),
    }


def recheck_records(
    input_path: Path,
    output_path: Path,
    *,
    group_id: int | None,
    execute: bool,
    allow_host: str | None,
    limit: int | None,
    timeout: float,
    delay: float,
    only_confirmed_bypasses: bool = False,
) -> dict[str, Any]:
    records = read_jsonl(input_path)
    selected = [
        record for record in records
        if (group_id is None or record.get("group_id") == group_id)
        and (not only_confirmed_bypasses or record.get("final_verdict") == "BYPASS_CONFIRMED")
    ]
    if limit is not None:
        selected = selected[:limit]
    results: list[dict[str, Any]] = []
    for index, record in enumerate(selected):
        request = extract_request(record["curl"])
        validate_replay_argv(request["argv"])
        host = request["host"]
        if allow_host and host != allow_host:
            raise ValueError(f"Host {host!r} is not allowed; expected {allow_host!r}")
        if not allow_host and execute:
            raise ValueError("--allow-host is required together with --execute")
        result = dict(record)
        result["stable_key"] = stable_key(record)
        if execute:
            try:
                result.update(_execute(record, timeout))
            except Exception as exc:
                result.update({
                    "checked_at": utc_now(), "server_header": None, "route_verdict": "ROUTE_UNCONFIRMED",
                    "final_verdict": "CHECK_ERROR", "duration_ms": None, "curl_exit_code": None, "stderr": str(exc),
                })
        else:
            result.update({
                "checked_at": None, "server_header": None, "route_verdict": "NOT_CHECKED",
                "final_verdict": "DRY_RUN", "duration_ms": None, "curl_exit_code": None, "stderr": "",
            })
        results.append(result)
        if execute and delay > 0 and index < len(selected) - 1:
            time.sleep(delay)
    write_jsonl(output_path, results)
    return {"selected": len(selected), "executed": len(selected) if execute else 0, "output": str(output_path)}

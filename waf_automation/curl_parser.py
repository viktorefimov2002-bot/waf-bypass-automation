from __future__ import annotations

import base64
import binascii
import html
import re
import shlex
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse


STANDARD_HEADERS = {
    "accept", "accept-encoding", "connection", "content-length", "content-type", "host", "user-agent", "referer", "cookie"
}


def split_curl(command: str) -> list[str]:
    argv = shlex.split(command, posix=True)
    if not argv or argv[0] != "curl":
        raise ValueError("Command is not a curl command")
    return argv


def _option_values(argv: list[str], names: set[str]) -> list[str]:
    values: list[str] = []
    index = 1
    while index < len(argv):
        item = argv[index]
        if item in names and index + 1 < len(argv):
            values.append(argv[index + 1])
            index += 2
            continue
        index += 1
    return values


def extract_request(command: str) -> dict[str, Any]:
    argv = split_curl(command)
    urls = [item for item in argv if item.startswith(("http://", "https://"))]
    if len(urls) != 1:
        raise ValueError(f"Expected exactly one URL, got {len(urls)}")
    url = urls[0]
    parsed = urlparse(url)
    method_values = _option_values(argv, {"-X", "--request"})
    data_values = _option_values(argv, {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"})
    headers = _option_values(argv, {"-H", "--header"})
    method = method_values[-1] if method_values else ("POST" if data_values else "GET")
    return {
        "argv": argv,
        "url": url,
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "method": method.upper(),
        "path": parsed.path or "/",
        "query": parsed.query,
        "headers": headers,
        "data": data_values,
    }


def parse_variant(variant: str) -> tuple[str, str]:
    parts = variant.upper().split(":", 1)
    zone = parts[0]
    encoding = parts[1] if len(parts) == 2 else "NONE"
    return zone, encoding


def _headers_map(headers: list[str]) -> list[tuple[str, str]]:
    result = []
    for header in headers:
        name, separator, value = header.partition(":")
        if separator:
            result.append((name.strip(), value.strip()))
    return result


def extract_payload(request: dict[str, Any], zone: str) -> str:
    headers = _headers_map(request["headers"])
    if zone == "URL":
        return request["path"] + (f"?{request['query']}" if request["query"] else "")
    if zone == "ARGS":
        pairs = parse_qsl(request["query"], keep_blank_values=True)
        return "&".join(value if value else key for key, value in pairs) if pairs else request["query"]
    if zone == "BODY":
        return "\n".join(request["data"])
    if zone == "COOKIE":
        return "\n".join(value for name, value in headers if name.lower() == "cookie")
    if zone == "USER-AGENT":
        return "\n".join(value for name, value in headers if name.lower() == "user-agent")
    if zone == "REFERER":
        return "\n".join(value for name, value in headers if name.lower() == "referer")
    if zone == "HEADER":
        custom = [f"{name}: {value}" for name, value in headers if name.lower() not in STANDARD_HEADERS]
        return "\n".join(custom or [f"{name}: {value}" for name, value in headers])
    return request["url"]


def _decode_js_unicode(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)
    return re.sub(r"\\u([0-9a-fA-F]{4})", replace, value)


def _base64_candidates(value: str) -> list[str]:
    candidates = re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])", value)
    if re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", value.strip()):
        candidates.insert(0, value.strip())
    return sorted(set(candidates), key=len, reverse=True)


def normalize_payload(raw: str, encoding: str) -> tuple[str, list[str]]:
    value = raw
    steps: list[str] = []
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
        steps.append("percent")
    html_decoded = html.unescape(value)
    if html_decoded != value:
        value = html_decoded
        steps.append("html_entity")
    js_decoded = _decode_js_unicode(value)
    if js_decoded != value:
        value = js_decoded
        steps.append("js_unicode")
    if encoding == "BASE64":
        for candidate in _base64_candidates(value):
            try:
                padding = "=" * ((4 - len(candidate) % 4) % 4)
                decoded_bytes = base64.b64decode(candidate + padding, validate=True)
                decoded = decoded_bytes.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            value = value.replace(candidate, decoded, 1)
            steps.append("base64")
            break
    return value, steps

from __future__ import annotations

import base64
import binascii
import html
import re
import shlex
from typing import Any
from urllib.parse import unquote, urlparse


STANDARD_HEADERS = {
    "accept", "accept-encoding", "connection", "content-length", "content-type", "host", "user-agent", "referer", "cookie"
}
_SAFE_ARGUMENT_NAME_RE = re.compile(r"^[A-Za-z0-9_.~-]{1,64}$")
_BASE64_QUERY_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={1,2}$")


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


def extract_payload_details(request: dict[str, Any], zone: str) -> dict[str, Any]:
    headers = _headers_map(request["headers"])
    if zone == "URL":
        value = request["path"] + (f"?{request['query']}" if request["query"] else "")
        return {"value": value, "component": "REQUEST_URI", "name": None}
    if zone == "ARGS":
        query = str(request["query"] or "")
        # A trailing '=' or '==' can be Base64 padding rather than an HTTP
        # name/value separator. Preserve the whole query in that case.
        if _BASE64_QUERY_RE.fullmatch(query):
            return {"value": query, "component": "ARG_NAME", "name": None, "raw_query": query}
        # Do not use parse_qsl for scanner payloads: literal &, = and Base64
        # padding can be part of the attack string and must remain intact.
        name, separator, value = query.partition("=")
        if separator and _SAFE_ARGUMENT_NAME_RE.fullmatch(name):
            return {"value": value, "component": "ARG_VALUE", "name": name, "raw_query": query}
        return {"value": query, "component": "ARG_NAME", "name": None, "raw_query": query}
    if zone == "BODY":
        return {"value": "\n".join(request["data"]), "component": "REQUEST_BODY", "name": None}
    if zone == "COOKIE":
        return {"value": "\n".join(value for name, value in headers if name.lower() == "cookie"), "component": "COOKIE_VALUE", "name": None}
    if zone == "USER-AGENT":
        return {"value": "\n".join(value for name, value in headers if name.lower() == "user-agent"), "component": "HEADER_VALUE", "name": "User-Agent"}
    if zone == "REFERER":
        return {"value": "\n".join(value for name, value in headers if name.lower() == "referer"), "component": "HEADER_VALUE", "name": "Referer"}
    if zone == "HEADER":
        custom = [(name, value) for name, value in headers if name.lower() not in STANDARD_HEADERS]
        selected = custom or headers
        return {
            "value": "\n".join(value for _, value in selected),
            "component": "HEADER_VALUE",
            "name": selected[0][0] if len(selected) == 1 else None,
        }
    return {"value": request["url"], "component": "UNKNOWN", "name": None}


def extract_payload(request: dict[str, Any], zone: str) -> str:
    return str(extract_payload_details(request, zone)["value"])


def _decode_js_unicode(value: str) -> str:
    def replace_unicode(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    def replace_hex(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    value = re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, value)
    return re.sub(r"\\x([0-9a-fA-F]{2})", replace_hex, value)


def _looks_textual(value: str) -> bool:
    if not value:
        return False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in value)
    return printable / len(value) >= 0.85


def _decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 8:
        return None
    padding = "=" * ((4 - len(compact) % 4) % 4)
    try:
        decoded_bytes = base64.b64decode(compact + padding, validate=False)
        decoded = decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if _looks_textual(decoded) else None


def normalize_payload_details(raw: str, encoding: str, max_layers: int = 6) -> dict[str, Any]:
    value = raw
    layers = [raw]
    steps: list[str] = []
    encoding = encoding.upper()
    base64_applied = False

    for _ in range(max_layers):
        changed = False

        percent_decoded = unquote(value)
        if percent_decoded != value:
            value = percent_decoded
            steps.append("percent")
            layers.append(value)
            changed = True

        html_decoded = html.unescape(value)
        if html_decoded != value:
            value = html_decoded
            steps.append("html_entity")
            layers.append(value)
            changed = True

        js_decoded = _decode_js_unicode(value)
        if js_decoded != value:
            value = js_decoded
            steps.append("js_unicode")
            layers.append(value)
            changed = True

        if encoding == "BASE64" and not base64_applied:
            decoded = _decode_base64(value)
            if decoded is not None and decoded != value:
                value = decoded
                base64_applied = True
                steps.append("base64")
                layers.append(value)
                changed = True

        without_nulls = value.replace("\x00", "")
        if without_nulls != value:
            value = without_nulls
            steps.append("remove_nulls")
            layers.append(value)
            changed = True

        if not changed:
            break

    stop_reason = "STABLE" if len(layers) <= max_layers + 1 else "MAX_LAYERS"
    return {
        "value": value,
        "steps": steps,
        "layers": layers,
        "complete": stop_reason == "STABLE",
        "stop_reason": stop_reason,
    }


def normalize_payload(raw: str, encoding: str) -> tuple[str, list[str]]:
    details = normalize_payload_details(raw, encoding)
    return str(details["value"]), list(details["steps"])

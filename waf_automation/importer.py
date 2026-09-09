from __future__ import annotations

from pathlib import Path
from typing import Any

from .classifier import classify, load_classification_config, load_groups
from .clustering import build_cluster_metadata
from .common import SCHEMA_VERSION, code_verdict, curl_hash, make_run_id, normalize_block_codes, parse_response_code, read_json, utc_now, write_jsonl
from .curl_parser import extract_payload_details, extract_request, normalize_payload_details, parse_variant


def import_report(
    report_path: Path,
    groups_path: Path,
    output_path: Path,
    taxonomy_path: Path | None = None,
    overrides_path: Path | None = None,
) -> dict[str, Any]:
    report = read_json(report_path)
    bypassed = report.get("BYPASSED", {})
    curls = report.get("cURL", {}).get("BYPASSED", {})
    if not isinstance(bypassed, dict) or not isinstance(curls, dict):
        raise ValueError("Report does not contain BYPASSED and cURL.BYPASSED mappings")

    groups = load_groups(groups_path, taxonomy_path)
    category_defaults, overrides = load_classification_config(taxonomy_path, overrides_path)
    run_id = make_run_id(report_path)
    imported_at = utc_now()
    target = str(report.get("TARGET", ""))
    block_codes = normalize_block_codes(report.get("BLOCK-CODE", [403]))
    records: list[dict[str, Any]] = []
    import_errors: list[dict[str, Any]] = []

    for payload_path in sorted(bypassed):
        category = payload_path.split("/", 1)[0]
        results = bypassed[payload_path]
        curl_variants = curls.get(payload_path, {})
        if not isinstance(results, dict):
            continue
        classification = classify(payload_path, category, groups, category_defaults, overrides)
        for variant in sorted(results):
            command = curl_variants.get(variant)
            zone, encoding = parse_variant(variant)
            if not command:
                import_errors.append({
                    "schema_version": SCHEMA_VERSION,
                    "run_id": run_id,
                    "payload_path": payload_path,
                    "category": category,
                    "variant": variant,
                    "zone": zone,
                    "encoding": encoding,
                    "error_type": "MISSING_CURL",
                    "error": "Report has a bypass result but no matching cURL command",
                    **classification,
                })
                continue

            try:
                request = extract_request(command)
                payload = extract_payload_details(request, zone)
                raw_payload = str(payload["value"])
                normalization = normalize_payload_details(raw_payload, encoding)
            except ValueError as error:
                import_errors.append({
                    "schema_version": SCHEMA_VERSION,
                    "run_id": run_id,
                    "payload_path": payload_path,
                    "category": category,
                    "variant": variant,
                    "zone": zone,
                    "encoding": encoding,
                    "curl": command,
                    "curl_hash": curl_hash(command),
                    "error_type": "CURL_PARSE_ERROR",
                    "error": str(error),
                    **classification,
                })
                continue

            response_raw = results[variant]
            http_code = parse_response_code(response_raw)
            record = {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "imported_at": imported_at,
                "report_file": report_path.name,
                "target": target,
                "block_codes": block_codes,
                "payload_path": payload_path,
                "category": category,
                "variant": variant,
                "zone": zone,
                "encoding": encoding,
                "response_raw": response_raw,
                "http_code": http_code,
                "code_verdict": code_verdict(http_code, block_codes),
                "curl": command,
                "curl_hash": curl_hash(command),
                "request_host": request["host"],
                "request_method": request["method"],
                "request_path": request["path"],
                "request_query": request["query"],
                "raw_payload": raw_payload,
                "payload_component": payload.get("component"),
                "payload_name": payload.get("name"),
                "payload_names": payload.get("cookie_names"),
                "raw_cookie": payload.get("raw_cookie"),
                "normalized_payload": normalization["value"],
                "normalization_steps": normalization["steps"],
                "normalization_layers": normalization["layers"],
                "normalization_complete": normalization["complete"],
                "normalization_stop_reason": normalization["stop_reason"],
                **classification,
            }
            # Generic clustering is derived after payload extraction and
            # normalization, so it reflects the actual request primitive rather
            # than merely the source folder name.
            record.update(build_cluster_metadata(record))
            records.append(record)

    write_jsonl(output_path, records)
    errors_path = output_path.with_name(f"{output_path.stem}.import-errors.jsonl")
    write_jsonl(errors_path, import_errors)
    return {
        "run_id": run_id,
        "payload_files": len({record["payload_path"] for record in records}),
        "variants": len(records),
        "groups": len(groups),
        "block_codes": block_codes,
        "import_errors": len(import_errors),
        "curl_parse_errors": sum(1 for row in import_errors if row.get("error_type") == "CURL_PARSE_ERROR"),
        "missing_curls": sum(1 for row in import_errors if row.get("error_type") == "MISSING_CURL"),
        "output": str(output_path),
        "errors_output": str(errors_path),
    }

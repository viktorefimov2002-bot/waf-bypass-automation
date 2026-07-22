from __future__ import annotations

from pathlib import Path
from typing import Any

from .classifier import classify, load_classification_config, load_groups
from .common import SCHEMA_VERSION, code_verdict, curl_hash, make_run_id, parse_response_code, read_json, utc_now, write_jsonl
from .curl_parser import extract_payload, extract_request, normalize_payload, parse_variant


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
    block_codes = [int(code) for code in report.get("BLOCK-CODE", [403])]
    records: list[dict[str, Any]] = []

    missing_curls: list[str] = []
    for payload_path in sorted(bypassed):
        category = payload_path.split("/", 1)[0]
        results = bypassed[payload_path]
        curl_variants = curls.get(payload_path, {})
        if not isinstance(results, dict):
            continue
        classification = classify(payload_path, category, groups, category_defaults, overrides)
        for variant in sorted(results):
            command = curl_variants.get(variant)
            if not command:
                missing_curls.append(f"{payload_path}::{variant}")
                continue
            zone, encoding = parse_variant(variant)
            request = extract_request(command)
            raw_payload = extract_payload(request, zone)
            normalized_payload, normalization_steps = normalize_payload(raw_payload, encoding)
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
                "code_verdict": code_verdict(http_code),
                "curl": command,
                "curl_hash": curl_hash(command),
                "request_host": request["host"],
                "request_method": request["method"],
                "request_path": request["path"],
                "raw_payload": raw_payload,
                "normalized_payload": normalized_payload,
                "normalization_steps": normalization_steps,
                **classification,
            }
            records.append(record)

    if missing_curls:
        sample = ", ".join(missing_curls[:5])
        raise ValueError(f"Missing cURL for {len(missing_curls)} bypass variants: {sample}")
    write_jsonl(output_path, records)
    return {
        "run_id": run_id,
        "payload_files": len({record["payload_path"] for record in records}),
        "variants": len(records),
        "groups": len(groups),
        "output": str(output_path),
    }

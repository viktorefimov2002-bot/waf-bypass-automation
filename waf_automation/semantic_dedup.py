from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def apply_semantic_dedup(rules_module: Any) -> None:
    """Replace suggest_rules with semantic clustering while preserving provenance."""

    def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
        records = [
            record
            for record in rules_module.read_jsonl(input_path)
            if record.get("final_verdict") in {"BYPASS_CONFIRMED", "BYPASS_ORIGIN_CONFIRMED"}
        ]
        if not records:
            raise ValueError("No confirmed bypass records; run verify first")

        clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        signatures: dict[str, tuple[str, str, str]] = {}
        skipped_rows: list[dict[str, Any]] = []

        for record in records:
            encoding = str(record.get("encoding", "NONE")).upper()
            if encoding not in rules_module.SUPPORTED_ENCODINGS:
                skipped_rows.append(
                    rules_module._skip_row(
                        record,
                        "UNSUPPORTED_ENCODING",
                        f"Encoding {encoding} has no supported transform profile",
                    )
                )
                continue

            target, target_error, generic_header = rules_module._record_target(record)
            if target_error:
                skipped_rows.append(
                    rules_module._skip_row(
                        record,
                        target_error,
                        "Request location cannot be mapped to a safe SecLang collection",
                    )
                )
                continue

            signature = rules_module._select_signature(record)
            if signature is None:
                family = rules_module._family(record)
                reason = "UNSUPPORTED_FAMILY" if family == "generic" else "KNOWN_FAMILY_MISSING_SIGNATURE"
                detail = (
                    "No primitive library exists for this category"
                    if family == "generic"
                    else "Normalized payload did not match any current primitive"
                )
                if record.get("normalization_complete") is False:
                    reason = "NORMALIZATION_INCOMPLETE"
                    detail = "Normalization stopped before reaching a stable representation"
                skipped_rows.append(rules_module._skip_row(record, reason, detail, family))
                continue

            family, primitive, pattern = signature
            rules_module._validate_pattern(pattern)
            transforms = rules_module._transforms(record)
            phase = rules_module._phase_for_record(record)
            signature_key = f"{family}|{primitive}|{pattern}"
            signatures[signature_key] = signature

            # group_id/group_name and target are deliberately excluded. Rules with
            # identical detection semantics can share a SecRule target union while
            # provenance remains available in coverage and manifest metadata.
            clusters[(signature_key, transforms, phase)].append(
                {**record, "_rule_target": target, "_generic_header_target": generic_header}
            )

        if not clusters:
            raise ValueError("Confirmed bypasses were found, but none matched a supported exploit primitive")

        rules: list[dict[str, Any]] = []
        coverage_rows: list[dict[str, Any]] = []
        for offset, (key, covered) in enumerate(
            sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))
        ):
            signature_key, transforms, phase = key
            family, primitive, pattern = signatures[signature_key]
            targets = rules_module._deduplicate_targets({str(record["_rule_target"]) for record in covered})
            encodings = sorted({str(record.get("encoding", "NONE")).upper() for record in covered})
            step_profiles = sorted(
                {">".join(rules_module._normalization_steps(record)) or "NONE" for record in covered}
            )
            source_group_ids = sorted(
                {str(record.get("group_id")) for record in covered if record.get("group_id") is not None}
            )
            source_group_names = sorted(
                {str(record.get("group_name")) for record in covered if record.get("group_name")}
            )
            sole_group_id: Any = source_group_ids[0] if len(source_group_ids) == 1 else "MULTIPLE"
            sole_group_name: Any = source_group_names[0] if len(source_group_names) == 1 else "Multiple payload groups"

            rule = {
                "rule_id": id_start + offset,
                "group_id": sole_group_id,
                "group_name": sole_group_name,
                "source_group_ids": source_group_ids,
                "source_group_names": source_group_names,
                "target": "|".join(targets),
                "targets": targets,
                "encodings": encodings,
                "family": family,
                "primitive": primitive,
                "pattern": pattern,
                "transforms": list(transforms),
                "phase": phase,
                "normalization_step_profiles": step_profiles,
                "coverage_count": len(covered),
                "generic_header_target": any(bool(record["_generic_header_target"]) for record in covered),
                "review_status": "REVIEW_REQUIRED",
                "coverage_status": "PROPOSED_NOT_VALIDATED",
            }
            rules.append(rule)

            for record in covered:
                coverage_rows.append(
                    {
                        "stable_key": rules_module.stable_key(record),
                        "payload_path": record["payload_path"],
                        "variant": record["variant"],
                        "group_id": record.get("group_id"),
                        "rule_id": rule["rule_id"],
                        "primitive": primitive,
                        "zone": record.get("zone"),
                        "encoding": record.get("encoding"),
                        "rule_target": rule["target"],
                        "phase": phase,
                        "normalization_steps": ">".join(rules_module._normalization_steps(record)),
                        "transform_profile": ">".join(transforms),
                        "grouped_rule": len(covered) > 1,
                        "generic_header_target": bool(record["_generic_header_target"]),
                        "normalized_payload": record.get("normalized_payload"),
                    }
                )

        output_dir.mkdir(parents=True, exist_ok=True)
        conf_path = output_dir / "candidate-rules.conf"
        conf_path.write_text(
            "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n"
            "# Dynamic scanner headers may map to REQUEST_HEADERS; such rules have explicit FP/load warnings.\n"
            "# Transform profiles follow recorded normalization_steps; request phase follows the payload zone.\n"
            "# Semantically identical rules are deduplicated across payload groups and compatible targets.\n"
            "# Only recognized exploit primitives are emitted; fallback payload rules are skipped.\n\n"
            + "\n".join(rules_module._render_rule(rule) for rule in rules),
            encoding="utf-8",
        )

        coverage_fields = [
            "stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive",
            "zone", "encoding", "rule_target", "phase", "normalization_steps",
            "transform_profile", "grouped_rule", "generic_header_target", "normalized_payload",
        ]
        coverage_path = output_dir / "coverage.csv"
        rules_module._write_csv(coverage_path, coverage_rows, coverage_fields)
        coverage_jsonl_path = output_dir / "coverage.jsonl"
        rules_module.write_jsonl(coverage_jsonl_path, coverage_rows)

        skipped_fields = [
            "stable_key", "payload_path", "variant", "group_id", "category", "family",
            "zone", "encoding", "payload_component", "payload_name", "normalization_complete",
            "normalization_steps", "reason", "detail", "invisible_codepoints",
            "normalized_payload_preview",
        ]
        skipped_path = output_dir / "skipped.csv"
        rules_module._write_csv(skipped_path, skipped_rows, skipped_fields)
        skipped_jsonl_path = output_dir / "skipped.jsonl"
        rules_module.write_jsonl(skipped_jsonl_path, skipped_rows)

        grouped_rules = sum(rule["coverage_count"] > 1 for rule in rules)
        covered_variants = len(coverage_rows)
        reason_counts = dict(sorted(Counter(row["reason"] for row in skipped_rows).items()))
        manifest_path = output_dir / "manifest.json"
        rules_module.write_json(
            manifest_path,
            {
                "source": str(input_path),
                "confirmed_bypass_variants": len(records),
                "covered_variants": covered_variants,
                "skipped_variants": len(skipped_rows),
                "candidate_rules": len(rules),
                "grouped_rules": grouped_rules,
                "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
                "skip_reason_counts": reason_counts,
                "generation_policy": {
                    "recognized_primitives_only": True,
                    "family_fallbacks": False,
                    "narrow_fallbacks": False,
                    "dynamic_test_headers_target": "REQUEST_HEADERS",
                    "generic_header_fp_risk": "HIGH",
                    "generic_header_load_risk": "INCREASED",
                    "supported_encodings": sorted(rules_module.SUPPORTED_ENCODINGS),
                    "legacy_seclang_safe_regex": True,
                    "iterative_transport_decoding": True,
                    "args_name_targeting": True,
                    "zero_width_sql_patterns": True,
                    "csv_and_jsonl_indexes": True,
                    "skipped_payload_revision": True,
                    "quoted_fragment_patterns": True,
                    "normalization_trace_driven_transforms": True,
                    "phase_selected_by_request_zone": True,
                    "semantic_rule_deduplication": True,
                    "payload_group_provenance_preserved": True,
                    "targets_merged_only_for_identical_semantics": True,
                },
                "rules": rules,
            },
        )

        if covered_variants + len(skipped_rows) != len(records):
            raise RuntimeError("Each confirmed bypass must be covered or explicitly skipped")

        return {
            "confirmed_bypass_variants": len(records),
            "covered_variants": covered_variants,
            "skipped_variants": len(skipped_rows),
            "candidate_rules": len(rules),
            "grouped_rules": grouped_rules,
            "max_variants_per_rule": max(rule["coverage_count"] for rule in rules),
            "skip_reason_counts": reason_counts,
            "generic_header_rules": sum(bool(rule["generic_header_target"]) for rule in rules),
            "coverage": str(coverage_path),
            "coverage_jsonl": str(coverage_jsonl_path),
            "skipped": str(skipped_path),
            "skipped_jsonl": str(skipped_jsonl_path),
            "rules": str(conf_path),
            "manifest": str(manifest_path),
        }

    rules_module.suggest_rules = suggest_rules

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any


def apply_rule_dedup(rules_module: Any) -> None:
    """Post-process generated rules, merging only semantically identical safe targets."""
    base_suggest_rules = rules_module.suggest_rules

    def _partition(rule: dict[str, Any]) -> str:
        target = str(rule["target"])
        # Exact ordered transforms and phase are already part of the semantic key.
        # Generic REQUEST_HEADERS can therefore share a target union with ARGS,
        # cookies, URI and other ordinary collections when behavior is identical.
        # Named headers remain separate so a broad header collection never silently
        # subsumes a deliberately scoped REQUEST_HEADERS:<Name> rule.
        if target.startswith("REQUEST_HEADERS:"):
            return "specific-request-headers"
        return "mergeable-targets"

    def suggest_rules(input_path: Path, output_dir: Path, id_start: int) -> dict[str, Any]:
        summary = base_suggest_rules(input_path, output_dir, id_start)
        manifest_path = Path(summary["manifest"])
        manifest = rules_module.read_json(manifest_path)
        original_rules = list(manifest["rules"])

        clusters: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        for rule in original_rules:
            key = (
                rule["family"],
                rule["primitive"],
                rule["pattern"],
                tuple(rule["transforms"]),
                int(rule["phase"]),
                _partition(rule),
            )
            clusters[key].append(rule)

        deduplicated: list[dict[str, Any]] = []
        old_to_new: dict[int, int] = {}
        for offset, (_, members) in enumerate(
            sorted(clusters.items(), key=lambda item: tuple(map(str, item[0])))
        ):
            first = members[0]
            targets = rules_module._deduplicate_targets(
                {target for member in members for target in member.get("targets", [member["target"]])}
            )
            source_group_ids = sorted(
                {
                    str(group_id)
                    for member in members
                    for group_id in member.get("source_group_ids", [member.get("group_id")])
                    if group_id is not None and str(group_id) != "MULTIPLE"
                }
            )
            source_group_names = sorted(
                {
                    str(group_name)
                    for member in members
                    for group_name in member.get("source_group_names", [member.get("group_name")])
                    if group_name and str(group_name) != "Multiple payload groups"
                }
            )
            new_id = id_start + offset
            merged = {
                **first,
                "rule_id": new_id,
                "group_id": source_group_ids[0] if len(source_group_ids) == 1 else "MULTIPLE",
                "group_name": source_group_names[0] if len(source_group_names) == 1 else "Multiple payload groups",
                "source_group_ids": source_group_ids,
                "source_group_names": source_group_names,
                "target": "|".join(targets),
                "targets": targets,
                "encodings": sorted({encoding for member in members for encoding in member.get("encodings", [])}),
                "normalization_step_profiles": sorted(
                    {profile for member in members for profile in member.get("normalization_step_profiles", [])}
                ),
                "coverage_count": sum(int(member["coverage_count"]) for member in members),
                "generic_header_target": any(bool(member.get("generic_header_target")) for member in members),
            }
            deduplicated.append(merged)
            for member in members:
                old_to_new[int(member["rule_id"])] = new_id

        coverage_path = Path(summary["coverage"])
        coverage_jsonl_path = Path(summary["coverage_jsonl"])
        coverage_rows = rules_module.read_jsonl(coverage_jsonl_path)
        rule_targets = {int(rule["rule_id"]): rule["target"] for rule in deduplicated}
        grouped_by_id = {int(rule["rule_id"]): int(rule["coverage_count"]) > 1 for rule in deduplicated}
        for row in coverage_rows:
            new_id = old_to_new[int(row["rule_id"])]
            row["rule_id"] = new_id
            row["rule_target"] = rule_targets[new_id]
            row["grouped_rule"] = grouped_by_id[new_id]

        coverage_fields = [
            "stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive",
            "zone", "encoding", "rule_target", "phase", "normalization_steps",
            "transform_profile", "grouped_rule", "generic_header_target", "normalized_payload",
        ]
        rules_module._write_csv(coverage_path, coverage_rows, coverage_fields)
        rules_module.write_jsonl(coverage_jsonl_path, coverage_rows)

        conf_path = Path(summary["rules"])
        conf_path.write_text(
            "# Auto-generated candidate SecLang rules. DO NOT auto-load.\n"
            "# Dynamic scanner headers may map to REQUEST_HEADERS; such rules have explicit FP/load warnings.\n"
            "# Transform profiles follow recorded normalization_steps; request phase follows the payload zone.\n"
            "# Semantically identical rules are deduplicated across payload groups and safe target partitions.\n"
            "# Only recognized exploit primitives are emitted; fallback payload rules are skipped.\n\n"
            + "\n".join(rules_module._render_rule(rule) for rule in deduplicated),
            encoding="utf-8",
        )

        manifest["candidate_rules"] = len(deduplicated)
        manifest["grouped_rules"] = sum(int(rule["coverage_count"]) > 1 for rule in deduplicated)
        manifest["max_variants_per_rule"] = max(int(rule["coverage_count"]) for rule in deduplicated)
        manifest["rules"] = deduplicated
        manifest["generation_policy"].update(
            {
                "semantic_rule_deduplication": True,
                "payload_group_provenance_preserved": True,
                "targets_merged_only_for_identical_semantics": True,
                "encoded_targets_remain_separate": False,
                "encoded_targets_merge_when_transform_profiles_match": True,
                "generic_request_headers_merge_with_ordinary_targets": True,
                "generic_and_specific_headers_remain_separate": True,
            }
        )
        rules_module.write_json(manifest_path, manifest)

        summary.update(
            {
                "candidate_rules": len(deduplicated),
                "grouped_rules": manifest["grouped_rules"],
                "max_variants_per_rule": manifest["max_variants_per_rule"],
                "generic_header_rules": sum(bool(rule.get("generic_header_target")) for rule in deduplicated),
            }
        )
        return summary

    rules_module.suggest_rules = suggest_rules

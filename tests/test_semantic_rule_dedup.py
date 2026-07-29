from __future__ import annotations

import json
from pathlib import Path

from waf_automation.common import read_json, read_jsonl, write_jsonl
from waf_automation.rules import suggest_rules


def _record(*, payload_path: str, variant: str, group_id: str, group_name: str, zone: str, steps: list[str]) -> dict:
    return {
        "payload_path": payload_path,
        "variant": variant,
        "group_id": group_id,
        "group_name": group_name,
        "category": "XSS",
        "zone": zone,
        "encoding": "NONE",
        "normalization_steps": steps,
        "normalization_complete": True,
        "normalized_payload": "<img onerror=alert(1)>",
        "raw_payload": "<img onerror=alert(1)>",
        "final_verdict": "BYPASS_CONFIRMED",
    }


def test_merges_targets_and_preserves_payload_group_provenance(tmp_path: Path) -> None:
    input_path = tmp_path / "verified.jsonl"
    output_dir = tmp_path / "rules"
    write_jsonl(
        input_path,
        [
            _record(
                payload_path="group-a/payload-1",
                variant="args",
                group_id="group-a",
                group_name="Arguments",
                zone="ARGS",
                steps=["percent"],
            ),
            _record(
                payload_path="group-b/payload-2",
                variant="cookie",
                group_id="group-b",
                group_name="Cookies",
                zone="COOKIE",
                steps=["percent"],
            ),
        ],
    )

    result = suggest_rules(input_path, output_dir, 991000)

    assert result["candidate_rules"] == 1
    manifest = read_json(output_dir / "manifest.json")
    rule = manifest["rules"][0]
    assert rule["target"] == "ARGS|REQUEST_COOKIES"
    assert rule["source_group_ids"] == ["group-a", "group-b"]
    assert rule["source_group_names"] == ["Arguments", "Cookies"]
    assert rule["group_id"] == "MULTIPLE"
    assert manifest["generation_policy"]["semantic_rule_deduplication"] is True

    coverage = read_jsonl(output_dir / "coverage.jsonl")
    assert {row["group_id"] for row in coverage} == {"group-a", "group-b"}
    assert {row["rule_id"] for row in coverage} == {991000}
    assert {row["rule_target"] for row in coverage} == {"ARGS|REQUEST_COOKIES"}


def test_does_not_merge_different_transform_profiles(tmp_path: Path) -> None:
    input_path = tmp_path / "verified.jsonl"
    output_dir = tmp_path / "rules"
    write_jsonl(
        input_path,
        [
            _record(
                payload_path="group-a/payload-1",
                variant="single-decode",
                group_id="group-a",
                group_name="Single decode",
                zone="ARGS",
                steps=["percent"],
            ),
            _record(
                payload_path="group-b/payload-2",
                variant="double-decode",
                group_id="group-b",
                group_name="Double decode",
                zone="COOKIE",
                steps=["percent", "percent"],
            ),
        ],
    )

    result = suggest_rules(input_path, output_dir, 991000)

    assert result["candidate_rules"] == 2
    manifest = read_json(output_dir / "manifest.json")
    profiles = {tuple(rule["transforms"]) for rule in manifest["rules"]}
    assert profiles == {
        ("t:none", "t:urlDecodeUni", "t:lowercase"),
        ("t:none", "t:urlDecodeUni", "t:urlDecodeUni", "t:lowercase"),
    }


def test_does_not_merge_phase_one_and_phase_two(tmp_path: Path) -> None:
    input_path = tmp_path / "verified.jsonl"
    output_dir = tmp_path / "rules"
    write_jsonl(
        input_path,
        [
            _record(
                payload_path="group-a/payload-1",
                variant="args",
                group_id="group-a",
                group_name="Arguments",
                zone="ARGS",
                steps=[],
            ),
            _record(
                payload_path="group-b/payload-2",
                variant="body",
                group_id="group-b",
                group_name="Body",
                zone="BODY",
                steps=[],
            ),
        ],
    )

    result = suggest_rules(input_path, output_dir, 991000)

    assert result["candidate_rules"] == 2
    manifest = read_json(output_dir / "manifest.json")
    assert {rule["phase"] for rule in manifest["rules"]} == {1, 2}

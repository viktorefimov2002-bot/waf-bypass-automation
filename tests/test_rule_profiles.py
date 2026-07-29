from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import write_jsonl
from waf_automation.rule_phase import phase_for_target, phase_for_targets
from waf_automation.rules import _phase_for_record, _transforms, suggest_rules


class RuleProfileTests(unittest.TestCase):
    def test_transforms_follow_normalization_steps_in_order(self) -> None:
        record = {
            "encoding": "BASE64",
            "normalization_steps": ["base64", "percent", "html_entity", "remove_nulls"],
        }
        self.assertEqual(
            _transforms(record),
            (
                "t:none",
                "t:base64DecodeExt",
                "t:urlDecodeUni",
                "t:htmlEntityDecode",
                "t:removeNulls",
                "t:lowercase",
            ),
        )

    def test_repeated_trace_steps_remain_repeated(self) -> None:
        record = {"encoding": "NONE", "normalization_steps": ["percent", "percent"]}
        self.assertEqual(
            _transforms(record),
            ("t:none", "t:urlDecodeUni", "t:urlDecodeUni", "t:lowercase"),
        )

    def test_encoding_fallback_is_narrow_when_trace_is_missing(self) -> None:
        self.assertEqual(
            _transforms({"encoding": "BASE64"}),
            ("t:none", "t:base64DecodeExt", "t:lowercase"),
        )
        self.assertEqual(
            _transforms({"encoding": "NONE"}),
            ("t:none", "t:lowercase"),
        )

    def test_phase_is_selected_from_actual_target_availability(self) -> None:
        for zone in ("URL", "COOKIE", "USER-AGENT", "REFERER"):
            self.assertEqual(_phase_for_record({"zone": zone}), 1)
        header_record = {
            "zone": "HEADER",
            "curl": "curl -H 'X-Api-Key: value' https://example.test/",
        }
        self.assertEqual(_phase_for_record(header_record), 1)
        self.assertEqual(_phase_for_record({"zone": "ARGS"}), 2)
        self.assertEqual(_phase_for_record({"zone": "BODY"}), 2)
        self.assertEqual(phase_for_target("REQUEST_HEADERS:Referer"), 1)
        self.assertEqual(phase_for_target("REQUEST_URI"), 1)
        self.assertEqual(phase_for_target("ARGS_NAMES"), 2)
        self.assertEqual(phase_for_targets(["REQUEST_HEADERS", "ARGS"]), 2)

    def test_generation_uses_maximum_phase_for_merged_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {
                "category": "XSS",
                "group_id": 85,
                "group_name": "XSS",
                "encoding": "NONE",
                "normalized_payload": "<svg onload=alert(1)>",
                "final_verdict": "BYPASS_CONFIRMED",
                "normalization_steps": ["percent"],
                "payload_path": "XSS/1.json",
            }
            records = [
                {**base, "variant": "ARGS", "zone": "ARGS"},
                {**base, "variant": "BODY", "zone": "BODY"},
            ]
            checked = root / "checked.jsonl"
            output_dir = root / "rules"
            write_jsonl(checked, records)

            summary = suggest_rules(checked, output_dir, 990000)
            self.assertEqual(summary["candidate_rules"], 1)

            rule_text = (output_dir / "candidate-rules.conf").read_text(encoding="utf-8")
            self.assertNotIn("phase:1", rule_text)
            self.assertIn("phase:2", rule_text)
            self.assertIn("SecRule ARGS|REQUEST_BODY", rule_text)
            self.assertNotIn("t:jsDecode", rule_text)
            self.assertNotIn("t:htmlEntityDecode", rule_text)
            self.assertNotIn("t:cssDecode", rule_text)

            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual({rule["phase"] for rule in manifest["rules"]}, {2})
            self.assertTrue(manifest["generation_policy"]["normalization_trace_driven_transforms"])
            self.assertTrue(manifest["generation_policy"]["phase_selected_by_target_availability"])
            self.assertTrue(manifest["generation_policy"]["merged_rule_uses_maximum_required_phase"])

            with (output_dir / "coverage.csv").open(encoding="utf-8") as handle:
                coverage = list(csv.DictReader(handle))
            self.assertEqual({row["phase"] for row in coverage}, {"2"})
            self.assertTrue(all(row["rule_target"] == "ARGS|REQUEST_BODY" for row in coverage))
            self.assertTrue(all(row["normalization_steps"] == "percent" for row in coverage))
            self.assertTrue(all("t:urlDecodeUni" in row["transform_profile"] for row in coverage))


if __name__ == "__main__":
    unittest.main()

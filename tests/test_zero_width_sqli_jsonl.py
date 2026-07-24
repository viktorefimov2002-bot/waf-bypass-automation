from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.rules import suggest_rules


class ZeroWidthSqliJsonlTests(unittest.TestCase):
    def test_zero_width_union_select_is_covered_and_indexes_are_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "verified.jsonl"
            payload = "' un\u200bion se\u200blect 1\u200b,2\u200b,3"
            record = {
                "category": "SQLi",
                "group_id": 81,
                "group_name": "SQL injection",
                "encoding": "NONE",
                "normalized_payload": payload,
                "normalization_complete": True,
                "normalization_steps": ["percent"],
                "final_verdict": "BYPASS_CONFIRMED",
                "payload_path": "SQLi/13.json",
                "variant": "ARGS",
                "zone": "ARGS",
                "payload_component": "ARG_VALUE",
                "payload_name": "param968b7a",
            }
            write_jsonl(input_path, [record])

            output_dir = root / "rules"
            summary = suggest_rules(input_path, output_dir, 999000)

            self.assertEqual(summary["covered_variants"], 1)
            self.assertEqual(summary["skipped_variants"], 0)
            self.assertTrue((output_dir / "coverage.csv").exists())
            self.assertTrue((output_dir / "coverage.jsonl").exists())
            self.assertTrue((output_dir / "skipped.csv").exists())
            self.assertTrue((output_dir / "skipped.jsonl").exists())

            coverage = read_jsonl(output_dir / "coverage.jsonl")
            self.assertEqual(coverage[0]["primitive"], "sqli_zero_width_union_select")
            self.assertEqual(coverage[0]["normalized_payload"], payload)

            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["generation_policy"]["zero_width_sql_patterns"])
            self.assertTrue(manifest["generation_policy"]["csv_and_jsonl_indexes"])

    def test_skipped_jsonl_preserves_invisible_codepoint_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "verified.jsonl"
            write_jsonl(input_path, [{
                "category": "SQLi",
                "group_id": 81,
                "group_name": "SQL injection",
                "encoding": "NONE",
                "normalized_payload": "opaque\u200bvalue",
                "normalization_complete": True,
                "normalization_steps": ["percent"],
                "final_verdict": "BYPASS_CONFIRMED",
                "payload_path": "SQLi/999.json",
                "variant": "COOKIE",
                "zone": "COOKIE",
            }])

            output_dir = root / "rules"
            with self.assertRaisesRegex(ValueError, "none matched"):
                suggest_rules(input_path, output_dir, 999000)


if __name__ == "__main__":
    unittest.main()

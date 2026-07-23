from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from waf_automation.common import read_jsonl, stable_key, write_jsonl
from waf_automation.validation import validate_fixes


class ValidateFixRuleMappingTests(unittest.TestCase):
    def test_validate_fix_includes_rule_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "verified.jsonl"
            record = {
                "payload_path": "SQLI/1.json",
                "variant": "ARGS",
                "zone": "ARGS",
                "encoding": "NONE",
                "group_id": 81,
                "group_name": "SQLI",
                "final_verdict": "BYPASS_CONFIRMED",
                "http_code": 200,
                "server_header": "nginx",
                "curl": "curl https://example.test/?q=union+select",
            }
            write_jsonl(before, [record])
            key = stable_key(record)

            coverage = root / "coverage.csv"
            with coverage.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "stable_key", "payload_path", "variant", "group_id", "rule_id",
                    "primitive", "zone", "encoding", "rule_target", "grouped_rule",
                ])
                writer.writeheader()
                writer.writerow({
                    "stable_key": key,
                    "payload_path": record["payload_path"],
                    "variant": record["variant"],
                    "group_id": 81,
                    "rule_id": 990014,
                    "primitive": "sqli_union_select",
                    "zone": "ARGS",
                    "encoding": "NONE",
                    "rule_target": "ARGS",
                    "grouped_rule": False,
                })

            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "rules": [{
                    "rule_id": 990014,
                    "primitive": "sqli_union_select",
                    "target": "ARGS",
                    "pattern": r"\bunion\b[\s\S]{0,64}\bselect\b",
                    "transforms": ["t:none", "t:urlDecodeUni", "t:lowercase"],
                }]
            }), encoding="utf-8")

            output_jsonl = root / "validation.jsonl"
            output_xlsx = root / "validation.xlsx"

            def fake_recheck(input_path: Path, output_path: Path, **kwargs):
                write_jsonl(output_path, [{
                    **record,
                    "http_code": 403,
                    "server_header": "pingora",
                    "final_verdict": "BLOCKED_BY_WAF",
                    "duration_ms": 42,
                }])
                return {"selected": 1, "executed": 1}

            with patch("waf_automation.validation.recheck_records", side_effect=fake_recheck):
                summary = validate_fixes(
                    before,
                    output_jsonl,
                    output_xlsx,
                    execute=True,
                    allow_host="example.test",
                    group_id=None,
                    limit=None,
                    timeout=5,
                    delay=0,
                    coverage_path=coverage,
                    manifest_path=manifest,
                )

            row = read_jsonl(output_jsonl)[0]
            self.assertEqual(row["status"], "FIXED")
            self.assertTrue(row["request_blocked_now"])
            self.assertEqual(row["rule_mapping_status"], "MAPPED")
            self.assertEqual(row["rule_id"], 990014)
            self.assertEqual(row["rule_primitive"], "sqli_union_select")
            self.assertEqual(row["rule_target"], "ARGS")
            self.assertIn("union", row["rule_pattern"])
            self.assertEqual(summary["mapped_to_rule"], 1)
            self.assertEqual(summary["fixed"], 1)
            self.assertTrue(output_xlsx.exists())

    def test_validate_fix_marks_missing_candidate_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "verified.jsonl"
            record = {
                "payload_path": "UWA/1.json",
                "variant": "COOKIE",
                "zone": "COOKIE",
                "encoding": "NONE",
                "group_id": 86,
                "group_name": "UWA",
                "final_verdict": "BYPASS_CONFIRMED",
                "http_code": 200,
                "server_header": "nginx",
                "curl": "curl https://example.test/",
            }
            write_jsonl(before, [record])
            output_jsonl = root / "validation.jsonl"
            output_xlsx = root / "validation.xlsx"

            def fake_recheck(input_path: Path, output_path: Path, **kwargs):
                write_jsonl(output_path, [{**record, "final_verdict": "BYPASS_CONFIRMED"}])
                return {"selected": 1, "executed": 1}

            with patch("waf_automation.validation.recheck_records", side_effect=fake_recheck):
                summary = validate_fixes(
                    before,
                    output_jsonl,
                    output_xlsx,
                    execute=True,
                    allow_host="example.test",
                    group_id=None,
                    limit=None,
                    timeout=5,
                    delay=0,
                )

            row = read_jsonl(output_jsonl)[0]
            self.assertEqual(row["status"], "STILL_BYPASSED")
            self.assertEqual(row["rule_mapping_status"], "NO_CANDIDATE_RULE")
            self.assertIsNone(row["rule_id"])
            self.assertEqual(summary["without_candidate_rule"], 1)


if __name__ == "__main__":
    unittest.main()

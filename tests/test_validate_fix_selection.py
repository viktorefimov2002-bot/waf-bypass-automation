from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from waf_automation.common import read_jsonl, stable_key, write_jsonl
from waf_automation.validation import validate_fixes


class ValidateFixSelectionTests(unittest.TestCase):
    def test_validate_fix_replays_only_records_present_in_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_path = root / "verified.jsonl"
            mapped = {
                "payload_path": "XSS/1.json", "variant": "ARGS", "zone": "ARGS",
                "encoding": "NONE", "group_id": 85, "group_name": "XSS",
                "final_verdict": "BYPASS_CONFIRMED", "http_code": 200,
                "server_header": "origin", "curl": "curl https://example.test/?q=alert(1)",
            }
            skipped = {
                "payload_path": "UWA/1.json", "variant": "COOKIE", "zone": "COOKIE",
                "encoding": "NONE", "group_id": 86, "group_name": "UWA",
                "final_verdict": "BYPASS_CONFIRMED", "http_code": 200,
                "server_header": "origin", "curl": "curl https://example.test/",
            }
            write_jsonl(before_path, [mapped, skipped])

            coverage_path = root / "coverage.csv"
            with coverage_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["stable_key", "rule_id", "primitive", "rule_target"])
                writer.writeheader()
                writer.writerow({
                    "stable_key": stable_key(mapped), "rule_id": "990001",
                    "primitive": "xss_execution_sink", "rule_target": "ARGS",
                })

            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({"rules": [{
                "rule_id": 990001, "primitive": "xss_execution_sink", "target": "ARGS",
                "pattern": "alert[(]", "transforms": ["t:none", "t:lowercase"],
            }]}), encoding="utf-8")

            def fake_recheck(input_path: Path, output_path: Path, **kwargs):
                selected = read_jsonl(input_path)
                self.assertEqual(len(selected), 1)
                self.assertEqual(stable_key(selected[0]), stable_key(mapped))
                write_jsonl(output_path, [{
                    **selected[0], "http_code": 403, "server_header": "waf",
                    "final_verdict": "BLOCKED_BY_WAF",
                }])
                return {"selected": 1, "executed": 1, "output": str(output_path)}

            output_jsonl = root / "fix-validation.jsonl"
            output_xlsx = root / "fix-validation.xlsx"
            with patch("waf_automation.validation.recheck_records", side_effect=fake_recheck):
                result = validate_fixes(
                    before_path, output_jsonl, output_xlsx, execute=True,
                    allow_host="example.test", group_id=None, limit=None,
                    timeout=5, delay=0, coverage_path=coverage_path,
                    manifest_path=manifest_path,
                )

            self.assertEqual(result["eligible_confirmed_bypasses"], 1)
            self.assertEqual(result["skipped_without_candidate_rule"], 1)
            self.assertEqual(result["records"], 1)
            rows = read_jsonl(output_jsonl)
            self.assertEqual(rows[0]["rule_id"], 990001)
            self.assertEqual(rows[0]["status"], "FIXED")

    def test_validate_fix_without_coverage_keeps_legacy_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before_path = root / "verified.jsonl"
            records = [{
                "payload_path": "XSS/1.json", "variant": "ARGS", "zone": "ARGS",
                "encoding": "NONE", "group_id": 85, "group_name": "XSS",
                "final_verdict": "BYPASS_CONFIRMED", "http_code": 200,
                "server_header": "origin", "curl": "curl https://example.test/",
            }]
            write_jsonl(before_path, records)

            def fake_recheck(input_path: Path, output_path: Path, **kwargs):
                self.assertEqual(input_path, before_path)
                write_jsonl(output_path, [{**records[0], "final_verdict": "BLOCKED_BY_WAF", "http_code": 403}])
                return {"selected": 1, "executed": 1, "output": str(output_path)}

            with patch("waf_automation.validation.recheck_records", side_effect=fake_recheck):
                result = validate_fixes(
                    before_path, root / "out.jsonl", root / "out.xlsx", execute=True,
                    allow_host="example.test", group_id=None, limit=None,
                    timeout=5, delay=0,
                )
            self.assertEqual(result["eligible_confirmed_bypasses"], 1)
            self.assertEqual(result["skipped_without_candidate_rule"], 0)


if __name__ == "__main__":
    unittest.main()

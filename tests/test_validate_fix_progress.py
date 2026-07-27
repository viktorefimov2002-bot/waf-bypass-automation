from __future__ import annotations

import csv
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from waf_automation.common import read_jsonl, stable_key, write_jsonl
from waf_automation.validation import validate_fixes


class ValidateFixProgressTests(unittest.TestCase):
    def _coverage(self, path: Path, record: dict, rule_id: int = 999001) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["stable_key", "rule_id", "primitive", "rule_target"],
            )
            writer.writeheader()
            writer.writerow({
                "stable_key": stable_key(record),
                "rule_id": rule_id,
                "primitive": "xss_execution_sink",
                "rule_target": "ARGS",
            })

    def test_legacy_confirmed_verdict_is_replayed_and_progress_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "payload_path": "XSS/1.json",
                "variant": "ARGS",
                "zone": "ARGS",
                "encoding": "NONE",
                "group_id": 85,
                "group_name": "XSS",
                "final_verdict": "BYPASS_ORIGIN_CONFIRMED",
                "http_code": 200,
                "server_header": "nginx",
                "curl": "curl https://example.test/?q=alert(1)",
            }
            before = root / "verified.jsonl"
            write_jsonl(before, [record])
            coverage = root / "coverage.csv"
            self._coverage(coverage, record)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"rules": [{
                "rule_id": 999001,
                "primitive": "xss_execution_sink",
                "target": "ARGS",
                "pattern": "alert[(]",
                "transforms": ["t:none", "t:lowercase"],
            }]}), encoding="utf-8")

            def fake_execute(_record, _timeout):
                return {
                    "checked_at": "2026-07-27T00:00:00+00:00",
                    "http_code": 403,
                    "server_header": "pingora",
                    "code_verdict": "BLOCKED_BY_CODE",
                    "route_verdict": "WAF_CONFIRMED",
                    "final_verdict": "BLOCKED_BY_WAF",
                    "duration_ms": 12,
                    "curl_exit_code": 0,
                    "stderr": "",
                }

            stderr = StringIO()
            with patch("waf_automation.recheck._execute", side_effect=fake_execute):
                with redirect_stderr(stderr):
                    result = validate_fixes(
                        before,
                        root / "fix-validation.jsonl",
                        root / "fix-validation.xlsx",
                        execute=True,
                        allow_host="example.test",
                        group_id=None,
                        limit=None,
                        timeout=5,
                        delay=0,
                        coverage_path=coverage,
                        manifest_path=manifest,
                    )

            self.assertEqual(result["records"], 1)
            self.assertEqual(result["fixed"], 1)
            self.assertIn("validate-fix selection", stderr.getvalue())
            self.assertIn("[1/1] replay XSS/1.json::ARGS", stderr.getvalue())
            replayed = read_jsonl(root / "fix-validation.replayed.jsonl")
            self.assertEqual(replayed[0]["final_verdict"], "BLOCKED_BY_WAF")

    def test_empty_coverage_match_fails_before_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {
                "payload_path": "XSS/1.json",
                "variant": "ARGS",
                "final_verdict": "BYPASS_CONFIRMED",
                "curl": "curl https://example.test/",
            }
            before = root / "verified.jsonl"
            write_jsonl(before, [record])
            coverage = root / "coverage.csv"
            coverage.write_text(
                "stable_key,rule_id,primitive,rule_target\nOTHER/1.json::ARGS,999001,xss_execution_sink,ARGS\n",
                encoding="utf-8",
            )
            manifest = root / "manifest.json"
            manifest.write_text('{"rules": []}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "No eligible confirmed bypasses"):
                validate_fixes(
                    before,
                    root / "fix-validation.jsonl",
                    root / "fix-validation.xlsx",
                    execute=True,
                    allow_host="example.test",
                    group_id=None,
                    limit=None,
                    timeout=5,
                    delay=0,
                    coverage_path=coverage,
                    manifest_path=manifest,
                )


if __name__ == "__main__":
    unittest.main()

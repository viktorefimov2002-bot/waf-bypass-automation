from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.curl_parser import extract_request, normalize_payload, split_curl
from waf_automation.diffing import diff_runs
from waf_automation.importer import import_report
from waf_automation.recheck import recheck_records, validate_replay_argv, verdict
from waf_automation.rules import suggest_rules


class ToolTests(unittest.TestCase):
    def test_curl_parser_does_not_execute_shell(self) -> None:
        command = "curl -X GET -H 'User-Agent: <svg/onload=alert(1)>' 'https://example.test/?q=x'"
        argv = split_curl(command)
        request = extract_request(command)
        self.assertEqual(argv[0], "curl")
        self.assertEqual(request["host"], "example.test")
        self.assertIn("<svg/onload=alert(1)>", request["headers"][0])

    def test_normalization(self) -> None:
        decoded, steps = normalize_payload(r"%5Cu003csvg%2Fonload%3Dalert%281%29%3E", "UTF-16")
        self.assertEqual(decoded, "<svg/onload=alert(1)>")
        self.assertIn("percent", steps)
        self.assertIn("js_unicode", steps)

    def test_verdict_matrix(self) -> None:
        self.assertEqual(verdict(403, "pingora")[2], "BLOCKED_WAF")
        self.assertEqual(verdict(200, "nginx/1.24.0 (Ubuntu)")[2], "BYPASS_ORIGIN_CONFIRMED")
        self.assertEqual(verdict(200, "pingora")[2], "BYPASS_WAF_CONTRACT_MISMATCH")
        self.assertEqual(verdict(200, None)[2], "BYPASS_ROUTE_UNCONFIRMED")

    def test_replay_rejects_local_file_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_replay_argv(split_curl("curl --config /etc/passwd https://example.test/"))
        with self.assertRaisesRegex(ValueError, "local file"):
            validate_replay_argv(split_curl("curl -d @/etc/passwd https://example.test/"))

    def test_import_dry_run_and_rule_suggestion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "groups.txt"
            groups.write_text("Первая группа\n", encoding="utf-8")
            taxonomy = root / "taxonomy.json"
            taxonomy.write_text(json.dumps({
                "additional_groups": [{"id": 85, "name": "Межсайтовый скриптинг (XSS)", "source": "local"}],
                "category_defaults": {"XSS": 85},
            }, ensure_ascii=False), encoding="utf-8")
            command = "curl -X GET -H 'User-Agent: test' 'https://example.test/?q=%3Csvg%2Fonload%3Dalert%281%29%3E'"
            report = root / "report.json"
            report.write_text(json.dumps({
                "TARGET": "https://example.test/",
                "BLOCK-CODE": [403],
                "BYPASSED": {"XSS/1.json": {"ARGS": "200 RESPONSE CODE"}},
                "cURL": {"BYPASSED": {"XSS/1.json": {"ARGS": command}}},
            }), encoding="utf-8")
            normalized = root / "normalized.jsonl"
            summary = import_report(report, groups, normalized, taxonomy, None)
            self.assertEqual(summary["variants"], 1)
            imported = read_jsonl(normalized)[0]
            self.assertEqual(imported["group_id"], 85)
            self.assertIn("<svg/onload=alert(1)>", imported["normalized_payload"])

            dry_run = root / "dry-run.jsonl"
            recheck_records(normalized, dry_run, group_id=85, execute=False, allow_host=None, limit=None, timeout=5, delay=0)
            self.assertEqual(read_jsonl(dry_run)[0]["final_verdict"], "DRY_RUN")

            confirmed = dict(imported)
            confirmed.update({
                "server_header": "nginx/1.24.0 (Ubuntu)",
                "route_verdict": "ORIGIN_CONFIRMED",
                "final_verdict": "BYPASS_ORIGIN_CONFIRMED",
            })
            checked = root / "checked.jsonl"
            write_jsonl(checked, [confirmed])
            output_dir = root / "rules"
            rule_summary = suggest_rules(checked, output_dir, 990000)
            self.assertEqual(rule_summary["confirmed_bypass_variants"], 1)
            self.assertIn("SecRule ARGS", (output_dir / "candidate-rules.conf").read_text(encoding="utf-8"))
            with (output_dir / "coverage.csv").open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)

    def test_diff_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {"payload_path": "XSS/1.json", "variant": "ARGS", "curl_hash": "same", "http_code": 200}
            before = root / "before.jsonl"
            after = root / "after.jsonl"
            write_jsonl(before, [{**base, "final_verdict": "BYPASS_ORIGIN_CONFIRMED"}])
            write_jsonl(after, [{**base, "http_code": 403, "final_verdict": "BLOCKED_WAF"}])
            diff_jsonl = root / "diff.jsonl"
            diff_xlsx = root / "diff.xlsx"
            diff_runs(before, after, diff_jsonl, diff_xlsx)
            self.assertEqual(read_jsonl(diff_jsonl)[0]["status"], "FIXED")
            self.assertTrue(diff_xlsx.exists())


if __name__ == "__main__":
    unittest.main()

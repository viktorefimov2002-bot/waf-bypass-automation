from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from waf_automation.common import code_verdict, read_jsonl, write_jsonl
from waf_automation.curl_parser import extract_request, normalize_payload, split_curl
from waf_automation.importer import import_report
from waf_automation.recheck import recheck_records, validate_replay_argv, verdict
from waf_automation.rules import suggest_rules
from waf_automation.validation import _fix_status, validate_fixes


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

    def test_verdict_matrix_and_custom_block_code(self) -> None:
        self.assertEqual(verdict(403, "pingora", [403])[2], "BLOCKED_BY_WAF")
        self.assertEqual(verdict(200, "nginx/1.24.0 (Ubuntu)", [403])[2], "BYPASS_CONFIRMED")
        self.assertEqual(verdict(200, "pingora", [403])[2], "BYPASS_UNCONFIRMED")
        self.assertEqual(verdict(403, "nginx/1.24.0 (Ubuntu)", [403])[2], "ROUTE_MISMATCH")
        self.assertEqual(verdict(406, "pingora", [406])[2], "BLOCKED_BY_WAF")
        self.assertEqual(code_verdict(406, [406]), "BLOCKED_BY_CODE")
        self.assertEqual(code_verdict(403, [406]), "BYPASS_BY_CODE")

    def test_replay_rejects_unsafe_options_and_redirects(self) -> None:
        with self.assertRaisesRegex(ValueError, "allowlist"):
            validate_replay_argv(split_curl("curl --config /etc/passwd https://example.test/"))
        with self.assertRaisesRegex(ValueError, "local file"):
            validate_replay_argv(split_curl("curl -d @/etc/passwd https://example.test/"))
        with self.assertRaisesRegex(ValueError, "redirect"):
            validate_replay_argv(split_curl("curl -L https://example.test/"))

    def test_import_uses_category_mapping_and_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "groups.txt"
            groups.write_text("Первая группа\n", encoding="utf-8")
            taxonomy = root / "taxonomy.json"
            taxonomy.write_text(json.dumps({
                "additional_groups": [
                    {"id": 85, "name": "Межсайтовый скриптинг (XSS)", "source": "local"},
                    {"id": 86, "name": "Неклассифицированные атаки на веб-приложения (UWA)", "source": "local"},
                ],
                "category_defaults": {"XSS": 85, "UWA": 86},
            }, ensure_ascii=False), encoding="utf-8")
            command = "curl -X GET -H 'User-Agent: test' 'https://example.test/?q=%3Csvg%2Fonload%3Dalert%281%29%3E'"
            report = root / "report.json"
            report.write_text(json.dumps({
                "TARGET": "https://example.test/",
                "BLOCK-CODE": [406],
                "BYPASSED": {"XSS/1.json": {"ARGS": "200 RESPONSE CODE"}},
                "cURL": {"BYPASSED": {"XSS/1.json": {"ARGS": command}}},
            }), encoding="utf-8")
            normalized = root / "normalized.jsonl"
            summary = import_report(report, groups, normalized, taxonomy, None)
            self.assertEqual(summary["variants"], 1)
            imported = read_jsonl(normalized)[0]
            self.assertEqual(imported["group_id"], 85)
            self.assertEqual(imported["block_codes"], [406])
            self.assertIn("<svg/onload=alert(1)>", imported["normalized_payload"])

            dry_run = root / "dry-run.jsonl"
            recheck_records(
                normalized, dry_run, group_id=None, execute=False, allow_host=None,
                limit=None, timeout=5, delay=0,
            )
            self.assertEqual(read_jsonl(dry_run)[0]["final_verdict"], "DRY_RUN")

    def test_rule_suggestion_groups_multiple_zones(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {
                "category": "XSS", "group_id": 85, "group_name": "Межсайтовый скриптинг (XSS)",
                "encoding": "NONE", "normalized_payload": "<svg onload=alert(1)>",
                "final_verdict": "BYPASS_CONFIRMED",
            }
            records = [
                {**base, "payload_path": "XSS/1.json", "variant": "ARGS", "zone": "ARGS"},
                {**base, "payload_path": "XSS/1.json", "variant": "COOKIE", "zone": "COOKIE"},
            ]
            checked = root / "checked.jsonl"
            write_jsonl(checked, records)
            output_dir = root / "rules"
            summary = suggest_rules(checked, output_dir, 990000)
            self.assertEqual(summary["confirmed_bypass_variants"], 2)
            self.assertEqual(summary["candidate_rules"], 1)
            self.assertEqual(summary["grouped_rules"], 1)
            self.assertEqual(summary["max_variants_per_rule"], 2)
            rule_text = (output_dir / "candidate-rules.conf").read_text(encoding="utf-8")
            self.assertIn("SecRule ARGS|REQUEST_COOKIES", rule_text)
            with (output_dir / "coverage.csv").open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["grouped_rule"] == "True" for row in rows))

    def test_validate_fix_statuses(self) -> None:
        self.assertEqual(_fix_status({"final_verdict": "BLOCKED_BY_WAF"}), "FIXED")
        self.assertEqual(_fix_status({"final_verdict": "BYPASS_CONFIRMED"}), "STILL_BYPASSED")
        self.assertEqual(_fix_status({"final_verdict": "CHECK_ERROR"}), "ERROR")
        self.assertEqual(_fix_status({"final_verdict": "BYPASS_UNCONFIRMED"}), "NEEDS_REVIEW")

    def test_validate_fixes_only_rechecks_confirmed_bypasses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.jsonl"
            confirmed = {
                "payload_path": "XSS/1.json", "variant": "ARGS", "group_id": 85,
                "group_name": "XSS", "final_verdict": "BYPASS_CONFIRMED",
                "http_code": 200, "server_header": "nginx", "curl": "curl https://example.test/",
            }
            blocked = {
                "payload_path": "XSS/2.json", "variant": "ARGS", "group_id": 85,
                "group_name": "XSS", "final_verdict": "BLOCKED_BY_WAF",
                "http_code": 403, "server_header": "pingora", "curl": "curl https://example.test/",
            }
            write_jsonl(before, [confirmed, blocked])
            output_jsonl = root / "validation.jsonl"
            output_xlsx = root / "validation.xlsx"

            def fake_recheck(input_path, output_path, **kwargs):
                self.assertTrue(kwargs["only_confirmed_bypasses"])
                write_jsonl(output_path, [{**confirmed, "http_code": 403, "server_header": "pingora", "final_verdict": "BLOCKED_BY_WAF"}])
                return {"selected": 1, "executed": 1, "output": str(output_path)}

            with patch("waf_automation.validation.recheck_records", side_effect=fake_recheck):
                summary = validate_fixes(
                    before, output_jsonl, output_xlsx, execute=True, allow_host="example.test",
                    group_id=None, limit=None, timeout=5, delay=0,
                )
            self.assertEqual(summary["records"], 1)
            self.assertEqual(summary["fixed"], 1)
            self.assertEqual(read_jsonl(output_jsonl)[0]["status"], "FIXED")
            self.assertTrue(output_xlsx.exists())


if __name__ == "__main__":
    unittest.main()

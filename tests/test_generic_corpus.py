from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.clustering import build_cluster_metadata
from waf_automation.common import read_jsonl
from waf_automation.curl_parser import extract_request, split_curl
from waf_automation.importer import import_report


class GenericCorpusTests(unittest.TestCase):
    def test_absolute_url_inside_data_is_not_request_url(self) -> None:
        command = "curl -X POST -d 'url=http://169.254.169.254/latest/meta-data/' 'https://example.test/fetch'"
        request = extract_request(command)
        self.assertEqual(request["url"], "https://example.test/fetch")
        self.assertEqual(request["data"], ["url=http://169.254.169.254/latest/meta-data/"])

    def test_absolute_url_inside_header_is_not_request_url(self) -> None:
        command = "curl -H 'X-Target: https://127.0.0.1/admin' https://example.test/"
        request = extract_request(command)
        self.assertEqual(request["url"], "https://example.test/")
        self.assertEqual(request["headers"], ["X-Target: https://127.0.0.1/admin"])

    def test_explicit_url_option_is_supported(self) -> None:
        request = extract_request("curl --url=https://example.test/path -d 'x=https://internal.test/'")
        self.assertEqual(request["url"], "https://example.test/path")

    def test_malformed_quote_does_not_invoke_shell_parser_failure(self) -> None:
        argv = split_curl("curl -H \"X-Test: a'b\" https://example.test/")
        self.assertEqual(argv[0], "curl")
        self.assertIn("https://example.test/", argv)

    def test_generic_cluster_is_primitive_and_zone_based(self) -> None:
        xss = build_cluster_metadata({
            "category": "XSS", "payload_path": "XSS/1.json", "zone": "ARGS",
            "payload_component": "ARG_VALUE", "encoding": "NONE",
            "normalization_steps": [], "normalized_payload": "<svg onload=alert(1)>",
        })
        ssrf = build_cluster_metadata({
            "category": "SSRF", "payload_path": "SSRF/1.json", "zone": "BODY",
            "payload_component": "REQUEST_BODY", "encoding": "NONE",
            "normalization_steps": [], "normalized_payload": "url=http://169.254.169.254/latest/meta-data/",
        })
        self.assertEqual(xss["attack_family"], "xss")
        self.assertEqual(xss["primary_primitive"], "xss_event_handler")
        self.assertEqual(ssrf["attack_family"], "ssrf")
        self.assertEqual(ssrf["primary_primitive"], "ssrf_internal_target")
        self.assertNotEqual(xss["cluster_key"], ssrf["cluster_key"])

    def test_importer_keeps_parse_failures_out_of_main_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "groups.txt"
            groups.write_text("Group one\n", encoding="utf-8")
            taxonomy = root / "taxonomy.json"
            taxonomy.write_text(json.dumps({"category_defaults": {"SSRF": 1}}), encoding="utf-8")
            report = root / "report.json"
            report.write_text(json.dumps({
                "TARGET": "https://example.test/",
                "BLOCK-CODE": [403],
                "BYPASSED": {
                    "SSRF/1.json": {"BODY": "200 RESPONSE CODE"},
                    "SSRF/2.json": {"BODY": "200 RESPONSE CODE"},
                },
                "cURL": {"BYPASSED": {
                    "SSRF/1.json": {"BODY": "curl -d 'url=http://169.254.169.254/' https://example.test/fetch"},
                    "SSRF/2.json": {"BODY": "not-curl https://example.test/"},
                }},
            }), encoding="utf-8")
            output = root / "normalized.jsonl"
            summary = import_report(report, groups, output, taxonomy, None)
            rows = read_jsonl(output)
            errors = read_jsonl(root / "normalized.import-errors.jsonl")
            self.assertEqual(summary["variants"], 1)
            self.assertEqual(summary["curl_parse_errors"], 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["attack_family"], "ssrf")
            self.assertEqual(rows[0]["primary_primitive"], "ssrf_internal_target")
            self.assertEqual(errors[0]["error_type"], "CURL_PARSE_ERROR")


if __name__ == "__main__":
    unittest.main()

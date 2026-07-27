from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.curl_parser import extract_payload_details, extract_request, normalize_payload_details
from waf_automation.importer import import_report
from waf_automation.rules import suggest_rules


class PayloadNormalizationTests(unittest.TestCase):
    def test_args_without_structural_name_preserves_raw_query(self) -> None:
        command = "curl -X GET 'https://example.test/?admin%2A%29%28%28%7Cuserpassword%3D%2A%29'"
        details = extract_payload_details(extract_request(command), "ARGS")
        self.assertEqual(details["component"], "ARG_NAME")
        self.assertEqual(details["value"], "admin%2A%29%28%28%7Cuserpassword%3D%2A%29")

    def test_named_argument_extracts_value(self) -> None:
        command = "curl 'https://example.test/?q=%3Csvg%20onload%3Dalert%281%29%3E'"
        details = extract_payload_details(extract_request(command), "ARGS")
        self.assertEqual(details["component"], "ARG_VALUE")
        self.assertEqual(details["name"], "q")
        self.assertEqual(details["value"], "%3Csvg%20onload%3Dalert%281%29%3E")

    def test_cookie_extracts_value_without_random_name(self) -> None:
        command = (
            "curl -H 'Cookie: WBC-2269fa="
            "Li4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Y2Jvb3QuaW5p' "
            "https://example.test/"
        )
        details = extract_payload_details(extract_request(command), "COOKIE")
        self.assertEqual(details["component"], "COOKIE_VALUE")
        self.assertEqual(details["name"], "WBC-2269fa")
        self.assertEqual(details["value"], "Li4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Y2Jvb3QuaW5p")
        result = normalize_payload_details(details["value"], "BASE64")
        self.assertEqual(result["value"], r"..\..\..\..\..\..\..\..\boot.ini")
        self.assertEqual(result["steps"], ["base64", "percent"])

    def test_multiple_cookies_normalize_values_without_names(self) -> None:
        command = "curl -H 'Cookie: session=abc; WBC-deadbe=PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+' https://example.test/"
        details = extract_payload_details(extract_request(command), "COOKIE")
        self.assertIsNone(details["name"])
        self.assertEqual(details["cookie_names"], ["session", "WBC-deadbe"])
        self.assertEqual(details["value"], "abc\nPHN2ZyBvbmxvYWQ9YWxlcnQoMSk+")

    def test_base64_then_percent_decode_ldap(self) -> None:
        raw = "YWRtaW4lMkElMjklMjglMjglN0N1c2VycGFzc3dvcmQlM0QlMkElMjk="
        result = normalize_payload_details(raw, "BASE64")
        self.assertEqual(result["value"], "admin*)((|userpassword=*)")
        self.assertEqual(result["steps"], ["base64", "percent"])
        self.assertIn("admin%2A%29%28%28%7Cuserpassword%3D%2A%29", result["layers"])

    def test_utf16_then_percent_decode_ldap(self) -> None:
        raw = r"\u0061\u0064\u006d\u0069\u006e\u0025\u0032\u0041\u0025\u0032\u0039\u0025\u0032\u0038\u0025\u0032\u0038\u0025\u0037\u0043\u0075\u0073\u0065\u0072\u0070\u0061\u0073\u0073\u0077\u006f\u0072\u0064\u0025\u0033\u0044\u0025\u0032\u0041\u0025\u0032\u0039"
        result = normalize_payload_details(raw, "UTF-16")
        self.assertEqual(result["value"], "admin*)((|userpassword=*)")
        self.assertEqual(result["steps"], ["js_unicode", "percent"])

    def test_nosqli_base64_query_with_ampersands_is_not_truncated(self) -> None:
        raw = "JTI3JTIw&&JTIwdGhpcy5wYXNzd29yZC5tYXRjaCUyOCUyRi4lMkElMkYlMjklMkYlMkYlMkIlMjUwMA=="
        result = normalize_payload_details(raw, "BASE64")
        self.assertEqual(result["value"], "'  this.password.match(/.*/)//+")
        self.assertEqual(result["steps"], ["base64", "percent", "percent", "remove_nulls"])

    def test_import_records_trace_and_suggests_args_names_with_layered_transforms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "groups.txt"
            groups.write_text("group\n", encoding="utf-8")
            taxonomy = root / "taxonomy.json"
            taxonomy.write_text(json.dumps({
                "additional_groups": [{"id": 50, "name": "LDAP", "source": "local"}],
                "category_defaults": {"LDAP": 50},
            }), encoding="utf-8")
            command = "curl -X GET 'https://example.test/?YWRtaW4lMkElMjklMjglMjglN0N1c2VycGFzc3dvcmQlM0QlMkElMjk='"
            report = root / "report.json"
            report.write_text(json.dumps({
                "TARGET": "https://example.test/",
                "BLOCK-CODE": [403],
                "BYPASSED": {"LDAP/14.json": {"ARGS:BASE64": "200 RESPONSE CODE"}},
                "cURL": {"BYPASSED": {"LDAP/14.json": {"ARGS:BASE64": command}}},
            }), encoding="utf-8")
            imported_path = root / "imported.jsonl"
            import_report(report, groups, imported_path, taxonomy, None)
            record = read_jsonl(imported_path)[0]
            self.assertEqual(record["payload_component"], "ARG_NAME")
            self.assertEqual(record["normalized_payload"], "admin*)((|userpassword=*)")
            self.assertEqual(record["normalization_steps"], ["base64", "percent"])
            self.assertGreaterEqual(len(record["normalization_layers"]), 3)
            record["final_verdict"] = "BYPASS_CONFIRMED"
            verified_path = root / "verified.jsonl"
            write_jsonl(verified_path, [record])
            rules_dir = root / "rules"
            suggest_rules(verified_path, rules_dir, 990000)
            rule_text = (rules_dir / "candidate-rules.conf").read_text(encoding="utf-8")
            self.assertIn("SecRule ARGS_NAMES", rule_text)
            self.assertIn("t:base64DecodeExt", rule_text)
            self.assertEqual(rule_text.count("t:urlDecodeUni"), 1)
            self.assertLess(rule_text.index("t:base64DecodeExt"), rule_text.index("t:urlDecodeUni"))
            self.assertIn("phase:1", rule_text)

    def test_import_cookie_records_name_and_normalized_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups = root / "groups.txt"
            groups.write_text("group\n", encoding="utf-8")
            taxonomy = root / "taxonomy.json"
            taxonomy.write_text(json.dumps({
                "additional_groups": [{"id": 31, "name": "LFI", "source": "local"}],
                "category_defaults": {"LFI": 31},
            }), encoding="utf-8")
            command = (
                "curl -H 'Cookie: WBC-2269fa="
                "Li4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Yy4uJTVjLi4lNWMuLiU1Y2Jvb3QuaW5p' "
                "https://example.test/"
            )
            report = root / "report.json"
            report.write_text(json.dumps({
                "TARGET": "https://example.test/",
                "BLOCK-CODE": [403],
                "BYPASSED": {"LFI/12.json": {"COOKIE:BASE64": "200 RESPONSE CODE"}},
                "cURL": {"BYPASSED": {"LFI/12.json": {"COOKIE:BASE64": command}}},
            }), encoding="utf-8")
            imported_path = root / "imported.jsonl"
            import_report(report, groups, imported_path, taxonomy, None)
            record = read_jsonl(imported_path)[0]
            self.assertEqual(record["payload_name"], "WBC-2269fa")
            self.assertEqual(record["payload_component"], "COOKIE_VALUE")
            self.assertEqual(record["normalized_payload"], r"..\..\..\..\..\..\..\..\boot.ini")
            self.assertEqual(record["normalization_steps"], ["base64", "percent"])
            self.assertTrue(record["raw_cookie"].startswith("WBC-2269fa="))


if __name__ == "__main__":
    unittest.main()

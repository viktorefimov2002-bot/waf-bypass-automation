from __future__ import annotations

import unittest

from waf_automation.rules import _select_signature, _validate_pattern


class DeepSkippedReviewTests(unittest.TestCase):
    def assert_primitive(self, category: str, payload: str, expected: str) -> None:
        signature = _select_signature({"category": category, "normalized_payload": payload})
        self.assertIsNotNone(signature, payload)
        assert signature is not None
        self.assertEqual(signature[1], expected)
        _validate_pattern(signature[2])

    def test_sql_escaped_quoted_fragment(self) -> None:
        self.assert_primitive(
            "SQLi",
            r'uni\",\"on sel\",\"ect 1,2,3,4,5,6,7,8,9\',11',
            "sqli_escaped_quoted_fragment_union_select",
        )

    def test_ssrf_template_file_paths(self) -> None:
        self.assert_primitive(
            "SSRF",
            "file:${br}/et${u}c/pas${te}swd?/",
            "ssrf_template_file_path",
        )
        self.assert_primitive(
            "SSRF",
            "file:$(br)/et$(u)c/pas$(te)swd?/",
            "ssrf_template_file_path",
        )

    def test_fragmented_javascript_scheme(self) -> None:
        self.assert_primitive(
            "XSS",
            '<a href="j\tavascript:a\tlert()">x</a>',
            "xss_fragmented_javascript_scheme",
        )

    def test_tagged_dangerous_calls(self) -> None:
        self.assert_primitive(
            "XSS",
            "Array.prototype.sort.call`${alert}1337`",
            "xss_tagged_dangerous_call",
        )
        self.assert_primitive(
            "XSS",
            "Reflect.set.call`${location}${'href'}${name}`",
            "xss_tagged_dangerous_call",
        )

    def test_css_escaped_javascript(self) -> None:
        self.assert_primitive(
            "XSS",
            r"<style>*{background-image:url('\6A\61\76\61\73\63\72\69\70\74\3A\61\6C\65\72\74')}</style>",
            "xss_css_escaped_javascript",
        )

    def test_malformed_svg_entity(self) -> None:
        self.assert_primitive("XSS", "lt;svg/onload", "xss_malformed_svg_entity")

    def test_suspicious_ssrf_remote_script(self) -> None:
        self.assert_primitive(
            "SSRF",
            "http://evil.example.com/c99.php",
            "ssrf_suspicious_remote_script",
        )

    def test_webshell_polyglot_path(self) -> None:
        self.assert_primitive("UWA", "/do.php嘊.png", "webshell_polyglot_path")


if __name__ == "__main__":
    unittest.main()

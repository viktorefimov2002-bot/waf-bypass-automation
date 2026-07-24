from __future__ import annotations

import unittest

from waf_automation.rules import _select_signature, _validate_pattern


class PrimitiveExpansionRound3Tests(unittest.TestCase):
    def assert_primitive(self, category: str, payload: str, expected: str) -> None:
        signature = _select_signature({"category": category, "normalized_payload": payload})
        self.assertIsNotNone(signature, payload)
        assert signature is not None
        self.assertEqual(signature[1], expected)
        _validate_pattern(signature[2])

    def test_sql_quoted_fragment_union_select(self) -> None:
        self.assert_primitive(
            "SQLi",
            'uni\",\"on sel\",\"ect 1,2,3,4,5,6,7,8,9\',11',
            "sqli_quoted_fragment_union_select",
        )

    def test_xss_concatenated_alert(self) -> None:
        self.assert_primitive("XSS", "'ale'+'rt'()", "xss_concatenated_sink")
        self.assert_primitive("XSS", "a'ale'+'rt'()", "xss_concatenated_sink")

    def test_xss_whitespace_and_parenthesized_alert(self) -> None:
        self.assert_primitive("XSS", "a l e r t(1)", "xss_whitespace_sink")
        self.assert_primitive("XSS", "(alert)(1)", "xss_parenthesized_sink")

    def test_xss_tagged_call_and_constructor_chain(self) -> None:
        self.assert_primitive("XSS", "alert.call`x`", "xss_tagged_call")
        self.assert_primitive("XSS", "constructor['constructor']('alert(1)')()", "xss_constructor_chain")


if __name__ == "__main__":
    unittest.main()

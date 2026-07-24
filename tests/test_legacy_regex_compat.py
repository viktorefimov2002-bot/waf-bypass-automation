from __future__ import annotations

import unittest

from waf_automation.rules import SIGNATURES, _select_signature, _validate_pattern


class LegacyRegexCompatibilityTests(unittest.TestCase):
    def test_no_backslash_only_character_classes_are_generated(self) -> None:
        for family, signatures in SIGNATURES.items():
            for primitive, pattern in signatures:
                with self.subTest(family=family, primitive=primitive):
                    self.assertNotIn(r"[\\]", pattern)
                    _validate_pattern(pattern)

    def test_escaped_quoted_sql_uses_hex_backslash(self) -> None:
        signature = _select_signature(
            {
                "category": "SQLi",
                "normalized_payload": r'uni\",\"on sel\",\"ect 1,2,3',
            }
        )
        self.assertIsNotNone(signature)
        assert signature is not None
        self.assertEqual(signature[1], "sqli_escaped_quoted_fragment_union_select")
        self.assertIn(r"\x5c", signature[2])
        self.assertNotIn(r"[\\]", signature[2])

    def test_jndi_and_css_patterns_use_legacy_safe_backslash(self) -> None:
        jndi = _select_signature({"category": "RCE", "normalized_payload": r"$\{jndi:ldap://x}"})
        css = _select_signature(
            {
                "category": "XSS",
                "normalized_payload": r"background-image:url(\6a\61\76\61\73\63\72\69\70\74\3a alert(1))",
            }
        )
        self.assertIsNotNone(jndi)
        self.assertIsNotNone(css)
        assert jndi is not None and css is not None
        self.assertEqual(jndi[1], "jndi_lookup")
        self.assertEqual(css[1], "xss_css_escaped_javascript")
        self.assertNotIn(r"[\\]", jndi[2])
        self.assertNotIn(r"[\\]", css[2])


if __name__ == "__main__":
    unittest.main()

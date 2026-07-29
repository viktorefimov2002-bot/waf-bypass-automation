from __future__ import annotations

import unittest

from waf_automation.rules import _render_rule


class RuleMetadataTests(unittest.TestCase):
    def _rule(self, family: str, primitive: str) -> dict:
        return {
            "rule_id": 990001,
            "phase": 1,
            "transforms": ["t:none", "t:lowercase"],
            "family": family,
            "primitive": primitive,
            "coverage_count": 1,
            "targets": ["ARGS"],
            "encodings": ["NONE"],
            "target": "ARGS",
            "pattern": "test",
            "generic_header_target": False,
        }

    def test_xss_bidi_rule_has_descriptive_message_and_tags(self) -> None:
        rendered = _render_rule(self._rule("xss", "xss_bidi_script_tag"))
        self.assertIn(
            "msg:'XSS script tag obfuscated with bidirectional Unicode control characters'",
            rendered,
        )
        self.assertIn("tag:'xss'", rendered)
        self.assertIn("tag:'primitive/xss_bidi_script_tag'", rendered)
        self.assertNotIn("Candidate coverage for confirmed waf-bypass", rendered)

    def test_sqli_and_ssrf_rules_use_family_tags(self) -> None:
        sqli = _render_rule(self._rule("sqli", "sqli_union_select"))
        ssrf = _render_rule(self._rule("ssrf", "internal_url"))
        self.assertIn("tag:'sqli'", sqli)
        self.assertIn("msg:'SQL injection UNION SELECT sequence detected'", sqli)
        self.assertIn("tag:'ssrf'", ssrf)
        self.assertIn("msg:'SSRF request targeting a local or private network address'", ssrf)

    def test_unknown_primitive_uses_readable_fallback(self) -> None:
        rendered = _render_rule(self._rule("custom", "custom_encoded_probe"))
        self.assertIn("msg:'CUSTOM pattern detected: custom encoded probe'", rendered)
        self.assertIn("tag:'custom'", rendered)


if __name__ == "__main__":
    unittest.main()

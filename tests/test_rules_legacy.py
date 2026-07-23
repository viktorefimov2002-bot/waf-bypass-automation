from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import write_jsonl
from waf_automation.rules import SIGNATURES, suggest_rules


class LegacySecLangRuleTests(unittest.TestCase):
    def test_all_signature_patterns_avoid_legacy_control_escapes(self) -> None:
        for family, signatures in SIGNATURES.items():
            for primitive, pattern in signatures:
                with self.subTest(family=family, primitive=primitive):
                    self.assertNotIn(r"\r", pattern)
                    self.assertNotIn(r"\n", pattern)
                    self.assertNotIn(r"\t", pattern)
                    self.assertNotIn(r"\$\(", pattern)
                    self.assertNotIn('"', pattern)

    def test_command_substitution_uses_legacy_safe_regex(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checked = root / "checked.jsonl"
            write_jsonl(checked, [{
                "category": "CM",
                "group_id": 37,
                "group_name": "Внедрение команд ОС",
                "encoding": "NONE",
                "normalized_payload": "$(whoami)",
                "final_verdict": "BYPASS_CONFIRMED",
                "payload_path": "CM/1.json",
                "variant": "COOKIE",
                "zone": "COOKIE",
            }])
            output_dir = root / "rules"
            suggest_rules(checked, output_dir, 990000)

            rule_text = (output_dir / "candidate-rules.conf").read_text(encoding="utf-8")
            self.assertIn(r"@rx [$][(][^)]{1,256}[)]", rule_text)
            self.assertNotIn(r"\r", rule_text)
            self.assertNotIn(r"\n", rule_text)
            self.assertNotIn(r"\$\(", rule_text)

            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["generation_policy"]["legacy_seclang_safe_regex"])
            self.assertFalse(manifest["generation_policy"]["control_character_escapes"])


if __name__ == "__main__":
    unittest.main()

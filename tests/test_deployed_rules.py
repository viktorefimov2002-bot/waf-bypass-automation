from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from waf_automation.deployed_rules import category_matches_rule, load_deployed_rules, normalize_deployed_rule


class DeployedRuleMetadataTests(unittest.TestCase):
    def test_low_configured_score_is_weak_without_explicit_tag(self) -> None:
        rule = normalize_deployed_rule({
            "id": 10280,
            "name": "xss-supporting-detector",
            "score": 1,
            "tags": ["xss", "generic"],
        })
        self.assertEqual(rule["family"], "xss")
        self.assertEqual(rule["confidence"], "weak")
        self.assertTrue(category_matches_rule("XSS", rule))

    def test_explicit_confidence_tag_takes_precedence_over_score_fallback(self) -> None:
        rule = normalize_deployed_rule({
            "id": 10001,
            "name": "xss-high-confidence",
            "score": 1,
            "tags": ["xss", "strong-signal"],
        })
        self.assertEqual(rule["confidence"], "strong")

    def test_loads_yaml_pack_and_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "rules.yaml"
            pack.write_text(
                """version: 1
rules:
  - id: 10280
    name: xss-weak
    score: 1
    tags: [xss]
  - id: 14020
    name: php-context
    score: 3
    tags: [php, contextual-signal]
""",
                encoding="utf-8",
            )
            rules = load_deployed_rules(pack)
            self.assertEqual(rules["10280"]["confidence"], "weak")
            self.assertEqual(rules["14020"]["family"], "php")

            duplicate = root / "duplicate.yaml"
            duplicate.write_text(
                """rules:
  - id: 1
    tags: [xss]
  - id: 1
    tags: [xss]
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate rule id"):
                load_deployed_rules(duplicate)


if __name__ == "__main__":
    unittest.main()

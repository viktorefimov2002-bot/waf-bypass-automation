from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import write_jsonl
from waf_automation.rules import suggest_rules


class GenericHeaderDedupTests(unittest.TestCase):
    def test_generic_headers_merge_with_ordinary_targets_but_named_headers_do_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {
                "category": "XSS",
                "group_id": 85,
                "group_name": "XSS",
                "encoding": "BASE64",
                "normalized_payload": "<svg onload=alert(1)>",
                "final_verdict": "BYPASS_CONFIRMED",
                "payload_path": "XSS/1.json",
            }
            records = [
                {**base, "variant": "ARGS:BASE64", "zone": "ARGS"},
                {
                    **base,
                    "variant": "HEADER:BASE64-DYNAMIC",
                    "zone": "HEADER",
                    "curl": "curl -H 'wbh-12abef: PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+' https://example.test/",
                },
                {
                    **base,
                    "variant": "HEADER:BASE64",
                    "zone": "HEADER",
                    "curl": "curl -H 'X-Api-Key: PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+' https://example.test/",
                },
            ]
            checked = root / "checked.jsonl"
            write_jsonl(checked, records)
            output_dir = root / "rules"

            summary = suggest_rules(checked, output_dir, 990000)
            self.assertEqual(summary["candidate_rules"], 2)

            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            targets = {rule["target"] for rule in manifest["rules"]}
            self.assertIn("ARGS|REQUEST_HEADERS", targets)
            self.assertIn("REQUEST_HEADERS:X-Api-Key", targets)

            policy = manifest["generation_policy"]
            self.assertTrue(policy["generic_request_headers_merge_with_ordinary_targets"])
            self.assertTrue(policy["generic_and_specific_headers_remain_separate"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import write_jsonl
from waf_automation.rules import suggest_rules


class RuleGenerationExpansionTests(unittest.TestCase):
    def _run(self, records):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        source = root / "verified.jsonl"
        write_jsonl(source, records)
        output = root / "rules"
        summary = suggest_rules(source, output, 999000)
        return summary, output

    def test_dynamic_header_uses_generic_request_headers_with_warning(self):
        record = {
            "payload_path": "XSS/1.json", "variant": "HEADER:BASE64", "zone": "HEADER",
            "encoding": "BASE64", "category": "XSS", "group_id": 85, "group_name": "XSS",
            "normalized_payload": "<svg onload=alert(1)>", "normalization_complete": True,
            "normalization_steps": ["base64"], "final_verdict": "BYPASS_CONFIRMED",
            "curl": "curl -H 'WBH-a1b2c3: PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+' https://example.test/",
        }
        summary, output = self._run([record])
        text = (output / "candidate-rules.conf").read_text(encoding="utf-8")
        self.assertIn("SecRule REQUEST_HEADERS", text)
        self.assertIn("false positives", text)
        self.assertEqual(summary["generic_header_rules"], 1)
        with (output / "coverage.csv").open(encoding="utf-8") as handle:
            row = next(csv.DictReader(handle))
        self.assertEqual(row["generic_header_target"], "True")

    def test_new_primitives_cover_major_missing_families(self):
        base = {"zone": "ARGS", "payload_component": "ARG_NAME", "encoding": "NONE",
                "group_id": 1, "group_name": "test", "normalization_complete": True,
                "normalization_steps": [], "final_verdict": "BYPASS_CONFIRMED", "curl": "curl https://example.test/"}
        records = [
            {**base, "payload_path": "RCE/1.json", "variant": "ARGS", "category": "RCE", "normalized_payload": "${jndi:dns://example.test/a}"},
            {**base, "payload_path": "RFI/1.json", "variant": "ARGS", "category": "RFI", "normalized_payload": "php://filter/convert.base64-encode/resource=index.php"},
            {**base, "payload_path": "LFI/1.json", "variant": "ARGS", "category": "LFI", "normalized_payload": "C:/WINDOWS/Repair/SAM"},
            {**base, "payload_path": "SSTI/1.json", "variant": "ARGS", "category": "SSTI", "normalized_payload": "#{1*1}"},
            {**base, "payload_path": "OR/1.json", "variant": "ARGS", "category": "OR", "normalized_payload": "///google.com"},
        ]
        summary, output = self._run(records)
        self.assertEqual(summary["covered_variants"], 5)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        primitives = {rule["primitive"] for rule in manifest["rules"]}
        self.assertTrue({"jndi_lookup", "php_wrapper", "windows_sensitive_file", "spel_expression", "redirect_scheme_relative"}.issubset(primitives))

    def test_skipped_csv_has_diagnostic_context(self):
        record = {
            "payload_path": "UNKNOWN/1.json", "variant": "ARGS", "zone": "ARGS", "encoding": "NONE",
            "category": "UNKNOWN", "group_id": 1, "group_name": "unknown", "payload_component": "ARG_NAME",
            "normalized_payload": "opaque-payload", "normalization_complete": True, "normalization_steps": ["percent"],
            "final_verdict": "BYPASS_CONFIRMED", "curl": "curl https://example.test/?opaque-payload",
        }
        with self.assertRaisesRegex(ValueError, "none matched"):
            self._run([record])


if __name__ == "__main__":
    unittest.main()

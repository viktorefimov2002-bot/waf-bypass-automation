from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import write_jsonl
from waf_automation.refinement import refine_rules


class RefineRulesTests(unittest.TestCase):
    def test_refines_supported_utf16_sensitive_file_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validation = root / "fix-validation.jsonl"
            write_jsonl(validation, [{
                "stable_key": "payload-1", "status": "STILL_BYPASSED",
                "rule_id": 990003, "rule_primitive": "sensitive_local_file",
                "encoding": "UTF-16", "curl": "curl -H 'Cookie: file=\\u002fetc\\u002fpasswd' https://example.test/",
            }])

            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"rules": [{
                "rule_id": 990003, "target": "REQUEST_COOKIES", "targets": ["REQUEST_COOKIES"],
                "encodings": ["UTF-16"], "primitive": "sensitive_local_file",
                "pattern": "(?:/etc/passwd|/proc/self)",
                "transforms": ["t:none", "t:urlDecodeUni", "t:jsDecode", "t:lowercase", "t:removeNulls"],
                "coverage_count": 1,
            }]}), encoding="utf-8")

            coverage = root / "coverage.csv"
            with coverage.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["stable_key", "payload_path", "variant", "group_id", "rule_id", "primitive", "zone", "encoding", "rule_target", "grouped_rule"])
                writer.writeheader()
                writer.writerow({"stable_key": "payload-1", "rule_id": "990003", "primitive": "sensitive_local_file", "encoding": "UTF-16", "rule_target": "REQUEST_COOKIES"})

            result = refine_rules(validation, manifest, coverage, root / "out")
            self.assertEqual(result["refined_rules"], 1)
            refined = json.loads((root / "out" / "manifest.json").read_text(encoding="utf-8"))["rules"][0]
            self.assertEqual(refined["revision"], 2)
            self.assertIn("u002fetc", refined["pattern"])
            self.assertEqual(refined["coverage_status"], "REFINED_NOT_VALIDATED")

    def test_unsupported_rule_goes_to_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            validation = root / "fix-validation.jsonl"
            write_jsonl(validation, [{
                "stable_key": "payload-1", "status": "STILL_BYPASSED",
                "rule_id": 990014, "rule_primitive": "sqli_union_select",
                "encoding": "NONE", "curl": "curl https://example.test/?id=1",
            }])
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"rules": [{
                "rule_id": 990014, "target": "ARGS", "targets": ["ARGS"],
                "encodings": ["NONE"], "primitive": "sqli_union_select",
                "pattern": "union[\\s\\S]{0,64}select", "transforms": ["t:none", "t:lowercase"],
                "coverage_count": 1,
            }]}), encoding="utf-8")
            coverage = root / "coverage.csv"
            coverage.write_text("stable_key,payload_path,variant,group_id,rule_id,primitive,zone,encoding,rule_target,grouped_rule\npayload-1,,,,990014,sqli_union_select,,NONE,ARGS,false\n", encoding="utf-8")

            result = refine_rules(validation, manifest, coverage, root / "out")
            self.assertEqual(result["refined_rules"], 0)
            self.assertEqual(result["cannot_safely_refine"], 1)
            unresolved = (root / "out" / "unresolved.csv").read_text(encoding="utf-8")
            self.assertIn("CANNOT_SAFELY_REFINE", unresolved)


if __name__ == "__main__":
    unittest.main()

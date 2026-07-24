from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.rules import suggest_rules


class SkippedPrimitiveRevisionTests(unittest.TestCase):
    def test_revised_primitives_cover_representative_payloads(self) -> None:
        samples = [
            ("XSS", "alert.call(null,1)", "xss_call_apply"),
            ("NOSQLI", "'; return '' == '", "nosql_return_predicate"),
            ("SSTI", "*{T(java.lang.Runtime).getRuntime()}", "thymeleaf_expression"),
            ("LDAP", "' or count() = '", "xpath_boolean_injection"),
            ("SSRF", "sftp://example.com:22/", "remote_non_http_scheme"),
            ("OR", "http://[::ffff:216.58.214.206]", "redirect_ipv6_literal"),
            ("GRAPHQL", "query { __schema { types { name } } }", "graphql_introspection"),
            ("UWA", "/.git/config", "exposed_vcs"),
        ]
        records = []
        for index, (category, payload, _) in enumerate(samples, start=1):
            records.append({
                "category": category,
                "group_id": index,
                "group_name": category,
                "encoding": "NONE",
                "normalized_payload": payload,
                "final_verdict": "BYPASS_CONFIRMED",
                "payload_path": f"{category}/{index}.json",
                "variant": "ARGS",
                "zone": "ARGS",
            })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "verified.jsonl"
            output = root / "rules"
            write_jsonl(source, records)
            summary = suggest_rules(source, output, 997000)
            self.assertEqual(summary["covered_variants"], len(samples))
            coverage = read_jsonl(output / "coverage.jsonl")
            primitives = {row["primitive"] for row in coverage}
            for _, _, primitive in samples:
                self.assertIn(primitive, primitives)


if __name__ == "__main__":
    unittest.main()

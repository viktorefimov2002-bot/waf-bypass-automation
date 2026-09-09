from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from waf_automation.clustering import build_payload_classification, cluster_records
from waf_automation.common import read_jsonl, write_jsonl


class GenericClusteringTests(unittest.TestCase):
    def test_source_cluster_is_stable_across_transport_variants(self) -> None:
        base = {"category": "SQLI", "payload_path": "SQLI/7.json"}
        args = build_payload_classification({
            **base, "zone": "ARGS", "encoding": "NONE",
            "raw_payload": "1 union select 1", "normalized_payload": "1 union select 1",
        })
        body = build_payload_classification({
            **base, "zone": "BODY", "encoding": "BASE64",
            "raw_payload": "param12ab34=MSB1bmlvbiBzZWxlY3QgMQ==",
            "normalized_payload": "param12ab34=MSB1bmlvbiBzZWxlY3QgMQ==",
            "normalization_steps": ["base64"],
        })
        self.assertEqual(args["source_cluster_id"], body["source_cluster_id"])
        self.assertEqual(args["semantic_cluster_id"], body["semantic_cluster_id"])

    def test_semantic_cluster_removes_referer_and_url_placement_wrappers(self) -> None:
        base = {"category": "RFI", "payload_path": "RFI/2.json", "encoding": "NONE"}
        args = build_payload_classification({
            **base, "zone": "ARGS", "raw_payload": "https://remote.example/a", "normalized_payload": "https://remote.example/a",
        })
        referer = build_payload_classification({
            **base, "zone": "REFERER", "raw_payload": "http://example.com/?https://remote.example/a",
            "normalized_payload": "http://example.com/?https://remote.example/a",
        })
        url = build_payload_classification({
            **base, "zone": "URL", "raw_payload": "/https://remote.example/a",
            "normalized_payload": "/https://remote.example/a",
        })
        self.assertEqual(args["semantic_cluster_id"], referer["semantic_cluster_id"])
        self.assertEqual(args["semantic_cluster_id"], url["semantic_cluster_id"])

    def test_structural_cluster_reduces_numeric_and_literal_noise(self) -> None:
        first = build_payload_classification({
            "category": "GENERIC", "payload_path": "GENERIC/1.json", "zone": "ARGS", "encoding": "NONE",
            "raw_payload": "object[12345]['alpha'](1)", "normalized_payload": "object[12345]['alpha'](1)",
        })
        second = build_payload_classification({
            "category": "GENERIC", "payload_path": "GENERIC/2.json", "zone": "COOKIE", "encoding": "NONE",
            "raw_payload": "object[98765]['beta'](9)", "normalized_payload": "object[98765]['beta'](9)",
        })
        self.assertNotEqual(first["semantic_cluster_id"], second["semantic_cluster_id"])
        self.assertEqual(first["structural_cluster_id"], second["structural_cluster_id"])

    def test_category_boundary_prevents_cross_family_collision(self) -> None:
        common = {"payload_path": "1.json", "zone": "ARGS", "encoding": "NONE", "raw_payload": "sleep(5)", "normalized_payload": "sleep(5)"}
        xss = build_payload_classification({**common, "category": "XSS"})
        sqli = build_payload_classification({**common, "category": "SQLI"})
        self.assertNotEqual(xss["semantic_cluster_id"], sqli["semantic_cluster_id"])
        self.assertNotEqual(xss["structural_cluster_id"], sqli["structural_cluster_id"])

    def test_technique_tags_cover_multiple_attack_families(self) -> None:
        sqli = build_payload_classification({
            "category": "SQLI", "payload_path": "SQLI/1.json", "zone": "ARGS", "encoding": "NONE",
            "raw_payload": "1%20UNION%20SELECT%20name%20FROM%20users%20--%20x",
            "normalized_payload": "1 UNION SELECT name FROM users -- x", "normalization_steps": ["percent"],
        })
        lfi = build_payload_classification({
            "category": "LFI", "payload_path": "LFI/1.json", "zone": "URL", "encoding": "NONE",
            "raw_payload": "/../../etc/passwd", "normalized_payload": "/../../etc/passwd",
        })
        rce = build_payload_classification({
            "category": "RCE", "payload_path": "RCE/1.json", "zone": "ARGS", "encoding": "NONE",
            "raw_payload": "; bash -c id", "normalized_payload": "; bash -c id",
        })
        self.assertIn("primitive:sql-expression", sqli["techniques"])
        self.assertIn("obfuscation:percent-encoding", sqli["techniques"])
        self.assertIn("syntax:path-traversal", lfi["techniques"])
        self.assertIn("primitive:command-expression", rce["techniques"])

    def test_cluster_records_annotates_existing_diagnosed_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "diagnosed.jsonl"
            output = root / "clustered.jsonl"
            write_jsonl(source, [
                {
                    "category": "SQLI", "payload_path": "SQLI/1.json", "diagnosis": "DETECTION_GAP",
                    "zone": "ARGS", "encoding": "NONE", "raw_payload": "1 union select 1", "normalized_payload": "1 union select 1",
                },
                {
                    "category": "SQLI", "payload_path": "SQLI/1.json", "diagnosis": "SCORING_GAP",
                    "zone": "BODY", "encoding": "NONE", "raw_payload": "param12ab34=1 union select 1", "normalized_payload": "param12ab34=1 union select 1",
                },
            ])
            summary = cluster_records(source, output)
            records = read_jsonl(output)
            self.assertEqual(summary["records"], 2)
            self.assertEqual(summary["source_clusters"], 1)
            self.assertEqual(summary["semantic_clusters"], 1)
            self.assertIn("payload_classification", records[0])


if __name__ == "__main__":
    unittest.main()

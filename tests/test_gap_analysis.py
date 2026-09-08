from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.gap_analysis import analyze_gap_clusters, evidence_status
from waf_automation.handoff import build_handoff_case


class GapAnalysisTests(unittest.TestCase):
    def _record(
        self,
        payload_path: str,
        variant: str,
        zone: str,
        encoding: str,
        diagnosis: str,
        score: int | None,
        rule_id: str | None = None,
        normalized_payload: str = "logical-payload",
    ):
        matched_rules = [] if rule_id is None else [{"rule_id": rule_id, "score": score, "vendor": "generic-pack"}]
        return {
            "payload_path": payload_path,
            "variant": variant,
            "zone": zone,
            "encoding": encoding,
            "normalized_payload": normalized_payload,
            "diagnosis": diagnosis,
            "diagnosis_reason": diagnosis,
            "category": "XSS",
            "case_id": f"case-{payload_path}-{variant}",
            "test_id": f"test-{payload_path}-{variant}",
            "security_log": {
                "runtime_anomaly_threshold": 7,
                "anomaly_score": score,
                "matched_rules": matched_rules,
                "verdict": "Allow",
            },
        }

    def test_evidence_status_keeps_weak_detection_separate_from_true_gap(self) -> None:
        weak = self._record("XSS/1.json", "ARGS", "ARGS", "NONE", "SCORING_GAP", 1, "10280")
        stronger = self._record("XSS/1.json", "ARGS", "ARGS", "NONE", "SCORING_GAP", 4, "20140")
        missing = self._record("XSS/1.json", "ARGS", "ARGS", "NONE", "DETECTION_GAP", 0)
        other_source = self._record("XSS/1.json", "ARGS", "ARGS", "NONE", "BLOCKED_OTHER_SOURCE", 0)
        self.assertEqual(evidence_status(weak), "WEAK_PARTIAL")
        self.assertEqual(evidence_status(stronger), "PARTIAL")
        self.assertEqual(evidence_status(missing), "NO_DETECTION")
        self.assertEqual(evidence_status(other_source), "REVIEW")

    def test_analyze_gap_clusters_finds_normalization_and_target_contrasts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "diagnosed.jsonl"
            records = [
                self._record("XSS/276.json", "ARGS", "ARGS", "NONE", "DETECTION_GAP", 0),
                self._record("XSS/276.json", "ARGS:BASE64", "ARGS", "BASE64", "SCORING_GAP", 4, "20140"),
                self._record("XSS/192.json", "ARGS", "ARGS", "NONE", "SCORING_GAP", 1, "10280"),
                self._record("XSS/192.json", "COOKIE", "COOKIE", "NONE", "DETECTION_GAP", 0),
                self._record("XSS/300.json", "ARGS", "ARGS", "NONE", "DETECTION_GAP", 0),
                self._record("XSS/300.json", "BODY", "BODY", "NONE", "DETECTION_GAP", 0),
                self._record("XSS/400.json", "ARGS", "ARGS", "NONE", "CHECK_ERROR", None),
            ]
            write_jsonl(source, records)
            output_dir = root / "gap-analysis"
            summary = analyze_gap_clusters(source, output_dir)

            self.assertEqual(summary["clusters"], 4)
            self.assertEqual(summary["cluster_flags"]["NORMALIZATION_GAP_CANDIDATE"], 1)
            self.assertEqual(summary["cluster_flags"]["TARGET_GAP_CANDIDATE"], 1)
            self.assertEqual(summary["cluster_flags"]["PURE_DETECTION_GAP"], 1)
            self.assertEqual(summary["cluster_flags"]["REPLAY_ERROR_PRESENT"], 1)

            clusters = {record["payload_path"]: record for record in read_jsonl(output_dir / "clusters.jsonl")}
            self.assertIn("NORMALIZATION_GAP_CANDIDATE", clusters["XSS/276.json"]["flags"])
            self.assertEqual(clusters["XSS/276.json"]["primary_workstream"], "normalization-review")
            self.assertIn("TARGET_GAP_CANDIDATE", clusters["XSS/192.json"]["flags"])
            self.assertIn("PARTIAL_DETECTION_CANDIDATE", clusters["XSS/192.json"]["flags"])
            self.assertEqual(clusters["XSS/192.json"]["normalized_payload_variant_count"], 1)

            cases = read_jsonl(output_dir / "cases.jsonl")
            normalized_case = next(record for record in cases if record["payload_path"] == "XSS/276.json")
            self.assertEqual(normalized_case["gap_analysis"]["primary_workstream"], "normalization-review")

            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["policy"]["automatic_score_increase"])
            self.assertTrue(manifest["policy"]["rule_metadata_required_for_true_scoring_gap"])
            self.assertTrue(manifest["policy"]["comparative_gap_requires_equal_normalized_payload"])

    def test_target_contrast_requires_same_normalized_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "diagnosed.jsonl"
            records = [
                self._record(
                    "XSS/192.json", "ARGS", "ARGS", "NONE", "SCORING_GAP", 1, "10280",
                    normalized_payload="prompt(1)",
                ),
                self._record(
                    "XSS/192.json", "COOKIE", "COOKIE", "NONE", "DETECTION_GAP", 0,
                    normalized_payload="param123=(1)",
                ),
            ]
            write_jsonl(source, records)
            output_dir = root / "gap-analysis"
            summary = analyze_gap_clusters(source, output_dir)
            self.assertNotIn("TARGET_GAP_CANDIDATE", summary["cluster_flags"])
            cluster = read_jsonl(output_dir / "clusters.jsonl")[0]
            self.assertEqual(cluster["target_contrasts"], [])
            self.assertEqual(cluster["normalized_payload_variant_count"], 2)

    def test_handoff_prefers_gap_analysis_workstream(self) -> None:
        record = self._record("XSS/276.json", "ARGS:BASE64", "ARGS", "BASE64", "SCORING_GAP", 4, "20140")
        record["gap_analysis"] = {
            "cluster_id": "wba-gap-test",
            "evidence_status": "PARTIAL",
            "cluster_flags": ["NORMALIZATION_GAP_CANDIDATE", "SCORING_REVIEW_CANDIDATE"],
            "recommended_workstreams": ["normalization-review", "scoring-review"],
            "primary_workstream": "normalization-review",
            "score": 4,
            "threshold": 7,
            "matched_rule_ids": ["20140"],
        }
        handoff = build_handoff_case(record)
        self.assertEqual(handoff["recommended_workstream"], "normalization-review")
        self.assertEqual(handoff["gap_analysis"]["cluster_id"], "wba-gap-test")


if __name__ == "__main__":
    unittest.main()

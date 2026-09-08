from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.handoff import build_handoff_case, export_rule_engineering_corpus


class HandoffTests(unittest.TestCase):
    def _record(self, diagnosis: str, *, category: str = "XSS", score: int = 0):
        return {
            "case_id": f"case-{diagnosis.lower()}",
            "test_id": f"test-{diagnosis.lower()}",
            "replay_run_id": "run-1",
            "report_file": "waf-bypass.json",
            "payload_path": "XSS/1.json",
            "variant": "ARGS",
            "category": category,
            "group_id": 85,
            "group_name": category,
            "zone": "ARGS",
            "encoding": "NONE",
            "raw_payload": "<svg/onload=alert(1)>",
            "normalized_payload": "<svg/onload=alert(1)>",
            "payload_component": "ARG_VALUE",
            "payload_name": "q",
            "normalization_steps": [],
            "normalization_layers": ["<svg/onload=alert(1)>"],
            "request_host": "example.test",
            "request_method": "GET",
            "request_path": "/",
            "request_query": "q=%3Csvg%2Fonload%3Dalert%281%29%3E",
            "curl": "curl 'https://example.test/?q=%3Csvg%2Fonload%3Dalert%281%29%3E'",
            "http_code": 200,
            "server_header": "nginx",
            "route_verdict": "ORIGIN_CONFIRMED",
            "final_verdict": "BYPASS_CONFIRMED",
            "correlation_status": "MATCHED",
            "diagnosis": diagnosis,
            "diagnosis_reason": "test reason",
            "security_log": {
                "waf_request_id": "req-1",
                "request_host": "example.test",
                "request_uri_redacted": "/?q=...",
                "method": "GET",
                "path_template": "/",
                "content_type_detected": "application/x-www-form-urlencoded",
                "client_status": 200,
                "origin_status": 200,
                "runtime_anomaly_threshold": 7,
                "anomaly_score": score,
                "runtime_blocking_mode": "block",
                "phase_terminated": "req_headers",
                "verdict": "Allow",
                "decision_source": ["RuleEngine"],
                "matched_rules": ([{"rule_id": "100", "score": score, "vendor": "yaml"}] if score else []),
            },
        }

    def test_build_handoff_case_preserves_request_payload_and_evidence(self) -> None:
        case = build_handoff_case(self._record("SCORING_GAP", score=5))
        self.assertEqual(case["case_kind"], "attack")
        self.assertEqual(case["expected_outcome"], "block")
        self.assertEqual(case["recommended_workstream"], "scoring-review")
        self.assertEqual(case["payload"]["normalized"], "<svg/onload=alert(1)>")
        self.assertEqual(case["request"]["method"], "GET")
        self.assertEqual(case["waf_evidence"]["threshold"], 7)
        self.assertEqual(case["waf_evidence"]["matched_rules"][0]["rule_id"], "100")

    def test_export_defaults_to_actionable_gap_diagnoses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnosed = root / "diagnosed.jsonl"
            write_jsonl(diagnosed, [
                self._record("DETECTION_GAP"),
                self._record("SCORING_GAP", score=5),
                self._record("BLOCKED", score=7),
            ])
            output_dir = root / "handoff"
            summary = export_rule_engineering_corpus(diagnosed, output_dir)
            cases = read_jsonl(output_dir / "cases.jsonl")
            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(summary["records"], 2)
            self.assertEqual({case["diagnosis"] for case in cases}, {"DETECTION_GAP", "SCORING_GAP"})
            self.assertTrue((output_dir / "detection-gap.jsonl").exists())
            self.assertTrue((output_dir / "scoring-gap.jsonl").exists())
            self.assertFalse((output_dir / "blocked.jsonl").exists())
            self.assertFalse(manifest["policy"]["automatic_rule_generation"])

    def test_export_can_select_regression_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnosed = root / "diagnosed.jsonl"
            write_jsonl(diagnosed, [self._record("BLOCKED", score=7)])
            output_dir = root / "handoff"
            summary = export_rule_engineering_corpus(diagnosed, output_dir, ["BLOCKED"])
            self.assertEqual(summary["records"], 1)
            case = read_jsonl(output_dir / "blocked.jsonl")[0]
            self.assertEqual(case["recommended_workstream"], "regression-reference")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.diagnosis import diagnose_observation, diagnose_observations
from waf_automation.telemetry import correlate_logs, normalize_security_row


class TelemetryDiagnosisTests(unittest.TestCase):
    def test_normalizes_rule_details_and_numeric_verdict(self) -> None:
        row = normalize_security_row({
            "test_id": "wba-test-1",
            "rule_details": "[('1019',7,'baseline-handwritten'),('941210',5,'crs4')]",
            "runtime_anomaly_threshold": "7",
            "anomaly_score": "12",
            "verdict": 2,
            "decision_source": "['RuleEngine']",
        })
        self.assertEqual(row["verdict"], "Block")
        self.assertEqual(row["runtime_anomaly_threshold"], 7)
        self.assertEqual(row["anomaly_score"], 12)
        self.assertEqual(row["matched_rules"], [
            {"rule_id": "1019", "score": 7, "vendor": "baseline-handwritten"},
            {"rule_id": "941210", "score": 5, "vendor": "crs4"},
        ])
        self.assertEqual(row["decision_source"], ["RuleEngine"])

    def test_falls_back_to_correlated_rule_arrays(self) -> None:
        row = normalize_security_row({
            "test_id": "wba-test-2",
            "rule_numbers": ["2084", "30001"],
            "scores": [5, 2],
            "vendors": ["baseline-handwritten", "generic-yaml"],
        })
        self.assertEqual(row["matched_rules"][1], {
            "rule_id": "30001", "score": 2, "vendor": "generic-yaml",
        })

    def test_correlate_logs_joins_strictly_by_test_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            replay = root / "verified.jsonl"
            write_jsonl(replay, [
                {"case_id": "case-a", "test_id": "test-a", "category": "XSS", "final_verdict": "BYPASS_CONFIRMED"},
                {"case_id": "case-b", "test_id": "test-b", "category": "SQLI", "final_verdict": "BYPASS_CONFIRMED"},
            ])
            security = root / "security.jsonl"
            security.write_text(
                json.dumps({
                    "test_id": "test-a", "rule_details": [["100", 3, "yaml"]],
                    "runtime_anomaly_threshold": 7, "anomaly_score": 3, "verdict": "Allow",
                    "runtime_blocking_mode": "block", "decision_source": ["RuleEngine"],
                }) + "\n" + json.dumps({"test_id": "orphan", "verdict": "Allow"}) + "\n",
                encoding="utf-8",
            )
            output = root / "observations.jsonl"
            summary = correlate_logs(replay, security, output)
            records = read_jsonl(output)
            self.assertEqual(summary["matched"], 1)
            self.assertEqual(summary["log_not_found"], 1)
            self.assertEqual(summary["orphan_security_log_rows"], 1)
            self.assertEqual(records[0]["correlation_status"], "MATCHED")
            self.assertEqual(records[0]["security_log"]["matched_rules"][0]["rule_id"], "100")
            self.assertEqual(records[1]["correlation_status"], "LOG_NOT_FOUND")

    def test_duplicate_test_id_is_not_silently_joined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            replay = root / "verified.jsonl"
            write_jsonl(replay, [{"case_id": "case-a", "test_id": "test-a"}])
            security = root / "security.json"
            security.write_text(json.dumps([
                {"test_id": "test-a", "verdict": "Allow"},
                {"test_id": "test-a", "verdict": "Block"},
            ]), encoding="utf-8")
            output = root / "observations.jsonl"
            summary = correlate_logs(replay, security, output)
            record = read_jsonl(output)[0]
            self.assertEqual(summary["multiple_log_matches"], 1)
            self.assertEqual(record["correlation_status"], "MULTIPLE_LOG_MATCHES")
            self.assertIsNone(record["security_log"])
            self.assertEqual(len(record["security_log_matches"]), 2)

    def _observation(self, **log_values):
        log = {
            "verdict": "Allow",
            "runtime_blocking_mode": "block",
            "runtime_anomaly_threshold": 7,
            "anomaly_score": 0,
            "matched_rules": [],
            "decision_source": ["RuleEngine"],
        }
        log.update(log_values)
        return {
            "correlation_status": "MATCHED",
            "final_verdict": "BYPASS_CONFIRMED",
            "security_log": log,
        }

    def test_diagnosis_matrix(self) -> None:
        diagnosis, _ = diagnose_observation(self._observation(
            verdict="Block", anomaly_score=7,
            matched_rules=[{"rule_id": "100", "score": 7, "vendor": "yaml"}],
        ))
        self.assertEqual(diagnosis, "BLOCKED")

        diagnosis, _ = diagnose_observation(self._observation())
        self.assertEqual(diagnosis, "DETECTION_GAP")

        diagnosis, _ = diagnose_observation(self._observation(
            anomaly_score=5,
            matched_rules=[{"rule_id": "100", "score": 5, "vendor": "yaml"}],
        ))
        self.assertEqual(diagnosis, "SCORING_GAP")

        diagnosis, _ = diagnose_observation(self._observation(
            verdict="ShadowWouldBlock", runtime_blocking_mode="monitor", anomaly_score=8,
        ))
        self.assertEqual(diagnosis, "WOULD_BLOCK")

        diagnosis, _ = diagnose_observation(self._observation(
            verdict="Allow", runtime_blocking_mode="block", anomaly_score=7,
        ))
        self.assertEqual(diagnosis, "NEEDS_REVIEW")

        diagnosis, _ = diagnose_observation(self._observation(
            verdict="Block", anomaly_score=0, decision_source=["RateLimiter"],
        ))
        self.assertEqual(diagnosis, "BLOCKED_OTHER_SOURCE")

    def test_diagnose_writes_summary_and_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "observations.jsonl"
            write_jsonl(input_path, [
                {**self._observation(), "category": "XSS"},
                {**self._observation(anomaly_score=4, matched_rules=[{"rule_id": "1", "score": 4, "vendor": "yaml"}]), "category": "XSS"},
                {"category": "SQLI", "correlation_status": "LOG_NOT_FOUND", "final_verdict": "BYPASS_CONFIRMED", "security_log": None},
            ])
            output_path = root / "diagnosed.jsonl"
            summary = diagnose_observations(input_path, output_path)
            self.assertEqual(summary["diagnoses"]["DETECTION_GAP"], 1)
            self.assertEqual(summary["diagnoses"]["SCORING_GAP"], 1)
            self.assertEqual(summary["diagnoses"]["LOG_NOT_FOUND"], 1)
            self.assertEqual(summary["by_category"]["XSS"]["SCORING_GAP"], 1)
            self.assertEqual(read_jsonl(output_path)[0]["diagnosis"], "DETECTION_GAP")


if __name__ == "__main__":
    unittest.main()

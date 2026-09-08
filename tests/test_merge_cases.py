from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.merge_cases import merge_case_records


class MergeCaseTests(unittest.TestCase):
    def test_replaces_by_case_id_and_preserves_base_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.jsonl"
            updates = root / "updates.jsonl"
            output = root / "merged.jsonl"
            write_jsonl(base, [
                {"case_id": "a", "diagnosis": "CHECK_ERROR"},
                {"case_id": "b", "diagnosis": "DETECTION_GAP"},
            ])
            write_jsonl(updates, [
                {"case_id": "a", "diagnosis": "SCORING_GAP", "test_id": "new-test"},
            ])
            summary = merge_case_records(base, updates, output)
            merged = read_jsonl(output)
            self.assertEqual(summary["replaced"], 1)
            self.assertEqual(summary["output_records"], 2)
            self.assertEqual([record["case_id"] for record in merged], ["a", "b"])
            self.assertEqual(merged[0]["diagnosis"], "SCORING_GAP")
            self.assertEqual(merged[0]["test_id"], "new-test")

    def test_rejects_duplicate_update_case_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.jsonl"
            updates = root / "updates.jsonl"
            output = root / "merged.jsonl"
            write_jsonl(base, [{"case_id": "a"}])
            write_jsonl(updates, [{"case_id": "a"}, {"case_id": "a"}])
            with self.assertRaisesRegex(ValueError, "duplicate case_id"):
                merge_case_records(base, updates, output)


if __name__ == "__main__":
    unittest.main()

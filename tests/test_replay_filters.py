from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.recheck import recheck_records


class ReplayFilterTests(unittest.TestCase):
    def test_only_verdict_selects_prior_check_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "verified.jsonl"
            output = root / "retry.jsonl"
            write_jsonl(source, [
                {
                    "payload_path": "XSS/97.json",
                    "variant": "ARGS",
                    "group_id": 85,
                    "final_verdict": "CHECK_ERROR",
                    "curl": "curl 'https://example.test/?q=top[alert](1)'",
                },
                {
                    "payload_path": "XSS/98.json",
                    "variant": "ARGS",
                    "group_id": 85,
                    "final_verdict": "BYPASS_CONFIRMED",
                    "curl": "curl 'https://example.test/?q=alert(1)'",
                },
            ])
            summary = recheck_records(
                source,
                output,
                group_id=None,
                execute=False,
                allow_host=None,
                limit=None,
                timeout=5,
                delay=0,
                only_verdicts=["CHECK_ERROR"],
            )
            records = read_jsonl(output)
            self.assertEqual(summary["selected"], 1)
            self.assertEqual(summary["verdict_filter"], ["CHECK_ERROR"])
            self.assertEqual(records[0]["payload_path"], "XSS/97.json")


if __name__ == "__main__":
    unittest.main()

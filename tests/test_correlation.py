from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from waf_automation.common import read_jsonl, write_jsonl
from waf_automation.correlation import CORRELATION_HEADER, make_case_id, make_replay_run_id, make_test_id
from waf_automation.recheck import recheck_records


class CorrelationTests(unittest.TestCase):
    def test_case_id_is_stable_and_request_sensitive(self) -> None:
        first = make_case_id("XSS/1.json", "ARGS", "abc123")
        self.assertEqual(first, make_case_id("XSS/1.json", "ARGS", "abc123"))
        self.assertNotEqual(first, make_case_id("XSS/1.json", "ARGS", "different"))
        self.assertTrue(first.startswith("wba-case-"))

    def test_test_id_is_unique_per_replay_position(self) -> None:
        replay_run_id = make_replay_run_id()
        first = make_test_id(replay_run_id, 1, "wba-case-0123456789abcdef")
        second = make_test_id(replay_run_id, 2, "wba-case-0123456789abcdef")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith(replay_run_id + "-"))

    def test_dry_run_persists_correlation_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.jsonl"
            output = root / "output.jsonl"
            write_jsonl(source, [{
                "payload_path": "XSS/1.json",
                "variant": "ARGS",
                "group_id": 85,
                "curl": "curl 'https://example.test/?q=test'",
            }])

            summary = recheck_records(
                source, output, group_id=None, execute=False, allow_host=None,
                limit=None, timeout=5, delay=0,
            )
            result = read_jsonl(output)[0]
            self.assertEqual(result["correlation_header"], CORRELATION_HEADER)
            self.assertTrue(result["case_id"].startswith("wba-case-"))
            self.assertTrue(result["test_id"].startswith(summary["replay_run_id"] + "-"))
            self.assertFalse(result["correlation_sent"])

    def test_execute_injects_correlation_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.jsonl"
            output = root / "output.jsonl"
            write_jsonl(source, [{
                "payload_path": "XSS/1.json",
                "variant": "ARGS",
                "group_id": 85,
                "block_codes": [403],
                "curl": "curl 'https://example.test/?q=test'",
            }])

            seen_command: list[str] = []

            def fake_run(command, **kwargs):
                seen_command.extend(command)
                header_path = Path(command[command.index("--dump-header") + 1])
                header_path.write_bytes(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
                return subprocess.CompletedProcess(command, 0, stdout=b"200", stderr=b"")

            with patch("waf_automation.recheck.subprocess.run", side_effect=fake_run):
                recheck_records(
                    source, output, group_id=None, execute=True, allow_host="example.test",
                    limit=None, timeout=5, delay=0,
                )

            result = read_jsonl(output)[0]
            header_value = f"{CORRELATION_HEADER}: {result['test_id']}"
            self.assertIn("--header", seen_command)
            self.assertIn(header_value, seen_command)
            self.assertTrue(result["correlation_sent"])
            self.assertEqual(result["final_verdict"], "BYPASS_CONFIRMED")


if __name__ == "__main__":
    unittest.main()

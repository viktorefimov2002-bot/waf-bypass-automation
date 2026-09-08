from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4


CORRELATION_HEADER = "waf-fp-test-id"


def make_case_id(payload_path: str, variant: str, curl_hash_value: str) -> str:
    """Return a stable ID for the same imported request variant."""
    material = "\x00".join((payload_path, variant, curl_hash_value))
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"wba-case-{digest}"


def make_replay_run_id() -> str:
    """Return a unique ID for one verify/replay command invocation."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"wba-{timestamp}-{uuid4().hex[:8]}"


def make_test_id(replay_run_id: str, index: int, case_id: str) -> str:
    """Return a unique security-log correlation ID for one replayed request."""
    case_suffix = case_id.rsplit("-", 1)[-1][-8:]
    return f"{replay_run_id}-{index:06d}-{case_suffix}"

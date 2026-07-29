from __future__ import annotations

from typing import Any


PHASE_TWO_TARGETS = {
    "ARGS",
    "ARGS_NAMES",
    "ARGS_POST",
    "ARGS_POST_NAMES",
    "REQUEST_BODY",
    "FILES",
    "FILES_NAMES",
    "FILES_SIZES",
    "FILES_TMPNAMES",
    "MULTIPART_PART_HEADERS",
}


def phase_for_target(target: str) -> int:
    """Return the earliest phase in which the full SecLang target is available."""
    base_target = str(target).split(":", 1)[0].strip().upper()
    return 2 if base_target in PHASE_TWO_TARGETS else 1


def phase_for_targets(targets: list[str] | tuple[str, ...] | set[str]) -> int:
    """Use the latest required phase for a rule that scans multiple targets."""
    return max((phase_for_target(target) for target in targets), default=1)


def apply_rule_phase_mapping(rules_module: Any) -> None:
    """Select request phase from the actual generated SecLang target."""

    def _phase_for_record(record: dict[str, Any]) -> int:
        target, error, _ = rules_module._record_target(record)
        if error or not target:
            return 2
        return phase_for_target(target)

    rules_module.phase_for_target = phase_for_target
    rules_module.phase_for_targets = phase_for_targets
    rules_module._phase_for_record = _phase_for_record

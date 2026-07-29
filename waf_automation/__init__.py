"""Automation helpers for nemesida/waf-bypass reports."""

__version__ = "0.1.0"

# Keep the main rule generator compact while allowing reviewed primitive packs,
# output metadata, target-aware phases and safe semantic deduplication to extend it.
from . import rules as _rules
from .common import read_json as _read_json
from .extra_primitives import apply_extra_primitives as _apply_extra_primitives
from .rule_metadata import apply_rule_metadata as _apply_rule_metadata
from .rule_phase import apply_rule_phase_mapping as _apply_rule_phase_mapping
from .rule_dedup import apply_rule_dedup as _apply_rule_dedup

_rules.read_json = _read_json
_apply_extra_primitives(_rules.SIGNATURES)
_apply_rule_metadata(_rules)
_apply_rule_phase_mapping(_rules)
_apply_rule_dedup(_rules)

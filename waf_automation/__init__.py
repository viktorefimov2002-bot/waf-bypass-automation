"""Automation helpers for nemesida/waf-bypass reports."""

__version__ = "0.1.0"

# Keep the main rule generator compact while allowing reviewed primitive packs
# to extend its signature library during package initialization.
from . import rules as _rules
from .extra_primitives import apply_extra_primitives as _apply_extra_primitives

_apply_extra_primitives(_rules.SIGNATURES)

"""Signal layer (Phase 3, M1): registry of evidence-backed signals and the `signal_hits` builder."""

from .build import build_signal_hits, evaluate, signal_hits_path, signal_hits_sql
from .registry import SIGNALS, SIGNALS_BY_ID, SIGNALS_VERSION, Signal

__all__ = [
    "SIGNALS", "SIGNALS_BY_ID", "SIGNALS_VERSION", "Signal",
    "build_signal_hits", "evaluate", "signal_hits_path", "signal_hits_sql",
]

"""Sales-facing wording: safe rendering of registry `observed_fact_template`s.

Templates are `str.format` strings over the evidence fields below. Rendering
never raises and never prints `None`: missing, empty or unknown values render
as an em dash, and a template that is malformed or uses positional, attribute
or index access falls back to a generic fact sentence.
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from datetime import datetime
from typing import Any

MISSING = "—"
TEMPLATE_FIELDS = (
    "observed_at", "ip", "port", "transport", "sni", "product", "version", "http_title", "module",
    "detail", "sub_flags",
)
GENERIC_TEMPLATE = "On {observed_at} UTC, {ip}:{port}/{transport} matched signal {signal_id} ({detail})."


def _text(value: Any) -> str:
    if value is None:
        return MISSING
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")  # observed_at is naive UTC; templates say "UTC"
    if isinstance(value, (list, tuple)):
        parts = [_text(v) for v in value if v is not None and v != ""]
        return ", ".join(parts) if parts else MISSING
    text = str(value)
    return text if text else MISSING


class _Values(dict):
    def __missing__(self, key: str) -> str:
        return MISSING


class _SafeFormatter(string.Formatter):
    """Named fields only; no attribute or index access, no conversions."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> tuple[Any, str]:
        if not field_name.isidentifier():
            raise ValueError(f"unsupported field: {field_name!r}")
        return self.get_value(field_name, args, kwargs), field_name

    def get_value(self, key: Any, args: Any, kwargs: Any) -> Any:
        if not isinstance(key, str):
            raise ValueError("positional fields are not supported")
        return kwargs[key]

    def convert_field(self, value: Any, conversion: str | None) -> Any:
        if conversion is not None:
            raise ValueError("conversions are not supported")
        return value


_FORMATTER = _SafeFormatter()


def render_fact(template: str | None, row: Mapping[str, Any]) -> str:
    """Render an observed-fact sentence for one evidence row."""
    values = _Values({k: _text(v) for k, v in row.items()})
    if template:
        try:
            return _FORMATTER.vformat(template, (), values)
        except (ValueError, IndexError, KeyError, AttributeError, TypeError):
            pass
    return _FORMATTER.vformat(GENERIC_TEMPLATE, (), values)

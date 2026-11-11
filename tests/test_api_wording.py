"""Safe rendering of registry `observed_fact_template` strings."""

from __future__ import annotations

from datetime import datetime

import pytest

from firmable.api.wording import render_fact

ROW = {
    "observed_at": datetime(2026, 11, 7, 14, 52, 1), "ip": "192.0.2.7", "port": 22, "transport": "tcp",
    "sni": None, "product": "OpenSSH", "version": None, "http_title": None, "module": "ssh",
    "detail": "SSH", "sub_flags": None, "signal_id": "S01",
}


def test_renders_known_fields_and_blanks_missing():
    assert render_fact("{ip}:{port} {product} {version} [{sub_flags}]", ROW) == "192.0.2.7:22 OpenSSH — [—]"


def test_unknown_placeholder_renders_as_missing():
    assert render_fact("{ip} {nonexistent}", ROW) == "192.0.2.7 —"


def test_empty_string_and_empty_list_render_as_missing():
    assert render_fact("{sni}|{sub_flags}", {**ROW, "sni": "", "sub_flags": []}) == "—|—"


@pytest.mark.parametrize(
    "template",
    ["{ip.__class__}", "{ip[0]}", "{0}", "{}", "{port:d}", "{ip", "ip}"],
)
def test_malformed_or_attribute_templates_fall_back_to_generic_fact(template):
    out = render_fact(template, ROW)
    assert out == "On 2026-11-07 14:52 UTC, 192.0.2.7:22/tcp matched signal S01 (SSH)."
    assert "class" not in out


def test_none_template_falls_back():
    assert render_fact(None, ROW).startswith("On 2026-11-07 14:52 UTC")


def test_real_registry_templates_state_the_timezone_once():
    from firmable.signals import SIGNALS

    for s in SIGNALS:
        out = render_fact(s.observed_fact_template, ROW)
        assert out.count("UTC") == 1, (s.id, out)
        assert "2026-11-07 14:52 UTC" in out

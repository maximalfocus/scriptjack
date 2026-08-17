"""Unit tests for the deliberately naive half-fixed blocklist (FR-007)."""

from __future__ import annotations

from scriptjack.vulnerable.blocklist import naive_blocklist


def test_strips_a_literal_script_tag() -> None:
    out = naive_blocklist("<script>window.x=1</script>").lower()
    assert "<script>" not in out
    assert "</script>" not in out


def test_nested_tag_reconstitutes_a_working_script() -> None:
    # A single removal pass turns the nested tag back into <script>...</script>.
    out = naive_blocklist("<scr<script>ipt>window.x=1</scr<script>ipt>")
    assert "<script>" in out
    assert "</script>" in out


def test_event_handler_attributes_survive() -> None:
    assert "onerror" in naive_blocklist('<img src=x onerror="window.x=1">')
    assert "onload" in naive_blocklist('<svg onload="window.x=1"></svg>')


def test_removes_the_javascript_scheme() -> None:
    assert "javascript:" not in naive_blocklist('<a href="javascript:window.x=1()">x</a>')

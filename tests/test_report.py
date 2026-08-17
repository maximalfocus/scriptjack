"""Unit tests for the comparison report and verdict logic (no browser)."""

from __future__ import annotations

from scriptjack.cli.report import contrast_holds, format_report
from scriptjack.cli.results import ScenarioResult


def _vuln_stored(*, executed: bool = True) -> ScenarioResult:
    return ScenarioResult(
        app="vulnerable",
        shape="Stored (capability statement)",
        sink_context="server template → HTML",
        executed=executed,
        server_received_payload=True,
        verdict="VULNERABLE" if executed else "SECURE",
        token_beaconed=executed,
        approval_state="approved" if executed else "pending",
        authority="reviewer (victim)" if executed else None,
        collector_total=1 if executed else 0,
        detail="console records: 2",
    )


def _secure_stored(*, executed: bool = False) -> ScenarioResult:
    return ScenarioResult(
        app="secure",
        shape="Stored (capability statement)",
        sink_context="server template → HTML",
        executed=executed,
        server_received_payload=True,
        verdict="VULNERABLE" if executed else "SECURE",
        token_beaconed=executed,
        approval_state="approved" if executed else "pending",
        authority=None,
        collector_total=0,
        detail="console records: 0",
    )


def test_report_shows_headers_verdicts_and_the_httponly_lesson() -> None:
    out = format_report([_vuln_stored(), _secure_stored()])
    assert "Verdict" in out
    assert "VULNERABLE" in out
    assert "SECURE" in out
    assert "HttpOnly" in out  # the narrative carries the lesson


def test_verbose_adds_console_detail() -> None:
    out = format_report([_vuln_stored()], verbose=True)
    assert "Verbose detail" in out
    assert "console records: 2" in out


def test_contrast_holds_when_vulnerable_executes_and_secure_does_not() -> None:
    assert contrast_holds([_vuln_stored(), _secure_stored()])


def test_contrast_fails_if_the_secure_app_executes() -> None:
    assert not contrast_holds([_vuln_stored(), _secure_stored(executed=True)])


def test_contrast_fails_if_the_vulnerable_app_does_not_execute() -> None:
    assert not contrast_holds([_vuln_stored(executed=False), _secure_stored()])

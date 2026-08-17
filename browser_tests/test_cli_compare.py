"""The comparison CLI's scenario engine, driven through the real browser."""

from __future__ import annotations

import os

from playwright.sync_api import Browser

from scriptjack.cli.report import contrast_holds, format_report
from scriptjack.cli.scenarios import Targets, run_all


def _targets() -> Targets:
    return Targets(
        secure=os.environ.get("SCRIPTJACK_BASE_URL", "http://secure-app:8000"),
        vulnerable=os.environ.get("SCRIPTJACK_VULN_BASE_URL", "http://vulnerable-app:8000"),
        half_fixed=os.environ.get("SCRIPTJACK_HALF_FIXED_BASE_URL", "http://half-fixed-app:8000"),
        csp=os.environ.get("SCRIPTJACK_CSP_BASE_URL", "http://csp-vuln-app:8000"),
        collector=os.environ.get("SCRIPTJACK_COLLECTOR_URL", "http://collector:8000"),
    )


def test_scenario_engine_produces_the_full_contrast(browser: Browser) -> None:
    results = run_all(browser, _targets())
    by_key = {(r.app, r.shape): r for r in results}

    # The core contrast holds.
    assert contrast_holds(results)

    # Vulnerable stored — full chain.
    stored = by_key[("vulnerable", "Stored (capability statement)")]
    assert stored.executed
    assert stored.token_beaconed
    assert stored.approval_state == "approved"
    assert stored.authority is not None

    # Secure stored — nothing.
    assert not by_key[("secure", "Stored (capability statement)")].executed

    # DOM-based — executes but the server never received the fragment.
    dom = by_key[("vulnerable", "DOM-based (URL fragment)")]
    assert dom.executed
    assert not dom.server_received_payload

    # Half-fixed — literal <script> stripped, <img onerror> bypass executes.
    assert not by_key[("half-fixed", "Half-fixed: literal <script>")].executed
    assert by_key[("half-fixed", "Half-fixed: <img onerror> bypass")].executed

    # CSP-alone — injected but not executed.
    assert not by_key[("csp", "CSP-alone (still-vulnerable sink)")].executed

    # The rendered report names the verdicts.
    report = format_report(results)
    assert "VULNERABLE" in report
    assert "MITIGATED (CSP)" in report

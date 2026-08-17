"""The scenario engine: drives the browser across shapes and both applications.

Directly testable — it takes a Playwright ``Browser`` and returns structured
``ScenarioResult`` objects with no terminal interaction.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

from playwright.sync_api import Browser, ConsoleMessage, Dialog

from scriptjack.cli.results import ScenarioResult
from scriptjack.common.payloads import (
    CHAIN_PAYLOAD,
    CHAIN_TARGET_VENDOR,
    CSP_DEMO_PAYLOAD,
    DOM_PAYLOAD,
    HALF_FIXED_BYPASSES,
    HALF_FIXED_STRIPPED,
    REFLECTED_PAYLOAD,
    Payload,
)
from scriptjack.harness.driver import REVIEWER, VENDOR, Portal


@dataclass(frozen=True)
class Targets:
    secure: str
    vulnerable: str
    half_fixed: str
    csp: str
    collector: str


def collector_count(collector_url: str) -> int:
    try:
        with urllib.request.urlopen(f"{collector_url}/beacons", timeout=5) as response:
            data = json.loads(response.read().decode())
    except OSError:
        return 0
    count = data.get("count", 0)
    return count if isinstance(count, int) else 0


def _new_portal(browser: Browser, base_url: str) -> tuple[Portal, list[str]]:
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    dialogs: list[str] = []
    console: list[str] = []

    def on_dialog(dialog: Dialog) -> None:
        dialogs.append(dialog.message)
        dialog.dismiss()

    def on_console(message: ConsoleMessage) -> None:
        console.append(f"{message.type}: {message.text}")

    page.on("dialog", on_dialog)
    page.on("console", on_console)
    return Portal(page, dialogs), console


def _deliver(portal: Portal, delivery: str, payload: Payload) -> None:
    if delivery == "reflected":
        portal.login(*REVIEWER)
        portal.open_search(payload.html)
    elif delivery == "dom":
        portal.login(*REVIEWER)
        portal.open_filtered(payload.html)
    else:  # "stored"
        portal.login(*VENDOR)
        portal.submit_capability("Operating note.", payload.html)
        portal.login(*REVIEWER)
        portal.open_queue()
    portal.settle()


def _chain_scenario(browser: Browser, targets: Targets, app: str, base_url: str) -> ScenarioResult:
    before = collector_count(targets.collector)
    portal, console = _new_portal(browser, base_url)
    try:
        _deliver(portal, "stored", CHAIN_PAYLOAD)
        executed = portal.xss_marker() == "chain"
        approval = (
            "approved" if "approved" in portal.vendor_status(CHAIN_TARGET_VENDOR) else "pending"
        )
    finally:
        portal.page.context.close()
    after = collector_count(targets.collector)
    return ScenarioResult(
        app=app,
        shape="Stored (capability statement)",
        sink_context="server template → HTML",
        executed=executed,
        server_received_payload=True,
        verdict="VULNERABLE" if executed else "SECURE",
        token_beaconed=after > before,
        approval_state=approval,
        authority="reviewer (victim)" if executed else None,
        collector_total=after,
        detail=f"console records: {len(console)}",
    )


def _execution_scenario(
    browser: Browser,
    targets: Targets,
    app: str,
    base_url: str,
    payload: Payload,
    delivery: str,
    shape: str,
    sink_context: str,
    server_received: bool,
    verdict_safe: str,
    verdict_executed: str = "VULNERABLE",
) -> ScenarioResult:
    portal, console = _new_portal(browser, base_url)
    try:
        _deliver(portal, delivery, payload)
        executed = portal.xss_marker() == payload.marker
    finally:
        portal.page.context.close()
    return ScenarioResult(
        app=app,
        shape=shape,
        sink_context=sink_context,
        executed=executed,
        server_received_payload=server_received,
        verdict=verdict_executed if executed else verdict_safe,
        collector_total=collector_count(targets.collector),
        detail=f"console records: {len(console)}",
    )


def run_all(browser: Browser, targets: Targets) -> list[ScenarioResult]:
    return [
        # Stored — the full takeover chain, vulnerable vs secure.
        _chain_scenario(browser, targets, "vulnerable", targets.vulnerable),
        _chain_scenario(browser, targets, "secure", targets.secure),
        # Reflected — execution proof, vulnerable vs secure.
        _execution_scenario(
            browser,
            targets,
            "vulnerable",
            targets.vulnerable,
            REFLECTED_PAYLOAD,
            "reflected",
            "Reflected (search q)",
            "search q → HTML",
            True,
            "SECURE",
        ),
        _execution_scenario(
            browser,
            targets,
            "secure",
            targets.secure,
            REFLECTED_PAYLOAD,
            "reflected",
            "Reflected (search q)",
            "search q → text",
            True,
            "SECURE",
        ),
        # DOM-based — execution proof; the server never receives the fragment.
        _execution_scenario(
            browser,
            targets,
            "vulnerable",
            targets.vulnerable,
            DOM_PAYLOAD,
            "dom",
            "DOM-based (URL fragment)",
            "fragment → innerHTML",
            False,
            "SECURE",
        ),
        _execution_scenario(
            browser,
            targets,
            "secure",
            targets.secure,
            DOM_PAYLOAD,
            "dom",
            "DOM-based (URL fragment)",
            "fragment → textContent",
            False,
            "SECURE",
        ),
        # Half-fixed — the naive blocklist strips <script> but is bypassed.
        _execution_scenario(
            browser,
            targets,
            "half-fixed",
            targets.half_fixed,
            HALF_FIXED_STRIPPED,
            "stored",
            "Half-fixed: literal <script>",
            "HTML (naive blocklist)",
            True,
            "BLOCKED (blocklist)",
        ),
        _execution_scenario(
            browser,
            targets,
            "half-fixed",
            targets.half_fixed,
            HALF_FIXED_BYPASSES[0],
            "stored",
            "Half-fixed: <img onerror> bypass",
            "HTML (naive blocklist)",
            True,
            "BLOCKED",
            "VULNERABLE (bypass)",
        ),
        # CSP-alone — injected but blocked from executing.
        _execution_scenario(
            browser,
            targets,
            "csp",
            targets.csp,
            CSP_DEMO_PAYLOAD,
            "stored",
            "CSP-alone (still-vulnerable sink)",
            "HTML (+ nonce CSP)",
            True,
            "MITIGATED (CSP)",
        ),
    ]

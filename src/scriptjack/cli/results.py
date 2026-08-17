"""Structured results for the comparison CLI (pure data — no browser)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioResult:
    """One scenario: a payload shape delivered to one application."""

    app: str  # "vulnerable" | "secure" | "half-fixed" | "csp"
    shape: str  # human-readable shape label
    sink_context: str  # where data crossed into markup/script
    executed: bool  # did the browser run the injected script?
    server_received_payload: bool  # did the request reach the server?
    verdict: str  # "VULNERABLE" | "SECURE" | "MITIGATED" | "BLOCKED"

    # Chain columns — populated only for the full takeover-chain scenario.
    token_beaconed: bool | None = None
    approval_state: str | None = None  # attacker vendor's status after the run
    authority: str | None = None  # whose authority the approval used
    collector_total: int | None = None

    # Optional verbose detail (HTTP status / console / CSP records).
    detail: str | None = None

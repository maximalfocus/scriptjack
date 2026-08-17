"""The half-fixed blocklist variant (FR-007) and the CSP-alone demo (FR-010).

The half-fixed app strips a literal `<script>` (it *appears* fixed) but is defeated by
an event handler, an alternative element, and a nested tag. The CSP-vulnerable app
leaves the sink unfixed but serves the nonce CSP, so the payload is injected yet does
not execute — defence in depth, not a fix.
"""

from __future__ import annotations

import pytest

from conftest import REVIEWER, VENDOR, Portal
from scriptjack.common.payloads import (
    CSP_DEMO_PAYLOAD,
    HALF_FIXED_BYPASSES,
    HALF_FIXED_STRIPPED,
    Payload,
)


def test_half_fixed_strips_a_literal_script(half_fixed_portal: Portal) -> None:
    half_fixed_portal.login(*VENDOR)
    half_fixed_portal.submit_capability("Ops note.", HALF_FIXED_STRIPPED.html)

    half_fixed_portal.login(*REVIEWER)
    half_fixed_portal.open_queue()
    half_fixed_portal.settle()

    assert half_fixed_portal.xss_marker() is None  # stripped — appears fixed


@pytest.mark.parametrize("payload", HALF_FIXED_BYPASSES, ids=lambda p: p.key)
def test_half_fixed_blocklist_is_bypassed(half_fixed_portal: Portal, payload: Payload) -> None:
    half_fixed_portal.login(*VENDOR)
    half_fixed_portal.submit_capability("Ops note.", payload.html)

    half_fixed_portal.login(*REVIEWER)
    half_fixed_portal.open_queue()
    half_fixed_portal.settle()

    assert half_fixed_portal.xss_marker() == payload.marker  # still executes


def test_csp_alone_blocks_execution_on_a_still_vulnerable_sink(csp_portal: Portal) -> None:
    csp_portal.login(*VENDOR)
    csp_portal.submit_capability("Ops note.", CSP_DEMO_PAYLOAD.html)

    csp_portal.login(*REVIEWER)
    response = csp_portal.goto("/queue")
    csp_portal.settle()

    # A nonce CSP with no unsafe-inline is served...
    csp = response.headers.get("content-security-policy", "")
    assert "script-src 'nonce-" in csp
    assert "unsafe-inline" not in csp
    # ...the payload markup is injected (the sink is still vulnerable)...
    assert "onerror" in csp_portal.page.content().lower()  # type: ignore[attr-defined]
    # ...but it does not execute.
    assert csp_portal.xss_marker() is None


def test_secure_app_resists_a_bypass_payload(portal: Portal) -> None:
    portal.login(*VENDOR)
    portal.submit_capability("Ops note.", HALF_FIXED_BYPASSES[0].html)

    portal.login(*REVIEWER)
    portal.open_queue()
    portal.settle()

    assert portal.xss_marker() is None

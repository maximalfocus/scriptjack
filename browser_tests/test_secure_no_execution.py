"""Browser-driven proof that the secure app executes no script (FR-013 / FR-008).

Every checked-in payload fixture is delivered through the real HTTP boundary at
each of the three surfaces and observed in headless Chromium. None of them set the
execution sentinel; the secure app shows them as inert text or removes them. The
reviewer's legitimate work — rendering, search, deep-linking, and approving —
still succeeds through the browser.
"""

from __future__ import annotations

import pytest

from conftest import REVIEWER, VENDOR, Portal
from scriptjack.common.payloads import (
    DOM_PAYLOAD,
    LEGITIMATE_CAPABILITY,
    REFLECTED_PAYLOAD,
    STORED_PAYLOADS,
    Payload,
)


@pytest.mark.parametrize("payload", STORED_PAYLOADS, ids=lambda p: p.key)
def test_secure_stored_payload_does_not_execute(portal: Portal, payload: Payload) -> None:
    portal.login(*VENDOR)
    portal.submit_capability("Ops note.", payload.html)

    portal.login(*REVIEWER)
    portal.open_queue()

    assert portal.xss_marker() is None
    assert portal.dialogs == []


def test_secure_reflected_payload_does_not_execute(portal: Portal) -> None:
    portal.login(*REVIEWER)
    portal.open_search(REFLECTED_PAYLOAD.html)

    assert portal.xss_marker() is None
    assert portal.dialogs == []
    # The reflected value is shown as literal text (autoescaped), not parsed.
    assert portal.inner_text(".echo") == REFLECTED_PAYLOAD.html


def test_secure_dom_fragment_payload_does_not_execute(portal: Portal) -> None:
    portal.login(*REVIEWER)
    portal.open_filtered(DOM_PAYLOAD.html)

    assert portal.xss_marker() is None
    assert portal.dialogs == []
    # The fragment is written with textContent, so it appears as literal text.
    assert portal.inner_text("#active-filter") == DOM_PAYLOAD.html


def test_secure_legitimate_capability_renders_through_the_browser(portal: Portal) -> None:
    portal.login(*VENDOR)
    portal.submit_capability("Ops.", LEGITIMATE_CAPABILITY)

    portal.login(*REVIEWER)
    portal.open_queue()
    # The vendor account owns v-northwind; assert its own row renders the bold text.
    assert portal.inner_text("tr[data-vendor='v-northwind'] td.capability strong") == "Legitimate"


def test_secure_reviewer_approval_via_ui_transitions_state(portal: Portal) -> None:
    portal.login(*REVIEWER)
    portal.open_queue()

    row = portal.page.locator("tr[data-vendor='v-globex']")  # type: ignore[attr-defined]
    row.locator("button.approve").click()
    # The approve action runs the app's own nonce-authorised script; wait for it.
    portal.page.wait_for_function(  # type: ignore[attr-defined]
        "() => { const r = document.querySelector(\"tr[data-vendor='v-globex']\");"
        " return r && r.querySelector('.status')"
        " && r.querySelector('.status').textContent.trim() === 'approved'; }"
    )
    assert "approved" in portal.inner_text("tr[data-vendor='v-globex'] .status")


def test_secure_response_carries_a_nonce_csp_without_unsafe_inline(portal: Portal) -> None:
    response = portal.goto("/login")
    csp = response.headers.get("content-security-policy", "")
    assert "script-src 'nonce-" in csp
    assert "unsafe-inline" not in csp

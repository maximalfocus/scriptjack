"""The vulnerable app's reflected and DOM-based sinks, and the secure app resisting.

The reflected payload arrives in the query string (the server receives it and echoes
it as markup). The DOM payload arrives in the URL fragment (the server never receives
it) yet still executes via innerHTML. Both complete the same FR-005 chain. The secure
app executes neither.
"""

from __future__ import annotations

from conftest import REVIEWER, Portal, collector_beacons
from scriptjack.common.payloads import (
    CHAIN_PAYLOAD,
    CHAIN_TARGET_VENDOR,
    DOM_PAYLOAD,
    REFLECTED_PAYLOAD,
)


def test_vulnerable_reflected_executes_and_server_receives_it(vuln_portal: Portal) -> None:
    vuln_portal.login(*REVIEWER)
    response = vuln_portal.open_search(REFLECTED_PAYLOAD.html)
    vuln_portal.settle()

    assert vuln_portal.xss_marker() == "reflected"
    # The server rendered the payload into the response — it received `q`.
    assert "__scriptjack_xss" in response.text()


def test_vulnerable_dom_executes_but_server_never_receives_it(vuln_portal: Portal) -> None:
    vuln_portal.login(*REVIEWER)
    response = vuln_portal.open_filtered(DOM_PAYLOAD.html)
    vuln_portal.settle()

    assert vuln_portal.xss_marker() == "dom"
    # The fragment is never transmitted: the server response carries no payload...
    assert "__scriptjack_xss" not in response.text()
    assert "onerror" not in response.text()
    # ...yet the live DOM contains the injected markup (written via innerHTML).
    assert "img" in vuln_portal.inner_html("#active-filter").lower()


def test_vulnerable_reflected_completes_the_chain(vuln_portal: Portal) -> None:
    before = collector_beacons()["count"]
    vuln_portal.login(*REVIEWER)
    reviewer_token = vuln_portal.api_token()
    vuln_portal.open_search(CHAIN_PAYLOAD.html)
    vuln_portal.settle()

    assert vuln_portal.xss_marker() == "chain"
    assert "approved" in vuln_portal.vendor_status(CHAIN_TARGET_VENDOR)
    after = collector_beacons()
    assert after["count"] >= before + 1
    assert any(b["token"] == reviewer_token for b in after["beacons"])


def test_vulnerable_dom_completes_the_chain(vuln_portal: Portal) -> None:
    before = collector_beacons()["count"]
    vuln_portal.login(*REVIEWER)
    reviewer_token = vuln_portal.api_token()
    vuln_portal.open_filtered(CHAIN_PAYLOAD.html)
    vuln_portal.settle()

    assert vuln_portal.xss_marker() == "chain"
    assert "approved" in vuln_portal.vendor_status(CHAIN_TARGET_VENDOR)
    after = collector_beacons()
    assert after["count"] >= before + 1
    assert any(b["token"] == reviewer_token for b in after["beacons"])


def test_secure_app_resists_reflected_and_dom(portal: Portal) -> None:
    portal.login(*REVIEWER)
    portal.open_search(REFLECTED_PAYLOAD.html)
    portal.settle()
    assert portal.xss_marker() is None

    portal.open_filtered(DOM_PAYLOAD.html)
    portal.settle()
    assert portal.xss_marker() is None

"""The contained takeover chain (FR-005) and the secure app's resistance to it.

In the vulnerable app the stored chain payload, when the reviewer merely opens the
queue, reads the page-embedded token, approves the attacker's own vendor as the
reviewer, and beacons the token to the in-network collector — without the HttpOnly
session cookie ever being read. The secure app does none of it for the same payload.
"""

from __future__ import annotations

from conftest import REVIEWER, VENDOR, Portal, collector_beacons
from scriptjack.common.payloads import CHAIN_PAYLOAD, CHAIN_TARGET_VENDOR


def test_vulnerable_takeover_chain_through_the_browser(vuln_portal: Portal) -> None:
    before = collector_beacons()["count"]

    # The attacker vendor stores the chain payload in their own capability.
    vuln_portal.login(*VENDOR)
    vuln_portal.submit_capability("Ops note.", CHAIN_PAYLOAD.html)

    # The reviewer does nothing but open the queue.
    vuln_portal.login(*REVIEWER)
    reviewer_token = vuln_portal.api_token()
    vuln_portal.open_queue()
    vuln_portal.settle()

    # The payload executed...
    assert vuln_portal.xss_marker() == "chain"
    # ...but never read the HttpOnly session cookie...
    assert "scriptjack_session" not in vuln_portal.cookie_string()
    # ...yet the attacker's own vendor was approved under the reviewer's authority,
    # with the reviewer having clicked nothing.
    assert "approved" in vuln_portal.vendor_status(CHAIN_TARGET_VENDOR)

    # ...and the token was exfiltrated to the in-network collector. The stored
    # payload re-fires on every render of the attacker's capability, so one or
    # more beacons arrive; the point is that the reviewer's token reached it.
    after = collector_beacons()
    assert after["count"] >= before + 1
    stolen = [b for b in after["beacons"] if b["vendor"] == CHAIN_TARGET_VENDOR]
    assert any(b["token"] == reviewer_token for b in stolen)


def test_secure_app_resists_the_same_chain(portal: Portal) -> None:
    before = collector_beacons()["count"]

    portal.login(*VENDOR)
    portal.submit_capability("Ops note.", CHAIN_PAYLOAD.html)

    portal.login(*REVIEWER)
    portal.open_queue()
    portal.settle()

    # No execution, no exfiltration, and the approval state is untouched.
    assert portal.xss_marker() is None
    assert "pending" in portal.vendor_status(CHAIN_TARGET_VENDOR)
    assert collector_beacons()["count"] == before

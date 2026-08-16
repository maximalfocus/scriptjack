"""Browser-driven proof that the vulnerable app's stored sink executes script.

The attacker vendor stores a checked-in payload; when the reviewer opens the queue
in the vulnerable app, the payload executes and sets the sentinel. The identical
payload against the secure app does not execute (see test_secure_no_execution.py) —
together they are the contrast.
"""

from __future__ import annotations

import pytest

from conftest import REVIEWER, VENDOR, Portal
from scriptjack.common.payloads import STORED_PAYLOADS, Payload


@pytest.mark.parametrize("payload", STORED_PAYLOADS, ids=lambda p: p.key)
def test_vulnerable_stored_payload_executes(vuln_portal: Portal, payload: Payload) -> None:
    vuln_portal.login(*VENDOR)
    vuln_portal.submit_capability("Ops note.", payload.html)

    vuln_portal.login(*REVIEWER)
    vuln_portal.open_queue()

    assert vuln_portal.xss_marker() == payload.marker

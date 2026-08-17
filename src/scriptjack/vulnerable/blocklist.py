"""The deliberately naive, hand-rolled blocklist (the half-fixed variant).

It strips ``<script>`` / ``</script>`` tags and the obvious ``javascript:`` scheme in
a **single pass**. Because it does not understand HTML, it is defeated by
event-handler attributes (``onerror``, ``onload``), alternative script-bearing
elements, and a nested tag that reconstitutes a working ``<script>`` after one
removal pass. This exists only to demonstrate why a blocklist over a grammar the
application does not own cannot enumerate its own failures — it is **not** a fix.
"""

from __future__ import annotations

import re

_SCRIPT_TAG = re.compile(r"(?i)</?\s*script[^>]*>")
_JS_SCHEME = re.compile(r"(?i)javascript:")


def naive_blocklist(html: str) -> str:
    out = _SCRIPT_TAG.sub("", html)
    out = _JS_SCHEME.sub("", out)
    return out

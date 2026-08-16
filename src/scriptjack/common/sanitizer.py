"""The maintained allowlist HTML sanitizer for the rich-text capability statement.

This is a **secondary** control (defence in depth), narrower and more fragile than
not rendering user HTML at all. It permits a small, explicit set of tags and
attributes and removes everything else — every event-handler attribute and every
non-allowlisted URL scheme included. It never reports *which* tags or attributes
it removed, so no response can act as a filter oracle.

It is backed by ``nh3`` (a maintained Rust/Ammonia binding), not a hand-rolled
blocklist. The hand-rolled blocklist exists only as the deliberately half-fixed
variant delivered in a later slice.
"""

from __future__ import annotations

import nh3

# A deliberately small allowlist: enough for legitimate emphasis and links.
ALLOWED_TAGS: set[str] = {"p", "br", "strong", "b", "em", "i", "ul", "ol", "li", "a"}
ALLOWED_ATTRIBUTES: dict[str, set[str]] = {"a": {"href"}}
ALLOWED_URL_SCHEMES: set[str] = {"https", "mailto"}


def sanitize_capability_statement(raw: str) -> tuple[str, bool]:
    """Return ``(sanitized_html, was_changed)``.

    ``was_changed`` is ``True`` when the sanitizer altered the submission (the
    signal used to emit exactly one audit event). Legitimate content authored in
    the sanitizer's own normal form passes through unchanged.
    """

    cleaned = nh3.clean(
        raw,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_URL_SCHEMES,
        link_rel="noopener noreferrer nofollow",
    )
    return cleaned, cleaned != raw

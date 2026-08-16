"""The conspicuously fictional, page-embedded per-session API token.

Rendered pages embed this token, as portal pages routinely do. The privileged
approve action requires it *in addition to* the session cookie. This is the
mechanism the XSS demonstration later turns against the victim: injected script
reads this token straight out of the DOM and calls approve, while the browser
attaches the ``HttpOnly`` session cookie automatically — so ``HttpOnly`` never
had to be defeated. In the secure application no script can reach the token, so
it stays a harmless implementation detail.
"""

from __future__ import annotations

from itsdangerous import BadData, URLSafeSerializer

from scriptjack.common.config import Settings

# A conspicuously fictional prefix, so the token reads as an obvious demo value
# in page source rather than resembling a real secret.
_PREFIX = "demo-api-token."
_SALT = "scriptjack-api-token-v1"


def _serializer(settings: Settings) -> URLSafeSerializer:
    return URLSafeSerializer(settings.session_signing_key, salt=_SALT)


def issue_api_token(settings: Settings, username: str) -> str:
    return _PREFIX + _serializer(settings).dumps({"sub": username, "scope": "approve"})


def verify_api_token(settings: Settings, token: object) -> str | None:
    """Return the token's subject username, or ``None`` if it is invalid."""

    if not isinstance(token, str) or not token.startswith(_PREFIX):
        return None
    try:
        data = _serializer(settings).loads(token[len(_PREFIX) :])
    except BadData:
        return None
    if not isinstance(data, dict) or data.get("scope") != "approve":
        return None
    sub = data.get("sub")
    return sub if isinstance(sub, str) else None

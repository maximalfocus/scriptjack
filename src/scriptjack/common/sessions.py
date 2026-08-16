"""Signed session cookies and demo credential checks.

The session cookie is ``HttpOnly`` and ``SameSite`` in every application, so that
cookie flags are never the variable under test in the XSS demonstration. The same
helpers are reused by both the secure and (later) the vulnerable application, so
their session handling is provably identical.
"""

from __future__ import annotations

import hmac

from itsdangerous import BadData, URLSafeTimedSerializer
from starlette.requests import Request
from starlette.responses import Response

from scriptjack.common.config import DEMO_USERS, DemoUser, Settings

_SALT = "scriptjack-session-v1"


def _serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_signing_key, salt=_SALT)


def authenticate(username: object, password: object) -> DemoUser | None:
    """Return the demo user for valid credentials, else ``None``.

    Missing (``None``), malformed (non-``str``), and unknown credentials all map
    to ``None`` so the caller can answer with a single generic ``401``.
    """

    if not isinstance(username, str) or not isinstance(password, str):
        return None
    user = DEMO_USERS.get(username)
    if user is None:
        return None
    if not hmac.compare_digest(user.password, password):
        return None
    return user


def issue_session(response: Response, settings: Settings, username: str) -> None:
    """Attach a signed, hardened session cookie for ``username``."""

    token = _serializer(settings).dumps({"sub": username})
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=False,  # loopback HTTP only; no TLS terminator in the demo
        path="/",
    )


def clear_session(response: Response, settings: Settings) -> None:
    """Remove the session cookie."""

    response.delete_cookie(settings.session_cookie_name, path="/")


def read_session(request: Request, settings: Settings) -> DemoUser | None:
    """Return the authenticated demo user, or ``None`` if the cookie is absent
    or fails signature verification."""

    raw = request.cookies.get(settings.session_cookie_name)
    if not raw:
        return None
    try:
        data = _serializer(settings).loads(raw, max_age=settings.session_max_age_seconds)
    except BadData:
        return None
    if not isinstance(data, dict):
        return None
    sub = data.get("sub")
    if not isinstance(sub, str):
        return None
    return DEMO_USERS.get(sub)

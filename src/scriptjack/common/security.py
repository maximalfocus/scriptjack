"""Per-response security context: a CSP nonce, a request id, and headers.

The middleware mints a fresh nonce and request id for every request and, on the
way out, sets a nonce-based Content Security Policy with **no** ``unsafe-inline``
script source on every response. The application's own scripts are the only
scripts that carry the nonce, so injected inline or attribute scripts have no
way to execute even on a vulnerable sink (the defence-in-depth demonstration a
later slice builds on).
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def build_csp(nonce: str) -> str:
    return "; ".join(
        (
            "default-src 'self'",
            f"script-src 'nonce-{nonce}'",
            "style-src 'self'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "base-uri 'none'",
            "object-src 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        )
    )


class SecurityContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        request.state.request_id = secrets.token_hex(8)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = build_csp(nonce)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

"""The secure application skeleton.

At this stage the secure app carries only the container/CI foundation and demo
authentication: a health probe, a form login that establishes a hardened session
cookie, a session-protected endpoint, and logout. Missing, malformed, and unknown
credentials all receive the same generic ``401``. The three rendering surfaces,
the allowlist sanitizer, the nonce-based CSP, and the audit event arrive in later
SLICE-001 increments; no vulnerable code exists here.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from scriptjack.common import sessions
from scriptjack.common.config import Settings, load_settings

_UNAUTHORIZED = HTTPException(status_code=401, detail="Unauthorized")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or load_settings()
    # OpenAPI docs are disabled: they add HTTP surface the demo does not need.
    app = FastAPI(
        title="scriptjack secure portal",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/login")
    async def login(request: Request) -> JSONResponse:
        form = await request.form()
        user = sessions.authenticate(form.get("username"), form.get("password"))
        if user is None:
            raise _UNAUTHORIZED
        response = JSONResponse({"role": user.role, "display_name": user.display_name})
        sessions.issue_session(response, resolved, user.username)
        return response

    @app.get("/session")
    async def session(request: Request) -> dict[str, str]:
        user = sessions.read_session(request, resolved)
        if user is None:
            raise _UNAUTHORIZED
        return {"role": user.role, "display_name": user.display_name}

    @app.post("/logout")
    async def logout() -> JSONResponse:
        response = JSONResponse({"ok": True})
        sessions.clear_session(response, resolved)
        return response

    return app


app = create_app()

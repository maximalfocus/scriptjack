"""The intentionally vulnerable portal (stored sink).

The differences from the secure app are deliberately small and all unsafe:

* ``POST /profile`` stores the capability statement **raw** — it does not call the
  allowlist sanitizer and emits no audit event;
* the reviewer queue and profile page render that raw value as **markup**
  (``| safe`` on untrusted input); and
* **no** Content Security Policy is served, so injected inline/handler script runs.

Its search and client filtered view are still safe here — the reflected and DOM
sinks arrive in SLICE-003. The app refuses to start unless ``ALLOW_VULNERABLE_DEMO``
is exactly ``true``.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.datastructures import FormData

from scriptjack.common import sessions, tokens
from scriptjack.common.config import DemoUser, Settings, load_settings
from scriptjack.common.fixtures import ORGANIZATION, VendorStore
from scriptjack.common.security import SecurityContextMiddleware
from scriptjack.vulnerable.blocklist import naive_blocklist

_SECURE_ROOT = Path(__file__).resolve().parent.parent / "secure"
_HERE = Path(__file__).resolve().parent
# Vulnerable overrides first, then the shared secure templates/static as fallback.
_TEMPLATES = Jinja2Templates(directory=[str(_HERE / "templates"), str(_SECURE_ROOT / "templates")])
_STATIC_DIR = _SECURE_ROOT / "static"
_VULN_STATIC_DIR = _HERE / "static"

_UNAUTHORIZED = HTTPException(status_code=401, detail="Unauthorized")


def _require_opt_in() -> None:
    if os.environ.get("ALLOW_VULNERABLE_DEMO") != "true":
        raise RuntimeError(
            "Refusing to start the vulnerable application: set ALLOW_VULNERABLE_DEMO=true "
            "and enable its Compose profile to run this intentionally insecure demo."
        )


def _form_str(form: FormData, key: str) -> str:
    value = form.get(key)
    return value if isinstance(value, str) else ""


def create_app(settings: Settings | None = None, store: VendorStore | None = None) -> FastAPI:
    _require_opt_in()
    resolved = settings or load_settings()
    vendors = store or VendorStore()
    # Two further-opt-in demonstration modes (each a distinct Compose service):
    #  - half-fixed: run the naive blocklist over the stored capability (FR-007);
    #  - csp: serve the nonce CSP over the still-vulnerable sink (FR-010 demo).
    half_fixed = os.environ.get("SCRIPTJACK_HALF_FIXED") == "true"
    csp_enabled = os.environ.get("SCRIPTJACK_CSP") == "true"

    app = FastAPI(
        title="scriptjack VULNERABLE portal",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    # CSP is served ONLY in the CSP-alone demonstration; the plain vulnerable app
    # serves no CSP on purpose so injected script executes.
    if csp_enabled:
        app.add_middleware(SecurityContextMiddleware)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    # The vulnerable DOM-sink script (innerHTML) lives in the vulnerable app's own
    # static path so the unsafe contrast is readable in served source.
    app.mount("/vuln-static", StaticFiles(directory=str(_VULN_STATIC_DIR)), name="vuln-static")

    def user_of(request: Request) -> DemoUser | None:
        return sessions.read_session(request, resolved)

    def render(request: Request, name: str, status_code: int = 200, **context: object) -> Response:
        # A real nonce only exists in CSP mode; otherwise it is empty and unenforced.
        nonce = request.state.csp_nonce if csp_enabled else ""
        base: dict[str, object] = {"org": ORGANIZATION, "nonce": nonce, "vulnerable": True}
        current = user_of(request)
        if current is not None:
            base["current_user"] = current
            base["api_token"] = tokens.issue_api_token(resolved, current.username)
        base.update(context)
        return _TEMPLATES.TemplateResponse(request, name, base, status_code=status_code)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    async def index(request: Request) -> Response:
        current = user_of(request)
        if current is None:
            return RedirectResponse("/login", status_code=303)
        return RedirectResponse(
            "/queue" if current.role == "reviewer" else "/profile", status_code=303
        )

    @app.get("/login")
    async def login_form(request: Request) -> Response:
        if user_of(request) is not None:
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html")

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        user = sessions.authenticate(form.get("username"), form.get("password"))
        if user is None:
            return render(request, "login.html", status_code=401, error="Invalid credentials.")
        response: Response = RedirectResponse(
            "/queue" if user.role == "reviewer" else "/profile", status_code=303
        )
        sessions.issue_session(response, resolved, user.username)
        return response

    @app.post("/logout")
    async def logout() -> Response:
        response: Response = RedirectResponse("/login", status_code=303)
        sessions.clear_session(response, resolved)
        return response

    @app.get("/session")
    async def session(request: Request) -> dict[str, str]:
        current = user_of(request)
        if current is None:
            raise _UNAUTHORIZED
        return {"role": current.role, "display_name": current.display_name}

    def require_reviewer(request: Request) -> DemoUser | Response:
        current = user_of(request)
        if current is None:
            return RedirectResponse("/login", status_code=303)
        if current.role != "reviewer":
            raise HTTPException(status_code=403, detail="Reviewers only")
        return current

    @app.get("/queue")
    async def queue(request: Request) -> Response:
        guard = require_reviewer(request)
        if isinstance(guard, Response):
            return guard
        return render(request, "queue.html", vendors=vendors.list_vendors())

    @app.get("/search")
    async def search(request: Request, q: str = "") -> Response:
        guard = require_reviewer(request)
        if isinstance(guard, Response):
            return guard
        # Still safe here: the reflected sink is introduced in SLICE-003.
        return render(request, "search.html", q=q, results=vendors.search_by_name(q))

    @app.get("/filtered")
    async def filtered(request: Request) -> Response:
        guard = require_reviewer(request)
        if isinstance(guard, Response):
            return guard
        return render(request, "filtered.html", vendors=vendors.list_vendors())

    @app.get("/vendors/{vendor_id}")
    async def vendor_page(request: Request, vendor_id: str) -> Response:
        current = user_of(request)
        if current is None:
            return RedirectResponse("/login", status_code=303)
        vendor = vendors.get(vendor_id)
        if vendor is None:
            raise HTTPException(status_code=404, detail="Not found")
        if current.role != "reviewer" and vendor.owner_username != current.username:
            raise HTTPException(status_code=403, detail="Forbidden")
        return render(request, "profile_view.html", vendor=vendor)

    @app.post("/vendors/{vendor_id}/approve")
    async def approve(request: Request, vendor_id: str) -> Response:
        current = user_of(request)
        if current is None or current.role != "reviewer":
            raise _UNAUTHORIZED
        token = request.headers.get("x-api-token")
        if token is None:
            form = await request.form()
            token = _form_str(form, "api_token")
        if tokens.verify_api_token(resolved, token) != current.username:
            raise _UNAUTHORIZED
        if not vendors.approve(vendor_id):
            raise HTTPException(status_code=404, detail="Not found")
        return JSONResponse({"vendor": vendor_id, "status": "approved"})

    @app.get("/profile")
    async def profile_form(request: Request) -> Response:
        current = user_of(request)
        if current is None:
            return RedirectResponse("/login", status_code=303)
        if current.role != "vendor":
            return RedirectResponse("/queue", status_code=303)
        vendor = vendors.owned_by(current.username)
        if vendor is None:
            raise HTTPException(status_code=404, detail="No vendor profile")
        return render(request, "profile_edit.html", vendor=vendor)

    @app.post("/profile")
    async def update_profile(request: Request) -> Response:
        current = user_of(request)
        if current is None or current.role != "vendor":
            raise _UNAUTHORIZED
        vendor = vendors.owned_by(current.username)
        if vendor is None:
            raise HTTPException(status_code=404, detail="No vendor profile")
        form = await request.form()
        raw_capability = _form_str(form, "capability_statement")
        # VULNERABLE: stored without the allowlist sanitizer. Half-fixed mode runs
        # the naive blocklist first — which is not a fix — otherwise it is raw.
        stored_capability = naive_blocklist(raw_capability) if half_fixed else raw_capability
        vendors.set_profile(vendor.id, _form_str(form, "operating_note"), stored_capability)
        return RedirectResponse(f"/vendors/{vendor.id}", status_code=303)

    return app


app = create_app()

"""The secure vendor-onboarding portal.

Every sink keeps request-borne data in a data context:

* server-side templates render with autoescaping on; the reflected search ``q`` is
  emitted as text; the rich-text capability statement is passed through the
  allowlist sanitizer and only its *sanitized* output is marked safe;
* the client filtered view writes the URL fragment with ``textContent``; and
* a nonce-based CSP with no ``unsafe-inline`` is served on every response.

Missing, malformed, and unknown credentials all receive a generic ``401``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.datastructures import FormData

from scriptjack.common import sessions, tokens
from scriptjack.common.audit import emit_sanitization_event
from scriptjack.common.config import DemoUser, Settings, load_settings
from scriptjack.common.fixtures import ORGANIZATION, VendorStore
from scriptjack.common.sanitizer import sanitize_capability_statement
from scriptjack.common.security import SecurityContextMiddleware

_HERE = Path(__file__).resolve().parent
_TEMPLATES = Jinja2Templates(directory=str(_HERE / "templates"))
_STATIC_DIR = _HERE / "static"

_UNAUTHORIZED = HTTPException(status_code=401, detail="Unauthorized")


def _form_str(form: FormData, key: str) -> str:
    value = form.get(key)
    return value if isinstance(value, str) else ""


def create_app(settings: Settings | None = None, store: VendorStore | None = None) -> FastAPI:
    resolved = settings or load_settings()
    vendors = store or VendorStore()

    app = FastAPI(title="scriptjack secure portal", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityContextMiddleware)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    def user_of(request: Request) -> DemoUser | None:
        return sessions.read_session(request, resolved)

    def render(request: Request, name: str, status_code: int = 200, **context: object) -> Response:
        base: dict[str, object] = {"org": ORGANIZATION, "nonce": request.state.csp_nonce}
        current = user_of(request)
        if current is not None:
            base["current_user"] = current
            base["api_token"] = tokens.issue_api_token(resolved, current.username)
        base.update(context)
        return _TEMPLATES.TemplateResponse(request, name, base, status_code=status_code)

    # ---- health & auth -----------------------------------------------------

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
        current = user_of(request)
        if current is not None:
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html")

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        user = sessions.authenticate(form.get("username"), form.get("password"))
        if user is None:
            return render(request, "login.html", status_code=401, error="Invalid credentials.")
        destination = "/queue" if user.role == "reviewer" else "/profile"
        response: Response = RedirectResponse(destination, status_code=303)
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

    # ---- reviewer surfaces -------------------------------------------------

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
        # The reflected parameter is passed to the template and emitted as TEXT.
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
        subject = tokens.verify_api_token(resolved, token)
        if subject != current.username:
            raise _UNAUTHORIZED
        if not vendors.approve(vendor_id):
            raise HTTPException(status_code=404, detail="Not found")
        return JSONResponse({"vendor": vendor_id, "status": "approved"})

    # ---- vendor surfaces ---------------------------------------------------

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
        operating_note = _form_str(form, "operating_note")
        raw_capability = _form_str(form, "capability_statement")
        sanitized, changed = sanitize_capability_statement(raw_capability)
        if changed:
            emit_sanitization_event(
                request_id=request.state.request_id,
                actor=current.username,
                field="capability_statement",
            )
        vendors.set_profile(vendor.id, operating_note, sanitized)
        return RedirectResponse(f"/vendors/{vendor.id}", status_code=303)

    return app


app = create_app()

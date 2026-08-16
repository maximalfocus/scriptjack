"""A minimal collector service.

``POST /beacon`` accepts only the demo's beacon shape (a JSON object with string
``token`` and ``vendor``) and records it. ``GET /beacons`` returns what has been
received, as evidence of what left the page. The service never makes an outbound
request of its own.
"""

from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response


def create_app() -> FastAPI:
    app = FastAPI(title="scriptjack collector", docs_url=None, redoc_url=None, openapi_url=None)
    beacons: list[dict[str, str]] = []

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/beacon")
    async def beacon(request: Request) -> Response:
        # Beacons arrive via navigator.sendBeacon as a text/plain JSON string, so
        # read and parse the raw body rather than relying on a declared type.
        raw = await request.body()
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return JSONResponse({"accepted": False}, status_code=400)
        if not isinstance(data, dict):
            return JSONResponse({"accepted": False}, status_code=400)
        token = data.get("token")
        vendor = data.get("vendor")
        if not isinstance(token, str) or not isinstance(vendor, str):
            return JSONResponse({"accepted": False}, status_code=400)
        beacons.append({"token": token, "vendor": vendor})
        return JSONResponse({"accepted": True}, status_code=201)

    @app.get("/beacons")
    async def list_beacons() -> dict[str, object]:
        return {"count": len(beacons), "beacons": list(beacons)}

    return app


app = create_app()

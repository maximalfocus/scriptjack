"""Playwright fixtures and a small portal driver for the headless-browser harness.

These run only inside the `harness` Compose service (its own headless-Chromium
container on the demo network); they are excluded from the unit `verify` image and
from mypy's source set. The harness drives a real browser against the running
application so script execution, non-execution, and CSP behaviour are observed
rather than asserted from markup.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote, urlencode

import pytest
from playwright.sync_api import Browser, Playwright, Response, sync_playwright

from scriptjack.common.payloads import SENTINEL_GLOBAL

BASE_URL = os.environ.get("SCRIPTJACK_BASE_URL", "http://secure-app:8000")
VULN_BASE_URL = os.environ.get("SCRIPTJACK_VULN_BASE_URL", "http://vulnerable-app:8000")
COLLECTOR_URL = os.environ.get("SCRIPTJACK_COLLECTOR_URL", "http://collector:8000")


def collector_beacons() -> dict[str, Any]:
    """Read the in-network collector's recorded beacons (harness is on the demo net)."""

    with urllib.request.urlopen(f"{COLLECTOR_URL}/beacons", timeout=5) as response:
        result: dict[str, Any] = json.loads(response.read().decode())
    return result


REVIEWER = ("reviewer@scriptjack.invalid", "demo-reviewer-password-not-secret")
VENDOR = ("vendor@scriptjack.invalid", "demo-vendor-password-not-secret")


class Portal:
    """A thin, page-bound driver for the portal's flows."""

    def __init__(self, page: object, dialogs: list[str]) -> None:
        # `page` is a playwright Page; typed loosely to keep this file
        # independent of mypy's source set.
        self.page = page
        self.dialogs = dialogs

    def login(self, username: str, password: str) -> None:
        # Start from a clean session so switching identities (vendor -> reviewer)
        # is not bounced by /login's "already authenticated" redirect.
        self.page.context.clear_cookies()  # type: ignore[attr-defined]
        self.page.goto("/login")  # type: ignore[attr-defined]
        self.page.fill("input[name='username']", username)  # type: ignore[attr-defined]
        self.page.fill("input[name='password']", password)  # type: ignore[attr-defined]
        # Scope to the login form: the header also holds a submit button (logout).
        self.page.click("form[action='/login'] button[type='submit']")  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    def submit_capability(self, note: str, capability: str) -> None:
        self.page.goto("/profile")  # type: ignore[attr-defined]
        self.page.fill("textarea[name='operating_note']", note)  # type: ignore[attr-defined]
        self.page.fill("textarea[name='capability_statement']", capability)  # type: ignore[attr-defined]
        # Scope to the profile form so we click "Save", not the header's logout.
        self.page.click("form[action='/profile'] button[type='submit']")  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    def open_queue(self) -> None:
        self.page.goto("/queue")  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    def open_search(self, q: str) -> Response:
        response = self.page.goto("/search?" + urlencode({"q": q}))  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]
        return response

    def open_filtered(self, fragment: str) -> None:
        self.page.goto("/filtered#" + quote(fragment))  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    def goto(self, path: str) -> Response:
        return self.page.goto(path)  # type: ignore[attr-defined,no-any-return]

    def xss_marker(self) -> str | None:
        # Give any asynchronous handler (e.g. img onerror) a moment to run,
        # then read the sentinel an executed payload would have set.
        self.page.wait_for_timeout(200)  # type: ignore[attr-defined]
        marker = self.page.evaluate(  # type: ignore[attr-defined]
            f"() => window.{SENTINEL_GLOBAL} ?? null"
        )
        return marker if isinstance(marker, str) else None

    def inner_text(self, selector: str) -> str:
        return str(self.page.inner_text(selector))  # type: ignore[attr-defined]

    def api_token(self) -> str:
        content = self.page.get_attribute(  # type: ignore[attr-defined]
            "meta[name='scriptjack-api-token']", "content"
        )
        return content or ""

    def cookie_string(self) -> str:
        return str(self.page.evaluate("() => document.cookie"))  # type: ignore[attr-defined]

    def settle(self, milliseconds: int = 500) -> None:
        self.page.wait_for_timeout(milliseconds)  # type: ignore[attr-defined]

    def vendor_status(self, vendor_id: str) -> str:
        self.page.goto(f"/vendors/{vendor_id}")  # type: ignore[attr-defined]
        self.page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]
        return self.inner_text(".status").strip().lower()


@pytest.fixture(scope="session")
def _playwright() -> Iterator[Playwright]:
    with sync_playwright() as pw:
        yield pw


@pytest.fixture(scope="session")
def browser(_playwright: Playwright) -> Iterator[Browser]:
    launched = _playwright.chromium.launch(
        headless=True,
        # The container is the isolation boundary, so Chromium's own sandbox
        # (which needs privileges the harness deliberately drops) is disabled.
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    yield launched
    launched.close()


def _make_portal(browser: Browser, base_url: str) -> Iterator[Portal]:
    context = browser.new_context(base_url=base_url)
    page = context.new_page()
    dialogs: list[str] = []

    def _on_dialog(dialog: object) -> None:
        dialogs.append(getattr(dialog, "message", ""))
        dialog.dismiss()  # type: ignore[attr-defined]

    page.on("dialog", _on_dialog)
    yield Portal(page, dialogs)
    context.close()


@pytest.fixture
def portal(browser: Browser) -> Iterator[Portal]:
    yield from _make_portal(browser, BASE_URL)


@pytest.fixture
def vuln_portal(browser: Browser) -> Iterator[Portal]:
    yield from _make_portal(browser, VULN_BASE_URL)

"""A thin, typed portal driver over a Playwright page.

Shared by the harness tests and the comparison CLI so the browser-driving logic
lives in one place. Everything is observed through a real browser: script
execution, non-execution, CSP behaviour, and what the server received.
"""

from __future__ import annotations

from urllib.parse import quote, urlencode

from playwright.sync_api import Page, Response

from scriptjack.common.payloads import SENTINEL_GLOBAL

REVIEWER = ("reviewer@scriptjack.invalid", "demo-reviewer-password-not-secret")
VENDOR = ("vendor@scriptjack.invalid", "demo-vendor-password-not-secret")


class Portal:
    """Drives one authenticated browser session against one application."""

    def __init__(self, page: Page, dialogs: list[str]) -> None:
        self.page = page
        self.dialogs = dialogs

    def login(self, username: str, password: str) -> None:
        # Start from a clean session so switching identities is not bounced by
        # /login's "already authenticated" redirect.
        self.page.context.clear_cookies()
        self.page.goto("/login")
        self.page.fill("input[name='username']", username)
        self.page.fill("input[name='password']", password)
        # Scope to the login form: the header also holds a submit button (logout).
        self.page.click("form[action='/login'] button[type='submit']")
        self.page.wait_for_load_state("networkidle")

    def submit_capability(self, note: str, capability: str) -> None:
        self.page.goto("/profile")
        self.page.fill("textarea[name='operating_note']", note)
        self.page.fill("textarea[name='capability_statement']", capability)
        self.page.click("form[action='/profile'] button[type='submit']")
        self.page.wait_for_load_state("networkidle")

    def goto(self, path: str) -> Response:
        response = self.page.goto(path)
        if response is None:
            raise RuntimeError(f"navigation to {path} returned no response")
        return response

    def open_queue(self) -> Response:
        return self.goto("/queue")

    def open_search(self, q: str) -> Response:
        response = self.goto("/search?" + urlencode({"q": q}))
        self.page.wait_for_load_state("networkidle")
        return response

    def open_filtered(self, fragment: str) -> Response:
        response = self.goto("/filtered#" + quote(fragment))
        self.page.wait_for_load_state("networkidle")
        return response

    def xss_marker(self) -> str | None:
        # Give any asynchronous handler (e.g. img onerror) a moment to run, then
        # read the sentinel an executed payload would have set.
        self.page.wait_for_timeout(200)
        marker = self.page.evaluate(f"() => window.{SENTINEL_GLOBAL} ?? null")
        return marker if isinstance(marker, str) else None

    def settle(self, milliseconds: int = 500) -> None:
        self.page.wait_for_timeout(milliseconds)

    def content(self) -> str:
        return self.page.content()

    def inner_text(self, selector: str) -> str:
        return self.page.inner_text(selector)

    def inner_html(self, selector: str) -> str:
        return self.page.inner_html(selector)

    def api_token(self) -> str:
        content = self.page.get_attribute("meta[name='scriptjack-api-token']", "content")
        return content or ""

    def cookie_string(self) -> str:
        cookies = self.page.evaluate("() => document.cookie")
        return cookies if isinstance(cookies, str) else ""

    def vendor_status(self, vendor_id: str) -> str:
        self.goto(f"/vendors/{vendor_id}")
        self.page.wait_for_load_state("networkidle")
        return self.inner_text(".status").strip().lower()

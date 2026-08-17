"""Playwright fixtures for the headless-browser harness (Compose service only).

The portal-driving logic lives in ``scriptjack.harness.driver`` so it is shared
with the comparison CLI; this module provides the browser/session fixtures and the
collector helper, and re-exports the driver names the tests use.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
from playwright.sync_api import Browser, Playwright, sync_playwright

from scriptjack.harness.driver import REVIEWER, VENDOR, Portal

__all__ = ["REVIEWER", "VENDOR", "Portal", "collector_beacons"]

BASE_URL = os.environ.get("SCRIPTJACK_BASE_URL", "http://secure-app:8000")
VULN_BASE_URL = os.environ.get("SCRIPTJACK_VULN_BASE_URL", "http://vulnerable-app:8000")
COLLECTOR_URL = os.environ.get("SCRIPTJACK_COLLECTOR_URL", "http://collector:8000")
HALF_FIXED_BASE_URL = os.environ.get("SCRIPTJACK_HALF_FIXED_BASE_URL", "http://half-fixed-app:8000")
CSP_BASE_URL = os.environ.get("SCRIPTJACK_CSP_BASE_URL", "http://csp-vuln-app:8000")


def collector_beacons() -> dict[str, Any]:
    """Read the in-network collector's recorded beacons (harness is on the demo net)."""

    with urllib.request.urlopen(f"{COLLECTOR_URL}/beacons", timeout=5) as response:
        result: dict[str, Any] = json.loads(response.read().decode())
    return result


@pytest.fixture(scope="session")
def _playwright() -> Iterator[Playwright]:
    with sync_playwright() as pw:
        yield pw


@pytest.fixture(scope="session")
def browser(_playwright: Playwright) -> Iterator[Browser]:
    launched = _playwright.chromium.launch(
        headless=True,
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


@pytest.fixture
def half_fixed_portal(browser: Browser) -> Iterator[Portal]:
    yield from _make_portal(browser, HALF_FIXED_BASE_URL)


@pytest.fixture
def csp_portal(browser: Browser) -> Iterator[Portal]:
    yield from _make_portal(browser, CSP_BASE_URL)

"""The three secure surfaces, the sanitizer, the nonce CSP, and the audit event.

Everything here is asserted at the HTTP boundary and by inspecting served
HTML/JS/headers. The browser-driven proof that no script *executes* is the next
increment's headless-Chromium harness.
"""

from __future__ import annotations

import json

from fastapi import FastAPI
from pytest import CaptureFixture
from starlette.testclient import TestClient

from tests.conftest import REVIEWER, VENDOR, api_token_from, login

# --- the reviewer queue (stored surface, rendered) --------------------------


def test_queue_lists_seeded_vendors_with_token_and_nonced_script(client: TestClient) -> None:
    login(client, REVIEWER)
    body = client.get("/queue").text
    for name in ["Northwind Traders", "Acme Components", "Globex Stationery", "Initech Print"]:
        assert name in body
    assert '<meta name="scriptjack-api-token"' in body
    assert '/static/approve.js" nonce="' in body


# --- the nonce-based CSP (FR-010, policy served) ----------------------------


def test_csp_is_present_and_has_no_unsafe_inline_when_unauthenticated(client: TestClient) -> None:
    csp = client.get("/login").headers["content-security-policy"]
    assert "script-src 'nonce-" in csp
    assert "unsafe-inline" not in csp


def test_csp_is_present_on_every_authenticated_response(client: TestClient) -> None:
    login(client, REVIEWER)
    for path in ["/healthz", "/queue", "/search?q=x", "/filtered"]:
        csp = client.get(path).headers["content-security-policy"]
        assert "script-src 'nonce-" in csp
        assert "unsafe-inline" not in csp


# --- the reflected search surface (FR-004 counterpart / FR-008) -------------


def test_reflected_search_parameter_is_escaped_as_text(client: TestClient) -> None:
    login(client, REVIEWER)
    response = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert response.status_code == 200
    body = response.text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_search_returns_expected_matches(client: TestClient) -> None:
    login(client, REVIEWER)
    assert "Northwind Traders" in client.get("/search", params={"q": "north"}).text


# --- the client filtered view (DOM sink, FR-008) ----------------------------


def test_filtered_client_script_uses_textcontent_only(client: TestClient) -> None:
    js = client.get("/static/filtered.js").text
    assert ".textContent" in js
    # Dangerous sink *usage* (dot/paren forms), not bare mentions in comments.
    for banned in [".innerHTML", ".outerHTML", ".insertAdjacentHTML(", "document.write(", "eval("]:
        assert banned not in js


def test_filtered_page_references_the_nonced_script(client: TestClient) -> None:
    login(client, REVIEWER)
    assert '/static/filtered.js" nonce="' in client.get("/filtered").text


# --- the allowlist sanitizer + audit event (FR-009, FR-011) -----------------


def test_dangerous_capability_is_sanitized_and_audited_once(
    app: FastAPI, capsys: CaptureFixture[str]
) -> None:
    vendor = TestClient(app)
    login(vendor, VENDOR)
    capsys.readouterr()  # discard anything emitted so far

    payload = "<script>steal()</script><img src=x onerror=alert(1)><b>ok</b>"
    response = vendor.post(
        "/profile",
        data={"operating_note": "Ops note.", "capability_statement": payload},
        follow_redirects=False,
    )
    assert response.status_code == 303

    events = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "capability_statement.sanitized" in line
    ]
    assert len(events) == 1
    event = json.loads(events[0])
    assert event["actor"] == "vendor@scriptjack.invalid"
    assert event["field"] == "capability_statement"
    assert event["outcome"] == "sanitized"
    assert event["request_id"]
    # No filter oracle and no leak: the raw payload never appears in the event.
    lowered = events[0].lower()
    for leaked in ["steal", "onerror", "alert", "<b>", "cookie", "password", "scriptjack_session"]:
        assert leaked not in lowered

    reviewer = TestClient(app)
    login(reviewer, REVIEWER)
    queue = reviewer.get("/queue").text
    assert "<b>ok</b>" in queue  # allowlisted tag survived
    assert "steal()" not in queue  # script content removed
    assert "onerror" not in queue  # event handler removed


def test_legitimate_formatting_is_preserved_without_an_audit_event(
    app: FastAPI, capsys: CaptureFixture[str]
) -> None:
    vendor = TestClient(app)
    login(vendor, VENDOR)
    capsys.readouterr()

    benign = "<p><strong>Legit</strong> formatting.</p>"
    response = vendor.post(
        "/profile",
        data={"operating_note": "Ops.", "capability_statement": benign},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "capability_statement.sanitized" not in capsys.readouterr().out

    reviewer = TestClient(app)
    login(reviewer, REVIEWER)
    assert "<strong>Legit</strong>" in reviewer.get("/queue").text


# --- the privileged approve transition (FR-012 legitimate path) -------------


def test_reviewer_can_approve_with_the_page_embedded_token(client: TestClient) -> None:
    login(client, REVIEWER)
    token = api_token_from(client.get("/queue").text)

    response = client.post("/vendors/v-globex/approve", headers={"X-Api-Token": token})
    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert "approved" in client.get("/vendors/v-globex").text


def test_approve_requires_a_valid_token(client: TestClient) -> None:
    login(client, REVIEWER)
    assert client.post("/vendors/v-globex/approve").status_code == 401
    bad = client.post("/vendors/v-globex/approve", headers={"X-Api-Token": "demo-api-token.bogus"})
    assert bad.status_code == 401


def test_a_vendor_cannot_approve(client: TestClient) -> None:
    login(client, VENDOR)
    token = api_token_from(client.get("/profile").text)
    response = client.post("/vendors/v-globex/approve", headers={"X-Api-Token": token})
    assert response.status_code == 401

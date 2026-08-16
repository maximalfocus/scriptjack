"""Authentication and session-handling behaviour for the secure app (FR-002)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import REVIEWER, VENDOR


def test_healthz_is_unauthenticated(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_redirects_and_sets_a_hardened_cookie(client: TestClient) -> None:
    response = client.post("/login", data=REVIEWER, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/queue"

    set_cookie = response.headers["set-cookie"].lower()
    assert "scriptjack_session=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


def test_vendor_login_redirects_to_profile(client: TestClient) -> None:
    response = client.post("/login", data=VENDOR, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/profile"


@pytest.mark.parametrize("credentials", [REVIEWER, VENDOR])
def test_valid_users_can_reach_the_session_endpoint(
    client: TestClient, credentials: dict[str, str]
) -> None:
    client.post("/login", data=credentials)
    session = client.get("/session")
    assert session.status_code == 200
    assert session.json()["role"] in {"reviewer", "vendor"}


def test_protected_endpoint_requires_a_session(client: TestClient) -> None:
    response = client.get("/session")
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


@pytest.mark.parametrize(
    "payload",
    [
        {},  # missing both fields
        {"username": "reviewer@scriptjack.invalid"},  # missing password
        {"password": "demo-reviewer-password-not-secret"},  # missing username
        {"username": "reviewer@scriptjack.invalid", "password": "wrong"},  # bad password
        {"username": "ghost@scriptjack.invalid", "password": "whatever"},  # unknown user
    ],
)
def test_missing_malformed_and_unknown_credentials_are_generic_401(
    client: TestClient, payload: dict[str, str]
) -> None:
    response = client.post("/login", data=payload, follow_redirects=False)
    assert response.status_code == 401
    # A generic rejection: the same login page, no session cookie issued.
    assert "invalid credentials" in response.text.lower()
    assert "set-cookie" not in {k.lower() for k in response.headers}


def test_logout_clears_the_session(client: TestClient) -> None:
    client.post("/login", data=REVIEWER)
    assert client.get("/session").status_code == 200
    assert client.post("/logout", follow_redirects=False).status_code == 303
    assert client.get("/session").status_code == 401


def test_a_tampered_cookie_is_rejected(client: TestClient) -> None:
    client.post("/login", data=REVIEWER)
    client.cookies.set("scriptjack_session", "tampered.value.not-a-valid-signature")
    assert client.get("/session").status_code == 401

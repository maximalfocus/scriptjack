"""Authentication and session-handling behaviour for the secure app (FR-002)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import REVIEWER, VENDOR


def test_healthz_is_unauthenticated(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_establishes_a_hardened_session_cookie(client: TestClient) -> None:
    response = client.post("/login", data=REVIEWER)
    assert response.status_code == 200
    assert response.json()["role"] == "reviewer"

    set_cookie = response.headers["set-cookie"].lower()
    assert "scriptjack_session=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


@pytest.mark.parametrize("credentials", [REVIEWER, VENDOR])
def test_valid_users_can_reach_the_protected_endpoint(
    client: TestClient, credentials: dict[str, str]
) -> None:
    assert client.post("/login", data=credentials).status_code == 200
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
    response = client.post("/login", data=payload)
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


def test_logout_clears_the_session(client: TestClient) -> None:
    assert client.post("/login", data=REVIEWER).status_code == 200
    assert client.get("/session").status_code == 200
    assert client.post("/logout").status_code == 200
    assert client.get("/session").status_code == 401


def test_a_tampered_cookie_is_rejected(client: TestClient) -> None:
    assert client.post("/login", data=REVIEWER).status_code == 200
    client.cookies.set("scriptjack_session", "tampered.value.not-a-valid-signature")
    assert client.get("/session").status_code == 401

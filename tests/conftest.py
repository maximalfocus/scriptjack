"""Shared pytest fixtures and helpers for the secure application."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from scriptjack.secure.app import create_app

# Valid demo credentials, mirrored from the deterministic demo fixtures.
REVIEWER = {
    "username": "reviewer@scriptjack.invalid",
    "password": "demo-reviewer-password-not-secret",
}
VENDOR = {
    "username": "vendor@scriptjack.invalid",
    "password": "demo-vendor-password-not-secret",
}

_META_TOKEN = re.compile(r'<meta name="scriptjack-api-token" content="([^"]+)"')


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, credentials: dict[str, str]) -> None:
    """Log in, following the post-login redirect so the session cookie sticks."""

    response = client.post("/login", data=credentials)
    assert response.status_code == 200


def api_token_from(html: str) -> str:
    match = _META_TOKEN.search(html)
    assert match is not None, "page did not embed an API token"
    return match.group(1)

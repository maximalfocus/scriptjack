"""Shared pytest fixtures for the secure application."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
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


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client

"""Deterministic, demo-only configuration.

Everything here is conspicuously fictional. The credentials and the session
signing key are **not** secrets: they exist only to make an educational demo
reproducible and are documented as insecure, public-by-design demo values.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DemoUser:
    """A fictional portal user. Passwords are demo-only, never real secrets."""

    username: str
    password: str
    role: str  # "reviewer" or "vendor"
    display_name: str


# Conspicuously fictional demo accounts. The ``.invalid`` TLD is reserved by
# RFC 2606 precisely so these can never collide with a real address.
DEMO_USERS: dict[str, DemoUser] = {
    "reviewer@scriptjack.invalid": DemoUser(
        username="reviewer@scriptjack.invalid",
        password="demo-reviewer-password-not-secret",
        role="reviewer",
        display_name="Riley Reviewer",
    ),
    "vendor@scriptjack.invalid": DemoUser(
        username="vendor@scriptjack.invalid",
        password="demo-vendor-password-not-secret",
        role="vendor",
        display_name="Vaughn Vendor (attacker)",
    ),
}


# A fixed, deliberately insecure signing key. It only authenticates the demo's
# own session cookie against tampering within a throwaway container; it protects
# nothing real and is safe to publish. An operator may override it via the
# environment, but the demo never depends on that.
_DEMO_SESSION_KEY = "scriptjack-demo-session-key-insecure-and-public-by-design"


@dataclass(frozen=True)
class Settings:
    """Runtime settings resolved from the environment with demo defaults."""

    session_signing_key: str = _DEMO_SESSION_KEY
    session_cookie_name: str = "scriptjack_session"
    session_max_age_seconds: int = 8 * 60 * 60


def load_settings() -> Settings:
    """Build :class:`Settings`, allowing an optional environment override."""

    return Settings(
        session_signing_key=os.environ.get("SCRIPTJACK_SESSION_KEY", _DEMO_SESSION_KEY),
    )

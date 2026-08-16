"""Containment: the harness (the context injected script runs in) has no egress.

These run inside the harness container, which is attached only to the hermetic,
egress-less demo network. External name resolution and external connections must
fail, while an in-network demo service remains reachable.
"""

from __future__ import annotations

import socket

import pytest


def test_external_dns_resolution_fails() -> None:
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)


def test_external_ip_connection_fails() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3)


def test_in_network_demo_service_is_reachable() -> None:
    # The secure app is on the same demo network and must resolve and connect.
    with socket.create_connection(("secure-app", 8000), timeout=5):
        pass

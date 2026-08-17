"""Unit tests for the CLI entry point's browser-free paths."""

from __future__ import annotations

import io

import pytest

from scriptjack.cli.__main__ import interactive, main


def test_interactive_quit_returns_zero() -> None:
    assert interactive(io.StringIO("q\n")) == 0


def test_main_without_a_command_prints_help_and_returns_two(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == 2
    assert "compare" in capsys.readouterr().out

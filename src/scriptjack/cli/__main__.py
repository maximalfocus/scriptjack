"""Command-line entry point: `python -m scriptjack.cli compare` (FR-014)."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import TextIO

from playwright.sync_api import sync_playwright

from scriptjack.cli.report import contrast_holds, format_report
from scriptjack.cli.scenarios import Targets, run_all


def targets_from_env() -> Targets:
    return Targets(
        secure=os.environ.get("SCRIPTJACK_BASE_URL", "http://secure-app:8000"),
        vulnerable=os.environ.get("SCRIPTJACK_VULN_BASE_URL", "http://vulnerable-app:8000"),
        half_fixed=os.environ.get("SCRIPTJACK_HALF_FIXED_BASE_URL", "http://half-fixed-app:8000"),
        csp=os.environ.get("SCRIPTJACK_CSP_BASE_URL", "http://csp-vuln-app:8000"),
        collector=os.environ.get("SCRIPTJACK_COLLECTOR_URL", "http://collector:8000"),
    )


def compare(*, verbose: bool) -> int:
    targets = targets_from_env()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        try:
            results = run_all(browser, targets)
        finally:
            browser.close()

    print(format_report(results, verbose=verbose))
    # Exit non-zero if the core contrast broke, so CI catches a regression.
    return 0 if contrast_holds(results) else 1


def interactive(stdin: TextIO = sys.stdin) -> int:
    print("scriptjack interactive — cross-site scripting comparison")
    print("  [enter] run the full vulnerable-vs-secure comparison")
    print("  [q]     quit")
    choice = stdin.readline().strip().lower()
    if choice in {"q", "quit"}:
        return 0
    return compare(verbose=False)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scriptjack",
        description="Compare the vulnerable and secure XSS demos through a real browser.",
    )
    subparsers = parser.add_subparsers(dest="command")

    compare_parser = subparsers.add_parser("compare", help="run the scripted comparison")
    compare_parser.add_argument(
        "--verbose", action="store_true", help="include HTTP/console/CSP detail"
    )
    subparsers.add_parser("interactive", help="interactive menu")

    args = parser.parse_args(argv)
    if args.command == "compare":
        return compare(verbose=bool(args.verbose))
    if args.command == "interactive":
        return interactive()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

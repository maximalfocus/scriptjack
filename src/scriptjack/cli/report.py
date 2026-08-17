"""Render scenario results as a narrative + comparison table (pure — no browser)."""

from __future__ import annotations

from collections.abc import Sequence

from scriptjack.cli.results import ScenarioResult

_NARRATIVE = (
    "scriptjack — cross-site scripting (XSS / CWE-79 / A03): vulnerable vs secure\n"
    "Data stops being data and becomes markup/script at a sink. Keeping data in a\n"
    "data context at every sink is the fix; the allowlist sanitizer and the\n"
    "nonce-based CSP are defence in depth, not the fix. HttpOnly does not stop the\n"
    "chain — the browser attaches the cookie to the script's own request.\n"
)

_HEADERS = (
    "App",
    "Shape",
    "Sink → context",
    "Exec",
    "Srv saw",
    "Beacon",
    "Approval",
    "Authority",
    "Verdict",
)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _optional(value: object) -> str:
    return "—" if value is None else str(value)


def _row(result: ScenarioResult) -> tuple[str, ...]:
    return (
        result.app,
        result.shape,
        result.sink_context,
        _yes_no(result.executed),
        _yes_no(result.server_received_payload),
        _optional(None if result.token_beaconed is None else _yes_no(result.token_beaconed)),
        _optional(result.approval_state),
        _optional(result.authority),
        result.verdict,
    )


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def line(cells: Sequence[str]) -> str:
        return " | ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells))

    separator = "-+-".join("-" * width for width in widths)
    out = [line(headers), separator]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


def format_report(results: Sequence[ScenarioResult], *, verbose: bool = False) -> str:
    rows = [_row(result) for result in results]
    parts = [_NARRATIVE, _render_table(_HEADERS, rows)]

    if verbose:
        detail_lines = ["", "Verbose detail:"]
        for result in results:
            detail_lines.append(f"  [{result.app}] {result.shape}: {_optional(result.detail)}")
        parts.append("\n".join(detail_lines))

    return "\n".join(parts)


def contrast_holds(results: Sequence[ScenarioResult]) -> bool:
    """True when the demonstration's core contrast is intact: the vulnerable app
    executes and completes the chain while the secure app executes nothing."""

    vulnerable_executed = any(r.executed for r in results if r.app == "vulnerable")
    secure_executed = any(r.executed for r in results if r.app == "secure")
    chain_beaconed = any(r.token_beaconed for r in results if r.app == "vulnerable")
    return vulnerable_executed and chain_beaconed and not secure_executed

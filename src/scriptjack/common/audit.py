"""The sanitization audit event (FR-011).

Exactly one generic structured JSON line is written to stdout when the secure
application sanitizes a submission. It supports request correlation and names the
authenticated actor, the field, and the outcome — but never echoes the payload,
never says which tags or attributes were removed (no filter oracle), and never
carries a session cookie, token, secret, or real personal information.
"""

from __future__ import annotations

import json
import sys


def emit_sanitization_event(*, request_id: str, actor: str, field: str) -> None:
    event = {
        "event": "capability_statement.sanitized",
        "request_id": request_id,
        "actor": actor,
        "field": field,
        "outcome": "sanitized",
    }
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()

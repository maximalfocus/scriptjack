"""The fictional vendor-onboarding domain model.

Everything here is invented. Vendors carry a plain-text operating note and a
rich-text capability statement; the portal's single privileged transition is
approving a vendor.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"


@dataclass
class Vendor:
    """A fictional vendor record.

    ``capability_statement_html`` holds HTML. In the secure application it is
    always the *sanitized* output of the allowlist sanitizer; the vulnerable
    application (a later slice) stores it raw — that is the contrast.
    """

    id: str
    name: str
    owner_username: str
    operating_note: str  # plain text, always rendered as text
    capability_statement_html: str  # rich text (sanitized in the secure app)
    status: ApprovalStatus


@dataclass(frozen=True)
class Organization:
    name: str

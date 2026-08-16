"""Deterministic, wholly fictional demo fixtures and an in-memory store.

The store is recreated from scratch whenever a process starts (and can be reset
explicitly), so no demonstration effect persists across runs. The flaw the demo
teaches lives in the rendering layer, not in storage, so a lightweight in-memory
store is sufficient and keeps the fixtures obvious.
"""

from __future__ import annotations

from scriptjack.common.models import ApprovalStatus, Organization, Vendor

ORGANIZATION = Organization(name="Meridian Procurement Cooperative")

# The attacker vendor is owned by the demo "vendor" account; every other vendor
# is an ordinary fictional supplier. Capability statements are authored in the
# exact shape the allowlist sanitizer emits, so seeding them is a no-op for the
# sanitizer (no audit event fires on unchanged, already-safe content).
_SEED: tuple[Vendor, ...] = (
    Vendor(
        id="v-northwind",
        name="Northwind Traders",
        owner_username="vendor@scriptjack.invalid",
        operating_note="Fulfils office-logistics orders within two demo days.",
        capability_statement_html=(
            "<p>Trusted supplier of <strong>office logistics</strong> and "
            "<em>same-week</em> fulfilment.</p>"
        ),
        status=ApprovalStatus.PENDING,
    ),
    Vendor(
        id="v-acme",
        name="Acme Components",
        owner_username="acme@scriptjack.invalid",
        operating_note="Supplies fictional precision parts.",
        capability_statement_html=(
            "<p>Precision components with a <strong>48-hour</strong> demo SLA.</p>"
        ),
        status=ApprovalStatus.APPROVED,
    ),
    Vendor(
        id="v-globex",
        name="Globex Stationery",
        owner_username="globex@scriptjack.invalid",
        operating_note="Bulk stationery for the demo cooperative.",
        capability_statement_html=(
            "<p>Recycled stationery and <em>carbon-neutral</em> demo delivery.</p>"
        ),
        status=ApprovalStatus.PENDING,
    ),
    Vendor(
        id="v-initech",
        name="Initech Print",
        owner_username="initech@scriptjack.invalid",
        operating_note="Managed print for fictional offices.",
        capability_statement_html=(
            "<p>Managed print and <strong>secure shred</strong> demo service.</p>"
        ),
        status=ApprovalStatus.APPROVED,
    ),
)


class VendorStore:
    """An in-memory vendor repository seeded from the deterministic fixtures."""

    def __init__(self) -> None:
        self._vendors: dict[str, Vendor] = {}
        self.reset()

    def reset(self) -> None:
        # Deep-copy each seed record so mutations (approval, profile edits) never
        # leak back into the shared seed tuple.
        self._vendors = {
            v.id: Vendor(
                id=v.id,
                name=v.name,
                owner_username=v.owner_username,
                operating_note=v.operating_note,
                capability_statement_html=v.capability_statement_html,
                status=v.status,
            )
            for v in _SEED
        }

    def list_vendors(self) -> list[Vendor]:
        return [self._vendors[key] for key in sorted(self._vendors)]

    def get(self, vendor_id: str) -> Vendor | None:
        return self._vendors.get(vendor_id)

    def owned_by(self, username: str) -> Vendor | None:
        for vendor in self.list_vendors():
            if vendor.owner_username == username:
                return vendor
        return None

    def search_by_name(self, query: str) -> list[Vendor]:
        needle = query.strip().lower()
        if not needle:
            return self.list_vendors()
        return [v for v in self.list_vendors() if needle in v.name.lower()]

    def set_profile(self, vendor_id: str, operating_note: str, capability_html: str) -> bool:
        vendor = self._vendors.get(vendor_id)
        if vendor is None:
            return False
        vendor.operating_note = operating_note
        vendor.capability_statement_html = capability_html
        return True

    def approve(self, vendor_id: str) -> bool:
        vendor = self._vendors.get(vendor_id)
        if vendor is None:
            return False
        vendor.status = ApprovalStatus.APPROVED
        return True

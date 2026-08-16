"""The in-network collector: the attacker's drop point, inside the demo network.

It stands in for where a real exfiltrated token would go. It accepts only the
demo's beacon shape, records beacons in memory so the harness and CLI can inspect
what left the page, makes **no** outbound requests, and runs on the egress-less
network with no route to anything outside it.
"""

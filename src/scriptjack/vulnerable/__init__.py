"""The intentionally vulnerable vendor-onboarding portal.

This application exists only to demonstrate cross-site scripting. It is opt-in
(a Compose profile plus ``ALLOW_VULNERABLE_DEMO=true``), runs only on an
egress-less container network against fictional fixtures, and must never be
deployed. Its stored sink renders the capability statement as raw markup and it
serves no Content Security Policy, so injected script executes.
"""

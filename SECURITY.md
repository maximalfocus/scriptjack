# Security policy

This repository is **local educational code**. It ships a deliberately vulnerable
application next to a secure one so the difference is visible. Read this before
reporting anything.

## The cross-site-scripting flaw here is intentional

`src/scriptjack/vulnerable/` exists to be exploited. Its stored, reflected, and
DOM-based sinks execute attacker-supplied markup **on purpose**, and its half-fixed
variant is defeated **on purpose** — that is the entire lesson. So are:

- the hand-rolled blocklist in `vulnerable/blocklist.py` and every payload that gets past it;
- the page-embedded fictional API token the injected script reads;
- the approval that the injected script performs under the reviewer's authority;
- the in-network collector that receives the beacon.

**Please do not report these.** They are the demonstrated subject matter, they are
covered in [`docs/explanation.md`](docs/explanation.md), and reports about them will
be closed as intended behaviour.

## What *is* worth reporting

Anything that breaks the containment this project promises, or any flaw in the parts
that are meant to be correct:

- the **secure** application (`src/scriptjack/secure/`) executing injected script at any sink;
- the vulnerable application starting **without** both opt-in actions — its `vulnerable`
  Compose profile *and* `ALLOW_VULNERABLE_DEMO=true`;
- anything on the demo network reaching a host **outside** it, or a published port
  reachable beyond `127.0.0.1`;
- the vulnerable app or the collector running without their hardening (non-root, all
  capabilities dropped, `no-new-privileges`, read-only root filesystem);
- a real credential, real personal data, or a live third-party endpoint anywhere in the
  repository or its history — every value here is meant to be fictional;
- a vulnerability in the build, the container images, or the verification tooling.

## How to report — privately

Use GitHub's **private vulnerability reporting** on this repository:
**Security → Report a vulnerability**. That channel is private to the maintainer; the
report is not visible publicly while it is open.

**Please do not open a public issue for a suspected unintended vulnerability.** There is
no other reporting channel, and no email address is published for this project.

This is a personal educational project, not a product. There is no service-level
agreement and no guaranteed response or fix time. Reports are read and handled on a
best-effort basis.

## Scope: nothing here is deployed

This project runs **only** on your own machine, over loopback, through Docker Compose.
It operates no hosted service, no public endpoint, and no published package or image.
There is no production system to test against, and testing anyone else's system with
this material is out of scope and not endorsed.

Script execution in the demo is confined on purpose — the demo's own origin, a headless
browser the demo drives, a container network with no egress, checked-in payload fixtures,
and wholly fictional data. See
[the contained-browser-execution boundary](docs/explanation.md#the-contained-browser-execution-boundary).

**Do not deploy this. Do not point it at anything real.**

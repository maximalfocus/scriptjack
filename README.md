# scriptjack

An educational, **container-only** demonstration of **cross-site scripting** (XSS —
OWASP A03:2021 Injection, CWE-79): how text a fictional vendor submits to an
onboarding portal stops being *data* and becomes *executable markup* in a reviewer's
browser, and how keeping data in a data context at every sink prevents it.

> ⚠️ This project is **local educational code**. It is designed to run only on your
> own machine over loopback, against wholly fictional fixture data. It ships no
> exploit against any real system and must not be deployed.

It presents the vulnerable behaviour and its fix side by side, proving the same flaw
through three delivery shapes — **stored**, **reflected**, and **DOM-based** — plus a
half-fixed variant whose hand-rolled blocklist is defeated without any `<script>` tag,
so the lesson lands on the *class* of mistake: data crossing into a markup or script
context. The primary fix is **context-correct output at every sink**; an allowlist
sanitizer and a nonce-based CSP are defence in depth, not the fix.

Two things people get wrong, demonstrated here: **`HttpOnly` cookies do not stop the
takeover** (the browser attaches the cookie to the script's own request), and **fixing
the server templates does not fix the DOM sink** (its payload rides in the URL fragment,
which the server never sees).

## Documentation

- **[docs/walkthrough.md](docs/walkthrough.md)** — the guided walkthrough, the one-shot
  command and its expected output, manual exploration, and the tests.
- **[docs/explanation.md](docs/explanation.md)** — cross-site scripting in plain
  language: data-versus-markup context, the XSS / CWE-79 / A03 terminology, the layered
  lesson, and the contained-browser-execution safety boundary.
- **[SECURITY.md](SECURITY.md)** — which flaws here are deliberate (most of them) and how
  to privately report one that is not.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — the Docker-only workflow, the verification
  gate, and the containment invariants a change must not break.

## Requirements

Only **Docker** (with Compose v2). No host Python, no browser install, and no
project packages are needed on the host.

## Run the secure application

```sh
docker compose up secure-app
```

The secure portal listens on `http://127.0.0.1:8000` (loopback only). No service
port is ever published beyond `127.0.0.1`.

## Run the checks

Ruff, mypy, and pytest run inside a container through a single command — the exact
same boundary used by CI:

```sh
docker compose run --rm verify
```

## Run the browser harness (the secure ↔ vulnerable demo)

A headless-Chromium (Playwright) service, attached **only** to a hermetic
egress-less network, drives a **real browser** against both apps: it proves the
checked-in payload fixtures **execute** at the vulnerable app's stored sink and
**do not** execute against the secure app, while the reviewer's legitimate work
still succeeds. It also drives the full contained takeover chain — the stored
payload reads the page-embedded token, approves the attacker's vendor **as the
reviewer**, and beacons the token to an in-network **collector** — and shows the
secure app resisting the identical payload. The vulnerable app and collector are
intentionally insecure and opt-in.

For a fresh, deterministic run:

```sh
docker compose down -v
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable \
  run --build --rm harness
```

The vulnerable app **will not start** without both enabling its `vulnerable`
profile and setting `ALLOW_VULNERABLE_DEMO=true`. Nothing unsafe starts with a
plain `docker compose up`.

## Run the comparison CLI

The comparison CLI drives every payload shape against both applications through the
real browser and prints a short narrative, a before/after comparison table, and a
vulnerable/secure verdict:

```sh
docker compose down -v
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable \
  run --build --rm harness python -m scriptjack.cli compare
```

Add `--verbose` for the HTTP/console/CSP detail. The full contrast completes in well
under five minutes once images are built.

## Scope and safety

- All users, credentials, and data are conspicuously fictional demo values.
- The secure application is the default. Nothing unsafe starts with
  `docker compose up`.
- Ports are loopback-only; there is no cloud or hosted deployment.
- The vulnerable application's cross-site-scripting flaws are **intentional** and are the
  subject being taught — see [SECURITY.md](SECURITY.md) before reporting one.
- Injected script runs only in the demo's own origin, in a headless browser the demo
  drives, on a container network with no egress, from checked-in payload fixtures. See
  [the contained-browser-execution boundary](docs/explanation.md#the-contained-browser-execution-boundary).

## No warranty, no service

This is a personal educational project, offered as-is. It makes **no** service-level,
support-duration, compatibility, or production-readiness promise, and it operates no
hosted service, public endpoint, or published package or image. Nothing here is intended
or suitable for production use, and none of it should be pointed at a system you do not
own.

## License

[MIT](LICENSE) — Copyright (c) 2026 maximalfocus.

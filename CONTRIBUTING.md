# Contributing

Thanks for looking. This is a small, single-purpose teaching project: it demonstrates
cross-site scripting and its context-correct fix, side by side. Contributions that make
the lesson clearer, more correct, or easier to run are welcome.

Before reporting a security problem, read [`SECURITY.md`](SECURITY.md) — the vulnerable
application's flaws are intentional and are not bugs.

## You only need Docker

There is no host Python environment, no browser install, and no project package to
install. Docker with Compose v2 is the whole toolchain.

```sh
git clone https://github.com/maximalfocus/scriptjack.git
cd scriptjack
docker compose up secure-app          # secure portal on http://127.0.0.1:8000
```

## The verification gate

One command runs Ruff, mypy, and the unit tests inside a container — the exact boundary
CI uses, so local and CI results cannot drift:

```sh
docker compose run --build --rm verify
```

The browser-driven regression matrix runs a real headless Chromium against both
applications:

```sh
docker compose down -v
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable run --build --rm harness
```

And the user-facing comparison:

```sh
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable \
  run --rm harness python -m scriptjack.cli compare
```

All three must be green before you open a pull request. CI runs the same three.

## Invariants a change must not break

These are the properties that make an intentionally vulnerable demo safe to hand to a
stranger. A change that weakens one will not be merged.

1. **The secure application is the default.** A plain `docker compose up` must never
   start anything unsafe.
2. **The vulnerable application stays opt-in behind two deliberate actions** — its
   `vulnerable` Compose profile *and* `ALLOW_VULNERABLE_DEMO=true`. The half-fixed
   variant needs a further explicit selection.
3. **Loopback only.** No published port may bind beyond `127.0.0.1`, and no cloud or
   hosted deployment configuration belongs here.
4. **The demo network has no egress.** The vulnerable app, the collector, and the
   harness stay on the hermetic network; the collector is the only beacon target.
5. **Hardening stays on** for the vulnerable app and the collector: non-root, all
   capabilities dropped, `no-new-privileges`, read-only root filesystem.
6. **Fictional data only.** No real credential, token, personal information, or real
   organization may enter the repository, its fixtures, its tests, or its history.
   Fixture "tokens" must stay conspicuously fake.
7. **Payloads are checked-in fixtures**, never arbitrary or externally fetched input,
   and the only privileged effect stays the one documented approval transition that a
   fresh run resets.
8. **No build step and no third-party runtime asset** on the client. Plain HTML, CSS,
   and JavaScript, so the `innerHTML`-versus-`textContent` contrast stays readable in
   the served source.
9. **Secure sinks stay context-correct.** The fix is correct output at every sink; the
   allowlist sanitizer and the nonce CSP are defence in depth, not the fix, and must not
   become the thing the demo relies on.
10. **No new oracle.** Responses and audit events must not disclose which tags or
    attributes were removed.

## Style

- Python 3.13, FastAPI, server-side Jinja2 templates.
- Ruff and mypy (`strict`) must both be clean; configuration lives in `pyproject.toml`.
- Match the surrounding code. Keep the diff small and focused.
- Add a test at the boundary you changed: a unit test in `tests/`, or a browser scenario
  in `browser_tests/` when only a real browser can prove it.

## Pull requests

Open an issue first for anything beyond a small fix, so the scope can be agreed before
you write code. In the pull request, say what changed, why, and paste the results of the
three commands above.

This is a personal project maintained on a best-effort basis. There is no service-level
agreement, no support commitment, and no promise of review or release timing.

## License

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE) that covers this project.

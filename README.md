# scriptjack

An educational, **container-only** demonstration of **cross-site scripting** (XSS —
OWASP A03:2021 Injection, CWE-79): how text a fictional vendor submits to an
onboarding portal stops being *data* and becomes *executable markup* in a reviewer's
browser, and how keeping data in a data context at every sink prevents it.

> ⚠️ This project is **local educational code**. It is designed to run only on your
> own machine over loopback, against wholly fictional fixture data. It ships no
> exploit against any real system and must not be deployed.

This repository is being built slice by slice. Today it contains the secure
application's container/CI foundation and demo authentication; the vulnerable
contrast, the in-network collector, the headless-browser harness, and the
comparison CLI arrive in later slices.

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

## Scope and safety

- All users, credentials, and data are conspicuously fictional demo values.
- The secure application is the default. Nothing unsafe starts with
  `docker compose up`.
- Ports are loopback-only; there is no cloud or hosted deployment.

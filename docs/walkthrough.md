# Walkthrough

> ⚠️ **Local educational code — do not deploy.** The vulnerable application intentionally executes
> attacker script. It runs only on your machine, over loopback, on an egress-less container
> network, against wholly fictional data. Read the [safety boundary](explanation.md#the-contained-browser-execution-boundary)
> first.

The demo models a fictional **vendor-onboarding portal**. External vendors submit a profile with a
plain-text operating note and a rich-text capability statement; internal reviewers open a queue,
search, and **approve** vendors (the portal's one privileged action). Each page embeds a
conspicuously fictional per-session API token. The session cookie is `HttpOnly` and `SameSite` in
**both** applications, so cookie flags are never the variable under test.

Everything runs in containers; the host needs only Docker (with Compose v2).

## The one command

Run the full three-axis contrast — every payload shape against both applications, through a real
headless browser — and read the verdict table:

```sh
docker compose down -v
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable \
  run --build --rm harness python -m scriptjack.cli compare
```

### Expected outcome

```
App        | Shape                             | Sink → context         | Exec | Srv saw | Beacon | Approval | Authority         | Verdict
vulnerable | Stored (capability statement)     | server template → HTML | yes  | yes     | yes    | approved | reviewer (victim) | VULNERABLE
secure     | Stored (capability statement)     | server template → HTML | no   | yes     | no     | pending  | —                 | SECURE
vulnerable | Reflected (search q)              | search q → HTML        | yes  | yes     | —      | —        | —                 | VULNERABLE
secure     | Reflected (search q)              | search q → text        | no   | yes     | —      | —        | —                 | SECURE
vulnerable | DOM-based (URL fragment)          | fragment → innerHTML   | yes  | no      | —      | —        | —                 | VULNERABLE
secure     | DOM-based (URL fragment)          | fragment → textContent | no   | no      | —      | —        | —                 | SECURE
half-fixed | Half-fixed: literal <script>      | HTML (naive blocklist) | no   | yes     | —      | —        | —                 | BLOCKED (blocklist)
half-fixed | Half-fixed: <img onerror> bypass  | HTML (naive blocklist) | yes  | yes     | —      | —        | —                 | VULNERABLE (bypass)
csp        | CSP-alone (still-vulnerable sink) | HTML (+ nonce CSP)     | no   | yes     | —      | —        | —                 | MITIGATED (CSP)
```

How to read it:

- **Exec** — did the browser run the injected script?
- **Srv saw** — did the payload reach the server? Note the **DOM-based** row: `no`. The fragment
  is never transmitted, so the flaw is entirely client-side and appears in **no** server log.
- **Beacon / Approval / Authority** — the takeover chain (shown for the stored headline): the token
  was beaconed to the collector, and the attacker's own vendor was **approved under the reviewer's
  authority** — the reviewer clicked nothing.
- **Verdict** — `MITIGATED (CSP)` is the still-vulnerable sink whose payload the nonce CSP blocks;
  `BLOCKED (blocklist)` is the one payload the naive blocklist happens to strip — while the next
  row shows it bypassed.

Add `--verbose` for the HTTP / console / CSP-violation detail.

## The scenarios, one at a time

### 1. Vulnerable path — the takeover chain (stored)

The attacker vendor saves a capability statement containing a checked-in payload. When the reviewer
opens the queue, the payload:

1. reads the page-embedded fictional API token;
2. calls **approve** on the attacker's own vendor — the browser attaches the `HttpOnly` session
   cookie automatically, so the action runs **as the reviewer**; and
3. beacons the token to the in-network collector.

The reviewer performed no approval and sees an unremarkable page. **`HttpOnly` did not help** — the
script never read the cookie ([why](explanation.md#httponly-cookies-do-not-stop-this)).

### 2. Reflected and DOM-based

- **Reflected:** a single crafted `/search?q=…` link executes the same way, with nothing stored on
  the server.
- **DOM-based:** a crafted `/filtered#…` deep link executes from the URL **fragment**. The server
  never receives the payload — proof the flaw is client-side, and proof that fixing the server
  templates alone would leave it wide open
  ([why](explanation.md#fixing-the-server-templates-does-not-fix-the-dom-sink)).

### 3. The half-fixed blocklist

With the hand-rolled blocklist enabled, a literal `<script>` payload is stripped and *appears*
fixed — while `<img src=x onerror=…>`, `<svg onload=…>`, and a nested tag that reconstitutes after
one removal pass each still execute.

### 4. Secure rejection

Against the secure app the **identical** payloads render as inert text or are removed by the
allowlist sanitizer; **no script executes** in any shape, the collector receives nothing, no token
leaves the page, and the reviewer's approval state is byte-for-byte unchanged. The sanitizer emits
exactly one generic audit event per sanitized submission and never says which tags it removed.

### 5. CSP as defence in depth

A separate instance keeps the vulnerable sink but serves a nonce-based CSP with no `unsafe-inline`.
The payload is **injected but does not execute** — CSP contains the blast radius while leaving the
injection unfixed.

### 6. Secure legitimate path

The reviewer's ordinary work is unaffected: a legitimate capability statement's bold, emphasis, and
links render exactly as in the vulnerable app, search returns the same results, the shareable
filtered view deep-links correctly, and a reviewer's own deliberate approval succeeds.

## Manual exploration

Bring up the applications and browse them yourself (loopback only):

```sh
# secure app — the default
docker compose up secure-app                      # http://127.0.0.1:8000

# vulnerable app + collector + variants (opt-in, two deliberate actions)
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile vulnerable up \
  vulnerable-app collector half-fixed-app csp-vuln-app
#   vulnerable   → http://127.0.0.1:8001
#   collector    → http://127.0.0.1:8002   (GET /beacons to see what was exfiltrated)
#   half-fixed   → http://127.0.0.1:8003
#   csp-vuln     → http://127.0.0.1:8004
```

Demo credentials are shown on each login page. The vulnerable application **will not start**
without both enabling its `vulnerable` profile and setting `ALLOW_VULNERABLE_DEMO=true`.

## Tests

```sh
# unit (Ruff + format + mypy + pytest), in one container:
docker compose run --rm verify

# the full browser regression matrix (secure + vulnerable contrast):
ALLOW_VULNERABLE_DEMO=true \
  docker compose --profile harness --profile vulnerable run --build --rm harness
```

Both are the exact boundaries CI runs.

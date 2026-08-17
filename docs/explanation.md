# Cross-site scripting, in plain language

> This is local educational material. Every organization, vendor, reviewer, token, and secret in
> this project is fictional. See the [safety boundary](#the-contained-browser-execution-boundary).

## Data versus a markup or script context

Software constantly moves text between **contexts**. The same characters mean different things
depending on where they land:

- In a **data context**, `<b>hi</b>` is five-plus characters of text — a literal angle bracket, a
  letter `b`, and so on. It is *shown*, not *interpreted*.
- In a **markup context**, `<b>hi</b>` is an instruction to the HTML parser: start a bold element,
  put "hi" inside it, end it. `<script>…</script>` is an instruction to *run code*.

A **sink** is the exact place where your program hands text to something that interprets it — an
HTML template, the browser's HTML parser via `innerHTML`, a script evaluator. **Cross-site
scripting (XSS) is what happens when attacker-supplied text reaches a markup or script sink still
being treated as code** — the browser parses it and runs it with everything the victim's session
can reach.

The fix is not a magic filter. It is **keeping data in a data context at every sink**: emit user
text as text, not as markup.

## The three shapes in this demo

This project proves the *same* flaw through three delivery shapes, because the lesson is about the
**class** of mistake — data crossing into a code context — not one framework, sink, or payload.

| Shape          | Where the crossing happens (this demo)                                     | Where the payload travels           |
| -------------- | -------------------------------------------------------------------------- | ----------------------------------- |
| **Stored**     | a persisted capability statement emitted as HTML by a server template      | saved on the server, shown to others |
| **Reflected**  | a search page that echoes its `q` parameter into the response as markup     | in a single crafted link's query    |
| **DOM-based**  | client code that assigns the URL **fragment** to `innerHTML`                | in the URL fragment (`#…`)          |

All three converge on the same outcome: **attacker script running with the reviewer's authority.**

## Terminology

- **Cross-Site Scripting (XSS)** — also **HTML injection** / **script injection**; the third shape
  is **DOM-based XSS** or **client-side injection**.
- **OWASP Top 10 2021: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/).**
- **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)** — *Improper Neutralization of Input
  During Web Page Generation.*

## The layered lesson

1. **The fix — context-correct output at every sink.** Server templates render with autoescaping
   on and no escape-suppressing construct on user data; the reflected parameter is emitted as text;
   client code uses `textContent` / `setAttribute`, never `innerHTML` / `document.write` / `eval`
   on request-borne data.
2. **Defence in depth #1 — an allowlist sanitizer** for the one field that must carry a little
   formatting (the capability statement). It is **narrower and more fragile than not rendering user
   HTML at all**, and only as good as the parser behind it.
3. **Defence in depth #2 — a nonce-based Content Security Policy** with no `unsafe-inline`. It
   contains the blast radius — even on a still-vulnerable sink the injected script cannot run — but
   it does **not** fix the injection.

The **half-fixed** variant shows the anti-pattern: a hand-rolled blocklist that strips `<script>`
*looks* fixed, yet `<img src=x onerror=…>`, `<svg onload=…>`, and a nested tag that reconstitutes
after one removal pass all still execute. **A blocklist over a grammar you do not own cannot
enumerate its own failures.**

## Two things people get wrong

### `HttpOnly` cookies do not stop this

`HttpOnly` stops JavaScript from *reading* `document.cookie`. It does **not** stop the script from
*acting as the victim*: the injected script reads a page-embedded API token, calls the privileged
**approve** endpoint, and the browser **attaches the `HttpOnly` session cookie to that request
automatically**. The script never needed to read the cookie. In this demo the reviewer opens their
queue and does nothing else, yet the attacker's own vendor is approved under the reviewer's
authority and the token is beaconed to a collector.

### Fixing the server templates does not fix the DOM sink

The DOM-based payload travels in the URL **fragment** (`#…`), which the browser **never sends to
the server**. No server-side template — however well escaped — sees it. Only fixing the *client*
sink (using `textContent` instead of `innerHTML`) closes it. That is why the client sink is a
first-class part of the fix, not an afterthought.

## The contained-browser-execution boundary

Script execution in the victim's browser *is* this vulnerability's mechanism, so this demo
deliberately performs it — under tight bounds:

- injected script runs **only** inside the demo's own origin, **only** in a headless browser the
  demo itself drives, on a **hermetic container network with no egress**;
- it touches **only** fictional fixture data; the one privileged action is a single documented
  approval transition that a fresh run resets;
- the exfiltration target is an **in-network collector** that never contacts anything outside the
  network; and
- the executed strings are **checked-in fixtures**, not arbitrary attacker input.

**The same execution reach could run arbitrary script against anything the victim's session can
reach in a real deployment.** This demo confines it on purpose. It is local educational code and
**must not be deployed.**

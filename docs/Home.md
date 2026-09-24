# nettls

**In short:** the building block that lets services talk to each other encrypted — and lets them
change identity along the way without losing the trust. Think of it as the padlock in the
browser, plus the machinery for changing the lock without handing out new keys.

## Why does it exist?

Because TLS looks like something that "just works", and the hard parts live somewhere other than
you'd think.

**The crypto engine can refuse to start.** The library we build on gives up if it is served two
different engines at once — and because dependencies stack on top of each other without asking,
that happens easily by accident. The ugly part is *when* it is discovered: not at build time, but
the moment someone actually connects. Which tends to be after things have been switched on.

**Recognizing each other without a third party is easy — until something has to change.** Two
services can recognize each other by a fingerprint instead of trusting a certificate authority.
But then the fingerprint must never change, and a key that sits unchanged for years is a key
someone has time to steal. If keys are to change often, the recognition has to survive it.

**And the same setup repeated in two services is the same mistakes made twice.**

The library gathers this in one place, with tests.

**Where it came from.** It was built for an application that needed its own traffic
encrypted — two services, one operator secret passing through both — and it has carried that
traffic ever since.

The shape of it comes from [RFC 8061](https://www.rfc-editor.org/rfc/rfc8061.html), on
confidentiality in the data plane: how two endpoints keep traffic between them confidential
without a certificate authority in the middle. They establish who the other is directly, and
the channel rests on that alone. That is why this crate looks the way it does — self-signed
certificates rather than a CA chain, a fingerprint as the identity, and a way for that identity
to change without the recognition breaking.

The cryptography itself is not here: every primitive comes from the `krypto` crate, on purpose,
so the same algorithms are not written twice in two places that then have to agree about them.

## What can you use it for?

| | |
|---|---|
| **Turn on HTTPS in a service** | gives you a finished config; you bind the port yourself |
| **Make a certificate yourself** | and remember it until the next start, so the fingerprint does not change on every restart |
| **Take a certificate you were given into use** | from files or pasted text — checked before use, so an invalid one never replaces one that works |
| **Recognize a peer by its fingerprint** | no certificate authority, no name lookups |
| **Change keys while the service runs** | no restart, no broken connections |
| **Let the peer follow you onto the new one** | the old identity vouches for the new, signed |
| **Require the peer to confirm** | a switch does not complete until the other side has acknowledged |
| **Send something secret to one specific recipient** | sealed so only the holder of the right key can open it |
| **Know when the certificate expires** | well in advance, as a number you can alert on |

**[Usage](Usage.md)** shows how to get started and in what order things are done. **[API](API.md)** is
the lookup reference for every type and function.

## Two ways to use it

The library is built for two different situations, and it is worth knowing which one you are in:

| | Right when | Certificate lifetime |
|---|---|---|
| **Pinning** | the peer is a human with a browser, or a party that cannot follow a switch | long |
| **Rolling** | both sides are services we control | short, changed regularly |

The first is simple: one fingerprint, approved once. The second is the secure one: keys change so
often that a key that leaks is already out of use. The price is that both sides have to take part
— and the library enforces it: a switch does not complete until the peer has acknowledged.

**Both parties must agree on which mode they are in.** If they do not, the library says so
instead of guessing.

## What it does not do

Just as important as what it can:

- **It does not run by itself.** It gives you the config; you bind the port, and you decide when
  a rotation happens. No background thread, no timers.
- **It logs nothing.** It returns facts — fingerprint, origin, days to expiry — and lets the
  service log them where it wants. A library that logged on its own would log in the wrong place.
- **It does not tie you to a framework.** No web server, no async runtime. That is why different
  services can use it without becoming alike.
- **It does not administer certificates.** No admin pages, no upload surface, no CSR generation.
  That belongs in the service that has an operator to talk to.
- **It does not decide your trust.** The root is always that a human approved the first identity.
  The library can extend a trust that exists; it cannot create one.
- **It does not negotiate ciphers on its own.** The channel's cipher is the consumer's choice
  (`TransportPolicy`, 0.8.3): AES-256-GCM alone by default — what every peer speaks — and
  ChaCha20-Poly1305 or AEGIS-256 on request, in the consumer's order. No common suite is a hard
  failure, never a fallback.
- **It does not set HSTS.** Deliberately — switched on once while running your own certificate,
  it locks the operator out permanently in that browser.

## What it is built on

| Purpose | Choice |
|---|---|
| TLS | [rustls](https://github.com/rustls/rustls) with **ring** as the crypto engine |
| Protocol versions | TLS 1.3 **and** 1.2 — 1.2 is there for compatibility, not out of habit |
| Key type on own certificates | **ECDSA P-256** |
| Signatures when identity changes | ECDSA P-256 and **Ed25519** — via krypto |
| Sealing to one recipient | **X25519** — via krypto |
| Secrets in memory, encryption at rest | **krypto** — AEGIS-256 by default, AES-256-GCM as the interop bridge |
| Max lifetime of an own certificate | 397 days — browsers reject longer |

Since 0.8.0 **every cryptographic primitive is krypto's**
(signatures, key agreement, hashing, hex, randomness) — nettls implements none of its own and no
longer depends directly on `ring` or `x25519-dalek`. What nettls owns is the TLS domain and its
**formats**: the envelope, the locked state file and the §6 messages — and, since 0.8.3, the
seam that puts AEGIS-256 into the TLS record layer (`aegis`).

> **⚠ One-time consequence of the migration:** krypto 0.5.0 fixed a key/nonce swap in the
> AEGIS-256 layer, and lockbox files and envelopes are AEGIS by default — anything written
> with krypto ≤ 0.4.4 must be re-created (lock/seal the content again). Nothing is in
> production; AES-256-GCM data is unaffected.

**About the choices:** they were made with reasons and should not be "improved" without reading
them. ECDSA over RSA is not a tightening — it actually gives *better* backwards compatibility.
TLS 1.2 being present looks like legacy, but removing it is a compatibility regression. The
reasons are in **[Usage](Usage.md)**.

`#![forbid(unsafe_code)]` — the library contains zero `unsafe`.

A **Python twin** (`python/nettls.py`) implements the protocol — messages, signatures, generation
state, the schedule, **and self-signed issuance** (`self_signed`: same P-256/SAN/lifetime rules
as the crate) — against the same frozen test vectors, so a Python service can create its own
identity and take part in the rotation.
The TLS transport itself stays in Rust.

## Who uses it

More than one application already runs on it: a portal that terminates HTTPS for an operator,
and a gateway toward network equipment — both recognizing each other through this crate.

The crate knows nothing about them. It has no opinion about what your services do — it gives
them an encrypted channel and a way of recognizing each other.

## Maturity

The core is built and tested: certificate handling, pinning, swapping certificates in flight, and
the entire announcement-and-receipt flow. The tests include **real TLS handshakes over TCP** —
the right fingerprint gets through, the wrong one is stopped, and a connection that is already up
survives the server changing certificates.

The tests also cover the cheating attempts: a confirmation signed with the wrong key is rejected
even when it otherwise looks right, and one where a single character was altered afterwards is
rejected too.


## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. 

The code is written by Claude AI (Opus and Fable).

Reviewed independently by DeepSeek, Qwen, Gemini and Fable.


## License

Open source: **MIT / Apache-2.0** — you pick. Free to use and build on.

# Using nettls

This page is the overall guide: what you do, in what order, and what to watch out for. If you
need to look up a specific type or function, **[API](API.md)** is the reference.

## The short picture

nettls gives you two things: **a TLS config you can bind a port with**, and **a way for two
services to recognize each other** without a certificate authority.

Everything the library does, it does on request. It starts no threads, takes no initiative and
logs nothing. The rhythm is yours.

## Step 1 — put it in

One rule before everything else: **call `install_crypto_provider()` first in `main()`.**

```rust
fn main() {
    nettls::install_crypto_provider();
    // … the rest of startup
}
```

The reason is the most important trap the library exists to avoid. The crypto engine under TLS
refuses to start if it finds two engines compiled in at once, and the failure only shows up at
the **first connection** — not at build time. This call makes the choice explicit.

> ⚠ **The crate cannot fix this for you alone.** It cleans up its own dependency tree; yours you
> must clean up yourself. In practice that means `default-features = false` on everything that
> pulls in TLS, and picking the variant *without* a built-in engine when a framework offers both.
> Add a test that fails if a second engine sneaks into the lockfile — that is how the crate does
> it itself (`no_other_crypto_provider_in_cargo_lock`).

## Step 2 — turn on HTTPS

You say where the certificate comes from, and get a finished config back.

```rust
let params = nettls::SelfSignedParams::new("my service", ["localhost", "10.0.0.5"]);
let material = nettls::TlsMaterial::load(&nettls::CertSource::auto("/tls", params))?;
let config = material.server_config()?;   // bind the port with this
```

Four sources exist: **`files`** (two PEM files), **`pem`** (PEM you hold in memory),
**`self_signed`** (make one now, store nothing) and **`auto`** (reuse what is in the directory,
make a new one if it is missing).

`auto` is the usual one. The point is the reuse: make a new certificate on every start, and the
fingerprint changes every time — and everyone who recognized you no longer does.

> ⚠ **Always log `origin()` at startup.** If the directory is not writable, `auto` falls back to
> a certificate that only exists in memory (`Ephemeral`). Everything works — until the next
> restart, when the fingerprint is new and the peers no longer recognize you. That is a failure
> you want to discover at once, not in three weeks.
>
> ⚠ **An expired stored certificate is reused too** — marked `ReusedExpired`. The service comes
> up, and clients complain about the date. That is deliberate: silently generating a new one
> would change the fingerprint and break every pinned pairing, turning a clear date error into an
> inexplicable connection failure. Replacing it is an operator action. Log this one loudly.

Worth logging at the same time: `fingerprint_sha256()` (what the peer pins) and
`days_until_expiry()`.

## Step 3 — the client side

If you talk to someone with their own certificate, you recognize them by the fingerprint:

```rust
let client = nettls::pinned_client_config(&fingerprint)?;
```

No certificate authority, no name check — the fingerprint *is* the identity. The handshake
signature itself is verified in full, and that is what makes this safe.

If you need the fingerprint of a certificate you have merely *seen* — for instance to show an
operator who is about to approve it — use `cert_fingerprint_sha256()`.

> **Where does the fingerprint come from the first time?** Not from the connection. The root of
> the whole model is that a human compared the fingerprint with the peer's own startup log and
> said yes. The library can extend a trust that exists; it cannot create one.

## Step 4 — choose a mode

Here the use splits in two, and the choice should be deliberate.

### Mode 1 — pinning

One certificate, long lifetime, approved once. No rotation.

Right when the peer is **a browser**, or a party that cannot follow a switch. Use
`mode1_params(...)` to build the parameters; you can set the lifetime yourself within the bounds
(47–365 days, default 90). You must warn ahead of expiry yourself — `days_until_expiry()` gives
you the number, and `mode1_should_warn()` gives you the threshold (30 days).

### Mode 2 — rolling

Short lifetime, changed regularly. Right when **both sides are services you control**.

This is the secure variant: keys change so often that a key that leaks is already out of use.
Use `mode2_params(...)` — the lifetime is always 30 days, on purpose not tunable: the rotation
*is* the security mechanism, and a lifetime the operator can tune would make it a setting instead
of a guarantee.

The price is that both sides take part. The library enforces it — a rotation does not complete
until the peer has acknowledged.

> **Both parties must agree on the mode.** `check_mode(ours, theirs)` says so if you are not,
> with a message you can display. It never guesses, and it never negotiates: a party that can
> *ask* for a mode can ask for the weakest one.

## Step 5 — if you chose mode 2

This is the part that asks the most of you, so here is the whole flow in broad strokes:

1. **You announce.** When the time approaches, you create an announcement: *"here is my next
   certificate"*, signed with the identities the peer already trusts (previous + current key —
   forging it takes two consecutive private keys). It is published where the peers can fetch it.
2. **The peers fetch and verify.** They check the signatures against what they have stored.
   If they hold, they store the new certificate as accepted — *next to* the old one.
3. **The peers acknowledge.** The receipt is signed too, and it is the gate. Without it, nothing
   more happens.
4. **You roll.** When everyone has acknowledged, you switch certificates. It happens while the
   service runs — no restart, no broken connections.

In practice `Announcer` keeps track of this for you: call `prepare()` when you want to announce,
`acked()` when a peer has answered (after **verifying** the receipt with `Receipt::verify` —
against both the pinned key and the fingerprint you announced), and `roll_if_ready()` regularly.
The last one does nothing until everyone has acknowledged.

> `Announcer::new` restores the chain and any pending switch itself, fail-closed: state on disk
> is used; state that exists but cannot be read fails construction loudly; nothing on disk means
> your anchor is generation 0. There is no startup call left to forget.

**Why two generations?** Because two services do not switch in the same second. Both are held
valid for a period, otherwise the connection would break mid-transition. Never more than two —
the trust surface would grow with every rotation, and an old leaked key would keep its value.

**Have work that must not be interrupted?** Use `roll_if_ready_gated(now, || safe_now())`. The
receipt answers for the peer; the gate answers for **you** — a gateway holding a device session
open mid-configuration returns `false` and is asked again later. The gate is consulted only when
everything else is ready, and a `false` postpones with no side effects.

### The switch and the live connections

These are the questions everyone asks at the first rotation, so here are the answers straight
out:

- **You never need to close anything for the switch to work.** The rotation applies to *new*
  connections. Open connections have already done their handshake and live on their own key
  material — the library does not touch them.
- **New connections get the new certificate automatically.** The server side
  (`RotatingResolver`) and the client side (`Trust`) read live state at every handshake. You
  build the config **once**; it follows the switches by itself. You never rebuild it for a
  rotation.
- **"Renegotiate" does not exist, and you do not need it.** Identity is checked only when a
  connection opens. After that the traffic keys protect it — they live their own life inside the
  connection.

So the important thing you *must* know, stated here because it cannot live in the code:

> ⚠ **Do not let connections live forever.** Identity is checked only as the connection opens —
> a connection is a snapshot of the trust *at that moment*. Never let it outlive the certificate
> it was approved under: recycle connections within the certificate's lifetime. (HTTP client
> pools often do this by themselves; hand-built long-lived connections do not.)
>
> ⚠ **If you rotate because you believe the key is compromised, you must close old connections
> yourself.** The library does not know *why* you rotate — and someone already inside an
> established connection stays there until it closes. `roll_if_ready` returns the old
> fingerprint as the handle for exactly this.

(Session resumption is already disabled on the client side — a resumed session would have
skipped the identity check.)

**Note the division of labour inside `Announcer`:** the chain and the serving switch **together,
inside `roll_if_ready`** — there is no way to roll the chain without the resolver following. If
you build on the primitives directly (`Schedule` + `RotatingResolver::swap`) instead, keeping
those two in one place in your code is on you: switch only one and you sign with the new key
while serving the old certificate, and the peer rejects you. And never use
`pinned_client_config` against a rotating peer — it accepts exactly one fingerprint forever;
against a rotating peer, `Trust` is the tool.

### When something is off

The library does not guess. If it meets an announcement it cannot verify, it stops and says what
is wrong — unknown certificate, invalid signature, or an abandoned certificate. Then a human must
approve anew.

There is a defined way down too: `FallToMode1` describes the transition to static pinning when
the rotation cannot continue. The point is that the downgrade is a choice someone makes, never
something that happens silently — and it is never retried on its own: a retry against an identity
we cannot verify is one more chance for whoever stands in the middle.

## Step 6 — what you do yourself

The library provides the building blocks. This is yours:

| | |
|---|---|
| **Bind the port** | you get a config, not a server |
| **Decide when** | no timers in the library — you call when you want |
| **Log** | fingerprint, origin, days left, and every rotation |
| **Show the operator something** | approving the first identity is a human action |
| **Publish the announcement** | the library builds it; you decide where it is fetched from |
| **Keep the files** | the directory must survive restarts, or you lose the identity |
| **Persist receipts state** | call `save_pending()` after `prepare`/`acked`, so a restart resumes instead of resetting |

## Easy ways to trip

- **Forgetting `install_crypto_provider()`.** Everything builds, nothing connects.
- **Not logging `origin()`.** Hides that the certificate is ephemeral — or expired.
- **Leaving the directory unwritable.** Same symptom, different cause.
- **Assuming rotation is automatic.** It happens when you call.
- **Setting HSTS yourself.** With your own certificate it locks the operator out permanently in
  that browser.

## Further

- **[Home](Home.md)** — what nettls is, and what it is not
- **[API](API.md)** — the reference for every type and function

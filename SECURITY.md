# Security Policy

## Before you report

This code has been reviewed a lot. Several different language models and analysis
tools have gone over it independently — DeepSeek, Qwen, Gemini and Claude among them —
across more than one release, with a person going through what each returned. The
passes were not only over the implementation: the API contract itself was reviewed
separately at three consecutive versions, and the crate was cross-checked against the
`krypto` crate it depends on, in both directions.

Those passes found real things. One was a defect and is fixed: a state file was
written with a plain `fs::write` — not replaced atomically, and without restrictive
permissions — so a crash mid-write could leave corrupt material behind. Others were examined and
deliberately left as they are, with the reasoning written down: fingerprint
comparisons that run in variable time because the values compared are public and
travel in cleartext during the handshake anyway, and a fingerprint parser that
tolerates separators a human would paste in.

That is not a claim that nothing is left. A review that finds things is evidence that
reviews find things, not that the next one will come up empty. Real findings are
genuinely welcome, and the crate is better for the ones that have arrived.

What it does mean is that the obvious pass has already been run. A report that reads
like the output of a first look — a vulnerability class named in general terms, no
file, no line, no reproduction — has in all likelihood been produced and answered
already. What is useful is precisely what a general pass does not produce: a specific
claim about this code, checked against it.

## Supported versions

The latest release. Older versions get no fixes — if you are on one, the answer to a
vulnerability is to upgrade.

| Version | Supported |
|---------|-----------|
| 0.8.x   | yes       |
| < 0.8   | no        |

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's **private vulnerability reporting** on this repository — the *Report a
vulnerability* button under the Security tab. It opens a thread only you and the
maintainer can see.

If that is not available to you, email **rogerj@gmail.com** with `nettls` in the
subject line.

## What a report must contain

A report is read when it shows that someone looked at this code. That means:

- **The file and line.** Which function, in which file, at which version or commit.
- **What the code actually does there** — not what a name suggests it does.
- **Why that is wrong**, stated as a concrete consequence: what an attacker gets, or
  what guarantee fails, and under what conditions.
- **How to see it.** A reproduction, a test, or a precise sequence of calls. If it
  cannot be reproduced, say so and explain what you did observe.

A proof of concept helps but is not required. A clear description of a real flaw is
worth more than a broken exploit.

## Reports produced with AI assistance

Use whatever tools you like to find a problem. But **a person must have checked the
finding against this code before it is sent, and that person must be able to answer
questions about it.**

The reason is arithmetic, not principle. A plausible-sounding report costs minutes to
produce and hours to disprove: the file has to be read, the claim traced, the
behaviour reproduced, and the conclusion written down. A handful of unverified
reports can consume more maintainer time than every real vulnerability this crate
will ever have — and they crowd out the real ones.

So no output pasted straight from a model. A report that reads as unreviewed
generated text will be closed without analysis and without a second look. The usual
signs:

- a claim with no file and no line
- code quoted that does not exist in this repository
- a reproduction that does not run, or that tests something else
- a vulnerability class named in the abstract, with nothing tying it to this code
- confident language and no evidence

If you did use a tool, say so. That is not held against you — it is useful context,
and an honest report that names its method is treated exactly like any other. What is
held against you is sending something you have not verified yourself.

## What to expect

This is a spare-time project with a single maintainer. **There is no guaranteed
response time.** You will get an answer when there is one, and it will say which of
these it is: a fix, a documented limitation, or an explanation of why the behaviour is
not what it appears to be.

A fix will not be published without telling you first, and you will be credited unless
you ask not to be.

## Scope

This crate builds on established libraries — rustls, rcgen, x509-parser, and `krypto`
for every cryptographic primitive.

**A flaw in one of those is not this crate's to fix.** Report it to that project —
that is where a fix can be made, and where every other user of it is waiting.

**But say that it exists.** This crate is exposed to it, and that is worth knowing
even though the repair happens elsewhere: a version can be pinned, a release can be
yanked, or the documentation can say what not to rely on until it is fixed. An issue
saying *"this dependency has this problem, here is the upstream report"* is enough —
no analysis needed.

What is in scope here is how the crate uses them:

- the crypto provider selection and its fail-closed behaviour
- self-signed generation: what goes into the certificate, and what is validated
- fingerprint pinning: what is compared, and what a successful match actually proves
- the announcement protocol (§6): the signed forms, the verification order, and what
  a receipt commits its sender to
- the sealed envelope format and what it authenticates
- how private key material is held in memory and written to disk

**Not in scope:** that a chosen algorithm is not the one you would have chosen, that a
dependency has a newer version, or that a documented and deliberate limitation exists.
Those are issues, not vulnerabilities, and they are welcome as such.

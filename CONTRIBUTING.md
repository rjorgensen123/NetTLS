# Contributing

## This repository is a mirror

The work happens elsewhere, and this repository is a copy that is pushed here. Every
sync overwrites what is here.

That has a consequence worth knowing before you spend time on it: **a pull request
opened here cannot be merged, and anything committed here is overwritten at the next
sync.** That is not a judgement on the change — the mechanism has nowhere to put it.

So if you have a change, it has to arrive in a form that survives the sync. An issue
with a description, a diff, or a patch works. A pull request does not.

## What is welcome

**Bug reports.** If something does not behave as the documentation says, or a
guarantee does not hold, open an issue. These get looked at first.

**Questions about the contract.** If the API documentation is unclear or wrong about
what a function does, that is worth an issue on its own — the docs are checked against
the code by a test, but a test cannot tell whether a sentence is *true*.

**Interoperability findings.** The crate ships a Python twin of the protocol, and the
two are held to the same wire format by a cross-test. If you build a third
implementation and it disagrees with either of them, that is a finding worth having —
whichever side turns out to be wrong.

**Security findings.** Not as an issue — see [SECURITY.md](SECURITY.md), which also
says what a report must contain.

## Code and features

Neither is refused. Both are low priority.

**Code.** If you have written something, describe it in an issue and attach the diff.
It will be read. Whether it lands, and when, depends on whether it fits what the crate
is for — and on time, of which there is not much. Do not expect a quick answer, and do
not take silence as rejection.

Code is accepted only under the crate's own terms: MIT **or** Apache-2.0, at the
recipient's choice. See [Contributions](README.md#contributions) in the README for what
that means and why.

**Feature requests.** Possible, and worth asking about. But the crate offers one
canonical way of doing each thing on purpose, so a second way is not a small change: it
is a decision about what every consumer then has to agree on, and for anything that
touches the wire it is a decision two implementations have to agree on. Say what you
are trying to do rather than which function you want — the problem is easier to judge
than the solution.

## If you are filing an issue

Say which version. It is declared in `Cargo.toml`; the crate exposes it as `nettls::VERSION`
and the Python twin as `nettls.__version__`, both derived from that one declaration.

Include what someone else needs to see the same thing: the calls you made, the input
shape, and the actual output or error. A failing test is the clearest form there is.
For anything touching the wire, the bytes matter — give them as hex, the way the test
vectors do, since a trailing newline or an invisible character does not survive being
read by eye.

# SPDX-License-Identifier: MIT OR Apache-2.0
"""The ring test (SPEC-nettls §6.15) — 3 nodes, mixed implementations.

```text
A → B → C → A
```

Every node is a full party: it both receives and **performs** rotations, and
it does not know which language its neighbours are written in.

## What the test actually proves

**The marker is its own oracle.** `A` sends it to `B`, which sends it to `C`,
which sends it to `A`. If the same thing does not come back, something is
wrong — without the test needing to know *what* is right. It is the only test
in this project that cannot pass for the wrong reason.

**Four rotations per node, not three.** Rotation 3 is the first time the chain
carries without the anchor. Rotation 4 shows it does so **again** — and that
the N-2 deletion is general, not just something that went well the one time
N-2 happened to be the anchor.

**Two configurations.** With only `2×Rust + 1×Python`, `Python → Python` is
never tried, and a bug Python shares with itself would slip through — both
sides would make the same wrong choice and agree about it.

Skipped if `cargo` is missing.
"""

from __future__ import annotations

import json
import os
import random
import select
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

HER = Path(__file__).resolve().parent
ROT = HER.parent
sys.path.insert(0, str(HER))

import nettls as n  # noqa: E402

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None, reason="cargo is missing — the ring test is skipped"
)

ROTASJONER = 4


def ledig_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class NodeProsess:
    """A node as a subprocess, controlled with JSON lines on stdin."""

    def __init__(self, lang: str, name: str, port: int, neighbour_port: int, seed: bytes):
        self.lang = lang
        self.name = name
        self.port = port
        self.neighbour_port = neighbour_port
        self.seed = seed
        # The Ed25519 seed survives a restart on purpose: it is the service's
        # STABLE, operator-distributed identity (§6.6b). It is the certificate
        # lineage that rotates, not the signing key.
        self.pub = n.ed25519_public_from_seed(seed)
        args = (
            [sys.executable, str(HER / "ringnode.py")]
            if lang == "python"
            else [
                "cargo", "run", "-q", "--example", "ringnode",
                "--manifest-path", str(ROT / "Cargo.toml"), "--",
            ]
        )
        self.p = subprocess.Popen(
            args + [name, str(port), str(neighbour_port), seed.hex()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        klar = json.loads(self._les())
        assert klar.get("ready") == name, klar
        self.start_fp = klar["fp"]

    # No command may be left standing and waiting. A node that does not answer
    # must give a READABLE error, not a test that stands until someone kills it.
    #
    # That is not hypothetical: the Rust node did `.unwrap()` on the reply from
    # a neighbour, so a killed neighbour felled the control thread — and then
    # no reply was ever written to stdout. The test hung. The node is fixed,
    # but the fence stays: next time the symptom must be an error message, not
    # a silence.
    SVARFRIST_S = 60

    def _les(self) -> str:
        klar, _, _ = select.select([self.p.stdout], [], [], self.SVARFRIST_S)
        if not klar:
            raise AssertionError(
                f"{self.name} did not answer within {self.SVARFRIST_S}s — the "
                f"node is hanging or the control thread is dead.\n"
                f"stderr:\n{self._stderr_saa_langt()}"
            )
        linje = self.p.stdout.readline()
        if not linje:
            raise AssertionError(f"{self.name} died:\n{self._stderr_saa_langt()}")
        return linje

    def _stderr_saa_langt(self) -> str:
        """Read what is on stderr without blocking if the process is alive."""
        if self.p.poll() is not None:
            return self.p.stderr.read()[-3000:]
        klar, _, _ = select.select([self.p.stderr], [], [], 0.2)
        return os.read(self.p.stderr.fileno(), 3000).decode(errors="replace") if klar else "(empty)"

    def styr(self, **m) -> dict:
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()
        reply = json.loads(self._les())
        assert "error" not in reply, f"{self.name}: {reply['error']}"
        return reply

    def drep(self) -> None:
        try:
            self.p.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        self.p.terminate()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def _bygg_ring(lang: list[str]) -> list[NodeProsess]:
    """A ring of arbitrary length: node *i* talks to node *i+1*, the last to the first."""
    count = len(lang)
    porter = [ledig_port() for _ in range(count)]
    nodes = []
    for i, (s, name) in enumerate(zip(lang, "abcdefghij")):
        nodes.append(
            NodeProsess(s, name, porter[i], porter[(i + 1) % count], bytes([i + 1] * 32))
        )
    # Wait until all are listening.
    for nd in nodes:
        for _ in range(200):
            try:
                socket.create_connection(("127.0.0.1", nd.port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError(f"{nd.name} is not listening on {nd.port}")
    return nodes


def _godkjenn_alle(nodes: list[NodeProsess]) -> None:
    """The operator's one-time approval — generation 0, the anchor it all hangs on.

    Each node approves its **successor**, since that is the edge it talks on.

    The two edges are **not** the same, and they are easy to mix up:

    | Edge | Means |
    |---|---|
    | `a` approves `b` | `a` **pins** `b`'s certificate |
    | `c` acks to `a` | `c` is the one pinning `a`, so it is `c` that must say "I have stored your next" |

    **Who must ack my rotation is whoever pins me — not whoever I pin.** The
    first draft tied the receipt requirement to the wrong edge, and the result
    was every node waiting forever for a receipt that was never meant to come.
    """
    for i, nd in enumerate(nodes):
        neighbour = nodes[(i + 1) % len(nodes)]
        nd.styr(
            op="approve",
            name=neighbour.name,
            port=neighbour.port,
            ed25519_pub=neighbour.pub.hex(),
        )
        # The predecessor: the one who PINS us, and who therefore must ack OUR
        # rotation. We must also be able to verify its receipt.
        forgjenger = nodes[(i - 1) % len(nodes)]
        nd.styr(op="know_key", name=forgjenger.name, ed25519_pub=forgjenger.pub.hex())
        nd.styr(op="require_ack_from", name=forgjenger.name)


def _rull_en_node(nodes: list[NodeProsess], i: int, now: int) -> None:
    """Roll **one** node. The others stand still (§6.7).

    This is the core of the asymmetry, and the whole reason §6 looks the way
    it does: **what the peer lacks is the certificate, not a time of day.**
    No node waits for anyone else to be ready.

    Three steps, and the order is not optional:

    1. `i` announces its next certificate.
    2. **The predecessor** — the one that *pins* `i` — fetches the announcement
       and acks. Not the successor: who must ack my rotation is whoever pins
       me.
    3. `i` rolls. Without the receipt in step 2 it could not (§6.8a), and that
       is deliberate: if I roll before the peer has stored my next, *its*
       handshake fails that very moment.

    Afterwards `i` stands on a new generation while everyone else stands on
    their old one. The ring must still carry a marker all the way round.
    """
    _rull_samtidig(nodes, [i], now)


def _rull_samtidig(nodes: list[NodeProsess], indekser: list[int], now: int) -> None:
    """Roll several nodes with **overlapping** announcement windows.

    With two neighbours in the set, **both ends of one link** change at once:
    one node holds its own pending announcement *while* storing its
    neighbour's. That is a different state from two rotations back to back,
    and it does not exist if nodes are always taken one by one.

    The steps are the same as for one node, but all announce before anyone
    acks: the overlap is precisely what is being probed.
    """
    valgt = [nodes[i] for i in indekser]

    for nd in valgt:
        nd.styr(op="prepare", now=now)

    # The predecessor acks — the one that PINS the node, not the one it pins.
    for i in indekser:
        nd = nodes[i]
        nodes[(i - 1) % len(nodes)].styr(
            op="fetch_and_ack", name=nd.name, port=nd.port, now=now
        )

    for nd in valgt:
        r = nd.styr(op="roll", now=now)
        assert r["rolled"], f"{nd.name} did not roll — did the receipt not arrive?"


def _er_skjev(nodes: list[NodeProsess]) -> bool:
    """Are the nodes on **different** generations right now?

    This is the measurable form of §6.7. A ring where everyone has always
    rolled the same number of times is a ring swapping in lockstep — and then
    there is nothing asymmetric to test, however many generations pass.
    """
    tellere = {nd.styr(op="status")["rotations"] for nd in nodes}
    return len(tellere) > 1


def _samtidige_grupper(
    round_no: int, count: int, rng: random.Random
) -> list[tuple[list[int], str]]:
    """Which nodes roll AT THE SAME TIME this round, and why.

    Two distinct properties, and they require different rings:

    | Case | What it probes | Where it exists |
    |---|---|---|
    | **Neighbours** | both ends of *the same link* swap at once | all rings |
    | **Non-neighbours** | two places in the ring swap at once, without contact | only rings ≥ 4 |

    In a ring of **three**, every node neighbours both the others, so "two
    that are not near each other" does not exist there. Pretending would give
    a test claiming to probe something it did not.

    The neighbour pair is probed **in several places**: the position is drawn
    anew each round, and in rings of six or more two *disjoint* neighbour
    pairs run in the same round — i.e. simultaneous rotations in two places at
    once.

    Every node still rolls exactly once per round; the groups only decide who
    does it *together*.
    """
    if round_no == 1:
        # One neighbour pair, randomly placed.
        p = rng.randrange(count)
        return [([p, (p + 1) % count], "neighbours")]

    if round_no == 2:
        if count >= 6:
            # Two disjoint neighbour pairs. With six nodes, `p, p+1` and
            # `p+3, p+4` are guaranteed to share no link.
            p = rng.randrange(count)
            return [
                ([p, (p + 1) % count], "neighbours"),
                ([(p + 3) % count, (p + 4) % count], "neighbours"),
            ]
        # A new neighbour pair somewhere OTHER than in round 1.
        p = rng.randrange(count)
        return [([p, (p + 1) % count], "neighbours")]

    if round_no == 3 and count >= 4:
        # Two nodes that are NOT neighbours: half the ring apart, so they
        # neither share a link nor pin each other. Requires ring ≥ 4.
        p = rng.randrange(count)
        return [([p, (p + count // 2) % count], "non-neighbours")]

    # Final round: everyone one by one, as a reference.
    return []


KORPUS = json.loads((ROT / "testvectors" / "errors.json").read_text())


def _injiser_feil(nodes: list[NodeProsess], round_no: int) -> None:
    """Feed hostile announcements into a ring that is mid-flight (§6.15b).

    ## Why mid-flight, and not on an empty node

    A node that just started has little to destroy. Here the ring has already
    rolled several times, so every node holds `previous`, `current` and `next`
    at once — that is when a half-accepted message does damage.

    ## Two requirements, and the second is the important one

    1. The message must be **rejected**.
    2. The state must be **unchanged** afterwards.

    A receiver that rejects, but manages to write half the message into
    `Generations` first, has not rejected it — it has merely refrained from
    saying yes. Without requirement 2 such a bug would look green.

    ## What this does NOT probe

    Only rejection is required here — not *where*. On purpose: for a ring the
    property is "the node cannot be poisoned", and defence in depth is then a
    strength, not something to complain about.

    The level is probed elsewhere: `python/test_feil.py` and `tests/errors.rs`
    require every entry stopped at the **right** level. Turn off the
    fingerprint validation and this test still passes (`receive` catches it),
    while the corpus tests fell it. The two complement each other, and neither
    replaces the other.

    ## The whole corpus, not a random sample

    The injection point varies between configurations (`round_no` picks the
    node), so the fault hits different positions in the ring — but *which*
    messages are probed is always all of them. A random sample would make a
    failing run impossible to reproduce, and a test you cannot reproduce is a
    test you end up ignoring.
    """
    offer = nodes[round_no % len(nodes)]
    neighbour = nodes[(round_no % len(nodes) + 1) % len(nodes)]

    for post in KORPUS["announcement"]:
        reply = offer.styr(
            op="inject", name=neighbour.name, announcement=post["json"]
        )
        assert reply["rejected"], (
            f"{offer.name} ACCEPTED a hostile announcement «{post['name']}» — "
            f"should have been rejected because {post['why']}"
        )
        assert reply["unchanged"], (
            f"{offer.name} rejected «{post['name']}», but the state changed "
            f"anyway. A message that gets to write before being rejected is "
            f"not rejected."
        )


def _kjor_ring(lang: list[str], injiser_etter: int = 2) -> None:
    nodes = _bygg_ring(lang)
    try:
        _godkjenn_alle(nodes)

        # Sanity: the marker goes round BEFORE anyone has rolled. Without it
        # the rest could have "passed" against a ring that never worked.
        reply = nodes[0].styr(op="marker", marker="start", skip=len(nodes))
        assert reply["marker"] == "start", reply

        # SEEDED randomness. The order must be spread and not a→b→c, but it
        # must also be the same every time: a failing run you cannot reproduce
        # is a run you end up ignoring. The seed hangs off the configuration,
        # so the five rings get different orders.
        rng = random.Random("|".join(lang))
        count = len(nodes)

        # Proof that the ring ACTUALLY was skewed, and that the simultaneous
        # groups actually ran. Without these, "asymmetric" and "simultaneous"
        # would be claims in a comment: a planner that one day returns empty,
        # or a sweep that accidentally becomes lockstep again, would look
        # green.
        sett_skjevt = False
        kjorte: list[str] = []

        now = 0
        for round_no in range(1, ROTASJONER + 1):
            # ASYMMETRIC (§6.7): the nodes roll ONE AT A TIME, not in lockstep.
            #
            # The first version of this test let everyone announce, everyone
            # ack and everyone roll in step. Four generations were probed —
            # but at every single observation point all nodes stood on the
            # SAME generation, and then the asymmetry is not probed at all.
            # That is precisely what §6 exists for: the peer lacks the
            # *certificate*, not a time of day.
            igjen = list(range(count))
            rng.shuffle(igjen)

            # Simultaneous rotations. Every node still rolls exactly once per
            # round — a pair just does it together instead of back to back,
            # with overlapping announcement windows.
            grupper = _samtidige_grupper(round_no, count, rng)
            for gruppe, _ in grupper:
                for i in gruppe:
                    igjen.remove(i)

            for gruppe, hva in grupper:
                now += 2 * 86_400
                _rull_samtidig(nodes, gruppe, now)
                name = [nodes[i].name for i in gruppe]
                kjorte.append(hva)
                if _er_skjev(nodes):
                    sett_skjevt = True
                merke = f"round_no-{round_no}-samtidig-{hva}-{'-'.join(name)}"
                reply = nodes[0].styr(op="marker", marker=merke, skip=count)
                assert reply["marker"] == merke, (
                    f"a message was lost when {hva} {name} rolled simultaneously "
                    f"(round {round_no}): {reply}"
                )

            for i in igjen:
                now += 2 * 86_400  # past the rate limit (§6.7c)
                _rull_en_node(nodes, i, now)

                # The marker while the ring is SKEWED: `i` stands on a new
                # generation, the others on their old one. If it comes round
                # whole here, the pinning has accepted `current` + `next` and
                # promoted on observation — all of §6.7 in one round.
                if _er_skjev(nodes):
                    sett_skjevt = True

                merke = f"round_no-{round_no}-node-{nodes[i].name}"
                reply = nodes[0].styr(op="marker", marker=merke, skip=count)
                assert reply["marker"] == merke, (
                    f"the marker did not come back whole while the ring was "
                    f"skewed (round {round_no}, {nodes[i].name} just rolled): {reply}"
                )

            # Error injection mid-flight. The rounds AFTER this one are the
            # real probe: a ring that survives the attack but cannot keep
            # rotating has not survived it.
            if round_no == injiser_etter:
                _injiser_feil(nodes, round_no)
                reply = nodes[0].styr(op="marker", marker="after-attack", skip=len(nodes))
                assert reply["marker"] == "after-attack", (
                    f"the ring did not carry the marker after the error injection: {reply}"
                )

        # Was the ring ACTUALLY skewed along the way? Without this, a change
        # making the rotation symmetric again could pass unnoticed — the test
        # would stay green while ceasing to probe what it exists for.
        assert sett_skjevt, (
            "the ring never stood on different generations at once — then §6.7 "
            "(asymmetric rotation) was not probed, however many generations "
            "were run"
        )

        # And did the simultaneous groups actually run?
        assert "neighbours" in kjorte, (
            f"no NEIGHBOURS rolled simultaneously — both ends of a link never "
            f"swapped at once. Ran: {kjorte}"
        )
        if count >= 4:
            assert "non-neighbours" in kjorte, (
                f"no NON-NEIGHBOURS rolled simultaneously. Two places in the "
                f"ring should have swapped independently. Ran: {kjorte}"
            )

        # Everyone must have rolled exactly this many times.
        for nd in nodes:
            st = nd.styr(op="status")
            assert st["rotations"] == ROTASJONER, f"{nd.name}: {st}"
            assert st["fp"] != nd.start_fp, f"{nd.name} is still on its starting certificate"

        # And nobody holds the anchor as current or previous anymore: after
        # four rotations both cert0 and cert1 are out of the picture.
        for i, nd in enumerate(nodes):
            neighbour = nodes[(i + 1) % len(nodes)]
            st = nd.styr(op="status")["peers"][neighbour.name]
            assert st["current"] != neighbour.start_fp, (
                f"{nd.name} still holds {neighbour.name}'s ANCHOR as current"
            )
            assert st["previous"] != neighbour.start_fp, (
                f"{nd.name} still holds {neighbour.name}'s anchor as previous"
            )
    finally:
        for nd in nodes:
            nd.drep()


@pytest.mark.slow
def test_ring_2rust_1python():
    """A (Rust) → B (Python) → C (Rust). Covers R→P, P→R and R→R."""
    _kjor_ring(["rust", "python", "rust"])


@pytest.mark.slow
def test_ring_2python_1rust():
    """A (Python) → B (Rust) → C (Python). Covers P→R, R→P and **P→P**.

    Not a repeat of the previous one: here `Python → Python` is probed for the
    first time, and a bug Python shares with itself would have slipped through
    without it.
    """
    _kjor_ring(["python", "rust", "python"], injiser_etter=1)


# ── Pure rings: does each implementation do the job ALONE? ────────────────── #
#
# The mixed rings above can hide something: if one side is lenient somewhere,
# the other may end up carrying it. A pure ring has no such help — every
# message is produced and consumed by the same implementation, and everything
# it does wrong it must live with itself.


@pytest.mark.slow
def test_ring_3rust():
    """Pure Rust ring. R→R on every edge, no Python anywhere near."""
    _kjor_ring(["rust", "rust", "rust"])


@pytest.mark.slow
def test_ring_3python():
    """Pure Python ring. P→P on every edge.

    The strictest probe that the Python side is a full implementation and not
    just something that works as long as a Rust node stands next to it
    correcting the form.
    """
    _kjor_ring(["python", "python", "python"], injiser_etter=3)


@pytest.mark.slow
def test_ring_6_alle_naboskap():
    """Six nodes, `3×Python + 3×Rust`, ordered so ALL neighbourhoods occur.

    ```text
    a(P) → b(P) → c(R) → d(R) → e(P) → f(R) → a(P)
    ```

    | Pattern | Where | What it probes |
    |---|---|---|
    | `P→P` | a→b | Python alone |
    | `R→R` | c→d | Rust alone |
    | `R→P→R` | d→e→f | a Python node **between two Rust** |
    | `P→R→P` | e→f→a | a Rust node **between two Python** |

    The last two are the point, and they exist in no ring of three. A node
    surrounded by the other implementation must receive from one and pass on
    to the other in the same round — and then being *compatible* is not
    enough; it must be **identical** in behaviour. That is exactly where a
    small difference in validation, or in what is stored when, becomes
    visible.
    """
    _kjor_ring(["python", "python", "rust", "rust", "python", "rust"], injiser_etter=2)


# ── Restart and resumption (§6.8) ─────────────────────────────────────────── #
#
# Roger: "if we introduce a fault, we restart exactly that node — we fix the
# fault, then communication must pick up again and work correctly."
#
# That is not a robustness detail, it is the designed way out. §6.8 separates
# two kinds of deviation, and they have different cures:
#
# | Deviation | Cure |
# |---|---|
# | **Liveness** — the peer does not answer | retries, alarm after 12 h, 20+ days of margin |
# | **Identity** — the peer is someone else | stop NOW, fall to mode 1, never an automatic retry |
#
# A node that restarts comes up with a NEW certificate. For the neighbour
# pinning it, that is by definition an identity deviation — and it should be.
# The way out is not that the ring "figures it out itself"; that would be a
# ring where anyone could become anyone by restarting. The way out is that
# **the operator pins anew** — exactly the same action as generation 0.
#
# The Ed25519 identity, by contrast, survives the restart. It is
# operator-distributed and stable; it is the certificate lineage that
# rotates.


def _restart(nodes: list[NodeProsess], i: int) -> NodeProsess:
    """Kill node `i` and start it anew on the same port, with the same Ed25519 seed."""
    old_node = nodes[i]
    old_node.drep()
    ny = NodeProsess(
        old_node.lang, old_node.name, old_node.port, old_node.neighbour_port, old_node.seed
    )
    nodes[i] = ny
    return ny


def _pin_paa_nytt(nodes: list[NodeProsess], i: int) -> None:
    """The operator's action after a restart — generation 0 all over again.

    Both edges must be set up anew, and it is easy to do it halfway:

    - the **restarted** node has forgotten everything and must pin its
      successor again, and know who must ack its rotations;
    - **the predecessor** must pin the NEW certificate. Without this it is
      left with a fingerprint that no longer exists.
    """
    ny = nodes[i]
    etterfolger = nodes[(i + 1) % len(nodes)]
    forgjenger = nodes[(i - 1) % len(nodes)]

    ny.styr(op="approve", name=etterfolger.name, port=etterfolger.port,
            ed25519_pub=etterfolger.pub.hex())
    ny.styr(op="know_key", name=forgjenger.name, ed25519_pub=forgjenger.pub.hex())
    ny.styr(op="require_ack_from", name=forgjenger.name)

    forgjenger.styr(op="approve", name=ny.name, port=ny.port,
                    ed25519_pub=ny.pub.hex())


@pytest.mark.slow
@pytest.mark.parametrize(
    "lang",
    [
        pytest.param(["rust", "python", "rust"], id="2rust_1python"),
        pytest.param(["python", "rust", "python"], id="2python_1rust"),
        pytest.param(["python", "python", "rust", "rust", "python", "rust"], id="ring6"),
    ],
)
def test_restart_resumes_communication(lang):
    """Ring in flight → one node dies → restart + new pinning → full rotation again.

    The test has four parts, and the third is what makes the others worth
    anything:

    1. The ring rotates normally, asymmetrically.
    2. One node is killed.
    3. **The ring is ACTUALLY broken** — the marker does not come round.
       Without this part, everything below could have passed against a ring
       that never noticed the node was gone, and the "resumption" would have
       proven nothing.
    4. The node is restarted, the operator pins anew, and the ring picks up —
       including **a new full rotation all the way round**. The marker going
       is not enough; the ring must be able to keep rotating afterwards.
    """
    nodes = _bygg_ring(lang)
    count = len(nodes)
    try:
        _godkjenn_alle(nodes)
        now = 0

        # 1. Normal, asymmetric operation first.
        for i in range(count):
            now += 2 * 86_400
            _rull_en_node(nodes, i, now)
        reply = nodes[0].styr(op="marker", marker="before", skip=count)
        assert reply["marker"] == "before", reply

        # 2. Kill a node that is not the sender of the marker.
        offer_i = 1
        offer_navn = nodes[offer_i].name
        nodes[offer_i].drep()

        # 3. The ring MUST be broken now.
        try:
            nodes[0].styr(op="marker", marker="during-break", skip=count)
        except AssertionError:
            pass  # expected: the neighbour does not answer
        else:
            raise AssertionError(
                f"the marker went round even though {offer_navn} was killed — "
                f"then the test does not measure what it thinks, and the "
                f"resumption below proves nothing"
            )

        # 4. Restart + the operator's new pinning.
        _restart(nodes, offer_i)
        ny_fp = nodes[offer_i].start_fp
        _pin_paa_nytt(nodes, offer_i)

        reply = nodes[0].styr(op="marker", marker="after", skip=count)
        assert reply["marker"] == "after", (
            f"communication did not pick up again after {offer_navn} "
            f"was restarted and pinned anew: {reply}"
        )

        # The restarted node stands on a NEW certificate, and the predecessor
        # pins exactly that.
        forgjenger = nodes[(offer_i - 1) % count]
        st = forgjenger.styr(op="status")["peers"][offer_navn]
        assert st["current"] == ny_fp, (
            f"{forgjenger.name} does not pin {offer_navn}'s new certificate: {st}"
        )

        # Rotation AFTER the restart is probed separately — see
        # `test_rotation_after_restart_is_blocked` below. That is an open
        # design decision, not a fault in this test.
    finally:
        for nd in nodes:
            nd.drep()


@pytest.mark.slow
def test_rotation_after_restart_resumes():
    """A8 (decided by Roger 2026-08-14): the pair rotates again after a
    restart-with-loss + re-anchoring.

    The receiver's state governs fully: holding only an anchor, it verifies
    `sig_curr` against the anchor and accepts — exactly as at generation 0→1.
    Generation numbering is local to the receiver; the operator's approval is
    the *previous* of a chain with no previous. Security equals bootstrap, an
    attacker cannot induce the anchor-only state, and a replayed old
    announcement fails the curr-vs-anchor check.

    (This was a strict xfail documenting the open decision; it flipped to
    "unexpectedly green" the moment the rule changed — as designed — and was
    rewritten to the positive form you are reading.)
    """
    lang = ["rust", "python", "rust"]
    nodes = _bygg_ring(lang)
    count = len(nodes)
    try:
        _godkjenn_alle(nodes)
        now = 0
        for i in range(count):
            now += 2 * 86_400
            _rull_en_node(nodes, i, now)

        nodes[1].drep()
        _restart(nodes, 1)
        _pin_paa_nytt(nodes, 1)

        # One more full round — the ring must keep rotating (A8).
        for i in range(count):
            now += 2 * 86_400
            _rull_en_node(nodes, i, now)
        merke = "after-reanchor"
        reply = nodes[0].styr(op="marker", marker=merke, skip=count)
        assert reply["marker"] == merke, (
            f"the ring could not carry the marker after re-anchoring: {reply}"
        )
    finally:
        for nd in nodes:
            nd.drep()


# ── The reach of a fault (§6.8) ───────────────────────────────────────────── #
#
# Roger: "a fault on one node affects only that node, plus the neighbours it
# has, i.e. at minimum a pair. No other node in a system knows anything about
# the state of anyone but its own neighbours."
#
# That is an invariant, not a hope — and it is the real reason §6 has no
# global state, no gossip and no coordinator. Knowledge is strictly local:
# every node knows its own neighbours and nothing else. Therefore a fault
# CANNOT propagate further than the pair it hits.
#
# An invariant no test enforces is an invariant that can quietly vanish the
# day someone adds a "little" piece of shared state.


def _lokal_probe(nodes: list[NodeProsess], i: int, merke: str) -> None:
    """One hop: node `i` → its successor and back.

    `skip=0` means the neighbour replies at once instead of passing it on.
    Then we measure exactly ONE link — the marker round the whole ring would
    break on any death at all and thus could not tell "this link is down"
    from "some link or other is down".
    """
    reply = nodes[i].styr(op="marker", marker=merke, skip=0)
    assert reply["marker"] == merke, f"the link {nodes[i].name}→successor is down: {reply}"


@pytest.mark.slow
def test_fault_affects_only_the_neighbour_pair():
    """Kill one node in the ring of six — the rest must not notice.

    ```text
    a(P) → b(P) → c(R) → d(R) → e(P) → f(R) → a(P)
                   ✗ drept
    ```

    | Node | Affected? | Why |
    |---|---|---|
    | `b` | **yes** | pins `c`, which is gone |
    | `d` | **yes** | `c` is its pinner, so `d` gets no receipt and cannot rotate |
    | `e`, `f`, `a` | no | `c` is not their neighbour, and they do not know it exists |

    The probe that matters is that `e` must be able to **rotate fully** while
    `c` lies dead. Not just talk — rotate: announce, get the receipt from `d`
    and swap certificates. If it manages that, the fault has demonstrably not
    crossed the pair.
    """
    lang = ["python", "python", "rust", "rust", "python", "rust"]
    nodes = _bygg_ring(lang)
    try:
        _godkjenn_alle(nodes)
        now = 0

        # Normal operation first, otherwise we do not know the ring worked.
        for i in range(len(nodes)):
            now += 2 * 86_400
            _rull_en_node(nodes, i, now)
        reply = nodes[0].styr(op="marker", marker="before", skip=len(nodes))
        assert reply["marker"] == "before", reply

        doed = 2  # c
        doed_navn = nodes[doed].name
        nodes[doed].drep()

        # The neighbour that PINS the dead one must notice. Without this part,
        # everything below could have passed against a "dead" node that was
        # actually alive.
        try:
            _lokal_probe(nodes, doed - 1, "towards-dead")
        except AssertionError:
            pass
        else:
            raise AssertionError(
                f"{nodes[doed - 1].name} reached {doed_navn} even though it was "
                f"killed — then the test does not measure what it thinks"
            )

        # Those who are NOT neighbours must not notice. `e→f` and `f→a` lie on
        # the opposite side of the ring from the death.
        for i in (4, 5):
            _lokal_probe(nodes, i, f"untouched-{nodes[i].name}")

        # And the real proof: `e` must be able to ROTATE fully, with `d`
        # acking, while `c` lies dead.
        for round_no in range(2):
            now += 2 * 86_400
            _rull_en_node(nodes, 4, now)
            _lokal_probe(nodes, 4, f"after-rotation-{round_no}")

        # One rotation in the normal round above, plus two while `c` lay dead.
        st = nodes[4].styr(op="status")
        assert st["rotations"] == 3, (
            f"e did not keep rotating while {doed_navn} was dead: {st}"
        )

        # `d`, by contrast, must NOT be able to rotate: its pinner is the dead
        # node, and without a receipt nobody rolls (§6.8a). That is the
        # liveness path — it waits, it does not fail hard.
        now += 2 * 86_400
        nodes[3].styr(op="prepare", now=now)
        r = nodes[3].styr(op="roll", now=now)
        assert not r["rolled"], (
            f"{nodes[3].name} rolled WITHOUT a receipt from its dead pinner "
            f"{doed_navn} — then §6.8a is broken, and a node can swap "
            f"certificates without the peer having stored it"
        )
    finally:
        for nd in nodes:
            nd.drep()


@pytest.mark.slow
@pytest.mark.parametrize(
    "lang,offer_i",
    [
        pytest.param(["python", "python", "python"], 1, id="3python_offer_python"),
        pytest.param(["rust", "rust", "rust"], 1, id="3rust_offer_rust"),
        pytest.param(["rust", "python", "rust"], 1, id="blandet_offer_python"),
        pytest.param(["python", "rust", "python"], 1, id="blandet_offer_rust"),
    ],
)
def test_restart_with_state_requires_no_operator(lang, offer_i):
    """The core of §6.8: a restart WITH state intact is not a deviation.

    Differs from `test_restart_resumes_communication` in the one thing that
    matters: there the node lost everything, and then the operator MUST pin
    anew. Here the consumer remembers — and then nothing may require a human.

    Runs in four configurations, and the last two are the point: a **mixed**
    ring where the victim is Python and Rust respectively. The recovery must
    work the same whichever implementation restarted, and whichever stands on
    either side of it.

    The order in the test mirrors the one in production:

    1. The ring rotates normally, asymmetrically.
    2. The node **exports** its state — what service would have had in Postgres.
    3. The node is killed, and the ring is demonstrably broken.
    4. A new process, the state is **imported**. No new pinning, no operator.
    5. The same certificate as before — the neighbour's pin still holds.
    6. The ring keeps rotating.

    Point 5 is what separates this from memory loss: if the node comes up
    with a NEW certificate, that is by definition an identity deviation at the
    neighbour.
    """
    nodes = _bygg_ring(lang)
    count = len(nodes)
    try:
        _godkjenn_alle(nodes)
        now = 0
        for i in range(count):
            now += 2 * 86_400
            _rull_en_node(nodes, i, now)
            # The marker MUST go here. Promotion happens on observation (§6.7),
            # so without a connection after each rotation the peer's
            # `previous` stays empty — and then we export a state with nothing
            # to restore. The test would pass whatever `import` did, and prove
            # nothing.
            nodes[0].styr(op="marker", marker=f"up-{i}", skip=count)

        # Control: is `previous` actually filled? If not, the rest of the test
        # does not probe the recovery at all.
        for i, nd in enumerate(nodes):
            neighbour = nodes[(i + 1) % count]
            st = nd.styr(op="status")["peers"][neighbour.name]
            assert st["previous"] is not None, (
                f"{nd.name} has no «previous» for {neighbour.name} — promotion has "
                f"not happened, and then there is nothing to restore"
            )

        offer = nodes[offer_i]
        offer_navn = offer.name
        fp_foer = offer.styr(op="status")["fp"]

        # 2. The consumer's memory.
        state = offer.styr(op="export")["state"]

        # 3. Dead node → the ring must be broken.
        offer.drep()
        try:
            nodes[0].styr(op="marker", marker="break", skip=count)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"the marker went round even though {offer_navn} was killed")

        # 4. A new process + imported state. NO operator action.
        _restart(nodes, offer_i)
        nodes[offer_i].styr(op="import", state=state)

        # 5. The same certificate as before — otherwise it is an identity deviation.
        fp_etter = nodes[offer_i].styr(op="status")["fp"]
        assert fp_etter == fp_foer, (
            f"{offer_navn} came up with a DIFFERENT certificate after the "
            f"restart ({fp_foer[:16]}… → {fp_etter[:16]}…). Then it has not "
            f"restored its identity, and the neighbour's pin is invalid"
        )

        reply = nodes[0].styr(op="marker", marker="after", skip=count)
        assert reply["marker"] == "after", (
            f"communication did not pick up again after {offer_navn} "
            f"restarted with its state intact: {reply}"
        )

        # 6. And the ring must be able to KEEP ROTATING — this is where memory
        #    loss would have stopped us, because the peer signs with prev+curr.
        for round_no in range(2):
            for i in range(count):
                now += 2 * 86_400
                _rull_en_node(nodes, i, now)
                merke = f"after-restart-{round_no}-{nodes[i].name}"
                reply = nodes[0].styr(op="marker", marker=merke, skip=count)
                assert reply["marker"] == merke, (
                    f"the ring could not keep rotating after the restart "
                    f"({nodes[i].name}): {reply}"
                )
    finally:
        for nd in nodes:
            nd.drep()

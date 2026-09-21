# SPDX-License-Identifier: MIT OR Apache-2.0
"""En ring-node i Python (SPEC-nettls §6.15).

Run as a subprocess of the ring test. The node is a **full party**: it both
receives and *performs* rotations, and it talks to neighbours whose
implementation language it does not know.

## The protocol between the nodes

One JSON line in, one JSON line out, over TLS. Deliberately minimal — the more
the node does, the greater the chance the test proves something about the node
instead of about the contract.

| `op` | Meaning |
|---|---|
| `identity` | What I present now, and a pending announcement if I have one |
| `ack` | "I have stored your next certificate" |
| `marker` | Pass the marker on around the ring |
| `stop` | Shut down |

## The marker

`A` sends the marker to `B`, which passes it to `C`, which sends it to `A`.
The skip counter makes it stop after a full round. **If the same thing does
not come back, something is wrong** — without the test needing to know *what*
is right.

Run:  python3 ringnode.py <name> <port> <neighbour-port> <ed25519-seed-hex>
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nettls as n  # noqa: E402


class Node:
    def __init__(self, name: str, port: int, neighbour_port: int, seed: bytes) -> None:
        self.name = name
        self.port = port
        self.neighbour_port = neighbour_port
        # The successor's name. Without it the marker path cannot PIN —
        # it would fall back to an unverified context.
        self.neighbour_name: str | None = None
        self.seed = seed
        self.lock = threading.Lock()

        # Our own identity.
        cert, key = n.self_signed(name, ["localhost", "127.0.0.1"], days=30)
        self.fp = n.fingerprint_from_pem(cert)
        self.cert, self.key = cert, key

        # Motpartene vi kjenner: name → Generations. Fylles av oppsettet.
        self.peers: dict[str, n.Generations] = {}
        # Their Ed25519 keys, for verifying receipts.
        self.peer_keys: dict[str, bytes] = {}

        self.announcer = n.Announcer(
            name,
            (name, ["localhost", "127.0.0.1"]),
            (self.fp, cert, key),
            n.Schedule([], 0),
            self._switch_to,
        )
        self.rolls = 0
        self._stop_flag = threading.Event()
        # The node's "database". `nettls.py` stores nothing itself (§6.11b),
        # so the consumer must remember — here the consumer is this node.
        self._stored: dict | None = None

    # -- serversiden -------------------------------------------------------- #

    def store(self, state: dict) -> None:
        """Konsumentens lagring (§6.11b). Her: en dict; i service: Postgres.

        `nettls.py` calls this **before** an announcement is returned, so the
        M-26 ordering is enforced by the call and not by someone remembering
        it.
        """
        self._stored = state

    def _switch_to(self, cert: str, key: str) -> None:
        """Callback from `Announcer`. The node knows **when**, not how."""
        with self.lock:
            self.cert, self.key = cert, key
            self.fp = n.fingerprint_from_pem(cert)
            self.rolls += 1
        # After a switch the state is different — store it. Generation N-2
        # vanishes here (M-29), and what is written contains exactly two keys
        # plus an optional pending.
        self._stored = self.announcer.state()

    def _server_ctx(self) -> ssl.SSLContext:
        """Ny kontekst per forbindelse — leser det **levende** sertifikatet.

        A cached context would serve the old one after a rotation — exactly
        the divergence between "what we advertise" and "what we present".
        """
        import tempfile

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.lock:
            pem = self.cert + self.key
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            sti = f.name
        try:
            ctx.load_cert_chain(sti)
        finally:
            Path(sti).unlink(missing_ok=True)
        return ctx

    def kjor(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(16)
        srv.settimeout(0.3)
        print(json.dumps({"ready": self.name, "fp": self.fp}), flush=True)
        while not self._stop_flag.is_set():
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._betjen, args=(sock,), daemon=True).start()
        srv.close()

    def _betjen(self, sock: socket.socket) -> None:
        try:
            with self._server_ctx().wrap_socket(sock, server_side=True) as s:
                data = b""
                while not data.endswith(b"\n"):
                    b = s.recv(65536)
                    if not b:
                        return
                    data += b
                reply = self._handle(json.loads(data.decode()))
                s.sendall((json.dumps(reply) + "\n").encode())
                # **close_notify.** Without it the peer sees a truncated stream,
                # and a strict TLS implementation (rustls) reports an error instead
                # to assume it went well. Closing without it is not "slightly
                # untidy" — it is being unable to tell a finished conversation
                # from
                # en avbrutt.
                try:
                    s.unwrap()
                except OSError:
                    pass
        except Exception as e:  # noqa: BLE001
            try:
                sock.close()
            except OSError:
                pass
            # **stderr, never stdout.** stdout is the control channel, and one
            # line there has one meaning: the reply to the previous command. If
            # we write diagnostics there, it is read as a reply — and then
            # something entirely different fails than what went wrong. (The
            # first draft did exactly that: a handshake failure from a startup
            # probe was read as the reply to
            # "approve".)
            print(f"[{self.name}] {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    def _handle(self, m: dict) -> dict:
        op = m.get("op")
        if op == "identity":
            with self.lock:
                cert, fp = self.cert, self.fp
            k = self.announcer.pending
            return n.identity_json(
                fingerprint=f"sha256:{fp}",
                cert_pem=cert,
                mode=n.Mode.ROLLING,
                sent_at=int(time.time()),
                announcement=k,
            )
        if op == "ack":
            kv = n.Receipt.from_json(m["receipt"])
            if kv.acker not in self.peer_keys:
                # A receipt from someone we hold no pinned key for can
                # not be verified — and then it is not a receipt.
                return {
                    "error": f"unknown acker \"{kv.acker}\" — no pinned "
                    f"Ed25519 key. Known: {sorted(self.peer_keys)}"
                }
            pk = self.peer_keys[kv.acker]
            # Verified against the PINNED key and against what we actually
            # announced — a genuine receipt for a different rotation is a
            # replay and must not make us roll.
            pending = self.announcer.pending
            kv.verify(pk, pending.new_fp if pending else kv.new_fp)
            self.announcer.acked(kv.acker)
            return {"ok": True}
        if op == "marker":
            return self._markor(m)
        if op == "stop":
            self._stop_flag.set()
            return {"ok": True}
        return {"error": f"unknown op: {op}"}

    def _markor(self, m: dict) -> dict:
        skip = int(m["skip"])
        if skip <= 0:
            return {"marker": m["marker"]}
        # **Pinned, like all other traffic.** Without `neighbour` here the marker fell
        # tilbake til en uverifisert kontekst — den beviste da konnektivitet,
        # not pinning, and promotion never happened on this path.
        reply = self.talk(
            self.neighbour_port,
            {"op": "marker", "marker": m["marker"], "skip": skip - 1},
            neighbour=self.neighbour_name,
        )
        return {"marker": reply["marker"]}

    # -- klientsiden -------------------------------------------------------- #

    def talk(self, port: int, message: dict, neighbour: str | None = None) -> dict:
        """One request to a neighbour, over **pinned** TLS.

        If the neighbour is known, `current` + `next` are pinned (§6.3) — and
        then a swap is accepted the moment the peer makes it, without us having
        been told when. If it is unknown (the setup phase), nothing is
        verified: the certificate
        er public, og tilliten etableres i next steg.
        """
        if neighbour and neighbour in self.peers:
            g = self.peers[neighbour]
            ctx = n.pinned_ssl_context([x.pem for x in g.accepted_in_handshake()])
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection(("127.0.0.1", port), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                # Observasjonen ER promoteringen (§6.7).
                if neighbour and neighbour in self.peers:
                    fp = n.fingerprint_from_der(s.getpeercert(binary_form=True))
                    self.peers[neighbour].observed(fp)
                s.sendall((json.dumps(message) + "\n").encode())
                data = b""
                while not data.endswith(b"\n"):
                    b = s.recv(65536)
                    if not b:
                        break
                    data += b
                try:
                    s.unwrap()
                except OSError:
                    pass
        return json.loads(data.decode())


def main() -> None:
    name, port, neighbour_port, froe_hex = sys.argv[1:5]
    node = Node(name, int(port), int(neighbour_port), bytes.fromhex(froe_hex))

    # Styres via stdin: én JSON-kommando per linje fra orkestratoren.
    def styring() -> None:
        for linje in sys.stdin:
            linje = linje.strip()
            if not linje:
                continue
            m = json.loads(linje)
            try:
                print(json.dumps(_styr(node, m)), flush=True)
            except Exception as e:  # noqa: BLE001
                # Here it IS a reply to a command, so it MUST go to stdout.
                print(json.dumps({"error": f"{type(e).__name__}: {e}"}), flush=True)

    threading.Thread(target=styring, daemon=True).start()
    node.kjor()


def _styr(node: Node, m: dict) -> dict:
    op = m["op"]
    if op == "approve":
        # The operator's approval: generation 0 (§6.4).
        reply = node.talk(int(m["port"]), {"op": "identity"})
        g = n.Generation.from_pem(reply["cert_pem"])
        node.peers[m["name"]] = n.Generations(g)
        if int(m["port"]) == node.neighbour_port:
            node.neighbour_name = m["name"]
        node.peer_keys[m["name"]] = bytes.fromhex(m["ed25519_pub"])
        return {"ok": True, "fp": g.fp}
    if op == "require_ack_from":
        # Who must ack MY rotation is whoever **pins me** — not whoever I pin.
        # The two edges differ, and mixing them makes you wait forever for a
        # receipt that was never meant to come.
        node.announcer.schedule.add_peer(m["name"])
        return {"ok": True}
    if op == "know_key":
        # Only the pinned Ed25519 key — no trust in a certificate.
        node.peer_keys[m["name"]] = bytes.fromhex(m["ed25519_pub"])
        return {"ok": True}
    if op == "prepare":
        # M-26: the state is saved BEFORE the announcement exists. If the save
        # fails, there is no announcement — and then we have not promised away
        # a key we cannot keep.
        k = node.announcer.prepare(int(m["now"]), node.store)
        return {"ok": True, "new_fp": k.new_fp}
    if op == "fetch_and_ack":
        # Fetch the neighbour's identity, store any announcement, and ack.
        name, port = m["name"], int(m["port"])
        reply = node.talk(port, {"op": "identity"}, neighbour=name)
        if not reply.get("announcement"):
            return {"ok": True, "no_announcement": True}
        k = n.Announcement.from_json(reply["announcement"])
        node.peers[name].receive(k)
        kv = n.Receipt.new(node.name, name, k.new_fp, int(m["now"]), node.seed)
        node.talk(port, {"op": "ack", "receipt": kv.to_json()}, neighbour=name)
        return {"ok": True, "acked_on": k.new_fp}
    if op == "roll":
        gammelt = node.announcer.roll_if_ready(int(m["now"]))
        return {"ok": True, "rolled": gammelt is not None, "old": gammelt}
    if op == "inject":
        # A hostile announcement fed straight into the receive path (§6.15b).
        #
        # Two things must hold, and the second is the important one: the
        # message must be rejected, AND the state must be unchanged afterwards.
        # A receiver that rejects, but manages to write half the message into
        # `Generations` first, has not rejected it — it has merely refrained
        # from saying yes.
        name = m["name"]

        def state():
            g = node.peers.get(name)
            if g is None:
                return None
            return (
                g.current.fp,
                g.previous.fp if g.previous else None,
                g.next.fp if g.next else None,
            )

        before = state()
        error_text = None
        try:
            k = n.Announcement.from_json(m["announcement"])
            node.peers[name].receive(k)
        except n.NettlsError as e:
            error_text = str(e)
        except Exception as e:  # noqa: BLE001
            # A foreign exception type is also an error we want to know about:
            # whoever
            # kaller oss fanger NettlsError og ingenting annet.
            error_text = f"{type(e).__name__}: {e}"
        return {
            "ok": True,
            "rejected": error_text is not None,
            # NOT "error": the control channel reads that field as a
            # protocol failure. Here a rejection is exactly what should happen.
            "rejected_reason": error_text,
            "unchanged": before == state(),
        }
    if op == "export":
        # The consumer's MEMORY (§6.8, §6.11b). `nettls.py` stores nothing itself
        # — the service remembers. Here the service is this node, and the
        # "database" is a dict; a real consumer would use its own store.
        #
        # Our own identity comes from `Announcer.state()` and not from
        # the node's own fields: then there is ONE place defining what must
        # lagres, og en ny ting der blir automatisk med hit.
        return {
            "ok": True,
            "state": {
                "announcer": node.announcer.state(),
                "rotations": node.rolls,
                "peers": {
                    name: {
                        "previous": g.previous.pem if g.previous else None,
                        "current": g.current.pem,
                        "next": g.next.pem if g.next else None,
                    }
                    for name, g in node.peers.items()
                },
                "keys": {k: v.hex() for k, v in node.peer_keys.items()},
            },
        }
    if op == "import":
        t = m["state"]

        # 1. Our own identity — including any PENDING key pair. Without it a
        #    restart between announcement and swap would lose a key the peer
        #    has already acked (M-26).
        node.announcer = n.Announcer.restore(t["announcer"], node._switch_to)
        node.cert = node.announcer.current[1]
        node.key = node.announcer.current[2]
        node.fp = node.announcer.current[0]
        node.rolls = t["rotations"]

        # 2. What the peer has told us. Without `restore` we could only
        #    set an anchor, and then the restart looked like memory loss: the
        #    peer's next announcement states a `previous` we do not know,
        #    og §6.3 avviser den — med rette.
        node.peers = {
            name: n.Generations.restore(
                n.Generation.from_pem(d["previous"]) if d["previous"] else None,
                n.Generation.from_pem(d["current"]),
                n.Generation.from_pem(d["next"]) if d["next"] else None,
            )
            for name, d in t["peers"].items()
        }
        node.peer_keys = {k: bytes.fromhex(v) for k, v in t["keys"].items()}
        return {"ok": True, "fp": node.fp}
    if op == "marker":
        reply = node.talk(
            node.neighbour_port,
            {"op": "marker", "marker": m["marker"], "skip": int(m["skip"])},
        )
        return {"ok": True, "marker": reply["marker"]}
    if op == "status":
        return {
            "ok": True,
            "fp": node.fp,
            "rotations": node.rolls,
            "peers": {
                k: {
                    "current": v.current.fp,
                    "previous": v.previous.fp if v.previous else None,
                    "next": v.next.fp if v.next else None,
                }
                for k, v in node.peers.items()
            },
        }
    if op == "stop":
        node._stop_flag.set()
        return {"ok": True}
    return {"error": f"unknown control op: {op}"}


if __name__ == "__main__":
    main()

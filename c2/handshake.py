"""THE VOID — C2 session handshake (ECDH + HMAC, replay-aware).

Session establishment between a C2 daemon and a beacon/implant, built on
the existing :class:`core.crypto.Crypto` primitives (P-256 ECDH key
agreement, AES-256-GCM sealing, HMAC-SHA256 auth).

Protocol (all messages JSON dicts — transport-agnostic):

    client → HELLO   {v, client_id, eph_pub, nonce_c, ts}
    server → REPLY   {v, eph_pub_s, nonce_s, ts, mac_s}
                     mac_s = HMAC(k_auth, "void-c2-hs1" | client_id |
                                  eph_pub_c | nonce_c | eph_pub_s | nonce_s)
    client → CONFIRM {mac_c}
                     mac_c = HMAC(k_auth, "void-c2-hs2" | nonce_s)

Threat model / guarantees (lab C2, pragmatic — no security theater):

* Ephemeral P-256 ECDH per session → forward secrecy for session traffic.
* Both MACs are keyed on k_auth, derived from the ECDH shared secret via
  HKDF-style HMAC expansion plus the transcript nonces. A pure MITM relaying
  two handshakes derives different secrets on each leg and cannot forge
  either MAC (transcript includes both ephemeral public keys and nonces).
* Replay: every nonce is single-use (tracked per peer with a bounded cache)
  and timestamps must fall inside a freshness window. A replayed HELLO or
  REPLY is rejected before any session key is derived.

Key material never appears in repr, logs, or WarLog evidence — only
non-secret identifiers (client id, peer key fingerprint, nonce hashes).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from core.crypto import Crypto

logger = logging.getLogger("void.c2.handshake")

HANDSHAKE_VERSION = 1

# MAC contexts (domain separation so confirm/final tags are not interchangeable).
_CTX_HELLO = b"void-c2-hs1"
_CTX_CONFIRM = b"void-c2-hs2"

# Freshness window for handshake timestamps (seconds).
DEFAULT_MAX_SKEW = 30.0

# Bounded replay cache size per peer.
MAX_NONCE_CACHE = 256


class HandshakeError(Exception):
    """Raised for any malformed, stale, or replayed handshake message."""


def _hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    """Minimal HKDF-style expansion (HMAC-SHA256 extract+expand)."""
    prk = hmac.new(secret, info, hashlib.sha256).digest()
    out = b""
    block = b""
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([len(out) // 32 + 1]), hashlib.sha256).digest()
        out += block
    return out[:length]


def _derive_session_material(shared_secret: bytes, nonce_c: str, nonce_s: str) -> tuple:
    """Derive (k_auth, k_session) from the ECDH secret + both nonces."""
    transcript = f"{nonce_c}|{nonce_s}".encode()
    k_auth = _hkdf_expand(shared_secret, b"void-c2-auth" + transcript, 32)
    k_session = _hkdf_expand(shared_secret, b"void-c2-session" + transcript, 32)
    return k_auth, k_session


def _key_fingerprint(public_key_b64: str) -> str:
    """Non-secret fingerprint of a public key (safe to log/evidence)."""
    return hashlib.sha256(public_key_b64.encode()).hexdigest()[:16]


@dataclass
class Session:
    """An established C2 session: peer identity + symmetric session crypto."""

    client_id: str
    crypto: Crypto
    peer_key_fingerprint: str
    established_at: float = field(default_factory=time.time)
    rotated: int = 0

    def seal(self, plaintext: str) -> str:
        return self.crypto.encrypt(plaintext)

    def open(self, blob: str) -> str:
        return self.crypto.decrypt(blob)

    def seal_json(self, data: Dict[str, Any]) -> str:
        return self.crypto.encrypt_json(data)

    def open_json(self, blob: str) -> Dict[str, Any]:
        return self.crypto.decrypt_json(blob)

    def rotate(self) -> bytes:
        """Rotate the session key deterministically (key material is never logged).

        Both peers derive the same next key from the current key and the
        rotation counter, so the channel stays usable after rotation.
        """
        self.rotated += 1
        return self.crypto.advance_key(
            b"void-c2-rotate" + self.rotated.to_bytes(4, "big")
        )

    def evidence(self) -> Dict[str, Any]:
        """Non-secret session descriptor for WarLog/Boneyard evidence."""
        return {
            "client_id": self.client_id,
            "peer_key_fingerprint": self.peer_key_fingerprint,
            "established_at": self.established_at,
            "rotations": self.rotated,
            "algorithm": "ECDH-P256+HKDF+AES-256-GCM",
        }


class _ReplayCache:
    """Bounded per-peer nonce cache with freshness window checks."""

    def __init__(self, max_skew: float = DEFAULT_MAX_SKEW):
        self.max_skew = max_skew
        self._seen: Set[str] = set()
        self._order: list = []

    def check_and_add(self, nonce: str, ts: float, peer: str) -> None:
        now = time.time()
        if abs(now - ts) > self.max_skew:
            raise HandshakeError(
                f"stale handshake timestamp from {peer} "
                f"(skew {abs(now - ts):.1f}s > {self.max_skew}s)"
            )
        if nonce in self._seen:
            raise HandshakeError(f"replayed handshake nonce from {peer}")
        self._seen.add(nonce)
        self._order.append(nonce)
        while len(self._order) > MAX_NONCE_CACHE:
            self._seen.discard(self._order.pop(0))


class HandshakeServer:
    """Daemon side of the handshake. One instance per C2Daemon.

    Stateless ECDH keypair generated at construction; per-peer replay
    tracking is bounded and cheap.
    """

    def __init__(self, crypto: Optional[Crypto] = None, max_skew: float = DEFAULT_MAX_SKEW):
        self.crypto = crypto or Crypto()
        self._eph = self.crypto.generate_key_exchange()
        self._replay = _ReplayCache(max_skew=max_skew)
        logger.info(
            "C2 handshake server ready (key fingerprint %s)",
            _key_fingerprint(self._eph["public_key"]),
        )

    def process_hello(self, hello: Dict[str, Any]) -> tuple:
        """Validate HELLO and produce (REPLY message, session factory state).

        The returned state must be passed to :meth:`confirm` to finalize.
        """
        try:
            version = int(hello.get("v", 0))
            client_id = str(hello["client_id"])
            eph_pub_c = str(hello["eph_pub"])
            nonce_c = str(hello["nonce_c"])
            ts = float(hello["ts"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HandshakeError(f"malformed hello: {exc}") from exc

        if version != HANDSHAKE_VERSION:
            raise HandshakeError(f"unsupported handshake version {version}")
        if not client_id or not eph_pub_c or not nonce_c:
            raise HandshakeError("hello missing required fields")

        self._replay.check_and_add(nonce_c, ts, peer=client_id)

        nonce_s = secrets.token_urlsafe(16)
        ts_s = time.time()
        shared = self.crypto.derive_shared_secret(
            self._eph["private_key"], eph_pub_c
        )
        k_auth, k_session = _derive_session_material(shared, nonce_c, nonce_s)

        mac_input = b"|".join(
            [
                _CTX_HELLO,
                client_id.encode(),
                eph_pub_c.encode(),
                nonce_c.encode(),
                self._eph["public_key"].encode(),
                nonce_s.encode(),
            ]
        )
        mac_s = hmac.new(k_auth, mac_input, hashlib.sha256).hexdigest()

        reply = {
            "v": HANDSHAKE_VERSION,
            "eph_pub_s": self._eph["public_key"],
            "nonce_s": nonce_s,
            "ts": ts_s,
            "mac_s": mac_s,
        }
        state = {
            "client_id": client_id,
            "k_auth": k_auth,
            "k_session": k_session,
            "nonce_s": nonce_s,
            "eph_pub_c": eph_pub_c,
        }
        return reply, state

    def confirm(self, state: Dict[str, Any], confirm_msg: Dict[str, Any]) -> Session:
        """Validate CONFIRM and return the established Session."""
        try:
            mac_c = str(confirm_msg["mac_c"])
        except (KeyError, TypeError) as exc:
            raise HandshakeError(f"malformed confirm: {exc}") from exc

        expected = hmac.new(
            state["k_auth"], _CTX_CONFIRM + state["nonce_s"].encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, mac_c):
            raise HandshakeError("confirm MAC mismatch")

        session_crypto = Crypto(key=state["k_session"])
        return Session(
            client_id=state["client_id"],
            crypto=session_crypto,
            peer_key_fingerprint="client:" + _key_fingerprint(state["eph_pub_c"]),
            established_at=time.time(),
        )


class HandshakeClient:
    """Beacon/implant side of the handshake."""

    def __init__(self, client_id: str, crypto: Optional[Crypto] = None, max_skew: float = DEFAULT_MAX_SKEW):
        self.client_id = client_id
        self.crypto = crypto or Crypto()
        self._eph = self.crypto.generate_key_exchange()
        self._replay = _ReplayCache(max_skew=max_skew)
        self._pending: Dict[str, Any] = {}

    def hello(self) -> Dict[str, Any]:
        """Produce the HELLO message and stash client-side state."""
        nonce_c = secrets.token_urlsafe(16)
        ts = time.time()
        self._pending = {"nonce_c": nonce_c, "ts": ts}
        return {
            "type": "handshake_hello",
            "v": HANDSHAKE_VERSION,
            "client_id": self.client_id,
            "eph_pub": self._eph["public_key"],
            "nonce_c": nonce_c,
            "ts": ts,
        }

    def process_reply(self, reply: Dict[str, Any]) -> tuple:
        """Validate REPLY; produce (CONFIRM message, Session)."""
        if not self._pending:
            raise HandshakeError("no hello sent")
        try:
            version = int(reply.get("v", 0))
            eph_pub_s = str(reply["eph_pub_s"])
            nonce_s = str(reply["nonce_s"])
            ts_s = float(reply["ts"])
            mac_s = str(reply["mac_s"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HandshakeError(f"malformed reply: {exc}") from exc

        if version != HANDSHAKE_VERSION:
            raise HandshakeError(f"unsupported handshake version {version}")

        self._replay.check_and_add(nonce_s, ts_s, peer="server")

        nonce_c = self._pending["nonce_c"]
        shared = self.crypto.derive_shared_secret(self._eph["private_key"], eph_pub_s)
        k_auth, k_session = _derive_session_material(shared, nonce_c, nonce_s)

        mac_input = b"|".join(
            [
                _CTX_HELLO,
                self.client_id.encode(),
                self._eph["public_key"].encode(),
                nonce_c.encode(),
                eph_pub_s.encode(),
                nonce_s.encode(),
            ]
        )
        expected = hmac.new(k_auth, mac_input, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac_s):
            raise HandshakeError("server MAC mismatch (possible MITM)")

        mac_c = hmac.new(k_auth, _CTX_CONFIRM + nonce_s.encode(), hashlib.sha256).hexdigest()
        session = Session(
            client_id=self.client_id,
            crypto=Crypto(key=k_session),
            peer_key_fingerprint="server:" + _key_fingerprint(eph_pub_s),
            established_at=time.time(),
        )
        self._pending = {}
        return {"mac_c": mac_c}, session

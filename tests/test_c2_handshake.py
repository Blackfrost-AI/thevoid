"""THE VOID — C2 handshake + daemon fail-closed tests (fully offline).

Covers:
  * ECDH handshake round-trip, replay/stale/tamper rejection, session crypto.
  * C2Daemon integration: handshake-required by default (fail closed),
    session-sealed command channel, WarLog evidence for every outcome.
  * Beacon.perform_handshake client flow against the server handshake.
  * Compat fixes: Crypto.encrypt/decrypt string API, Executor.run_command.
"""

import io
import json
import time
from collections import deque

import pytest

from c2.beacon import Beacon
from c2.daemon import C2Daemon
from c2.handshake import (
    HandshakeClient,
    HandshakeError,
    HandshakeServer,
    Session,
)
from core.crypto import Crypto
from core.executor import Executor
from core.warlog import WarLog


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


class ScriptedSocket:
    """In-memory socket (bytes-only, like a real socket): scripted recv queue,
    recorded sends, on_send hook."""

    def __init__(self, on_send=None):
        self.sent = []
        self.queue = deque()
        self.on_send = on_send
        self.closed = False

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sent.append(data)
        if self.on_send:
            self.on_send(data, self.queue)
        return len(data)

    def recv(self, n):
        item = self.queue.popleft() if self.queue else b""
        return item.encode() if isinstance(item, str) else item

    def close(self):
        self.closed = True


# ─── Handshake protocol ──────────────────────────────────────────────────────

class TestHandshake:
    def test_round_trip_and_shared_session_key(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")

        hello = client.hello()
        reply, state = server.process_hello(hello)
        confirm, session_c = client.process_reply(reply)
        session_s = server.confirm(state, confirm)

        sealed = session_c.seal("ping")
        assert session_s.open(sealed) == "ping"
        assert session_c.open(session_s.seal("pong")) == "pong"
        assert session_s.open_json(session_c.seal_json({"cmd": 1})) == {"cmd": 1}

    def test_session_evidence_contains_no_key_material(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        reply, state = server.process_hello(hello)
        confirm, session = client.process_reply(reply)

        evidence = session.evidence()
        blob = json.dumps(evidence)
        assert "k_session" not in blob and "k_auth" not in blob
        assert len(evidence["peer_key_fingerprint"].split(":")[1]) == 16

    def test_replayed_hello_rejected(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        server.process_hello(hello)

        with pytest.raises(HandshakeError, match="replayed"):
            server.process_hello(hello)

    def test_stale_timestamp_rejected(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        hello["ts"] = time.time() - 3600

        with pytest.raises(HandshakeError, match="stale"):
            server.process_hello(hello)

    def test_tampered_reply_rejected_by_client(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        reply, _state = server.process_hello(hello)
        reply["mac_s"] = "deadbeef" * 8

        with pytest.raises(HandshakeError, match="MAC mismatch"):
            client.process_reply(reply)

    def test_tampered_confirm_rejected_by_server(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        reply, state = server.process_hello(hello)
        confirm, _session = client.process_reply(reply)
        confirm["mac_c"] = "deadbeef" * 8

        with pytest.raises(HandshakeError, match="confirm MAC"):
            server.confirm(state, confirm)

    def test_malformed_hello_rejected(self):
        server = HandshakeServer()
        with pytest.raises(HandshakeError, match="malformed"):
            server.process_hello({"v": 1})

    def test_wrong_version_rejected(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        hello["v"] = 99

        with pytest.raises(HandshakeError, match="version"):
            server.process_hello(hello)

    def test_session_rotation_keeps_channel_working(self):
        server = HandshakeServer()
        client = HandshakeClient("beacon-01")
        hello = client.hello()
        reply, state = server.process_hello(hello)
        confirm, session_c = client.process_reply(reply)
        session_s = server.confirm(state, confirm)

        session_c.rotate()
        session_s.rotate()
        assert session_c.rotated == 1
        assert session_s.open(session_c.seal("after-rotate")) == "after-rotate"


# ─── Daemon integration (fail closed) ───────────────────────────────────────

class TestDaemonHandshakeIntegration:
    def _connected_daemon(self, tmp_path):
        warlog = make_warlog(tmp_path)
        daemon = C2Daemon(warlog=warlog)
        client_hs = HandshakeClient("beacon-t1")
        state = {"step": 0, "session": None}

        def on_send(data, queue):
            if state["step"] == 0:
                reply = json.loads(daemon.crypto.decrypt(data.decode()))
                confirm, session = client_hs.process_reply(reply)
                state["session"] = session
                queue.append(daemon.crypto.encrypt(json.dumps(confirm)).encode())
                state["step"] = 1
            else:
                state["step"] = 2

        sock = ScriptedSocket(on_send=on_send)
        sock.queue.append(daemon.crypto.encrypt(json.dumps(client_hs.hello())).encode())
        daemon._handle_client(sock, ("127.0.0.1", 55555))
        return daemon, sock, state, warlog

    def test_handshake_registers_session_with_evidence(self, tmp_path):
        daemon, sock, state, warlog = self._connected_daemon(tmp_path)

        assert state["step"] == 2
        assert len(daemon.clients) == 1
        events = warlog.get_entries(module="c2.daemon")
        assert any(e["data"].get("status", "ok") and "handshake_ok" in e["message"]
                   for e in events)

        # Ack is session-sealed and carries the session descriptor.
        ack = state["session"].open_json(sock.sent[-1].decode())
        assert ack["type"] == "handshake_ok"
        assert ack["session"]["client_id"] == "beacon-t1"

    def test_command_before_handshake_refused(self, tmp_path):
        warlog = make_warlog(tmp_path)
        daemon = C2Daemon(warlog=warlog)
        sock = ScriptedSocket()
        sock.queue.append(daemon.crypto.encrypt(json.dumps(
            {"type": "exec", "command": ["echo", "hi"]})).encode())

        daemon._handle_client(sock, ("127.0.0.1", 55556))

        assert sock.sent == []          # no response to unauthenticated caller
        assert sock.closed               # connection dropped
        events = warlog.get_entries(module="c2.daemon")
        assert any("handshake_required" in e["message"] for e in events)

    def test_sealed_session_command_executes(self, tmp_path):
        daemon, _sock, state, warlog = self._connected_daemon(tmp_path)
        session = state["session"]

        cmd = {"type": "exec", "command": ["echo", "handshake-works"]}
        envelope = daemon.crypto.encrypt(json.dumps(
            {"session": "beacon-t1", "sealed": session.seal_json(cmd)})).encode()
        sock2 = ScriptedSocket()
        sock2.queue.append(envelope)

        daemon._handle_client(sock2, ("127.0.0.1", 55557))

        assert len(sock2.sent) == 1
        response = session.open_json(sock2.sent[0].decode())
        assert response["success"] is True
        assert "handshake-works" in response["stdout"]

    def test_forged_session_id_refused(self, tmp_path):
        daemon, _sock, state, _warlog = self._connected_daemon(tmp_path)
        session = state["session"]

        envelope = daemon.crypto.encrypt(json.dumps(
            {"session": "not-a-client", "sealed": session.seal_json({"type": "exec"})})).encode()
        sock2 = ScriptedSocket()
        sock2.queue.append(envelope)

        daemon._handle_client(sock2, ("127.0.0.1", 55558))

        assert sock2.sent == []
        assert sock2.closed

    def test_replayed_handshake_rejected_with_evidence(self, tmp_path):
        daemon, _sock, _state, warlog = self._connected_daemon(tmp_path)
        client_hs = HandshakeClient("beacon-t2")
        hello = client_hs.hello()
        reply, _st = daemon.handshake.process_hello(hello)

        sock = ScriptedSocket()
        sock.queue.append(daemon.crypto.encrypt(json.dumps(hello)).encode())
        daemon._handle_client(sock, ("127.0.0.1", 55559))

        assert sock.sent == []
        events = warlog.get_entries(module="c2.daemon")
        assert any("handshake_rejected" in e["message"] for e in events)

    def test_legacy_mode_still_serves_plain_commands(self, tmp_path):
        warlog = make_warlog(tmp_path)
        daemon = C2Daemon(warlog=warlog, require_handshake=False)
        sock = ScriptedSocket()
        sock.queue.append(daemon.crypto.encrypt(json.dumps(
            {"type": "exec", "command": ["echo", "legacy"]})).encode())

        daemon._handle_client(sock, ("127.0.0.1", 55560))

        assert len(sock.sent) == 1
        response = json.loads(daemon.crypto.decrypt(sock.sent[0].decode()))
        assert response["success"] is True
        assert "legacy" in response["stdout"]


# ─── Beacon client flow ──────────────────────────────────────────────────────

class TestBeaconHandshake:
    def test_beacon_performs_handshake_and_seals(self):
        shared = Crypto()
        server = HandshakeServer(crypto=shared)
        beacon = Beacon("beacon-b1", crypto=shared)
        state = {"st": None}

        def on_send(data, queue):
            outer = json.loads(shared.decrypt(data.decode()))
            if outer.get("type") == "handshake_hello":
                reply, state["st"] = server.process_hello(outer)
                queue.append(shared.encrypt(json.dumps(reply)).encode())
            else:
                session_s = server.confirm(state["st"], outer)
                queue.append(session_s.seal_json(
                    {"type": "handshake_ok", "session": session_s.evidence()}).encode())

        sock = ScriptedSocket(on_send=on_send)
        session = beacon.perform_handshake(sock)

        assert beacon.session is session
        assert session.open(session.seal("x")) == "x"


# ─── Compat fixes (latent bugs fixed in this phase) ─────────────────────────

class TestCompatFixes:
    def test_crypto_string_api_round_trip(self):
        crypto = Crypto()
        blob = crypto.encrypt("hello world")
        assert crypto.decrypt(blob) == "hello world"
        assert isinstance(crypto.decrypt_json(crypto.encrypt_json({"a": 1})), dict)

    def test_crypto_decrypt_rejects_tamper(self):
        import base64

        crypto = Crypto()
        blob = crypto.encrypt("secret")
        raw = bytearray(base64.b64decode(blob))
        raw[-3] ^= 0xFF
        with pytest.raises(Exception):
            crypto.decrypt(base64.b64encode(bytes(raw)).decode())

    def test_executor_run_command_exists_and_is_argv_safe(self):
        executor = Executor()
        result = executor.run_command(["echo", "a; b | c"])
        assert result.success
        assert "a; b | c" in result.stdout  # literal, no shell interpretation

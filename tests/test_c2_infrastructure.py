"""THE VOID — hardened HTTP C2 listener tests (fully offline).

Covers the legacy-listener defects that were fixed:
  * binds an explicit address (loopback default) — never all interfaces
  * ``/exec`` requires a bearer token (constant-time compare)
  * commands execute as argv lists with shell=False — string commands are
    rejected outright (the old listener ran ``shell=True`` on attacker input)
  * auth failures are logged, the token itself never is

The generated listener source is compiled and exercised in-process against a
real ThreadingTCPServer bound to an ephemeral loopback port — no external
network, no fixed ports.
"""

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from core.warlog import WarLog
from exploit.c2_infrastructure import (
    C2Infrastructure,
    C2_LOG_NAME,
    C2_RUNTIME_DIR,
    C2_SCRIPT_NAME,
    C2_TOKEN_NAME,
    render_listener_source,
)


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def load_listener(tmp_path, bind="127.0.0.1"):
    """Compile the rendered listener source and start it on an ephemeral port."""
    log_path = tmp_path / "access.log"
    source = render_listener_source(str(log_path), bind=bind, port=0)

    spec = importlib.util.spec_from_loader(
        "void_c2_listener_under_test", loader=None
    )
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, "<c2-listener>", "exec"), module.__dict__)

    module.socketserver.TCPServer.allow_reuse_address = True
    server = module.socketserver.ThreadingTCPServer(
        (bind, 0), module.C2Handler
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, log_path, source


def post(port, path, payload=None, token=None):
    body = json.dumps(payload).encode() if payload is not None else b""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class TestListenerSource:
    def test_no_shell_execution_in_source(self):
        source = render_listener_source("/tmp/x.log")
        assert "shell=True" not in source
        assert "shell=False" in source
        assert "subprocess.run(" in source

    def test_binds_explicit_address(self):
        source = render_listener_source("/tmp/x.log", bind="127.0.0.1", port=9)
        assert "BIND = '127.0.0.1'" in source
        assert "TCPServer(('', PORT)" not in source          # legacy all-interfaces
        assert "TCPServer((BIND, PORT)" in source

    def test_refuses_to_start_without_token(self):
        source = render_listener_source("/tmp/x.log")
        assert "VOID_C2_TOKEN not set" in source
        assert "refusing to start unauthenticated listener" in source


class TestListenerRuntime:
    @pytest.fixture(autouse=True)
    def _token_env(self, monkeypatch):
        monkeypatch.setenv("VOID_C2_TOKEN", "tok-123")

    def test_unauthenticated_exec_rejected_and_logged(self, tmp_path):
        server, port, log_path, _ = load_listener(tmp_path)
        try:
            status, _body = post(port, "/exec", {"argv": ["echo", "hi"]})
            assert status == 401
            entries = [json.loads(line) for line in log_path.read_text().splitlines()]
            assert any(e.get("event") == "auth_failed" for e in entries)
        finally:
            server.shutdown()

    def test_string_command_rejected(self, tmp_path):
        server, port, log_path, _ = load_listener(tmp_path)
        try:
            status, body = post(port, "/exec", {"cmd": "echo hi"}, token="tok-123")
            assert status == 400
            assert b"argv list required" in body
            entries = [json.loads(line) for line in log_path.read_text().splitlines()]
            assert any(e.get("event") == "exec_rejected" for e in entries)
        finally:
            server.shutdown()

    def test_argv_exec_runs_without_shell(self, tmp_path):
        server, port, log_path, _ = load_listener(tmp_path)
        try:
            status, body = post(
                port, "/exec", {"argv": ["echo", "hi; not-a-shell"]}, token="tok-123"
            )
            assert status == 200
            result = json.loads(body)
            assert result["exit_code"] == 0
            assert result["stdout"].strip() == "hi; not-a-shell"  # literal
            entries = [json.loads(line) for line in log_path.read_text().splitlines()]
            assert any(e.get("event") == "exec" and e.get("argv0") == "echo"
                       for e in entries)
        finally:
            server.shutdown()

    def test_token_never_written_to_log(self, tmp_path, monkeypatch):
        secret = "S3CRET-TOKEN-DO-NOT-LOG"
        monkeypatch.setenv("VOID_C2_TOKEN", secret)
        server, port, log_path, _ = load_listener(tmp_path)
        try:
            post(port, "/exec", {"argv": ["echo", "x"]}, token=secret)
            post(port, "/exec", {"argv": ["echo", "x"]})   # wrong/no token
            assert secret not in log_path.read_text()
        finally:
            server.shutdown()

    def test_unknown_path_404(self, tmp_path):
        server, port, _log_path, _ = load_listener(tmp_path)
        try:
            status, _body = post(port, "/nope", {"argv": ["echo", "x"]}, token="t")
            assert status == 404
        finally:
            server.shutdown()

    def test_get_still_answers_beacon_ping(self, tmp_path):
        server, port, _log_path, _ = load_listener(tmp_path)
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=10
            ) as response:
                assert response.status == 200
                assert b"C2 Active" in response.read()
        finally:
            server.shutdown()


class TestDeploy:
    def test_deploy_writes_private_artifacts_and_evidences(self, tmp_path, monkeypatch):
        monkeypatch.setattr("exploit.c2_infrastructure.C2_RUNTIME_DIR", tmp_path / "c2state")
        warlog = make_warlog(tmp_path)
        infra = C2Infrastructure(warlog=warlog)

        result = infra.deploy_http_c2_server(start=False)

        assert result["type"] == "http_c2_server_deployed"
        assert result["status"] == "ready"
        assert result["url"] == "http://127.0.0.1:8080"

        state_dir = tmp_path / "c2state"
        script = state_dir / C2_SCRIPT_NAME
        token = state_dir / C2_TOKEN_NAME
        assert script.exists() and token.exists()

        # Owner-only artifacts (0700 dir created by private_directory; 0600 token).
        assert (state_dir.stat().st_mode & 0o777) == 0o700
        assert (token.stat().st_mode & 0o777) == 0o600

        # Token is never in the result dict or WarLog evidence.
        secret = token.read_text().strip()
        assert secret not in json.dumps(result)
        events = warlog.get_entries(module="exploit.c2_infrastructure")
        assert any("listener_deployed" in e["message"] for e in events)
        assert all(secret not in json.dumps(e["data"]) for e in events)

    def test_deploy_reuses_existing_token(self, tmp_path, monkeypatch):
        monkeypatch.setattr("exploit.c2_infrastructure.C2_RUNTIME_DIR", tmp_path / "c2state")
        infra = C2Infrastructure(warlog=make_warlog(tmp_path))

        infra.deploy_http_c2_server(start=False)
        token_path = tmp_path / "c2state" / C2_TOKEN_NAME
        first = token_path.read_text().strip()
        infra.deploy_http_c2_server(start=False)
        second = token_path.read_text().strip()

        assert first == second

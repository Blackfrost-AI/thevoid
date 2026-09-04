"""Access-boundary tests against an in-memory, mocked localhost application."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from commandcenter.backend.config import Settings, allowed_browser_origins
from commandcenter.session import access_token, browser_bootstrap, browser_url


@pytest.fixture
def local_app(tmp_path, monkeypatch):
    monkeypatch.setenv("VOID_RUNTIME_DIR", str(tmp_path / "run"))
    from commandcenter.backend.main import create_app

    bridge = MagicMock()
    bridge.degraded = []
    with (
        patch("commandcenter.backend.main.get_bridge", return_value=bridge),
        patch("commandcenter.backend.services.poller.EventPoller.start", new_callable=AsyncMock),
        patch("commandcenter.backend.services.poller.EventPoller.stop", new_callable=AsyncMock),
    ):
        with TestClient(create_app(), base_url="http://127.0.0.1:7070") as client:
            yield client, bridge


def test_api_requires_explicit_operator_token(local_app):
    client, _ = local_app
    assert client.get("/api/session").status_code == 401
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/session", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = client.get("/api/session", headers={"Authorization": "Bearer " + access_token(7070)})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers


def test_public_health_has_no_license_identity_and_degraded_fails(local_app):
    client, bridge = local_app
    assert "license" not in client.get("/api/health").json()
    bridge.degraded = ["boneyard"]
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.json()["ready"] is False


def test_websocket_requires_token_and_returns_only_public_subprotocol(local_app):
    client, _ = local_app
    with pytest.raises(WebSocketDisconnect) as denied:
        with client.websocket_connect("ws://127.0.0.1:7070/ws/live"):
            pass
    assert denied.value.code == 1008
    with client.websocket_connect(
        "ws://127.0.0.1:7070/ws/live", subprotocols=["void-session", access_token(7070)]
    ) as websocket:
        assert websocket.accepted_subprotocol == "void-session"
        assert websocket.receive_json()["type"] == "connected"


def test_cross_origin_mutation_denied_even_with_valid_token(local_app):
    client, _ = local_app
    response = client.post(
        "/api/demo/enable",
        headers={
            "Authorization": "Bearer " + access_token(7070),
            "Origin": "https://fixture.invalid",
        },
    )
    assert response.status_code == 403


def test_launcher_fragment_and_token_permissions(local_app, tmp_path):
    url = browser_url(7070)
    assert "?" not in url
    assert "#access_token=" in url
    assert (tmp_path / "run" / "command-center-7070.token").stat().st_mode & 0o777 == 0o600


def test_development_origins_not_allowed_by_default():
    assert "http://127.0.0.1:5173" not in allowed_browser_origins(Settings())


def test_browser_launch_argument_does_not_contain_secret(local_app, tmp_path):
    launch_uri = browser_bootstrap(7070)
    assert launch_uri.startswith("file://")
    assert access_token(7070) not in launch_uri
    bootstrap = tmp_path / "run" / "command-center-7070-open.html"
    assert bootstrap.stat().st_mode & 0o777 == 0o600
    assert browser_url(7070) in bootstrap.read_text()


def test_server_startup_enforces_operator_before_creating_token():
    from commandcenter.backend.main import create_app

    with (
        patch("commandcenter.launcher._ensure_unprivileged", side_effect=RuntimeError("not root")),
        patch("commandcenter.backend.main.access_token") as token,
        pytest.raises(RuntimeError, match="not root"),
    ):
        with TestClient(create_app(), base_url="http://127.0.0.1:7070"):
            pass
    token.assert_not_called()

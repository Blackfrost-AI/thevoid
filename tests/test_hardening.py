"""Offline regression tests for defensive controls; no operational engines."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli.app import cli
from config.settings import Settings
from core.authorization import AuthorizationGate
from core.boneyard import Boneyard
from core.private_storage import private_directory, private_file, store_passphrase
from core.recovery_guard import is_recovery_command
from modules.evidence_reports import recorded_engagements


def authorization(**overrides):
    now = datetime.now(timezone.utc)
    return {
        "authorized": True,
        "engagement_name": "offline-unit-test",
        "operator": "test-operator",
        "in_scope": ["fixture.invalid"],
        "allowed_modes": ["quick"],
        "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        **overrides,
    }


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("VOID_CONFIG_DIR", str(tmp_path / "config"))
    Settings()._load_defaults()
    yield
    Settings()._load_defaults()


@pytest.mark.parametrize("required", [True, False])
def test_authorization_cannot_open_without_document(required):
    assert (
        not AuthorizationGate(require_authorization=required)
        .check_target("fixture.invalid")
        .allowed
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"authorized": "true"},
        {"authorized": 1},
        {"authorized": False},
        {"operator": ""},
        {"in_scope": "fixture.invalid"},
        {"allowed_modes": []},
        {"allow_out_of_scope": True},
        {"expires_at": "2020-01-01T00:00:00Z"},
        {"expires_at": "2099-01-01T00:00:00"},
        {"not_before": None},
    ],
)
def test_authorization_rejects_invalid_documents(changes):
    gate = AuthorizationGate(data=authorization(**changes))
    assert not gate.check_target("fixture.invalid", "quick").allowed
    assert gate.filter_phases(["recon"]) == []


def test_authorization_exact_scope_does_not_imply_subdomains():
    gate = AuthorizationGate(data=authorization())
    assert gate.check_target("fixture.invalid", "quick").allowed
    assert not gate.check_target("child.fixture.invalid", "quick").allowed


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"REQUIRE_AUTHORIZATON": True},
        {"REQUIRE_AUTHORIZATION": False},
        {"CLIENT_MODE": "true"},
        {"DEFAULT_TIMEOUT": True},
        {"HIGH_RISK_PHASES": [42]},
    ],
)
def test_invalid_configuration_is_atomic(tmp_path, data):
    settings = Settings()
    before = settings.to_dict()
    config = tmp_path / "config.json"
    config.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        settings.load_file(str(config))
    assert settings.to_dict() == before


def test_cli_missing_configuration_is_usage_error(tmp_path):
    with (
        patch("cli.app._make_evidence_bridge") as observer,
        patch("cli.app._make_engine") as engine,
    ):
        result = CliRunner().invoke(cli, ["status", "--config", str(tmp_path / "absent.json")])
    assert result.exit_code == 2
    assert "Cannot load configuration" in result.output
    observer.assert_not_called()
    engine.assert_not_called()


def test_default_keys_are_random_private_and_stable(tmp_path):
    first_db, second_db = tmp_path / "one.db", tmp_path / "two.db"
    first = store_passphrase(first_db)
    assert len(first) == 64
    assert store_passphrase(first_db) == first
    assert store_passphrase(second_db) != first
    files = list((tmp_path / "config" / "evidence-keys").glob("*.key"))
    assert len(files) == 2
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in files)


def test_legacy_store_is_not_rekeyed(tmp_path):
    database = tmp_path / "existing.db"
    database.write_bytes(b"preserve-legacy-bytes")
    with pytest.raises(RuntimeError, match="legacy migration"):
        store_passphrase(database)
    assert database.read_bytes() == b"preserve-legacy-bytes"
    assert not list((tmp_path / "config" / "evidence-keys").glob("*.key"))


def test_private_storage_rejects_symlinks_and_shared_modes(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    with pytest.raises(PermissionError):
        private_directory(shared)
    original = tmp_path / "original"
    original.write_bytes(b"retained")
    original.chmod(0o600)
    link = tmp_path / "linked"
    link.symlink_to(original)
    with pytest.raises(OSError):
        private_file(link)
    assert original.read_bytes() == b"retained"


def test_sensitive_evidence_encrypted_and_readable_after_restart(tmp_path):
    marker = "fictional-sensitive-" + secrets.token_hex(8)
    store = Boneyard(str(tmp_path / "store"))
    item_id = store.store("secret", {"secret": marker})
    assert store._encrypted is True
    assert marker.encode() not in Path(store._db_path).read_bytes()
    reopened = Boneyard(str(tmp_path / "store"))
    assert reopened.get(item_id)["data"]["secret"] == marker
    assert reopened.verify_integrity().verified is True
    assert Path(store._db_path).stat().st_mode & 0o777 == 0o600
    assert not hasattr(store, "_encrypt_field_fallback")


def test_missing_supported_crypto_does_not_create_store(tmp_path):
    with patch.dict("sys.modules", {"cryptography.hazmat.primitives.ciphers.aead": None}):
        with pytest.raises(ImportError):
            Boneyard(str(tmp_path / "not-created"))
    assert not (tmp_path / "not-created").exists()


@pytest.mark.parametrize(
    "arguments, expected",
    [
        (["restore"], True),
        (["doctor"], True),
        (["status", "--no-public-ip"], True),
        (["--persona", "fixture", "restore"], True),
        (["--persona=fixture", "restore"], True),
        (["--help"], True),
        (["--version"], True),
        (["engage"], False),
        (["--persona", "restore", "engage"], False),
        (["engage", "--iface", "restore"], False),
        (["--persona"], False),
        (["--unknown", "restore"], False),
        ([], False),
    ],
)
def test_only_recovery_is_exempt_from_license(arguments, expected):
    assert is_recovery_command(arguments) is expected


def test_report_reads_recorded_data_and_refuses_truncation():
    evidence = MagicMock()
    evidence.categories.return_value = ["other", "attack_fixture"]
    payload = {"target": "fixture.invalid", "status": "completed"}
    evidence.search.return_value = [{"data": payload}, {"data": payload}]
    assert recorded_engagements(evidence) == [payload]
    with pytest.raises(RuntimeError, match="limit"):
        recorded_engagements(evidence, category_limit=1)


def test_failed_export_is_nonzero_and_stdout_remains_json():
    reporter = MagicMock()
    reporter.generate.return_value = '{"fixture": true}'
    exporter = MagicMock()
    exporter.name = "fixture-export"
    exporter.export.return_value = False
    with (
        patch("modules.reporter.Reporter", return_value=reporter),
        patch("core.warlog.WarLog"),
        patch("core.boneyard.Boneyard"),
        patch("modules.exporters.WebhookExporter", return_value=exporter),
    ):
        result = CliRunner(mix_stderr=False).invoke(
            cli, ["report", "--format", "json", "--export", "webhook"]
        )
    assert result.exit_code == 1
    assert json.loads(result.stdout) == {"fixture": True}
    assert "failed" in result.stderr


def test_status_reads_evidence_without_constructing_engine():
    observer = MagicMock()
    observer.degraded = []
    observer.get_status.return_value = {"attack_log": 2, "target_count": 3}
    with (
        patch("cli.app._make_evidence_bridge", return_value=observer),
        patch("cli.app._make_engine") as engine,
    ):
        result = CliRunner().invoke(cli, ["status", "--json-output"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["recorded_engagements"] == 2
    assert payload["runtime_state"] == "not_attached"
    engine.assert_not_called()


def test_target_edit_rejected_before_engine_initialization():
    with (
        patch("cli.app._make_engine") as engine,
        patch("cli.app._make_evidence_bridge") as observer,
    ):
        result = CliRunner().invoke(cli, ["targets", "--clear"])
    assert result.exit_code == 2
    engine.assert_not_called()
    observer.assert_not_called()


def test_dependency_gate_requires_both_nonempty_inventories():
    from release.check_scan_inventory import REQUIRED_LOCKS, check_inventory

    complete = {
        "Results": [{"Target": path, "Packages": [{"Name": "fixture"}]} for path in REQUIRED_LOCKS]
    }
    assert check_inventory(complete) == {path: 1 for path in REQUIRED_LOCKS}
    with pytest.raises(ValueError, match="omitted"):
        check_inventory({"Results": complete["Results"][:1]})
    with pytest.raises(ValueError, match="omitted"):
        check_inventory({"Results": [{"Target": path, "Packages": []} for path in REQUIRED_LOCKS]})


def test_uvicorn_uses_the_explicit_websocket_provider():
    from uvicorn import Config
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol

    async def inert_app(scope, receive, send):
        return None

    config = Config(inert_app, ws="wsproto")
    config.load()
    assert config.ws_protocol_class is WSProtocol


def test_package_metadata_requires_confirmed_support_address(tmp_path, monkeypatch):
    from release.build_release import _write_control

    monkeypatch.delenv("VOID_SUPPORT_EMAIL", raising=False)
    with pytest.raises(RuntimeError, match="monitored support address"):
        _write_control(
            tmp_path,
            package="fixture",
            version="1.0.0",
            architecture="amd64",
            depends="",
            description="fixture",
        )
    assert not (tmp_path / "DEBIAN").exists()


def test_snowblind_wrapper_checks_recovery_before_entitlement():
    from release.build_release import _snowblind_wrapper

    script = _snowblind_wrapper(development=False)
    assert script.index("core.recovery_guard") < script.index("license status --feature snowblind")


def test_rotated_log_database_and_archives_stay_private(tmp_path):
    from core.warlog import WarLog

    directory = tmp_path / "logs"
    log = WarLog(
        log_dir=str(directory), log_file=str(directory / "events.jsonl"), rotate_on_init=False
    )
    log.log("synthetic fixture event")
    first = Path(log._rotate())
    second = Path(log._rotate())
    assert first != second
    assert first.exists() and second.exists()
    assert first.stat().st_mode & 0o777 == 0o600
    assert second.stat().st_mode & 0o777 == 0o600
    assert Path(log._db_path).stat().st_mode & 0o777 == 0o600
    reopened = WarLog(
        log_dir=str(directory), log_file=str(directory / "events.jsonl"), rotate_on_init=False
    )
    assert reopened.verify_integrity().verified

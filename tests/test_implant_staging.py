"""THE VOID — implant staging + reversible impact tests (P1-2, offline).

Covers:
  * StageBundle: encrypt+sign on build; tamper -> verify() False; expiry
    math (TTL cap at 24h; expired() false at boundary-minus, true after).
  * Killswitch: signed, verified; wrong action rejected at issue();
    tampered signature never verifies.
  * ImplantLoader.check(): fail-closed matrix — expired / bad signature /
    budget exhausted / killswitch fired each independently yield
    healthy=False.
  * Durable vs volatile staging: durable lands under ~/.void/..., volatile
    under /dev/shm (test overrides root so nothing touches the host).
  * payload_file() + cleanup(): original file restored byte-for-byte;
    evidence written; errors reported, never swallowed.
  * DestructionExecutor reversible mode: refuses to run without
    warlog/crypto; sandbox+evidence before impact; impact failure still
    restores; evidence_id present in report; legacy mode unchanged.
"""

import json
import time
from pathlib import Path

import pytest

from core.crypto import Crypto
from core.warlog import LogLevel, WarLog
from exploit.destruction_executor import DestructionExecutor
from implant.staging import (
    ImplantLoader,
    Killswitch,
    KillswitchError,
    StageBundle,
    StageBundleError,
)


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def make_bundle(crypto, ttl=3600.0, payload=None, metadata=None):
    return StageBundle.build(
        crypto,
        payload or {"cmd": "sleep 3600"},
        ttl_seconds=ttl,
        metadata=metadata,
    )


# ─── StageBundle integrity + expiry ────────────────────────────────────────

class TestStageBundle:
    def test_build_encrypts_and_signs(self):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        assert bundle.verify(crypto)
        assert bundle.encryption["ciphertext"] != json.dumps({"x": 1})
        assert bundle.decrypt(crypto) == {"cmd": "sleep 3600"}

    def test_tampered_ciphertext_fails_verification(self):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        bundle.encryption["ciphertext"] = bundle.encryption["ciphertext"][:10] + "AA"
        assert bundle.verify(crypto) is False

    def test_tampered_metadata_fails_verification(self):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        bundle.metadata["evil"] = True
        assert bundle.verify(crypto) is False

    def test_ttl_capped_at_24h(self):
        crypto = Crypto()
        bundle = make_bundle(crypto, ttl=10 * 24 * 3600)
        assert bundle.ttl_seconds == 24 * 3600
        assert bundle.expires_at <= bundle.created_at + 24 * 3600

    def test_expiry_math(self):
        crypto = Crypto()
        bundle = make_bundle(crypto, ttl=60.0)
        assert bundle.expired(now=bundle.created_at + 59) is False
        assert bundle.expired(now=bundle.created_at + 61) is True
        assert bundle.expired() is False  # real clock is well before expiry

    def test_serialization_roundtrip(self):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        restored = StageBundle.from_dict(json.loads(json.dumps(bundle.to_dict())))
        assert restored.verify(crypto)
        assert restored.stage_id == bundle.stage_id

    def test_roundtrip_tampered_bundle_stays_suspicious(self):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        blob = bundle.to_dict()
        blob["metadata"] = {"tampered": True}
        restored = StageBundle.from_dict(blob)
        assert restored.verify(crypto) is False

    def test_zero_ttl_rejected(self):
        crypto = Crypto()
        with pytest.raises(ValueError):
            make_bundle(crypto, ttl=0)


# ─── Killswitch ────────────────────────────────────────────────────────────

class TestKillswitch:
    def test_signed_and_verified(self):
        crypto = Crypto()
        ks = Killswitch.issue(crypto, "cleanup")
        assert ks.verify(crypto)
        assert ks.action == "cleanup"

    def test_invalid_action_rejected(self):
        crypto = Crypto()
        with pytest.raises(KillswitchError):
            Killswitch.issue(crypto, "self_destroy_permanently")

    def test_tampered_signature_rejected(self):
        crypto = Crypto()
        ks = Killswitch.issue(crypto, "cleanup")
        ks.signature = "deadbeef" + ks.signature[8:]
        assert ks.verify(crypto) is False

    def test_wrong_key_rejected(self):
        crypto = Crypto()
        other = Crypto(key=b"x" * 32)
        ks = Killswitch.issue(crypto, "self_delete")
        assert ks.verify(other) is False

    def test_roundtrip(self):
        crypto = Crypto()
        ks = Killswitch.issue(crypto, "cleanup")
        restored = Killswitch.from_dict(ks.to_dict())
        assert restored.verify(crypto)


# ─── Loader fail-closed health check ───────────────────────────────────────

class TestLoaderCheck:
    @pytest.fixture()
    def loader(self, tmp_path):
        return ImplantLoader(staging_root=tmp_path / "staging",
                             warlog=make_warlog(tmp_path))

    def test_healthy_bundle_passes(self, loader):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        status = loader.check(bundle, crypto)
        assert status.healthy is True
        assert status.reasons == []

    def test_expired_bundle_fails(self, loader):
        crypto = Crypto()
        bundle = make_bundle(crypto, ttl=60.0)
        status = loader.check(bundle, crypto,
                              now=bundle.created_at + 61)
        assert status.healthy is False
        assert status.expired is True
        assert "bundle expired" in status.reasons

    def test_tampered_bundle_fails(self, loader):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        bundle.metadata["x"] = True
        status = loader.check(bundle, crypto)
        assert status.healthy is False
        assert status.signature_valid is False

    def test_budget_exhaustion_fails(self, loader):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        status = loader.check(bundle, crypto, boot_budget_used=loader.boot_budget)
        assert status.healthy is False
        assert status.budget_ok is False

    @pytest.mark.parametrize("budget", [0, -1])
    def test_invalid_boot_budget_capped(self, tmp_path, budget):
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path),
                               boot_budget=budget)
        assert loader.boot_budget == min(budget, 1)  # ceiling applies, floor 0/-1 kept

    def test_valid_killswitch_fires(self, loader):
        crypto = Crypto()
        bundle = make_bundle(crypto)
        ks = Killswitch.issue(crypto, "cleanup")
        status = loader.check(bundle, crypto, killswitch=ks)
        assert status.killswitch_fired is True
        assert status.healthy is False

    def test_forged_killswitch_still_fires(self, loader):
        # Fail closed: an unverified killswitch is treated as fired.
        crypto = Crypto()
        bundle = make_bundle(crypto)
        ks = Killswitch(action="cleanup", signature="forged",
                        issued_at=time.time())
        status = loader.check(bundle, crypto, killswitch=ks)
        assert status.killswitch_fired is True
        assert status.healthy is False
        assert any("unverified" in r for r in status.reasons)


# ─── Durable vs volatile staging ───────────────────────────────────────────

class TestDurableVsVolatile:
    def test_roots(self):
        assert str(ImplantLoader.durable_staging()).startswith(str(Path("~").expanduser()))
        assert str(ImplantLoader.volatile_staging()).startswith("/dev/shm")

    def test_install_durable(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        result = loader.install(bundle, crypto, durable=True)
        assert Path(result["evidence"]).exists()
        assert result["durable"] is True

    def test_install_volatile_writes_to_tmpfs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "implant.staging.Volatile", None, raising=False)
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        fake_tmpfs = tmp_path / "tmpfs"
        monkeypatch.setattr(ImplantLoader, "volatile_staging",
                            staticmethod(lambda: fake_tmpfs))
        result = loader.install(bundle, crypto, durable=False)
        assert Path(result["staging"]) == fake_tmpfs
        assert fake_tmpfs.exists()

    def test_install_rejects_tampered_bundle(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        bundle.metadata["evil"] = True
        with pytest.raises(StageBundleError):
            loader.install(bundle, crypto)


# ─── Reversible payload staging + cleanup ──────────────────────────────────

class TestPayloadStaging:
    def test_payload_staged_and_restored(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        install = loader.install(bundle, crypto)
        target = tmp_path / "host-file"
        target.write_bytes(b"original")

        staged = loader.payload_file(bundle, crypto, target)
        assert staged.exists()
        assert not target.exists()

        # Evidence file references the staged copy.
        evidence = json.loads(Path(install["evidence"]).read_text())
        evidence["staged_files"].append(
            {"original": str(target), "staged": str(staged)})
        Path(install["evidence"]).write_text(json.dumps(evidence))

        report = loader.cleanup(bundle, crypto, install["evidence"])
        assert report.clean
        assert target.read_bytes() == b"original"
        assert report.restored[0]["original"] == str(target)

    def test_cleanup_survives_missing_staged_file(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        install = loader.install(bundle, crypto)
        evidence = json.loads(Path(install["evidence"]).read_text())
        evidence["staged_files"].append(
            {"original": str(tmp_path / "gone"),
             "staged": str(tmp_path / "staging" / "missing.bin")})
        Path(install["evidence"]).write_text(json.dumps(evidence))

        report = loader.cleanup(bundle, crypto, install["evidence"])
        assert not report.clean
        assert any("staged file missing" in e for e in report.errors)

    def test_killswitch_triggers_cleanup(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        install = loader.install(bundle, crypto)
        target = tmp_path / "host-file"
        target.write_bytes(b"data")
        staged = loader.payload_file(bundle, crypto, target)
        evidence = json.loads(Path(install["evidence"]).read_text())
        evidence["staged_files"].append(
            {"original": str(target), "staged": str(staged)})
        Path(install["evidence"]).write_text(json.dumps(evidence))

        ks = Killswitch.issue(crypto, "cleanup")
        report = loader.cleanup(bundle, crypto, install["evidence"],
                                killswitch=ks)
        assert report.killswitch_fired is True
        assert report.clean
        assert target.read_bytes() == b"data"

    def test_missing_payload_file_raises(self, tmp_path):
        crypto = Crypto()
        loader = ImplantLoader(staging_root=tmp_path / "staging",
                               warlog=make_warlog(tmp_path))
        bundle = make_bundle(crypto)
        loader.install(bundle, crypto)
        with pytest.raises(FileNotFoundError):
            loader.payload_file(bundle, crypto, tmp_path / "nope")


# ─── DestructionExecutor reversible mode ───────────────────────────────────

class TestDestructionReversible:
    @pytest.fixture()
    def executor(self, tmp_path):
        return DestructionExecutor(
            executor=None, warlog=make_warlog(tmp_path), crypto=Crypto(),
            sensitive_files=[], reversible=False)

    def test_legacy_mode_unchanged(self, executor):
        assert executor.reversible is False
        # Legacy constructor call (no kwargs) still works:
        legacy = DestructionExecutor()
        assert legacy.name == "DestructionExecutor"

    def test_reversible_requires_evidence(self, tmp_path):
        with pytest.raises(ValueError, match="warlog"):
            DestructionExecutor(crypto=Crypto(), reversible=True)
        with pytest.raises(ValueError, match="crypto"):
            DestructionExecutor(warlog=make_warlog(tmp_path), reversible=True)

    def test_impact_without_reversible_flag_refuses(self, tmp_path):
        executor = DestructionExecutor()
        with pytest.raises(ValueError, match="reversible=True"):
            executor.reversible_impact("h1")

    def test_impact_stages_then_restores(self, tmp_path):
        sentinel = tmp_path / "sensitive.txt"
        sentinel.write_bytes(b"top secret")
        executor = DestructionExecutor(
            warlog=make_warlog(tmp_path), crypto=Crypto(),
            sensitive_files=[str(sentinel)], reversible=True,
            staging_root=tmp_path / "staging",
        )
        # Prevent real host impact: stub the step dispatcher.
        executor._execute_step = lambda name, target: True

        report = executor.reversible_impact("h1")

        assert report["evidence_id"]
        assert report["integrity"] == "restored_verified"
        assert report["staged"][0]["original"] == str(sentinel)
        assert sentinel.read_bytes() == b"top secret"
        assert report["restored"] == [str(sentinel)]

        events = executor.warlog.get_entries(
            module="exploit.destruction_executor")
        messages = [e["message"] for e in events]
        assert "reversible_impact_start" in messages
        assert "reversible_impact_complete" in messages

    def test_impact_failure_still_restores(self, tmp_path):
        sentinel = tmp_path / "sensitive.txt"
        sentinel.write_bytes(b"vital")
        executor = DestructionExecutor(
            warlog=make_warlog(tmp_path), crypto=Crypto(),
            sensitive_files=[str(sentinel)], reversible=True,
            staging_root=tmp_path / "staging",
        )
        executor.execute_destruction_sequence = lambda target: {
            "target": target, "steps": {}, "completed": [],
            "failed": ["all"], "timestamp": "",
        }

        report = executor.reversible_impact("h1")

        assert report["integrity"] == "restored_verified"
        assert sentinel.read_bytes() == b"vital"
        assert report["impact"].get("failed")  # impact failure recorded

    def test_missing_sensitive_file_is_reported(self, tmp_path):
        executor = DestructionExecutor(
            warlog=make_warlog(tmp_path), crypto=Crypto(),
            sensitive_files=[str(tmp_path / "gone")], reversible=True,
            staging_root=tmp_path / "staging",
        )
        executor._execute_step = lambda name, target: True
        report = executor.reversible_impact("h1")
        assert any("missing" in e for e in report["stage_errors"])
        assert report["integrity"] == "restored_verified"  # nothing to restore

    def test_restore_tampered_stage_retains_evidence(self, tmp_path):
        sentinel = tmp_path / "sensitive.txt"
        sentinel.write_bytes(b"vital")
        executor = DestructionExecutor(
            warlog=make_warlog(tmp_path), crypto=Crypto(),
            sensitive_files=[str(sentinel)], reversible=True,
            staging_root=tmp_path / "staging",
        )

        # Simulate an adversary tampering with the staged copy *during*
        # the impact phase — exactly the window between sandbox and prove.
        def corrupting_sequence(target):
            stage = executor.staging_root / "sensitive.txt.enc.json"
            blob = json.loads(stage.read_text())
            blob["ciphertext"] = "A" * len(blob["ciphertext"])
            stage.write_text(json.dumps(blob))
            return {"target": target, "steps": {}, "completed": [],
                    "failed": ["x"], "timestamp": ""}

        executor.execute_destruction_sequence = corrupting_sequence

        report = executor.reversible_impact("h1")

        assert report["integrity"] == "stage_retained"
        assert report["restore_failures"]
        assert executor._evidence_id in report["evidence_id"]
        assert (executor.staging_root / "sensitive.txt.enc.json").exists()
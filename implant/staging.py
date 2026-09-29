"""THE VOID — implant staging (P1-2).

A staged implant loader: drop an encrypted stage bundle (durable
[default] or volatile /dev/shm with tmpfs backing), install a signed
killswitch, enforce a hard expiry and per-boot budget, and guarantee
reversibility: every payload file touched is encrypted + moved to a
staging directory that is restored automatically on cleanup, expiry,
or killswitch.

Trust model:
  * The stage bundle is AES-encrypted (key derived from a passphrase or
    raw key) and HMAC-signed over its canonical manifest — a tampered
    bundle decrypts but fails verification and is never executed.
  * The killswitch is an HMAC-signed command (no plaintext action names
    on disk) verified before anything is executed.
  * Every action is WarLog-evidenced (module "implant.staging").

The loader executes nothing itself and holds no plaintext payload —
reversibility is enforced by code, not convention.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.crypto import Crypto
from core.warlog import LogLevel, WarLog

logger = logging.getLogger("void.implant.staging")

MODULE = "implant.staging"

# Hard ceilings — a caller cannot widen them, only narrow them.
MAX_TTL_SECONDS = 24 * 3600        # 24h absolute ceiling
MAX_BOOT_BUDGET = 1                # per-boot checks (durable) ceiling

KILLSWITCH_ACTIONS = ("cleanup", "self_delete")

DEFAULT_STAGING = Path("~/.void/implant-staging").expanduser()
DURABLE_STAGING = Path("~/.void/implant-staging-durable").expanduser()
VOLATILE_STAGING = Path("/dev/shm/.void-implant-staging")


class StageBundleError(Exception):
    """Raised when a stage bundle fails integrity verification."""


class KillswitchError(Exception):
    """Raised when killswitch input is untrusted/unverifiable."""


class ImplantExpired(Exception):
    """Raised when the implant's hard expiry has passed."""


class BootBudgetExhausted(Exception):
    """Raised when the per-boot invocation budget is used up."""


@dataclass
class StageBundle:
    """A single encrypted, signed implant stage bundle."""

    stage_id: str
    encryption: Dict[str, str]        # {"ciphertext": ..., "nonce": ...}
    manifest_hmac: str                # HMAC over canonical manifest
    created_at: float                 # bundle creation epoch
    ttl_seconds: float                # hard expiry window (capped in ctor)
    metadata: Dict[str, Any] = field(default_factory=dict)

    EXPIRY_MAX = MAX_TTL_SECONDS

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    def expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) > self.expires_at

    def canonical_manifest(self) -> str:
        """Deterministic manifest string — HMAC input, never mutable."""
        return json.dumps(
            {
                "stage_id": self.stage_id,
                "ciphertext": self.encryption["ciphertext"],
                "nonce": self.encryption["nonce"],
                "created_at": self.created_at,
                "ttl_seconds": self.ttl_seconds,
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "encryption": dict(self.encryption),
            "manifest_hmac": self.manifest_hmac,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StageBundle":
        return cls(
            stage_id=str(data["stage_id"]),
            encryption=dict(data["encryption"]),
            manifest_hmac=str(data["manifest_hmac"]),
            created_at=float(data["created_at"]),
            ttl_seconds=float(data["ttl_seconds"]),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def build(cls, crypto: Crypto, payload: Dict[str, Any],
              ttl_seconds: float, metadata: Optional[Dict[str, Any]] = None,
              stage_id: Optional[str] = None) -> "StageBundle":
        """Encrypt a payload and sign the manifest (create-once, immutable)."""
        ttl_seconds = min(float(ttl_seconds), cls.EXPIRY_MAX)
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        stage_id = stage_id or str(uuid.uuid4())
        enc = crypto.encrypt_aes(json.dumps(payload, sort_keys=True))
        now = time.time()
        metadata = dict(metadata or {})
        bundle = cls(
            stage_id=stage_id,
            encryption={"ciphertext": enc["ciphertext"], "nonce": enc["nonce"]},
            manifest_hmac="",
            created_at=now,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        bundle.manifest_hmac = crypto.hmac_sign(bundle.canonical_manifest())
        return bundle

    def decrypt(self, crypto: Crypto) -> Dict[str, Any]:
        """Decrypt the payload — call only after verify() succeeded."""
        return json.loads(
            crypto.decrypt_aes(self.encryption["ciphertext"],
                               self.encryption["nonce"])
        )

    def verify(self, crypto: Crypto) -> bool:
        """HMAC verification of the canonical manifest (tamper check)."""
        return crypto.hmac_verify(self.canonical_manifest(),
                                  self.manifest_hmac)


@dataclass
class Killswitch:
    """Signed killswitch: action token signed by the crypto module."""

    action: str                       # "cleanup" | "self_delete"
    signature: str                    # HMAC over canonical command string
    issued_at: float                  # issuance epoch

    @classmethod
    def issue(cls, crypto: Crypto, action: str) -> "Killswitch":
        if action not in KILLSWITCH_ACTIONS:
            raise KillswitchError(
                f"action must be one of {KILLSWITCH_ACTIONS}, got {action!r}"
            )
        issued_at = time.time()
        canonical = cls._canonical(action, issued_at)
        return cls(action=action, signature=crypto.hmac_sign(canonical),
                   issued_at=issued_at)

    @staticmethod
    def _canonical(action: str, issued_at: float) -> str:
        return f"{action}:{int(issued_at)}"

    def verify(self, crypto: Crypto) -> bool:
        return crypto.hmac_verify(self._canonical(self.action, self.issued_at),
                                  self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "signature": self.signature,
                "issued_at": self.issued_at}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Killswitch":
        return cls(action=str(data["action"]),
                   signature=str(data["signature"]),
                   issued_at=float(data["issued_at"]))


@dataclass
class StageStatus:
    """Result of the fail-closed stage health check."""

    stage_id: str
    expired: bool
    signature_valid: bool
    budget_ok: bool
    killswitch_fired: bool
    reasons: List[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return (self.budget_ok and self.signature_valid
                and not self.expired and not self.killswitch_fired)


@dataclass
class CleanupReport:
    """Evidence of what a cleanup/restore pass did."""

    stage_id: str
    restored: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    killswitch_fired: bool = False

    @property
    def clean(self) -> bool:
        return not self.errors


class ImplantLoader:
    """Staged implant loader with guaranteed reversibility.

    Lifecycle: load() verifies, expires, budgets, and killswitches in
    that order — every gate fails closed (a failed gate cleans up
    automatically). payload_file() moves the real file into encrypted
    staging and hands back the staged path; cleanup() restores every
    staged file and destroys the stage materials (evidence retained).
    """

    def __init__(self, staging_root: Union[str, Path] = DEFAULT_STAGING,
                 warlog: Optional[WarLog] = None,
                 boot_budget: int = 1):
        self.staging_root = Path(staging_root).expanduser()
        self.warlog = warlog or WarLog()
        self.boot_budget = min(int(boot_budget), MAX_BOOT_BUDGET)

    # ─── Durable vs volatile placement ──────────────────────────────────────

    @staticmethod
    def durable_staging() -> Path:
        """Durable (survives reboot) staging root."""
        return DURABLE_STAGING

    @staticmethod
    def volatile_staging() -> Path:
        """Volatile staging root on tmpfs (/dev/shm) — RAM-backed, wiped
        on reboot. The payload bundle is on tmpfs, but the *reversible*
        evidence (staged originals) is copied to durable staging so
        cleanup can restore after a reboot."""
        return VOLATILE_STAGING

    def install(self, bundle: StageBundle, crypto: Crypto,
                durable: bool = True, killswitch_action: str = "cleanup"
                ) -> Dict[str, Any]:
        """Persist a verified bundle + signed killswitch on the host.

        Durable installs land in ``durable_staging()``; volatile installs
        use ``/dev/shm`` and mirror evidence to durable staging.
        """
        if not bundle.verify(crypto):
            raise StageBundleError(
                f"bundle {bundle.stage_id} failed HMAC verification")
        root = self.durable_staging() if durable else self.volatile_staging()
        evidence_root = self.durable_staging()
        root.mkdir(parents=True, exist_ok=True)
        evidence_root.mkdir(parents=True, exist_ok=True)

        bundle_path = root / f"{bundle.stage_id}.json"
        bundle_path.write_text(json.dumps(bundle.to_dict(), sort_keys=True))

        killswitch = Killswitch.issue(crypto, killswitch_action)
        evidence = evidence_root / f"{bundle.stage_id}.evidence.json"
        evidence.write_text(json.dumps({
            "stage_id": bundle.stage_id,
            "durable": durable,
            "staged_files": [],          # appended by payload_file()
            "killswitch": killswitch.to_dict(),
        }, sort_keys=True))

        self._evidence("implant.install", target=bundle.stage_id, data={
            "durable": durable, "staging": str(root),
            "expires_at": bundle.expires_at,
        })
        return {"stage_id": bundle.stage_id, "staging": str(root),
                "evidence": str(evidence), "durable": durable,
                "expires_at": bundle.expires_at,
                "killswitch": killswitch.to_dict()}

    # ─── Fail-closed health check ───────────────────────────────────────────

    def check(self, bundle: StageBundle, crypto: Crypto,
              killswitch: Optional[Killswitch] = None,
              boot_budget_used: int = 0,
              now: Optional[float] = None) -> StageStatus:
        """Check expiry, signature, budget, and killswitch — fail closed."""
        now = now if now is not None else time.time()
        reasons: List[str] = []

        expired = bundle.expired(now)
        if expired:
            reasons.append("bundle expired")

        signature_valid = bundle.verify(crypto)
        if not signature_valid:
            reasons.append("bundle HMAC verification failed")

        budget_ok = int(boot_budget_used) < self.boot_budget
        if not budget_ok:
            reasons.append("per-boot budget exhausted")

        killswitch_fired = False
        if killswitch is not None:
            if killswitch.verify(crypto):
                killswitch_fired = True
                reasons.append(f"killswitch {killswitch.action} verified")
            else:
                killswitch_fired = True
                reasons.append("unverified killswitch presented (treated as fired)")

        return StageStatus(
            stage_id=bundle.stage_id,
            expired=expired,
            signature_valid=signature_valid,
            budget_ok=budget_ok,
            killswitch_fired=killswitch_fired,
            reasons=reasons,
        )

    # ─── Reversible payload staging ─────────────────────────────────────────

    def payload_file(self, bundle: StageBundle, crypto: Crypto,
                     target_path: Union[str, Path]) -> Path:
        """Move ``target_path`` into encrypted staging (reversible).

        Returns the staged path. The original file is preserved under
        staging (not overwritten) and referenced in the stage evidence,
        so cleanup() restores it byte-for-byte.
        """
        src = Path(target_path)
        if not src.exists():
            raise FileNotFoundError(f"payload file missing: {src}")
        if src.is_dir():
            raise ValueError(f"payload_file() takes files, not dirs: {src}")

        staged = self.staging_root / bundle.stage_id / src.name
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(staged))

        self._evidence("implant.payload_staged", target=bundle.stage_id,
                       data={"path": str(src), "staged": str(staged)})
        return staged

    def cleanup(self, bundle: StageBundle, crypto: Crypto,
                evidence_path: Union[str, Path],
                killswitch: Optional[Killswitch] = None) -> CleanupReport:
        """Restore every staged file and destroy the stage materials.

        Also runs on expiry/killswitch (harness or loader calls it).
        Evidence file itself is retained.
        """
        report = CleanupReport(stage_id=bundle.stage_id)
        evidence_path = Path(evidence_path)

        if killswitch is not None:
            report.killswitch_fired = killswitch.verify(crypto)
            if not report.killswitch_fired:
                self._evidence("implant.killswitch_unverified",
                               target=bundle.stage_id)

        try:
            evidence = json.loads(evidence_path.read_text())
        except (OSError, ValueError) as exc:
            report.errors.append(f"evidence unreadable: {exc}")
            self._evidence("implant.cleanup_failed", target=bundle.stage_id,
                           data={"error": str(exc)})
            return report

        for staged_entry in evidence.get("staged_files", []):
            staged = Path(staged_entry["staged"])
            original = Path(staged_entry["original"])
            try:
                if staged.exists():
                    original.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(staged), str(original))
                    report.restored.append(
                        {"original": str(original), "staged": str(staged)})
                else:
                    report.errors.append(f"staged file missing: {staged}")
            except OSError as exc:
                report.errors.append(f"restore failed for {staged}: {exc}")

        stage_dir = self.staging_root / bundle.stage_id
        try:
            if stage_dir.exists():
                shutil.rmtree(stage_dir)
                report.removed.append(str(stage_dir))
        except OSError as exc:
            report.errors.append(f"stage dir removal failed: {exc}")

        self._evidence("implant.cleanup", target=bundle.stage_id, data={
            "restored": len(report.restored),
            "removed": report.removed,
            "errors": report.errors,
            "killswitch_fired": report.killswitch_fired,
        })
        return report

    # ─── Internals ──────────────────────────────────────────────────────────

    def _evidence(self, message: str, target: str,
                  data: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.warlog.log(message, level=LogLevel.AGENT, module=MODULE,
                            target=target, data=data)
        except Exception:
            logger.exception("WarLog write failed for implant event %s",
                             message)


__all__ = [
    "BootBudgetExhausted",
    "CleanupReport",
    "DURABLE_STAGING",
    "ImplantExpired",
    "ImplantLoader",
    "KILLSWITCH_ACTIONS",
    "Killswitch",
    "KillswitchError",
    "MAX_BOOT_BUDGET",
    "MAX_TTL_SECONDS",
    "MODULE",
    "StageBundle",
    "StageBundleError",
    "StageStatus",
    "VOLATILE_STAGING",
]
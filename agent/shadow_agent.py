"""THE VOID — Frosty agent execution runtime.

The implementation retains the ``ShadowAgent`` class name for API
compatibility. All execution remains subject to operator authorization and
configured scope.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from core.executor import Executor
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog, LogLevel
from core.stealth import Stealth
from core.crypto import Crypto
from config.settings import Settings

from agent.injection_defense import InjectionDefense

from recon.osint import OSINT
from recon.portscan import PortScan
from recon.webrecon import WebRecon
from recon.hostenum import HostEnum

from exploit.credattack import CredAttack
from exploit.smbad import SMBAD
from exploit.vulnscan import VulnScan
from exploit.webexploit import WebExploit

# CVE exploits
from exploit.cve_2026_32202 import CVE2026_32202
from exploit.cve_2026_41940 import CVE2026_41940
from exploit.cve_2026_41089 import CVE2026_41089
from exploit.cve_2025_55182 import CVE2025_55182

# Attack modules
from exploit.zero_click_automation import ZeroClickAutomation
from exploit.destruction_executor import DestructionExecutor
from exploit.k8s_container_attack import K8sExploit
from exploit.wireless_iot_attack import WirelessIoTAttack

# Cloud attacks
from exploit.aws_cloud_attack import AWSExploit
from exploit.azure_cloud_attack import AzureExploit
from exploit.gcp_cloud_attack import GCPExploit

# Crypto + JBFuzz + Persistent exfil
from exploit.crypto_theft_pipeline import CryptoTheftPipeline
from exploit.llm_jailbreak_jbfuzz import JBFuzz
from exploit.persistent_exfil import PersistentExfilPipeline

from modules.datatheft import DataTheft
from modules.llm_jailbreak import LLMJailbreak
from modules.network_bypass import NetworkBypass

from c2.daemon import C2Daemon
from c2.beacon import Beacon
from c2.commands import C2Commands
from c2.mcp_c2 import MCPC2

# MCP attack modules
from exploit.mcp_attack import MCPAttack
from agent.mcp_chain import MCPChain

# MCP vulnerability scanner — imported via path injection at runtime
# (see _ensure_mcp_scanner_path in __init__)
MCPScanner = None
MCPScannerImportError = None


logger = logging.getLogger("void.agent")


# ─── Attack-path persistence (W3) ───────────────────────────────────────────
# Maps each engagement phase to the Boneyard attack_paths ``step_type`` enum
# (initial_access | privesc | lateral | persist | exfil | c2) and the
# ``outcomes.outcome_type`` enum (access | credential | data | privilege |
# persistence | detection). These are honest kill-chain buckets — a phase that
# doesn't fit is mapped to the closest real bucket, never invented.
PHASE_TO_STEP_TYPE: Dict[str, str] = {
    "recon": "initial_access",        # first touch / discovery → foothold prep
    "exploit": "initial_access",      # exploitation achieves initial access
    "llm_jailbreak": "initial_access",
    "zero_click": "initial_access",
    "datatheft": "exfil",             # data theft → exfiltration
    "network_bypass": "lateral",      # pivot / bypass to reach others
    "mcp_chain": "lateral",           # tool chaining expands reach
    "mcp_c2": "c2",                   # command & control
    "destruction": "persist",         # impact/entrenchment → persistence bucket
}

PHASE_TO_OUTCOME_TYPE: Dict[str, str] = {
    "recon": "access",
    "exploit": "access",
    "llm_jailbreak": "access",
    "zero_click": "access",
    "datatheft": "data",
    "network_bypass": "access",
    "mcp_chain": "privilege",
    "mcp_c2": "persistence",
    "destruction": "persistence",
}


def _looks_like_ip(value: str) -> bool:
    """True when a target value parses as a dotted-quad IPv4 address."""
    try:
        import ipaddress
        ipaddress.IPv4Address(str(value).strip())
        return True
    except Exception:
        return False


class ShadowAgent:
    """Frosty's compatibility runtime for authorized security validation.

    The class performs configured reconnaissance and validation phases while
    preserving authorization, phase-deny, and audit controls.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.name = self.settings.get("AGENT_NAME", "Frosty")
        self.executor = Executor()
        self.boneyard = Boneyard()
        self.warlog = WarLog()
        self.stealth = Stealth()
        self.crypto = Crypto()

        # Recon modules
        self.osint = OSINT(self.executor)
        self.portscan = PortScan(self.executor)
        self.webrecon = WebRecon(self.executor)
        self.hostenum = HostEnum(self.executor)

        # Exploit modules
        self.credattack = CredAttack(self.executor)
        self.smbad = SMBAD(self.executor)
        self.vulnscan = VulnScan(self.executor)
        self.webexploit = WebExploit(self.executor)

        # CVE exploit modules
        self.cve_2026_32202 = CVE2026_32202(self.executor)
        self.cve_2026_41940 = CVE2026_41940(self.executor)
        self.cve_2026_41089 = CVE2026_41089(self.executor)
        self.cve_2025_55182 = CVE2025_55182(self.executor)

        # Attack modules
        self.zero_click = ZeroClickAutomation(self.executor)
        self.destruction = DestructionExecutor(self.executor)
        self.k8s_attack = K8sExploit(self.executor)
        self.wireless_iot = WirelessIoTAttack(self.executor)

        # Cloud attack modules
        self.aws_exploit = AWSExploit(self.executor)
        self.azure_exploit = AzureExploit(self.executor)
        self.gcp_exploit = GCPExploit(self.executor)

        # Crypto theft + exfil modules
        self.crypto_theft = CryptoTheftPipeline(self.executor)
        self.persistent_exfil = PersistentExfilPipeline(self.executor)

        # LLM jailbreak modules (JBFuzz/PyRIT/Garak)
        self.jbfuzz = JBFuzz(self.executor)
        self.llm_jailbreak = LLMJailbreak(self.executor)

        # Core modules
        self.datatheft = DataTheft(self.executor, self.boneyard)
        self.network_bypass = NetworkBypass(self.executor)

        # MCP vulnerability scanner (optional — may fail to import)
        self.mcp_scanner = self._init_mcp_scanner()

        # Injection defense
        self.defense = InjectionDefense(warlog=self.warlog)

        # C2 modules
        self.c2_daemon = C2Daemon()
        self.beacons: Dict[str, Beacon] = {}
        self.c2_commands = C2Commands(self.executor, self.crypto)

        # MCP attack modules
        self.mcp_attack = MCPAttack(
            executor=self.executor, boneyard=self.boneyard, warlog=self.warlog,
        )
        self.mcp_c2 = MCPC2(
            executor=self.executor, boneyard=self.boneyard, warlog=self.warlog,
        )
        self.mcp_chain = MCPChain(
            executor=self.executor, boneyard=self.boneyard, warlog=self.warlog,
        )

        # State
        self.targets: List[Target] = []
        self.active_sessions: Dict[str, Any] = {}
        self.stolen_data: List[Dict[str, Any]] = []
        self.attack_log: List[Dict[str, Any]] = []
        self.engaged = False

        # Scenario override (roadmap R-6): when set to a scenario name
        # from `scenarios/`, engage() runs its phase list INSTEAD of the
        # mode-derived list from MODE_PHASES. Scenario influence ends here;
        # phases_for_mode() embodies the fallback. A None string means off.
        self.scenario: Optional[str] = None
        self._scenario_library = None  # lazy import — breaks circularity
        self._scenario_phases: Optional[List[str]] = None
        self._scenario_registry: Optional[Dict[str, Any]] = None

        # Governance hooks (set by ChaosEngine when authz/profile is active)
        self.authz = None  # Optional[AuthorizationGate]
        # Default-deny high-risk phases: every engagement starts with the
        # configured high-risk phase set denied (client-safety contract,
        # hardened in 8ad2cf0). Callers that need the full phase list clear
        # this set explicitly (e.g. authorized lab profiles, tests).
        if self.settings.get("DENY_HIGH_RISK_PHASES", True):
            self.extra_denied_phases: set = set(
                self.settings.get("HIGH_RISK_PHASES") or []
            )
        else:
            self.extra_denied_phases = set()

        # Phase-progress observer (W4-2.2a). Optional callable receiving
        # phase lifecycle events during engage():
        #   {"event": "phase_start", "phase": str, "index": int, "total": int,
        #    "target": str, "mode": str}
        #   {"event": "phase_end",   "phase": str, "index": int, "total": int,
        #    "target": str, "mode": str, "ok": bool, "error": str|None}
        #   {"event": "engage_end",  "target": str, "mode": str, "status": str}
        # Exceptions raised by the listener are swallowed (never break the
        # engagement). Default None = no-op. Set by the CLI's rich.Live tracker.
        self._phase_listener: Optional[Any] = None

        logger.info("%s initialized — ready for authorized engagement", self.name)

    def set_phase_listener(self, listener: Optional[Any]) -> None:
        """Attach/detach a phase-progress observer.

        Pass None to clear. The listener is advisory only — it must not
        influence engagement outcome, and its exceptions are never allowed
        to propagate into the engagement loop.
        """
        self._phase_listener = listener

    def _emit_phase_event(self, event: Dict[str, Any]) -> None:
        """Deliver a phase event to the listener, swallowing listener errors.

        Uses ``getattr`` so instances created without ``__init__`` (some
        tests) never raise AttributeError.
        """
        listener = getattr(self, "_phase_listener", None)
        if listener is None:
            return
        try:
            listener(event)
        except Exception:  # noqa: BLE001 — observer must never break engage
            pass

    def _init_mcp_scanner(self):
        """Import and instantiate the MCP vulnerability scanner.

        The scanner lives in mcp-tools/mcp-scanner/src/ and is loaded via
        path injection. If the import fails (missing dependencies or
        sandbox restrictions), the attribute is set to None and the
        absence is logged — other phases proceed normally.
        """
        try:
            import importlib
            import sys as _sys
            scanner_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "mcp-tools", "mcp-scanner"
            )
            pkg_dir = os.path.join(scanner_dir, "src")
            if pkg_dir not in _sys.path:
                _sys.path.insert(0, pkg_dir)
            # Import as top-level modules from the src directory
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "mcp_scanner_pkg",
                os.path.join(pkg_dir, "__init__.py"),
            )
            if spec is None or spec.loader is None:
                raise ImportError("Could not create module spec for MCP scanner")
            mod = importlib.util.module_from_spec(spec)
            _sys.modules["mcp_scanner_pkg"] = mod
            spec.loader.exec_module(mod)
            scanner_cls = getattr(mod, "Scanner", None)
            if scanner_cls is None:
                raise ImportError("Scanner class not found in MCP scanner package")
            instance = scanner_cls()
            logger.info("MCP vulnerability scanner loaded")
            return instance
        except Exception as e:
            logger.warning(f"MCP vulnerability scanner unavailable: {e}")
            return None


    # ─── Injection Defense Helpers ────────────────────────────────────────

    def _sanitize_output(self, output: Any, source: str = "unknown") -> Any:
        """Sanitize a tool output through the injection defense pipeline.

        If output is a string, runs it through defense.sanitize().
        If output is a dict, recursively sanitizes string values.
        Returns the sanitized output, or the original if defense is disabled.
        """
        if not self.defense.enabled:
            return output

        if isinstance(output, str):
            result = self.defense.sanitize(output, source=source)
            if result.is_quarantined:
                return {"_quarantined": True, "_reason": result.quarantine.reason,
                        "_sanitized": result.sanitized[:200] if result.safe else ""}
            return result.sanitized
        elif isinstance(output, dict):
            sanitized = {}
            for k, v in output.items():
                if isinstance(v, str):
                    result = self.defense.sanitize(v, source=f"{source}.{k}")
                    if result.is_quarantined:
                        sanitized[k] = {"_quarantined": True, "_reason": result.quarantine.reason}
                    else:
                        sanitized[k] = result.sanitized
                else:
                    sanitized[k] = v
            return sanitized
        elif isinstance(output, list):
            return [self._sanitize_output(item, source=f"{source}[{i}]")
                    for i, item in enumerate(output)]
        return output

    def _validate_action(self, action: Any, sanitized_context: Any = None) -> bool:
        """Validate a proposed action through the injection defense pipeline.

        Returns True if approved, False if denied.
        Logs denial to warlog on rejection.
        """
        if not self.defense.enabled:
            return True
        result = self.defense.validate_action(action, sanitized_context=sanitized_context)
        if not result.approved:
            logger.warning(f"Injection defense denied action: {result.reason}")
        return result.approved

    # ─── Target Management ───────────────────────────────────────────────

    def add_target(self, target: Target) -> None:
        """Add a target."""
        self.targets.append(target)
        self.warlog.log("Target acquired", level=LogLevel.AGENT, target=target.name)
        logger.info(f"Target acquired: {target.name}")

    def remove_target(self, target: Target) -> None:
        """Remove a target."""
        self.targets.remove(target)
        logger.info(f"Target removed: {target.name}")

    def get_target(self, name: str) -> Optional[Target]:
        """Get a target by name."""
        for t in self.targets:
            if t.name == name:
                return t
        return None

    # ─── Engagement ──────────────────────────────────────────────────────

    # Mode → phase names. "quick" is recon-only (safe default for demos).
    MODE_PHASES: Dict[str, List[str]] = {
        "quick": ["recon"],
        "stealth": ["recon", "exploit", "network_bypass", "mcp_scan"],
        "full": [
            "recon", "exploit", "data_theft", "llm_jailbreak",
            "network_bypass", "c2", "mcp_scan", "mcp_attack", "mcp_chain",
        ],
        "aggressive": [
            "recon", "exploit", "data_theft", "llm_jailbreak",
            "network_bypass", "c2", "cloud_attack", "k8s_attack",
            "cve_exploit", "mcp_scan", "mcp_attack", "mcp_chain", "mcp_c2",
            "advanced_jailbreak",
        ],
        "chaos": [
            "recon", "exploit", "data_theft", "llm_jailbreak",
            "network_bypass", "c2", "cloud_attack", "crypto_theft",
            "persistent_exfil", "zero_click", "k8s_attack", "wireless_iot",
            "advanced_jailbreak", "cve_exploit", "destruction",
            "mcp_scan", "mcp_attack", "mcp_chain", "mcp_c2",
        ],
    }

    def phases_for_mode(self, mode: str) -> List[str]:
        """Return the ordered phase list for *mode*, after deny filters.

        If a scenario is active (``self.scenario`` set via the catalog),
        its phase list replaces the mode-derived list; deny filters still
        apply afterward so authorization / ROE ordering is preserved.
        """
        if self.scenario is not None:
            if self._scenario_phases is None:
                lib = self._load_scenario_library()
                setattr(self, "_scenario_phases", lib.get_phases(self.scenario))
            phases = list(self._scenario_phases) if self._scenario_phases else []
        else:
            phases = list(self.MODE_PHASES.get(mode, self.MODE_PHASES["full"]))
        if self.extra_denied_phases:
            phases = [p for p in phases if p not in self.extra_denied_phases]
        if self.authz is not None:
            phases = self.authz.filter_phases(phases)
        return phases

    def _load_scenario_library(self):
        """Lazy-import the scenarios package (R-6) so this module isn't a hard
        dependency of the catalog and vice versa."""
        if self._scenario_library is None:
            from scenarios import scenario_library as lib
            self._scenario_library = lib
        return self._scenario_library

    def set_scenario(self, scenario_name: Optional[str]) -> None:
        """Enable/disable a scenario override for subsequent engage() calls.

        Passing None disables the override — returns to mode-driven phase
        selection. The scenario is *resolved* eagerly to fail-fast on
        misspellings, and its phases cached so scenarios are stable across
        an operator session.
        """
        if scenario_name is None:
            self.scenario = None
            self._scenario_phases = None
            return
        lib = self._load_scenario_library()
        sc = lib.get(scenario_name)
        self.scenario = sc.name
        self._scenario_phases = list(sc.phases)
        logger.info("Scenario engaged: %s (phases=%s)", sc.name, sc.phases)

    def get_scenario(self) -> Optional[Dict[str, Any]]:
        """Return the active scenario as a dict, or None."""
        if self.scenario is None:
            return None
        sc = self._load_scenario_library().get(self.scenario)
        return {
            "name": sc.name,
            "description": sc.description,
            "phases": list(sc.phases),
            "version": sc.version,
            "mitre_techniques": list(sc.mitre_techniques),
        }

    def engage(self, target: Target, mode: str = "full") -> Dict[str, Any]:
        """Engage a target under the selected mode.

        Args:
            target: The target to engage
            mode: Engagement mode (quick, full, aggressive, stealth, chaos)

        Returns:
            Dict with engagement findings
        """
        logger.info(f"Engaging target: {target.name} (mode={mode})")
        self.warlog.log(
            f"ENGAGING target in {mode} mode",
            level=LogLevel.AGENT, target=target.name,
        )
        self.engaged = True
        start_time = time.time()

        planned = self.phases_for_mode(mode)

        # W4-2.2a: announce the engagement to the phase listener (rich.Live).
        # Emitted BEFORE the pre-flight gate so event ordering is consistent
        # even when the engagement is denied pre-flight.
        self._emit_phase_event({
            "event": "engage_start", "target": target.name, "mode": mode,
            "phases": list(planned), "total": len(planned),
        })

        # ── Pre-flight injection / action gate (BEFORE any phase runs) ──
        action_plan = {
            "action": "engage",
            "mode": mode,
            "target": target.value,
            "phases": planned,
        }
        if not self._validate_action(action_plan):
            reason = "injection defense denied engagement pre-flight"
            self.warlog.log(
                reason, level=LogLevel.WARNING, target=target.name,
            )
            self.engaged = False
            self._emit_phase_event({
                "event": "engage_end", "target": target.name, "mode": mode,
                "status": "denied",
            })
            return {
                "target": target.name,
                "mode": mode,
                "status": "denied",
                "reason": reason,
                "planned_phases": planned,
                "findings": {},
                "elapsed": round(time.time() - start_time, 2),
            }

        findings: Dict[str, Any] = {
            "target": target.name,
            "mode": mode,
            "started_at": start_time,
            "planned_phases": planned,
            "findings": {},
        }

        # Phase dispatch — consulted through the phase registry (R-7).
        # Behavior preserved: resolve() re-binds the agent reference per
        # call and invokes the same private helpers the old inline lambda
        # table used to invoke, including the mcp_chain/mcp_c2 context
        # hand-off. Returned stubs mirror the legacy "unknown phase" error.
        # Import lazily so this module can never be a hard dependency of
        # anything that would otherwise only need enum names (Arnofog).
        if not hasattr(self, "_phase_registry"):
            from agent.phase_registry import PhaseRegistry
            self._phase_registry = PhaseRegistry()

        phase_runners = {
            name: lambda n=name: (
                self._phase_registry.resolve(n)(self, target, mode, findings)
            )
            for name in self._phase_registry.phases
        }

        # W3: persist this engagement's attack path into the Boneyard so the
        # Command Center Attack Graph + kill-chain timeline reflect REAL data
        # (never synthesized). One host row anchors the chain; each phase
        # becomes a step chained to the previous one. Failures here must never
        # break the engagement.
        attack_path_root = None
        parent_step_id = None
        try:
            attack_path_root = self.boneyard.ensure_host(
                ip=target.value if _looks_like_ip(target.value) else "",
                hostname=target.name,
                data={"engagement_target": target.value, "mode": mode},
            )
        except Exception as e:
            logger.warning("ensure_host failed (%s); attack path not persisted", e)
            attack_path_root = None

        for idx, phase in enumerate(planned, start=1):
            runner = phase_runners.get(phase)
            if runner is None:
                findings["findings"][phase] = {"error": f"unknown phase: {phase}"}
                self._emit_phase_event({
                    "event": "phase_end", "phase": phase,
                    "index": idx, "total": len(planned),
                    "target": target.name, "mode": mode,
                    "ok": False, "error": f"unknown phase: {phase}",
                })
                continue

            # Per-phase action validation (denylist on real phase name)
            if not self._validate_action(
                {"action": "phase", "phase": phase, "target": target.value, "mode": mode}
            ):
                findings["findings"][phase] = {
                    "skipped": True,
                    "reason": "denied by injection defense",
                }
                logger.warning("Phase %s denied by injection defense", phase)
                self._emit_phase_event({
                    "event": "phase_end", "phase": phase,
                    "index": idx, "total": len(planned),
                    "target": target.name, "mode": mode,
                    "ok": False, "error": "denied by injection defense",
                })
                continue

            logger.info("Phase %d/%d: %s", idx, len(planned), phase)
            self._emit_phase_event({
                "event": "phase_start", "phase": phase,
                "index": idx, "total": len(planned),
                "target": target.name, "mode": mode,
            })
            phase_error = None
            try:
                findings["findings"][phase] = self._sanitize_output(
                    runner(), source=f"{phase}.{target.name}",
                )
            except Exception as e:
                phase_error = str(e)
                findings["findings"][phase] = {"error": str(e)}
            self._emit_phase_event({
                "event": "phase_end", "phase": phase,
                "index": idx, "total": len(planned),
                "target": target.name, "mode": mode,
                "ok": phase_error is None, "error": phase_error,
            })

            # W3: record the phase as an attack-path step + outcome, and chain
            # the next phase to it. Never raises (logging-only fallback).
            new_step_id = self._record_phase_step(
                host_id=attack_path_root,
                phase=phase,
                result=findings["findings"][phase],
                error=phase_error,
                parent_step_id=parent_step_id,
            )
            if new_step_id:
                parent_step_id = new_step_id

        # Final sanitization of the full findings dict
        findings = self._sanitize_output(
            findings, source=f"engage_full.{target.name}",
        )

        elapsed = time.time() - start_time
        findings["elapsed"] = round(elapsed, 2)
        findings["status"] = "completed"

        self.warlog.log(
            f"Engagement completed in {elapsed:.2f}s",
            level=LogLevel.AGENT, target=target.name,
        )
        self.attack_log.append(findings)
        self.boneyard.store(f"attack_{target.name}_{int(time.time())}", findings)
        self.engaged = False
        self._emit_phase_event({
            "event": "engage_end", "target": target.name, "mode": mode,
            "status": "completed", "elapsed": findings["elapsed"],
        })
        return findings

    def engage_all(self, mode: str = "full") -> Dict[str, Any]:
        """Engage all targets.

        Args:
            mode: Engagement mode

        Returns:
            Dict with engagement findings for all targets
        """
        results = {}
        for target in self.targets:
            results[target.name] = self.engage(target, mode)
        return results

    def _record_phase_step(
        self,
        host_id: Optional[str],
        phase: str,
        result: Dict[str, Any],
        error: Optional[str],
        parent_step_id: Optional[str],
    ) -> Optional[str]:
        """Persist one engagement phase as an attack-path step + outcome.

        Honest mapping: recon/exploit phases bucket to ``initial_access``
        steps with an ``access`` outcome; datatheft buckets to ``exfil``/
        ``data``; etc. ``outcome_status`` is ``failed`` only when the phase
        raised or returned an ``error`` key; otherwise ``attempted`` (we
        never invent a ``success`` verdict — the CoverageScorer decides
        verified/exploited/reachability downstream from real findings).

        Returns the new step id (to chain as the next parent), or None when
        persistence is unavailable or skipped. Never raises.
        """
        if not host_id:
            return None
        try:
            step_type = PHASE_TO_STEP_TYPE.get(phase, "initial_access")
            outcome_type = PHASE_TO_OUTCOME_TYPE.get(phase, "access")
            failed = error is not None or (
                isinstance(result, dict) and "error" in result
            )
            status = "failed" if failed else "attempted"

            # Tool/description are drawn from the real phase spec when the
            # registry has it, so the step reflects the actual runner.
            tool_used = ""
            technique = ""
            try:
                spec = self._phase_registry.spec(phase)
                if spec:
                    tool_used = getattr(spec, "member", "") or ""
                    technique = getattr(spec, "description", "") or ""
            except Exception:
                pass

            description = f"phase={phase} status={status}"
            if failed and error:
                description += f" error={str(error)[:200]}"

            step_id = self.boneyard.record_attack_step(
                host_id=host_id,
                step_type=step_type,
                technique=technique,
                description=description,
                parent_step_id=parent_step_id,
                outcome_status=status,
                detected_by="",
                tool_used=tool_used,
                duration_sec=0.0,
            )
            self.boneyard.record_outcome(
                attack_path_id=step_id,
                outcome_type=outcome_type,
                success=not failed,
                evidence={"phase": phase},
                output_raw="",
                mitigation="",
            )
            return step_id
        except Exception as e:
            logger.warning("record_attack_step failed for phase %s: %s", phase, e)
            return None

    # ─── Internal Phase Methods ──────────────────────────────────────────

    def _recon(self, target: Target, mode: str) -> Dict[str, Any]:
        """Perform reconnaissance."""
        if mode == "quick":
            return self._quick_recon(target)
        elif mode == "full":
            return self._full_recon(target)
        elif mode == "aggressive":
            return self._aggressive_recon(target)
        else:
            return self._quick_recon(target)

    def _quick_recon(self, target: Target) -> Dict[str, Any]:
        """Quick reconnaissance."""
        findings = {}
        try:
            findings["osint"] = self.osint.full_recon(target)
        except Exception as e:
            findings["osint"] = {"error": str(e)}
        try:
            findings["portscan"] = self.portscan.quick_scan(target)
        except Exception as e:
            findings["portscan"] = {"error": str(e)}
        return findings

    def _full_recon(self, target: Target) -> Dict[str, Any]:
        """Full reconnaissance."""
        findings = {}
        try:
            findings["osint"] = self.osint.full_recon(target)
        except Exception as e:
            findings["osint"] = {"error": str(e)}
        try:
            findings["portscan"] = self.portscan.full_scan(target)
        except Exception as e:
            findings["portscan"] = {"error": str(e)}
        try:
            findings["webrecon"] = self.webrecon.full_web_recon(target)
        except Exception as e:
            findings["webrecon"] = {"error": str(e)}
        try:
            findings["hostenum"] = self.hostenum.full_enum(target)
        except Exception as e:
            findings["hostenum"] = {"error": str(e)}
        return findings

    def _aggressive_recon(self, target: Target) -> Dict[str, Any]:
        """Aggressive reconnaissance."""
        findings = {}
        try:
            findings["osint"] = self.osint.full_recon(target)
        except Exception as e:
            findings["osint"] = {"error": str(e)}
        try:
            findings["portscan"] = self.portscan.aggressive_scan(target)
        except Exception as e:
            findings["portscan"] = {"error": str(e)}
        try:
            findings["webrecon"] = self.webrecon.full_web_recon(target)
        except Exception as e:
            findings["webrecon"] = {"error": str(e)}
        try:
            findings["hostenum"] = self.hostenum.full_enum(target)
        except Exception as e:
            findings["hostenum"] = {"error": str(e)}
        return findings

    def _exploit(self, target: Target, mode: str) -> Dict[str, Any]:
        """Perform exploitation."""
        findings = {}
        try:
            findings["cred_attack"] = self.credattack.hydra_bruteforce(target)
        except Exception as e:
            findings["cred_attack"] = {"error": str(e)}
        try:
            findings["smb"] = self.smbad.full_smb_attack(target)
        except Exception as e:
            findings["smb"] = {"error": str(e)}
        try:
            findings["vuln_scan"] = self.vulnscan.full_vuln_scan(target)
        except Exception as e:
            findings["vuln_scan"] = {"error": str(e)}
        try:
            findings["web_exploit"] = self.webexploit.full_web_exploit(target)
        except Exception as e:
            findings["web_exploit"] = {"error": str(e)}
        return findings

    def _steal_data(self, target: Target, mode: str) -> Dict[str, Any]:
        """Steal data from target."""
        findings = {}
        try:
            findings["exfil_file"] = self.datatheft.exfil_file(target, "/etc/passwd", "/tmp/")
        except Exception as e:
            findings["exfil_file"] = {"error": str(e)}
        try:
            findings["exfil_db"] = self.datatheft.exfil_database(target)
        except Exception as e:
            findings["exfil_db"] = {"error": str(e)}
        return findings

    def _jailbreak_llm(self, target: Target) -> Dict[str, Any]:
        """Jailbreak an LLM."""
        try:
            return self.llm_jailbreak.full_jailbreak_test(target)
        except Exception as e:
            return {"error": str(e)}

    def _bypass_network(self, target: Target) -> Dict[str, Any]:
        """Bypass network encryption."""
        try:
            return self.network_bypass.full_bypass(target)
        except Exception as e:
            return {"error": str(e)}

    def _setup_c2(self, target: Target) -> Dict[str, Any]:
        """Set up C2 channel."""
        try:
            beacon = Beacon()
            self.beacons[beacon.beacon_id] = beacon
            self.c2_daemon.register_beacon(beacon.beacon_id)
            return {"beacon_id": beacon.beacon_id, "status": "active"}
        except Exception as e:
            return {"error": str(e)}

    # ─── Cloud Attack ────────────────────────────────────────────────────

    def _cloud_attack(self, target: Target, mode: str) -> Dict[str, Any]:
        """Perform cloud infrastructure attacks (AWS, Azure, GCP)."""
        findings = {}

        # AWS
        try:
            findings["aws_scan"] = self.aws_exploit.scan()
        except Exception as e:
            findings["aws_scan"] = {"error": str(e)}
        try:
            findings["aws_iam_escalation"] = self.aws_exploit.exploit_iam_privilege_escalation()
        except Exception as e:
            findings["aws_iam_escalation"] = {"error": str(e)}
        try:
            findings["aws_metadata"] = self.aws_exploit.exploit_ec2_metadata_exposure()
        except Exception as e:
            findings["aws_metadata"] = {"error": str(e)}
        try:
            findings["aws_s3"] = self.aws_exploit.exploit_s3_bucket_public()
        except Exception as e:
            findings["aws_s3"] = {"error": str(e)}

        # Azure
        try:
            findings["azure_scan"] = self.azure_exploit.scan()
        except Exception as e:
            findings["azure_scan"] = {"error": str(e)}
        try:
            findings["azure_keyvault"] = self.azure_exploit.exploit_keyvault_secrets()
        except Exception as e:
            findings["azure_keyvault"] = {"error": str(e)}
        try:
            findings["azure_storage"] = self.azure_exploit.exploit_storage_account_misconfig()
        except Exception as e:
            findings["azure_storage"] = {"error": str(e)}
        try:
            findings["azure_aks"] = self.azure_exploit.exploit_aks_kubernetes_cluster()
        except Exception as e:
            findings["azure_aks"] = {"error": str(e)}

        # GCP
        try:
            findings["gcp_scan"] = self.gcp_exploit.scan()
        except Exception as e:
            findings["gcp_scan"] = {"error": str(e)}
        try:
            findings["gcp_storage"] = self.gcp_exploit.exploit_cloud_storage_public()
        except Exception as e:
            findings["gcp_storage"] = {"error": str(e)}
        try:
            findings["gcp_compute"] = self.gcp_exploit.exploit_compute_engine_metadata()
        except Exception as e:
            findings["gcp_compute"] = {"error": str(e)}
        try:
            findings["gcp_iam"] = self.gcp_exploit.exploit_iam_permissions()
        except Exception as e:
            findings["gcp_iam"] = {"error": str(e)}
        try:
            findings["gcp_sql"] = self.gcp_exploit.exploit_cloud_sql_credentials()
        except Exception as e:
            findings["gcp_sql"] = {"error": str(e)}

        return findings

    # ─── Crypto Theft ───────────────────────────────────────────────────

    def _crypto_theft(self, target: Target, mode: str) -> Dict[str, Any]:
        """Perform cryptocurrency theft operations."""
        findings = {}
        try:
            findings["scan"] = self.crypto_theft.scan()
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["wallet_keys"] = self.crypto_theft.extract_wallet_keys(
                str(target.value)
            )
        except Exception as e:
            findings["wallet_keys"] = {"error": str(e)}
        try:
            findings["cryptojacking"] = self.crypto_theft.detect_cryptocurrency_jacking()
        except Exception as e:
            findings["cryptojacking"] = {"error": str(e)}
        try:
            findings["exchange_creds"] = self.crypto_theft.extract_exchange_credentials()
        except Exception as e:
            findings["exchange_creds"] = {"error": str(e)}
        try:
            findings["blockchain_analysis"] = self.crypto_theft.analyze_blockchain_transactions()
        except Exception as e:
            findings["blockchain_analysis"] = {"error": str(e)}
        return findings

    # ─── Persistent Exfiltration ───────────────────────────────────────

    def _persistent_exfil(self, target: Target, mode: str) -> Dict[str, Any]:
        """Plant persistent exfiltration mechanisms."""
        findings = {}
        try:
            findings["scan"] = self.persistent_exfil.scan()
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["webshell"] = self.persistent_exfil.plant_webshell(
                target.get_domain() if hasattr(target, "get_domain") else str(target.value)
            )
        except Exception as e:
            findings["webshell"] = {"error": str(e)}
        try:
            findings["backdoor"] = self.persistent_exfil.plant_backdoor_script(
                str(target.value)
            )
        except Exception as e:
            findings["backdoor"] = {"error": str(e)}
        try:
            findings["screenshot_harvester"] = self.persistent_exfil.plant_screenshot_harvester()
        except Exception as e:
            findings["screenshot_harvester"] = {"error": str(e)}
        try:
            findings["keylogger"] = self.persistent_exfil.plant_keylogger()
        except Exception as e:
            findings["keylogger"] = {"error": str(e)}
        try:
            findings["clipboard_thief"] = self.persistent_exfil.plant_clipboard_thief()
        except Exception as e:
            findings["clipboard_thief"] = {"error": str(e)}
        return findings

    # ─── Zero-Click Automation ──────────────────────────────────────────

    def _zero_click(self, target: Target, mode: str) -> Dict[str, Any]:
        """Deploy zero-click automation and scheduled persistence."""
        findings = {}
        try:
            findings["scan"] = self.zero_click.scan()
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["cron"] = self.zero_click.create_cron_job("/tmp/.void_cron")
        except Exception as e:
            findings["cron"] = {"error": str(e)}
        try:
            findings["systemd"] = self.zero_click.create_systemd_timer("void-svc")
        except Exception as e:
            findings["systemd"] = {"error": str(e)}
        try:
            findings["tor_exfil"] = self.zero_click.setup_tor_scheduled_exfil(
                str(target.value), 30
            )
        except Exception as e:
            findings["tor_exfil"] = {"error": str(e)}
        try:
            findings["verify"] = self.zero_click.verify_scheduled_tasks()
        except Exception as e:
            findings["verify"] = {"error": str(e)}
        return findings

    # ─── K8s Container Attack ──────────────────────────────────────────

    def _k8s_attack(self, target: Target, mode: str) -> Dict[str, Any]:
        """Attack Kubernetes clusters and containers."""
        findings = {}
        try:
            findings["scan"] = self.k8s_attack.scan()
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["privilege_escalation"] = self.k8s_attack.exploit_pod_privilege_escalation()
        except Exception as e:
            findings["privilege_escalation"] = {"error": str(e)}
        try:
            findings["secrets_exposure"] = self.k8s_attack.exploit_secrets_exposure()
        except Exception as e:
            findings["secrets_exposure"] = {"error": str(e)}
        try:
            findings["service_account_tokens"] = self.k8s_attack.exploit_service_account_tokens()
        except Exception as e:
            findings["service_account_tokens"] = {"error": str(e)}
        try:
            findings["container_images"] = self.k8s_attack.exploit_container_images()
        except Exception as e:
            findings["container_images"] = {"error": str(e)}
        return findings

    # ─── Wireless/IoT Attack ───────────────────────────────────────────

    def _wireless_iot(self, target: Target, mode: str) -> Dict[str, Any]:
        """Attack wireless networks and IoT devices."""
        findings = {}
        try:
            findings["scan"] = self.wireless_iot.scan()
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["wifi_crack"] = self.wireless_iot.crack_wifi_network(
                str(target.value)
            )
        except Exception as e:
            findings["wifi_crack"] = {"error": str(e)}
        try:
            findings["iot_exploit"] = self.wireless_iot.exploit_iot_device(
                str(target.value)
            )
        except Exception as e:
            findings["iot_exploit"] = {"error": str(e)}
        try:
            findings["wireless_sniff"] = self.wireless_iot.sniff_wireless_traffic()
        except Exception as e:
            findings["wireless_sniff"] = {"error": str(e)}
        return findings

    # ─── Advanced LLM Jailbreak (JBFuzz/PyRIT/Garak) ───────────────────

    def _advanced_jailbreak(self, target: Target, mode: str) -> Dict[str, Any]:
        """Run advanced LLM jailbreak and adversarial model testing."""
        findings = {}
        try:
            findings["jbfuzz_scan"] = self.jbfuzz.scan()
        except Exception as e:
            findings["jbfuzz_scan"] = {"error": str(e)}
        try:
            findings["jbfuzz_generate"] = self.jbfuzz.generate_jailbreak(
                str(target.value)
            )
        except Exception as e:
            findings["jbfuzz_generate"] = {"error": str(e)}
        try:
            findings["jbfuzz_run"] = self.jbfuzz.run_jailbreak(str(target.value))
        except Exception as e:
            findings["jbfuzz_run"] = {"error": str(e)}

        # PyRIT and Garak are in the same module
        try:
            from exploit.llm_jailbreak_jbfuzz import PyRIT, Garak
            pyrit = PyRIT(self.executor)
            findings["pyrit_scan"] = pyrit.scan()
        except Exception as e:
            findings["pyrit_scan"] = {"error": str(e)}
        try:
            from exploit.llm_jailbreak_jbfuzz import PyRIT, Garak
            pyrit = PyRIT(self.executor)
            findings["pyrit_test"] = pyrit.test_model(str(target.value))
        except Exception as e:
            findings["pyrit_test"] = {"error": str(e)}
        try:
            from exploit.llm_jailbreak_jbfuzz import PyRIT, Garak
            garak = Garak(self.executor)
            findings["garak_scan"] = garak.scan()
        except Exception as e:
            findings["garak_scan"] = {"error": str(e)}
        try:
            from exploit.llm_jailbreak_jbfuzz import PyRIT, Garak
            garak = Garak(self.executor)
            findings["garak_run"] = garak.run_scan(str(target.value))
        except Exception as e:
            findings["garak_run"] = {"error": str(e)}

        return findings

    # ─── CVE Exploitation ──────────────────────────────────────────────

    def _cve_exploit(self, target: Target, mode: str) -> Dict[str, Any]:
        """Run CVE exploit modules."""
        findings = {}

        # CVE-2026-32202
        try:
            cve = self.cve_2026_32202
            findings["cve_2026_32202_scan"] = cve.scan()
        except Exception as e:
            findings["cve_2026_32202_scan"] = {"error": str(e)}
        try:
            cve = self.cve_2026_32202
            lnk_chain = cve.craft_lnk_chain()
            if lnk_chain:
                findings["cve_2026_32202_lnk"] = cve.deliver_lnk(
                    str(target.value), lnk_chain
                )
            else:
                findings["cve_2026_32202_lnk"] = {"status": "lnk_chain_failed"}
        except Exception as e:
            findings["cve_2026_32202_lnk"] = {"error": str(e)}
        try:
            cve = self.cve_2026_32202
            findings["cve_2026_32202_ntlm"] = cve.harvest_ntlm_hashes()
        except Exception as e:
            findings["cve_2026_32202_ntlm"] = {"error": str(e)}
        try:
            cve = self.cve_2026_32202
            findings["cve_2026_32202_crack"] = cve.crack_ntlm_hashes("/tmp/void_hashes.txt")
        except Exception as e:
            findings["cve_2026_32202_crack"] = {"error": str(e)}

        # CVE-2026-41940
        try:
            cve = self.cve_2026_41940
            findings["cve_2026_41940_scan"] = cve.scan()
        except Exception as e:
            findings["cve_2026_41940_scan"] = {"error": str(e)}
        try:
            cve = self.cve_2026_41940
            findings["cve_2026_41940_exploit"] = cve.exploit(
                {"target": str(target.value), "mode": mode}
            )
        except Exception as e:
            findings["cve_2026_41940_exploit"] = {"error": str(e)}

        # CVE-2026-41089
        try:
            cve = self.cve_2026_41089
            findings["cve_2026_41089_scan"] = cve.scan()
        except Exception as e:
            findings["cve_2026_41089_scan"] = {"error": str(e)}
        try:
            cve = self.cve_2026_41089
            findings["cve_2026_41089_exploit"] = cve.exploit(
                {"target": str(target.value), "mode": mode}
            )
        except Exception as e:
            findings["cve_2026_41089_exploit"] = {"error": str(e)}

        # CVE-2025-55182
        try:
            cve = self.cve_2025_55182
            findings["cve_2025_55182_scan"] = cve.scan(str(target.value))
        except Exception as e:
            findings["cve_2025_55182_scan"] = {"error": str(e)}
        try:
            cve = self.cve_2025_55182
            findings["cve_2025_55182_exploit"] = cve.exploit(
                {"target": str(target.value), "mode": mode}
            )
        except Exception as e:
            findings["cve_2025_55182_exploit"] = {"error": str(e)}

        return findings

    # ─── Destruction ───────────────────────────────────────────────────

    def _destruction(self, target: Target, mode: str) -> Dict[str, Any]:
        """Execute destruction sequence on target."""
        findings = {}
        try:
            findings["scan"] = self.destruction.scan(str(target.value))
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            findings["execution"] = self.destruction.execute_destruction_sequence(
                str(target.value)
            )
        except Exception as e:
            findings["execution"] = {"error": str(e)}
        try:
            findings["report"] = self.destruction.get_destruction_report(
                str(target.value)
            )
        except Exception as e:
            findings["report"] = {"error": str(e)}
        return findings

    # ─── MCP Vulnerability Scan ────────────────────────────────────────

    def _mcp_scan(self, target: Target, mode: str) -> Dict[str, Any]:
        """Run MCP vulnerability scanner against target."""
        findings = {}
        if self.mcp_scanner is None:
            return {
                "error": "MCP scanner not available (import failed)",
                "status": "skipped",
            }
        try:
            from pathlib import Path
            target_path = Path(str(target.value))
            findings["scan"] = self.mcp_scanner.scan(target_path)
        except Exception as e:
            findings["scan"] = {"error": str(e)}
        try:
            from pathlib import Path
            target_path = Path(str(target.value))
            scan_result = self.mcp_scanner.scan(target_path)
            findings["report"] = self.mcp_scanner.generate_report(
                scan_result, format="json"
            )
        except Exception as e:
            findings["report"] = {"error": str(e)}
        return findings

    # ─── MCP Attack (Phase 17) ─────────────────────────────────────────

    def _mcp_attack(self, target: Target, mode: str) -> Dict[str, Any]:
        """Run MCPAttack CVE + attack-class scanning against target."""
        findings = {}
        try:
            results = self.mcp_attack.scan(target)
            findings["scan"] = results
            findings["finding_count"] = len(results)
            findings["critical"] = [
                f for f in results
                if isinstance(f, dict) and f.get("severity") == "critical"
            ]
            findings["high"] = [
                f for f in results
                if isinstance(f, dict) and f.get("severity") == "high"
            ]
        except Exception as e:
            findings["scan"] = {"error": str(e)}
            findings["finding_count"] = 0
        return findings

    # ─── MCP Chain (Phase 18) ──────────────────────────────────────────

    def _mcp_chain(
        self, target: Target, mode: str,
        mcp_attack_findings: Any = None,
    ) -> Dict[str, Any]:
        """Build attack chains from MCPAttack findings + detect cascades."""
        findings = {}
        if not mcp_attack_findings:
            findings["status"] = "skipped"
            findings["reason"] = "No MCP attack findings available"
            return findings
        try:
            attack_list = (
                mcp_attack_findings
                if isinstance(mcp_attack_findings, list)
                else [mcp_attack_findings]
            )
            chain = self.mcp_chain.build_chain(attack_list, target)
            findings["chain"] = chain.to_dict() if hasattr(chain, "to_dict") else str(chain)
            findings["chain_id"] = getattr(chain, "id", None)
        except Exception as e:
            findings["chain"] = {"error": str(e)}
        try:
            cascade = self.mcp_chain.detect_cascade(target)
            findings["cascade"] = cascade if isinstance(cascade, dict) else str(cascade)
        except Exception as e:
            findings["cascade"] = {"error": str(e)}
        return findings

    # ─── MCP C2 (Phase 19) ─────────────────────────────────────────────

    def _mcp_c2(
        self, target: Target, mode: str,
        mcp_attack_findings: Any = None,
    ) -> Dict[str, Any]:
        """Post-exploitation C2 channel through compromised MCP servers."""
        findings = {}
        if not mcp_attack_findings:
            findings["status"] = "skipped"
            findings["reason"] = "No MCP attack findings available"
            return findings
        try:
            attack_list = (
                mcp_attack_findings
                if isinstance(mcp_attack_findings, list)
                else [mcp_attack_findings]
            )
            results = self.mcp_c2.establish_channel(target, auth={})
            findings["channel"] = results if isinstance(results, dict) else str(results)
        except Exception as e:
            findings["channel"] = {"error": str(e)}
        return findings

    # ─── Stealth ─────────────────────────────────────────────────────────

    def activate_stealth(self) -> None:
        """Activate stealth mode."""
        self.stealth.activate_tor()
        self.warlog.log("Stealth mode activated", level=LogLevel.STEALTH)

    def deactivate_stealth(self) -> None:
        """Deactivate stealth mode."""
        self.stealth.deactivate_tor()
        self.warlog.log("Stealth mode deactivated", level=LogLevel.STEALTH)

    # ─── Status ──────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the Frosty agent runtime."""
        return {
            "agent_name": getattr(self, "name", "Frosty"),
            "engaged": self.engaged,
            "targets": [t.name for t in self.targets],
            "active_sessions": list(self.active_sessions.keys()),
            "stolen_data": len(self.stolen_data),
            "stealth_active": self.stealth.is_tor_active(),
            "warlog_entries": self.warlog.get_summary()["total_entries"],
            "attack_log": len(self.attack_log),
            "beacons": list(self.beacons.keys()),
            "c2_status": self.c2_daemon.get_status(),
        }

    def get_report(self) -> Dict[str, Any]:
        """Get a full report of all findings."""
        return {
            "status": self.get_status(),
            "attack_log": self.attack_log,
            "stolen_data": self.stolen_data,
            "warlog": self.warlog.get_summary(),
        }

    # ─── Convenience ─────────────────────────────────────────────────────

    def quick_attack(self, target: Target) -> Dict[str, Any]:
        """Perform a quick attack on a target."""
        return self.engage(target, mode="quick")

    def full_attack(self, target: Target) -> Dict[str, Any]:
        """Perform a full attack on a target."""
        return self.engage(target, mode="full")

    def aggressive_attack(self, target: Target) -> Dict[str, Any]:
        """Perform an aggressive attack on a target."""
        return self.engage(target, mode="aggressive")

    def chaos_mode(self, target: Target) -> Dict[str, Any]:
        """Perform the scope-gated chaos mode phase plan."""
        return self.engage(target, mode="chaos")

"""THE VOID — ChaosEngine: The chaos engine orchestrator.

The ChaosEngine runs the ShadowAgent, manages targets, and orchestrates
the entire attack pipeline. It is the main loop of the system.
"""

import json
import logging
import os
import sys
import time
import signal
from typing import Any, Dict, List, Optional

from core.target import Target
from core.warlog import WarLog, LogLevel
from core.boneyard import Boneyard
from core.authorization import AuthorizationGate
from config.settings import Settings
from agent.shadow_agent import ShadowAgent
from orchestrator.difficulty import DifficultyAssessor, DifficultyReport, Action, Context

logger = logging.getLogger("void.orchestrator")


def clamp_recon_depth(discoveries: dict) -> float:
    """Estimate recon depth (0.0–1.0) from a target's discoveries dict.

    More discovery categories and more entries within them → deeper recon.
    Capped at 1.0. Used to build a Context for the difficulty assessor.
    """
    if not discoveries:
        return 0.0
    # Heuristic: depth grows with number of keys (categories) and entries.
    # ~5 categories with ~3 entries each (~15 total) → ~full depth.
    categories = len(discoveries)
    total_entries = sum(
        len(v) if isinstance(v, (list, dict)) else 1 for v in discoveries.values()
    )
    cat_score = min(1.0, categories / 5.0)
    entry_score = min(1.0, total_entries / 15.0)
    return round(0.5 * cat_score + 0.5 * entry_score, 4)


class ChaosEngine:
    """The ChaosEngine — the main orchestrator that runs the ShadowAgent.

    It manages the lifecycle of the agent, targets, and attacks.
    It provides a simple interface for engaging targets.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.agent = ShadowAgent(self.settings)
        self.warlog = WarLog()
        self.boneyard = Boneyard()
        self.assessor = DifficultyAssessor(boneyard=self.boneyard)
        # When True, abort-mode assessments actually skip the engagement.
        # Default False = advisory (logs assessment, continues regardless).
        # Demo / client profiles set STRICT_DIFFICULTY=true in settings.
        self.strict_difficulty = bool(self.settings.get("STRICT_DIFFICULTY", False))
        self.client_mode = bool(self.settings.get("CLIENT_MODE", False))
        self.dry_run = bool(self.settings.get("DRY_RUN", False))

        authz_path = self.settings.get("AUTHORIZATION_FILE") or ""
        if authz_path and not os.path.isabs(authz_path):
            # Resolve relative to project root (parent of config/)
            base = self.settings.get("BASE_DIR") or os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
            candidate = os.path.join(base, authz_path)
            if os.path.isfile(candidate):
                authz_path = candidate
        require_authz = bool(self.settings.get("REQUIRE_AUTHORIZATION", False))
        self.authz = AuthorizationGate(
            authz_path=authz_path or None,
            require_authorization=require_authz,
            auth_mode=self.settings.get("AUTH_MODE") or None,
        )
        # Propagate denied phases + client policy into the agent
        self.agent.authz = self.authz
        if self.settings.get("DENY_HIGH_RISK_PHASES"):
            high_risk = list(self.settings.get("HIGH_RISK_PHASES") or [])
            self.agent.extra_denied_phases = set(high_risk)

        self.running = False
        self.results: List[Dict[str, Any]] = []
        logger.info(
            "ChaosEngine initialized (strict_difficulty=%s, client_mode=%s, authz=%s)",
            self.strict_difficulty,
            self.client_mode,
            "loaded" if self.authz.loaded else "open",
        )

    def add_target(self, target: Target) -> None:
        """Add a target to the engine."""
        self.agent.add_target(target)
        self.warlog.log("Target added to chaos engine", level=LogLevel.AGENT, module="chaos", target=target.value)

    def add_targets(self, targets: List[Target]) -> None:
        """Add multiple targets to the engine."""
        for target in targets:
            self.add_target(target)

    def engage(self, target: Target, mode: str = "full") -> Dict[str, Any]:
        """Engage a target.

        Args:
            target: The target to engage
            mode: Engagement mode (quick, full, aggressive, chaos)

        Returns:
            Dict with engagement results
        """
        logger.info(f"ChaosEngine engaging {target.name} (mode={mode})")
        self.warlog.log(f"ChaosEngine engaging in {mode} mode", level=LogLevel.AGENT, module="chaos", target=target.value)

        # ── Scope / ROE gate (runs before any tool execution) ───────────
        decision = self.authz.check_target(target.value, mode=mode)
        if not decision.allowed:
            self.warlog.log(
                f"Engagement denied by authorization gate: {decision.reason}",
                level=LogLevel.WARNING, module="authorization", target=target.value,
            )
            return {
                "target": target.name,
                "mode": mode,
                "status": "denied",
                "reason": decision.reason,
                "authorization": decision.to_dict(),
            }

        if self.dry_run:
            planned = self.agent.phases_for_mode(mode)
            planned = self.authz.filter_phases(planned)
            self.warlog.log(
                f"DRY-RUN: would engage {target.name} phases={planned}",
                level=LogLevel.AGENT, module="chaos", target=target.value,
            )
            return {
                "target": target.name,
                "mode": mode,
                "status": "dry_run",
                "planned_phases": planned,
                "authorization": decision.to_dict(),
                "reason": "dry-run — no tools executed",
            }

        # P1.2.3: Difficulty assessment gate. Assesses the engagement before
        # committing. Advisory by default (logs + stores); when strict_difficulty
        # is set, abort-mode assessments skip the engagement entirely.
        report = self._assess_engagement(target, mode)
        if report is not None and report.mode == 'abort' and self.strict_difficulty:
            self.warlog.log(
                f"Engagement {target.name} aborted by difficulty gate "
                f"(score={report.score:.3f})",
                level=LogLevel.WARNING, module="chaos", target=target.value,
            )
            return {
                'target': target.name, 'mode': mode, 'status': 'aborted',
                'difficulty': report.to_dict(), 'reason': report.rationale,
                'authorization': decision.to_dict(),
            }

        results = self.agent.engage(target, mode)
        results.setdefault('difficulty', report.to_dict() if report else None)
        results.setdefault('authorization', decision.to_dict())
        self.results.append(results)
        self.boneyard.store(f"chaos_{target.name}_{int(time.time())}", results)

        # P1.2.4: Feed the assessment outcome back into the boneyard for
        # future calibration (success if engagement produced findings).
        if report is not None and getattr(report, 'assessment_id', None):
            outcome = self._classify_outcome(results)
            try:
                self.boneyard.update_difficulty_outcome(report.assessment_id, outcome)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Difficulty outcome update failed (non-fatal): {e}")

        return results

    def _assess_engagement(self, target: Target, mode: str) -> Optional[DifficultyReport]:
        """Run the difficulty assessor before committing to an engagement.

        Converts the (target, mode) into an Action + Context for the assessor,
        runs it, logs to warlog, and persists to the boneyard difficulty table.
        Returns the DifficultyReport (or None on failure — the gate never blocks).
        """
        try:
            # Map chaos mode → (estimated_steps, phase, technique) for the assessor
            mode_profiles = {
                'quick':       (3,  'recon',   'quick_recon'),
                'full':        (10, 'exploit', 'full_chain'),
                'aggressive':  (12, 'exploit', 'aggressive_chain'),
                'chaos':       (15, 'exfil',   'chaos_exfil'),
            }
            steps, phase, technique = mode_profiles.get(mode, (10, 'exploit', 'unknown'))

            action = Action(
                name=f"{mode}:{target.name}",
                phase=phase,
                technique=technique,
                target=target.value,
                estimated_steps=steps,
            )

            # Build context from what we actually know about the target so far.
            discoveries = getattr(target, 'discoveries', {}) or {}
            findings_count = len(discoveries)
            known_vulns = sum(
                1 for v in discoveries.values()
                if isinstance(v, dict) and v.get('type') == 'vulnerability'
            )
            known_creds = sum(
                1 for v in discoveries.values()
                if isinstance(v, dict) and v.get('type') == 'credential'
            )
            recon_depth = clamp_recon_depth(discoveries)
            familiarity = min(1.0, findings_count / 20.0)
            context = Context(
                findings_count=findings_count,
                recon_depth=recon_depth,
                known_vulns=known_vulns,
                known_creds=known_creds,
                target_familiarity=familiarity,
                engagement_phase=1,
            )

            report = self.assessor.assess_and_store(action=action, context=context)

            self.warlog.log(
                f"Difficulty assessment for {target.name}: score={report.score:.3f} "
                f"mode={report.mode} ({report.rationale})",
                level=LogLevel.INFO, module="difficulty", target=target.value,
            )
            return report
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Difficulty assessment failed (non-fatal, gate open): {e}")
            return None

    @staticmethod
    def _classify_outcome(results: Dict[str, Any]) -> str:
        """Classify an engagement's outcome for difficulty calibration.

        Heuristic: success if the agent produced at least one phase finding that
        isn't purely an error dict. 'failure' if everything errored out.
        'partial' if some phases errored but at least one succeeded.
        """
        findings = results.get('findings') or {}
        if not isinstance(findings, dict) or not findings:
            return 'failure'

        ok = 0
        err = 0
        for _phase, data in findings.items():
            if isinstance(data, dict) and 'error' in data and len(data) == 1:
                err += 1
            elif data:  # non-empty, non-pure-error
                ok += 1
            else:
                err += 1

        if ok and err:
            return 'partial'
        if ok:
            return 'success'
        return 'failure'

    def engage_all(self, mode: str = "full") -> Dict[str, Any]:
        """Engage all targets.

        Routes every target through self.engage() so that the authorization
        gate, difficulty assessment, dry-run logic, and boneyard persistence
        are enforced for each target — never delegates to ShadowAgent
        directly, which would bypass all safety controls.

        Args:
            mode: Engagement mode

        Returns:
            Dict mapping target name → engagement results for all targets
        """
        logger.info(f"ChaosEngine engaging all targets (mode={mode})")
        results: Dict[str, Any] = {}
        for target in list(self.agent.targets):
            results[target.name] = self.engage(target, mode)
        return results

    def quick_attack(self, target: Target) -> Dict[str, Any]:
        """Perform a quick attack."""
        return self.engage(target, mode="quick")

    def full_attack(self, target: Target) -> Dict[str, Any]:
        """Perform a full attack."""
        return self.engage(target, mode="full")

    def aggressive_attack(self, target: Target) -> Dict[str, Any]:
        """Perform an aggressive attack."""
        return self.engage(target, mode="aggressive")

    def chaos_mode(self, target: Target) -> Dict[str, Any]:
        """Perform the full scope-gated chaos mode phase plan."""
        return self.engage(target, mode="chaos")

    def activate_stealth(self) -> None:
        """Activate stealth mode."""
        self.agent.activate_stealth()
        self.warlog.log("Stealth mode activated", level=LogLevel.AGENT, module="chaos")

    def deactivate_stealth(self) -> None:
        """Deactivate stealth mode."""
        self.agent.deactivate_stealth()
        self.warlog.log("Stealth mode deactivated", level=LogLevel.AGENT, module="chaos")

    def get_status(self) -> Dict[str, Any]:
        """Get the current status."""
        return self.agent.get_status()

    def get_report(self) -> Dict[str, Any]:
        """Get a full report."""
        return self.agent.get_report()

    def start(self) -> None:
        """Start the chaos engine."""
        self.running = True
        logger.info("ChaosEngine started")
        self.warlog.log("ChaosEngine started", level=LogLevel.AGENT, module="chaos")

    def stop(self) -> None:
        """Stop the chaos engine."""
        self.running = False
        logger.info("ChaosEngine stopped")
        self.warlog.log("ChaosEngine stopped", level=LogLevel.AGENT, module="chaos")

    def run(self, targets: Optional[List[Target]] = None, mode: str = "full") -> Dict[str, Any]:
        """Run the chaos engine.

        Args:
            targets: List of targets to engage
            mode: Engagement mode

        Returns:
            Dict with engagement results
        """
        if targets is None:
            targets = self.agent.targets

        self.start()
        results = {}
        try:
            for target in targets:
                results[target.name] = self.engage(target, mode)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            self.warlog.log("Interrupted by user", level=LogLevel.AGENT, module="chaos")
        finally:
            self.stop()

        return results

    @staticmethod
    def _validate_target_name(name: str) -> Optional[str]:
        """Validate a target name entered in interactive mode.

        Returns the cleaned name if valid, None if invalid.
        Defensive measure — the authorization gate is the real control,
        but this prevents malformed input from reaching downstream tools.
        """
        if not name or not name.strip():
            print("Error: target name cannot be empty")
            return None
        cleaned = name.strip()
        if len(cleaned) > 512:
            print("Error: target name too long (max 512 characters)")
            return None
        # Reject null bytes and control characters
        if any(ord(c) < 32 and c not in '\t' for c in cleaned):
            print("Error: target name contains control characters")
            return None
        return cleaned

    @staticmethod
    def _print_engagement_result(results: Dict[str, Any]) -> None:
        """Print engagement results, surfacing denied/aborted status clearly."""
        status = results.get("status") if isinstance(results, dict) else None
        if status in ("denied", "aborted"):
            print(f"⚠ {status.upper()}: {results.get('reason', 'no reason provided')}")
        print(json.dumps(results, indent=2))

    def run_interactive(self) -> None:
        """Run the chaos engine in interactive mode."""
        self.start()
        print("\n" + "=" * 60)
        print("THE VOID — ChaosEngine")
        print("=" * 60)
        print("Commands: add <target>, engage <target> [mode], status, report, exit")
        print("Modes: quick, full, aggressive, chaos")
        print("=" * 60 + "\n")

        while self.running:
            try:
                cmd = input("void> ").strip()
                if cmd == "exit" or cmd == "quit":
                    self.stop()
                    break
                elif cmd == "status":
                    status = self.get_status()
                    print(json.dumps(status, indent=2))
                elif cmd == "report":
                    report = self.get_report()
                    print(json.dumps(report, indent=2))
                elif cmd.startswith("add "):
                    target_name = self._validate_target_name(cmd[4:])
                    if target_name is None:
                        continue
                    target = Target(value=target_name, name=target_name)
                    self.add_target(target)
                    print(f"Target {target_name} added")
                elif cmd.startswith("engage "):
                    parts = cmd[7:].strip().split()
                    if len(parts) < 1:
                        print("Usage: engage <target> [mode]")
                        continue
                    target_name = self._validate_target_name(parts[0])
                    if target_name is None:
                        continue
                    mode = parts[1] if len(parts) > 1 else "full"
                    target = Target(value=target_name, name=target_name)
                    self.add_target(target)
                    results = self.engage(target, mode)
                    self._print_engagement_result(results)
                elif cmd.startswith("quick "):
                    target_name = self._validate_target_name(cmd[6:])
                    if target_name is None:
                        continue
                    target = Target(value=target_name, name=target_name)
                    self.add_target(target)
                    results = self.quick_attack(target)
                    self._print_engagement_result(results)
                elif cmd.startswith("chaos "):
                    target_name = self._validate_target_name(cmd[6:])
                    if target_name is None:
                        continue
                    target = Target(value=target_name, name=target_name)
                    self.add_target(target)
                    results = self.chaos_mode(target)
                    self._print_engagement_result(results)
                elif cmd == "stealth on":
                    self.activate_stealth()
                    print("Stealth mode activated")
                elif cmd == "stealth off":
                    self.deactivate_stealth()
                    print("Stealth mode deactivated")
                else:
                    print(f"Unknown command: {cmd}")
            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                logger.error(f"Error in interactive command '{cmd}': {e}", exc_info=True)
                print(f"[ERROR] Command '{cmd}' failed: {e}")

        print("ChaosEngine stopped")

"""Coverage bridge — exposes the REAL R-line engines to the Command Center.

The web UI must never re-derive coverage, MITRE mapping, or compliance data
with client-side heuristics. This bridge routes every insights endpoint
through the same engines the CLI report uses, so the web UI and
``thevoid report`` can never disagree:

    /api/coverage     → modules.coverage.CoverageScorer.score_all()     (R-2)
    /api/mitre        → modules.reporter._annotate_mitre via gather_data (R-1)
    /api/compliance   → reporter COMPLIANCE_MAP cross-reference          (R-4)
    /api/drift        → boneyard findings with category "drift"          (R-3)
    /api/scenarios    → scenarios.ScenarioLibrary.describe()             (R-6)

Attack-log reconstruction
-------------------------
The agent's ``attack_log`` is in-memory only, but ``ShadowAgent.engage()``
persists every payload via ``boneyard.store(f"attack_{target}_{ts}", payload)``.
The bridge rebuilds the attack log from persisted boneyard findings
(source of truth across restarts) and appends any in-memory payloads not
yet persisted, deduplicating by payload identity.

Honesty rules
-------------
Empty store ⇒ zeroed, empty-list responses straight from the engines — no
synthesized data. ALIAS:/UNMAPPED technique rules live in the Reporter and
are never re-implemented here.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("void.commandcenter.coverage_bridge")

# gather_data() is O(findings) — cache briefly so dashboard polling
# (and multiple insights panels loading at once) doesn't hammer SQLite.
_CACHE_TTL_SECONDS = 2.0


def _payload_key(payload: Dict[str, Any]) -> str:
    """Stable identity for an engagement payload (dedup key)."""
    return json.dumps(payload, sort_keys=True, default=str)


class CoverageBridge:
    """Read-only bridge from the Command Center API to the R-line engines.

    Wraps a :class:`ServiceBridge` (lazy module holders for warlog /
    boneyard / chaos). Never writes to the stores; never bypasses safety
    controls.
    """

    def __init__(self, service_bridge: Any) -> None:
        self._sb = service_bridge
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] = {}
        self._cache_at: float = 0.0

    # ─── Attack log reconstruction ────────────────────────────────────────

    def attack_log(self) -> List[Dict[str, Any]]:
        """Rebuild the engagement attack log (persisted + in-memory, deduped)."""
        payloads: List[Dict[str, Any]] = []
        seen: set = set()

        # 1. Persisted payloads — source of truth across restarts.
        boneyard = self._sb._boneyard
        if boneyard is not None:
            try:
                categories = list(boneyard.categories() or [])
                for cat in sorted(c for c in categories if c.startswith("attack_")):
                    rows = boneyard.search(category=cat, limit=500)
                    for row in rows:
                        payload = row.get("data")
                        if not isinstance(payload, dict):
                            continue
                        key = _payload_key(payload)
                        if key in seen:
                            continue
                        seen.add(key)
                        payloads.append(payload)
            except Exception as exc:
                logger.warning("attack_log: boneyard read failed: %s", exc)

        # 2. In-memory payloads from the live agent (not yet persisted or
        #    persisted under a different identity). Suppressed in demo mode
        #    so the demo store stays isolated from live in-memory data.
        chaos = self._sb._chaos
        agent = getattr(chaos, "agent", None) if chaos is not None else None
        demo_active = bool(getattr(self._sb, "is_demo_mode", lambda: False)())
        if agent is not None and not demo_active:
            for payload in list(getattr(agent, "attack_log", []) or []):
                if not isinstance(payload, dict):
                    continue
                key = _payload_key(payload)
                if key in seen:
                    continue
                seen.add(key)
                payloads.append(payload)

        return payloads

    # ─── Endpoints ────────────────────────────────────────────────────────

    def coverage(self) -> Dict[str, Any]:
        """Prevention-strength scoring (R-2) over the rebuilt attack log."""
        try:
            from modules.coverage import CoverageScorer

            return CoverageScorer().score_all(self.attack_log())
        except Exception as exc:
            logger.exception("coverage scoring failed: %s", exc)
            return {"aggregated": 0.0, "count": 0, "engagement_scores": [],
                    "error": str(exc)}

    def mitre(self) -> Dict[str, Any]:
        """Real MITRE ATT&CK coverage (R-1) via Reporter.gather_data().

        Excludes ``mapped_findings`` (large; the findings panel already
        serves those). Never re-implements ALIAS:/UNMAPPED rules.
        """
        data = self._gather()
        mitre = dict(data.get("mitre") or {})
        mitre.pop("mapped_findings", None)
        return mitre

    def compliance(self) -> Dict[str, Any]:
        """Compliance cross-reference (R-4) — native techniques only."""
        data = self._gather()
        mitre = data.get("mitre") or {}
        return {
            "compliance": dict(mitre.get("compliance") or {}),
            "techniques_used": [
                t for t in (mitre.get("techniques_used") or [])
            ],
            "note": "Curated advisory cross-reference, not a certification.",
        }

    def drift(self) -> Dict[str, Any]:
        """Continuity drift events (R-3) persisted by ContinuityScheduler."""
        events: List[Dict[str, Any]] = []
        boneyard = self._sb._boneyard
        if boneyard is not None:
            try:
                rows = boneyard.search(category="drift", limit=500)
                for row in rows:
                    events.append(self._sb._sanitize_finding(dict(row)))
            except Exception as exc:
                logger.warning("drift: boneyard read failed: %s", exc)
                return {"events": [], "count": 0, "error": str(exc)}
        # Most recent first
        events.sort(key=lambda r: r.get("epoch") or 0, reverse=True)
        return {"events": events, "count": len(events)}

    def scenarios(self) -> Dict[str, Any]:
        """Scenario catalog (R-6) — pure data from the registry."""
        try:
            from scenarios import ScenarioLibrary

            items = ScenarioLibrary().describe()
            return {"scenarios": items, "count": len(items)}
        except Exception as exc:
            logger.exception("scenario catalog failed: %s", exc)
            return {"scenarios": [], "count": 0, "error": str(exc)}

    # ─── Internals ────────────────────────────────────────────────────────

    def _gather(self) -> Dict[str, Any]:
        """Run Reporter.gather_data() once and briefly cache the result.

        Same Reporter construction as ServiceBridge.build_reporter, so the
        web insights and the CLI report share one code path.
        """
        with self._lock:
            now = time.monotonic()
            if self._cache and (now - self._cache_at) < _CACHE_TTL_SECONDS:
                return self._cache

            try:
                from modules.reporter import Reporter

                reporter = Reporter(
                    warlog=self._sb._warlog,
                    boneyard=self._sb._boneyard,
                    attack_log=self.attack_log(),
                )
                data = reporter.gather_data()
            except Exception as exc:
                logger.exception("gather_data failed: %s", exc)
                data = {"mitre": {}, "coverage": {"aggregated": 0.0, "count": 0,
                                                  "engagement_scores": []},
                        "error": str(exc)}

            self._cache = data
            self._cache_at = now
            return data

    def invalidate_cache(self) -> None:
        """Drop the gather cache (used after engagements complete)."""
        with self._lock:
            self._cache = {}
            self._cache_at = 0.0


# Process-wide instance (separate from the ServiceBridge singleton so the
# insights layer can be reset independently in tests).
_coverage_bridge: Optional[CoverageBridge] = None


def get_coverage_bridge() -> CoverageBridge:
    from commandcenter.backend.services.bridge import get_bridge

    global _coverage_bridge
    if _coverage_bridge is None:
        _coverage_bridge = CoverageBridge(get_bridge())
    return _coverage_bridge


def reset_coverage_bridge() -> None:
    """Reset singleton (tests)."""
    global _coverage_bridge
    _coverage_bridge = None

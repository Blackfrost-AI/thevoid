"""Service bridge — thin adapter over existing VOID modules.

No business logic lives here. Reads existing stores and exposes query-only
methods for the REST/WebSocket layers. Write operations route through
existing module APIs without bypassing safety controls.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("void.commandcenter.bridge")

# Ensure project root is on sys.path for VOID imports
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


class ServiceBridge:
    """Singleton-style bridge to persistent stores and reporting services.

    Modules are initialized lazily and failures are captured as degraded
    services rather than crashing the API process.
    """

    def __init__(self, settings: Any = None) -> None:
        self._settings = settings
        self.degraded: List[str] = []
        self._boneyard: Any = None
        self._warlog: Any = None
        self._chaos: Any = None
        self._mcp_c2: Any = None
        self._reporter: Any = None
        # DEMO MODE state — isolated store swap (see enable_demo_mode).
        self._demo_lock = threading.RLock()
        self._demo_active = False
        self._live_boneyard: Any = None
        self._live_warlog: Any = None
        self._demo_summary: Dict[str, Any] = {}
        # State-change listeners: callable(reason: str) → notify (poller
        # diff-state resets, hub broadcasts). Kept in-process, no I/O here.
        self._state_listeners: List[Callable[[str], None]] = []
        self._init_modules()

    def _init_modules(self) -> None:
        try:
            from core.boneyard import Boneyard

            self._boneyard = Boneyard(
                storage_dir=self._settings.get("BONEYARD_DIR") if self._settings else None
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.exception("Boneyard unavailable: %s", exc)
            self.degraded.append("boneyard")

        try:
            from core.warlog import WarLog

            self._warlog = WarLog(
                log_dir=self._settings.get("WARLOG_DIR") if self._settings else None,
                log_file=self._settings.get("LOG_FILE") if self._settings else None,
                rotate_on_init=False,
            )
        except Exception as exc:  # pragma: no cover
            logger.exception("WarLog unavailable: %s", exc)
            self.degraded.append("warlog")

        # Do not construct ChaosEngine here. The Command Center is a
        # read-mostly observer, and instantiating the active engine loads an
        # ungated agent runtime that neither represents nor shares ephemeral
        # state with a separate operator process. Persistent stores below are
        # the cross-process source of truth. A future visual runner should be
        # explicit and scope-gated rather than appearing as a startup side effect.

        # Do not create a second, empty MCPC2 runtime. Channels owned by an
        # operator process are ephemeral and cannot be observed by instantiating
        # another object here. The bridge projects their persisted evidence;
        # deployments that embed both runtimes may explicitly inject the live
        # adapter into ``_mcp_c2``.

        try:
            from modules.reporter import Reporter

            self._reporter = Reporter(
                warlog=self._warlog,
                boneyard=self._boneyard,
                attack_log=self.get_attack_log(),
            )
        except Exception as exc:  # pragma: no cover
            logger.exception("Reporter unavailable: %s", exc)
            self.degraded.append("reporter")

        logger.info(
            "ServiceBridge ready (degraded=%s)",
            self.degraded or "none",
        )

    # ─── DEMO MODE ────────────────────────────────────────────────────────
    # Stage/demo mode swaps the bridge onto ISOLATED boneyard+warlog stores
    # seeded deterministically (see services/demo_seed.py). The live stores
    # are preserved and restored on disable — demo data NEVER touches live
    # integrity claims. Everything routed through the public store APIs so
    # HMAC chains stay valid on the demo DBs.

    def register_state_listener(self, listener: Callable[[str], None]) -> None:
        """Register callable(reason) invoked on demo enable/disable."""
        with self._demo_lock:
            if listener not in self._state_listeners:
                self._state_listeners.append(listener)

    def unregister_state_listener(self, listener: Callable[[str], None]) -> None:
        with self._demo_lock:
            if listener in self._state_listeners:
                self._state_listeners.remove(listener)

    def is_demo_mode(self) -> bool:
        return self._demo_active

    def demo_status(self) -> Dict[str, Any]:
        """Demo-mode descriptor for API/UI surfacing."""
        return {
            "demo_mode": self._demo_active,
            "scenario": self._demo_summary.get("scenario") if self._demo_active else None,
            "hosts": self._demo_summary.get("hosts", 0) if self._demo_active else 0,
            "steps": self._demo_summary.get("steps", 0) if self._demo_active else 0,
            "outcomes": self._demo_summary.get("outcomes", 0) if self._demo_active else 0,
            "engagements": self._demo_summary.get("engagements", 0) if self._demo_active else 0,
            "note": "DEMO: synthetic stage data — isolated stores, no live integrity impact",
        }

    def _notify_state_change(self, reason: str) -> None:
        listeners = list(self._state_listeners)
        for listener in listeners:
            try:
                listener(reason)
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning("state listener failed on %s: %s", reason, exc)

    def enable_demo_mode(self) -> Dict[str, Any]:
        """Swap onto isolated seeded demo stores. Idempotent.

        Wipes the demo runtime dir, builds fresh Boneyard/WarLog there,
        seeds the deterministic stage scenario, then swaps store refs and
        rebuilds the Reporter against the demo stores.
        """
        with self._demo_lock:
            if self._demo_active:
                return self.demo_status()
            if self._boneyard is None or self._warlog is None:
                raise RuntimeError(
                    "Cannot enter demo mode: core stores unavailable "
                    f"(degraded={self.degraded})"
                )
            from commandcenter.backend.config import load_settings
            from commandcenter.backend.services import demo_seed
            from core.boneyard import Boneyard
            from core.warlog import WarLog
            from modules.reporter import Reporter

            demo_dir = load_settings().demo_dir
            # Hard isolation: never swap the live dirs onto demo by accident.
            shutil.rmtree(demo_dir, ignore_errors=True)
            demo_dir.mkdir(parents=True, exist_ok=True)

            demo_boneyard = Boneyard(storage_dir=str(demo_dir / "boneyard"))
            demo_warlog = WarLog(log_dir=str(demo_dir / "warlog"))

            summary = demo_seed.seed_demo_boneyard(demo_boneyard)
            warlog_count = demo_seed.seed_demo_warlog(demo_warlog)
            self._demo_summary = dict(summary)
            self._demo_summary["scenario"] = demo_seed.DEMO_SCENARIO_NAME
            self._demo_summary["warlog_entries"] = warlog_count

            # Keep live refs, swap in demo refs.
            self._live_boneyard = self._boneyard
            self._live_warlog = self._warlog
            self._boneyard = demo_boneyard
            self._warlog = demo_warlog

            # Reporter caches store refs at construction — rebuild it against
            # the demo stores + the demo attack log.
            try:
                self._reporter = Reporter(
                    warlog=self._warlog,
                    boneyard=self._boneyard,
                    attack_log=list(summary.get("attack_log") or []),
                )
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning("demo reporter rebuild failed: %s", exc)

            self._demo_active = True
            logger.info("DEMO MODE enabled (dir=%s)", demo_dir)
            self._notify_state_change("demo_enabled")
            return self.demo_status()

    def disable_demo_mode(self) -> Dict[str, Any]:
        """Restore live stores and discard the demo runtime. Idempotent."""
        with self._demo_lock:
            if not self._demo_active:
                return self.demo_status()
            from commandcenter.backend.config import load_settings
            from modules.reporter import Reporter

            self._boneyard = self._live_boneyard
            self._warlog = self._live_warlog
            self._live_boneyard = None
            self._live_warlog = None
            self._demo_active = False
            self._demo_summary = {}

            try:
                self._reporter = Reporter(
                    warlog=self._warlog,
                    boneyard=self._boneyard,
                    attack_log=self.get_attack_log(),
                )
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning("live reporter rebuild failed: %s", exc)

            demo_dir = load_settings().demo_dir
            shutil.rmtree(demo_dir, ignore_errors=True)
            logger.info("DEMO MODE disabled — live stores restored")
            self._notify_state_change("demo_disabled")
            return self.demo_status()

    # ─── Status ────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Aggregate current runtime state with persisted engagement evidence."""
        status: Dict[str, Any] = {
            "engaged": False,
            "demo_mode": self._demo_active,
            "targets": [],
            "target_count": 0,
            "active_sessions": [],
            "stolen_data": 0,
            "stealth_active": False,
            "warlog_entries": 0,
            "attack_log": 0,
            "beacons": [],
            "beacon_count": 0,
            "c2_status": {},
            "c2_channels": 0,
            "c2_active_channels": 0,
            "c2_recorded_channels": 0,
            "c2_beacons": 0,
            "c2_tasks": 0,
            "boneyard_items": 0,
            "degraded": list(self.degraded),
        }

        if self._chaos is not None:
            try:
                raw = self._chaos.get_status() or {}
                status["engaged"] = bool(raw.get("engaged", False))
                targets = raw.get("targets") or []
                status["targets"] = list(targets)
                status["target_count"] = len(targets)
                status["active_sessions"] = list(raw.get("active_sessions") or [])
                status["stolen_data"] = int(raw.get("stolen_data") or 0)
                status["stealth_active"] = bool(raw.get("stealth_active", False))
                status["warlog_entries"] = int(raw.get("warlog_entries") or 0)
                status["attack_log"] = int(raw.get("attack_log") or 0)
                beacons = raw.get("beacons") or []
                status["beacons"] = list(beacons)
                status["beacon_count"] = len(beacons)
                status["c2_status"] = raw.get("c2_status") or {}
            except Exception as exc:
                logger.warning("get_status chaos failed: %s", exc)
                if "chaos" not in status["degraded"]:
                    status["degraded"].append("chaos")

        if self._mcp_c2 is not None:
            try:
                status["c2_channels"] = int(self._mcp_c2.get_active_channel_count())
                status["c2_active_channels"] = status["c2_channels"]
                status["c2_beacons"] = int(self._mcp_c2.get_total_beacons())
                status["c2_tasks"] = int(self._mcp_c2.get_total_tasks())
            except Exception as exc:
                logger.warning("get_status c2 failed: %s", exc)

        if self._warlog is not None and not status["warlog_entries"]:
            try:
                summary = self._warlog.get_summary() or {}
                status["warlog_entries"] = int(summary.get("total_entries") or 0)
            except Exception:
                pass

        if self._boneyard is not None:
            try:
                summary = self._boneyard.summary() or {}
                status["boneyard_items"] = int(summary.get("total_items") or 0)
            except Exception:
                pass

        # The browser often starts after a CLI run has finished, so the
        # command-center process has no in-memory target/attack list. Fall
        # back to the shared persistent store to keep dashboard totals aligned
        # with the Targets and insight views across process restarts.
        if not status["targets"] and self._boneyard is not None:
            try:
                seen: set[str] = set()
                recorded_targets: List[str] = []
                for host in self.query_hosts({}):
                    name = host.get("hostname") or host.get("ip_address")
                    normalized = str(name or '').strip()
                    if normalized and normalized not in seen:
                        seen.add(normalized)
                        recorded_targets.append(normalized)
                status["targets"] = recorded_targets
                status["target_count"] = len(recorded_targets)
            except Exception:
                pass

        if not status["attack_log"] and self._boneyard is not None:
            try:
                status["attack_log"] = len(self.get_attack_log())
            except Exception:
                pass

        # Live MCPC2 state disappears with its process. Merge restart-safe
        # evidence into the total while preserving an explicit active count.
        try:
            channels = self.list_channels()
            if channels:
                status["c2_channels"] = len(channels)
                status["c2_active_channels"] = sum(
                    bool(channel.get("live")) and channel.get("status") == "active"
                    for channel in channels
                )
                status["c2_recorded_channels"] = sum(
                    not bool(channel.get("live")) for channel in channels
                )
                status["c2_beacons"] = sum(
                    int(channel.get("beacon_count") or 0) for channel in channels
                )
                status["c2_tasks"] = sum(
                    int(channel.get("task_count") or 0) for channel in channels
                )
                status["c2_status"] = {
                    "active": status["c2_active_channels"],
                    "recorded": status["c2_recorded_channels"],
                }
            elif not status["c2_status"]:
                status["c2_status"] = {
                    "active": status["c2_active_channels"],
                    "recorded": 0,
                }
        except Exception:
            pass

        # DEMO MODE targets override: while active, report the seeded demo
        # hosts (fictional *.demo.void) so the UI shows the stage scenario.
        if self._demo_active:
            try:
                hosts = self.query_hosts({}) or []
                seen: set[str] = set()
                targets: List[str] = []
                for h in hosts:
                    name = h.get("hostname") or h.get("ip_address")
                    if name and name not in seen:
                        seen.add(name)
                        targets.append(name)
                status["targets"] = targets
                status["target_count"] = len(targets)
                status["attack_log"] = int(self._demo_summary.get("engagements") or 0)
            except Exception:
                pass

        return status

    # ─── Targets / Boneyard ────────────────────────────────────────────────

    def query_hosts(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self._boneyard is None:
            return []
        try:
            result = self._boneyard.query_hosts(filters)
            return [self._sanitize(dict(r)) for r in result]
        except Exception as exc:
            logger.warning("query_hosts failed: %s", exc)
            return []

    def get_target(self, host_id: str) -> Dict[str, Any]:
        hosts = self.query_hosts()
        host = next((h for h in hosts if str(h.get("id")) == str(host_id)), None)
        if host is None:
            # Fallback: match by ip/hostname
            host = next(
                (
                    h
                    for h in hosts
                    if str(h.get("ip_address")) == host_id
                    or str(h.get("hostname")) == host_id
                ),
                None,
            )
        findings = self.query_findings({"host_id": host_id}) if host else []
        if not findings and host and host.get("id"):
            findings = self.query_findings({"host_id": host["id"]})
        paths = self.graph_attack_paths(host_id if host else None)
        if host and host.get("id") and host_id != host.get("id"):
            paths = self.graph_attack_paths(host["id"])
        return {
            "host": host or {},
            "findings": findings,
            "attack_paths": paths,
        }

    def query_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if self._boneyard is None:
            return []
        try:
            result = self._boneyard.query_findings(filters)
            return [self._sanitize_finding(dict(r)) for r in result]
        except Exception as exc:
            logger.warning("query_findings failed: %s", exc)
            return []

    def search_findings(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        if self._boneyard is None:
            return []
        try:
            rows = self._boneyard.search(
                category=category, tags=tags, query=query, limit=limit
            )
            return [self._sanitize_finding(dict(r)) for r in rows]
        except Exception as exc:
            logger.warning("search_findings failed: %s", exc)
            return []

    def boneyard_summary(self) -> Dict[str, Any]:
        if self._boneyard is None:
            return {"total_items": 0, "categories": {}, "error": "boneyard unavailable"}
        try:
            return self._sanitize(self._boneyard.summary() or {})
        except Exception as exc:
            logger.warning("boneyard_summary failed: %s", exc)
            return {"total_items": 0, "categories": {}, "error": str(exc)}

    def boneyard_categories(self) -> List[str]:
        if self._boneyard is None:
            return []
        try:
            return list(self._boneyard.categories() or [])
        except Exception as exc:
            logger.warning("boneyard_categories failed: %s", exc)
            return []

    def verify_integrity(self) -> Dict[str, Any]:
        if self._boneyard is None:
            return {
                "verified": False,
                "total_rows_checked": 0,
                "broken_hmacs": [],
                "broken_chain_links": [],
                "orphaned_audit_entries": [],
                "table_counts": {},
                "audit_chain_length": 0,
                "error": "boneyard unavailable",
            }
        try:
            report = self._boneyard.verify_integrity()
            if hasattr(report, "to_dict"):
                return report.to_dict()
            return dict(report) if isinstance(report, dict) else {"verified": bool(report)}
        except Exception as exc:
            logger.warning("verify_integrity failed: %s", exc)
            return {
                "verified": False,
                "total_rows_checked": 0,
                "broken_hmacs": [],
                "broken_chain_links": [],
                "orphaned_audit_entries": [],
                "table_counts": {},
                "audit_chain_length": 0,
                "error": str(exc),
            }

    def graph_attack_paths(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        if self._boneyard is None:
            return {"nodes": [], "edges": [], "outcomes": [], "error": "boneyard unavailable"}
        try:
            graph = self._boneyard.graph_attack_paths(host_id)
            nodes = [dict(node) for node in (graph.get("nodes") or [])]
            host_names: Dict[str, str] = {}
            for host in self.query_hosts({}):
                hid = str(host.get("id") or "")
                name = host.get("hostname") or host.get("ip_address")
                if hid and name:
                    host_names[hid] = str(name)
            for node in nodes:
                node_host_id = str(node.get("host_id") or "")
                if node_host_id in host_names:
                    node["host_name"] = host_names[node_host_id]
            return {
                "nodes": self._sanitize(nodes),
                "edges": list(graph.get("edges") or []),
                "outcomes": list(graph.get("outcomes") or []),
                "error": graph.get("error"),
            }
        except Exception as exc:
            logger.warning("graph_attack_paths failed: %s", exc)
            return {"nodes": [], "edges": [], "outcomes": [], "error": str(exc)}

    # ─── C2 ────────────────────────────────────────────────────────────────

    @staticmethod
    def _counter(value: Any) -> int:
        """Normalize persisted counters without dropping an entire result set."""
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def _persisted_channels(self) -> List[Dict[str, Any]]:
        """Return restart-safe channel evidence from the Boneyard.

        MCPC2's live channel objects are process-local. A Command Center
        launched after an operator run must therefore treat the shared store
        as historical evidence, not proof that a channel is still reachable.
        """
        if self._boneyard is None:
            return []
        try:
            rows = self._boneyard.search(category="mcp_c2_channel", limit=500) or []
            recorded: List[Dict[str, Any]] = []
            seen: set[str] = set()
            for row in rows:
                data = row.get("data") if isinstance(row, dict) else None
                if not isinstance(data, dict):
                    continue
                channel_id = str(data.get("channel_id") or "").strip()
                if not channel_id or channel_id in seen:
                    continue
                seen.add(channel_id)
                recorded.append(
                    self._sanitize(
                        {
                            "channel_id": channel_id,
                            "status": "recorded",
                            "last_known_status": data.get("status") or "active",
                            "source": "evidence",
                            "live": False,
                            "target": data.get("target"),
                            "endpoint": data.get("endpoint"),
                            "tool_name": data.get("tool_name"),
                            "encoding": data.get("encoding"),
                            "beacon_count": self._counter(data.get("beacon_count")),
                            "task_count": self._counter(data.get("task_count")),
                            "fail_count": self._counter(data.get("fail_count")),
                            "established_at": data.get("established_at") or row.get("epoch"),
                            "last_beacon": data.get("last_beacon"),
                        }
                    )
                )
            return recorded
        except Exception as exc:
            logger.warning("persisted C2 channel query failed: %s", exc)
            return []

    def list_channels(self) -> List[Dict[str, Any]]:
        persisted = {c["channel_id"]: c for c in self._persisted_channels()}
        if self._mcp_c2 is None:
            return list(persisted.values())
        try:
            channels = self._mcp_c2.list_channels() or []
            # Enrich with target names when available
            enriched = []
            for ch in channels:
                item = dict(ch)
                cid = item.get("channel_id")
                if cid and cid in getattr(self._mcp_c2, "channels", {}):
                    state = self._mcp_c2.channels[cid]
                    target = getattr(state, "target", None)
                    if target is not None:
                        item["target"] = getattr(target, "name", str(target))
                    item["endpoint"] = item.get("endpoint") or getattr(state, "endpoint", None)
                item["source"] = "live"
                item["live"] = True
                # Never leak auth credentials
                item.pop("auth", None)
                enriched.append(self._sanitize(item))
                persisted.pop(str(cid or ""), None)
            return enriched + list(persisted.values())
        except Exception as exc:
            logger.warning("list_channels failed: %s", exc)
            return list(persisted.values())

    def get_channel_status(self, channel_id: str) -> Dict[str, Any]:
        live_channels = getattr(self._mcp_c2, "channels", {}) if self._mcp_c2 is not None else {}
        if channel_id not in live_channels:
            recorded = next(
                (item for item in self._persisted_channels() if item["channel_id"] == channel_id),
                None,
            )
            if recorded is not None:
                return recorded
            return {
                "status": "error",
                "reason": f"Unknown channel: {channel_id}",
                "channel_id": channel_id,
            }
        try:
            raw = self._mcp_c2.get_channel_status(channel_id) or {}
            raw.pop("auth", None)
            state = live_channels[channel_id]
            target = getattr(state, "target", None)
            if target is not None:
                raw["target"] = getattr(target, "name", str(target))
            raw["source"] = "live"
            raw["live"] = True
            return self._sanitize(raw)
        except Exception as exc:
            logger.warning("get_channel_status failed: %s", exc)
            return {"status": "error", "reason": str(exc), "channel_id": channel_id}

    def check_channel_health(self, channel_id: str) -> Dict[str, Any]:
        live_channels = getattr(self._mcp_c2, "channels", {}) if self._mcp_c2 is not None else {}
        if channel_id not in live_channels:
            recorded = any(
                item["channel_id"] == channel_id for item in self._persisted_channels()
            )
            return {
                "healthy": False,
                "status": "recorded" if recorded else "unknown",
                "live": False,
                "reason": (
                    "Historical evidence only; live health is unavailable"
                    if recorded
                    else "Unknown channel"
                ),
                "channel_id": channel_id,
            }
        try:
            # Health check may probe the network — wrap carefully
            return self._sanitize(self._mcp_c2.check_channel_health(channel_id) or {})
        except Exception as exc:
            logger.warning("check_channel_health failed: %s", exc)
            return {"healthy": False, "reason": str(exc), "channel_id": channel_id}

    def get_tasks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if self._mcp_c2 is None:
            return []
        try:
            return [self._sanitize(t) for t in (self._mcp_c2.get_tasks(status) or [])]
        except Exception as exc:
            logger.warning("get_tasks failed: %s", exc)
            return []

    # ─── WarLog ────────────────────────────────────────────────────────────

    def get_warlog_entries(
        self,
        level: Optional[str] = None,
        module: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if self._warlog is None:
            return []
        try:
            from core.warlog import LogLevel

            level_enum = None
            if level:
                try:
                    level_enum = LogLevel(level.lower())
                except ValueError:
                    level_enum = None
            entries = self._warlog.get_entries(
                level=level_enum, module=module, target=target
            )
            # Most recent first for the UI
            entries = list(reversed(entries))
            sliced = entries[offset : offset + limit]
            return [self._normalize_warlog_entry(e) for e in sliced]
        except Exception as exc:
            logger.warning("get_warlog_entries failed: %s", exc)
            return []

    def get_warlog_summary(self) -> Dict[str, Any]:
        if self._warlog is None:
            return {
                "session_id": None,
                "total_entries": 0,
                "duration_seconds": 0.0,
                "level_counts": {},
            }
        try:
            return self._sanitize(self._warlog.get_summary() or {})
        except Exception as exc:
            logger.warning("get_warlog_summary failed: %s", exc)
            return {
                "session_id": None,
                "total_entries": 0,
                "duration_seconds": 0.0,
                "level_counts": {},
                "error": str(exc),
            }

    def query_spans(
        self,
        operation: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        if self._warlog is None:
            return []
        try:
            spans = self._warlog.query_spans(operation=operation, limit=limit)
            return [self._normalize_warlog_entry(s) for s in spans]
        except Exception as exc:
            logger.warning("query_spans failed: %s", exc)
            return []

    def export_warlog(self, export_dir: Path) -> Dict[str, Any]:
        if self._warlog is None:
            raise RuntimeError("warlog unavailable")
        export_dir.mkdir(parents=True, exist_ok=True)
        path = str(export_dir / "warlog_export.json")
        self._warlog.export(path)
        summary = self.get_warlog_summary()
        return {"path": path, "entries": int(summary.get("total_entries") or 0)}

    # ─── Reports ───────────────────────────────────────────────────────────

    def get_attack_log(self) -> List[Dict[str, Any]]:
        """Reconstruct completed engagement payloads across process restarts."""
        payloads: List[Dict[str, Any]] = []
        seen: set[str] = set()
        if self._boneyard is not None:
            try:
                from modules.evidence_reports import recorded_engagements

                payloads = recorded_engagements(self._boneyard)
                seen.update(json.dumps(p, sort_keys=True, default=str) for p in payloads)
            except Exception as exc:
                logger.warning("attack log reconstruction failed: %s", exc)
                if "recorded_reports" not in self.degraded:
                    self.degraded.append("recorded_reports")
                raise RuntimeError("Recorded reports are unavailable; refusing incomplete totals.") from exc

        if self._chaos is not None and not self._demo_active:
            agent = getattr(self._chaos, "agent", None)
            for payload in list(getattr(agent, "attack_log", []) or []):
                if not isinstance(payload, dict):
                    continue
                key = json.dumps(payload, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    payloads.append(payload)
        return payloads

    def _refresh_reporter_attack_log(self) -> None:
        if self._reporter is not None:
            self._reporter.attack_log = self.get_attack_log()

    def gather_report_data(
        self,
        operator: str = "THE VOID",
        engagement_name: str = "Engagement Report",
    ) -> Dict[str, Any]:
        if self._reporter is None:
            return {"error": "reporter unavailable"}
        try:
            self._refresh_reporter_attack_log()
            self._reporter.operator = operator
            self._reporter.engagement_name = engagement_name
            return self._sanitize(self._reporter.gather_data())
        except Exception as exc:
            logger.warning("gather_report_data failed: %s", exc)
            return {"error": str(exc)}

    def generate_report(
        self,
        fmt: str = "json",
        operator: str = "THE VOID",
        engagement_name: str = "Engagement Report",
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self._reporter is None:
            raise RuntimeError("reporter unavailable")
        self._refresh_reporter_attack_log()
        self._reporter.operator = operator
        self._reporter.engagement_name = engagement_name
        content = self._reporter.generate(format=fmt, output_path=output_path)
        return {"format": fmt, "content": content, "path": output_path}

    # ─── Helpers ───────────────────────────────────────────────────────────

    _SENSITIVE_KEYS = frozenset(
        {
            "auth",
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "passphrase",
            "credential",
            "credentials",
            "hmac_key",
            "encryption_key",
            "row_hmac",
            "chain_hmac",
            "access_token",
            "refresh_token",
            "auth_token",
            "bearer",
            "session",
            "session_id",
            "cookie",
            "jwt",
            "private",
            "ssn",
            "bank_account",
            "credit_card",
            "card_number",
            "cvv",
            "ssh_key",
            "client_secret",
            "client_id",
            "secret_key",
            "access_key",
            "access_secret",
            "api_secret",
            "private_key_id",
            "pgp_private",
            "pgp_pass",
        }
    )

    def _sanitize(self, obj: Any) -> Any:
        """Recursively strip sensitive keys from API payloads."""
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                if str(k).lower() in self._SENSITIVE_KEYS:
                    continue
                out[k] = self._sanitize(v)
            return out
        if isinstance(obj, list):
            return [self._sanitize(i) for i in obj]
        return obj

    def _sanitize_finding(self, row: Dict[str, Any]) -> Dict[str, Any]:
        clean = self._sanitize(row)
        # Ensure consistent shape
        if "data" in clean and not isinstance(clean["data"], dict):
            clean["data"] = {"value": clean["data"]}
        if "tags" in clean and not isinstance(clean["tags"], list):
            clean["tags"] = []
        return clean

    def _normalize_warlog_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        e = self._sanitize(dict(entry))
        # Map common field aliases for the frontend
        if "message" not in e:
            e["message"] = e.get("operation") or e.get("msg") or e.get("event_type") or ""
        if "timestamp" not in e and e.get("epoch"):
            try:
                from datetime import datetime, timezone

                e["timestamp"] = datetime.fromtimestamp(
                    float(e["epoch"]), tz=timezone.utc
                ).isoformat()
            except (TypeError, ValueError, OSError):
                pass
        # Use row id or span_id as stable id
        if "id" not in e:
            e["id"] = e.get("span_id") or e.get("event_id") or e.get("rowid")
        return e


# Process-wide bridge instance
_bridge: Optional[ServiceBridge] = None


def get_bridge() -> ServiceBridge:
    global _bridge
    if _bridge is None:
        _bridge = ServiceBridge()
    return _bridge


def reset_bridge() -> None:
    """Reset singleton (tests)."""
    global _bridge
    _bridge = None

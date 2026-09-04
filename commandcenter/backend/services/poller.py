"""Background pollers that push diffs over WebSocket."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, Optional, Set

from commandcenter.backend.services.bridge import ServiceBridge, get_bridge
from commandcenter.backend.ws.hub import hub

logger = logging.getLogger("void.commandcenter.poller")


class EventPoller:
    """Poll VOID stores and broadcast changes to WebSocket clients."""

    def __init__(
        self,
        bridge: Optional[ServiceBridge] = None,
        warlog_interval: float = 1.0,
        c2_interval: float = 2.0,
        engagement_interval: float = 2.0,
        integrity_interval: float = 30.0,
    ) -> None:
        self.bridge = bridge or get_bridge()
        self.warlog_interval = warlog_interval
        self.c2_interval = c2_interval
        self.engagement_interval = engagement_interval
        self.integrity_interval = integrity_interval
        self.attack_graph_interval = 2.0
        self._tasks: list[asyncio.Task] = []
        self._running = False
        # Diff state
        self._seen_warlog_ids: Set[str] = set()
        self._last_warlog_count = 0
        self._last_engagement: Dict[str, Any] = {}
        self._last_c2_snapshot: str = ""
        self._last_integrity_verified: Optional[bool] = None
        self._seen_attack_nodes: Set[str] = set()
        self._started_at = time.time()
        self._event_rate_window: list[float] = []
        # Store-swap signal (demo mode enable/disable) — the listener fires
        # from a worker thread, so use a threading event checked each tick.
        self._store_swapped = threading.Event()

    def _on_bridge_state_change(self, reason: str) -> None:
        """ServiceBridge notified us the underlying stores were swapped.

        Flag so every poll loop resets its diff baseline on the next tick
        (the new store's contents must be treated as all-new).
        """
        logger.info("bridge state change: %s — diff baselines will reset", reason)
        self._store_swapped.set()

    def _maybe_reset_diff_state(self) -> None:
        if not self._store_swapped.is_set():
            return
        self._store_swapped.clear()
        self._seen_warlog_ids.clear()
        self._last_warlog_count = 0
        self._last_engagement = {}
        self._last_c2_snapshot = ""
        self._last_integrity_verified = None
        self._seen_attack_nodes.clear()
        logger.info("poller diff baselines reset after store swap")

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.bridge.register_state_listener(self._on_bridge_state_change)
        # Seed warlog baseline so we don't flood on connect
        await self._seed_warlog()
        self._tasks = [
            asyncio.create_task(self._loop_warlog(), name="poll-warlog"),
            asyncio.create_task(self._loop_c2(), name="poll-c2"),
            asyncio.create_task(self._loop_engagement(), name="poll-engagement"),
            asyncio.create_task(self._loop_integrity(), name="poll-integrity"),
            asyncio.create_task(self._loop_metrics(), name="poll-metrics"),
            asyncio.create_task(self._loop_attack_graph(), name="poll-attack-graph"),
        ]
        logger.info("EventPoller started")

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        try:
            self.bridge.unregister_state_listener(self._on_bridge_state_change)
        except Exception:
            pass
        logger.info("EventPoller stopped")

    async def _seed_warlog(self) -> None:
        try:
            entries = await asyncio.to_thread(
                self.bridge.get_warlog_entries, None, None, None, 50, 0
            )
            for e in entries:
                eid = str(e.get("id") or e.get("epoch") or "")
                if eid:
                    self._seen_warlog_ids.add(eid)
            summary = await asyncio.to_thread(self.bridge.get_warlog_summary)
            self._last_warlog_count = int(summary.get("total_entries") or 0)
        except Exception as exc:
            logger.warning("warlog seed failed: %s", exc)

    async def _loop_warlog(self) -> None:
        while self._running:
            try:
                await self._poll_warlog()
            except Exception as exc:
                logger.debug("warlog poll error: %s", exc)
            await asyncio.sleep(self.warlog_interval)

    async def _poll_warlog(self) -> None:
        if hub.client_count == 0:
            return
        self._maybe_reset_diff_state()
        entries = await asyncio.to_thread(
            self.bridge.get_warlog_entries, None, None, None, 30, 0
        )
        # entries are newest-first; emit oldest of the batch first
        new_entries = []
        for e in reversed(entries):
            eid = str(e.get("id") or f"{e.get('epoch')}:{e.get('message')}")
            if eid and eid not in self._seen_warlog_ids:
                self._seen_warlog_ids.add(eid)
                new_entries.append(e)
                self._event_rate_window.append(time.time())
        # Cap seen set
        if len(self._seen_warlog_ids) > 5000:
            self._seen_warlog_ids = set(list(self._seen_warlog_ids)[-2500:])
        for e in new_entries:
            await hub.broadcast("warlog", {"type": "warlog_entry", "data": e})

    async def _loop_c2(self) -> None:
        while self._running:
            try:
                await self._poll_c2()
            except Exception as exc:
                logger.debug("c2 poll error: %s", exc)
            await asyncio.sleep(self.c2_interval)

    async def _poll_c2(self) -> None:
        if hub.client_count == 0:
            return
        self._maybe_reset_diff_state()
        channels = await asyncio.to_thread(self.bridge.list_channels)
        snapshot = str(
            sorted(
                (
                    c.get("channel_id"),
                    c.get("status"),
                    c.get("beacon_count"),
                    c.get("last_beacon"),
                )
                for c in channels
            )
        )
        if snapshot != self._last_c2_snapshot:
            self._last_c2_snapshot = snapshot
            await hub.broadcast(
                "c2",
                {
                    "type": "c2_beacon",
                    "data": {
                        "channels": channels,
                        "count": len(channels),
                        "ts": time.time(),
                    },
                },
            )

    async def _loop_engagement(self) -> None:
        while self._running:
            try:
                await self._poll_engagement()
            except Exception as exc:
                logger.debug("engagement poll error: %s", exc)
            await asyncio.sleep(self.engagement_interval)

    async def _poll_engagement(self) -> None:
        if hub.client_count == 0:
            return
        self._maybe_reset_diff_state()
        status = await asyncio.to_thread(self.bridge.get_status)
        # Compare key fields
        keys = (
            "engaged",
            "target_count",
            "warlog_entries",
            "beacon_count",
            "c2_channels",
            "boneyard_items",
            "stolen_data",
            "stealth_active",
        )
        slim = {k: status.get(k) for k in keys}
        if slim != self._last_engagement:
            self._last_engagement = slim
            await hub.broadcast(
                "engagement",
                {"type": "engagement_update", "data": status},
            )

    async def _loop_integrity(self) -> None:
        while self._running:
            try:
                await self._poll_integrity()
            except Exception as exc:
                logger.debug("integrity poll error: %s", exc)
            await asyncio.sleep(self.integrity_interval)

    async def _poll_integrity(self) -> None:
        report = await asyncio.to_thread(self.bridge.verify_integrity)
        verified = bool(report.get("verified", True))
        if self._last_integrity_verified is None:
            self._last_integrity_verified = verified
            return
        if verified != self._last_integrity_verified:
            self._last_integrity_verified = verified
            if not verified:
                await hub.broadcast(
                    "integrity",
                    {"type": "integrity_alert", "data": report},
                )

    async def _loop_metrics(self) -> None:
        while self._running:
            try:
                await self._poll_metrics()
            except Exception as exc:
                logger.debug("metrics poll error: %s", exc)
            await asyncio.sleep(5.0)

    async def _poll_metrics(self) -> None:
        if hub.client_count == 0:
            return
        now = time.time()
        # Events in last 60s
        self._event_rate_window = [t for t in self._event_rate_window if now - t < 60]
        rate = len(self._event_rate_window)
        summary = await asyncio.to_thread(self.bridge.get_warlog_summary)
        status = await asyncio.to_thread(self.bridge.get_status)
        await hub.broadcast(
            "metrics",
            {
                "type": "metrics_tick",
                "data": {
                    "ts": now,
                    "uptime_seconds": round(now - self._started_at, 1),
                    "events_per_minute": rate,
                    "warlog_entries": summary.get("total_entries", 0),
                    "session_id": summary.get("session_id"),
                    "c2_channels": status.get("c2_channels", 0),
                    "c2_beacons": status.get("c2_beacons", 0),
                    "ws_clients": hub.client_count,
                    "level_counts": summary.get("level_counts", {}),
                },
            },
        )

    async def _loop_attack_graph(self) -> None:
        while self._running:
            try:
                await self._poll_attack_graph()
            except Exception as exc:
                logger.debug("attack_graph poll error: %s", exc)
            await asyncio.sleep(self.attack_graph_interval)

    async def _poll_attack_graph(self) -> None:
        """Diff new attack-path nodes and push them live.

        Emits ``attack_node`` for each newly recorded step (so the graph can
        pulse/animate it) plus ``attack_graph_full`` whenever the node count
        changes (so clients rebuild edges/outcomes). Only broadcasts real
        data from ``graph_attack_paths`` — never synthesizes.

        We seed ``_seen_attack_nodes`` even when no clients are connected so
        that the moment a viewer attaches we don't flood it with pulses for
        nodes the Attack Graph view has already rendered via REST.
        """
        graph = await asyncio.to_thread(self.bridge.graph_attack_paths, None)
        nodes = graph.get("nodes", []) or []
        self._maybe_reset_diff_state()
        if not nodes:
            return
        node_ids = {n.get("id") for n in nodes if n.get("id")}
        new_ids = node_ids - self._seen_attack_nodes
        if not new_ids:
            return
        # Remember the whole node set first to avoid re-emit races.
        self._seen_attack_nodes = node_ids
        if hub.client_count == 0:
            return  # seed state but don't broadcast
        new_nodes = [n for n in nodes if n.get("id") in new_ids]
        for n in new_nodes:
            await hub.broadcast(
                "attack_graph",
                {"type": "attack_node", "data": n},
            )
        # Full rebuild signal so clients re-relayout with the new edges.
        await hub.broadcast(
            "attack_graph",
            {"type": "attack_graph_full", "data": graph},
        )

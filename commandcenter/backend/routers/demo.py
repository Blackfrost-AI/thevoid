"""DEMO MODE toggle endpoints.

DEMO MODE swaps the Command Center onto isolated, deterministically seeded
stores so the stage demo never depends on live engagement data — and never
pollutes live integrity claims. See services/demo_seed.py for the scenario.

    GET  /api/demo          → current demo status
    POST /api/demo/enable   → enable (idempotent; wipes + reseeds demo stores)
    POST /api/demo/disable  → restore live stores and discard demo runtime

While active, every REST/WS endpoint transparently serves the seeded demo
data; ``demo_mode`` is also echoed in /api/status so the UI can badge it.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException

from commandcenter.backend.services.bridge import get_bridge
from commandcenter.backend.services.coverage_bridge import get_coverage_bridge
from commandcenter.backend.ws.hub import hub

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.get("")
async def demo_status():
    return get_bridge().demo_status()


@router.post("/enable")
async def demo_enable():
    bridge = get_bridge()
    try:
        status = await asyncio.to_thread(bridge.enable_demo_mode)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    await asyncio.to_thread(get_coverage_bridge().invalidate_cache)
    await hub.broadcast("demo", {"type": "demo_state", "data": status})
    return status


@router.post("/disable")
async def demo_disable():
    bridge = get_bridge()
    status = await asyncio.to_thread(bridge.disable_demo_mode)
    await asyncio.to_thread(get_coverage_bridge().invalidate_cache)
    await hub.broadcast("demo", {"type": "demo_state", "data": status})
    return status

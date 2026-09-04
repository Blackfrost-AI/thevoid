"""GET /api/status"""

from __future__ import annotations

from fastapi import APIRouter

from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["status"])


@router.get("/api/status")
async def get_status():
    bridge = get_bridge()
    return bridge.get_status()

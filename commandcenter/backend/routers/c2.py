"""C2 channel monitoring endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["c2"])


@router.get("/api/c2/channels")
async def list_channels():
    channels = get_bridge().list_channels()
    return {"channels": channels, "count": len(channels)}


@router.get("/api/c2/channels/{channel_id}")
async def channel_status(channel_id: str):
    status = get_bridge().get_channel_status(channel_id)
    if status.get("status") == "error" and "Unknown channel" in str(status.get("reason", "")):
        raise HTTPException(status_code=404, detail=status.get("reason"))
    return status


@router.get("/api/c2/channels/{channel_id}/health")
async def channel_health(channel_id: str):
    return get_bridge().check_channel_health(channel_id)


@router.get("/api/c2/tasks")
async def list_tasks(status: Optional[str] = Query(None)):
    tasks = get_bridge().get_tasks(status)
    return {"tasks": tasks, "count": len(tasks)}

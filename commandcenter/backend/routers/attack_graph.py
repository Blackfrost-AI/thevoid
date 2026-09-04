"""Attack graph endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["attack-graph"])


@router.get("/api/attack-graph")
async def attack_graph(host_id: Optional[str] = Query(None)):
    return get_bridge().graph_attack_paths(host_id)


@router.get("/api/attack-graph/{host_id}")
async def attack_graph_for_host(host_id: str):
    return get_bridge().graph_attack_paths(host_id)

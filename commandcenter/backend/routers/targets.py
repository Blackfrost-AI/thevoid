"""GET /api/targets"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["targets"])


@router.get("/api/targets")
async def list_targets(
    ip_address: Optional[str] = None,
    hostname: Optional[str] = None,
    domain: Optional[str] = None,
    status: Optional[str] = None,
    is_critical: Optional[bool] = None,
):
    filters = {}
    if ip_address is not None:
        filters["ip_address"] = ip_address
    if hostname is not None:
        filters["hostname"] = hostname
    if domain is not None:
        filters["domain"] = domain
    if status is not None:
        filters["status"] = status
    if is_critical is not None:
        filters["is_critical"] = 1 if is_critical else 0
    bridge = get_bridge()
    hosts = bridge.query_hosts(filters or None)
    return {"targets": hosts, "count": len(hosts)}


@router.get("/api/targets/{host_id}")
async def get_target(host_id: str):
    bridge = get_bridge()
    detail = bridge.get_target(host_id)
    if not detail.get("host"):
        raise HTTPException(status_code=404, detail=f"Target not found: {host_id}")
    return detail

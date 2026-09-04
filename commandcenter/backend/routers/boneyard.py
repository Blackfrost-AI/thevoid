"""Boneyard findings / summary / integrity endpoints."""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query

from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["boneyard"])


@router.get("/api/findings")
async def list_findings(
    category: Optional[str] = None,
    host_id: Optional[str] = None,
    risk_min: Optional[float] = None,
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    limit: int = Query(200, ge=1, le=5000),
):
    filters: dict = {"limit": limit}
    if category:
        filters["category"] = category
    if host_id:
        filters["host_id"] = host_id
    if risk_min is not None:
        filters["risk_min"] = risk_min
    if tags:
        filters["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    bridge = get_bridge()
    findings = bridge.query_findings(filters)
    return {"findings": findings, "count": len(findings)}


@router.get("/api/findings/search")
async def search_findings(
    q: Optional[str] = Query(None, alias="query"),
    category: Optional[str] = None,
    tags: Optional[str] = None,
    limit: int = Query(200, ge=1, le=2000),
):
    tag_list: Optional[List[str]] = None
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    bridge = get_bridge()
    results = bridge.search_findings(
        query=q, category=category, tags=tag_list, limit=limit
    )
    return {"findings": results, "count": len(results), "query": q}


@router.get("/api/boneyard/summary")
async def boneyard_summary():
    return get_bridge().boneyard_summary()


@router.get("/api/boneyard/categories")
async def boneyard_categories():
    cats = get_bridge().boneyard_categories()
    return {"categories": cats, "count": len(cats)}


@router.get("/api/boneyard/integrity")
async def boneyard_integrity():
    return get_bridge().verify_integrity()

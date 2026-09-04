"""WarLog endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from commandcenter.backend.config import load_settings
from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["warlog"])


@router.get("/api/warlog/entries")
async def warlog_entries(
    level: Optional[str] = None,
    module: Optional[str] = None,
    target: Optional[str] = None,
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
):
    entries = get_bridge().get_warlog_entries(
        level=level, module=module, target=target, limit=limit, offset=offset
    )
    return {"entries": entries, "count": len(entries), "limit": limit, "offset": offset}


@router.get("/api/warlog/summary")
async def warlog_summary():
    return get_bridge().get_warlog_summary()


@router.get("/api/warlog/spans")
async def warlog_spans(
    operation: Optional[str] = None,
    limit: int = Query(500, ge=1, le=5000),
):
    spans = get_bridge().query_spans(operation=operation, limit=limit)
    return {"spans": spans, "count": len(spans)}


@router.post("/api/warlog/export")
async def warlog_export():
    settings = load_settings()
    try:
        result = get_bridge().export_warlog(settings.export_dir)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return result


@router.get("/api/warlog/export/download")
async def warlog_export_download():
    """Export and immediately return the file for download."""
    settings = load_settings()
    try:
        result = get_bridge().export_warlog(settings.export_dir)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return FileResponse(
        result["path"],
        media_type="application/json",
        filename="warlog_export.json",
    )

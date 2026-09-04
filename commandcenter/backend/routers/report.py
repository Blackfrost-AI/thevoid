"""Report generation endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from commandcenter.backend.config import load_settings
from commandcenter.backend.models.schemas import ReportGenerateRequest
from commandcenter.backend.services.bridge import get_bridge

router = APIRouter(tags=["report"])


@router.get("/api/report/preview")
async def report_preview(
    operator: str = Query("THE VOID"),
    engagement_name: str = Query("Engagement Report"),
):
    data = get_bridge().gather_report_data(
        operator=operator, engagement_name=engagement_name
    )
    if data.get("error"):
        raise HTTPException(status_code=503, detail=data["error"])
    return data


@router.post("/api/report/generate")
async def report_generate(body: ReportGenerateRequest):
    settings = load_settings()
    fmt = (body.format or "json").lower().strip()
    if fmt not in ("json", "markdown", "md", "html"):
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")
    output_path = body.output_path
    if output_path is not None:
        # Constrain to export_dir — prevent arbitrary file writes
        candidate = Path(output_path)
        if not candidate.is_absolute():
            candidate = (settings.export_dir / candidate)
        try:
            candidate.resolve().relative_to(settings.export_dir.resolve())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="output_path must be within the export directory",
            )
        output_path = str(candidate)
    else:
        ext = "md" if fmt in ("markdown", "md") else fmt
        output_path = str(settings.export_dir / f"report.{ext}")
    try:
        result = get_bridge().generate_report(
            fmt=fmt,
            operator=body.operator,
            engagement_name=body.engagement_name,
            output_path=output_path,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result

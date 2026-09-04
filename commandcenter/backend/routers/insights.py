"""Insights endpoints — real R-line engine data for the web UI.

Replaces client-side heuristics with the same engines the CLI report uses:

    GET /api/coverage     — prevention-strength scoring (R-2)
    GET /api/mitre        — MITRE ATT&CK technique coverage (R-1)
    GET /api/compliance   — NIST CSF / PCI DSS / ISO 27001 overlay (R-4)
    GET /api/drift        — continuity drift events (R-3)
    GET /api/scenarios    — scenario catalog (R-6)

All endpoints are read-only, localhost-bound, and return honest empty
responses when no data exists.
"""

from __future__ import annotations

from fastapi import APIRouter

from commandcenter.backend.services.coverage_bridge import get_coverage_bridge

router = APIRouter(tags=["insights"])


@router.get("/api/coverage")
async def coverage():
    """Prevention-strength scoring over all engagements (R-2)."""
    return get_coverage_bridge().coverage()


@router.get("/api/mitre")
async def mitre():
    """Real MITRE ATT&CK technique/tactic coverage (R-1)."""
    return get_coverage_bridge().mitre()


@router.get("/api/compliance")
async def compliance():
    """Compliance cross-reference for mapped techniques (R-4)."""
    return get_coverage_bridge().compliance()


@router.get("/api/drift")
async def drift():
    """Continuity drift events persisted by the scheduler (R-3)."""
    return get_coverage_bridge().drift()


@router.get("/api/scenarios")
async def scenarios():
    """Attack scenario catalog (R-6)."""
    return get_coverage_bridge().scenarios()

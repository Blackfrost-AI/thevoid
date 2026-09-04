"""Shared projection of recorded evidence for CLI and browser reports."""

from __future__ import annotations

import json
from typing import Any


def recorded_engagements(boneyard: Any, *, category_limit: int = 10000) -> list[dict[str, Any]]:
    """Read stored summaries without instantiating an operational engine.

    Oversized or invalid reports fail explicitly rather than returning false
    zero counts or truncated totals.
    """
    if boneyard is None:
        raise RuntimeError("Evidence store is unavailable.")
    payloads: list[dict[str, Any]] = []
    seen: set[str] = set()
    for category in sorted(c for c in boneyard.categories() if c.startswith("attack_")):
        rows = boneyard.search(category=category, limit=category_limit + 1)
        if len(rows) > category_limit:
            raise RuntimeError(
                "Recorded report exceeds its per-category limit; totals cannot be reported completely."
            )
        for row in rows:
            payload = row.get("data")
            if not isinstance(payload, dict):
                raise ValueError("Recorded engagement contains an invalid payload.")
            key = json.dumps(payload, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                payloads.append(payload)
    return payloads

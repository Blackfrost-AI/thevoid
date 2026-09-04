"""Fail a dependency gate when either required lockfile was not inventoried."""

from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_LOCKS = (
    "release/requirements-runtime.txt",
    "commandcenter/frontend/package-lock.json",
)


def check_inventory(document: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in document.get("Results", []):
        target = str(result.get("Target", "")).replace("\\", "/")
        for expected in REQUIRED_LOCKS:
            if target == expected or target.endswith("/" + expected):
                counts[expected] = len(result.get("Packages") or [])
    missing = [path for path in REQUIRED_LOCKS if not counts.get(path)]
    if missing:
        raise ValueError(
            "Dependency scan omitted required package inventories: " + ", ".join(missing)
        )
    return counts


def main() -> int:
    try:
        document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        print(json.dumps(check_inventory(document), sort_keys=True))
    except (OSError, ValueError, IndexError, AttributeError, TypeError) as exc:
        print(f"Dependency inventory check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

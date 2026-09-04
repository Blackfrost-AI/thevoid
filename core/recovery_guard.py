"""Classify recovery-only Snowblind invocations without importing host modules."""

from __future__ import annotations

import sys
from collections.abc import Sequence


def is_recovery_command(arguments: Sequence[str]) -> bool:
    """Match the actual subcommand, never a word occurring in an option value."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"--help", "-h", "--version", "-v"}:
            return True
        if argument == "--dry-run" or argument.startswith("--persona="):
            index += 1
            continue
        if argument == "--persona":
            if index + 1 >= len(arguments) or arguments[index + 1].startswith("-"):
                return False
            index += 2
            continue
        return argument in {"restore", "doctor", "status"}
    return False


if __name__ == "__main__":
    raise SystemExit(0 if is_recovery_command(sys.argv[1:]) else 1)

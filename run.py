#!/usr/bin/env python3
"""THE VOID — Runner script.

This is the main entry point for THE VOID — operator-authorized AI red team.

Usage:
    python run.py <target> [mode]
    python run.py engage <target> --mode <mode>
    python run.py demo --no-animate
    python run.py --help

Modes:
    quick       Reconnaissance-only validation
    full        Standard authorized phase plan
    aggressive  Expanded authorized phase plan
    chaos       Full scope-gated phase plan
"""

import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import Settings
from orchestrator.chaos import ChaosEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("void")


def print_banner():
    """Print the banner (canonical source: config.defaults.VOID_BANNER)."""
    from config.defaults import VOID_BANNER
    print(VOID_BANNER)
    print("    THE VOID — Operator-authorized AI red team")
    print("    Local · Auditable · MCP-aware · Scope-gated")
    print()


def main():
    """Main entry point.

    Delegates to the new click-based CLI (``cli.app:cli``) for a unified
    experience. The legacy argparse-style invocation is still supported:
    a bare ``python run.py <target> [mode]`` is translated into
    ``thevoid engage <target> --mode <mode>``.
    """
    # Detect legacy positional invocation: `python run.py <target> [mode]`
    # without any click-style flags. If recognized, dispatch via the CLI.
    raw_args = sys.argv[1:]

    # Hand every explicit Click command to the Click CLI. Keep this list in
    # sync with cli.app so the compatibility entrypoint cannot accidentally
    # interpret a subcommand name as a target.
    click_commands = {
        "engage", "recon", "report", "targets", "status", "version",
        "demo", "scenarios", "continuity",
    }
    if not raw_args or raw_args[0].startswith("-") or raw_args[0] in click_commands:
        from cli.app import cli
        cli(prog_name="thevoid")
        return

    # Legacy mode: translate `python run.py <target> [mode] [flags...]`
    # into the click equivalent.
    from cli.app import cli as _cli

    if "--interactive" in raw_args or "-i" in raw_args:
        settings = Settings()
        engine = ChaosEngine(settings)
        print_banner()
        engine.run_interactive()
        return

    # Legacy form: `run.py TARGET [MODE] [CLICK OPTIONS]`.
    target = raw_args[0]
    remainder = list(raw_args[1:])
    click_args = ["engage", target]
    if remainder and remainder[0].lower() in {
        "quick", "full", "aggressive", "stealth", "chaos",
    }:
        click_args.extend(["--mode", remainder.pop(0).lower()])
    click_args.extend(remainder)

    print_banner()
    _cli(args=click_args, prog_name="thevoid", obj={})


if __name__ == "__main__":
    main()

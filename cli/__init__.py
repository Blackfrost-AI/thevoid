"""THE VOID — CLI package.

A click-based command-line interface for THE VOID hacker agent.

Entry point: ``thevoid`` (registered in setup.py console_scripts).
Programmatic access: ``from cli.app import cli``.
"""

from .app import cli  # noqa: F401

__all__ = ["cli"]

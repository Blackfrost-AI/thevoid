"""Root conftest — ensure project root is importable for all tests."""

from __future__ import annotations

import os
import sys

# Project root is this file's directory.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

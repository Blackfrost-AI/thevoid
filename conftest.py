"""Root conftest — ensure project root is importable for all tests."""

from __future__ import annotations

import os
import sys
import tempfile

# Project root is this file's directory.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Keep every test-created database, log, export, and launcher record away from
# both the repository and the operator's real XDG state. This is established
# before test modules import config.defaults.
_TEST_RUNTIME = tempfile.TemporaryDirectory(prefix="the-void-tests-")
for _name, _leaf in (
    ("VOID_CONFIG_DIR", "config"),
    ("VOID_STATE_DIR", "state"),
    ("VOID_DATA_DIR", "data"),
    ("VOID_CACHE_DIR", "cache"),
    ("VOID_RUNTIME_DIR", "run"),
):
    os.environ[_name] = os.path.join(_TEST_RUNTIME.name, _leaf)

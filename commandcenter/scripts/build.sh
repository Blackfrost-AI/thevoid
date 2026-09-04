#!/usr/bin/env bash
# Build frontend and leave dist for FastAPI static serving.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CC="$ROOT/commandcenter"

echo "==> Building frontend"
cd "$CC/frontend"
npm install
npm run build

echo "==> Frontend built to $CC/frontend/dist"
echo "    Run: PYTHONPATH=$ROOT python -m commandcenter.backend.main"
echo "    Open: http://127.0.0.1:7070"

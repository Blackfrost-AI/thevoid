#!/usr/bin/env bash
# Start FastAPI backend + Vite frontend for development.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CC="$ROOT/commandcenter"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

HOST="${VOID_CC_HOST:-127.0.0.1}"
PORT="${VOID_CC_PORT:-7070}"

if [[ "$HOST" == "0.0.0.0" ]]; then
  echo "ERROR: Refusing VOID_CC_HOST=0.0.0.0 (localhost only)" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
  if [[ -n "${FRONTEND_PID:-}" ]]; then kill "$FRONTEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

echo "==> Starting command center backend on ${HOST}:${PORT}"
cd "$ROOT"
python -m commandcenter.backend.main &
BACKEND_PID=$!

# Wait for API
for i in $(seq 1 30); do
  if curl -sf "http://${HOST}:${PORT}/api/health" >/dev/null 2>&1; then
    echo "==> Backend healthy"
    break
  fi
  sleep 0.3
done

echo "==> Starting Vite dev server (proxies /api and /ws)"
cd "$CC/frontend"
npm run dev -- --host 127.0.0.1 --port 5173 &
FRONTEND_PID=$!

echo ""
echo "  Backend:  http://${HOST}:${PORT}"
echo "  Frontend: http://127.0.0.1:5173"
echo "  API docs: http://${HOST}:${PORT}/api/docs"
echo ""
wait

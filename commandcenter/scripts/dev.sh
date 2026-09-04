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
BACKEND_HEALTHY=false
for i in $(seq 1 30); do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "ERROR: Command Center backend exited during startup" >&2
    wait "$BACKEND_PID" || true
    exit 1
  fi
  if curl -sf "http://${HOST}:${PORT}/api/health" >/dev/null 2>&1; then
    echo "==> Backend healthy"
    BACKEND_HEALTHY=true
    break
  fi
  sleep 0.3
done

if [[ "$BACKEND_HEALTHY" != "true" ]]; then
  echo "ERROR: Command Center backend did not become healthy at http://${HOST}:${PORT}" >&2
  exit 1
fi

echo "==> Starting Vite dev server (proxies /api and /ws)"
cd "$CC/frontend"
npm run dev -- --host 127.0.0.1 --port 5173 &
FRONTEND_PID=$!

echo ""
echo "  Backend:  http://${HOST}:${PORT}"
echo "  Frontend: http://127.0.0.1:5173"
echo "  API docs: http://${HOST}:${PORT}/api/docs"
echo ""

# Stop the paired process if either side exits. Otherwise a backend crash can
# leave a healthy-looking Vite page whose API and WebSocket proxy are dead.
set +e
wait -n "$BACKEND_PID" "$FRONTEND_PID"
STATUS=$?
set -e

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo "ERROR: Command Center backend stopped; shutting down the dev server" >&2
  if [[ "$STATUS" -eq 0 ]]; then STATUS=1; fi
elif ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
  echo "==> Frontend dev server stopped; shutting down the backend"
fi

exit "$STATUS"

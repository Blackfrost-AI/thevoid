#!/usr/bin/env bash
# Serve THE VOID engagement marketing site on localhost only.
set -euo pipefail
cd "$(dirname "$0")"
HOST="${1:-127.0.0.1}"
PORT="${2:-8088}"
if [[ "$HOST" == "0.0.0.0" ]]; then
  echo "Refusing 0.0.0.0 — use 127.0.0.1 for demo." >&2
  exit 1
fi
echo "THE VOID marketing site → http://${HOST}:${PORT}"
echo "Operator Command Center (separate) → http://127.0.0.1:7070"
exec python3 -m http.server "$PORT" --bind "$HOST"

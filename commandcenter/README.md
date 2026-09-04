# THE VOID — Command Center

Localhost-only operator console for THE VOID red team platform. Dense dark operator theme, real-time WarLog stream, Boneyard intelligence, attack graph, C2 evidence, and report generation.

**Binding:** `127.0.0.1:7070` only. No multi-tenant, no cloud, no external network.

## Quick start

```bash
# Development (API + Vite HMR)
cd commandcenter
./scripts/dev.sh
# → Frontend http://127.0.0.1:5173
# → Backend  http://127.0.0.1:7070

# Production (single process)
./scripts/build.sh
cd ..
thevoid-command-center start
# → http://127.0.0.1:7070
```

## Architecture

```
Browser ──REST/WS──► FastAPI projection ──► Boneyard / WarLog / Reporter
```

- **Visual-first, read-mostly** workflow against existing SQLite stores
- **WebSocket** pollers push WarLog, C2 evidence, engagement, metrics, integrity, and graph diffs
- Completed engagements and channel evidence remain visible across process restarts
- Secrets (`auth`, tokens, HMACs) stripped from API responses

## Views

| View | Purpose |
|------|---------|
| Operations | Engagement status, live WarLog, C2 activity, MITRE heatmap, event-rate sparkline |
| Targets | Host table from `Boneyard.query_hosts()` |
| Boneyard | Findings, search, categories, integrity badge |
| Attack Graph | Directed, outcome-aware `graph_attack_paths()` visualization |
| C2 Channels | Live channel state when injected plus restart-safe recorded evidence |
| WarLog | Filtered event table + export |
| Reports | `Reporter.generate()` JSON / Markdown / HTML |
| Timeline | Chronological engagement-phase evidence |
| Prevention | Coverage score and control effectiveness |
| Compliance | MITRE-to-framework advisory cross-reference |
| Drift | Changes between recorded runs |
| Ctrl+K | Command palette for navigation & actions |

## API

See interactive docs at `/api/docs` when the server is running.

Key routes: `/api/status`, `/api/targets`, `/api/findings`, `/api/boneyard/*`, `/api/attack-graph`, `/api/c2/*`, `/api/warlog/*`, `/api/report/*`, `WS /ws/live`.

## Tests

```bash
# Backend
cd /path/to/void_client
python -m pytest commandcenter/tests/backend/ -v
```

## Security

| Control | Detail |
|---------|--------|
| Localhost bind | Asserted at startup; rejects `0.0.0.0` |
| Browser boundary | Loopback Host allowlist plus Origin checks on mutations and WebSockets |
| Browser hardening | CSP, frame denial, no-referrer, MIME sniffing, and permissions headers |
| No telemetry | No outbound analytics or hosted service dependency |
| Offline entitlement | Commercial startup verifies a signed local license; status is visible in Settings |
| No secrets in browser | Response sanitizer strips credentials / HMACs |
| Write path | Report/export only; no attack initiation |

This release visualizes, investigates, and exports validation evidence. It
does not launch validation jobs; a future visual runner needs an explicit
scope, authorization, approval, and cancellation workflow before it replaces
that remaining operator path.

## Process lifecycle and local files

```bash
thevoid-command-center start       # background + open browser
thevoid-command-center start --no-open
thevoid-command-center status
thevoid-command-center open
thevoid-command-center stop
thevoid-command-center foreground  # terminal-attached troubleshooting
```

The background launcher records a mode-0600 PID file below the operator's XDG
runtime directory and writes logs below
`~/.local/state/blackfrost/the-void/logs/`. It refuses to run as root and never
signals a PID unless `/proc` confirms the process belongs to the current user
and is the expected backend.

Mutable stores, exports, UI preferences, and Demo Mode data also live outside
the source/install tree in XDG state/data locations. See the root README for
the complete layout.

## Stack

- Backend: FastAPI + uvicorn
- Frontend: React 19 + TypeScript + Vite + Tailwind CSS v4 + Zustand + Recharts + react-force-graph-2d

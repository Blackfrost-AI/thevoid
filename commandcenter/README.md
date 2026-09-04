# THE VOID — Command Center

Localhost-only operator console for THE VOID red team platform. Palantir-style dark theme, real-time WarLog stream, Boneyard intelligence, attack graph, C2 monitoring, and report generation.

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
PYTHONPATH=. python -m commandcenter.backend.main
# → http://127.0.0.1:7070
```

## Architecture

```
Browser ──REST/WS──► FastAPI (bridge) ──► Boneyard / WarLog / ChaosEngine / MCPC2 / Reporter
```

- **Read-mostly** against existing SQLite stores
- **WebSocket** pollers push WarLog, C2, engagement, metrics, integrity diffs
- **No modification** of core VOID modules — import-only bridge layer
- Secrets (`auth`, tokens, HMACs) stripped from API responses

## Views

| View | Purpose |
|------|---------|
| Operations | Engagement status, live WarLog, C2 health, MITRE heatmap, event-rate sparkline |
| Targets | Host table from `Boneyard.query_hosts()` |
| Boneyard | Findings, search, categories, integrity badge |
| Attack Graph | Force-directed `graph_attack_paths()` |
| C2 Channels | `MCPC2.list_channels()` + health checks |
| WarLog | Filtered event table + export |
| Reports | `Reporter.generate()` JSON / Markdown / HTML |
| Timeline | Chronological engagement-phase evidence |
| Prevention | Coverage score and control effectiveness |
| Compliance | Authorization and policy posture |
| Drift | Changes between recorded runs |
| ⌘K | Command palette for navigation & actions |

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
| No egress | No outbound telemetry; deps bundled |
| No secrets in browser | Response sanitizer strips credentials / HMACs |
| Write path | Report/export only; no attack initiation |

## Stack

- Backend: FastAPI + uvicorn
- Frontend: React 19 + TypeScript + Vite + Tailwind CSS v4 + Zustand + Recharts + react-force-graph-2d

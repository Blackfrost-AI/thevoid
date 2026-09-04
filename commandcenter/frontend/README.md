# Command Center frontend

React and TypeScript browser client for the localhost Command Center. The
production bundle is served by FastAPI from `dist/`; Vite is only used during
development.

## Develop

From the repository root:

```bash
./commandcenter/scripts/dev.sh
```

Open `http://127.0.0.1:5173`. Vite proxies REST and WebSocket traffic to the
backend on `127.0.0.1:7070`.

## Verify and build

```bash
npm ci
npm run lint
npm run build
```

The committed `dist/` bundle is the client-testing artifact. Rebuild it after
every frontend change and test the production URL at `http://127.0.0.1:7070`.

## Interaction model

- Primary navigation has stable URLs and supports browser Back/Forward.
- `Ctrl+K` opens navigation and common actions.
- Demo Mode uses isolated synthetic data and is clearly badged.
- Tables, graphs, timeline evidence, reports, and downloads are browser-first.
- The layout supports desktop and narrow operator windows.

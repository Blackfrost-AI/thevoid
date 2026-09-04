# THE VOID

Local, operator-authorized security validation for Linux environments.

THE VOID combines a scope-gated command-line workflow, tamper-evident local
records, coverage scoring, reporting, and a localhost Command Center. All
runtime data stays on the operator's machine unless the operator explicitly
exports it.

> Use only on systems you own or have written permission to test. Define the
> rules of engagement before running active phases.

## Included components

| Component | Purpose |
|---|---|
| `cli/` | Primary `thevoid` command-line interface |
| `agent/` | Phase orchestration and injection defenses |
| `core/` | Authorization, execution, local storage, and integrity controls |
| `recon/` | Reconnaissance modules |
| `exploit/` | Scope-gated validation modules |
| `modules/` | Reporting, coverage, continuity, and export support |
| `scenarios/` | Curated phase plans |
| `commandcenter/` | Localhost REST, WebSocket, and browser console |
| `mcp-tools/mcp-scanner/` | MCP configuration and dependency scanner |
| `snowblind/` | Bundled Linux privacy and network-containment toolkit |
| `Frosty/` | Frosty agent identity and operating policy |
| `website/` | Optional local demonstration site |
| `tests/` | Core automated test suite |

Historical customer data, prior assessment output, credentials, runtime
databases, session logs, model weights, and internal research are intentionally
not included in this client repository.

## Requirements

- Linux; Kali or another Debian-family distribution is recommended
- Python 3.10 or newer
- Node.js 18 or newer only when rebuilding the Command Center frontend
- Security tools required by the phases you explicitly enable

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The two installed command names are equivalent:

```bash
thevoid version
void version
```

## Safe first run

Inspect the demonstration authorization profile, then perform a dry run:

```bash
thevoid recon 127.0.0.1 --profile demo --dry-run
thevoid engage 127.0.0.1 --profile demo --dry-run --mode quick
```

The guided demonstration uses fictional data and performs no network activity:

```bash
thevoid demo --no-animate
```

## Authorization

Use `--authz PATH`, `--profile client`, or a configuration file to require a
scope document. A minimal example is available at
`config/examples/authorization.demo.json`.

Active phases should never be used without written authorization. The operator
remains responsible for target scope, timing, credentials, and permitted
techniques.

## Command Center

The Command Center binds to `127.0.0.1:7070` and rejects non-loopback hosts.

```bash
python -m commandcenter.backend.main
```

Open `http://127.0.0.1:7070`. The production frontend is bundled under
`commandcenter/frontend/dist`. To rebuild it:

```bash
cd commandcenter/frontend
npm ci
npm run build
npm run lint
```

The Command Center's Demo Mode uses isolated synthetic stores. Disable Demo
Mode before returning to live local records.

## Snowblind

Snowblind is included directly in this repository so client testing does not
depend on a second download. It retains its own license, acceptable-use policy,
installation guide, and `snow` CLI under `snowblind/`.

Review `snowblind/README.md` and run its read-only diagnostic before applying
host networking changes:

```bash
cd snowblind
sudo python3 snow.py doctor
```

## Verification

```bash
python -m pytest tests commandcenter/tests/backend -q
python -m compileall -q agent c2 cli commandcenter config core exploit llm modules orchestrator recon scenarios
cd commandcenter/frontend && npm ci && npm run build && npm run lint
```

For the complete client acceptance sequence, see [CLIENT_TESTING.md](CLIENT_TESTING.md).

## Runtime data

The following are local runtime state and must not be committed:

- `.env*` except `.env.example`
- `.shadow/`, `results/`, `targets/`, and `archive/`
- `boneyard/`, `warlog/`, Command Center exports, and Snowblind state
- model weights, private keys, certificates, and credential files

## License

THE VOID is proprietary Blackfrost AI software. Bundled components retain the
license files shipped in their respective directories.

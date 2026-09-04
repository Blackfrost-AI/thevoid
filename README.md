# THE VOID

Operator-authorized, local-first security validation for Linux.

THE VOID combines scope-gated validation, tamper-evident evidence, coverage
scoring, reporting, continuity checks, and a browser-first Command Center.
Frosty is the operator-facing agent identity. Runtime evidence remains on the
operator workstation unless an operator explicitly selects an export.

> **Authorized use only.** Run active phases only against systems you own or
> have written permission to test. Confirm the target, time window, permitted
> techniques, credentials, and restoration plan in the rules of engagement
> before execution.

This repository is the clean client-testing baseline. It intentionally contains
no previous customer records, assessment output, credentials, runtime databases,
session logs, private model weights, or internal research.

| Release detail | Value |
|---|---|
| THE VOID | 1.1.0 |
| Command Center | 1.0.0 |
| Agent identity | Frosty |
| Primary experience | Local browser console |
| Gated execution path | <code>thevoid</code> CLI |
| Supported runtime | Linux, Python 3.10+ |
| Primary demo platform | Kali Linux |
| License | Proprietary Blackfrost AI software |

## Contents

- [Start here: browser demo](#start-here-browser-demo)
- [What THE VOID is](#what-the-void-is)
- [Architecture](#architecture)
- [Repository map](#repository-map)
- [Requirements](#requirements)
- [Installation](#installation)
- [Private commercial distribution](#private-commercial-distribution)
- [Command Center](#command-center)
- [Authorization and rules of engagement](#authorization-and-rules-of-engagement)
- [CLI reference](#cli-reference)
- [Modes and scenarios](#modes-and-scenarios)
- [Evidence, integrity, and reporting](#evidence-integrity-and-reporting)
- [Continuity and drift](#continuity-and-drift)
- [Bundled components](#bundled-components)
- [Verification and CI](#verification-and-ci)
- [Client demonstration playbook](#client-demonstration-playbook)
- [Runtime data and repository hygiene](#runtime-data-and-repository-hygiene)
- [Troubleshooting](#troubleshooting)
- [Documentation and support handoff](#documentation-and-support-handoff)

## Start here: browser demo

The production browser bundle is committed, so Node.js is not required just to
run the client demo.

From the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m commandcenter.backend.main
~~~

Open [http://127.0.0.1:7070](http://127.0.0.1:7070). On an empty workspace,
select **Explore Demo**, or use the **DEMO OFF** toggle in the top bar. Demo Mode
loads a deterministic fictional assessment into isolated stores and does not
contact real targets.

Useful checks from a second terminal:

~~~bash
curl -fsS http://127.0.0.1:7070/api/health
thevoid version
thevoid status
~~~

The health response should report <code>"ok": true</code>. Stop the server with
Ctrl+C. Use the top-bar toggle to return to live local stores before beginning an
authorized assessment.

## What THE VOID is

THE VOID is:

- A Linux security-validation platform controlled by an operator.
- A visual evidence and reporting workspace backed by local data.
- A CLI execution path with target, mode, and phase authorization gates.
- A deterministic, network-free demo for client walkthroughs and training.
- An auditable evidence pipeline built around WarLog and Boneyard.
- A set of curated validation scenarios, continuity checks, and prevention
  scoring.
- MCP-aware, with a bundled scanner integration whose current maturity and
  limitations are documented.

THE VOID is not:

- A remote, multi-tenant service or hosted control plane.
- A replacement for written authorization or professional judgment.
- An autonomous authorization authority.
- A guarantee of compromise, prevention, or compliance.
- A repository for customer evidence, credentials, or engagement archives.

The Command Center currently visualizes, investigates, and exports evidence. It
does **not** launch validation jobs. Active execution remains on the gated CLI
until a browser runner includes explicit scope review, approval, progress,
cancellation, and recovery controls.

## Architecture

~~~text
                         local operator workstation

  approved target + ROE
           |
           v
  thevoid CLI -> scope/mode/phase gates -> Frosty orchestrator -> adapters
                                                |
                                                v
                                      WarLog + Boneyard
                                                |
                                                v
  Browser <--- localhost REST + WebSocket --- Command Center
                                                |
                                      reports / local exports

  Explore Demo -> isolated synthetic stores ----^
~~~

The browser and CLI read the same live local evidence stores. WebSocket pollers
project new WarLog, engagement, graph, metrics, integrity, and channel events
into the interface. Completed engagements and recorded channel evidence remain
visible after a Command Center restart.

Demo Mode swaps the projection layer to an isolated directory below the
operator's XDG state root. It does not write to the live Boneyard or WarLog,
and the synthetic stores are rebuilt deterministically whenever Demo Mode is
enabled.

## Repository map

| Path | Purpose |
|---|---|
| <code>cli/</code> | Main <code>thevoid</code> command group and operator output |
| <code>agent/</code> | Frosty orchestration, phase selection, and injection defenses |
| <code>orchestrator/</code> | Engagement coordination |
| <code>core/</code> | Authorization, execution, targets, WarLog, Boneyard, and integrity |
| <code>recon/</code> | Reconnaissance modules |
| <code>exploit/</code> | Scope-gated validation modules |
| <code>modules/</code> | Reporting, export, coverage, continuity, and specialist phases |
| <code>c2/</code> | Channel abstractions used by authorized validation workflows |
| <code>llm/</code> | LLM security-validation support |
| <code>scenarios/</code> | Curated named phase plans |
| <code>commandcenter/</code> | FastAPI backend, React frontend, scripts, and tests |
| <code>mcp-tools/mcp-scanner/</code> | Bundled MCP scanner integration scaffold |
| <code>Frosty/</code> | Agent identity, operating policy, and local settings |
| <code>snowblind/</code> | Bundled Linux privacy and network-containment toolkit |
| <code>website/</code> | Optional localhost demonstration site |
| <code>tests/</code> | Core automated test suite |
| <code>docs/</code> | Operator documentation |
| <code>config/examples/</code> | Fictional demo authorization and profile examples |

## Requirements

### Required

- Linux. Kali Linux is the primary demo target; other Debian-family systems are
  suitable for development and testing.
- Python 3.10 or newer.
- <code>python3-venv</code> and <code>python3-pip</code>.
- A modern browser.

On a minimal Kali installation:

~~~bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
~~~

### Frontend development only

The committed production bundle does not need Node.js. Rebuilding or developing
the frontend requires a Node.js version supported by Vite 8:

- Node.js 20.19 or newer in the Node 20 line, or
- Node.js 22.12 or newer.

### Phase-specific tools

Some active phases use external security tools or services. Install only the
dependencies required by the approved validation plan. A successful Python
installation does not imply that every optional external adapter is available.
Missing integrations should be treated as a preflight finding, not bypassed.

## Installation

### Licensed customer bundle

The supported commercial delivery is one customer-specific archive containing
the main application package, the Snowblind companion package, and an offline
signed entitlement:

~~~bash
tar --extract --zstd --file the-void-<version>-linux-amd64-<token>.tar.zst
cd the-void-<version>-linux-amd64-<token>
sudo ./install.sh /path/to/blackfrost-release-signing.pub
thevoid-command-center start
~~~

The release key must be downloaded independently and kept outside the extracted
bundle; the installer refuses any key located inside the bundle as its trust
anchor. The launcher opens the local browser console. Blackfrost's package
scripts do not start the application or change firewall/routing policy. Confirm
the archive SHA-256 and release-key fingerprint against the authenticated
customer portal first.

### Private source checkout

Create an isolated environment from the repository root:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
~~~

The editable install exposes the CLI and visual launcher entry points:

~~~bash
thevoid version
void version
thevoid-command-center --help
~~~

Use <code>thevoid</code> in documentation and operator notes for consistency.
After reopening a terminal, reactivate the environment:

~~~bash
source .venv/bin/activate
~~~

For a runtime-only installation, omit the development extra:

~~~bash
python -m pip install -e .
~~~

## Private commercial distribution

Source stays in the private repository. Release engineering produces two
native `.deb` packages, SPDX SBOMs, signed checksums, and a single
customer-specific `tar.zst`. The application packages are generic and signed
once; the fulfillment worker adds a separately signed offline entitlement for
each paid order.

Packaging is not source-code secrecy. Python wheels, Debian packages, and
frozen executables can be inspected. The security boundary is private source
access, protected signing keys, least-privilege runtime design, verified
artifacts, entitlement enforcement, and the commercial agreement.

See [Private Commercial Distribution](docs/DISTRIBUTION.md) for the build,
signing, verification, upgrade, and recovery runbook. The exact implementation
contract for the existing store, site, and object storage is in
[Store, Website, and Object-Storage Handoff](docs/STORE_S3_HANDOFF.md).

## Command Center

### Production mode

~~~bash
thevoid-command-center start
thevoid-command-center status
thevoid-command-center stop
~~~

Use `thevoid-command-center foreground` when terminal-attached logs are
preferred. The single process serves the API, WebSocket endpoint, and bundled frontend at
[http://127.0.0.1:7070](http://127.0.0.1:7070). Interactive API documentation is
available at [http://127.0.0.1:7070/api/docs](http://127.0.0.1:7070/api/docs).

To select another local port:

~~~bash
VOID_CC_PORT=7071 python -m commandcenter.backend.main
~~~

The host setting is intentionally restricted to loopback. Startup rejects
wildcard and non-local addresses.

### Development mode

~~~bash
cd commandcenter
./scripts/dev.sh
~~~

Development mode serves the Vite frontend at
[http://127.0.0.1:5173](http://127.0.0.1:5173) and the backend at
[http://127.0.0.1:7070](http://127.0.0.1:7070).

To rebuild the production bundle:

~~~bash
cd commandcenter/frontend
npm ci --no-audit --no-fund
npm run build
npm run lint
~~~

### Views

| View | Operator use |
|---|---|
| Operations | Engagement state, event stream, activity, metrics, and MITRE overview |
| Targets | Recorded host inventory and per-target details |
| Boneyard | Searchable findings, categories, summaries, and integrity status |
| Attack Graph | Outcome-aware relationships between hosts, phases, and findings |
| Timeline | Chronological engagement and phase evidence |
| C2 Channels | Live injected state when available plus restart-safe recorded evidence |
| WarLog | Filtered operational events and browser-native JSON download |
| Reports | Generate and download JSON, Markdown, or HTML reports |
| Prevention | Coverage score and observed control effectiveness |
| Compliance | Advisory mapping of observed techniques to security frameworks |
| Drift | Differences recorded across continuity runs |
| Settings | Runtime health, signed entitlement, storage counts, setup guidance, and diagnostics |

### Interaction model

- Use the left navigation rail on desktop or the menu button on smaller screens.
- Press Ctrl+K to navigate, refresh status, export WarLog, or generate a report.
- Select rows, graph nodes, or techniques to open the detail inspector.
- Browser back/forward and deep links preserve the selected view.
- Filters and empty states distinguish absent evidence from loading failures.
- The **LIVE** badge means the browser WebSocket is connected; it does not mean
  an engagement is running.
- **IDLE** and **ENGAGED** describe the current validation state.
- **DEMO** and **DEMO ON** always identify synthetic evidence.
- A recorded channel is historical evidence; only an explicitly injected active
  adapter can supply live channel state.

### Browser boundary

The Command Center enforces a loopback host allowlist, checks origins for
mutating requests and WebSockets, strips credential-like fields from API
responses, and sends browser hardening headers including a Content Security
Policy and frame denial.

Loopback binding is not a substitute for workstation security. Use a controlled
operator account, lock the demo machine when unattended, and do not run the
Command Center as root.

See [commandcenter/README.md](commandcenter/README.md) for the API and frontend
architecture.

## Authorization and rules of engagement

Use the <code>client</code> profile for real client validation. It requires an
authorization file. Keep customer-specific scope documents outside the
repository if they contain names, addresses, credentials, or other sensitive
details.

A fictional structure is provided at
[config/examples/authorization.demo.json](config/examples/authorization.demo.json).
An authorization document defines:

- Engagement name and operator.
- Explicit authorization state.
- In-scope and out-of-scope targets.
- Allowed modes.
- Denied phases.
- Optional engagement notes.

Always inspect the resolved plan with <code>--dry-run</code>:

~~~bash
thevoid engage <approved-target> \
  --profile client \
  --authz /secure/path/engagement-scope.json \
  --mode quick \
  --dry-run
~~~

Only remove <code>--dry-run</code> after a human confirms:

1. The target resolves to the approved asset.
2. The current time is inside the approved window.
3. The selected mode or scenario is allowed.
4. Denied phases were removed from the plan.
5. Credentials and test data are approved for use.
6. Monitoring, escalation, cancellation, and restoration contacts are ready.

Mode and scenario selection never overrides denied-phase filtering or target
scope. The software guardrails supplement the signed rules of engagement; they
do not broaden it.

## CLI reference

~~~text
thevoid [--help] [--version] COMMAND [OPTIONS]
~~~

| Command | Purpose |
|---|---|
| <code>version</code> | Show application, Python, platform, phase, scenario, and Command Center metadata |
| <code>status</code> | Show Frosty, target, session, evidence, and integrity state |
| <code>demo</code> | Run the deterministic narrated demo with zero network activity |
| <code>recon</code> | Schedule only the reconnaissance phase |
| <code>engage</code> | Plan or run an authorized mode/scenario against one or more targets |
| <code>targets</code> | Add, remove, clear, or list targets for the active agent |
| <code>scenarios list</code> | List curated phase plans |
| <code>scenarios show NAME</code> | Inspect one scenario |
| <code>report</code> | Render current WarLog and Boneyard evidence |
| <code>continuity start</code> | Run an interval-based authorized validation schedule |
| <code>continuity drift</code> | Display recorded drift events |
| <code>license status</code> | Verify the configured offline entitlement without contacting a server |

Safe inspection commands:

~~~bash
thevoid --help
thevoid version
thevoid status
thevoid scenarios list
thevoid scenarios show baseline-network
thevoid demo --no-animate
~~~

Safe planning commands:

~~~bash
thevoid recon <approved-target> --profile client \
  --authz /secure/path/engagement-scope.json --dry-run

thevoid engage <approved-target> --profile client \
  --authz /secure/path/engagement-scope.json --mode quick --dry-run
~~~

Use <code>--json-output</code> where offered for automation. Run
<code>thevoid COMMAND --help</code> for the authoritative options of a
subcommand.

## Modes and scenarios

Modes choose a default ordered phase set. Scenarios replace that default with a
curated phase plan. Both are filtered by the active profile and authorization
document.

| Mode | Ordered phases | Operational note |
|---|---|---|
| <code>quick</code> | <code>recon</code> | Reconnaissance only; preferred starting point |
| <code>stealth</code> | <code>recon</code>, <code>exploit</code>, <code>network_bypass</code>, <code>mcp_scan</code> | Active validation; name describes the phase plan, not authorization |
| <code>full</code> | <code>recon</code>, <code>exploit</code>, <code>data_theft</code>, <code>llm_jailbreak</code>, <code>network_bypass</code>, <code>c2</code>, <code>mcp_scan</code>, <code>mcp_attack</code>, <code>mcp_chain</code> | Broad validation; review every phase |
| <code>aggressive</code> | Full-style coverage plus cloud, Kubernetes, CVE, advanced LLM, and MCP channel phases | High impact; requires explicit approval and close monitoring |
| <code>chaos</code> | All registered phases, including destructive and persistence-oriented phases | Highest risk; denied by the demo safeguards and inappropriate unless individually authorized |

The <code>--mode stealth</code> plan and the <code>--stealth</code> transport
option are separate controls. Review both before execution.

Built-in scenarios:

| Scenario | Purpose | Phases |
|---|---|---|
| <code>baseline-network</code> | Standard network validation chain | <code>recon</code>, <code>exploit</code>, <code>data_theft</code>, <code>c2</code> |
| <code>cloud-hygiene</code> | Cloud configuration, IAM, and container posture | <code>cloud_attack</code>, <code>k8s_attack</code> |
| <code>crypto-persistence</code> | High-risk asset and persistence controls | <code>crypto_theft</code>, <code>persistent_exfil</code>, <code>zero_click</code> |
| <code>llm-trust</code> | Adversarial LLM trust validation | <code>llm_jailbreak</code>, <code>advanced_jailbreak</code> |
| <code>mcp-critical</code> | MCP scan, attack, chaining, and channel coverage | <code>mcp_scan</code>, <code>mcp_attack</code>, <code>mcp_chain</code>, <code>mcp_c2</code> |

Inspect a scenario and dry-run it before use:

~~~bash
thevoid scenarios show mcp-critical
thevoid engage <approved-target> --scenario mcp-critical \
  --profile client --authz /secure/path/engagement-scope.json --dry-run
~~~

## Evidence, integrity, and reporting

### Local evidence model

- **WarLog** is an append-oriented SQLite event record with HMAC chain-of-custody
  metadata, spans, traces, rotation, and integrity verification.
- **Boneyard** is a SQLite evidence store for hosts, findings, attack paths, and
  outcomes, with integrity metadata and optional passphrase-based encryption.
- **Reporter** renders the current stores as JSON, Markdown, or HTML.
- **Coverage scoring** summarizes observed prevention strength; it is not a
  certification.

Integrity protects evidence against undetected modification; it does not make
the evidence secret. Boneyard encryption is optional, and default development
stores are not encrypted. Protect the workstation with OS access controls and
full-disk encryption appropriate to the engagement.

Generate a local report:

~~~bash
mkdir -p "$HOME/.local/share/blackfrost/the-void/exports"
thevoid report --format html \
  --output "$HOME/.local/share/blackfrost/the-void/exports/report.html" \
  --name "Authorized Validation" --operator "Operator" \
  --verify-integrity
~~~

Integrity verification is intentionally opt-in because it is slower on large
logs. The Command Center can generate the same three report formats and can
download a WarLog JSON export directly through the browser.

### Explicit external exports

The CLI supports <code>file_jsonlines</code>, <code>syslog</code>, and
<code>webhook</code> report sinks. These are never implicit. Selecting a network
sink can move evidence off the workstation and must be approved in the
engagement data-handling plan.

Webhook credentials come from environment variables, not tracked files:

~~~bash
export THE_VOID_SIEM_URL='https://approved.example/ingest'
export THE_VOID_SIEM_TOKEN='retrieve-from-secret-manager'
thevoid report --format json --export webhook
~~~

Do not place real values in <code>.env.example</code>, shell history, screenshots,
support tickets, or committed authorization files.

## Continuity and drift

Continuity repeats an authorized plan and records verdict changes between runs.
It is a long-running operator process, not an unattended authorization grant.
Unlike <code>engage</code>, <code>continuity start</code> accepts a settings
file instead of per-command <code>--profile</code> and <code>--authz</code>
options. Its secured settings file must enable the client authorization gate and
reference the approved scope document:

~~~json
{
  "CLIENT_MODE": true,
  "REQUIRE_AUTHORIZATION": true,
  "STRICT_DIFFICULTY": true,
  "AUTHORIZATION_FILE": "/secure/path/engagement-scope.json",
  "DENY_HIGH_RISK_PHASES": true
}
~~~

Validate the equivalent one-time plan with <code>engage --dry-run</code> before
starting the scheduler. Then pass that settings file explicitly:

~~~bash
thevoid continuity start <approved-target> \
  --mode quick --interval-hours 24 --max-runs 3 \
  --config /secure/path/client-continuity.json

thevoid continuity drift --list
thevoid continuity drift --json-output \
  --output "$HOME/.local/share/blackfrost/the-void/exports/drift.json"
~~~

Before starting a scheduler, confirm that the full schedule stays inside the
approved window and that the authorization file remains valid for every run.
Stop the process with Ctrl+C when required.

## Bundled components

### Frosty

Frosty is the agent identity used in configuration, status output, demo
profiles, and operator-facing documentation. Its operating policy and local
settings live in [Frosty/README.md](Frosty/README.md).

### Snowblind

Snowblind is bundled so the client test does not depend on a second repository
or download. It keeps its own documentation, license, acceptable-use terms, and
<code>snowblind</code> CLI (plus the shorter <code>snow</code> alias) under
<code>snowblind/</code>.

Read [snowblind/README.md](snowblind/README.md) before any privileged operation.
Begin with the read-only diagnostic and retain independent console access for
recovery before changing host network policy:

~~~bash
# Licensed package:
sudo snowblind doctor

# Private source checkout:
sudo python3 snowblind/snow.py doctor
~~~

### MCP scanner

The bundled [MCP scanner](mcp-tools/mcp-scanner/README.md) is wired into Frosty's
<code>mcp_scan</code> phase. Its availability is reported separately from the
rest of the phase system so an import failure does not silently become a
successful scan.

The current scanner engines are an integration scaffold, not a production
vulnerability authority: several analysis, dependency, drift, correlation, and
report paths still use deterministic placeholder behavior. Treat their output
as demonstration evidence until the acceptance items in the scanner guide are
implemented and independently validated.

### Optional demonstration site

The [local demonstration site](website/README.md) is separate from the Command
Center and is useful for a controlled localhost presentation:

~~~bash
cd website
./serve.sh
~~~

It binds to [http://127.0.0.1:8088](http://127.0.0.1:8088).

## Verification and CI

Run the Python suites from the repository root:

~~~bash
python -m pytest tests commandcenter/tests/backend -q
python -m compileall -q \
  agent c2 cli commandcenter config core exploit llm modules orchestrator recon scenarios
~~~

Run the CI-equivalent fatal-error lint:

~~~bash
ruff check \
  agent c2 cli commandcenter config core exploit llm modules orchestrator recon scenarios tests \
  --select E9,F63,F7,F82
~~~

Verify the frontend:

~~~bash
cd commandcenter/frontend
npm ci --no-audit --no-fund
npm run build
npm run lint
~~~

The handoff gate runs the complete Python suite. GitHub Actions also validates:

- Python 3.10 and 3.12 test matrices.
- Frontend reproducible install, production build, and lint.
- High and critical dependency vulnerabilities with Trivy.
- Full-history secret detection with Gitleaks.
- Fatal Python syntax and name-resolution rules with Ruff.

Live third-party security-tool integrations remain an operator-run acceptance
step on the intended Kali machine. See [CLIENT_TESTING.md](CLIENT_TESTING.md)
for the complete acceptance sequence.

## Client demonstration playbook

### Preflight

~~~bash
source .venv/bin/activate
thevoid version
thevoid status
thevoid demo --no-animate
git status --short
thevoid-command-center start --no-open
~~~

Confirm the health endpoint is green and that no customer-specific runtime data
is present.

### Suggested browser walkthrough

1. Open the Command Center and select **Explore Demo**.
2. Use **Operations** to explain engagement state, evidence counts, and live
   browser connectivity.
3. Open **Targets** and **Boneyard** to inspect the fictional evidence.
4. Follow relationships in **Attack Graph** and sequencing in **Timeline**.
5. Review recorded activity in **C2 Channels** and **WarLog**.
6. Explain observed control strength in **Prevention** and the advisory nature
   of **Compliance**.
7. Use Ctrl+K to demonstrate keyboard navigation and actions.
8. Generate a report in **Reports** and inspect the downloaded file.
9. Return the top-bar toggle to **DEMO OFF** and confirm the live workspace is
   restored.

For a clean presentation, use Demo Mode until the client has approved a real
scope document. Do not improvise an active target during the walkthrough.

## Runtime data and repository hygiene

Runtime state is local and excluded from Git. Source checkouts and installed
packages use the same XDG layout by default:

| Path | Contents |
|---|---|
| <code>~/.config/blackfrost/the-void/</code> | Per-operator configuration and optional source entitlement |
| <code>~/.local/state/blackfrost/the-void/boneyard/</code> | Live evidence SQLite database and journals |
| <code>~/.local/state/blackfrost/the-void/warlog/</code> | Live event database, journals, and rotated archives |
| <code>~/.local/state/blackfrost/the-void/logs/</code> | Compatibility and Command Center logs |
| <code>~/.local/state/blackfrost/the-void/quarantine/</code> | Private injection-defense payload quarantine |
| <code>~/.local/state/blackfrost/the-void/commandcenter/</code> | UI/session state and isolated demo stores |
| <code>~/.local/share/blackfrost/the-void/exports/</code> | Browser-generated report and WarLog files |
| <code>~/.local/share/blackfrost/the-void/loot/</code> | Optional explicitly generated phase output |
| <code>.shadow/sessions/</code>, <code>.shadow/checkpoints/</code> | Local sessions and checkpoints |
| <code>/var/lib/blackfrost/the-void/snowblind/</code> | Privileged Snowblind journal, backups, and recovery state |
| <code>Frosty/.shadow/</code> | Frosty local session state |
| <code>release/out/</code>, <code>release/wheelhouse/</code> | Ignored release outputs and offline dependencies |

Also ignored are environment files other than <code>.env.example</code>, private
keys and certificates, credential-shaped files, dependency trees, caches,
build output, local model weights, and private Frosty memory.

Before committing or handing off:

~~~bash
git status --short
git diff --check
git diff --cached --name-only
~~~

Stage only intentional source and documentation paths. Never force-add ignored
runtime data. Review every report or support bundle for customer identifiers,
credentials, tokens, target details, and screenshots before sharing it.

The ignore file is a last line of defense, not a secret-management system. If a
secret is ever committed, remove it from history and rotate it; deleting the
working-tree file is not enough.

## Troubleshooting

| Symptom | Check |
|---|---|
| <code>thevoid: command not found</code> | Activate <code>.venv</code> and rerun <code>python -m pip install -e '.[dev]'</code> |
| Import error at startup | Confirm the terminal is at the repository root and the intended virtual environment is active |
| Port 7070 already in use | Inspect with <code>ss -ltnp \| grep ':7070'</code>, or select another loopback port with <code>VOID_CC_PORT</code> |
| API-only JSON appears at <code>/</code> | Rebuild <code>commandcenter/frontend/dist</code> with <code>npm ci</code> and <code>npm run build</code> |
| Browser shows no evidence | This is expected for a clean live store; select **Explore Demo** or run an authorized workflow |
| Synthetic records are visible | Confirm the top bar says **DEMO ON**, then toggle it off to restore live stores |
| **LIVE** but engagement is **IDLE** | The WebSocket is connected; no validation is currently running |
| A channel says recorded rather than active | The UI found persisted evidence but has no live adapter injected in this process |
| Health lists degraded components | Check the server log, virtual environment, optional adapter dependencies, and local store permissions |
| License gate blocks startup | Run <code>thevoid license status</code>; install the entitlement issued for this version rather than disabling the commercial wrapper |
| Desktop launcher exits during startup | Inspect <code>~/.local/state/blackfrost/the-void/logs/command-center.log</code> and run <code>thevoid-command-center foreground</code> |
| Mutation or WebSocket receives 403 | Open the UI through its documented loopback URL; cross-origin browser requests are rejected |
| Browser shows stale assets after rebuild | Stop the server, restart it, and perform a hard refresh |
| Vite reports an unsupported Node engine | Upgrade to Node 20.19+ or 22.12+ |
| Scope or phase is rejected | Treat the rejection as a guardrail; correct the target or authorization document instead of bypassing it |
| Integrity verification is slow | This is expected for large evidence stores; run it during preflight or closeout rather than repeatedly |
| Report is empty | Reports use the currently active live or demo stores; confirm the selected mode and evidence counts |

If privileged Snowblind diagnostics or restoration are involved, use its own
troubleshooting and recovery guide rather than treating it as a Command Center
problem.

## Documentation and support handoff

- [Client testing guide](CLIENT_TESTING.md)
- [Operator guide](docs/OPERATOR_GUIDE.md)
- [Private distribution guide](docs/DISTRIBUTION.md)
- [Store/S3 implementation handoff](docs/STORE_S3_HANDOFF.md)
- [Command Center guide](commandcenter/README.md)
- [Frosty guide](Frosty/README.md)
- [Snowblind guide](snowblind/README.md)
- [MCP scanner guide](mcp-tools/mcp-scanner/README.md)
- [License](LICENSE)

For a useful support report, include:

- THE VOID, Python, Node.js (if relevant), browser, and OS versions.
- The sanitized command or browser route.
- Expected and actual behavior.
- Sanitized logs and the <code>/api/health</code> response.
- Whether Demo Mode or live mode was active.
- Whether the failure reproduces after a clean restart.

Remove credentials, customer identifiers, real targets, and sensitive evidence
before sending any support material.

## License

THE VOID is proprietary Blackfrost AI software. Bundled components retain the
license files and usage terms shipped in their respective directories.

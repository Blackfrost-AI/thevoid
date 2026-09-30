# THE VOID

**A local-first security validation engine with tamper-evident evidence, agentic planning, and a browser-first Command Center — in one Python package that never phones home.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-green)](https://python.org)

THE VOID runs authorized validation against systems you own or test under contract — and leaves a cryptographic paper trail for every step. Evidence is HMAC-chained, Merkle-anchored, and verifiable; the agent maps what it executed to MITRE ATLAS; and the operator stays in control with rules of engagement, approval gates, and kill switches.

**Local-first means:** no telemetry, no account, no cloud dependency. Your evidence stays on your workstation unless you export it.

## Why this exists

Most pentest tooling gives you shell access and leaves you to assemble the narrative. THE VOID treats the engagement itself as an evidence-producing system:

- **Tamper-evident evidence** — every event is HMAC-chained and can be Merkle-anchored, so a record of what ran (and what didn't) survives tampering.
- **Rules of engagement, enforced** — scope-gated execution, dual-LLM ROE review (Sentinel), and operator approval gates on planning. The agent cannot freelance.
- **Coverage you can measure** — executed phases map to MITRE ATLAS technique IDs, and prevention strength is scored per engagement.
- **Agentic, but leashed** — the planner proposes next steps from the attack graph; the operator approves. Hard branch and time-box limits.
- **A Command Center you can demo** — browser console with a deterministic demo mode that touches nothing.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m commandcenter.launcher start
```

The launcher opens an authorized browser tab at localhost. On an empty workspace, select **Explore Demo** — Demo Mode loads a deterministic fictional assessment into isolated stores and does not contact real targets.

```bash
curl -fsS http://127.0.0.1:7070/api/health   # expect "ok": true
thevoid demo                                  # narrated demo, zero network
thevoid version                               # metadata
```

> **Authorized use only.** Run active phases only against systems you own or have written permission to test. Confirm target, time window, permitted techniques, credentials, and restoration plan in the rules of engagement before execution.

## What's inside

| Component | Role |
|---|---|
| `agent/` | ShadowAgent engagement loop, phase registry, planner (evidence-grounded), Sentinel (dual-LLM ROE review) |
| `c2/` | C2 daemon, malleable profiles, ECDH handshake, hardened listener, S3/webhook transports |
| `cli/` | `thevoid` command surface |
| `commandcenter/` | Browser-first console (FastAPI backend + committed frontend bundle) |
| `core/` | WarLog (HMAC-chained, Merkle-anchorable evidence store), Boneyard, crypto, authorization |
| `exploit/` | Exploitation, C2 infrastructure, destruction executor (reversible impact mode) |
| `implant/` | Staged loader with kill switch and expiry |
| `llm/` | Local-first provider layer; every call is WarLog-audited |
| `modules/` | Jailbreak, data theft, coverage/ATLAS mapping, evidence reports |
| `snowblind/` | Bundled network discovery toolkit |
| `mcp-tools/` | MCP vulnerability scanner |
| `Frosty/` | Operator-facing agent identity |

## Evidence integrity

The WarLog is an SQLite-backed evidence store where every row carries an HMAC over its content, and event ranges can be Merkle-anchored:

```python
from core.warlog import WarLog

wl = WarLog(...)                          # integrity key required
wl.log("recon complete", module="recon", target="10.0.0.5")

anchor = wl.anchor_events(1, wl.max_seq())  # freeze the range
assert wl.verify_anchor(anchor["anchor_id"])
assert wl.verify_row(1, anchor_id=anchor["anchor_id"])
```

Tampering any row breaks the anchor; anchoring any row re-signs it. Publish anchor roots off-host (`mark_anchor_published`) to detect whole-history truncation by an attacker who holds the integrity key.

## MITRE ATLAS coverage

Coverage is computed against the canonical ATLAS-2026.09 dataset (120 base techniques) with mapping validated fail-closed at import time:

```python
from modules.atlas_coverage import coverage_for, map_engagement

s = coverage_for(["recon", "c2", "mcp_attack"])
# s["coverage_pct"], s["covered"], s["per_phase"]
map_engagement(engagement_result, warlog)   # records evidence + content hash
```

A full engagement run covers 46 of 120 techniques (38.3%) of the current matrix — gaps are enumerable, not vibes.

## CLI reference

| Command | Purpose |
|---|---|
| `thevoid demo` | Deterministic narrated demo, zero network activity |
| `thevoid recon <target>` | Reconnaissance phase (scope-gated) |
| `thevoid engage <target> --mode <m>` | Run an authorized mode/scenario |
| `thevoid scenarios list` | Curated phase plans |
| `thevoid report` | Render WarLog + Boneyard evidence |
| `thevoid continuity start` | Interval-based authorized validation |
| `thevoid license status` | Verify offline entitlement |

All execution commands require `--authz` (a rules-of-engagement file) and support `--dry-run` to show the plan without executing.

## Safety properties

- **Fail closed.** Missing authorization, expired entitlement, or out-of-scope target aborts the phase before it touches anything.
- **Approval gates.** The planner's proposed next steps require explicit operator approval; branch fan-out and wall-clock limits are enforced, not advisory.
- **Kill switches.** Staged implants carry kill switches and expiry; impact mode is encrypt-prove-restore reversible.
- **Dual-LLM ROE review.** Sentinel reviews agent actions against the engagement's ROE using two independent model lanes; provenance of every reviewer opinion is tagged and logged.

## Development

```bash
pip install -e '.[dev]'
pytest                                  # full suite
pytest tests/test_warlog_merkle.py      # integrity subsystem
```

- [Operator guide](docs/OPERATOR_GUIDE.md)
- [Command Center guide](commandcenter/README.md)
- [Snowblind guide](snowblind/README.md)
- [MCP scanner guide](mcp-tools/mcp-scanner/README.md)
- [Security policy](SECURITY.md)

## Contributing

We welcome issues, PRs, and forks. To keep the project's licensing history clean:

1. Sign off every commit (`git commit -s`) — this project uses DCO sign-off.
2. Open an issue first for anything non-trivial so we can agree on scope.
3. No vendor or customer data in fixtures — sanitized, synthetic, fictionalized only.

## License

Apache License 2.0. See [LICENSE](LICENSE). Bundled third-party components retain their own license files; check the component directory before redistributing them.

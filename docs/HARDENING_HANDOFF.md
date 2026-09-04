# Defensive hardening handoff

Status: local changes under verification; **not approved for production release**.
Base: client repository commit `c89eae5`. No customer state is migrated or erased.

## Implemented scope

Authorization/configuration restrictions, evidence key and file protections,
local API access control, recovery classification, read-only report/status
correctness, WebSocket runtime dependency, and defensive CI inventory checks.
No live operational workflow, host networking change, commercial deployment,
release signing, store upload, or public publication is part of verification.

## Operator-visible changes

Use the desktop launcher or `thevoid-command-center start` for browser access.
If the process is already running, `thevoid-command-center open` authorizes a
new tab. A bare localhost URL intentionally shows a locked screen. Do not share
the fragment-bearing launcher URL or copy token files into a ticket.

The token is stored in `VOID_RUNTIME_DIR` (or the resolved XDG runtime root) as
`command-center-<port>.token`, with mode 0600. It is stable across ordinary
process restarts. To rotate it, stop the server, remove only that resolved token
file and its sibling `command-center-<port>-open.html` bootstrap, then restart
and reopen the browser. The bootstrap is also private (0600) and prevents
secret-bearing URLs from appearing in browser-launch command arguments.
No signing key is involved. Older
tabs require reopening. Never recursively remove a runtime or home directory.

Development origins require `VOID_CC_DEV_ORIGINS=1`; this is not a production
setting. The browser is still an evidence observer and synthetic demo, not an
active job launcher. Local Bearer credentials do not protect a compromised
operator account or browser.

`thevoid status` now describes recorded evidence, with `runtime_state` set to
`not_attached`. It must not imply that a separate active process is idle.
`targets` lists recorded hosts; the old nonpersistent add/remove/clear behavior
is rejected. Report exports return nonzero on any failed sink, keep JSON stdout
parseable, and put diagnostics on stderr. Missing config files are usage errors.

## Evidence migration and recovery — release blocker

Do not open the operator's original legacy stores with a migration script that
has not been reviewed. New managed-key creation is refused for a nonempty
database that has no corresponding key. Existing broadly accessible paths are
rejected, not silently chmodded. Read-only observers disable WarLog rotation
on initialization.

Before migration, stop every writer and make a consistent backup including
SQLite WAL state as applicable, JSONL logs, original key material, and path
configuration. Keep the old installation and backup intact. Managed key lookup
is tied to the absolute database path: restore keys and stores to their original
paths unless a separately reviewed relocation/migration handles the mapping.

A migration must run on copies, verify pre/post counts and integrity under the
appropriate old/new keys, preserve timestamps and report totals, and prove a
restore drill before any replacement is approved. There is no automatic legacy
migration in this update. Missing keys are not recoverable by generating new
ones. Field encryption does not cover all relational metadata or event logs;
full-disk encryption remains required for confidential workstations/backups.

## Outstanding release gates

| Gate | Required evidence or owner input |
|---|---|
| Legacy evidence migration | Reviewed copy-based migration and restore drill |
| Installer transaction | Validate entitlement before package changes; atomically replace license; preserve previous packages/license on failure |
| Clean Kali artifact lifecycle | Disposable-VM install, browser access/reconnect, upgrade, failed upgrade, uninstall, recovery; exact runtime and artifact hashes recorded |
| Release approvals | Named GitHub user/team and agreed approval policy |
| Protected infrastructure | Protected main, required checks, signing environment, isolated runner; no signing keys committed |
| Support metadata | Confirmed monitored mailbox; `VOID_SUPPORT_EMAIL` is mandatory for package metadata |
| Reproducibility/provenance | Two independent comparable builds and recorded builder/dependency provenance; current staging-venv portability remains unproven |
| Operational scope | No active or destructive capability is validated or deployed by this hardening pass |

Do not interpret source unit tests, dependency scans, or a successful frontend
build as closing the artifact lifecycle or operational acceptance gates.

## Verification baseline

Primary verification uses an isolated Python 3.13 environment installed from
the hash-locked runtime, with test-only dependencies added separately. The new
defensive suites are `tests/test_hardening.py` and `tests/test_local_session.py`.
Existing launcher, licensing, report, runtime-path, and mocked browser API
suites provide regression coverage. No tests should access client targets.

CI inventories both the Python runtime lock and frontend lock and fails when
either inventory is empty/missing. New small security modules receive Ruff
error/security checks; this is not a claim that the whole legacy codebase has
completed strict lint/type or exhaustive coverage adoption.

## Verification record — 2026-09-04

- Kali / CPython 3.13, isolated runtime installed with every dependency hash
  checked; all 37 runtime packages installed and `pip check` passed.
- 256 selected defensive, report, synthetic-demo, and mocked API regression
  tests passed together in 63.34 seconds. One upstream TestClient deprecation
  warning was emitted; no failure resulted. A final 105-test focused run also
  passed after the private-browser-bootstrap, server startup, and log-rotation
  permission changes. These runs overlap; the counts must not be added.
- Frontend production build and lint passed; generated bundles were rebuilt.
- Ruff fatal/error checks over the reviewed Python areas and stronger
  error/security checks on new small security modules passed.
- Trivy inventoried 37 Python and 183 frontend packages, with zero HIGH/CRITICAL
  findings in those inventories. This is not an actual-package vulnerability scan.
- Gitleaks working-tree scan found no leaks. `git diff --check` passed.
- No whole-repository operational test pass, browser usability session, package
  install/upgrade acceptance, release workflow run, commit, push, or publication
  is claimed by this record. GitHub's existing green run is for the base commit.

## Site/store handoff

The approved product page is `https://blackfrostai.com/void`. The release
candidate must remain private and unavailable for download until the gates
above are closed. Do not provision production signing secrets, run a release,
or upload to object storage based on this document alone. Existing download
architecture is described in `STORE_S3_HANDOFF.md`; release approval is separate.

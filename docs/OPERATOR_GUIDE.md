# Operator Guide

## Safety model

THE VOID is an operator-controlled security-testing platform. The authorization
gate determines whether a target and mode are allowed, and phase filtering
enforces denied techniques. These controls supplement—not replace—the written
rules of engagement.

Use the client profile for real assessments. Use Demo Mode or `--dry-run` while
learning the interface.

## Local data model

- WarLog records ordered operational events with integrity metadata.
- Boneyard stores findings, hosts, attack paths, and outcomes locally.
- Reporter produces Markdown, HTML, and JSON output.
- Coverage scoring summarizes observed prevention strength.
- Continuity compares authorized runs over time and records drift.

Runtime records are excluded from version control. Never copy one customer's
local state into another customer's repository or test machine.

## Modes and scenarios

Modes select a default phase set. Scenarios provide named, curated phase plans.
Both remain subject to authorization and denied-phase filtering.

Inspect before running:

```bash
thevoid scenarios list
thevoid scenarios show <name>
thevoid engage <target> --profile client --authz /path/to/scope.json --dry-run
```

## Command Center

The Command Center is a localhost-only situational-awareness interface. It
reads the same local stores used by the CLI and does not provide a remote,
multi-tenant control plane.

Demo Mode swaps the interface onto isolated synthetic stores. Its records are
clearly marked and are discarded when Demo Mode is disabled.

Start it as the desktop operator, never with `sudo`:

```bash
thevoid-command-center start
thevoid-command-center status
thevoid-command-center stop
```

Commercial packages verify the offline signed entitlement before serving the
browser. Inspect it with `thevoid license status`; do not bypass a failed gate.
The Settings view shows the same sanitized state, customer ID, expiry, and
licensed components.

## Snowblind

Snowblind is bundled under `snowblind/` and maintains its own operational and
restoration workflow. Read its documentation and acceptable-use policy before
running privileged commands. Always run the diagnostic first and retain console
access capable of recovery if host network policy is changed.

Snowblind is part of the customer bundle but remains a separate package and
privilege boundary. Installation performs no active network changes. Its
privileged journal defaults to `/var/lib/blackfrost/the-void/snowblind` and
must remain intact until any engaged state has been restored.

## Closeout

1. Stop active schedulers and processes.
2. Disable Command Center Demo Mode if enabled.
3. Restore host networking if Snowblind was engaged.
4. Verify WarLog and Boneyard integrity.
5. Generate the approved report formats.
6. Review exports for credentials and customer identifiers.
7. Store or destroy local evidence according to the engagement agreement.

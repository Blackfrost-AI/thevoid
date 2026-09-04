# Client Testing Guide

> The working tree contains an unreleased defensive update. Do not use this
> guide as production sign-off: [HARDENING_HANDOFF.md](docs/HARDENING_HANDOFF.md)
> lists outstanding migration, installer, and release-infrastructure gates.
> Only synthetic/offline acceptance is covered by this update's verification.

This repository is a clean testing baseline. It contains no prior customer
records or historical assessment results.

## 1. Prepare a private source checkout

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Confirm the local metadata and command routing:

```bash
thevoid version
void version
thevoid scenarios list
void demo --no-animate
thevoid license status
```

## 2. Verify the baseline

```bash
python -m pytest tests commandcenter/tests/backend -q
python -m compileall -q agent c2 cli commandcenter config core exploit llm modules orchestrator recon scenarios
```

For the browser console:

```bash
cd commandcenter/frontend
npm ci
npm run build
npm run lint
cd ../..
thevoid-command-center start --no-open
```

Open `http://127.0.0.1:7070`, enable Demo Mode, and confirm that Operations,
Targets, Attack Graph, Timeline, Prevention, Compliance, Drift, and WarLog show
the fictional stage scenario. Disable Demo Mode after the review.

## 3. Configure an authorized test

Copy `config/examples/authorization.demo.json`, replace the example fields with
the approved scope, and keep the resulting file outside Git if it contains
customer information.

Start with a dry run:

```bash
thevoid engage <approved-target> --profile client --authz /path/to/scope.json --dry-run
```

Only remove `--dry-run` after confirming the target, mode, denied phases, test
window, and written authorization.

## 4. Test the commercial customer bundle

Run this section on a disposable Kali amd64 VM with no prior THE VOID install.
Obtain the archive digest and release-key fingerprint through the authenticated
customer portal, independently of the downloaded archive. Confirm OpenSSL is
installed and normal Kali package sources are available for missing Snowblind
system dependencies.

```bash
sha256sum the-void-*.tar.zst
tar --extract --zstd --file the-void-*.tar.zst
cd the-void-*-linux-amd64-*
openssl pkeyutl -verify \
  -pubin \
  -inkey /secure/trusted-release-signing.pub \
  -rawin \
  -in SHA256SUMS \
  -sigfile SHA256SUMS.sig
sha256sum --check SHA256SUMS
sudo ./install.sh /secure/trusted-release-signing.pub
```

Confirm:

```bash
thevoid license status
thevoid version
thevoid-command-center start --no-open
thevoid-command-center status
curl -fsS http://127.0.0.1:7070/api/health
thevoid-command-center stop
sudo snowblind doctor
```

The health response must show a valid entitlement for the intended product
version. Open the application-menu entry and repeat the fictional Demo Mode
walkthrough. Package installation must not start services, launch the browser,
or change firewall/routing state. Do not run `snowblind engage` as part of a
basic packaging test.

For upgrade testing, preserve the entitlement and XDG state, install the newer
packages, and confirm the same local evidence remains readable. Restore any
active Snowblind session before upgrade or removal.

## 5. Expected local output

Runtime databases, logs, exports, and reports live below the operator's XDG
directories and are ignored by Git. Privileged Snowblind recovery state lives
under `/var/lib/blackfrost/the-void/snowblind`. Before sharing a support bundle,
review it for customer identifiers and secrets. Never include `license.json`
unless the protected support procedure explicitly requires it.

## 6. Release acceptance

The release operator must additionally complete the signed-package gate in
[`docs/DISTRIBUTION.md`](docs/DISTRIBUTION.md). The site/store implementation
must pass the fulfillment and authorization checklist in
[`docs/STORE_S3_HANDOFF.md`](docs/STORE_S3_HANDOFF.md).

## Support handoff

When reporting a problem, include:

- THE VOID version and Python version
- the command used, with secrets and customer identifiers removed
- expected and actual behavior
- relevant sanitized logs
- whether Demo Mode or live mode was active

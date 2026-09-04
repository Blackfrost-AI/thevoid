# Client Testing Guide

This repository is a clean testing baseline. It contains no prior customer
records or historical assessment results.

## 1. Prepare

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
python -m commandcenter.backend.main
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

## 4. Expected local output

Runtime databases, logs, exports, and reports are ignored by Git. Before
sharing a support bundle, review it for customer identifiers and secrets.

## Support handoff

When reporting a problem, include:

- THE VOID version and Python version
- the command used, with secrets and customer identifiers removed
- expected and actual behavior
- relevant sanitized logs
- whether Demo Mode or live mode was active

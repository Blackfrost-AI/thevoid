# Changelog

## Unreleased — defensive hardening

- Fail-closed authorization with explicit consent and validity windows.
- Atomic configuration validation; missing or unsafe configuration is an error.
- Managed evidence keys, restrictive file access, and no custom crypto fallback.
- Private rotation archives with collision-resistant names and private replacement databases.
- Operator-token boundary for localhost REST and WebSockets; development
  browser origins disabled by default.
- Nonzero degraded health and failed-export exits; clean JSON stdout.
- Shared persisted report projection and explicit recorded-only CLI status.
- Target edit flags now fail explicitly instead of pretending to persist.
- Recovery/diagnostic Snowblind commands are exempt from the license wrapper.
- Explicit WebSocket dependency in the Python 3.13 runtime lock.
- Defensive regression coverage and dependency-inventory completeness gates.

Compatibility changes: legacy evidence requires a separately reviewed
migration, old scope documents need validity windows, and direct browser links
without a launcher-issued token show the local-access screen. The CLI status
JSON schema is now `thevoid.status.v1`. No versioned commercial artifact has
been issued for these changes.

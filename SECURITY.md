# Security policy

This is a private, pre-release application. Hardening changes in the working
tree are not a production certification or approval to distribute an artifact.

## Reporting a concern

Use the private contact established in your Blackfrost client handoff. A
monitored public security mailbox and response-time commitment are pending
owner confirmation. Do not submit credentials, client records, database files,
access tokens, signing keys, or sensitive scope documents to a public issue.
Provide the version, affected component, expected behavior, and a redacted
description. Agree on a secure channel before transferring any evidence.

## Local trust model

- Command Center is loopback-only and intended for one controlled operator
  account. It is not a remote or multi-tenant service.
- HTTP APIs require an explicit operator Bearer token. WebSockets require the
  same token in a subprotocol header; the token is never echoed as the selected
  protocol. The launcher uses a private 0600 bootstrap HTML file, so browser
  command arguments contain only that file's path, not a token. Its redirect
  transfers the token in a URL fragment, which the frontend removes and keeps
  only in that tab's session storage.
- Cookies are not used for this boundary because localhost cookies are shared
  across ports. Tokens are private local files, not embedded in distributed
  JavaScript or returned by unauthenticated endpoints.
- A compromised operator account, root, an untrusted browser extension, or
  arbitrary same-origin JavaScript remains outside this protection boundary.
- The minimal health endpoint is public for local readiness checks. It does not
  disclose customer license identity. Detailed application data requires access.

## Evidence and keys

New stores use random per-store keys under the operator's configuration root,
in `evidence-keys/`. Keys and database/log files require owner-only permissions;
store directories require 0700. Insecure existing paths and final symlinks are
rejected rather than silently changing permissions or following them.

Boneyard encrypts sensitive finding payloads with supported AES-GCM. Sensitive
payloads are excluded from full-text indexing. This is **not whole-database
encryption**: relational metadata, titles, tags, other finding categories, and
WarLog/JSONL messages can remain plaintext. Do not put secrets in those fields.
Use full-disk encryption, a private operator account, and controlled exports.

Integrity keys are secrets, not machine/path-derived development values.
Local HMAC chains are tamper-evident under the key-protection assumptions, not
immutable storage and not protection against an attacker holding the keys.

There is no homegrown cryptographic fallback. Missing supported cryptography,
missing managed keys for existing stores, and decryption failures must not be
treated as successful reads or fresh empty evidence.

## Authorization boundary

The scope gate rejects missing documents, implicit consent, malformed fields,
empty scope/modes, out-of-scope overrides, and expired/not-yet-valid windows.
The shipped scope example is deliberately inactive. This is a safety control,
not proof of written permission, an OS sandbox, or authorization for internal
APIs used independently of the CLI. No active workflow was exercised as part
of this defensive hardening pass.

## Release protection

Keep signing keys and client licenses outside Git. Dependency and secret scans
must cover both lockfiles and the actual eventual artifact. A signature alone
does not establish build provenance, reproducibility, or runtime correctness.
Open a confidential report through the channel described above for outstanding hardening questions.

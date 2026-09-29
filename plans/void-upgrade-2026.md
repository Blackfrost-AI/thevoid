# VOID upgrade implementation plan (2026-09-29)

Baseline (tests/ only): 1155 tests, 10 failures, 0 errors.
Root causes: (a) AuthorizationGate fails closed unconditionally — 9 failures expect
dev/on-off behavior; (b) click 8.2+ removed CliRunner(mix_stderr=...) — dev install
gets 8.5 while runtime lock pins 8.1.8.

## Work items
0. Fix baseline: VOID_AUTH_MODE dev|strict switch (default strict, fails closed;
   dev = legacy on/off via REQUIRE_AUTHORIZATION), click compat shim in test.
1. P0-1 llm/providers.py + llm/frosty_brain.py — local-first provider layer,
   zero-egress default, WarLog-audited calls. [done 2026-09-29: providers.py
   + frosty_brain.py + tests/test_llm_providers.py (20 tests). Fixed
   ProviderRegistry.pick() to truly prefer local providers over registration
   order. frosty_brain audits one WarLog record per call (ok and all failure
   paths) with call_id, model, provider, latency, usage, sampling params,
   prompt SHA-256 only — never prompt text — plus egress decision. Evidence
   write failure never masks the call.]
2. P0-2 c2/profiles.py malleable profiles; encrypted handshake on daemon
   (ECDH via existing Crypto); fix c2_infrastructure listener (argv exec, auth,
   bind 127.0.0.1); cloud transports (S3 poll, webhook). [done 2026-09-29:
   c2/handshake.py (ECDH-P256 + HMAC transcript auth, replay/freshness cache,
   deterministic session re-key), c2/profiles.py (reversible transforms:
   prepend/append/base64/xor-mask, HTTP shape, jitter; 2 built-ins; JSON
   load/save/validate), c2/transports.py (WebhookTransport + S3PollTransport
   with injectable requests/boto3-like clients; send/send_task/receive/
   receive_result; WarLog-evidenced every op), hardened listener (loopback
   bind, bearer-token /exec with constant-time compare, argv-only shell=False,
   private 0700/0600 state dir, render_listener_source() testable seam),
   ECDH handshake wired into C2Daemon (fail-closed require_handshake=True,
   session-sealed command channel) + Beacon.perform_handshake. Fixed latent
   bugs: Crypto.encrypt/decrypt + Executor.run_command compat (used across
   c2/ but missing), Session.rotate now deterministic (Crypto.advance_key),
   HandshakeClient.hello was missing its type field, exploit/__init__.py
   C2Infrastructure export restored (stale syntax-error note). 68 new tests.]
3. P0-3 agent/sentinel.py dual-LLM ROE reviewer + provenance tagging.
4. P1-1 agent/planner.py agentic planner over Boneyard + phase registry,
   operator approval gate, max-branch/time-box limits.
5. P1-2 implant/ staged loader + killswitch + expiry; reversible impact mode
   (encrypt-prove-restore) in destruction_executor.
6. P2 WarLog Merkle root + external anchor stub; ATLAS mapping table in coverage.
7. Full test run, reviewer pass, commit.

## Rules
- Default auth stays strict/fail-closed. Dev switch is explicit opt-in and loudly
  logged/warlogged.
- No live network in tests. All transports testable offline via fakes.
- Evidence: every new capability writes WarLog/Boneyard events.
# VOID upgrade implementation plan (2026-09-29)

Baseline (tests/ only): 1155 tests, 10 failures, 0 errors.
Root causes: (a) AuthorizationGate fails closed unconditionally — 9 failures expect
dev/on-off behavior; (b) click 8.2+ removed CliRunner(mix_stderr=...) — dev install
gets 8.5 while runtime lock pins 8.1.8.

## Work items
0. Fix baseline: VOID_AUTH_MODE dev|strict switch (default strict, fails closed;
   dev = legacy on/off via REQUIRE_AUTHORIZATION), click compat shim in test.
1. P0-1 llm/providers.py + llm/frosty_brain.py — local-first provider layer,
   zero-egress default, WarLog-audited calls.
2. P0-2 c2/profiles.py malleable profiles; encrypted handshake on daemon
   (ECDH via existing Crypto); fix c2_infrastructure listener (argv exec, auth,
   bind 127.0.0.1); cloud transports (S3 poll, webhook).
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
"""THE VOID — Sentinel dual-LLM ROE reviewer tests (fully offline).

Covers:
  * Deterministic ROE gate: out-of-scope / missing / expired docs DENY
    before any LLM call happens (fail closed).
  * Dual-LLM reconciliation: dual allow -> ALLOW; any deny -> DENY;
    abstain/unparsable/crashed reviewer -> DENY; missing secondary under
    require_dual -> DENY.
  * Provenance tagging: every review returns a Provenance with both
    reviewers' model/provider/prompt-hash/call-id, and writes exactly one
    WarLog record. Prompt text is never recorded.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from agent.sentinel import (
    MODULE,
    Provenance,
    Sentinel,
    VERDICT_ABSTAIN,
    VERDICT_ALLOW,
    VERDICT_DENY,
    normalize_risk,
)
from core.authorization import AuthorizationGate
from core.warlog import LogLevel, WarLog


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def roe_doc(**overrides):
    """A valid ROE document with a fresh validity window."""
    now = datetime.now(timezone.utc)
    doc = {
        "engagement_name": "Authorized Local Lab",
        "operator": "shadow-operator",
        "authorized": True,
        "allow_out_of_scope": False,
        "in_scope": ["192.0.2.0/24", "127.0.0.1"],
        "out_of_scope": ["198.51.100.0/24"],
        "allowed_modes": ["quick", "full", "stealth"],
        "denied_phases": ["destruction"],
        "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "notes": "Lab only.",
    }
    doc.update(overrides)
    return doc


def make_gate(doc=None):
    return AuthorizationGate(data=doc if doc is not None else roe_doc())


class FakeBrain:
    """Scripted FrostyBrain stand-in (no network, no provider layer)."""

    def __init__(self, replies=None, error=None, model="fake-ro-7b", provider="fake_local"):
        self.replies = list(replies or [])
        self.error = error
        self.model = model
        self.provider = provider
        self.calls = []

    def chat(self, messages, temperature=0.2, max_tokens=1024, purpose="", target=None):
        self.calls.append({"messages": messages, "purpose": purpose, "target": target})
        if self.error is not None:
            raise self.error
        text = self.replies.pop(0) if self.replies else '{"verdict": "abstain", "reason": "no script"}'
        return FakeResponse(text, model=self.model, provider=self.provider,
                            call_id=f"call-{uuid.uuid4().hex[:8]}")


class FakeResponse:
    def __init__(self, text, model="fake-ro-7b", provider="fake_local", call_id="call-1"):
        self.text = text
        self.model = model
        self.provider = provider
        self.call_id = call_id
        self.prompt_sha256 = "a" * 64
        self.egress_decision = "local"
        self.latency_ms = 5
        self.usage = {}


def allow_reply(reason="in scope"):
    return json.dumps({"verdict": "allow", "reason": reason})


def deny_reply(reason="risky"):
    return json.dumps({"verdict": "deny", "reason": reason})


def abstain_reply(reason="unclear"):
    return json.dumps({"verdict": "abstain", "reason": reason})


ACTION = {
    "target": "192.0.2.10",
    "phase": "recon",
    "mode": "full",
    "risk": "low",
    "description": "OSINT + port enumeration",
    "source": "planner",
    "source_confidence": 0.8,
}


# ─── Deterministic ROE gate ──────────────────────────────────────────────────

class TestRoeGate:
    def test_out_of_scope_denied_without_llm_calls(self, tmp_path):
        warlog = make_warlog(tmp_path)
        primary = FakeBrain([allow_reply(), allow_reply()])
        secondary = FakeBrain([allow_reply(), allow_reply()])
        sentinel = Sentinel(primary, secondary, gate=make_gate(), warlog=warlog)

        result = sentinel.review({**ACTION, "target": "203.0.113.5"})

        assert result.verdict == VERDICT_DENY
        assert result.roe_allowed is False
        assert "ROE gate denied" in result.reason
        assert primary.calls == [] and secondary.calls == []  # gate short-circuits

        events = warlog.get_entries(module=MODULE)
        assert len(events) == 1
        assert events[0]["level"] == LogLevel.ERROR.value
        assert events[0]["data"]["verdict"] == VERDICT_DENY

    def test_missing_document_denies(self, tmp_path):
        sentinel = Sentinel(FakeBrain(), FakeBrain(), gate=None, warlog=make_warlog(tmp_path))
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert "no ROE gate configured" in result.reason

    def test_expired_document_denies(self, tmp_path):
        now = datetime.now(timezone.utc)
        doc = roe_doc(
            not_before=(now - timedelta(days=2)).isoformat(),
            expires_at=(now - timedelta(days=1)).isoformat(),
        )
        sentinel = Sentinel(FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
                            gate=make_gate(doc), warlog=make_warlog(tmp_path))
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert result.roe_allowed is False

    def test_denied_phase_path_still_goes_to_llm_but_gate_allows_target(self, tmp_path):
        # denied_phases is enforced by the orchestrator; the gate's job here is
        # target/mode scope. The LLM reviewers may still deny a destructive phase.
        sentinel = Sentinel(
            FakeBrain([deny_reply("destruction is denied by ROE")]),
            FakeBrain([deny_reply("destruction is denied by ROE")]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review({**ACTION, "phase": "destruction", "risk": "high"})
        assert result.verdict == VERDICT_DENY
        assert result.roe_allowed is True
        assert result.risk == "high"

    def test_disallowed_mode_denied_by_gate(self, tmp_path):
        sentinel = Sentinel(FakeBrain(), FakeBrain(), gate=make_gate(),
                            warlog=make_warlog(tmp_path))
        result = sentinel.review({**ACTION, "mode": "yolo"})
        assert result.verdict == VERDICT_DENY
        assert "mode" in result.reason


# ─── Risk normalization ─────────────────────────────────────────────────────

class TestRiskNormalization:
    def test_known_risks_pass_through(self):
        assert normalize_risk("low", "recon") == "low"
        assert normalize_risk("CRITICAL", "recon") == "critical"

    def test_unknown_risk_fails_closed_to_high(self):
        assert normalize_risk("meh", "recon") == "high"
        assert normalize_risk(None, "recon") == "high"

    def test_high_risk_phases_have_high_floor(self):
        assert normalize_risk("low", "destruction") == "high"
        assert normalize_risk("medium", "crypto_theft") == "high"
        assert normalize_risk("critical", "destruction") == "critical"

    def test_normal_phase_keeps_low(self):
        assert normalize_risk("low", "recon") == "low"


# ─── Dual-LLM reconciliation (fail closed) ─────────────────────────────────

class TestDualLlmReconciliation:
    def test_dual_allow_is_allow(self, tmp_path):
        warlog = make_warlog(tmp_path)
        sentinel = Sentinel(
            FakeBrain([allow_reply("p-ok")]),
            FakeBrain([allow_reply("s-ok")], model="fake-ro-14b", provider="fake_local2"),
            gate=make_gate(), warlog=warlog,
        )
        result = sentinel.review(ACTION)

        assert result.verdict == VERDICT_ALLOW
        assert result.roe_allowed is True
        assert result.primary["verdict"] == VERDICT_ALLOW
        assert result.secondary["verdict"] == VERDICT_ALLOW
        assert result.primary["model"] == "fake-ro-7b"
        assert result.secondary["model"] == "fake-ro-14b"
        assert result.secondary["provider"] == "fake_local2"

        events = warlog.get_entries(module=MODULE)
        assert len(events) == 1
        assert events[0]["level"] == LogLevel.AGENT.value
        assert events[0]["data"]["verdict"] == VERDICT_ALLOW

    def test_one_deny_denies_even_if_other_allows(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]),
            FakeBrain([deny_reply("out of policy")]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert "denied" in result.reason

    def test_secondary_deny_denies(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([deny_reply("nope")]),
            FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        assert sentinel.review(ACTION).verdict == VERDICT_DENY

    def test_any_abstain_denies(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]),
            FakeBrain([abstain_reply("cannot judge")]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert "inconclusive" in result.reason

    def test_unparsable_response_is_abstain_then_deny(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain(["I think this is fine, go ahead"]),
            FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert result.primary["verdict"] == VERDICT_ABSTAIN

    def test_ambiguous_keyword_reply_fails_closed_to_abstain(self, tmp_path):
        # "cannot allow ... denied" mentions two verdict words: must NOT
        # parse as allow (fail-closed keyword fallback).
        sentinel = Sentinel(
            FakeBrain(["I cannot allow this, it must be denied"]),
            FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert result.primary["verdict"] == VERDICT_ABSTAIN

    def test_lone_deny_keyword_parses_as_deny(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain(["deny"]),
            FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert result.primary["verdict"] == VERDICT_DENY

    def test_garbage_source_confidence_does_not_crash(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review({**ACTION, "source_confidence": "not-a-number"})
        assert result.verdict == VERDICT_ALLOW
        assert result.source_confidence == 0.0  # least trust on unparseable metadata

    def test_reviewer_call_failure_is_abstain_then_deny(self, tmp_path):
        warlog = make_warlog(tmp_path)
        sentinel = Sentinel(
            FakeBrain(error=RuntimeError("brain down")),
            FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=warlog,
        )
        result = sentinel.review(ACTION)

        assert result.verdict == VERDICT_DENY
        assert result.primary["verdict"] == VERDICT_ABSTAIN
        assert "brain down" in result.primary["reason"]
        events = warlog.get_entries(module=MODULE)
        assert len(events) == 1  # exactly one record even on failure

    def test_missing_secondary_under_require_dual_denies(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]),
            secondary=None,
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_DENY
        assert "dual review required" in result.secondary["reason"]

    def test_single_reviewer_mode_allows_when_permitted(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]),
            secondary=None,
            gate=make_gate(), warlog=make_warlog(tmp_path),
            require_dual=False,
        )
        result = sentinel.review(ACTION)
        assert result.verdict == VERDICT_ALLOW
        assert result.secondary == {}

    def test_single_reviewer_mode_still_denies_on_deny(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([deny_reply("no")]),
            secondary=None,
            gate=make_gate(), warlog=make_warlog(tmp_path),
            require_dual=False,
        )
        assert sentinel.review(ACTION).verdict == VERDICT_DENY


# ─── Provenance tagging ─────────────────────────────────────────────────────

class TestProvenance:
    def test_provenance_captures_both_reviewers(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()], model="m1", provider="p1"),
            FakeBrain([allow_reply()], model="m2", provider="p2"),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)

        assert isinstance(result, Provenance)
        assert result.primary["model"] == "m1" and result.primary["provider"] == "p1"
        assert result.secondary["model"] == "m2" and result.secondary["provider"] == "p2"
        assert result.primary["prompt_sha256"] and result.secondary["prompt_sha256"]
        assert result.primary["call_id"] != result.secondary["call_id"]
        assert result.review_id

    def test_tag_is_compact_and_carries_review_id(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        tag = result.tag()

        assert tag["sentinel_review_id"] == result.review_id
        assert tag["sentinel_verdict"] == VERDICT_ALLOW
        assert tag["roe_allowed"] is True
        assert tag["sentinel_high_risk"] is False  # risk=low
        assert tag["reviewed_by"] == ["fake-ro-7b", "fake-ro-7b"]

    def test_high_risk_flag_set_for_destructive_phase(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review({**ACTION, "phase": "destruction", "risk": "low"})
        assert result.risk == "high"                       # phase floor applied
        assert result.tag()["sentinel_high_risk"] is True   # risk flag raised

    def test_tag_finding_attaches_provenance(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        result = sentinel.review(ACTION)
        finding = sentinel.tag_finding({"kind": "open_port", "port": 443}, result)

        assert finding["provenance"]["sentinel_review_id"] == result.review_id
        assert finding["kind"] == "open_port"  # original keys preserved

    def test_prompt_text_never_recorded(self, tmp_path):
        warlog = make_warlog(tmp_path)
        secret = "SECRET-TARGET-DO-NOT-LOG"
        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=warlog,
        )
        sentinel.review({**ACTION, "target": "192.0.2.10",
                         "description": f"probe {secret} endpoint"})

        events = warlog.get_entries(module=MODULE)
        blob = json.dumps(events)
        assert secret not in blob

    def test_each_review_gets_unique_id_and_one_record(self, tmp_path):
        warlog = make_warlog(tmp_path)
        sentinel = Sentinel(
            FakeBrain([allow_reply(), allow_reply()]),
            FakeBrain([allow_reply(), allow_reply()]),
            gate=make_gate(), warlog=warlog,
        )
        r1 = sentinel.review(ACTION)
        r2 = sentinel.review({**ACTION, "target": "192.0.2.11"})

        assert r1.review_id != r2.review_id
        assert len(warlog.get_entries(module=MODULE)) == 2

    def test_review_batch_preserves_order(self, tmp_path):
        sentinel = Sentinel(
            FakeBrain([allow_reply(), deny_reply(), allow_reply()]),
            FakeBrain([allow_reply(), deny_reply(), allow_reply()]),
            gate=make_gate(), warlog=make_warlog(tmp_path),
        )
        results = sentinel.review_batch([
            {**ACTION, "target": "192.0.2.10"},
            {**ACTION, "target": "192.0.2.11"},
            {**ACTION, "target": "192.0.2.12"},
        ])
        assert [r.verdict for r in results] == [VERDICT_ALLOW, VERDICT_DENY, VERDICT_ALLOW]

    def test_warlog_failure_does_not_mask_review(self, tmp_path):
        class ExplodingWarlog:
            def log(self, *args, **kwargs):
                raise RuntimeError("warlog down")

        sentinel = Sentinel(
            FakeBrain([allow_reply()]), FakeBrain([allow_reply()]),
            gate=make_gate(), warlog=ExplodingWarlog(),
        )
        assert sentinel.review(ACTION).verdict == VERDICT_ALLOW

"""THE VOID — agentic phase planner tests (fully offline).

Covers:
  * Evidence grounding: steps come from Boneyard attack-graph evidence
    (citing step id / host / step_type / technique); empty graph -> empty plan.
  * Hard limits: max_steps, max_branches, time-box — enforced by code even
    when the LLM proposes more; invalid limits rejected at construction.
  * Operator approval gate: execute() refuses unapproved plans; ambiguous
    approval callbacks are denials; only clear True approves.
  * Sentinel integration: denied steps are dropped (fail closed); missing
    sentinel means no step survives.
  * Failure handling: a failing step stops the plan (fail closed).
  * LLM proposal with deterministic fallback: garbage/failed brain calls
    degrade to the fallback mapper.
"""

import json

import pytest

from agent.phase_registry import PhaseRegistry
from agent.planner import (
    HARD_MAX_BRANCHES,
    HARD_MAX_STEPS,
    HARD_TIME_BOX_SECONDS,
    PhasePlanner,
    PlanLimitExceeded,
    PlanNotApproved,
)
from agent.sentinel import Provenance, VERDICT_ALLOW, VERDICT_DENY
from core.boneyard import Boneyard
from core.warlog import WarLog


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def make_boneyard(tmp_path, steps=None):
    boneyard = Boneyard(storage_dir=str(tmp_path / "boneyard"))
    host_id = boneyard.ensure_host("192.0.2.10", "h1.lab")
    for step in (DEFAULT_STEPS if steps is None else steps):
        boneyard.record_attack_step(host_id, **step)
    return boneyard


DEFAULT_STEPS = [
    {"step_type": "initial_access", "technique": "T1190",
     "outcome_status": "success", "description": "exploit web app"},
    {"step_type": "privesc", "technique": "T1068",
     "outcome_status": "success", "description": "kernel exploit"},
    {"step_type": "exfil", "technique": "T1041",
     "outcome_status": "attempted", "description": "stage data"},
]


class FakeSentinel:
    """Scripted Sentinel: verdict by phase name; records reviews."""

    def __init__(self, verdicts=None):
        self.verdicts = dict(verdicts or {})
        self.default = VERDICT_ALLOW
        self.reviews = []

    def review(self, action):
        self.reviews.append(action)
        verdict = self.verdicts.get(action["phase"], self.default)
        return Provenance(
            review_id=f"rev-{len(self.reviews)}",
            verdict=verdict,
            reason=f"scripted {verdict}",
            target=action.get("target", ""),
            phase=action["phase"],
            mode=action.get("mode", ""),
            risk=action.get("risk", ""),
            source=action.get("source", ""),
            source_confidence=action.get("source_confidence", 1.0),
            roe_allowed=verdict == VERDICT_ALLOW,
            roe_reason="scripted",
            engagement_name="lab",
            operator="op",
            primary={"model": "fake-1"},
            secondary={"model": "fake-2"},
        )


class FakeBrain:
    def __init__(self, replies=None, error=None):
        self.replies = list(replies or [])
        self.error = error
        self.calls = []

    def chat(self, messages, **kwargs):
        self.calls.append(messages)
        if self.error is not None:
            raise self.error
        text = self.replies.pop(0) if self.replies else "[]"
        return type("Resp", (), {"text": text})()


class FakeAgent:
    """Fake ShadowAgent: private phase methods record calls and can fail."""

    def __init__(self, fail_on=None):
        self.fail_on = set(fail_on or [])
        self.executed = []

    # The registry dispatches recon/exploit/data_theft/cve_exploit/mcp_scan
    # as (target, mode); c2 and similar as (target) only; mcp_chain/mcp_c2
    # as (target, mode, findings). Mirror the real signatures.
    def _recon(self, target, mode):
        return self._run("recon", target, mode)

    def _exploit(self, target, mode):
        return self._run("exploit", target, mode)

    def _cve_exploit(self, target, mode):
        return self._run("cve_exploit", target, mode)

    def _mcp_scan(self, target, mode):
        return self._run("mcp_scan", target, mode)

    def _mcp_attack(self, target, mode):
        return self._run("mcp_attack", target, mode)

    def _mcp_chain(self, target, mode, findings):
        return self._run("mcp_chain", target, mode)

    def _mcp_c2(self, target, mode, findings):
        return self._run("mcp_c2", target, mode)

    def _setup_c2(self, target):
        return self._run("c2", target, "n/a")

    def _steal_data(self, target, mode):
        return self._run("data_theft", target, mode)

    def _persistent_exfil(self, target, mode):
        return self._run("persistent_exfil", target, mode)

    def _run(self, phase, target, mode):
        if phase in self.fail_on:
            raise RuntimeError(f"{phase} exploded")
        self.executed.append((phase, target, mode))
        return {"phase": phase, "ok": True}


def make_planner(tmp_path, steps=None, sentinel=None, brain=None, agent=None,
                 **limits):
    return PhasePlanner(
        boneyard=make_boneyard(tmp_path, steps),
        registry=PhaseRegistry(),
        sentinel=sentinel,
        brain=brain,
        agent=agent or FakeAgent(),
        warlog=make_warlog(tmp_path),
        **limits,
    )


# ─── Construction limits ────────────────────────────────────────────────────

class TestLimits:
    def test_valid_limits_accepted(self, tmp_path):
        planner = make_planner(tmp_path, max_steps=1, max_branches=1,
                               time_box_seconds=60.0)
        assert planner.max_steps == 1

    @pytest.mark.parametrize("kwargs", [
        {"max_steps": 0},
        {"max_steps": HARD_MAX_STEPS + 1},
        {"max_branches": 0},
        {"max_branches": HARD_MAX_BRANCHES + 1},
        {"time_box_seconds": 0},
        {"time_box_seconds": HARD_TIME_BOX_SECONDS + 1},
    ])
    def test_invalid_limits_rejected(self, tmp_path, kwargs):
        with pytest.raises(PlanLimitExceeded):
            make_planner(tmp_path, **kwargs)


# ─── Evidence grounding ─────────────────────────────────────────────────────

class TestEvidenceGrounding:
    def test_steps_cite_graph_evidence(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")

        assert len(plan.steps) == 3
        by_type = {s.graph_step_type: s for s in plan.steps}
        assert set(by_type) == {"initial_access", "privesc", "exfil"}
        step = by_type["initial_access"]
        assert step.graph_step_id
        assert step.host_id
        assert step.technique == "T1190"
        assert step.risk in ("low", "medium", "high", "critical")
        assert step.phase in ("recon", "cve_exploit", "mcp_scan")

    def test_empty_graph_yields_empty_plan(self, tmp_path):
        planner = make_planner(tmp_path, steps=[], sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        assert plan.steps == []
        assert plan.approved is False

    def test_oldest_evidence_first(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        order = [s.graph_step_type for s in plan.steps]
        assert order.index("initial_access") < order.index("privesc")
        assert order.index("privesc") < order.index("exfil")


# ─── Hard limits enforced by code ──────────────────────────────────────────

class TestHardLimits:
    def test_max_steps_truncates(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), max_steps=2)
        plan = planner.plan("192.0.2.10")
        assert len(plan.steps) == 2
        assert any("max_steps" in d["reason"] for d in plan.dropped)

    def test_max_branches_caps_alternatives(self, tmp_path):
        brain = FakeBrain([json.dumps(["recon", "cve_exploit", "mcp_scan",
                                       "c2", "k8s_attack"])])
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=brain,
                               max_branches=2)
        plan = planner.plan("192.0.2.10")
        for step in plan.steps:
            assert len(step.alternatives) <= 1  # primary + <=1 alternative

    def test_time_box_exhaustion_stops_planning(self, tmp_path):
        # A 10s box cannot fit even the cheapest step (recon ~60s).
        planner = make_planner(tmp_path, sentinel=FakeSentinel(),
                               time_box_seconds=10.0)
        plan = planner.plan("192.0.2.10")
        assert len(plan.steps) == 0
        assert plan.time_box_exhausted is True
        assert any("time_box" in d["reason"] for d in plan.dropped)

    def test_plan_always_unapproved(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        assert plan.approved is False
        assert "awaiting" in plan.approval_note


# ─── Sentinel integration (fail closed) ────────────────────────────────────

class TestSentinelIntegration:
    def test_missing_sentinel_drops_everything(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=None)
        plan = planner.plan("192.0.2.10")
        assert plan.steps == []
        assert len(plan.dropped) == 3
        assert all("fail closed" in d["reason"] for d in plan.dropped)

    def test_denied_phase_dropped(self, tmp_path):
        sentinel = FakeSentinel(verdicts={"data_theft": VERDICT_DENY})
        planner = make_planner(tmp_path, sentinel=sentinel)
        plan = planner.plan("192.0.2.10")

        assert len(plan.steps) == 2
        assert all(s.phase != "data_theft" for s in plan.steps)
        assert any("sentinel denied" in d["reason"] for d in plan.dropped)

    def test_every_surviving_step_carries_provenance(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        for step in plan.steps:
            assert step.provenance["sentinel_review_id"]
            assert step.provenance["sentinel_verdict"] == VERDICT_ALLOW


# ─── Operator approval gate ────────────────────────────────────────────────

class TestApprovalGate:
    def test_execute_refuses_unapproved_plan(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        with pytest.raises(PlanNotApproved):
            planner.execute(plan)

    def test_clear_true_approves_and_executes(self, tmp_path):
        agent = FakeAgent()
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), agent=agent)
        plan = planner.plan("192.0.2.10")

        planner.request_approval(plan, lambda p: True)
        assert plan.approved is True
        assert plan.approval_note == "operator approved"

        results = planner.execute(plan)
        assert len(results) == len(plan.steps)
        assert all(r["status"] == "ok" for r in results)
        assert len(agent.executed) == len(plan.steps)

    def test_false_denies(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        planner.request_approval(plan, lambda p: False)
        assert plan.approved is False
        assert plan.approval_note == "operator denied"
        with pytest.raises(PlanNotApproved):
            planner.execute(plan)

    @pytest.mark.parametrize("callback", [
        lambda p: None,
        lambda p: "yes",
        lambda p: 1,
        lambda p: 0,
    ])
    def test_ambiguous_approval_is_denial(self, tmp_path, callback):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        planner.request_approval(plan, callback)
        assert plan.approved is False
        with pytest.raises(PlanNotApproved):
            planner.execute(plan)

    def test_approval_callback_exception_is_denial(self, tmp_path):
        def boom(p):
            raise RuntimeError("operator away")
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        planner.request_approval(plan, boom)
        assert plan.approved is False
        assert "error" in plan.approval_note

    def test_execute_without_agent_fails_closed(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        planner.agent = None
        plan = planner.plan("192.0.2.10")
        planner.request_approval(plan, lambda p: True)
        with pytest.raises(PlanNotApproved, match="no agent"):
            planner.execute(plan)


# ─── Execution failure handling ────────────────────────────────────────────

class TestExecution:
    def test_failing_step_stops_plan(self, tmp_path):
        agent = FakeAgent(fail_on={"recon"})
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), agent=agent)
        plan = planner.plan("192.0.2.10")
        # Fallback mapping for initial_access starts with "recon",
        # so step 1 is deterministic.
        assert plan.steps[0].phase == "recon"
        planner.request_approval(plan, lambda p: True)

        results = planner.execute(plan)

        assert results[0]["status"] == "error"
        assert "recon exploded" in results[0]["error"]
        # Fail closed: execution stops at the first failure.
        assert len(results) == 1

    def test_unknown_phase_fails_closed(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel())
        plan = planner.plan("192.0.2.10")
        plan.steps[0].phase = "not-a-phase"
        planner.request_approval(plan, lambda p: True)

        results = planner.execute(plan)
        assert results[0]["status"] == "error"
        assert results[0]["error"] == "unknown phase"
        assert len(results) == 1


# ─── LLM proposal + fallback ───────────────────────────────────────────────

class TestLlmProposal:
    def test_llm_phases_used_when_valid(self, tmp_path):
        brain = FakeBrain([json.dumps(["cve_exploit", "recon"]),
                           json.dumps(["cve_exploit"]),
                           json.dumps(["recon"])])
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=brain)
        plan = planner.plan("192.0.2.10")

        assert plan.steps[0].source == "llm"
        assert plan.steps[0].source_confidence == 0.9

    def test_llm_cannot_propose_unknown_phases(self, tmp_path):
        brain = FakeBrain([json.dumps(["not-a-phase", "recon", "also-bogus"])])
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=brain)
        plan = planner.plan("192.0.2.10")
        # "recon" is the only known phase in the proposal; unknown names
        # are filtered out and it still counts as an LLM-sourced step.
        assert plan.steps[0].source == "llm"
        assert plan.steps[0].phase == "recon"
        assert plan.steps[0].source_confidence == 0.9

    def test_garbage_reply_falls_back(self, tmp_path):
        brain = FakeBrain(["definitely not json"])
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=brain)
        plan = planner.plan("192.0.2.10")
        assert plan.steps[0].source == "fallback"
        assert plan.steps[0].source_confidence == 1.0

    def test_brain_failure_falls_back(self, tmp_path):
        brain = FakeBrain(error=RuntimeError("brain down"))
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=brain)
        plan = planner.plan("192.0.2.10")
        assert len(plan.steps) == 3
        assert all(s.source == "fallback" for s in plan.steps)

    def test_no_brain_uses_fallback(self, tmp_path):
        planner = make_planner(tmp_path, sentinel=FakeSentinel(), brain=None)
        plan = planner.plan("192.0.2.10")
        assert all(s.source == "fallback" for s in plan.steps)
        assert all(s.source_confidence == 1.0 for s in plan.steps)
        assert all(s.phase in planner.registry.phases for s in plan.steps)


# ─── Evidence ──────────────────────────────────────────────────────────────

class TestEvidence:
    def test_plan_creation_evidenced(self, tmp_path):
        warlog = make_warlog(tmp_path)
        planner = PhasePlanner(
            boneyard=make_boneyard(tmp_path),
            registry=PhaseRegistry(),
            sentinel=FakeSentinel(),
            warlog=warlog,
        )
        plan = planner.plan("192.0.2.10")
        events = warlog.get_entries(module="agent.planner")
        assert any("plan_created" in e["message"] for e in events)
        assert any("approval" in e["message"] for e in events) is False  # not approved yet

    def test_approval_and_execution_evidenced(self, tmp_path):
        warlog = make_warlog(tmp_path)
        agent = FakeAgent()
        planner = PhasePlanner(
            boneyard=make_boneyard(tmp_path),
            registry=PhaseRegistry(),
            sentinel=FakeSentinel(),
            agent=agent,
            warlog=warlog,
        )
        plan = planner.plan("192.0.2.10")
        planner.request_approval(plan, lambda p: True)
        planner.execute(plan)

        events = warlog.get_entries(module="agent.planner")
        messages = [e["message"] for e in events]
        assert any("approval" in m for m in messages)
        assert any("step_executed" in m for m in messages)
        assert any("plan_executed" in m for m in messages)

    def test_warlog_failure_does_not_mask_planning(self, tmp_path):
        class ExplodingWarlog:
            def log(self, *args, **kwargs):
                raise RuntimeError("warlog down")

        planner = PhasePlanner(
            boneyard=make_boneyard(tmp_path),
            registry=PhaseRegistry(),
            sentinel=FakeSentinel(),
            warlog=ExplodingWarlog(),
        )
        plan = planner.plan("192.0.2.10")
        assert len(plan.steps) == 3
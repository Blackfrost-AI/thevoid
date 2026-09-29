"""THE VOID — local-first LLM provider layer + FrostyBrain audit contract tests.

All tests run fully offline: providers are fakes/mocks and no sockets are
opened. The contracts under test:

  1. Egress policy defaults to local_only and rejects garbage values.
  2. ProviderRegistry is local-first and refuses cloud providers under
     local-only egress (registration refusal + EgressViolation on chat).
  3. FrostyBrain writes exactly one WarLog evidence record per call —
     success and failure alike — carrying model, provider, latency,
     prompt hash and the egress decision, and never the prompt text.
"""

import pytest

from core.warlog import LogLevel, WarLog
from llm.frosty_brain import (
    EGRESS_DECISION_CLOUD_BLOCKED,
    EGRESS_DECISION_CLOUD_PERMITTED,
    EGRESS_DECISION_LOCAL,
    EgressViolation,
    FrostyBrain,
    MODULE,
)
from llm.providers import (
    EGRESS_CLOUD_ALLOWED,
    EGRESS_LOCAL_ONLY,
    LLMProvider,
    LLMResponse,
    ProviderRegistry,
    resolve_egress_policy,
    prompt_hash,
)


# ─── Fakes (no network) ──────────────────────────────────────────────────────

class FakeLocalProvider(LLMProvider):
    name = "fake_local"
    local = True

    def __init__(self, model="fake-7b", available=True, fail=False):
        super().__init__(model=model, base_url="http://127.0.0.1:0/v1")
        self._available = available
        self._fail = fail
        self.chat_calls = []

    def _chat(self, messages, temperature=0.2, max_tokens=1024):
        self.chat_calls.append(messages)
        if self._fail:
            raise RuntimeError("simulated provider failure")
        return "fake completion", {"prompt_tokens": 3, "completion_tokens": 2}

    def _probe(self):
        return self._available


class FakeCloudProvider(FakeLocalProvider):
    name = "fake_cloud"
    local = False


class FakeUnavailableProvider(FakeLocalProvider):
    name = "fake_down"

    def __init__(self):
        super().__init__(model="down-7b", available=False)


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


def llm_events(warlog):
    return warlog.get_entries(module=MODULE)


# ─── Egress policy ───────────────────────────────────────────────────────────

class TestEgressPolicy:
    def test_default_is_local_only(self, monkeypatch):
        monkeypatch.delenv("VOID_LLM_EGRESS", raising=False)
        assert resolve_egress_policy() == EGRESS_LOCAL_ONLY

    def test_legacy_vocabulary(self):
        assert resolve_egress_policy("local") == EGRESS_LOCAL_ONLY
        assert resolve_egress_policy("off") == EGRESS_LOCAL_ONLY
        assert resolve_egress_policy("cloud") == EGRESS_CLOUD_ALLOWED
        assert resolve_egress_policy("on") == EGRESS_CLOUD_ALLOWED

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            resolve_egress_policy("yolo")


# ─── ProviderRegistry ────────────────────────────────────────────────────────

class TestProviderRegistry:
    def test_cloud_registration_refused_under_local_only(self):
        registry = ProviderRegistry()
        registry.register(FakeCloudProvider())
        assert registry.providers == []

    def test_cloud_registration_allowed_when_opted_in(self):
        registry = ProviderRegistry(egress_policy=EGRESS_CLOUD_ALLOWED)
        registry.register(FakeCloudProvider())
        assert len(registry.providers) == 1

    def test_pick_is_local_first(self):
        registry = ProviderRegistry()
        cloud = FakeCloudProvider()
        local = FakeLocalProvider()
        registry.register(cloud)
        registry.register(local)
        assert registry.pick() is local

    def test_pick_skips_unavailable(self):
        registry = ProviderRegistry()
        registry.register(FakeUnavailableProvider())
        good = FakeLocalProvider()
        registry.register(good)
        assert registry.pick() is good

    def test_pick_raises_when_nothing_available(self):
        registry = ProviderRegistry()
        registry.register(FakeUnavailableProvider())
        with pytest.raises(RuntimeError):
            registry.pick()

    def test_chat_egress_violation_if_cloud_under_local_only(self):
        # Simulate a cloud provider sneaking into a local-only registry.
        registry = ProviderRegistry()
        cloud = FakeCloudProvider()
        registry._providers.append(cloud)
        with pytest.raises(EgressViolation):
            registry.chat([{"role": "user", "content": "hi"}])
        assert cloud.chat_calls == []  # nothing was sent

    def test_chat_uses_local_provider(self):
        registry = ProviderRegistry()
        local = FakeLocalProvider()
        registry.register(local)
        response = registry.chat([{"role": "user", "content": "hi"}])
        assert response.text == "fake completion"
        assert response.provider == "fake_local"
        assert response.local is True
        assert response.latency_ms >= 0
        assert response.usage == {"prompt_tokens": 3, "completion_tokens": 2}


# ─── prompt_hash ─────────────────────────────────────────────────────────────

class TestPromptHash:
    def test_stable_and_content_sensitive(self):
        a = [{"role": "user", "content": "one"}]
        b = [{"role": "user", "content": "two"}]
        assert prompt_hash(a) == prompt_hash(list(a))
        assert prompt_hash(a) != prompt_hash(b)
        assert len(prompt_hash(a)) == 64  # sha-256 hex


# ─── FrostyBrain audit contract ─────────────────────────────────────────────

class TestFrostyBrainAudit:
    def test_successful_call_is_audited(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        local = FakeLocalProvider()
        registry.register(local)
        brain = FrostyBrain(registry=registry, warlog=warlog)

        messages = [{"role": "user", "content": "hello frosty"}]
        response = brain.chat(messages, purpose="recon-summary")

        events = llm_events(warlog)
        assert len(events) == 1
        event = events[0]
        data = event["data"]
        assert event["level"] == LogLevel.AGENT.value
        assert data["status"] == "ok"
        assert data["provider"] == "fake_local"
        assert data["model"] == "fake-7b"
        assert data["purpose"] == "recon-summary"
        assert data["egress_decision"] == EGRESS_DECISION_LOCAL
        assert data["egress_policy"] == EGRESS_LOCAL_ONLY
        assert data["prompt_sha256"] == prompt_hash(messages)
        assert data["latency_ms"] >= 0
        assert data["usage"] == {"prompt_tokens": 3, "completion_tokens": 2}
        assert data["temperature"] == 0.2
        assert data["max_tokens"] == 1024
        assert data["call_id"] == response.call_id

        # Provenance rides on the response too.
        assert response.prompt_sha256 == data["prompt_sha256"]
        assert response.egress_decision == EGRESS_DECISION_LOCAL
        assert response.purpose == "recon-summary"

    def test_prompt_text_never_recorded(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        registry.register(FakeLocalProvider())
        brain = FrostyBrain(registry=registry, warlog=warlog)

        secret = "DO-NOT-LOG-THIS-SECRET-PROMPT"
        brain.ask(secret, system="SYS-SECRET-PREAMBLE")

        events = llm_events(warlog)
        assert len(events) == 1
        # No field anywhere in the record (message or data) contains the text.
        blob = repr(events[0])
        assert secret not in blob
        assert "SYS-SECRET-PREAMBLE" not in blob

    def test_provider_failure_is_audited_then_propagates(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        registry.register(FakeLocalProvider(fail=True))
        brain = FrostyBrain(registry=registry, warlog=warlog)

        with pytest.raises(RuntimeError, match="simulated provider failure"):
            brain.chat([{"role": "user", "content": "hi"}])

        events = llm_events(warlog)
        assert len(events) == 1
        data = events[0]["data"]
        assert events[0]["level"] == LogLevel.ERROR.value
        assert data["status"] == "error"
        assert data["error_type"] == "RuntimeError"
        assert "simulated provider failure" in data["error"]
        assert data["prompt_sha256"]

    def test_no_provider_available_is_audited_then_propagates(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        registry.register(FakeUnavailableProvider())
        brain = FrostyBrain(registry=registry, warlog=warlog)

        with pytest.raises(RuntimeError):
            brain.chat([{"role": "user", "content": "hi"}])

        events = llm_events(warlog)
        assert len(events) == 1
        assert events[0]["data"]["status"] == "error"
        assert events[0]["level"] == LogLevel.ERROR.value

    def test_cloud_call_blocked_under_local_only_is_audited(self, tmp_path):
        # A cloud provider forced into a local-only registry must be refused
        # at the brain layer *and* produce evidence of the refusal.
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        cloud = FakeCloudProvider()
        registry._providers.append(cloud)
        brain = FrostyBrain(registry=registry, warlog=warlog)

        with pytest.raises(EgressViolation):
            brain.chat([{"role": "user", "content": "hi"}])

        assert cloud.chat_calls == []  # data never left the host
        events = llm_events(warlog)
        assert len(events) == 1
        data = events[0]["data"]
        assert events[0]["level"] == LogLevel.ERROR.value
        assert data["egress_decision"] == EGRESS_DECISION_CLOUD_BLOCKED
        assert data["status"] == "error"

    def test_cloud_call_permitted_when_opted_in_is_audited(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry(egress_policy=EGRESS_CLOUD_ALLOWED)
        registry.register(FakeCloudProvider())
        brain = FrostyBrain(registry=registry, warlog=warlog)

        response = brain.chat([{"role": "user", "content": "hi"}])

        assert response.egress_decision == EGRESS_DECISION_CLOUD_PERMITTED
        events = llm_events(warlog)
        assert len(events) == 1
        assert events[0]["data"]["egress_decision"] == EGRESS_DECISION_CLOUD_PERMITTED
        assert events[0]["data"]["status"] == "ok"

    def test_local_preferred_over_cloud_in_brain(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry(egress_policy=EGRESS_CLOUD_ALLOWED)
        cloud = FakeCloudProvider()
        local = FakeLocalProvider()
        registry.register(cloud)
        registry.register(local)
        brain = FrostyBrain(registry=registry, warlog=warlog)

        response = brain.chat([{"role": "user", "content": "hi"}])

        assert response.provider == "fake_local"
        assert response.egress_decision == EGRESS_DECISION_LOCAL
        assert cloud.chat_calls == []

    def test_each_call_gets_unique_call_id_and_one_record(self, tmp_path):
        warlog = make_warlog(tmp_path)
        registry = ProviderRegistry()
        registry.register(FakeLocalProvider())
        brain = FrostyBrain(registry=registry, warlog=warlog)

        r1 = brain.chat([{"role": "user", "content": "a"}])
        r2 = brain.chat([{"role": "user", "content": "b"}])

        assert r1.call_id != r2.call_id
        assert r1.prompt_sha256 != r2.prompt_sha256
        assert len(llm_events(warlog)) == 2

    def test_warlog_failure_does_not_mask_call(self, tmp_path):
        # Evidence write failure must never break the reasoning call itself.
        class ExplodingWarlog:
            def log(self, *args, **kwargs):
                raise RuntimeError("warlog down")

        registry = ProviderRegistry()
        registry.register(FakeLocalProvider())
        brain = FrostyBrain(registry=registry, warlog=ExplodingWarlog())
        response = brain.chat([{"role": "user", "content": "hi"}])
        assert response.text == "fake completion"

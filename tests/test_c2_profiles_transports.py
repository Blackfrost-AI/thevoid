"""THE VOID — malleable C2 profile + cloud transport tests (fully offline).

Covers:
  * Profile wrap/unwrap round-trip for every built-in profile and arbitrary
    transform chains; validation failures for malformed profiles.
  * HTTP shaping (render_request/parse_response) and timing jitter bounds.
  * WebhookTransport and S3PollTransport with fakes — no network, no boto3,
    no requests. WarLog evidence for every transport operation.
"""

import json

import pytest

from core.warlog import WarLog
from c2.profiles import (
    BUILTIN_PROFILES,
    Profile,
    ProfileError,
    builtin,
    validate_profile,
)
from c2.transports import S3PollTransport, TransportError, WebhookTransport


def make_warlog(tmp_path):
    return WarLog(
        log_dir=str(tmp_path / "warlog"),
        log_file=str(tmp_path / "warlog" / "warlog.log"),
        rotate_on_init=False,
    )


# ─── Profile transforms ──────────────────────────────────────────────────────

class TestProfileTransforms:
    @pytest.mark.parametrize("name", sorted(BUILTIN_PROFILES))
    @pytest.mark.parametrize("payload", [b"hello", b"", b"\x00\x01\xff", b"x" * 5000])
    def test_builtin_round_trip(self, name, payload):
        profile = builtin(name)
        assert profile.unwrap(profile.wrap(payload)) == payload

    def test_mixed_chain_round_trip(self):
        profile = Profile(
            name="mixed",
            transforms=[
                {"type": "prepend", "value": "HDR:"},
                {"type": "xor-mask", "key": "k3"},
                {"type": "base64"},
                {"type": "append", "value": ":END"},
            ],
        )
        for payload in (b"", b"single", b"with\x00nulls\xff", b"q" * 999):
            assert profile.unwrap(profile.wrap(payload)) == payload

    def test_unwrap_detects_tampered_marker(self):
        profile = Profile(
            name="marked",
            transforms=[{"type": "prepend", "value": "V1::"}],
        )
        with pytest.raises(ProfileError, match="prepend marker"):
            profile.unwrap(b"XXtampered")

    def test_builtin_returns_independent_copies(self):
        a = builtin("http-beacon")
        b = builtin("http-beacon")
        a.headers["X-Mutated"] = "1"
        assert "X-Mutated" not in b.headers


# ─── Validation / serialization ─────────────────────────────────────────────

class TestProfileValidation:
    def test_unknown_transform_rejected(self):
        with pytest.raises(ProfileError, match="unknown transform"):
            Profile.from_dict({"name": "bad", "transforms": [{"type": "rot13"}]})

    def test_bad_method_rejected(self):
        with pytest.raises(ProfileError, match="method"):
            Profile.from_dict({"name": "bad", "method": "DELETE"})

    def test_bad_jitter_rejected(self):
        with pytest.raises(ProfileError, match="jitter"):
            Profile.from_dict({"name": "bad", "jitter": 1.5})

    def test_xor_mask_requires_key(self):
        with pytest.raises(ProfileError, match="xor-mask"):
            Profile.from_dict({"name": "bad", "transforms": [{"type": "xor-mask"}]})

    def test_future_version_rejected(self):
        with pytest.raises(ProfileError, match="version"):
            Profile.from_dict({"name": "bad", "version": 99})

    def test_dict_round_trip(self):
        original = builtin("https-mimic")
        clone = Profile.from_dict(original.to_dict())
        assert clone.to_dict() == original.to_dict()
        assert clone.wrap(b"m") == original.wrap(b"m")

    def test_save_load_round_trip(self, tmp_path):
        original = builtin("http-beacon")
        path = tmp_path / "profiles" / "beacon.json"
        original.save(str(path))
        loaded = Profile.load(str(path))
        assert loaded.to_dict() == original.to_dict()

    def test_load_missing_file_raises(self):
        with pytest.raises(ProfileError, match="cannot load"):
            Profile.load("/nonexistent/profile.json")

    def test_validate_profile_helper(self):
        profile = validate_profile({"name": "ok", "transforms": [{"type": "base64"}]})
        assert profile.name == "ok"

    def test_builtin_unknown_name_raises(self):
        with pytest.raises(ProfileError, match="no built-in profile"):
            builtin("nope")


# ─── HTTP shaping + timing ──────────────────────────────────────────────────

class TestProfileHttpAndTiming:
    def test_render_request_shape(self):
        profile = builtin("http-beacon")
        request = profile.render_request(b"body-bytes", nonce="42")
        assert request["method"] == "POST"
        assert request["url"] == "/api/v42"
        assert request["body"] == b"body-bytes"
        assert request["headers"]["X-Request-Id"] == profile.watermark

    def test_parse_response_rejects_unexpected_status(self):
        profile = builtin("http-beacon")
        with pytest.raises(ProfileError, match="unexpected response status"):
            profile.parse_response(500, profile.wrap(b"x"))

    def test_parse_response_unwraps_body(self):
        profile = builtin("http-beacon")
        assert profile.parse_response(200, profile.wrap(b"ok")) == b"ok"

    def test_next_sleep_within_jitter_bounds(self):
        profile = Profile(name="t", sleep=10.0, jitter=0.5)
        samples = [profile.next_sleep() for _ in range(200)]
        assert all(5.0 <= s <= 15.0 for s in samples)

    def test_next_sleep_no_jitter(self):
        profile = Profile(name="t", sleep=7.0, jitter=0.0)
        assert profile.next_sleep() == 7.0


# ─── Webhook transport (fake session) ───────────────────────────────────────

class FakeResponse:
    def __init__(self, status_code=200, content=b""):
        self.status_code = status_code
        self.content = content


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.posts = []
        self.gets = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.posts.append({"url": url, "data": data, "headers": headers})
        if self.error:
            raise self.error
        return self.response

    def get(self, url, headers=None, timeout=None):
        self.gets.append({"url": url, "headers": headers})
        if self.error:
            raise self.error
        return self.response


class TestWebhookTransport:
    def test_send_frames_and_evidences(self, tmp_path):
        warlog = make_warlog(tmp_path)
        profile = builtin("http-beacon")
        session = FakeSession(FakeResponse(202))
        transport = WebhookTransport(
            "https://lab.invalid/hook", session=session,
            profile=profile, warlog=warlog,
        )

        result = transport.send(b"frame-bytes")

        assert result["ok"] is True and result["status"] == 202
        assert session.posts[0]["url"] == "https://lab.invalid/hook"
        assert session.posts[0]["data"] == profile.wrap(b"frame-bytes")
        events = warlog.get_entries(module="c2.transport.webhook")
        assert len(events) == 1 and events[0]["data"]["status"] == "ok"
        assert events[0]["data"]["bytes"] == len(b"frame-bytes")

    def test_send_rejects_unexpected_status_with_evidence(self, tmp_path):
        warlog = make_warlog(tmp_path)
        session = FakeSession(FakeResponse(500))
        transport = WebhookTransport(
            "https://lab.invalid/hook", session=session, warlog=warlog
        )

        with pytest.raises(TransportError, match="status 500"):
            transport.send(b"x")

        events = warlog.get_entries(module="c2.transport.webhook")
        assert events[0]["data"]["status"] == "error"

    def test_send_transport_error_evidenced(self, tmp_path):
        warlog = make_warlog(tmp_path)
        session = FakeSession(error=ConnectionError("boom"))
        transport = WebhookTransport(
            "https://lab.invalid/hook", session=session, warlog=warlog
        )

        with pytest.raises(TransportError, match="boom"):
            transport.send(b"x")

        events = warlog.get_entries(module="c2.transport.webhook")
        assert events[0]["data"]["status"] == "error"

    def test_receive_unwraps_response_body(self, tmp_path):
        warlog = make_warlog(tmp_path)
        profile = builtin("http-beacon")
        session = FakeSession(FakeResponse(200, profile.wrap(b"task-payload")))
        transport = WebhookTransport(
            "https://lab.invalid/hook", session=session,
            profile=profile, warlog=warlog,
        )

        assert transport.receive() == b"task-payload"
        assert session.gets[0]["url"] == "https://lab.invalid/hook"

    def test_receive_empty_body_ok(self, tmp_path):
        warlog = make_warlog(tmp_path)
        profile = builtin("https-mimic")
        session = FakeSession(FakeResponse(200, profile.wrap(b"")))
        transport = WebhookTransport(
            "https://lab.invalid/hook", session=session,
            profile=profile, warlog=warlog,
        )
        assert transport.receive() == b""

    def test_requires_url(self):
        with pytest.raises(TransportError, match="url"):
            WebhookTransport("", session=FakeSession())


# ─── S3 poll transport (fake client) ────────────────────────────────────────

class FakeS3Client:
    def __init__(self):
        self.objects = {}
        self.puts = []

    def put_object(self, Bucket, Key, Body, ContentType=""):
        self.objects[(Bucket, Key)] = Body
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body})

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise KeyError(Key)
        return {"Body": self.objects[(Bucket, Key)]}

    def list_objects_v2(self, Bucket, Prefix):
        keys = sorted(k for (b, k) in self.objects if b == Bucket and k.startswith(Prefix))
        return {"Contents": [{"Key": k} for k in keys]}


class TestS3PollTransport:
    def test_send_pushes_result_frame(self, tmp_path):
        warlog = make_warlog(tmp_path)
        profile = builtin("http-beacon")
        client = FakeS3Client()
        transport = S3PollTransport(
            "lab-bucket", "void-c2", client=client,
            profile=profile, warlog=warlog,
        )

        result = transport.send(b"result-frame", key="r1.frame")

        assert result["ok"] is True
        assert result["key"] == "void-c2/results/r1.frame"
        assert client.puts[0]["Body"] == profile.wrap(b"result-frame")
        events = warlog.get_entries(module="c2.transport.s3poll")
        assert events[0]["data"]["status"] == "ok"

    def test_receive_fetches_oldest_task(self, tmp_path):
        warlog = make_warlog(tmp_path)
        profile = builtin("http-beacon")
        client = FakeS3Client()
        client.objects[("lab-bucket", "void-c2/tasks/b.frame")] = profile.wrap(b"task-b")
        client.objects[("lab-bucket", "void-c2/tasks/a.frame")] = profile.wrap(b"task-a")
        transport = S3PollTransport(
            "lab-bucket", "void-c2", client=client,
            profile=profile, warlog=warlog,
        )

        assert transport.receive() == b"task-a"  # oldest key first

    def test_receive_empty_queue_evidenced(self, tmp_path):
        warlog = make_warlog(tmp_path)
        transport = S3PollTransport(
            "lab-bucket", "void-c2", client=FakeS3Client(), warlog=warlog
        )

        assert transport.receive() == b""
        events = warlog.get_entries(module="c2.transport.s3poll")
        assert any("receive_empty" in e["message"] for e in events)

    def test_send_failure_evidenced(self, tmp_path):
        warlog = make_warlog(tmp_path)

        class BrokenClient:
            def put_object(self, **kwargs):
                raise RuntimeError("s3 down")

        transport = S3PollTransport(
            "lab-bucket", "void-c2", client=BrokenClient(), warlog=warlog
        )
        with pytest.raises(TransportError, match="s3 down"):
            transport.send(b"x")

        events = warlog.get_entries(module="c2.transport.s3poll")
        assert events[0]["data"]["status"] == "error"

    def test_requires_bucket(self):
        with pytest.raises(TransportError, match="bucket"):
            S3PollTransport("", client=FakeS3Client())

    def test_round_trip_via_bucket(self, tmp_path):
        """Beacon pushes a result, daemon polls it — profile-shaped both ways."""
        warlog = make_warlog(tmp_path)
        profile = builtin("https-mimic")
        client = FakeS3Client()
        beacon_side = S3PollTransport(
            "lab-bucket", "void-c2", client=client,
            profile=profile, warlog=warlog,
        )
        daemon_side = S3PollTransport(
            "lab-bucket", "void-c2", client=client,
            profile=profile, warlog=warlog,
        )

        daemon_side.send_task(b"run-this-task", key="t1.task")
        assert beacon_side.receive() == b"run-this-task"

        beacon_side.send(b"exfil-chunk", key="e1.frame")
        assert daemon_side.receive_result() == b"exfil-chunk"

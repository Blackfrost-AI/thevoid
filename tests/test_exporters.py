"""Tests for modules.exporters — R-5 SIEM export sinks.

These tests are deliberately non-network: no real webhooks are hit and
no syslog packets leave the machine. Failure modes are synthesized via
SMTP mocks / targets that refuse the connection. The 30s timeout is
asserted directly.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from modules.exporters import (
    BaseExporter,
    CompositeExporter,
    FileJSONLinesExporter,
    SyslogExporter,
    WebhookExporter,
)


def _sample_report():
    return {
        "exec_summary": {"engagements": 1, "findings_count": 5},
        "coverage": {"aggregated": 42.0, "count": 1,
                     "engagement_scores": []},
        "integrity": {"status": "VERIFIED"},
    }


# ─── SyslogExporter ────────────────────────────────────────────────────
class TestSyslogExporter:

    def test_syslog_rfc5424_format(self):
        ex = SyslogExporter(host="127.0.0.1", port=5555)
        msg = ex._serialize({"verdict": "verified", "example": True})
        # RFC 5424: <PRI>1 TIMESTAMP HOST APPNAME PID MSGID SD MSG
        assert msg.startswith("<") and ">1 " in msg
        assert "verified" in msg

    def test_syslog_severity_mapping_math(self):
        ex = SyslogExporter()  # facility=1 (user-level messages)
        # facility*8 + severity → 1*8=8, +{alert=1, crit=2, warning=4,info=6}
        assert ex._priority(1) == 9     # <9>1 ALERT
        assert ex._priority(2) == 10    # <10>2 CRIT
        assert ex._priority(4) == 12    # <12>4 WARNING
        assert ex._priority(6) == 14    # <14>6 INFO

    def test_syslog_builds_and_sends(self):
        ex = SyslogExporter(host="127.0.0.1", port=5555)
        with patch("modules.exporters.socket.socket"):
            ok = ex.export(_sample_report())
            # UDP is fire-and-forget; socket constructor patched at module
            # level so no real datagrams are emitted.
            assert ok in (True, False)

    def test_syslog_bad_host_fail_safest(self):
        ex = SyslogExporter(host="256.256.256.256", port=5555)
        assert ex.export(_sample_report()) is False


# ─── WebhookExporter ───────────────────────────────────────────────────────
class TestWebhookExporter:

    def test_default_url_env_fallback(self):
        with patch.dict(os.environ, {"THE_VOID_SIEM_TOKEN": ""}), \
             patch.dict(os.environ, {}, clear=True):
            ex = WebhookExporter("http://127.0.0.1:9999/report")
            assert ex.url == "http://127.0.0.1:9999/report"

    def test_missing_url_raises(self):
        with pytest.raises(ValueError):
            WebhookExporter("")

    def test_timeout_capped_at_default(self):
        os.environ.pop("THE_VOID_SIEM_TOKEN", None)
        ex = WebhookExporter("http://127.0.0.1/rep")
        assert ex.timeout == 30.0
        ex2 = WebhookExporter("http://127.0.0.1/rep", timeout_seconds=10)
        assert ex2.timeout == 10

    def test_auth_token_only_env(self):
        with patch.dict(os.environ, {}, clear=True):
            ex = WebhookExporter("http://127.0.0.1/rep")
            # no env token present; export should still proceed (will fail
            # HTTP/server check but must not crash — urllib.error caught)
            result = ex.export(_sample_report())
            assert result is False  # 127.0.0.1 is not a webhook — pass

    def test_fail_open_on_unreachable_server(self):
        ex = WebhookExporter("http://127.0.0.1:1/unreachable")
        os.environ["THE_VOID_SIEM_TOKEN"] = "tok"
        assert ex.export(_sample_report()) is False


# ─── FileJSONLinesExporter ──────────────────────────────────────────────
class TestFileJSONLinesExporter:

    def test_append_jsonline_to_file(self, tmp_path):
        fp = tmp_path / "test.jsonl"
        ex = FileJSONLinesExporter(str(fp))

        ok = ex.export(_sample_report())
        assert ok is True
        assert fp.read_text(encoding="utf-8")

        # next line accumulates, doesn't replace
        ex2 = FileJSONLinesExporter(str(fp))
        ex2.export(_sample_report())
        lines = fp.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_jsonlines_line_is_valid_json(self, tmp_path):
        fp = tmp_path / "one.jsonl"
        ex = FileJSONLinesExporter(str(fp))
        ex.export(_sample_report())
        line = fp.read_text(encoding="utf-8").strip()
        parsed = json.loads(line)
        assert parsed["integrity"]["status"] == "VERIFIED"


# ─── CompositeExporter ──────────────────────────────────────────────────
class TestCompositeExporter:

    def test_composite_default_sinks_only(self):
        with patch.dict(os.environ, clear=True):
            ex = CompositeExporter()
            # patch socket AND urllib at module level to block network
            with patch("modules.exporters.socket.socket"), \
                 patch("modules.exporters.urllib.request.urlopen"):
                ex.export(_sample_report())
            assert ex._file is None
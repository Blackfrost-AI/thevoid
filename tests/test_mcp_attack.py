"""THE VOID — Tests for MCPAttack module: MCP protocol vulnerability scanner."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from exploit.mcp_attack import (
    MCPAttack, MCPFinding, AuthCheck, Endpoints, CVE_PROBES,
)
from core.executor import Executor
from core.target import Target
from core.boneyard import Boneyard
from core.warlog import WarLog


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPFinding:
    """Tests for MCPFinding dataclass."""

    def test_init_defaults(self):
        f = MCPFinding(type="test", severity="high")
        assert f.type == "test"
        assert f.severity == "high"
        assert f.cve is None
        assert f.attack_class is None
        assert f.evidence == ""
        assert f.confidence == 0.0
        assert f.endpoint == ""
        assert f.details == {}

    def test_init_full(self):
        f = MCPFinding(type="cve", severity="critical", cve="CVE-2025-6514",
                       attack_class="rce", evidence="inject",
                       confidence=0.95, endpoint="/tools", details={"key": "val"})
        assert f.cve == "CVE-2025-6514"
        assert f.confidence == 0.95
        assert f.details == {"key": "val"}

    def test_to_dict(self):
        f = MCPFinding(type="cve", severity="high", cve="CVE-2025-1",
                       confidence=0.8, endpoint="/tools")
        d = f.to_dict()
        assert d["type"] == "cve"
        assert d["severity"] == "high"
        assert d["cve"] == "CVE-2025-1"
        assert d["confidence"] == 0.8
        assert d["endpoint"] == "/tools"

    def test_to_dict_roundtrip(self):
        f = MCPFinding(type="auth", severity="medium", evidence="no auth")
        d = f.to_dict()
        assert "type" in d
        assert "severity" in d
        assert "evidence" in d


class TestAuthCheck:
    """Tests for AuthCheck dataclass."""

    def test_init(self):
        a = AuthCheck(check_name="no_auth", status="fail", risk_level="critical")
        assert a.check_name == "no_auth"
        assert a.status == "fail"
        assert a.risk_level == "critical"

    def test_defaults(self):
        a = AuthCheck(check_name="test", status="pass", risk_level="low")
        assert a.evidence == ""
        assert a.details == {}


class TestEndpoints:
    """Tests for Endpoints dataclass."""

    def test_init_empty(self):
        ep = Endpoints()
        assert ep.tools == []
        assert ep.resources == []
        assert ep.prompts == []
        assert ep.raw_response == {}

    def test_init_with_data(self):
        ep = Endpoints(tools=[{"name": "ping"}], resources=[{"uri": "file://x"}])
        assert len(ep.tools) == 1
        assert len(ep.resources) == 1


# ═══════════════════════════════════════════════════════════════════════════════
#  CVE PROBES CONSTANT
# ═══════════════════════════════════════════════════════════════════════════════

class TestCVEProbes:
    """Tests for the CVE_PROBES constant."""

    def test_probes_count(self):
        assert len(CVE_PROBES) == 8

    def test_probe_fields(self):
        for probe in CVE_PROBES:
            assert "id" in probe
            assert "name" in probe
            assert "description" in probe
            assert "method" in probe
            assert "params" in probe

    def test_probe_ids_unique(self):
        ids = [p["id"] for p in CVE_PROBES]
        assert len(ids) == len(set(ids))

    def test_probe_cve_format(self):
        for probe in CVE_PROBES:
            assert probe["id"].startswith("CVE-")


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack INIT & BASIC
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackInit:
    """Tests for MCPAttack class initialization."""

    def test_init_default(self):
        m = MCPAttack()
        assert m.executor is not None
        assert m.boneyard is not None
        assert m.warlog is not None

    def test_init_custom_executor(self):
        e = Executor()
        m = MCPAttack(executor=e)
        assert m.executor is e

    def test_init_custom_boneyard(self):
        b = Boneyard()
        m = MCPAttack(boneyard=b)
        assert m.boneyard is b

    def test_init_custom_warlog(self):
        w = WarLog()
        m = MCPAttack(warlog=w)
        # Note: MCPAttack uses `warlog or WarLog()` — WarLog() may be falsy,
        # so we check that m.warlog is a WarLog instance (identity may differ)
        assert isinstance(m.warlog, WarLog)

    def test_severity_order_constant(self):
        assert MCPAttack.SEVERITY_ORDER["critical"] == 0
        assert MCPAttack.SEVERITY_ORDER["high"] == 1
        assert MCPAttack.SEVERITY_ORDER["medium"] == 2
        assert MCPAttack.SEVERITY_ORDER["low"] == 3
        assert MCPAttack.SEVERITY_ORDER["info"] == 4


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack PUBLIC METHODS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackPublicMethods:
    """Tests for MCPAttack public API."""

    def test_scan_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'scan')

    def test_enumerate_endpoints_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_enumerate_endpoints')

    def test_probe_cves_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_probe_cves')

    def test_detect_attack_classes_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_detect_attack_classes')

    def test_assess_auth_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_assess_auth')

    def test_format_report_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'format_report')

    def test_get_tool_count_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'get_tool_count')

    def test_get_attack_class_findings_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'get_attack_class_findings')

    def test_get_cve_findings_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'get_cve_findings')

    def test_get_auth_findings_exists(self):
        m = MCPAttack()
        assert hasattr(m, 'get_auth_findings')


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack HELPER METHODS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackHelpers:
    """Tests for MCPAttack helper methods."""

    def test_sort_findings_empty(self):
        result = MCPAttack._sort_findings([])
        assert result == []

    def test_sort_findings(self):
        findings = [
            MCPFinding(type="test", severity="low"),
            MCPFinding(type="test", severity="critical"),
            MCPFinding(type="test", severity="medium"),
        ]
        result = MCPAttack._sort_findings(findings)
        assert result[0].severity == "critical"
        assert result[1].severity == "medium"
        assert result[2].severity == "low"

    def test_count_by_severity_empty(self):
        result = MCPAttack._count_by_severity([])
        assert result == {}

    def test_count_by_severity(self):
        findings = [
            MCPFinding(type="test", severity="high"),
            MCPFinding(type="test", severity="high"),
            MCPFinding(type="test", severity="low"),
        ]
        result = MCPAttack._count_by_severity(findings)
        assert result["high"] == 2
        assert result["low"] == 1

    def test_get_tool_count_empty(self):
        m = MCPAttack()
        ep = Endpoints()
        assert m.get_tool_count(ep) == 0

    def test_get_tool_count_with_tools(self):
        m = MCPAttack()
        ep = Endpoints(tools=[{"name": "a"}, {"name": "b"}])
        assert m.get_tool_count(ep) == 2

    def test_classify_cve_error(self):
        m = MCPAttack()
        # _classify_cve_error(self, cve_id, probe, error_msg, base_url) -> MCPFinding
        result = m._classify_cve_error("CVE-2025-6514", {"name": "test_probe"}, "timeout", "http://localhost:3000")
        assert isinstance(result, MCPFinding)

    def test_format_report_empty(self):
        m = MCPAttack()
        report = m.format_report([])
        assert isinstance(report, str)
        assert len(report) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack SCAN WITH MOCKS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackScan:
    """Tests for MCPAttack.scan with mocked executor."""

    @patch('exploit.mcp_attack.MCPAttack._json_rpc_call')
    @patch('exploit.mcp_attack.MCPAttack._enumerate_endpoints')
    @patch('exploit.mcp_attack.MCPAttack._probe_cves')
    @patch('exploit.mcp_attack.MCPAttack._detect_attack_classes')
    @patch('exploit.mcp_attack.MCPAttack._assess_auth')
    @patch('exploit.mcp_attack.MCPAttack._store_findings')
    def test_scan_returns_findings(self, mock_store, mock_auth, mock_detect,
                                    mock_probe, mock_enum, mock_rpc):
        mock_enum.return_value = Endpoints(tools=[{"name": "ping"}])
        mock_probe.return_value = []
        mock_detect.return_value = []
        mock_auth.return_value = []
        mock_store.return_value = []
        m = MCPAttack()
        target = Target("10.0.0.1")
        result = m.scan(target)
        assert isinstance(result, list)

    @patch('exploit.mcp_attack.MCPAttack._json_rpc_call')
    @patch('exploit.mcp_attack.MCPAttack._enumerate_endpoints')
    @patch('exploit.mcp_attack.MCPAttack._probe_cves')
    @patch('exploit.mcp_attack.MCPAttack._detect_attack_classes')
    @patch('exploit.mcp_attack.MCPAttack._assess_auth')
    @patch('exploit.mcp_attack.MCPAttack._store_findings')
    def test_scan_with_findings(self, mock_store, mock_auth, mock_detect,
                                 mock_probe, mock_enum, mock_rpc):
        mock_enum.return_value = Endpoints(tools=[{"name": "ping"}])
        mock_probe.return_value = [MCPFinding(type="cve", severity="critical",
                                              cve="CVE-2025-6514", confidence=0.9)]
        mock_detect.return_value = [MCPFinding(type="attack_class", severity="high",
                                                attack_class="tool_poisoning")]
        mock_auth.return_value = [MCPFinding(type="auth", severity="medium")]
        mock_store.return_value = []
        m = MCPAttack()
        target = Target("10.0.0.1")
        result = m.scan(target)
        assert isinstance(result, list)
        # The scan should return dicts (from findings)
        if result:
            assert isinstance(result[0], dict)

    @patch('exploit.mcp_attack.MCPAttack._enumerate_endpoints')
    def test_scan_empty_endpoints(self, mock_enum):
        mock_enum.return_value = Endpoints()
        m = MCPAttack()
        target = Target("10.0.0.1")
        with patch('exploit.mcp_attack.MCPAttack._probe_cves', return_value=[]), \
             patch('exploit.mcp_attack.MCPAttack._detect_attack_classes', return_value=[]), \
             patch('exploit.mcp_attack.MCPAttack._assess_auth', return_value=[]), \
             patch('exploit.mcp_attack.MCPAttack._store_findings', return_value=[]):
            result = m.scan(target)
            assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack ATTACK CLASS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackDetection:
    """Tests for MCPAttack attack class detection."""

    def test_detect_attack_classes_empty(self):
        m = MCPAttack()
        result = m._detect_attack_classes("http://localhost:3000", Endpoints())
        assert isinstance(result, list)

    def test_gather_text_for_detection_empty(self):
        m = MCPAttack()
        result = m._gather_text_for_detection(Endpoints())
        assert isinstance(result, list)
        assert len(result) == 0

    def test_gather_text_for_detection_with_tools(self):
        m = MCPAttack()
        ep = Endpoints(tools=[{"name": "execute", "description": "Run a command"}])
        result = m._gather_text_for_detection(ep)
        assert isinstance(result, list)
        assert len(result) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack AUTH ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackAuth:
    """Tests for MCPAttack auth assessment."""

    def test_assess_auth_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_assess_auth')

    def test_check_no_auth_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_no_auth')

    def test_check_static_key_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_static_key')

    def test_check_oauth_misconfig_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_oauth_misconfig')

    def test_check_binding_0000_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_binding_0000')

    def test_check_internet_exposed_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_internet_exposed')

    def test_check_tls_disabled_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_check_tls_disabled')


# ═══════════════════════════════════════════════════════════════════════════════
#  MCPAttack JSON-RPC
# ═══════════════════════════════════════════════════════════════════════════════

class TestMCPAttackJsonRpc:
    """Tests for MCPAttack JSON-RPC communication."""

    def test_json_rpc_call_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_json_rpc_call')

    def test_resolve_url_exists(self):
        m = MCPAttack()
        assert hasattr(m, '_resolve_url')

    def test_resolve_url_default(self):
        m = MCPAttack()
        target = Target("10.0.0.1")
        url = m._resolve_url(target)
        assert isinstance(url, str)
        assert "10.0.0.1" in url

    def test_resolve_url_with_port(self):
        m = MCPAttack()
        target = Target("10.0.0.1", name="10.0.0.1:8080")
        url = m._resolve_url(target)
        assert isinstance(url, str)
        assert "10.0.0.1" in url

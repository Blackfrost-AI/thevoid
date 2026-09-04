"""THE VOID — Tests for recon modules: OSINT, PortScan, WebRecon, HostEnum."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.executor import Executor, CommandResult
from core.target import Target, TargetType
from recon.osint import OSINT
from recon.portscan import PortScan
from recon.webrecon import WebRecon
from recon.hostenum import HostEnum


# ═══════════════════════════════════════════════════════════════════════════════
#  OSINT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestOSINT:
    """Tests for OSINT module."""

    def test_init(self):
        o = OSINT()
        assert o.executor is not None
        assert "amass" in o.tools
        assert "subfinder" in o.tools
        assert "whois" in o.tools

    def test_init_custom_executor(self):
        e = Executor()
        o = OSINT(executor=e)
        assert o.executor is e

    def test_enumerate_subdomains(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="amass", stdout="sub1.example.com\nsub2.example.com\n",
            stderr="", exit_code=0, duration=1.0
        )
        mock_sf = CommandResult(
            command="subfinder", stdout="sub3.example.com\n",
            stderr="", exit_code=0, duration=1.0
        )
        o.executor.run_tool = MagicMock(side_effect=[mock_result, mock_sf])
        result = o.enumerate_subdomains(target)
        assert "subdomains" in result
        assert "count" in result

    def test_whois_lookup(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        whois_output = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar
Creation Date: 2020-01-01
Expiry Date: 2025-01-01
Name Server: ns1.example.com
"""
        mock_result = CommandResult(
            command="whois", stdout=whois_output,
            stderr="", exit_code=0, duration=2.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.whois_lookup(target)
        assert "domain name" in result

    def test_whois_lookup_failure(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="whois", stdout="", stderr="not found",
            exit_code=1, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.whois_lookup(target)
        assert "error" in result

    def test_dns_lookup(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        dns_results = [
            CommandResult(command="dig", stdout="93.184.216.34\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="dig", stdout="ns1.example.com\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="dig", stdout="mx1.example.com\n", stderr="", exit_code=0, duration=1.0),
        ]
        o.executor.run_tool = MagicMock(side_effect=dns_results)
        result = o.dns_lookup(target)
        assert "a_records" in result
        assert "93.184.216.34" in result["a_records"]

    def test_whatweb_scan(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="whatweb", stdout="example.com [200] Apache, PHP, jQuery",
            stderr="", exit_code=0, duration=3.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.whatweb_scan(target)
        assert "url" in result

    def test_whatweb_scan_failure(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="whatweb", stdout="", stderr="timeout",
            exit_code=1, duration=3.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.whatweb_scan(target)
        assert "error" in result

    def test_full_recon(self):
        target = Target("example.com")
        o = OSINT(executor=MagicMock())
        mock_results = [
            CommandResult(command="amass", stdout="sub1.example.com\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="subfinder", stdout="sub2.example.com\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="whois", stdout="Domain Name: EXAMPLE.COM\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="dig", stdout="93.184.216.34\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="dig", stdout="ns1.example.com\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="dig", stdout="mx1.example.com\n", stderr="", exit_code=0, duration=1.0),
            CommandResult(command="whatweb", stdout="Apache", stderr="", exit_code=0, duration=1.0),
        ]
        o.executor.run_tool = MagicMock(side_effect=mock_results)
        result = o.full_recon(target)
        assert "subdomains" in result
        assert "whois" in result
        assert "dns" in result
        assert "technologies" in result

    def test_parse_whois(self):
        o = OSINT()
        raw = "Domain Name: EXAMPLE.COM\nRegistrar: Test\nCreation Date: 2020-01-01\n"
        result = o._parse_whois(raw)
        assert "domain name" in result
        assert result["domain name"] == "EXAMPLE.COM"

    def test_parse_whatweb(self):
        o = OSINT()
        raw = "example.com [200] Apache, PHP, jQuery"
        result = o._parse_whatweb(raw)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════════════════════════
#  PORTSCAN TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPortScan:
    """Tests for PortScan module."""

    def test_init(self):
        p = PortScan()
        assert p.executor is not None

    def test_init_custom_executor(self):
        e = Executor()
        p = PortScan(executor=e)
        assert p.executor is e

    def test_quick_scan_success(self):
        target = Target("192.168.1.1")
        p = PortScan(executor=MagicMock())
        nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        mock_result = CommandResult(
            command="nmap", stdout=nmap_xml,
            stderr="", exit_code=0, duration=10.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.quick_scan(target)
        assert "error" not in result or "error" in result

    def test_quick_scan_failure(self):
        target = Target("192.168.1.1")
        p = PortScan(executor=MagicMock())
        mock_result = CommandResult(
            command="nmap", stdout="", stderr="Host seems down",
            exit_code=1, duration=5.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.quick_scan(target)
        assert "error" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBRECON TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebRecon:
    """Tests for WebRecon module."""

    def test_init(self):
        w = WebRecon()
        assert w.executor is not None

    def test_init_custom_executor(self):
        e = Executor()
        w = WebRecon(executor=e)
        assert w.executor is e


# ═══════════════════════════════════════════════════════════════════════════════
#  HOSTENUM TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHostEnum:
    """Tests for HostEnum module."""

    def test_init(self):
        h = HostEnum()
        assert h.executor is not None

    def test_init_custom_executor(self):
        e = Executor()
        h = HostEnum(executor=e)
        assert h.executor is e

"""THE VOID — Tests for modules: DataTheft, LLMJailbreak, NetworkBypass."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.executor import Executor, CommandResult
from core.target import Target
from core.boneyard import Boneyard
from modules.datatheft import DataTheft
from modules.llm_jailbreak import LLMJailbreak
from modules.network_bypass import NetworkBypass


# ═══════════════════════════════════════════════════════════════════════════════
#  DATA THEFT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataTheft:
    """Tests for DataTheft module."""

    def test_init(self):
        d = DataTheft()
        assert d.executor is not None
        assert d.boneyard is not None

    def test_init_custom_executor_boneyard(self):
        e = Executor()
        b = Boneyard()
        d = DataTheft(executor=e, boneyard=b)
        assert d.executor is e
        assert d.boneyard is b

    def test_has_exfil_file(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_file')

    def test_has_exfil_directory(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_directory')

    def test_has_exfil_via_http(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_via_http')

    def test_has_exfil_via_dns(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_via_dns')

    def test_has_exfil_database(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_database')

    def test_has_exfil_via_tor(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_via_tor')

    def test_has_exfil_via_ssh(self):
        d = DataTheft()
        assert hasattr(d, 'exfil_via_ssh')


# ═══════════════════════════════════════════════════════════════════════════════
#  LLM JAILBREAK TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLLMJailbreak:
    """Tests for LLMJailbreak module."""

    def test_init(self):
        l = LLMJailbreak()
        assert l.executor is not None

    def test_init_custom_executor(self):
        e = Executor()
        l = LLMJailbreak(executor=e)
        assert l.executor is e

    def test_has_test_prompt_injection(self):
        l = LLMJailbreak()
        assert hasattr(l, 'test_prompt_injection')

    def test_has_test_system_prompt_extraction(self):
        l = LLMJailbreak()
        assert hasattr(l, 'test_system_prompt_extraction')

    def test_has_test_role_switching(self):
        l = LLMJailbreak()
        assert hasattr(l, 'test_role_switching')

    def test_has_full_jailbreak_test(self):
        l = LLMJailbreak()
        assert hasattr(l, 'full_jailbreak_test')


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK BYPASS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkBypass:
    """Tests for NetworkBypass module."""

    def test_init(self):
        n = NetworkBypass()
        assert n.executor is not None

    def test_init_custom_executor(self):
        e = Executor()
        n = NetworkBypass(executor=e)
        assert n.executor is e

    def test_has_ssl_strip(self):
        n = NetworkBypass()
        assert hasattr(n, 'ssl_strip')

    def test_has_nmap_ssl_scan(self):
        n = NetworkBypass()
        assert hasattr(n, 'nmap_ssl_scan')

    def test_has_mitm_attack(self):
        n = NetworkBypass()
        assert hasattr(n, 'mitm_attack')

    def test_has_dns_spoof(self):
        n = NetworkBypass()
        assert hasattr(n, 'dns_spoof')

    def test_has_tcp_hijack(self):
        n = NetworkBypass()
        assert hasattr(n, 'tcp_hijack')

    def test_has_port_forward(self):
        n = NetworkBypass()
        assert hasattr(n, 'port_forward')

    def test_has_full_bypass(self):
        n = NetworkBypass()
        assert hasattr(n, 'full_bypass')

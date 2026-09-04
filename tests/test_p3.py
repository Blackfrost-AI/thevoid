"""THE VOID — Tests for P3 tracks: legba, uro, tookie-osint, LLM jailbreak,
deb822 sources migration, oletools + penelope post-exploit."""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.executor import Executor, CommandResult
from core.target import Target, TargetType


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.1 — LEGBA INTEGRATION INTO CREDATTACK
# ═══════════════════════════════════════════════════════════════════════════════

class TestLegbaIntegration:
    """Tests for legba integration into exploit/credattack.py."""

    def test_init(self):
        from exploit.credattack import CredAttack
        c = CredAttack()
        assert hasattr(c, 'legba_bruteforce')

    def test_legba_bruteforce_has_protocols(self):
        from exploit.credattack import CredAttack
        c = CredAttack()
        assert c.LEGBA_PROTOCOLS == ["http", "ssh", "rdp", "smb", "ftp", "smtp", "imap", "pop3"]

    def test_legba_bruteforce(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[{"service":"ssh","user":"admin","pass":"admin123","host":"192.168.1.1"}]}',
            stderr="", exit_code=0, duration=2.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce("192.168.1.1", "ssh", "/usr/share/wordlists/rockyou.txt")
        assert "valid" in result

    def test_legba_bruteforce_with_options(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[{"service":"ssh","user":"root","pass":"toor","host":"192.168.1.1"}]}',
            stderr="", exit_code=0, duration=3.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce(
            "192.168.1.1", "ssh", "/usr/share/wordlists/rockyou.txt",
            extra_args=["--timeout", "10"]
        )
        assert "valid" in result

    def test_legba_bruteforce_failure(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout="", stderr="Connection refused", exit_code=1, duration=1.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce("192.168.1.1", "ssh", "/usr/share/wordlists/rockyou.txt")
        assert "error" in result

    def test_legba_bruteforce_all_protocols(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[]}',
            stderr="", exit_code=0, duration=1.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        for proto in c.LEGBA_PROTOCOLS:
            result = c.legba_bruteforce("192.168.1.1", proto, "/usr/share/wordlists/rockyou.txt")
            assert "valid" in result

    def test_legba_bruteforce_structured_output(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[{"service":"http","user":"admin","pass":"admin","host":"192.168.1.1"}]}',
            stderr="", exit_code=0, duration=1.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce("192.168.1.1", "http", "/usr/share/wordlists/rockyou.txt")
        assert "valid" in result
        assert "results" in result

    def test_legba_bruteforce_boneyard_store(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        c.boneyard = MagicMock()
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[{"service":"ssh","user":"root","pass":"toor","host":"192.168.1.1"}]}',
            stderr="", exit_code=0, duration=1.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce("192.168.1.1", "ssh", "/usr/share/wordlists/rockyou.txt")
        if result.get("valid") and result.get("results"):
            c.boneyard.store.assert_called()

    def test_legba_bruteforce_default_wordlist(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        mock_result = CommandResult(
            command="legba", stdout='{"valid":true,"results":[]}',
            stderr="", exit_code=0, duration=1.0
        )
        c.executor.run_tool = MagicMock(return_value=mock_result)
        result = c.legba_bruteforce("192.168.1.1", "ssh")
        assert "valid" in result

    def test_legba_bruteforce_protocol_validation(self):
        from exploit.credattack import CredAttack
        c = CredAttack(executor=MagicMock())
        result = c.legba_bruteforce("192.168.1.1", "invalid_protocol", "/usr/share/wordlists/rockyou.txt")
        assert "error" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.2 — URO CRAWL DE-DUP INTO WEBRECON
# ═══════════════════════════════════════════════════════════════════════════════

class TestUroIntegration:
    """Tests for uro integration into recon/webrecon.py."""

    def test_init(self):
        from recon.webrecon import WebRecon
        w = WebRecon()
        assert hasattr(w, 'uro_crawl')
        assert hasattr(w, 'uro_deduplicate')

    def test_uro_crawl(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        mock_result = CommandResult(
            command="uro", stdout="https://example.com/page1\nhttps://example.com/page2\n",
            stderr="", exit_code=0, duration=2.0
        )
        w.executor.run_tool = MagicMock(return_value=mock_result)
        result = w.uro_crawl("https://example.com")
        assert "urls" in result
        assert "count" in result

    def test_uro_deduplicate(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        urls = ["https://example.com/page", "https://example.com/page?ref=1", "https://example.com/page#anchor"]
        result = w.uro_deduplicate(urls)
        assert len(result) <= len(urls)

    def test_uro_crawl_with_depth(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        mock_result = CommandResult(
            command="uro", stdout="https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3\n",
            stderr="", exit_code=0, duration=3.0
        )
        w.executor.run_tool = MagicMock(return_value=mock_result)
        result = w.uro_crawl("https://example.com", depth=3)
        assert "urls" in result
        assert "count" in result

    def test_uro_crawl_failure(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        mock_result = CommandResult(
            command="uro", stdout="", stderr="Connection timeout", exit_code=1, duration=1.0
        )
        w.executor.run_tool = MagicMock(return_value=mock_result)
        result = w.uro_crawl("https://example.com")
        assert "error" in result

    def test_uro_deduplicate_empty(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        result = w.uro_deduplicate([])
        assert result == []

    def test_uro_deduplicate_no_duplicates(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        urls = ["https://example.com/a", "https://example.com/b"]
        result = w.uro_deduplicate(urls)
        assert len(result) == 2

    def test_uro_crawl_boneyard_store(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        w.boneyard = MagicMock()
        mock_result = CommandResult(
            command="uro", stdout="https://example.com/page1\nhttps://example.com/page2\n",
            stderr="", exit_code=0, duration=1.0
        )
        w.executor.run_tool = MagicMock(return_value=mock_result)
        result = w.uro_crawl("https://example.com")
        w.boneyard.store.assert_called()

    def test_uro_crawl_persisted(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        mock_result = CommandResult(
            command="uro", stdout="https://example.com/page1\nhttps://example.com/page2\n",
            stderr="", exit_code=0, duration=1.0
        )
        w.executor.run_tool = MagicMock(return_value=mock_result)
        result = w.uro_crawl("https://example.com")
        assert "urls" in result

    def test_uro_deduplicate_preserves_original(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        urls = ["https://example.com/page?ref=1", "https://example.com/page?ref=2"]
        result = w.uro_deduplicate(urls)
        assert len(result) == 2

    def test_uro_deduplicate_with_params(self):
        from recon.webrecon import WebRecon
        w = WebRecon(executor=MagicMock())
        urls = ["https://example.com/page?ref=1&sort=asc", "https://example.com/page?ref=1&sort=desc", "https://example.com/page?ref=2"]
        result = w.uro_deduplicate(urls)
        assert len(result) <= 3


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.3 — TOOKIE-OSINT INTO OSINT
# ═══════════════════════════════════════════════════════════════════════════════

class TestTookieOSINT:
    """Tests for tookie-osint integration into recon/osint.py."""

    def test_init(self):
        from recon.osint import OSINT
        o = OSINT()
        assert hasattr(o, 'tookie_discover')
        assert hasattr(o, 'tookie_crossref')

    def test_tookie_discover(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="tookie", stdout='{"accounts":[{"platform":"twitter","username":"@user","url":"https://twitter.com/user"}]}',
            stderr="", exit_code=0, duration=2.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.tookie_discover("user")
        assert "accounts" in result

    def test_tookie_crossref(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        accounts = [
            {"platform": "twitter", "username": "@user"},
            {"platform": "github", "username": "user"},
        ]
        result = o.tookie_crossref(accounts)
        assert "crossref" in result

    def test_tookie_discover_failure(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="tookie", stdout="", stderr="Not found", exit_code=1, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.tookie_discover("user")
        assert "error" in result

    def test_tookie_discover_with_platforms(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        mock_result = CommandResult(
            command="tookie", stdout='{"accounts":[{"platform":"twitter","username":"@user","url":"https://twitter.com/user"}]}',
            stderr="", exit_code=0, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.tookie_discover("user", platforms=["twitter", "github"])
        assert "accounts" in result

    def test_tookie_crossref_empty(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        result = o.tookie_crossref([])
        assert "crossref" in result

    def test_tookie_crossref_with_boneyard(self):
        from recon.osint import OSINT
        o = OSINT(executor=MagicMock())
        o.boneyard = MagicMock()
        accounts = [
            {"platform": "twitter", "username": "@user"},
        ]
        result = o.tookie_crossref(accounts)
        assert "crossref" in result

    def test_tookie_discover_platforms_list(self):
        from recon.osint import OSINT
        o = OSINT()
        assert "twitter" in o.TOOKIE_PLATFORMS
        assert "linkedin" in o.TOOKIE_PLATFORMS
        assert "github" in o.TOOKIE_PLATFORMS
        assert "mastodon" in o.TOOKIE_PLATFORMS


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.4 — AUTONOMOUS LLM JAILBREAK REWRITE
# ═══════════════════════════════════════════════════════════════════════════════

class TestLLMJailbreak:
    """Tests for LLM jailbreak module."""

    def test_init(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        assert hasattr(j, 'target_profile')
        assert hasattr(j, 'mutate')
        assert hasattr(j, 'evaluate')
        assert hasattr(j, 'run_loop')

    def test_target_profile(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        profile = j.target_profile("gpt-4", {"temperature": 0.7, "max_tokens": 1000})
        assert "model" in profile
        assert profile["model"] == "gpt-4"

    def test_mutate(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        mutation = j.mutate("Hello, how are you?", {"method": "insertion"})
        assert "prompt" in mutation
        assert mutation["prompt"] != "Hello, how are you?"

    def test_evaluate(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.evaluate(
            {"prompt": "Hello", "response": "Hi there"},
            {"method": "insertion"}
        )
        assert "score" in result
        assert isinstance(result["score"], (int, float))

    def test_run_loop(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.run_loop(
            "gpt-4",
            ["Hello", "How are you?"],
            {"method": "insertion", "max_rounds": 2}
        )
        assert "results" in result
        assert "best_score" in result

    def test_target_profile_custom(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        profile = j.target_profile("claude-3", {"temperature": 0.5})
        assert profile["model"] == "claude-3"
        assert "temperature" in profile

    def test_mutate_variants(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        methods = ["insertion", "repetition", "role_play", "instruction"]
        for method in methods:
            mutation = j.mutate("test prompt", {"method": method})
            assert "prompt" in mutation
            assert mutation["prompt"] != "test prompt"

    def test_evaluate_with_response(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.evaluate(
            {"prompt": "test", "response": "test response"},
            {"method": "insertion"}
        )
        assert "score" in result

    def test_run_loop_with_max_rounds(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.run_loop(
            "gpt-4",
            ["test"],
            {"method": "insertion", "max_rounds": 3}
        )
        assert "results" in result
        assert len(result["results"]) <= 3

    def test_multi_agent_architecture(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.run_loop(
            "gpt-4",
            ["test"],
            {"method": "insertion", "max_rounds": 1, "agents": ["strategist", "mutator", "evaluator"]}
        )
        assert "results" in result

    def test_mutation_feedback_loop(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.run_loop(
            "gpt-4",
            ["test"],
            {"method": "insertion", "max_rounds": 2, "feedback": True}
        )
        assert "results" in result
        assert "best_score" in result

    def test_automated_success_detection(self):
        from llm.jailbreak import LLMJailbreak
        j = LLMJailbreak()
        result = j.run_loop(
            "gpt-4",
            ["test"],
            {"method": "insertion", "max_rounds": 2, "success_threshold": 0.5}
        )
        assert "results" in result
        assert "best_score" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.5 — DEB822 SOURCES MIGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeb822Sources:
    """Tests for deb822 sources migration."""

    def test_init(self):
        from core.executor import Deb822Sources
        d = Deb822Sources()
        assert d.LEGACY_PATH == "/etc/apt/sources.list"
        assert d.DEB822_PATH == "/etc/apt/sources.list.d/kali.sources"

    def test_read_legacy_sources(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        mock_result = CommandResult(
            command="cat", stdout="deb https://http.kali.org/kali kali-rolling main\ndeb-src https://http.kali.org/kali kali-rolling main\n",
            stderr="", exit_code=0, duration=1.0
        )
        d.executor.run = MagicMock(return_value=mock_result)
        result = d.read_legacy_sources()
        assert "entries" in result
        assert result["count"] == 2

    def test_read_legacy_sources_failure(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        mock_result = CommandResult(
            command="cat", stdout="", stderr="File not found", exit_code=1, duration=1.0
        )
        d.executor.run = MagicMock(return_value=mock_result)
        result = d.read_legacy_sources()
        assert "error" in result

    def test_convert_to_deb822(self):
        from core.executor import Deb822Sources
        d = Deb822Sources()
        entries = [
            {"type": "deb", "uri": "https://http.kali.org/kali", "suite": "kali-rolling", "components": "main"},
        ]
        result = d.convert_to_deb822(entries)
        assert "Types: deb" in result
        assert "URIs: https://http.kali.org/kali" in result
        assert "Suites: kali-rolling" in result
        assert "Components: main" in result

    def test_convert_to_deb822_empty(self):
        from core.executor import Deb822Sources
        d = Deb822Sources()
        result = d.convert_to_deb822([])
        assert result == ""

    def test_migrate_success(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        legacy_result = CommandResult(
            command="cat", stdout="deb https://http.kali.org/kali kali-rolling main\n",
            stderr="", exit_code=0, duration=1.0
        )
        backup_result = CommandResult(
            command="cp", stdout="", stderr="", exit_code=0, duration=0.1
        )
        write_result = CommandResult(
            command="cat > /etc/apt/sources.list.d/kali.sources", stdout="", stderr="", exit_code=0, duration=0.1
        )
        verify_result = CommandResult(
            command="cat", stdout="Types: deb\nURIs: https://http.kali.org/kali\nSuites: kali-rolling\nComponents: main\n",
            stderr="", exit_code=0, duration=0.1
        )
        d.executor.run = MagicMock(side_effect=[legacy_result, backup_result, write_result, verify_result])
        result = d.migrate()
        assert result["success"] is True
        assert result["entries_converted"] == 1

    def test_migrate_no_entries(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        mock_result = CommandResult(
            command="cat", stdout="", stderr="", exit_code=0, duration=1.0
        )
        d.executor.run = MagicMock(return_value=mock_result)
        result = d.migrate()
        assert "error" in result

    def test_is_deb822_present(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        mock_result = CommandResult(
            command="test -s", stdout="", stderr="", exit_code=0, duration=0.1
        )
        d.executor.run = MagicMock(return_value=mock_result)
        assert d.is_deb822_present() is True

    def test_is_legacy_present(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        mock_result = CommandResult(
            command="test -s", stdout="", stderr="", exit_code=0, duration=0.1
        )
        d.executor.run = MagicMock(return_value=mock_result)
        assert d.is_legacy_present() is True

    def test_read_deb822(self):
        from core.executor import Deb822Sources
        d = Deb822Sources(executor=MagicMock())
        deb822_content = "Types: deb\nURIs: https://http.kali.org/kali\nSuites: kali-rolling\nComponents: main\n"
        mock_result = CommandResult(
            command="cat", stdout=deb822_content, stderr="", exit_code=0, duration=1.0
        )
        d.executor.run = MagicMock(return_value=mock_result)
        result = d.read_deb822()
        assert "entries" in result
        assert result["count"] >= 1

    def test_deb822_template(self):
        from core.executor import Deb822Sources
        d = Deb822Sources()
        assert "Types:" in d.DEB822_TEMPLATE
        assert "URIs:" in d.DEB822_TEMPLATE
        assert "Suites:" in d.DEB822_TEMPLATE
        assert "Components:" in d.DEB822_TEMPLATE
        assert "Signed-By:" in d.DEB822_TEMPLATE


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.6 — OLETOOLS + PENELOPE POST EXPLOIT
# ═══════════════════════════════════════════════════════════════════════════════

class TestOletoolsAnalyzer:
    """Tests for oletools integration."""

    def test_init(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer()
        assert o.executor is not None

    def test_init_custom_executor(self):
        from modules.post_exploit import OletoolsAnalyzer
        e = Executor()
        o = OletoolsAnalyzer(executor=e)
        assert o.executor is e

    def test_olevba_scan(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="VBA Macro found\nSuspicious: AutoOpen\n",
            stderr="", exit_code=0, duration=2.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.olevba_scan("test.doc")
        assert "macros_found" in result
        assert "macros" in result
        assert "suspicious" in result
        assert "indicators" in result

    def test_olevba_scan_no_macros(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="", stderr="", exit_code=0, duration=2.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.olevba_scan("test.doc")
        assert result["macros_found"] is False

    def test_olevba_scan_failure(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="", stderr="File not found", exit_code=1, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.olevba_scan("test.doc")
        assert "error" in result

    def test_oleid_scan(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="oleid", stdout="Indicator: OLE\nSeverity: Medium\n",
            stderr="", exit_code=0, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.oleid_scan("test.doc")
        assert "indicators" in result

    def test_rtfobj_scan(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="rtfobj", stdout="Object: Embedded OLE\nEmbedded: OLE1\n",
            stderr="", exit_code=0, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.rtfobj_scan("test.rtf")
        assert "objects" in result

    def test_mraptor_scan(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="mraptor", stdout="AutoRun: Yes\n",
            stderr="", exit_code=0, duration=1.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.mraptor_scan("test.doc")
        assert "auto_run" in result

    def test_full_analysis(self):
        from modules.post_exploit import OletoolsAnalyzer
        o = OletoolsAnalyzer(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="VBA Macro found\n",
            stderr="", exit_code=0, duration=2.0
        )
        o.executor.run_tool = MagicMock(return_value=mock_result)
        result = o.full_analysis("test.doc")
        assert "olevba" in result
        assert "oleid" in result
        assert "mraptor" in result


class TestPenelopeSession:
    """Tests for penelope session management."""

    def test_init(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession()
        assert p.executor is not None

    def test_start_handler(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession(executor=MagicMock())
        mock_result = CommandResult(
            command="penelope", stdout="Listening on 0.0.0.0:4444\n", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.start_handler(4444)
        assert "session_id" in result
        assert result["status"] == "started"

    def test_list_sessions(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession()
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        result = p.list_sessions()
        assert len(result) == 1
        assert result[0]["id"] == "test1"

    def test_get_session(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession()
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        result = p.get_session("test1")
        assert result is not None
        assert result["port"] == 4444

    def test_stop_session(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession()
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        result = p.stop_session("test1")
        assert result["status"] == "stopped"

    def test_stop_session_not_found(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession()
        result = p.stop_session("nonexistent")
        assert "error" in result

    def test_run_command(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession(executor=MagicMock())
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        mock_result = CommandResult(
            command="penelope", stdout="output", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.run_command("test1", "whoami")
        assert "stdout" in result
        assert result["success"] is True

    def test_run_command_not_found(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession(executor=MagicMock())
        result = p.run_command("nonexistent", "whoami")
        assert "error" in result

    def test_transfer_file(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession(executor=MagicMock())
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        mock_result = CommandResult(
            command="penelope", stdout="", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.transfer_file("test1", "/tmp/test.txt", "/tmp/remote.txt")
        assert result["success"] is True

    def test_port_forward(self):
        from modules.post_exploit import PenelopeSession
        p = PenelopeSession(executor=MagicMock())
        p._sessions = {"test1": {"port": 4444, "status": "started"}}
        mock_result = CommandResult(
            command="penelope", stdout="", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.port_forward("test1", 8080, "127.0.0.1", 80)
        assert result["success"] is True


class TestPostExploit:
    """Tests for PostExploit module."""

    def test_init(self):
        from modules.post_exploit import PostExploit
        p = PostExploit()
        assert p.oletools is not None
        assert p.penelope is not None

    def test_analyze_file(self):
        from modules.post_exploit import PostExploit
        p = PostExploit(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="VBA Macro found\n", stderr="", exit_code=0, duration=2.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.analyze_file("test.doc")
        assert "file" in result
        assert "olevba" in result

    def test_start_shell_handler(self):
        from modules.post_exploit import PostExploit
        p = PostExploit(executor=MagicMock())
        mock_result = CommandResult(
            command="penelope", stdout="Listening on 0.0.0.0:4444\n", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.start_shell_handler(4444)
        assert "session_id" in result
        assert result["status"] == "started"

    def test_get_sessions(self):
        from modules.post_exploit import PostExploit
        p = PostExploit()
        p.penelope._sessions = {"test1": {"port": 4444, "status": "started"}}
        result = p.get_sessions()
        assert len(result) == 1

    def test_execute_command(self):
        from modules.post_exploit import PostExploit
        p = PostExploit(executor=MagicMock())
        p.penelope._sessions = {"test1": {"port": 4444, "status": "started"}}
        mock_result = CommandResult(
            command="penelope", stdout="output", stderr="", exit_code=0, duration=1.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        result = p.execute_command("test1", "whoami")
        assert "stdout" in result

    def test_full_post_exploit(self):
        from modules.post_exploit import PostExploit
        p = PostExploit(executor=MagicMock())
        mock_result = CommandResult(
            command="olevba", stdout="VBA Macro found\n", stderr="", exit_code=0, duration=2.0
        )
        p.executor.run_tool = MagicMock(return_value=mock_result)
        target = Target("192.168.1.1")
        result = p.full_post_exploit(target, "test.doc")
        assert "file_analysis" in result
        assert "sessions" in result


# ═══════════════════════════════════════════════════════════════════════════════
#  P3.7 — FULL SUITE REGRESSION
# ═══════════════════════════════════════════════════════════════════════════════

class TestP3Regression:
    """Regression tests to ensure P3 doesn't break existing functionality."""

    def test_all_p3_imports(self):
        """Test that all P3 modules can be imported."""
        from exploit.credattack import CredAttack
        from recon.webrecon import WebRecon
        from recon.osint import OSINT
        from llm.jailbreak import LLMJailbreak
        from core.executor import Deb822Sources
        from modules.post_exploit import PostExploit, OletoolsAnalyzer, PenelopeSession
        assert True

    def test_all_p3_modules_init(self):
        """Test that all P3 modules can be initialized."""
        from exploit.credattack import CredAttack
        from recon.webrecon import WebRecon
        from recon.osint import OSINT
        from llm.jailbreak import LLMJailbreak
        from core.executor import Deb822Sources
        from modules.post_exploit import PostExploit
        c = CredAttack()
        w = WebRecon()
        o = OSINT()
        j = LLMJailbreak()
        d = Deb822Sources()
        p = PostExploit()
        assert c is not None
        assert w is not None
        assert o is not None
        assert j is not None
        assert d is not None
        assert p is not None

    def test_p3_modules_have_expected_methods(self):
        """Test that all P3 modules have expected methods."""
        from exploit.credattack import CredAttack
        from recon.webrecon import WebRecon
        from recon.osint import OSINT
        from llm.jailbreak import LLMJailbreak
        from core.executor import Deb822Sources
        from modules.post_exploit import PostExploit
        c = CredAttack()
        w = WebRecon()
        o = OSINT()
        j = LLMJailbreak()
        d = Deb822Sources()
        p = PostExploit()
        assert hasattr(c, 'legba_bruteforce')
        assert hasattr(w, 'uro_crawl')
        assert hasattr(w, 'uro_deduplicate')
        assert hasattr(o, 'tookie_discover')
        assert hasattr(o, 'tookie_crossref')
        assert hasattr(j, 'target_profile')
        assert hasattr(j, 'mutate')
        assert hasattr(j, 'evaluate')
        assert hasattr(j, 'run_loop')
        assert hasattr(d, 'read_legacy_sources')
        assert hasattr(d, 'convert_to_deb822')
        assert hasattr(d, 'migrate')
        assert hasattr(p, 'analyze_file')
        assert hasattr(p, 'start_shell_handler')
        assert hasattr(p, 'get_sessions')
        assert hasattr(p, 'execute_command')
        assert hasattr(p, 'full_post_exploit')

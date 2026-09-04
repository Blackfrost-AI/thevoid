"""THE VOID — Tests for modules.reporter.Reporter.

Covers:
    - Data gathering (gather_data / to_dict)
    - JSON / Markdown / HTML generation
    - Output-to-file behaviour
    - Integrity verification flag (skipped vs. invoked)
    - Findings collection + sorting by risk_score
    - Engagement summarization
    - Error tolerance (None sources, broken sources)
    - Format validation
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.reporter import Reporter, __version__ as REPORTER_VERSION


# ═══════════════════════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

def _make_warlog(total_entries=5, levels=None):
    """Create a mock WarLog with a controlled get_summary()."""
    wl = MagicMock()
    wl.get_summary.return_value = {
        "session_id": "test-session-abc",
        "total_entries": total_entries,
        "duration_seconds": 12.34,
        "level_counts": levels or {"INFO": 3, "WARN": 1, "ERROR": 1},
        "log_file": "/tmp/warlog.json",
    }
    return wl


def _make_boneyard(total_items=10, categories=None, findings=None):
    """Create a mock Boneyard."""
    by = MagicMock()
    by.get_summary.return_value = {
        "total_items": total_items,
        "categories": categories or {"cred": 4, "host": 3, "vuln": 3},
        "storage_dir": "/tmp/boneyard",
        "encrypted": True,
        "schema_version": "2.0",
    }
    by.query_findings.return_value = findings or []
    return by


def _sample_attack_log():
    """Two engagement entries with findings dicts."""
    return [
        {
            "target": "10.0.0.1",
            "mode": "full",
            "status": "completed",
            "elapsed": 5.2,
            "started_at": "2026-01-01T00:00:00Z",
            "findings": {"recon": {"ports": [22, 80]}, "exploit": {"cve": "x"}},
        },
        {
            "target": "10.0.0.2",
            "mode": "quick",
            "status": "completed",
            "elapsed": 2.1,
            "started_at": "2026-01-01T00:05:00Z",
            "findings": {"recon": {"error": "timeout"}},
        },
    ]


def _sample_findings():
    """Findings with varied risk_scores (should sort desc)."""
    return [
        {"id": "f1", "category": "cred", "risk_score": 9.5,
         "tags": ["ssh"], "host_id": "h1", "timestamp": "2026-01-01"},
        {"id": "f2", "category": "vuln", "risk_score": 3.0,
         "tags": [], "host_id": "h2", "timestamp": "2026-01-02"},
        {"id": "f3", "category": "cred", "risk_score": 7.0,
         "tags": ["db"], "host_id": "h3", "timestamp": "2026-01-03"},
    ]


@pytest.fixture
def reporter():
    """A fully-wired Reporter with mock data sources."""
    return Reporter(
        warlog=_make_warlog(),
        boneyard=_make_boneyard(findings=_sample_findings()),
        attack_log=_sample_attack_log(),
        operator="test-op",
        engagement_name="Test Engagement",
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  INIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestReporterInit:
    def test_default_verify_integrity_is_false(self):
        r = Reporter()
        assert r.verify_integrity is False

    def test_verify_integrity_true(self):
        r = Reporter(verify_integrity=True)
        assert r.verify_integrity is True

    def test_defaults(self):
        r = Reporter()
        assert r.warlog is None
        assert r.boneyard is None
        assert r.attack_log == []
        assert r.operator == "THE VOID"
        assert r.engagement_name == "Engagement Report"

    def test_attack_log_copied(self):
        al = [{"target": "x"}]
        r = Reporter(attack_log=al)
        assert r.attack_log == al
        assert r.attack_log is not al  # defensive copy

    def test_valid_formats_constant(self):
        assert "html" in Reporter.VALID_FORMATS
        assert "json" in Reporter.VALID_FORMATS
        assert "markdown" in Reporter.VALID_FORMATS
        assert "md" in Reporter.VALID_FORMATS


# ═══════════════════════════════════════════════════════════════════════════════
#  GATHER DATA
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatherData:
    def test_top_level_keys(self, reporter):
        data = reporter.gather_data()
        for key in ("report_metadata", "exec_summary", "engagements",
                    "findings", "boneyard_inventory", "warlog_telemetry",
                    "integrity"):
            assert key in data, f"Missing key: {key}"

    def test_to_dict_alias(self, reporter, monkeypatch):
        """to_dict() is an alias for gather_data(); verify same structure.

        Each gather_data() stamps a fresh timestamp, so we freeze the clock
        to compare exact equality.
        """
        from modules import reporter as mod
        from datetime import datetime, timezone

        frozen = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        class _FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen

        monkeypatch.setattr(mod, "datetime", _FrozenDateTime)
        assert reporter.to_dict() == reporter.gather_data()

    def test_metadata(self, reporter):
        md = reporter.gather_data()["report_metadata"]
        assert md["operator"] == "test-op"
        assert md["engagement_name"] == "Test Engagement"
        assert md["tool"] == "THE VOID"
        assert md["version"] == REPORTER_VERSION
        assert "generated_at" in md
        assert isinstance(md["generated_epoch"], float)

    def test_exec_summary_counts(self, reporter):
        es = reporter.gather_data()["exec_summary"]
        assert es["engagements"] == 2
        assert es["targets"] == 2
        assert sorted(es["target_names"]) == ["10.0.0.1", "10.0.0.2"]
        assert es["findings_count"] == 3
        assert es["boneyard_items"] == 10
        assert es["warlog_events"] == 5

    def test_warlog_telemetry(self, reporter):
        wl = reporter.gather_data()["warlog_telemetry"]
        assert wl["session_id"] == "test-session-abc"
        assert wl["total_entries"] == 5
        assert wl["duration_seconds"] == 12.34
        assert wl["level_counts"] == {"INFO": 3, "WARN": 1, "ERROR": 1}

    def test_boneyard_inventory(self, reporter):
        inv = reporter.gather_data()["boneyard_inventory"]
        assert inv["total_items"] == 10
        assert inv["categories"] == {"cred": 4, "host": 3, "vuln": 3}
        assert inv["encrypted"] is True

    def test_integrity_skipped_by_default(self, reporter):
        integ = reporter.gather_data()["integrity"]
        assert integ["overall_verified"] is None
        assert integ["status"] == "UNKNOWN"
        assert integ["warlog"]["verified"] is None
        assert integ["boneyard"]["verified"] is None
        # Should NOT have called verify_integrity on mocks
        reporter.warlog.verify_integrity.assert_not_called()
        reporter.boneyard.verify_integrity.assert_not_called()

    def test_none_sources_safe(self):
        """No warlog/boneyard — should not crash."""
        r = Reporter(warlog=None, boneyard=None, attack_log=[])
        data = r.gather_data()
        assert data["warlog_telemetry"]["total_entries"] == 0
        assert data["boneyard_inventory"]["total_items"] == 0
        assert data["findings"] == []
        assert data["exec_summary"]["engagements"] == 0

    def test_broken_source_safe(self):
        """A source whose get_summary raises — should not crash."""
        bad_wl = MagicMock()
        bad_wl.get_summary.side_effect = RuntimeError("boom")
        bad_by = MagicMock()
        bad_by.get_summary.side_effect = RuntimeError("boom")
        bad_by.query_findings.side_effect = RuntimeError("boom")
        r = Reporter(warlog=bad_wl, boneyard=bad_by, attack_log=[])
        data = r.gather_data()
        # _safe_call swallows and returns default {}
        assert data["warlog_telemetry"]["total_entries"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  FINDINGS COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestFindingsCollection:
    def test_sorted_by_risk_desc(self, reporter):
        findings = reporter.gather_data()["findings"]
        scores = [f["risk_score"] for f in findings]
        assert scores == sorted(scores, reverse=True)
        assert scores[0] == 9.5

    def test_findings_shape(self, reporter):
        f = reporter.gather_data()["findings"][0]
        for key in ("id", "category", "risk_score", "tags", "host_id",
                    "timestamp"):
            assert key in f

    def test_no_boneyard_no_findings(self):
        r = Reporter(boneyard=None)
        assert r.gather_data()["findings"] == []

    def test_boneyard_query_findings_returns_none_safe(self):
        by = MagicMock()
        by.get_summary.return_value = {"total_items": 0, "categories": {}}
        by.query_findings.return_value = None
        r = Reporter(boneyard=by)
        assert r.gather_data()["findings"] == []

    def test_risk_score_non_numeric_handled(self):
        """Findings with non-numeric risk_score should sort to bottom."""
        by = MagicMock()
        by.get_summary.return_value = {"total_items": 2, "categories": {}}
        by.query_findings.return_value = [
            {"id": "a", "risk_score": "high"},
            {"id": "b", "risk_score": 5.0},
        ]
        r = Reporter(boneyard=by)
        findings = r.gather_data()["findings"]
        assert findings[0]["id"] == "b"  # numeric 5.0 first


# ═══════════════════════════════════════════════════════════════════════════════
#  ENGAGEMENT SUMMARIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestEngagementSummarization:
    def test_engagement_shape(self, reporter):
        e = reporter.gather_data()["engagements"][0]
        assert e["target"] == "10.0.0.1"
        assert e["mode"] == "full"
        assert e["status"] == "completed"
        assert e["elapsed"] == 5.2
        assert e["phases"] == 2
        assert e["errors"] == 0

    def test_error_count_in_findings(self, reporter):
        e = reporter.gather_data()["engagements"][1]
        assert e["errors"] == 1  # {"error": "timeout"}

    def test_empty_attack_log(self):
        r = Reporter(attack_log=[])
        assert r.gather_data()["engagements"] == []
        assert r.gather_data()["exec_summary"]["engagements"] == 0

    def test_engagement_missing_fields(self):
        r = Reporter(attack_log=[{}])
        e = r.gather_data()["engagements"][0]
        assert e["target"] == "unknown"
        assert e["mode"] == "unknown"
        assert e["status"] == "unknown"
        assert e["phases"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
#  INTEGRITY (verify_integrity=True path)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrityVerification:
    def test_verify_true_calls_warlog(self):
        wl = MagicMock()
        wl.get_summary.return_value = {"total_entries": 0, "level_counts": {}}
        ir = MagicMock()
        ir.to_dict.return_value = {"verified": True, "total_events": 5,
                                   "broken_hmacs": [], "broken_chain_links": []}
        wl.verify_integrity.return_value = ir
        by = MagicMock()
        by.get_summary.return_value = {"total_items": 0, "categories": {}}
        by.query_findings.return_value = []
        bi = MagicMock()
        bi.to_dict.return_value = {"verified": True, "total_rows_checked": 3,
                                   "broken_hmacs": [], "broken_chain_links": []}
        by.verify_integrity.return_value = bi

        r = Reporter(warlog=wl, boneyard=by, verify_integrity=True)
        integ = r.gather_data()["integrity"]
        assert integ["overall_verified"] is True
        assert integ["status"] == "VERIFIED"
        wl.verify_integrity.assert_called_once()
        by.verify_integrity.assert_called_once()

    def test_verify_true_tampered(self):
        wl = MagicMock()
        wl.get_summary.return_value = {"total_entries": 0, "level_counts": {}}
        ir = MagicMock()
        ir.to_dict.return_value = {"verified": False, "total_events": 5,
                                   "broken_hmacs": [1, 2]}
        wl.verify_integrity.return_value = ir
        by = MagicMock()
        by.get_summary.return_value = {"total_items": 0, "categories": {}}
        by.query_findings.return_value = []
        bi = MagicMock()
        bi.to_dict.return_value = {"verified": True, "total_rows_checked": 0,
                                   "broken_hmacs": []}
        by.verify_integrity.return_value = bi

        r = Reporter(warlog=wl, boneyard=by, verify_integrity=True)
        integ = r.gather_data()["integrity"]
        assert integ["overall_verified"] is False
        assert integ["status"] == "TAMPERED"


# ═══════════════════════════════════════════════════════════════════════════════
#  JSON GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestJsonGeneration:
    def test_generate_json_valid(self, reporter):
        data = reporter.gather_data()
        out = reporter.generate_json(data)
        parsed = json.loads(out)
        assert parsed["report_metadata"]["operator"] == "test-op"
        assert parsed["exec_summary"]["engagements"] == 2

    def test_generate_json_roundtrip(self, reporter):
        data = reporter.gather_data()
        out = reporter.generate_json(data)
        parsed = json.loads(out)
        # Re-serialize and compare (deterministic given same data)
        assert json.loads(reporter.generate_json(data)) == parsed

    def test_generate_format_json(self, reporter):
        out = reporter.generate(format="json")
        assert json.loads(out)["report_metadata"]["tool"] == "THE VOID"


# ═══════════════════════════════════════════════════════════════════════════════
#  MARKDOWN GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestMarkdownGeneration:
    def test_generate_markdown_has_header(self, reporter):
        out = reporter.generate_markdown(reporter.gather_data())
        assert "# Test Engagement" in out
        assert "**Operator:** test-op" in out
        assert "THE VOID" in out

    def test_generate_markdown_has_sections(self, reporter):
        out = reporter.generate_markdown(reporter.gather_data())
        assert "## Executive Summary" in out
        assert "## Engagements" in out
        assert "## Findings" in out
        assert "## Boneyard Inventory" in out
        assert "## WarLog Telemetry" in out
        assert "## Integrity Verification" in out

    def test_generate_markdown_engagement_table(self, reporter):
        out = reporter.generate_markdown(reporter.gather_data())
        assert "| 10.0.0.1 | full | completed |" in out
        assert "| Target | Mode | Status |" in out

    def test_generate_markdown_findings(self, reporter):
        out = reporter.generate_markdown(reporter.gather_data())
        assert "risk: 9.5" in out
        assert "`f1`" in out

    def test_generate_format_markdown_and_md_alias(self, reporter, monkeypatch):
        """markdown and md should produce identical output.

        Freeze the clock so the two calls stamp the same timestamp.
        """
        from modules import reporter as mod
        from datetime import datetime, timezone

        frozen = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        class _FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen

        monkeypatch.setattr(mod, "datetime", _FrozenDateTime)
        md1 = reporter.generate(format="markdown")
        md2 = reporter.generate(format="md")
        assert md1 == md2
        assert "# Test Engagement" in md1

    def test_markdown_empty_findings_message(self):
        r = Reporter(warlog=_make_warlog(0, {}),
                     boneyard=_make_boneyard(0, {}, findings=[]),
                     attack_log=[])
        out = r.generate(format="markdown")
        assert "_No engagements recorded._" in out
        assert "_No findings recorded._" in out


# ═══════════════════════════════════════════════════════════════════════════════
#  HTML GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestHtmlGeneration:
    def test_generate_html_structure(self, reporter):
        out = reporter.generate_html(reporter.gather_data())
        assert out.startswith("<!DOCTYPE html>")
        assert "<html" in out
        assert "</html>" in out
        assert "<style>" in out
        assert "THE VOID" in out

    def test_generate_html_has_header(self, reporter):
        out = reporter.generate_html(reporter.gather_data())
        assert "<h1>THE VOID</h1>" in out
        assert "Test Engagement" in out

    def test_generate_html_has_sections(self, reporter):
        out = reporter.generate_html(reporter.gather_data())
        assert 'id="exec-summary"' in out
        assert "Executive Summary" in out
        assert "Engagements" in out

    def test_generate_html_escaping(self):
        """Operator name with HTML chars must be escaped."""
        r = Reporter(operator="<script>alert(1)</script>",
                     warlog=_make_warlog(0, {}),
                     boneyard=_make_boneyard(0, {}, findings=[]),
                     attack_log=[])
        out = r.generate_html(r.gather_data())
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_generate_format_html(self, reporter):
        out = reporter.generate(format="html")
        assert "<!DOCTYPE html>" in out


# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE (PUBLIC DISPATCHER)
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateDispatcher:
    def test_invalid_format_raises(self, reporter):
        with pytest.raises(ValueError, match="Unsupported format"):
            reporter.generate(format="xml")

    def test_generate_writes_file(self, reporter, tmp_path):
        out_file = tmp_path / "report.json"
        reporter.generate(format="json", output_path=str(out_file))
        assert out_file.exists()
        parsed = json.loads(out_file.read_text())
        assert parsed["report_metadata"]["tool"] == "THE VOID"

    def test_generate_creates_parent_dirs(self, reporter, tmp_path):
        out_file = tmp_path / "deep" / "nested" / "dir" / "report.html"
        reporter.generate(format="html", output_path=str(out_file))
        assert out_file.exists()
        assert out_file.read_text().startswith("<!DOCTYPE html>")

    def test_generate_returns_content(self, reporter):
        content = reporter.generate(format="json")
        assert isinstance(content, str)
        assert json.loads(content)

    def test_generate_all_formats(self, reporter):
        for fmt in ("html", "json", "markdown", "md"):
            content = reporter.generate(format=fmt)
            assert isinstance(content, str)
            assert len(content) > 0


# ═══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK + COMPLIANCE OVERLAY
# ═══════════════════════════════════════════════════════════════════════════════

class TestMitreAnnotation:
    def test_mitre_section_present_in_gather_data(self, reporter):
        data = reporter.gather_data()
        assert "mitre" in data
        for key in ("techniques_used", "technique_counts", "tactic_coverage",
                    "tactics", "coverage_pct", "coverage_denominator",
                    "compliance", "mapped_findings", "mapped_phases"):
            assert key in data["mitre"]

    def test_findings_carry_technique_fields(self, reporter):
        findings = reporter.gather_data()["findings"]
        assert findings  # fixture provides findings
        for f in findings:
            assert "mitre_technique_id" in f
            assert "mitre_technique_name" in f
            assert "mitre_tactic" in f
            assert isinstance(f["mitre_technique_id"], str)

    def test_unknown_category_goes_to_unmapped(self):
        r = Reporter(
            warlog=_make_warlog(0, {}),
            boneyard=_make_boneyard(0, {}, findings=[
                {"id": "x1", "category": "brandnewcategory",
                 "risk_score": 5.0, "tags": [], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[],
        )
        data = r.gather_data()
        assert data["findings"][0]["mitre_technique_id"] == "UNMAPPED"
        assert data["findings"][0]["mitre_tactic"] == "Unmapped"

    def test_native_and_alias_techniques_separated(self):
        # cred → T1110 (native); mcp_scan + llm_jailbreak phases → ALIAS entries
        r = Reporter(
            warlog=_make_warlog(0, {}),
            boneyard=_make_boneyard(0, {}, findings=[
                {"id": "c1", "category": "cred", "risk_score": 8.0,
                 "tags": [], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[
                {"target": "t", "mode": "full", "status": "completed",
                 "elapsed": 1.0,
                 "findings": {"mcp_scan": {"info": 1}, "mcp_attack": {"info": 2},
                              "llm_jailbreak": {"info": 3}, "recon": {"info": 4}}},
            ],
        )
        data = r.gather_data()
        tech_ids = {t["id"] for t in data["mitre"]["techniques_used"]}
        assert "T1110" in tech_ids
        assert any(t.startswith("ALIAS:") for t in tech_ids)
        # compliance must only include native techniques (no ALIAS)
        for tid in data["mitre"]["compliance"]:
            assert not tid.startswith("ALIAS:")
            assert tid != "UNMAPPED"

    def test_tactics_are_attack_forward_ordered(self, reporter):
        tactics = reporter.gather_data()["mitre"]["tactics"]
        # tactics must follow the ATTACK_TACTIC_ORDER constant, not alphabetical
        order = Reporter.ATTACK_TACTIC_ORDER
        seen = [t for t in order if t in tactics]
        assert seen == [t for t in tactics if t in order]  # order preserved

    def test_coverage_counts_only_unmapped_excluded(self):
        # Ensure UNMAPPED findings do not inflate native technique coverage.
        r = Reporter(
            warlog=_make_warlog(0, {}),
            boneyard=_make_boneyard(0, {}, findings=[
                {"id": "a", "category": "other",  "risk_score": 1.0,
                 "tags": [], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[],
        )
        data = r.gather_data()
        assert data["findings"][0]["mitre_technique_id"] == "UNMAPPED"
        # used_native excludes UNMAPPED by construction; coverage_pct is 0
        assert data["mitre"]["coverage_pct"] == 0.0
        assert data["mitre"]["native_techniques_used"] == 0

    def test_alias_does_not_inflate_native_coverage(self):
        # Pure ALIAS engagement (MCP-only) contributes 0 native techniques.
        r = Reporter(
            warlog=_make_warlog(0, {}),
            boneyard=_make_boneyard(0, {}, findings=[]),
            attack_log=[
                {"target": "t", "mode": "full", "status": "completed",
                 "elapsed": 1.0,
                 "findings": {"mcp_scan": {}, "mcp_attack": {}, "llm_jailbreak": {}}},
            ],
        )
        data = r.gather_data()
        assert data["mitre"]["native_techniques_used"] == 0
        assert data["mitre"]["coverage_pct"] == 0.0
        assert data["mitre"]["alias_techniques_used"] > 0

    def test_compliance_requires_stable_technique_ids(self):
        for tid, entry in Reporter.COMPLIANCE_MAP.items():
            assert not tid.startswith("ALIAS:")
            assert tid != "UNMAPPED"
            for frame in ("nist", "pci", "iso"):
                assert frame in entry

    def test_mitre_markdown_section(self):
        r = Reporter(
            warlog=_make_warlog(),
            boneyard=_make_boneyard(findings=[
                {"id": "r1", "category": "recon", "risk_score": 5.0,
                 "tags": ["s"], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[],
        )
        out = r.generate(format="markdown")
        assert "## MITRE ATT&CK Coverage" in out
        assert "## Compliance Cross-Reference" in out
        assert "NIST SP 800-53" in out

    def test_mitre_html_section(self):
        r = Reporter(
            warlog=_make_warlog(),
            boneyard=_make_boneyard(findings=[
                {"id": "r1", "category": "recon", "risk_score": 5.0,
                 "tags": ["s"], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[],
        )
        out = r.generate_html(r.gather_data())
        assert 'id="mitre"' in out
        assert "Compliance Cross-Reference" in out
        assert "NIST SP 800-53" in out

    def test_mcp_alias_annotated_in_findings(self):
        r = Reporter(
            warlog=_make_warlog(0, {}),
            boneyard=_make_boneyard(0, {}, findings=[
                {"id": "m1", "category": "mcp", "risk_score": 5.0,
                 "tags": [], "host_id": "h", "timestamp": "t"},
            ]),
            attack_log=[],
        )
        out = r.generate(format="markdown")
        assert "ALIAS:MCP" in out
        assert "MCP" in out


# ═══════════════════════════════════════════════════════════════════════════════
#  DETERMINISM
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeterminism:
    def test_same_data_same_findings_order(self, reporter):
        f1 = reporter.gather_data()["findings"]
        f2 = reporter.gather_data()["findings"]
        assert [f["id"] for f in f1] == [f["id"] for f in f2]

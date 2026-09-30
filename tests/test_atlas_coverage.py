"""THE VOID — ATLAS coverage mapping tests (P2, offline)."""

import pytest

from agent.phase_registry import PhaseRegistry
from core.warlog import WarLog
from modules import atlas_coverage as ac
from modules.atlas_coverage import (
    ATLAS_VERSION,
    CANONICAL_TECHNIQUES,
    _MAPPING,
    _validate_mapping,
    canonical_ids,
    coverage_for,
    known_ids,
    map_engagement,
    phases_for,
    techniques_for,
    uncovered_ids,
)


class TestCanonicalDataset:
    def test_dataset_shape(self):
        assert ATLAS_VERSION == "ATLAS-2026.09"
        assert len(CANONICAL_TECHNIQUES) == 120
        # canonical dataset keeps every ID it defines used or uncovered,
        # never an ID that does not exist upstream
        for tid, name in CANONICAL_TECHNIQUES.items():
            assert tid.startswith("AML.T") and len(tid) == len("AML.T0000")
            assert name and name == name.strip()

    def test_tactics_not_embedded(self):
        # The tactic linkage was not machine-readable in the bundle;
        # embedding guessed tactics would mis-file techniques.
        for value in CANONICAL_TECHNIQUES.values():
            assert not value.startswith("AML.TA")


class TestMappingIntegrity:
    def test_all_ids_valid(self):
        # _validate_mapping() already ran at import; assert it agrees
        _validate_mapping()                      # idempotent, must not raise
        bad = {t for ids in _MAPPING.values() for t in ids
               if t not in CANONICAL_TECHNIQUES}
        assert bad == set()

    def test_validate_fails_closed(self, monkeypatch):
        monkeypatch.setitem(_MAPPING, "__test__", ["AML.T9999"])
        with pytest.raises(RuntimeError, match="unknown ATLAS IDs"):
            _validate_mapping()                  # must raise, not warn
        del _MAPPING["__test__"]

    def test_registry_fully_mapped(self):
        reg = PhaseRegistry()
        assert set(reg.phases) == set(_MAPPING)

    @pytest.mark.parametrize("phase", sorted(_MAPPING))
    def test_phase_mapping_non_empty(self, phase):
        ids = techniques_for(phase)
        assert ids and all(t in CANONICAL_TECHNIQUES for t in ids)


class TestQueries:
    def test_techniques_for_unknown_phase(self):
        assert techniques_for("nonsense") == []

    def test_phases_for_technique(self):
        # LLM Jailbreak is exercised by both jailbreak phases
        assert sorted(phases_for("AML.T0054")) == ["advanced_jailbreak",
                                                    "llm_jailbreak"]

    def test_phases_for_unknown_returns_empty(self):
        assert phases_for("AML.T9999") == []

    def test_uncovered_partition(self):
        uncovered = set(uncovered_ids())
        assert uncovered | set(known_ids()) == set(CANONICAL_TECHNIQUES)
        assert not (uncovered & set(known_ids()))


class TestCoverageFor:
    def test_full_run(self):
        c = coverage_for(PhaseRegistry().phases)
        assert c["version"] == ATLAS_VERSION
        assert c["total_techniques"] == 120
        assert c["covered_count"] == len(known_ids())
        assert c["coverage_pct"] == round(
            100 * c["covered_count"] / 120, 1)
        assert c["unknown_phases"] == []

    def test_subset(self):
        c = coverage_for(["llm_jailbreak"])
        assert c["covered"] == sorted(techniques_for("llm_jailbreak"))
        assert c["uncovered_count"] == 120 - c["covered_count"]

    def test_empty(self):
        c = coverage_for([])
        assert c["covered_count"] == 0
        assert c["coverage_pct"] == 0.0

    def test_overlap_dedupes(self):
        # T0054 appears in both jailbreak phases; covered set stays a set
        c = coverage_for(["llm_jailbreak", "advanced_jailbreak"])
        assert c["covered"].count("AML.T0054") == 1

    def test_unknown_phase_ignored_but_reported(self):
        c = coverage_for(["recon", "bogus"])
        assert c["unknown_phases"] == ["bogus"]
        assert c["covered"] == sorted(techniques_for("recon"))


class TestMapEngagement:
    @pytest.fixture()
    def warlog(self, tmp_path):
        return WarLog(log_dir=str(tmp_path / "w"),
                      log_file=str(tmp_path / "w" / "w.log"),
                      rotate_on_init=False)

    def test_evidence_written(self, warlog):
        summary = map_engagement(
            {"phases": [{"phase": "recon"}, {"phase": "c2"}]}, warlog)
        entries = warlog.get_entries(module="modules.atlas_coverage")
        assert len(entries) == 1
        assert f"{summary['coverage_pct']}%" in entries[0]["message"]
        assert entries[0]["data"]["summary"]["version"] == ATLAS_VERSION

    def test_evidence_hash_stable(self, warlog):
        eng = {"phases": [{"phase": "recon"}]}
        s1 = map_engagement(eng, warlog)
        s2 = map_engagement(eng, warlog)
        assert s1["evidence_hash"] == s2["evidence_hash"]
        assert len(s1["evidence_hash"]) == 64

    def test_works_without_warlog(self):
        s = map_engagement({"phases_executed": ["recon"]}, None)
        assert s["covered"] == sorted(techniques_for("recon"))

    def test_phases_executed_fallback(self):
        s = map_engagement({"phases_executed": ["c2", "c2"]}, None)
        assert s["covered"] == sorted(techniques_for("c2"))

    def test_anchored_end_to_end(self, warlog):
        map_engagement({"phases": [{"phase": "mcp_attack"}]}, warlog)
        seq = warlog.max_seq()
        assert seq > 0
        anchor = warlog.anchor_events(1, seq)
        assert warlog.verify_anchor(anchor["anchor_id"])
        assert warlog.verify_row(seq, anchor_id=anchor["anchor_id"])
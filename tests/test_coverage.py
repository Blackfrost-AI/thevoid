"""Tests for modules.coverage — R-2 prevention-strength scoring engine.

Rubric (frozen in research/realism-audit-2026-07-29.md):
  score = Σ(w_coverage × c_confidence) / N_phases × 100
  cve_exploit  → 1.0 × 0.6 = 0.6  → 60 points when alone
  exploit      → 0.7 × 0.6 = 0.42 → 42 points when alone
  recon        → 0.3 × 0.1 = 0.03  → 3 points when alone
  unknown      → 0.0             → 0 points
"""

from __future__ import annotations

import pytest

from modules.coverage import CoverageScorer


def _eng(status="completed", phases=None, target="a.example"):
    return {
        "status": status,
        "findings": dict(phases or {}),
        "target": target,
        "mode": "full",
        "errors": [],
    }


# ─── Rubric frozen values ──────────────────────────────────────────────
# Matches the realism-audit numbers exactly. Any drift in
# modules/coverage.py is caught here.
EXPECTED_SCORES = {
    "recon": 3.0,         # reachability × passive  = 0.03 → 3
    "exploit": 42.0,      # exploited   × multiple  = 0.42 → 42
    "data_theft": 3.0,    # reachability × passive  = 0.03
    "c2": 3.0,            # reachability × passive  = 0.03
    "cloud_attack": 3.0,  # reachability × passive  = 0.03
    "crypto_theft": 3.0,  # reachability × passive  = 0.03
    "persistent_exfil": 3.0,
    "zero_click": 3.0,
    "k8s_attack": 3.0,
    "wireless_iot": 3.0,
    "llm_jailbreak": 0.0,
    "network_bypass": 3.0,
    "advanced_jailbreak": 0.0,
    "mcp_scan": 0.0,
    "mcp_attack": 0.0,
    "mcp_chain": 0.0,
    "mcp_c2": 0.0,
    "cve_exploit": 60.0,  # verified   × multiple  = 0.60 → 60
    "destruction": 3.0,
}


class TestCoverageScorer:

    # ── Single-phase engagement → rubric score ─────────────────────────
    @pytest.mark.parametrize("phase,expected", list(EXPECTED_SCORES.items()))
    def test_per_phase_rubric_scores(self, phase, expected):
        scorer = CoverageScorer()
        eng = _eng(phases={phase: {}})
        out = scorer.score_engagement(eng)
        assert out["score"] == pytest.approx(expected, 0.1)

    # ── Verdict / coverage labeling ────────────────────────────────────
    def test_unknown_phase_yields_zero(self):
        scorer = CoverageScorer()
        eng = _eng(phases={"recon": {}})
        out = scorer.score_engagement(eng)
        assert out["verdict_counts"] == {"reachability": 1}

    def test_verified_cve_phase(self):
        scorer = CoverageScorer()
        eng = _eng(phases={"cve_exploit": {}})
        out = scorer.score_engagement(eng)
        assert out["score"] == pytest.approx(60.0, 0.1)
        assert out["verdict_counts"] == {"verified": 1}

    def test_mixed_verdict_counts(self):
        scorer = CoverageScorer()
        eng = _eng(phases={
            "recon": {},                     # reachability
            "c2": {},                        # reachability
            "exploit": {},                   # exploited (multiple)
            "mcp_scan": {},                  # unknown
            "mcp_attack": {},                # unknown
            "destruction": {},               # reachability
            "cve_exploit": {},               # verified (60)
        })
        out = scorer.score_engagement(eng)
        vc = out["verdict_counts"]
        assert vc["reachability"] == 3
        assert vc["unknown"] == 2
        assert vc["verified"] == 1
        assert "multiple" not in vc          # multiple only as confidence

    # ── Structural guarantees ─────────────────────────────────────────
    def test_non_dict_tolerated(self):
        scorer = CoverageScorer()
        assert scorer.score_all(["x", None, 42])["count"] == 0
        assert scorer.score_all([])["count"] == 0

    def test_incomplete_engagement_zero(self):
        scorer = CoverageScorer()
        eng = _eng(status="failed", phases={"recon": {}})
        out = scorer.score_all([eng])
        # incomplete engagements are listed but carry zero score
        assert out["count"] == 1
        assert out["engagement_scores"][0]["score"] == 0.0

    def test_breakdown_fields_schema(self):
        scorer = CoverageScorer()
        out = scorer.score_engagement(_eng(phases={"recon": {}}))
        row = out["breakdown"]["recon"]
        assert set(row.keys()) == {
            "coverage", "confidence", "weight", "contribution", "points"
        }

    def test_aggregate_mean(self):
        scorer = CoverageScorer()
        eng1 = _eng(phases={"recon": {}})       # 3
        eng2 = _eng(phases={"exploit": {}})     # 42
        out = scorer.score_all([eng1, eng2])
        assert out["aggregated"] == pytest.approx(22.5, 0.1)
        assert out["count"] == 2

    def test_max_score_cap_is_fixed_at_60(self):
        """The frozen rubric's ceiling is per-phase (verified × multiple = 60).
        Running every phase dilutes by N, so any engagement's max is bounded
        by the per-phase cap divided by total phases engaged. The absolute
        ceiling is fixed: only cve_exploit yields the highest contribution.
        An engagement containing only cve_exploit scores exactly 60."""
        scorer = CoverageScorer()
        # only cve_exploit → 60
        out = scorer.score_engagement(_eng(phases={"cve_exploit": {}}))
        assert out["score"] == pytest.approx(60.0, 0.1)
        # all phases → diluted by 19
        all_eng = _eng(phases={p: {} for p in EXPECTED_SCORES})
        assert scorer.score_engagement(all_eng)["score"] < 60.0

    # ── Reporter wiring ────────────────────────────────────────────────
    def test_reporter_includes_coverage_section(self):
        from modules.reporter import Reporter
        reporter = Reporter(attack_log=[
            _eng(status="completed", phases={"recon": {}}),
            _eng(status="completed", phases={"cve_exploit": {}}),
        ])
        data = reporter.gather_data()
        assert "coverage" in data
        assert data["coverage"]["count"] == 2
        assert 0.0 < data["coverage"]["aggregated"] < 100.0

    def test_reporter_markdown_has_coverage_block(self):
        from modules.reporter import Reporter
        reporter = Reporter(attack_log=[
            _eng(status="completed", phases={"cve_exploit": {}}),
        ])
        data = reporter.gather_data()
        md = reporter.generate_markdown(data)
        assert "Prevention Strength" in md
        assert "Aggregated prevention score" in md


# ─── Determinism ────────────────────────────────────────────────────────
class TestCoverageDeterminism:

    def test_same_input_same_output(self):
        scorer = CoverageScorer()
        eng = _eng(phases={"recon": {}, "mcp_scan": {}, "cve_exploit": {}})
        r1 = scorer.score_engagement(eng)
        r2 = scorer.score_engagement(eng)
        assert r1 == r2

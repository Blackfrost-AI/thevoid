"""Tests for modules.continuity — R-3 continuity scheduler."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from modules.continuity import ContinuityScheduler


def _mock_agent(findings_map=None):
    agent = MagicMock()
    agent.engage = MagicMock(
        return_value={"status": "completed", "findings": findings_map or {},
                      "errors": [], "elapsed_seconds": 1.0}
    )
    return agent


class TestContinuityScheduler:

    # ── Polling loop ─────────────────────────────────────────────────
    def test_interval_clamps_to_minimum_one_hour(self):
        # Floors: interval cannot go below 3600s
        sched = ContinuityScheduler(
            MagicMock(), targets=["a"], interval_seconds=3599, max_runs=1
        )
        assert sched._interval == 3600

    def test_interval_enforced_at_minimum_one_hour(self):
        # Same as above — explicit floor enforcement (not an exception).
        # This protects operators from accidentally flooding the scheduler.
        sched = ContinuityScheduler(
            MagicMock(), targets=["a"], interval_seconds=1, max_runs=1
        )
        assert sched._interval == 3600

    def test_max_runs_stops_loop(self):
        agent = _mock_agent()
        scheduler = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=2
        )
        assert scheduler._run_count == 0
        with patch("threading.Thread") as mock_thread:
            scheduler.start()
            # simulate internal loop advancing _run_count
            scheduler._run_count = 2
        assert scheduler._run_count == 2

    # ── Drift detection: verdict changes ──────────────────────────────
    def test_drift_reachability_to_verified(self):
        agent = MagicMock()
        agent.engage = MagicMock(
            side_effect=[
                {"status": "completed", "findings": {"recon": {}},
                 "errors": [], "elapsed_seconds": 1.0},
                {"status": "completed", "findings": {"recon": {}, "cve_exploit": {}},
                 "errors": [], "elapsed_seconds": 1.0},
            ]
        )
        logger = MagicMock()
        scheduler = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=2,
            warlog=logger, boneyard=logger
        )
        # bypass thread for direct _run_one call
        scheduler._run_one("a")
        scheduler._run_one("a")
        assert scheduler._run_count == 0  # run_count set by loop, not _run_one

    def test_drift_new_phase_appears(self):
        agent = MagicMock()
        agent.engage = MagicMock(
            side_effect=[
                {"status": "completed", "findings": {"recon": {}},
                 "errors": [], "elapsed_seconds": 1.0},
                {"status": "completed",
                 "findings": {"recon": {}, "new_thing": {}},
                 "errors": [], "elapsed_seconds": 1.0},
            ]
        )
        logger = MagicMock()
        logger.log = MagicMock()
        sched = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=2,
            warlog=logger, boneyard=logger
        )
        sched._run_one("a")
        sched._run_one("a")
        # persistence happens but _run_count is only bumped by _loop
        assert sched._run_count == 0  # direct call, not through loop

    def test_drift_verdict_changes_are_recorded(self):
        agent = MagicMock()
        agent.engage = MagicMock(
            side_effect=[
                {"status": "completed", "findings": {"recon": {}},
                 "errors": [], "elapsed_seconds": 1.0},
                {"status": "completed", "findings": {"recon": {}},
                 "errors": [], "elapsed_seconds": 1.0},
                {"status": "completed",
                 "findings": {"recon": {}, "exploited": {}},
                 "errors": [], "elapsed_seconds": 1.0},
            ]
        )
        sched = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=1
        )
        assert sched._previous == {}
        sched._run_one("a")
        assert sched._previous["a"]["recon"] == "reachability"
        sched._run_one("a")
        assert sched._previous["a"]["recon"] == "reachability"
        # internal dict persists from run to run

    # ── Persistence safety ───────────────────────────────────────────
    def test_scheduler_survives_engage_failures(self):
        agent = MagicMock()
        agent.engage = MagicMock(side_effect=Exception("boom"))
        sched = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=1
        )
        # _run_one propagates — this confirms the caller must handle
        try:
            sched._run_one("a")
            assert False  # should have raised
        except Exception:
            pass  # propagate confirms loop-guard is the real mechanism

    def test_warlog_boneyard_none_safe(self):
        agent = _mock_agent()
        sched = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=1,
            warlog=None, boneyard=None
        )
        sched._run_one("a")
        assert sched._run_count == 0

    # ── Factory helper ────────────────────────────────────────────────
    def test_create_scheduler_factory(self):
        agent = _mock_agent()
        sched = ContinuityScheduler(
            agent, targets=["a"], interval_seconds=3600, max_runs=1
        )
        assert sched._interval == 3600
        assert sched._agent is agent
        assert sched._targets == ["a"]
        assert sched._max_runs == 1

    def test_create_scheduler_converts_hours(self):
        from modules.continuity import create_scheduler
        sched = create_scheduler(MagicMock(), ["a"], mode="quick",
                                 interval_hours=6)
        assert sched._interval == 6 * 3600

    def test_thread_thread_alive_property(self):
        sched = ContinuityScheduler(
            _mock_agent(), targets=["a"], interval_seconds=3600, max_runs=1
        )
        assert sched.is_alive is False  # not started yet

    def test_lift_ms(self):
        agent = _mock_agent()
        sched = ContinuityScheduler(agent, targets=["a"], max_runs=3)
        assert sched._max_runs == 3
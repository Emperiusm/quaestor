"""Controls for the outcome ledger: is the native-handoff success rate MEASURED correctly?

The live baseline this instrument exists to move: 24/32 valid on the 2026-08-24
LOCAL_GOVERNED program, 8 children answering in prose, target >99% native schema-validated.
A summary that miscounts hides exactly the regression it was built to expose, so every bucket
below is asserted against rows seeded to mimic the real worker-written shapes
(worker.record_result / record_handoff), not against the summariser's own output.
"""
from __future__ import annotations

import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import domain
from quaestor.core.executor_contract import (HANDOFF_STRENGTH_DEGRADED,  # noqa: E402
                       HANDOFF_STRENGTH_NATIVE, HANDOFF_STRENGTH_WEAK)
from quaestor.core.handoff import RESULT_INVALID, VALID  # noqa: E402
from quaestor.core.store import Store  # noqa: E402
from quaestor.transports import cli  # noqa: E402

_NOW = 1000.0


class _SeededHome:
    """A temp dir with an orchestrator store whose rows mimic the real shapes."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-outcomes-")
        self.db = os.path.join(self.dir, "orchestrator.sqlite3")
        self.store = Store(self.db)

    def close(self):
        self.store.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def run(self, run_id, *, workflow_id="wf-standalone", valid=False,
            outcome=RESULT_INVALID, reason="", package=None):
        """One dispatch + attempt + result (+ handoff) chain, as the worker would leave it."""
        key = "%s:%s" % (workflow_id, run_id)
        c = self.store.conn
        c.execute("INSERT OR IGNORE INTO workflow(workflow_id, title, created_at) VALUES(?,?,?)",
                  (workflow_id, "", _NOW))
        c.execute(
            "INSERT OR IGNORE INTO dispatch(dispatch_key, workflow_id, step_id, prompt_sha256,"
            " repo_id, worktree_path, expected_branch, expected_head, authority_profile,"
            " capabilities_json, identity_json, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, workflow_id, run_id, "p" * 64, "repo", "C:/wt", "main", "a" * 64,
             "READ_ONLY", "[]", "{}", _NOW))
        state = domain.HANDOFF_READY if valid else domain.RESULT_INVALID
        c.execute(
            "INSERT INTO attempt(run_id, dispatch_key, attempt_no, run_nonce, execution_state,"
            " is_write, run_dir, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, key, 1, "nonce", state, 0, "C:/runs/" + run_id, _NOW, _NOW))
        h = dict(package or {})
        c.execute(
            "INSERT INTO result(run_id, received_at, raw_sha256, valid, outcome, invalid_reason,"
            " handoff_json) VALUES(?,?,?,?,?,?,?)",
            (run_id, _NOW, "r" * 64, 1 if valid else 0, outcome, reason or None,
             json.dumps(h) if h else None))
        if valid and package is not None:
            c.execute("INSERT INTO handoff(run_id, ready_at, handoff_json) VALUES(?,?,?)",
                      (run_id, _NOW, json.dumps(package)))


def _package(strength: str) -> dict:
    """A trimmed build_handoff_package shape -- the keys outcome_summary actually reads."""
    return {"protocol": "QUAESTOR_HANDOFF_V1", "run_id": "x", "handoff_strength": strength,
            "claude_report": {}, "bridge_evidence": {}}


class OutcomeSummaryTests(unittest.TestCase):
    def setUp(self):
        self.h = _SeededHome()

    def tearDown(self):
        self.h.close()

    def test_empty_db_yields_the_zeroed_shape_without_raising(self):
        for pid in (None, "no-such-program"):
            s = self.h.store.outcome_summary(pid)
            self.assertEqual(s["runs_with_result"], 0)
            self.assertEqual(s["valid"], 0)
            self.assertEqual(s["invalid"], 0)
            self.assertEqual(s["native_rate"], 0.0)
            self.assertEqual(s["failure_classes"], {})
            self.assertEqual(set(s["strength"]), {HANDOFF_STRENGTH_NATIVE,
                                                  HANDOFF_STRENGTH_DEGRADED,
                                                  HANDOFF_STRENGTH_WEAK})
            self.assertEqual(sum(s["strength"].values()), 0)

    def test_mixed_outcomes_are_counted_and_program_scoped(self):
        h = self.h
        # Program prog-1: three valid at three strengths, one invalid per class.
        h.run("r-native", workflow_id="prog-1", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_NATIVE))
        h.run("r-exact", workflow_id="prog-1", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_DEGRADED))
        h.run("r-fenced", workflow_id="prog-1-review", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_WEAK))
        h.run("r-prose", workflow_id="prog-1",
              reason="[PROSE_ONLY_RESULT] no structured handoff in the result envelope")
        h.run("r-schema", workflow_id="prog-1",
              reason="[SCHEMA_VALIDATION_FAILED] summary is empty")
        # A second program, plus two traps for a naive starts-with filter.
        h.run("other-native", workflow_id="prog-2", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_NATIVE))
        h.run("prefix-trap", workflow_id="prog-11", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_NATIVE))
        h.run("suffix-trap", workflow_id="xprog-1", valid=True, outcome=VALID,
              package=_package(HANDOFF_STRENGTH_NATIVE))

        whole = h.store.outcome_summary()
        self.assertEqual(whole["runs_with_result"], 8)
        self.assertEqual(whole["valid"], 6)
        self.assertEqual(whole["invalid"], 2)
        self.assertEqual(whole["strength"][HANDOFF_STRENGTH_NATIVE], 4)
        self.assertEqual(whole["strength"][HANDOFF_STRENGTH_DEGRADED], 1)
        self.assertEqual(whole["strength"][HANDOFF_STRENGTH_WEAK], 1)
        self.assertEqual(whole["failure_classes"],
                         {"PROSE_ONLY_RESULT": 1, "SCHEMA_VALIDATION_FAILED": 1})
        self.assertEqual(whole["native_rate"], round(4 / 6, 4))

        p1 = h.store.outcome_summary("prog-1")
        self.assertEqual(p1["runs_with_result"], 5)   # prefix-trap and suffix-trap excluded
        self.assertEqual(p1["valid"], 3)
        self.assertEqual(p1["invalid"], 2)
        self.assertEqual(p1["strength"][HANDOFF_STRENGTH_NATIVE], 1)
        self.assertEqual(p1["native_rate"], round(1 / 3, 4))
        self.assertEqual(p1["failure_classes"]["PROSE_ONLY_RESULT"], 1)

    def test_strength_is_read_from_the_handoff_package_json_not_invented(self):
        h = self.h
        h.run("r1", valid=True, outcome=VALID, package=_package(HANDOFF_STRENGTH_DEGRADED))
        got = h.store.outcome_summary()["strength"]
        self.assertEqual(got[HANDOFF_STRENGTH_DEGRADED], 1)
        self.assertEqual(got[HANDOFF_STRENGTH_NATIVE], 0)

    def test_valid_run_without_a_handoff_package_counts_valid_but_never_native(self):
        h = self.h
        h.run("r1", valid=True, outcome=VALID)  # result row only: no handoff row written
        s = h.store.outcome_summary()
        self.assertEqual((s["runs_with_result"], s["valid"], s["invalid"]), (1, 1, 0))
        self.assertEqual(sum(s["strength"].values()), 0)
        self.assertEqual(s["native_rate"], 0.0)

    def test_unprefixed_legacy_reasons_are_not_laundered_into_a_class(self):
        h = self.h
        h.run("r1", reason="some pre-quaestor-4ci prose failure")
        s = h.store.outcome_summary()
        self.assertEqual(s["invalid"], 1)
        self.assertEqual(s["failure_classes"], {})

    def test_a_corrupt_package_never_raises_and_still_counts_the_run(self):
        c = self.h.store.conn
        self.h.run("r1", valid=True, outcome=VALID, package=_package(HANDOFF_STRENGTH_NATIVE))
        c.execute("UPDATE handoff SET handoff_json='{not json' WHERE run_id='r1'")
        s = self.h.store.outcome_summary()
        self.assertEqual(s["valid"], 1)
        self.assertEqual(sum(s["strength"].values()), 0)
        self.assertEqual(s["native_rate"], 0.0)


class WiringTests(unittest.TestCase):
    """The surfaces are wired by calling the underlying helpers directly -- no server."""

    def setUp(self):
        self.h = _SeededHome()
        self.home = self.h.dir
        self.h.run("r1", workflow_id="prog-9", valid=True, outcome=VALID,
                   package=_package(HANDOFF_STRENGTH_NATIVE))
        self.h.run("r2", workflow_id="prog-9", reason="[PROSE_ONLY_RESULT] prose only")

    def tearDown(self):
        self.h.close()

    def test_read_outcome_summary_matches_the_store_for_home_and_program(self):
        whole = cli.read_outcome_summary(self.home)
        self.assertEqual(whole["runs_with_result"], 2)
        self.assertEqual(whole["native_rate"], 1.0)
        scoped = cli.read_outcome_summary(self.home, "prog-9")
        self.assertEqual(scoped, self.h.store.outcome_summary("prog-9"))
        self.assertEqual(scoped["invalid"], 1)
        self.assertEqual(scoped["failure_classes"], {"PROSE_ONLY_RESULT": 1})

    def test_doctor_emits_handoff_health_and_status_json_emits_outcome_summary(self):
        doctor_src = inspect.getsource(cli.cmd_doctor)
        self.assertIn('"handoff_health"', doctor_src)
        status_src = inspect.getsource(cli.cmd_program_status)
        self.assertIn('read_outcome_summary(a.home, a.program_id)', status_src)
        self.assertIn('"outcome_summary"', status_src)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

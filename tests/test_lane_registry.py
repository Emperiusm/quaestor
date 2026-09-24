"""test_lane_registry -- CONTROLS on reap()'s lane-handler registry (§18).

THE LIVE DEFECT THESE CONTROLS PREVENT
---------------------------------------
Found LIVE: a newly added lane kind fell through reap()'s if/elif role chain into the
catch-all "NOTED" branch. The run was marked processed, but nothing ever advanced its lane:
the lane stayed ACTIVE, so schedule() re-dispatched it on EVERY tick -- each dispatch a real,
paid executor invocation -- and every tick looked like ordinary progress. Two gaps allowed
that, and each now has a machine-enforced control:

  * COVERAGE (TestRegistryCoverage). Nothing forced set(LANE_HANDLERS) == set(LANE_KINDS),
    so a kind could exist without a handler. The orchestrator now enforces this at IMPORT
    time via verify_lane_registry(); these tests pin the shipped registry AND include a
    NEGATIVE CONTROL proving the gate actually fires when a kind is added without one.

  * TERMINAL REACHABILITY (TestHandlersDeclareTerminal +
    TestReportOnlyKindsReachTerminal). A handler-shaped branch that merely consumes runs
    drives no lane anywhere. Every handler must DECLARE terminal reachability adjacent to
    the registry (HANDLER_REACHES_TERMINAL), and the report-only kinds must DEMONSTRATE it
    end to end: a fake-executor program per kind drives its lane to programs.LANE_COMPLETE
    with EXACTLY ONE durable run -- one run total, not one per tick, which is the defect's
    own signature -- and the program must go terminal.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
import unittest.mock as mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import orchestrator as orch          # noqa: E402
from quaestor.core import programs as programs_mod      # noqa: E402
from tests.test_operational_e2e import EngineHarness    # noqa: E402


class TestRegistryCoverage(unittest.TestCase):
    """CONTROL (invariant a): the handler registry is TOTAL over the declared kinds."""

    def test_registry_covers_exactly_the_declared_kinds(self):
        """set(LANE_HANDLERS) == set(LANE_KINDS): a kind added without a handler fails here
        -- and at orchestrator import time -- instead of failing live, forever."""
        self.assertEqual(set(orch.LANE_HANDLERS), set(orch.LANE_KINDS))

    def test_import_time_gate_accepts_the_shipped_registry(self):
        self.assertIsNone(orch.verify_lane_registry())

    def test_adding_a_kind_without_a_handler_makes_the_gate_fire(self):
        """NEGATIVE CONTROL: prove the coverage gate can actually fire.

        Extending LANE_KINDS with a hypothetical future kind (security_review, §18) while
        leaving LANE_HANDLERS alone must (a) break the bare invariant this suite exists to
        enforce and (b) make verify_lane_registry() raise ValueError NAMING the uncovered
        kind. Without this control, a refactor that silently disconnected the gate would
        still pass every positive test above it -- the alarm must be tested too.
        """
        bogus = "security_review"
        self.assertNotIn(bogus, orch.LANE_KINDS)      # precondition: not shipped yet
        widened = tuple(orch.LANE_KINDS) + (bogus,)
        with mock.patch.object(orch, "LANE_KINDS", widened):
            self.assertNotEqual(set(orch.LANE_HANDLERS), set(orch.LANE_KINDS))
            with self.assertRaises(ValueError) as caught:
                orch.verify_lane_registry()
            self.assertIn(bogus, str(caught.exception))


class TestHandlersDeclareTerminal(unittest.TestCase):
    """CONTROL (invariant b, declarative half): every kind declares terminal reachability."""

    def test_terminal_declaration_covers_every_kind_and_is_true(self):
        self.assertEqual(set(orch.HANDLER_REACHES_TERMINAL), set(orch.LANE_KINDS))
        for kind in orch.LANE_KINDS:
            self.assertIs(orch.HANDLER_REACHES_TERMINAL[kind], True,
                          "%s must declare terminal reachability" % kind)


class TestReportOnlyKindsReachTerminal(unittest.TestCase):
    """CONTROL (invariant b, behavioral half): the declarations are TRUE, demonstrated end
    to end through the real scheduler/reap seams with the fake executor.

    The live F2 defect lived exactly here: verification lanes had handler-SHAPED handling
    that never completed. Each report-only kind therefore proves, through EngineHarness's
    full dispatch->worker->reap loop, that its lane reaches COMPLETE and stops consuming
    executors.
    """

    def test_each_report_only_kind_completes_its_lane_and_its_program(self):
        for kind in (orch.KIND_RESEARCH, orch.KIND_VERIFICATION, orch.KIND_INTEGRATION):
            with self.subTest(kind=kind):
                self.assertIs(orch.HANDLER_REACHES_TERMINAL[kind], True)
                h = EngineHarness()
                self.addCleanup(h.close)
                pid, lanes = h.new_program(
                    "registry: %s reaches terminal" % kind,
                    "one %s lane must complete instead of redispatching forever" % kind,
                    [{"key": "lane", "title": str(kind), "kind": kind,
                      "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
                      "acceptance": ()}],
                    policy=orch.ProgramPolicy(require_adversarial=False))
                last = h.drive(pid, max_ticks=8)
                self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                                 json.dumps(last, default=str))
                lane = h.sstore.get_lane(lanes["lane"])
                self.assertEqual(lane.state, programs_mod.LANE_COMPLETE)
                self.assertTrue(lane.terminal)
                # THE DEFECT'S SIGNATURE: exactly ONE durable run. The unterminated-lane bug
                # left the lane schedulable, producing one fresh paid run PER TICK instead.
                self.assertEqual(len(h.sstore.runs_for_lane(lanes["lane"])), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""test_soak_qualification -- bd quaestor-6e9: the long-run soak + takeover qualification bar.

WHAT THIS QUALIFIES (direction section 14: long-running automation must survive strategist
replacement, worker death and restart from CANONICAL STATE ALONE -- never from a live session)
------------------------------------------------------------------------------------------------
Three qualifications extend tests/test_operational_e2e.TestTakeoverAndSoak without weakening it:

  * SOAK: an ELEVEN-lane program -- two implementation chains joined by REQUIRES dependencies,
    a docs lane, a research lane, a terminal verification lane, one lane scripted to emit
    DECISION_REQUEST and resume after the answer, and one lane whose first run WORKER_CRASHes
    through the REAL detached-worker path -- driven to CANDIDATE_PASS with >=60 durable
    transitions (RUN_BOUND + LANE_STATE_CHANGED + SCHEDULED + CHECKPOINT_SAVED) whose event log
    alone reconstructs every lane's final state.
  * TAKEOVER MID-FIX-CYCLE: session A stops the moment an adversarial finding has scheduled a
    fix attempt (the fix run already bound but unconsumed); brand-new StrategicStore/Store
    objects -- a new strategist session with no transcript and no memory -- must see a
    non-vacuous status view, a usable handoff bundle, answer the still-unanswered
    DECISION_REQUEST, consume the pending fix, and drive the program to PASS.
  * COMPOSITION: crash recovery happens INSIDE the very soak program that is taken over
    mid-flight, so the three survival mechanisms compose instead of passing in isolation.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import domain                                  # noqa: E402
from quaestor.core import events as ev_mod                        # noqa: E402
from quaestor.core import orchestrator as orch                    # noqa: E402
from quaestor.core import programs as programs_mod                # noqa: E402
from quaestor.core import runfiles as rf_mod                      # noqa: E402
from quaestor.core import strategic_store as ss_mod               # noqa: E402
from quaestor.core import store as store_mod                      # noqa: E402
from tests.test_operational_e2e import (EngineHarness,            # noqa: E402
                                        TERMINAL_STATUSES,
                                        fake_preflight,
                                        in_process_spawner,
                                        read_file,
                                        subprocess_spawner)

TRANSITION_TYPES = ("RUN_BOUND", "LANE_STATE_CHANGED", "SCHEDULED", "CHECKPOINT_SAVED")
SOAK_TRANSITION_FLOOR = 60


def crash_aware_spawner(runs_root):
    """Route ONLY the self-killing WORKER_CRASH run through a real child process.

    A WORKER_CRASH scenario hard-exits its own process (os._exit), which in-process would take
    the test process with it; everything else stays in-process so an 11-lane soak keeps its
    runtime budget. The decision reads the run's own request artifact -- the same seam the
    dispatcher's real-child concurrency gate uses -- never a side channel.
    """
    def spawner(*, db_path, run_id):
        req = rf_mod.read_json(rf_mod.p(rf_mod.run_dir(runs_root, run_id), rf_mod.REQUEST))
        cfg = ((req.get("executor") or {}).get("config")) or {}
        if str(cfg.get("scenario") or "") == "WORKER_CRASH":
            return subprocess_spawner(db_path=db_path, run_id=run_id)
        return in_process_spawner(db_path=db_path, run_id=run_id)
    return spawner


def event_counts(events):
    counts = {}
    for e in events:
        counts[e["event_type"]] = counts.get(e["event_type"], 0) + 1
    return counts


def lane_state_transitions(events, lane_id):
    """The lane's LANE_STATE_CHANGED sequence as (from, to) pairs, oldest first."""
    seq = []
    for e in events:
        if e["event_type"] == ev_mod.LANE_STATE_CHANGED and e["lane_id"] == lane_id:
            d = json.loads(e["detail_json"] or "{}")
            seq.append((str(d.get("from")), str(d.get("to"))))
    return seq


class TestSoakQualification(unittest.TestCase):
    def test_soak_eleven_lanes_survives_crash_and_strategist_replacement(self):
        """CONTROL (quaestor-6e9; direction section 14): a long-running program drives 11 lanes
        to terminal across a worker death AND a full strategist replacement, leaves no
        unprocessed work and no waiting lane, accumulates >=60 durable transitions, and its
        event log alone reconstructs every lane's final state."""
        h = EngineHarness()
        self.addCleanup(h.close)

        def writer(name):
            return {"kind": "fake", "config": {
                "scenario": "OK_PASS",
                "write_files": {"mod_%s.py" % name: "VALUE_%s = %d\n" % (name.upper(),
                                                                         len(name))},
                "claimed_files": ["mod_%s.py" % name]}}

        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Config ownership: which module owns defaults?"}]}}
        crash = {"kind": "fake", "config": {"scenario": "WORKER_CRASH"}}
        specs = [
            {"key": "alpha", "title": "impl-alpha", "executor": writer("alpha"),
             "acceptance": ("alpha written",)},
            {"key": "beta", "title": "impl-beta", "depends_on": ("alpha",),
             "executor": writer("beta"), "acceptance": ("beta written",)},
            {"key": "gamma", "title": "impl-gamma", "depends_on": ("beta",),
             "executor": writer("gamma"), "acceptance": ("gamma written",)},
            {"key": "delta", "title": "impl-delta", "executor": writer("delta"),
             "acceptance": ("delta written",)},
            {"key": "epsilon", "title": "impl-epsilon", "depends_on": ("delta",),
             "executor": writer("epsilon"), "acceptance": ("epsilon written",)},
            {"key": "zeta", "title": "impl-zeta", "depends_on": ("gamma", "epsilon"),
             "executor": writer("zeta"), "acceptance": ("zeta written",)},
            {"key": "docs", "title": "docs-lane", "executor": {"kind": "fake", "config": {
                "scenario": "OK_PASS",
                "write_files": {"README.md": "# modules\nalpha beta gamma delta epsilon "
                                             "zeta asker crasher\n"},
                "claimed_files": ["README.md"]}},
             "acceptance": ("docs written",)},
            {"key": "asker", "title": "ask-then-write",
             "executor": {"kind": "fake", "attempt_variants": [ask, writer("asker")]},
             "acceptance": ("asker written",)},
            {"key": "crasher", "title": "crash-then-write",
             "executor": {"kind": "fake", "attempt_variants": [crash, writer("crasher")]},
             "acceptance": ("crasher written",)},
            {"key": "survey", "title": "research-survey", "kind": orch.KIND_RESEARCH,
             "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
             "acceptance": ()},
            {"key": "final_check", "title": "verify-all", "kind": orch.KIND_VERIFICATION,
             "depends_on": ("zeta", "asker", "crasher"),
             "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
             "acceptance": ()},
        ]
        pid, lanes = h.new_program(
            "soak qualification",
            "eleven lanes: chains, docs, research, ask, crash, terminal verification", specs,
            policy=orch.ProgramPolicy(max_concurrent_executors=4, require_adversarial=False))
        spawner = crash_aware_spawner(os.path.join(h.home, "runs"))

        def takeover_ready(report):
            asked = any(i["kind"] == "DECISION_REQUEST"
                        for i in orch.inbox(h.sstore, pid)["items"])
            recovered = any(
                e["event_type"] == ev_mod.RECONCILIATION_CLASSIFIED
                and json.loads(e["detail_json"] or "{}").get("classification")
                == "DEAD_WORKER_CLEAN_TREE"
                for e in h.sstore.events(program_id=pid))
            return asked and recovered

        last = {}
        for _ in range(40):
            last = h.tick(pid, spawner=spawner)
            if takeover_ready(last):
                break
        self.assertTrue(takeover_ready(last), json.dumps(last, default=str))

        h.sstore.close()
        h.store.close()
        h.sstore = ss_mod.StrategicStore(ss_mod.strategic_path(h.home))
        h.store = store_mod.Store(os.path.join(h.home, "orchestrator.sqlite3"))
        view = orch.status_view(h.sstore, h.store, pid)
        self.assertFalse(view["vacuous"])
        self.assertEqual(view["status"], orch.PROGRAM_WAITING_STRATEGIST)
        bundle = h.sstore.handoff_bundle(pid)
        self.assertFalse(bundle["vacuous"])
        self.assertEqual(bundle["next_authority"], "STRATEGIST")
        self.assertTrue(bundle["inspected"]["events"] > 0)
        asks = [i for i in orch.inbox(h.sstore, pid)["items"]
                if i["kind"] == "DECISION_REQUEST"]
        self.assertEqual(len(asks), 1)
        orch.answer(h.sstore, pid, asks[0]["message_id"],
                    decision_text="defaults live in mod_asker",
                    rationale="single owner per concern", actor_id="strategist-B")

        last = h.drive(pid, max_ticks=40, spawner=spawner)
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last.get("integration"), default=str))

        lane_rows = h.sstore.lanes(pid)
        self.assertEqual(len(lane_rows), 11)
        for l in lane_rows:
            self.assertEqual(l.state, programs_mod.LANE_COMPLETE, l.title)
            self.assertEqual(l.verdict, programs_mod.PASS, l.title)
            self.assertNotIn(l.state, programs_mod.WAITING_STATES)

        events = h.sstore.events(program_id=pid)
        counts = event_counts(events)
        total = sum(counts.get(t, 0) for t in TRANSITION_TYPES)
        self.assertGreaterEqual(total, SOAK_TRANSITION_FLOOR, json.dumps(counts))

        total_runs = 0
        for l in lane_rows:
            bindings = h.sstore.runs_for_lane(l.lane_id)
            total_runs += len(bindings)
            self.assertTrue(all(b["processed"] for b in bindings),
                            "unprocessed run on %s" % l.title)
            rb = sum(1 for e in events if e["event_type"] == ev_mod.RUN_BOUND
                     and e["lane_id"] == l.lane_id)
            sch = sum(1 for e in events if e["event_type"] == ev_mod.SCHEDULED
                      and e["lane_id"] == l.lane_id)
            ck = sum(1 for e in events if e["event_type"] == ev_mod.CHECKPOINT_SAVED
                     and e["lane_id"] == l.lane_id)
            self.assertEqual(rb, len(bindings),
                             "every durable run needs its RUN_BOUND (%s)" % l.title)
            self.assertGreaterEqual(sch, rb, l.title)
            self.assertGreaterEqual(ck, 1, l.title)
            seq = lane_state_transitions(events, l.lane_id)
            self.assertTrue(seq, "no state transitions recorded for %s" % l.title)
            self.assertEqual(seq[0][0], programs_mod.LANE_PLANNED, l.title)
            for i in range(1, len(seq)):
                self.assertEqual(seq[i][0], seq[i - 1][1],
                                 "broken transition chain on %s" % l.title)
            self.assertEqual(seq[-1][1], programs_mod.LANE_COMPLETE, l.title)
            self.assertEqual(seq[-1][1], l.state,
                             "final state not derivable from events (%s)" % l.title)
        self.assertGreaterEqual(total_runs, len(lane_rows))

        crash_states = [h.store.get_run(b["run_id"])["execution_state"]
                        for b in h.sstore.runs_for_lane(lanes["crasher"])]
        self.assertIn(domain.WORKER_FAILED, crash_states)
        self.assertIn(domain.HANDOFF_READY, crash_states)
        self.assertTrue(any(
            e["event_type"] == ev_mod.RECONCILIATION_CLASSIFIED
            and json.loads(e["detail_json"] or "{}").get("classification")
            == "DEAD_WORKER_CLEAN_TREE" for e in events))

        decs = h.sstore.decisions(pid)
        self.assertTrue(any(d.decision == "defaults live in mod_asker" for d in decs))
        integ = h.sstore.get_integration_state(pid)
        self.assertEqual(integ["state"], "COMPLETE")
        self.assertGreaterEqual(len(integ["detail"]["merged"]), 9)
        leftovers = [i["kind"] for i in orch.inbox(h.sstore, pid)["items"]]
        self.assertFalse([k for k in leftovers if k in ("DECISION_REQUEST", "BLOCKER")],
                         leftovers)

    def test_session_b_takes_over_mid_fix_cycle_from_canonical_state_alone(self):
        """CONTROL (quaestor-6e9; direction section 14): session A stops mid-fix-cycle -- a
        reviewer finding has scheduled fix attempt 1 and that attempt has paused on an
        UNANSWERED DECISION_REQUEST. A brand-new strategist session (new stores, no transcript,
        no memory) must resume from canonical rows alone: see the pending fix and the open
        question, answer it, land the fix through re-review, and reach PASS."""
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        tests = read_file(os.path.join(h.repo, "test_mathlib.py"))
        buggy = app + "\n\ndef mul(a, b):\n    return a + b   # subtle defect\n"
        fixed = app + "\n\ndef mul(a, b):\n    return a * b\n"
        new_tests = tests + ("\nimport unittest\nfrom app import mathlib\n\n"
                             "class MulTest(unittest.TestCase):\n"
                             "    def test_mul(self):\n"
                             "        self.assertEqual(mathlib.mul(3, 4), 12)\n")
        attempt0 = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py": buggy, "test_mathlib.py": new_tests},
            "claimed_files": ["app/mathlib.py", "test_mathlib.py"]}}
        attempt_fix = {"kind": "fake", "config": {
            "scenario": "OK_PASS", "write_files": {"app/mathlib.py": fixed},
            "claimed_files": ["app/mathlib.py"]}}
        finding_review = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "REVIEW_FINDING", "payload": "mul adds instead of multiplying",
             "severity": "HIGH",
             "detail": {"location": "app/mathlib.py",
                        "failure_mode": "returns a+b"}}]}}
        ok_review = {"kind": "fake", "config": {"scenario": "OK_PASS"}}
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Fix direction: multiply via operator or bitwise trick?"}]}}
        docs_v1 = {"kind": "fake", "config": {
            "scenario": "OK_PASS", "write_files": {"NOTES.md": "v1\n"},
            "claimed_files": ["NOTES.md"]}}
        docs_v2 = {"kind": "fake", "config": {
            "scenario": "OK_PASS", "write_files": {"NOTES.md": "v2\n"},
            "claimed_files": ["NOTES.md"]}}
        pid, lanes = h.new_program(
            "mid-fix-cycle takeover", "implement mul correctly after clarifying the fix",
            [{"key": "main", "title": "impl-mul",
              "executor": {"kind": "fake",
                           "attempt_variants": [attempt0, ask, attempt_fix]},
              "acceptance": ("mul works",)},
             {"key": "notes", "title": "impl-notes",
              "executor": {"kind": "fake",
                           "attempt_variants": [docs_v1, docs_v2]},
              "acceptance": ("notes written",)}],
            extra_meta={"review_executor": json.dumps(
                {"attempt_variants": [finding_review, ok_review]})})

        h.tick(pid)
        h.tick(pid)
        h.tick(pid)

        task = h.sstore.get_lane_task(lanes["main"])
        self.assertEqual(task["attempt"], 1, "a fix attempt must have been scheduled")
        fix_events = [e for e in h.sstore.events(program_id=pid, lane_id=lanes["main"])
                      if e["event_type"] == ev_mod.FIX_LANE_CREATED]
        self.assertTrue(fix_events, "FIX_LANE_CREATED must be in the durable record")
        main_bindings = h.sstore.runs_for_lane(lanes["main"])
        unprocessed = [b for b in main_bindings if not b["processed"]]
        self.assertEqual(len(unprocessed), 1, json.dumps(main_bindings, default=str))
        self.assertEqual(unprocessed[0]["role"], "implementation")
        ib = orch.inbox(h.sstore, pid)
        asks_a = [i for i in ib["items"] if i["kind"] == "DECISION_REQUEST"]
        self.assertEqual(len(asks_a), 1)
        mid = asks_a[0]["message_id"]

        h.sstore.close()
        h.store.close()
        sstore_b = ss_mod.StrategicStore(ss_mod.strategic_path(h.home))
        store_b = store_mod.Store(os.path.join(h.home, "orchestrator.sqlite3"))
        try:
            view = orch.status_view(sstore_b, store_b, pid)
            self.assertFalse(view["vacuous"])
            self.assertEqual(view["status"], orch.PROGRAM_WAITING_STRATEGIST)
            rows = {r["title"]: r for r in view["lanes"]}
            self.assertEqual(len(rows), 2)
            self.assertGreaterEqual(rows["impl-mul"]["attempt"], 1)

            bundle = sstore_b.handoff_bundle(pid)
            self.assertFalse(bundle["vacuous"])
            self.assertEqual(bundle["next_authority"], "STRATEGIST")
            self.assertGreaterEqual(bundle["inspected"]["events"], 1)
            self.assertEqual(len(bundle["lanes"]), 2)
            self.assertEqual(len(bundle["open_questions"]), 1)
            self.assertEqual(bundle["open_questions"][0]["message_type"], "DECISION_REQUEST")

            orch.answer(sstore_b, pid, mid, decision_text="use the multiplication operator",
                        rationale="simplest correct semantics", actor_id="strategist-B")
            self.assertTrue(sstore_b.message(mid).get("answered_by"))

            last = {}
            for _ in range(16):
                last = orch.tick(h.home, sstore_b, store_b, program_id=pid, cfg=h.cfg,
                                 preflight=fake_preflight, spawner=in_process_spawner)
                if last["status_out"] in TERMINAL_STATUSES:
                    break
            self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                             json.dumps(last.get("integration"), default=str))
            for lane_id in (lanes["main"], lanes["notes"]):
                lane = sstore_b.get_lane(lane_id)
                self.assertEqual(lane.state, programs_mod.LANE_COMPLETE, lane.title)
                self.assertTrue(all(b["processed"]
                                    for b in sstore_b.runs_for_lane(lane_id)))
            impl_runs = [b for b in sstore_b.runs_for_lane(lanes["main"])
                         if b["role"] == "implementation"]
            self.assertEqual(len(impl_runs), 3,
                             "attempt 0 + the paused fix attempt + the post-answer landing")
            reviews = sstore_b.reviews_for(pid)
            self.assertGreaterEqual(len(reviews), 4)
            self.assertTrue(any(d.decision == "use the multiplication operator"
                                and d.actor_id == "strategist-B"
                                for d in sstore_b.decisions(pid)))
            integ = sstore_b.get_integration_state(pid)
            self.assertEqual(integ["state"], "COMPLETE")
            with open(os.path.join(integ["workspace_path"], "app", "mathlib.py"),
                      encoding="utf-8") as fh:
                self.assertIn("return a * b", fh.read())
        finally:
            sstore_b.close()
            store_b.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

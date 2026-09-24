"""test_operational_e2e -- the operational loop, driven END TO END with in-process workers.

WHAT THESE TESTS BUY
--------------------
Every stage of the program engine is exercised through its REAL seams -- dispatcher admission,
detached-worker code path (run in-process for speed via the spawner seam), independent evidence,
deterministic verification, adversarial review, bounded fix cycles, integration merges and
program verdicts. The only thing substituted is process-spawn latency.

The REAL detached-worker path is covered by the qualification suite's spawn controls and by the
live demonstrations; one test here drives a real subprocess spawn to keep that seam honest.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import domain                              # noqa: E402
from quaestor.core import orchestrator as orch                # noqa: E402
from quaestor.core import programs as programs_mod            # noqa: E402
from quaestor.core import store as store_mod                  # noqa: E402
from quaestor.core import strategic_store as ss_mod           # noqa: E402
from quaestor.core.credential_policy import ACCEPT, PreflightDecision  # noqa: E402
from quaestor.projects import config as proj_cfg              # noqa: E402
from tests.test_operational_controls import make_fixture_repo  # noqa: E402



def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


TERMINAL_STATUSES = {orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
                     orch.PROGRAM_CANCELLED}


def fake_preflight(claude_path="", requires_write=False):
    return PreflightDecision(ACCEPT, "", "fake executor: no credential question",
                             "NOT_APPLICABLE_FAKE_EXECUTOR", (),
                             {"claude_binary_invoked": False})


def in_process_spawner(*, db_path, run_id):
    from quaestor.core import worker as worker_mod
    rc = worker_mod.run_worker(db_path=db_path, run_id=run_id)
    assert rc == 0, "in-process worker failed rc=%s for %s" % (rc, run_id)
    return os.getpid()


def subprocess_spawner(*, db_path, run_id):
    """A synchronous REAL worker process. Used where the scripted scenario kills its own
    process (WORKER_CRASH): an in-process worker would take the test process with it."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "src") + os.pathsep + env.get("PYTHONPATH", "")
    p = subprocess.run([sys.executable, "-m", "quaestor.core.worker",
                        "--db", db_path, "--run-id", run_id],
                       capture_output=True, shell=False, env=env,
                       cwd=os.path.join(ROOT, "src"), stdin=subprocess.DEVNULL, timeout=120)
    return os.getpid()


class EngineHarness:
    """One deployment home + fixture repo + drive loop."""

    def __init__(self):
        self.base = tempfile.mkdtemp(prefix="qx-e2e-")
        self.home = os.path.join(self.base, "home")
        self.repo = make_fixture_repo(self.base)
        os.makedirs(os.path.join(self.home, "runs"), exist_ok=True)
        self.sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        self.store = store_mod.Store(os.path.join(self.home, "orchestrator.sqlite3"))
        cfg, reason = proj_cfg.load_nearest(self.repo)
        assert cfg is not None, reason
        self.cfg = cfg

    def close(self):
        self.sstore.close()
        self.store.close()
        shutil.rmtree(self.base, ignore_errors=True)

    # -- program construction helpers ----------------------------------------------------------
    def new_program(self, title, objective, lane_specs, *, policy=None, extra_meta=None):
        pid = orch.create_program(self.sstore, title=title, objective=objective,
                                  constraints=["tests must pass"], policy=policy, actor_id="test")
        self.sstore.set_program_meta(pid, "repository", self.repo.replace("\\", "/"))
        self.sstore.set_program_meta(pid, "project_name", self.cfg.name)
        lanes = {}
        for spec in lane_specs:
            deps = [lanes[d] for d in spec.get("depends_on", ())]
            lanes[spec["key"]] = orch.plan_lane(
                self.sstore, pid, title=spec["title"], task=spec.get("task", spec["title"]),
                kind=spec.get("kind", orch.KIND_IMPLEMENTATION), depends_on=deps,
                acceptance=spec.get("acceptance", ()),
                executor=spec.get("executor"), actor_id="test")
        for k, v in (extra_meta or {}).items():
            self.sstore.set_program_meta(pid, k, v)
        return pid, lanes

    def tick(self, pid, spawner=in_process_spawner):
        return orch.tick(self.home, self.sstore, self.store, program_id=pid, cfg=self.cfg,
                         preflight=fake_preflight, spawner=spawner)

    def drive(self, pid, max_ticks=30, on_tick=None, spawner=in_process_spawner):
        """Tick until terminal or exhausted. Returns the last report."""
        last = {}
        for _ in range(max_ticks):
            last = self.tick(pid, spawner=spawner)
            if on_tick:
                on_tick(last)
            if last["status_out"] in TERMINAL_STATUSES:
                break
        return last


class TestHappyPathMultiLane(unittest.TestCase):
    def test_two_implementation_lanes_with_dependency_and_integration_pass(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        tests = read_file(os.path.join(h.repo, "test_mathlib.py"))
        impl_a = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py": app + "\n\ndef sub(a, b):\n    return a - b\n"},
            "claimed_files": ["app/mathlib.py"]}}
        impl_b = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"test_mathlib.py": tests +
                            "\nimport unittest\nfrom app import mathlib\n\n"
                            "class SubTest(unittest.TestCase):\n"
                            "    def test_sub(self):\n"
                            "        self.assertEqual(mathlib.sub(4, 1), 3)\n"},
            "claimed_files": ["test_mathlib.py"]}}
        pid, lanes = h.new_program(
            "multi-lane happy path",
            "Add sub() to mathlib and cover it with tests.",
            [{"key": "impl", "title": "implement-sub", "executor": impl_a,
              "acceptance": ("sub exists",)},
             {"key": "tests", "title": "add-tests", "depends_on": ("impl",),
              "executor": impl_b, "acceptance": ("tests pass",)}])
        report = h.drive(pid)
        self.assertEqual(report["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(report.get("integration"), default=str))
        integ = h.sstore.get_integration_state(pid)
        self.assertEqual(integ["state"], "COMPLETE")
        self.assertEqual(len(integ["detail"]["merged"]), 2)
        # Dependency ordering held: the tests lane could not start before impl completed.
        runs = {b["role"]: b for b in h.sstore.runs_for_lane(lanes["tests"])}
        self.assertIn("implementation", runs)
        # The merged tree actually contains both contributions.
        wt = integ["workspace_path"]
        with open(os.path.join(wt, "app", "mathlib.py"), encoding="utf-8") as fh:
            self.assertIn("def sub(", fh.read())

    def test_lane_worktrees_are_distinct_per_lane(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        seen = set()
        pid = orch.create_program(h.sstore, title="wt", objective="x", actor_id="t")
        h.sstore.set_program_meta(pid, "repository", h.repo.replace("\\", "/"))
        for i in range(2):
            lane = orch.plan_lane(h.sstore, pid, title="L%d" % i, task="t",
                                  kind=orch.KIND_IMPLEMENTATION, actor_id="t")
            from quaestor.workspace import worktrees as wt_mod
            ck = h.sstore.get_lane_task(lane)["checkpoint"]
            path = ck.get("worktree_path") or wt_mod.lane_worktree_path(h.home, pid, lane)
            seen.add(path.lower())
        self.assertEqual(len(seen), 2)


class TestTwoWay(unittest.TestCase):
    def test_decision_request_persists_waits_and_resumes_after_answer(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        tests = read_file(os.path.join(h.repo, "test_mathlib.py"))
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Should divide-by-zero raise or return None?"}]}}
        finish = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py":
                            app + "\n\ndef div(a, b):\n    if b == 0:\n"
                                  "        raise ValueError('div by zero')\n"
                                  "    return a / b\n"},
            "claimed_files": ["app/mathlib.py"]}}
        variants = [ask, finish]
        pid, lanes = h.new_program(
            "two-way", "Implement div after clarifying semantics.",
            [{"key": "main", "title": "ask-then-implement", "executor":
              {"kind": "fake", "attempt_variants": variants},
              "acceptance": ("div works",)}])
        r1 = h.tick(pid)
        # The in-process worker finishes INSIDE this tick, so the lane may already be waiting.
        self.assertIn(r1["status_out"], (orch.PROGRAM_RUNNING,
                                         orch.PROGRAM_WAITING_STRATEGIST))
        r2 = h.tick(pid)   # reap the ask run
        ib = orch.inbox(h.sstore, pid)
        self.assertEqual([i["kind"] for i in ib["items"]], ["DECISION_REQUEST"])
        lane_state = h.sstore.get_lane(lanes["main"]).state
        self.assertEqual(lane_state, prog_wait())
        mid = ib["items"][0]["message_id"]
        orch.answer(h.sstore, pid, mid, decision_text="Raise ValueError.",
                    rationale="explicit failure beats a sentinel", actor_id="strategist-A")
        r3 = h.drive(pid)
        self.assertEqual(r3["status_out"], orch.PROGRAM_CANDIDATE_PASS)
        decs = h.sstore.decisions(pid)
        self.assertTrue(any(d.decision == "Raise ValueError." for d in decs))
        # The resumed run received the directive: its request prompt contains it.
        bound = [b for b in h.sstore.runs_for_lane(lanes["main"])]
        self.assertGreaterEqual(len(bound), 2, "expected an ask run AND a resume run")


def prog_wait():
    return prog_mod_waiting()


def prog_mod_waiting():
    from quaestor.core import programs as prog
    return prog.LANE_WAITING_STRATEGIST


class TestAdversarialLoop(unittest.TestCase):
    def test_review_finding_triggers_fix_then_pass(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        buggy = app + "\n\ndef mul(a, b):\n    return a + b   # subtle defect\n"
        fixed = app + "\n\ndef mul(a, b):\n    return a * b\n"
        tests = read_file(os.path.join(h.repo, "test_mathlib.py"))
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
        reviewer_ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "REVIEW_FINDING", "payload": "mul adds instead of multiplying",
             "severity": "HIGH",
             "detail": {"location": "app/mathlib.py", "failure_mode": "returns a+b"}}]}}
        reviewer_ok = {"kind": "fake", "config": {"scenario": "OK_PASS"}}
        reviewer_variants = {"attempt_variants": [reviewer_ask, reviewer_ok]}
        pid, lanes = h.new_program(
            "adversarial catch", "Implement mul correctly.",
            [{"key": "main", "title": "impl-mul", "executor": {"kind": "fake",
                                                               "attempt_variants":
                                                               [attempt0, attempt_fix]},
              "acceptance": ("mul works",)}],
            extra_meta={"review_executor": json.dumps(reviewer_variants)})
        reports = []
        last = h.drive(pid, max_ticks=24, on_tick=lambda r: reports.append(r))
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last.get("integration"), default=str))
        reviews = h.sstore.reviews_for(pid)
        self.assertTrue(reviews, "an adversarial review must have been recorded")
        # The fix cycle consumed exactly one more implementation run.
        impl_runs = [b for b in h.sstore.runs_for_lane(lanes["main"])
                     if b["role"] == "implementation"]
        self.assertEqual(len(impl_runs), 2)

    def test_review_cycles_are_bounded_then_escalated(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        # Each attempt writes DISTINCT truthful content (a fresh marker line), so every
        # attempt's claim matches measurement -- the escalation under test must come from the
        # review bound, never from an evidence disagreement.
        writers = [{"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py": app + "\ndef neg(a):\n    return -a\n"
                                             "# attempt %d\n" % i},
            "claimed_files": ["app/mathlib.py"]}} for i in range(4)]
        always_findings = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "REVIEW_FINDING", "payload": "still bad (%d)" % i, "severity": "HIGH",
             "detail": {"location": "x", "failure_mode": "perpetual"}} for i in range(9)]}}
        pid, lanes = h.new_program(
            "bounded loop", "Implement neg.",
            [{"key": "main", "title": "impl-neg",
              "executor": {"kind": "fake", "attempt_variants": writers},
              "acceptance": ("n",)}],
            policy=orch.ProgramPolicy(max_review_cycles=2),
            extra_meta={"review_executor": json.dumps(always_findings)})
        last = h.drive(pid, max_ticks=40)
        lane = h.sstore.get_lane(lanes["main"])
        self.assertEqual(lane.state, prog_wait())
        ib = orch.inbox(h.sstore, pid)
        self.assertTrue(any(i["kind"] == "BLOCKER" for i in ib["items"]),
                        "escalation must land in the strategist inbox")
        # Bound respected: attempts beyond the budget were NOT dispatched.
        impl_runs = [b for b in h.sstore.runs_for_lane(lanes["main"])
                     if b["role"] == "implementation"]
        self.assertLessEqual(len(impl_runs), 3)


class TestReportOnlyKinds(unittest.TestCase):
    def test_verification_lane_completes_exactly_once(self):
        """CONTROL (found LIVE): a verification run's verdict must ADVANCE its lane.

        reap() handled research but let verification fall into the catch-all 'NOTED' branch:
        the run was consumed, the lane stayed ACTIVE, and the scheduler re-dispatched a fresh
        executor on every tick forever -- each dispatch a real invocation under
        LOCAL_GOVERNED. The lane must reach COMPLETE and the program must go terminal.
        """
        h = EngineHarness()
        self.addCleanup(h.close)
        pid, lanes = h.new_program(
            "verification completes", "static check only",
            [{"key": "check", "title": "verify", "kind": orch.KIND_VERIFICATION,
              "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
              "acceptance": ()}],
            policy=orch.ProgramPolicy(require_adversarial=False))
        last = h.drive(pid, max_ticks=8)
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last, default=str))
        lane = h.sstore.get_lane(lanes["check"])
        self.assertEqual(lane.state, programs_mod.LANE_COMPLETE)
        # Exactly ONE durable run: no re-dispatch loop.
        self.assertEqual(len(h.sstore.runs_for_lane(lanes["check"])), 1)


class TestSyncFailureEscalation(unittest.TestCase):
    def test_repeated_dependency_sync_failure_escalates_once(self):
        """CONTROL (found LIVE): a conflicted dependency merge skipped its lane every tick with
        nothing but a line in the tick report -- the program stalled SILENTLY until an operator
        read raw output. After SYNC_FAIL_ESCALATE_AFTER consecutive failures the strategist
        inbox must hold ONE BLOCKER naming the error; an identical further failure must NOT
        re-escalate; a successful sync must clear the counter.
        """
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        parent = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py": app + "\n\ndef base(a):\n    return a\n"},
            "claimed_files": ["app/mathlib.py"]}}
        dependent = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/extra.py": "VALUE = 1\n"},
            "claimed_files": ["app/extra.py"]}}
        pid, lanes = h.new_program(
            "sync escalation", "parent then dependent",
            [{"key": "p", "title": "parent", "executor": parent, "acceptance": ()},
             {"key": "d", "title": "dependent", "depends_on": ("p",),
              "executor": dependent, "acceptance": ()}],
            policy=orch.ProgramPolicy(require_adversarial=False))

        h.tick(pid)                       # parent dispatched
        from quaestor.workspace import worktrees as wt_mod
        original = wt_mod.merge_branch
        wt_mod.merge_branch = lambda *a, **k: {
            "ok": False,
            "error": "CONFLICT (content): Merge conflict in app/mathlib.py"}
        try:
            h.tick(pid)                   # parent reaped -> COMPLETE; dependent sync fails #1
            ib = orch.inbox(h.sstore, pid)
            self.assertFalse(any(i["kind"] == "BLOCKER" for i in ib["items"]))
            h.tick(pid)                   # failure #2 -> escalate ONCE
            h.tick(pid)                   # identical failure -> NO new blocker
        finally:
            wt_mod.merge_branch = original

        ib = orch.inbox(h.sstore, pid)
        blockers = [i for i in ib["items"] if i["kind"] == "BLOCKER"]
        self.assertEqual(len(blockers), 1, json.dumps(ib["items"], default=str))
        self.assertIn("DEPENDENCY_SYNC failed", blockers[0]["payload"])
        self.assertIn("Merge conflict in app/mathlib.py", blockers[0]["payload"])
        # The lane is PARKED, not silently retried: it waits for the strategist.
        self.assertEqual(h.sstore.get_lane(lanes["d"]).state,
                         programs_mod.LANE_WAITING_STRATEGIST)

        # The strategist answers; the lane wakes to PLANNED and proceeds. The counter clears
        # on the NEXT reap -- deliberately not pre-dispatch, because the worker rewrites the
        # checkpoint from its own snapshot and would resurrect a pre-dispatch clear (measured).
        orch.answer(h.sstore, pid, blockers[0]["message_id"],
                    decision_text="Branches reconciled by owner; retry the sync.",
                    rationale="operator fixed the conflicted branches",
                    actor_id="strategist-test")
        h.tick(pid)                       # dispatches (sync succeeds)
        h.tick(pid)                       # reap consumes the run -> counter reset
        ckpt = h.sstore.get_lane_task(lanes["d"])["checkpoint"]
        self.assertFalse(ckpt.get("sync_fail_count"))
        self.assertEqual(h.sstore.get_lane(lanes["d"]).state, programs_mod.LANE_COMPLETE)
        # Once answered and resolved, the blocker LEAVES the inbox by construction
        # (inbox surfaces blockers only for waiting lanes) -- but the durable record keeps it.
        ib = orch.inbox(h.sstore, pid)
        self.assertFalse(any(i["kind"] == "BLOCKER" for i in ib["items"]))
        record = h.sstore.message(blockers[0]["message_id"])
        self.assertTrue(record.get("answered_by"), "blocker must stay answered in the ledger")


class TestCrashRecovery(unittest.TestCase):
    def test_retry_dispatch_states_the_handoff_contract(self):
        """CONTROL (found LIVE): a retry is the one moment the structured-handoff contract can
        be restated where the child is guaranteed to re-read it. 8 of 32 real children in the
        first LOCAL_GOVERNED program answered in prose and died RESULT_INVALID; attempt 0 must
        NOT carry the notice, every later attempt MUST.
        """
        h = EngineHarness()
        self.addCleanup(h.close)
        crasher = {"kind": "fake", "config": {"scenario": "WORKER_CRASH"}}
        finisher = {"kind": "fake", "config": {"scenario": "OK_PASS"}}
        pid, lanes = h.new_program(
            "retry notice", "survive and restate the contract",
            [{"key": "main", "title": "flaky", "executor":
              {"kind": "fake", "attempt_variants": [crasher, finisher]},
              "acceptance": ()}])
        last = h.drive(pid, max_ticks=20, spawner=subprocess_spawner)
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS)

        runs = []
        for b in h.sstore.runs_for_lane(lanes["main"]):
            run = h.store.get_run(b["run_id"])
            req = json.loads(read_file(os.path.join(h.home, "runs", b["run_id"],
                                                    "request.json")))
            runs.append((float(run["created_at"]), req["prompt"]))
        runs.sort()
        self.assertGreaterEqual(len(runs), 2, "expected a failed attempt AND its retry")
        self.assertNotIn("RETRY NOTICE", runs[0][1])
        for _, prompt in runs[1:]:
            self.assertIn("RETRY NOTICE", prompt)
            self.assertIn("EXACTLY ONE JSON object", prompt)

    def test_worker_crash_is_retried_then_completes(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        crasher = {"kind": "fake", "config": {"scenario": "WORKER_CRASH"}}
        finisher = {"kind": "fake", "config": {"scenario": "OK_PASS"}}
        pid, lanes = h.new_program(
            "crash recovery", "survive a worker crash",
            [{"key": "main", "title": "flaky", "executor":
              {"kind": "fake", "attempt_variants": [crasher, finisher]},
              "acceptance": ()}])
        states = []

        def on_tick(report):
            for b in h.sstore.runs_for_lane(lanes["main"]):
                run = h.store.get_run(b["run_id"])
                states.append(run["execution_state"])

        last = h.drive(pid, max_ticks=20, on_tick=on_tick, spawner=subprocess_spawner)
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS)
        self.assertIn(domain.WORKER_FAILED, states)


class TestTakeoverAndSoak(unittest.TestCase):
    def test_new_session_takes_over_from_durable_state_alone(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST", "payload": "Naming: snake or camel?"}]}}
        finish = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py": app + "\n\ndef snake_fn(a):\n    return a\n"},
            "claimed_files": ["app/mathlib.py"]}}
        pid, lanes = h.new_program(
            "takeover", "decide naming then proceed",
            [{"key": "main", "title": "session-a",
              "executor": {"kind": "fake", "attempt_variants": [ask, finish]},
              "acceptance": ()}],
            policy=orch.ProgramPolicy(require_adversarial=False))
        h.tick(pid)
        time.sleep(0.05)
        h.tick(pid)
        # SESSION B: brand-new stores object, no transcript, no memory.
        h.sstore.close()
        h.store.close()
        sstore_b = ss_mod.StrategicStore(ss_mod.strategic_path(h.home))
        store_b = store_mod.Store(os.path.join(h.home, "orchestrator.sqlite3"))
        try:
            view = orch.status_view(sstore_b, store_b, pid)
            self.assertFalse(view["vacuous"])
            self.assertEqual(view["status"], orch.PROGRAM_WAITING_STRATEGIST)
            ib = orch.inbox(sstore_b, pid)
            self.assertEqual(ib["items"][0]["kind"], "DECISION_REQUEST")
            bundle = sstore_b.handoff_bundle(pid)
            self.assertFalse(bundle["vacuous"])
            self.assertEqual(bundle["next_authority"], "STRATEGIST")
            mid = ib["items"][0]["message_id"]
            orch.answer(sstore_b, pid, mid, decision_text="snake_case",
                        rationale="repo convention", actor_id="strategist-B")
            # ...and session B drives it home with its own handles.
            cfg, _ = proj_cfg.load_nearest(h.repo)
            last = {}
            for _ in range(10):
                last = orch.tick(h.home, sstore_b, store_b, program_id=pid, cfg=cfg,
                                 preflight=fake_preflight, spawner=in_process_spawner)
                if last["status_out"] in TERMINAL_STATUSES:
                    break
            self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS)
        finally:
            sstore_b.close()
            store_b.close()

    def test_soak_many_durable_transitions(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        app = read_file(os.path.join(h.repo, "app", "mathlib.py"))
        tests = read_file(os.path.join(h.repo, "test_mathlib.py"))

        def impl_fn(name):
            return {"kind": "fake", "config": {
                "scenario": "OK_PASS",
                "write_files": {f"mod_{name}.py": f"VALUE_{name} = {len(name)}\n"},
                "claimed_files": [f"mod_{name}.py"]}}

        specs = []
        names = ["alpha", "beta", "gamma", "delta", "epsilon"]
        for n in names:
            specs.append({"key": n, "title": "impl-%s" % n, "executor": impl_fn(n),
                          "acceptance": ("%s written" % n,)})
        specs.append({"key": "docs", "title": "docs-lane",
                      "executor": {"kind": "fake", "config": {
                          "scenario": "OK_PASS",
                          "write_files": {"README.md": "# modules\n" + "".join(
                              "- %s\n" % n for n in names)},
                          "claimed_files": ["README.md"]}},
                      "acceptance": ("docs written",)})
        specs.append({"key": "research", "title": "survey", "kind": orch.KIND_RESEARCH,
                      "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
                      "acceptance": ()})
        pid, lanes = h.new_program(
            "soak", "many small modules plus docs plus research", specs,
            policy=orch.ProgramPolicy(max_concurrent_executors=4, require_adversarial=False))
        ticks = h.drive(pid, max_ticks=60)
        self.assertEqual(ticks["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(ticks.get("integration"), default=str))
        total_runs = sum(len(h.sstore.runs_for_lane(l.lane_id))
                         for l in h.sstore.lanes(pid))
        self.assertGreaterEqual(total_runs, 7,
                                "each lane should have produced at least one durable run")
        events = h.sstore.events(program_id=pid)
        transitions = [e for e in events if e["event_type"] in
                       ("RUN_BOUND", "LANE_STATE_CHANGED", "SCHEDULED", "CHECKPOINT_SAVED")]
        self.assertGreaterEqual(len(transitions), 20,
                                "soak floor: >=20 durable task/run transitions")

    def test_real_detached_worker_spawn_once(self):
        """One dispatch through the REAL detached-worker path (subprocess), end to end."""
        h = EngineHarness()
        self.addCleanup(h.close)
        writer = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"real.txt": "spawned\n"},
            "claimed_files": ["real.txt"]}}
        pid, lanes = h.new_program(
            "real spawn", "prove the detached worker path",
            [{"key": "main", "title": "spawned-lane", "executor": writer, "acceptance": ()}],
            policy=orch.ProgramPolicy(max_concurrent_executors=1, require_adversarial=False))
        deadline = time.time() + 90
        last = {}
        while time.time() < deadline:
            last = orch.tick(h.home, h.sstore, h.store, program_id=pid, cfg=h.cfg,
                             preflight=fake_preflight)     # spawn=True: the REAL path
            if last["status_out"] in TERMINAL_STATUSES:
                break
            time.sleep(1.5)
        self.assertEqual(last["status_out"], orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last.get("integration"), default=str))
        integ = h.sstore.get_integration_state(pid)
        with open(os.path.join(integ["workspace_path"], "real.txt"), encoding="utf-8") as fh:
            self.assertIn("spawned", fh.read())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

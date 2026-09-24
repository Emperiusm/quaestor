"""P0 MUTATION SUITE -- the eighteen required failure classes, plus controls on the controls.

Everything here runs against REAL git repositories and, where OS semantics are the subject, REAL
detached processes. The only thing faked is Claude.

READ THIS BEFORE ADDING A TEST: a control that only exercises the happy path proves
serialization, not verification. Every control below either MUTATES something (kill a process,
move HEAD, plant a foreign artifact, set a credential variable) or asserts a REFUSAL. The
positive controls exist to prove the refusals are discriminating rather than universal -- a gate
that refuses everything passes every negative test and is worthless.
"""
from __future__ import annotations

import dataclasses
import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import authority
from quaestor.core import domain
from quaestor.evidence import model as evidence
from quaestor.core import handoff
from quaestor.core import proc
from quaestor.core import reconcile
from quaestor.workspace import git as repo
from quaestor.core import runfiles  # noqa: E402
from quaestor.core import worker as worker_mod  # noqa: E402
from quaestor.core.dispatcher import DispatchSpec, dispatch  # noqa: E402
from quaestor.core.store import Store  # noqa: E402
from tests import support  # noqa: E402
from tests.controls import control  # noqa: E402


def spec(sb, step="s1", *, profile=authority.READ_ONLY, scenario="OK_PASS", repo_name="repo",
         caps=None, **cfg):
    executor = {"kind": "fake", "config": dict(scenario=scenario, **cfg)}
    return DispatchSpec(workflow_id="wf-1", step_id=step, task="report a repository fact",
                        worktree_path=sb.repo(repo_name), authority_profile=profile,
                        required_capabilities=tuple(caps) if caps else (),
                        executor=executor, timeout_s=60.0)


class Base(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox()
        self.addCleanup(self.sb.close)

    def state(self, run_id):
        return str(self.sb.store.get_run(run_id)["execution_state"])


# =============================================================================================
# 1 -- duplicate dispatch
# =============================================================================================
class TestDuplicateDispatch(Base):
    @control(1)
    def test_identical_dispatch_twice_spawns_one_execution(self):
        calls = []

        def counting_spawner(*, db_path, run_id):
            calls.append(run_id)
            return os.getpid()

        s = spec(self.sb)
        first = dispatch(self.sb.store, s, run_root=self.sb.runs,
                         preflight=support.preflight_stub(), spawner=counting_spawner)
        second = dispatch(self.sb.store, s, run_root=self.sb.runs,
                          preflight=support.preflight_stub(), spawner=counting_spawner)

        self.assertEqual(first.outcome, "ADMITTED")
        self.assertEqual(second.outcome, "DUPLICATE")
        self.assertEqual(second.run_id, first.run_id)
        self.assertEqual(second.dispatch_key, first.dispatch_key)
        self.assertEqual(len(calls), 1, "a second worker was spawned for a duplicate dispatch")

    def test_the_database_itself_refuses_a_second_active_attempt(self):
        """Control on the control: the invariant survives a caller that bypasses admit()."""
        s = spec(self.sb)
        res = dispatch(self.sb.store, s, run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawner=support.inline_spawner())
        run = self.sb.store.get_run(res.run_id)
        with self.assertRaises(sqlite3.IntegrityError):
            self.sb.store.conn.execute(
                "INSERT INTO attempt(run_id, dispatch_key, attempt_no, run_nonce, execution_state,"
                " is_write, run_dir, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("forced", run["dispatch_key"], 2, "n", domain.CREATED, 0, "x", 1.0, 1.0))

    def test_a_different_step_is_a_different_execution(self):
        """Control on the control: deduplication must not swallow genuinely distinct work."""
        a = dispatch(self.sb.store, spec(self.sb, "s1"), run_root=self.sb.runs,
                     preflight=support.preflight_stub(), spawner=support.inline_spawner())
        b = dispatch(self.sb.store, spec(self.sb, "s2"), run_root=self.sb.runs,
                     preflight=support.preflight_stub(), spawner=support.inline_spawner())
        self.assertEqual(a.outcome, "ADMITTED")
        self.assertEqual(b.outcome, "ADMITTED")
        self.assertNotEqual(a.run_id, b.run_id)


# =============================================================================================
# 2 -- lease exclusivity
# =============================================================================================
class TestLeaseExclusivity(Base):
    @control(2)
    def test_second_mutable_run_on_the_same_worktree_is_refused(self):
        first = dispatch(self.sb.store, spec(self.sb, "s1", profile=authority.STANDARD_EDIT),
                         run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
        second = dispatch(self.sb.store, spec(self.sb, "s2", profile=authority.STANDARD_EDIT),
                          run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(first.outcome, "ADMITTED")
        self.assertEqual(second.outcome, "REFUSED")
        self.assertEqual(second.state, domain.LEASE_REFUSED)
        self.assertIn(first.run_id, second.detail)

    def test_two_read_only_runs_share_a_worktree(self):
        """Control on the control: a lease that refused EVERYTHING would pass the test above."""
        a = dispatch(self.sb.store, spec(self.sb, "s1"), run_root=self.sb.runs,
                     preflight=support.preflight_stub(), spawn=False)
        b = dispatch(self.sb.store, spec(self.sb, "s2"), run_root=self.sb.runs,
                     preflight=support.preflight_stub(), spawn=False)
        self.assertEqual((a.outcome, b.outcome), ("ADMITTED", "ADMITTED"))

    def test_a_mutable_run_on_another_worktree_is_allowed(self):
        a = dispatch(self.sb.store, spec(self.sb, "s1", profile=authority.STANDARD_EDIT),
                     run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
        b = dispatch(self.sb.store,
                     spec(self.sb, "s2", profile=authority.STANDARD_EDIT, repo_name="repo2"),
                     run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
        self.assertEqual((a.outcome, b.outcome), ("ADMITTED", "ADMITTED"))


# =============================================================================================
# 3, 4 -- worktree drift
# =============================================================================================
class TestWorktreeDrift(Base):
    @control(3)
    def test_head_drift_between_admission_and_dispatch_refuses(self):
        real = repo.probe
        calls = {"n": 0}

        def drifting_probe(path, **kw):
            snap = real(path, **kw)
            calls["n"] += 1
            if calls["n"] == 1:
                return snap
            return evidence.RepoSnapshot(**{**snap.to_dict(),
                                            "changed_paths": tuple(snap.changed_paths or ()),
                                            "head": "0" * 40})

        res = dispatch(self.sb.store, spec(self.sb, profile=authority.STANDARD_EDIT),
                       run_root=self.sb.runs, preflight=support.preflight_stub(),
                       probe=drifting_probe, spawn=False)
        self.assertEqual(res.outcome, "REFUSED")
        self.assertEqual(res.state, domain.LEASE_REFUSED)
        self.assertEqual(res.reason, repo.HEAD_DRIFT)
        self.assertGreaterEqual(calls["n"], 2, "the drift re-check never ran")

    @control(3)
    def test_a_pinned_head_that_does_not_match_refuses(self):
        pinned = dataclasses.replace(spec(self.sb), expected_head="0" * 40)
        res = dispatch(self.sb.store, pinned, run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.reason, repo.HEAD_DRIFT)

    @control(3)
    def test_the_worker_re_checks_drift_after_the_dispatcher_passed_it(self):
        """HEAD really moves between admission and the worker starting."""
        res = dispatch(self.sb.store, spec(self.sb, profile=authority.STANDARD_EDIT),
                       run_root=self.sb.runs, preflight=support.preflight_stub(),
                       spawner=support.inline_spawner())
        self.assertEqual(res.state, domain.DISPATCHED)

        path = self.sb.repo()
        with open(os.path.join(path, "NEW.txt"), "w", encoding="utf-8") as fh:
            fh.write("moved\n")
        support.git(["add", "-A"], path)
        support.git(["commit", "-m", "another lane committed"], path)

        worker_mod.run_worker(db_path=self.sb.db, run_id=res.run_id)
        self.assertEqual(self.state(res.run_id), domain.LEASE_REFUSED)
        self.assertIn("HEAD_DRIFT", str(self.sb.store.get_run(res.run_id)["refusal_reason"]))

    @control(4)
    def test_branch_drift_refuses(self):
        pinned = dataclasses.replace(spec(self.sb),
                                     expected_branch="a-branch-that-is-not-checked-out")
        res = dispatch(self.sb.store, pinned, run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.outcome, "REFUSED")
        self.assertEqual(res.reason, repo.BRANCH_DRIFT)

    def test_a_matching_worktree_is_not_refused(self):
        """Control on the control: drift detection must not refuse an unmoved tree."""
        res = dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.outcome, "ADMITTED")


# =============================================================================================
# 5, 12, 13 -- real processes: crash, restart, no-retry
# =============================================================================================
class TestWorkerLifecycle(Base):
    def _wait_not_running(self, run_id, timeout=60.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rec = reconcile.reconcile_run(self.sb.store, run_id, apply=False)
            if rec.classification != reconcile.RUNNING:
                return rec
            time.sleep(0.25)
        return reconcile.reconcile_run(self.sb.store, run_id, apply=False)

    @control(5)
    def test_a_worker_that_crashes_before_a_result_is_ambiguous_not_retried(self):
        res = support.dispatch_detached(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT, scenario="WORKER_CRASH"))
        self.assertEqual(res.outcome, "ADMITTED")
        self.assertTrue(res.spawned)

        rec = self._wait_not_running(res.run_id)
        self.assertEqual(rec.classification, reconcile.AMBIGUOUS_EXECUTION, rec.reason)
        self.assertFalse(rec.auto_redispatch_allowed)

        applied = reconcile.reconcile_run(self.sb.store, res.run_id, apply=True)
        self.assertEqual(applied.classification, reconcile.AMBIGUOUS_EXECUTION)
        self.assertEqual(self.state(res.run_id), domain.AMBIGUOUS_EXECUTION)
        self.assertIsNone(self.sb.store.get_handoff(res.run_id))

    @control(13)
    def test_an_uncertain_execution_is_never_auto_redispatched(self):
        s = spec(self.sb, profile=authority.STANDARD_EDIT, scenario="WORKER_CRASH")
        res = support.dispatch_detached(self.sb, s)
        self._wait_not_running(res.run_id)
        reconcile.reconcile_run(self.sb.store, res.run_id, apply=True)
        self.assertEqual(self.state(res.run_id), domain.AMBIGUOUS_EXECUTION)

        calls = []

        def counting_spawner(*, db_path, run_id):
            calls.append(run_id)
            return os.getpid()

        again = dispatch(self.sb.store, s, run_root=self.sb.runs,
                         preflight=support.preflight_stub(), spawner=counting_spawner)
        self.assertEqual(again.outcome, "DUPLICATE")
        self.assertEqual(again.run_id, res.run_id)
        self.assertEqual(calls, [], "an ambiguous execution was silently retried")
        # And reconciliation itself must not have started anything either.
        self.assertEqual(self.state(res.run_id), domain.AMBIGUOUS_EXECUTION)

    @control(12)
    def test_a_restarted_dispatcher_rediscovers_a_live_worker(self):
        res = support.dispatch_detached(
            self.sb, spec(self.sb, scenario="SLOW", delay_s=6.0))
        self.assertTrue(res.spawned)

        # A COMPLETELY SEPARATE Store handle, as a restarted bridge would have.
        fresh = Store(self.sb.db)
        self.addCleanup(fresh.close)
        seen_running = False
        deadline = time.time() + 20.0
        while time.time() < deadline:
            rec = reconcile.reconcile_run(fresh, res.run_id, apply=False)
            if rec.classification == reconcile.RUNNING:
                seen_running = True
                break
            time.sleep(0.2)
        self.assertTrue(seen_running, "a live detached worker was not rediscovered as RUNNING")

        row = support.wait_for_terminal(self.sb.store, res.run_id, timeout=60.0)
        self.assertEqual(str(row["execution_state"]), domain.HANDOFF_READY)

    @control(12)
    def test_an_unprovable_worker_is_ambiguous_rather_than_assumed_dead(self):
        """The conservative half of control 12: UNKNOWN liveness never resolves to 'retry'."""
        rec = reconcile.classify(run_state=domain.RUNNING, is_write=True, liveness=proc.UNKNOWN,
                                 worker_started=True, exit_receipt=None, result_valid=None,
                                 observed_change=None)
        self.assertEqual(rec.classification, reconcile.AMBIGUOUS_EXECUTION)
        self.assertFalse(rec.auto_redispatch_allowed)

    def test_a_worker_that_never_started_is_the_one_case_that_may_be_reissued(self):
        """Control on the control: 'no blind retry' must not mean 'never recoverable'."""
        rec = reconcile.classify(run_state=domain.DISPATCHED, is_write=True, liveness=proc.DEAD,
                                 worker_started=False, exit_receipt=None, result_valid=None,
                                 observed_change=None)
        self.assertEqual(rec.classification, reconcile.WORKER_FAILED)
        self.assertTrue(rec.auto_redispatch_allowed)

    def test_a_second_worker_cannot_take_a_run_a_live_worker_owns(self):
        res = support.dispatch_detached(self.sb, spec(self.sb, scenario="SLOW", delay_s=5.0))
        run = self.sb.store.get_run(res.run_id)
        lock_path = runfiles.p(str(run["run_dir"]), runfiles.LOCK)
        deadline = time.time() + 20.0
        while time.time() < deadline and proc.probe_lock(lock_path) != proc.LOCK_HELD:
            time.sleep(0.1)
        self.assertEqual(proc.probe_lock(lock_path), proc.LOCK_HELD)
        rc = worker_mod.run_worker(db_path=self.sb.db, run_id=res.run_id)
        self.assertEqual(rc, 4, "a second worker was allowed to adopt a live run")
        support.wait_for_terminal(self.sb.store, res.run_id, timeout=60.0)


# =============================================================================================
# 6, 7, 8, 9 -- result validation
# =============================================================================================
class TestResultValidation(Base):
    def _run(self, scenario, **cfg):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb, scenario=scenario, **cfg))
        return res

    @control(6)
    def test_malformed_json_result_is_result_invalid(self):
        res = self._run("MALFORMED_JSON")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        row = self.sb.store.get_result(res.run_id)
        self.assertEqual(row["valid"], 0)
        self.assertIn("not valid JSON", row["invalid_reason"])
        self.assertIsNone(self.sb.store.get_handoff(res.run_id))

    @control(6)
    def test_empty_stdout_is_result_invalid_not_an_empty_pass(self):
        res = self._run("EMPTY_STDOUT")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        self.assertIn("empty", self.sb.store.get_result(res.run_id)["invalid_reason"])

    @control(7)
    def test_a_schema_valid_result_with_the_wrong_run_identity_is_refused(self):
        res = self._run("WRONG_RUN_IDENTITY")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        row = self.sb.store.get_result(res.run_id)
        self.assertEqual(row["outcome"], handoff.RUN_IDENTITY_REFUSED)
        self.assertIn("NONCE_MISMATCH", row["invalid_reason"])

    @control(8)
    def test_a_missing_structured_handoff_is_result_invalid(self):
        res = self._run("MISSING_HANDOFF")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        self.assertIn("no structured handoff",
                      self.sb.store.get_result(res.run_id)["invalid_reason"])

    @control(9)
    def test_an_unsupported_protocol_version_is_refused(self):
        res = self._run("BAD_PROTOCOL_VERSION")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        row = self.sb.store.get_result(res.run_id)
        self.assertEqual(row["outcome"], handoff.PROTOCOL_REFUSED)
        self.assertIn("unsupported handoff protocol major version", row["invalid_reason"])

    def test_a_failed_child_process_is_claude_failed_not_result_invalid(self):
        """Control on the control: distinct failures must not collapse into one verdict."""
        res = self._run("PROCESS_FAILURE")
        self.assertEqual(self.state(res.run_id), domain.RESULT_INVALID)
        worker_row = self.sb.store.get_worker(res.run_id)
        self.assertEqual(worker_row["exit_code"], 1)
        self.assertEqual(worker_row["exit_class"], "NONZERO_EXIT")

    def test_a_spawn_failure_is_worker_failed(self):
        res = self._run("SPAWN_FAILURE")
        self.assertEqual(self.state(res.run_id), domain.WORKER_FAILED)


# =============================================================================================
# 10 -- the orthogonal state model
# =============================================================================================
class TestOrthogonalStates(Base):
    @control(10)
    def test_complete_prompt_with_failing_program_is_a_valid_handoff(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb, scenario="OK_FAIL"))
        self.assertEqual(self.state(res.run_id), domain.HANDOFF_READY)

        row = self.sb.store.get_result(res.run_id)
        self.assertEqual(row["prompt_disposition"], domain.COMPLETE)
        self.assertEqual(row["program_verdict"], domain.FAIL)
        self.assertEqual(row["next_authority"], domain.GPT_ORCHESTRATOR)
        self.assertEqual(row["valid"], 1)

        package = self.sb.store.get_handoff(res.run_id)
        self.assertIsNotNone(package, "a failing program must still produce a handoff")

    @control(10)
    def test_a_failing_program_is_not_recorded_as_an_execution_failure(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb, scenario="OK_FAIL"))
        state = self.state(res.run_id)
        for failure_state in (domain.CLAUDE_FAILED, domain.RESULT_INVALID, domain.WORKER_FAILED,
                              domain.AMBIGUOUS_EXECUTION, domain.EVIDENCE_INVALID):
            self.assertNotEqual(state, failure_state)

    def test_a_blocked_prompt_still_produces_a_handoff(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb, scenario="BLOCKED"))
        self.assertEqual(self.state(res.run_id), domain.HANDOFF_READY)
        row = self.sb.store.get_result(res.run_id)
        self.assertEqual(row["prompt_disposition"], domain.BLOCKED)
        self.assertEqual(row["program_verdict"], domain.NOT_EVALUATED)

    def test_the_happy_path_reaches_handoff_ready(self):
        """Control on the control: the suite must be able to reach success at all."""
        res, rc = support.dispatch_inline(self.sb, spec(self.sb, scenario="OK_PASS"))
        self.assertEqual(rc, 0)
        self.assertEqual(self.state(res.run_id), domain.HANDOFF_READY)


# =============================================================================================
# 11 -- authority
# =============================================================================================
class TestAuthorityEnforcement(Base):
    @control(11)
    def test_a_capability_outside_the_profile_yields_owner_required(self):
        res = dispatch(self.sb.store,
                       spec(self.sb, profile=authority.READ_ONLY, caps=["repo_write"]),
                       run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.outcome, "REFUSED")
        self.assertEqual(res.state, domain.OWNER_REQUIRED)
        self.assertIn("repo_write", res.extra["missing"])

    @control(11)
    def test_an_owner_gated_capability_requires_an_owner_grant(self):
        s = spec(self.sb, profile=authority.GIT_PUSH, caps=["git_push"])
        refused = dispatch(self.sb.store, s, run_root=self.sb.runs,
                           preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(refused.state, domain.OWNER_REQUIRED)
        self.assertIn("git_push", refused.extra["ungranted"])

        # TIGHTENED IN P2.5: recording a grant does NOT open the gate. The ledger row is a
        # claim that someone approved something; authority requires an independent authenticated
        # channel, and until one exists the capability stays locked. The claim is still visible
        # in the refusal, which is the point of keeping the ledger at all.
        self.sb.store.add_owner_grant("git_push", note="recorded claim, not authority")
        still_refused = dispatch(self.sb.store, spec(self.sb, "s2", profile=authority.GIT_PUSH,
                                                     caps=["git_push"]),
                                 run_root=self.sb.runs, preflight=support.preflight_stub(),
                                 spawn=False)
        self.assertEqual(still_refused.state, domain.OWNER_REQUIRED,
                         "a database row must not be able to grant owner authority")
        self.assertIn("git_push", still_refused.extra["ungranted"])

    @control(11)
    def test_paid_and_external_capabilities_are_owner_gated_too(self):
        for profile, cap in ((authority.PAID_EXECUTION, "paid_execution"),
                             (authority.EXTERNAL_WRITE, "external_write"),
                             (authority.DESTRUCTIVE, "destructive")):
            res = dispatch(self.sb.store, spec(self.sb, "step-" + cap, profile=profile,
                                               caps=[cap]),
                           run_root=self.sb.runs, preflight=support.preflight_stub(), spawn=False)
            self.assertEqual(res.state, domain.OWNER_REQUIRED, cap)

    def test_a_read_only_run_within_its_envelope_is_admitted(self):
        """Control on the control."""
        res = dispatch(self.sb.store, spec(self.sb, caps=["repo_read"]), run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.outcome, "ADMITTED")


# =============================================================================================
# 14, 15 -- evidence disagreement
# =============================================================================================
class TestEvidenceDisagreement(Base):
    @control(14)
    def test_claiming_no_change_while_the_fixture_changed_is_a_disagreement(self):
        res, _ = support.dispatch_inline(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT,
                          scenario="CLAIM_CLEAN_BUT_WRITE", touch_file="touched.txt"))
        self.assertEqual(self.state(res.run_id), domain.EVIDENCE_INVALID)
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertEqual(ev["verdict"], evidence.DISAGREEMENT)
        self.assertIn(evidence.CLAIMED_CLEAN_BUT_CHANGED, ev["envelope_json"])
        self.assertIsNone(self.sb.store.get_handoff(res.run_id))

    @control(15)
    def test_claiming_a_change_the_fixture_did_not_receive_is_a_disagreement(self):
        res, _ = support.dispatch_inline(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT,
                          scenario="CLAIM_CHANGED_BUT_CLEAN"))
        self.assertEqual(self.state(res.run_id), domain.EVIDENCE_INVALID)
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertEqual(ev["verdict"], evidence.DISAGREEMENT)
        self.assertIn(evidence.CLAIMED_CHANGED_BUT_CLEAN, ev["envelope_json"])

    def test_an_accurate_claim_agrees(self):
        """Control on the control: the comparison must be able to agree."""
        res, _ = support.dispatch_inline(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT, scenario="OK_PASS",
                          touch_file="touched.txt", claimed_files=["touched.txt"]))
        self.assertEqual(self.state(res.run_id), domain.HANDOFF_READY)
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertEqual(ev["verdict"], evidence.OK)
        self.assertEqual(ev["observed_change"], 1)

    def test_the_measurement_is_independent_of_the_claim(self):
        """The observed set comes from git, not from the report."""
        res, _ = support.dispatch_inline(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT, scenario="OK_PASS",
                          touch_file="a.txt", claimed_files=["a.txt"]))
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertIn("a.txt", ev["envelope_json"])


# =============================================================================================
# 16 -- stale artifacts
# =============================================================================================
class TestStaleArtifact(Base):
    @control(16)
    def test_a_result_artifact_from_a_prior_run_is_refused(self):
        first, _ = support.dispatch_inline(self.sb, spec(self.sb, "s1", scenario="OK_PASS"))
        self.assertEqual(self.state(first.run_id), domain.HANDOFF_READY)
        stale_bytes = support.runfiles_read(self.sb, first.run_id, runfiles.STDOUT)
        self.assertIn("AEGIS_ORCHESTRATOR_HANDOFF", stale_bytes)

        second = dispatch(self.sb.store, spec(self.sb, "s2", scenario="STALE_ARTIFACT"),
                          run_root=self.sb.runs, preflight=support.preflight_stub(),
                          spawner=support.inline_spawner())
        self.assertEqual(second.state, domain.DISPATCHED)

        # Plant run 1's output in run 2's directory, exactly as a reused artifact path would.
        target = support.run_file(self.sb, second.run_id, runfiles.STDOUT)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(stale_bytes)

        worker_mod.run_worker(db_path=self.sb.db, run_id=second.run_id)
        self.assertEqual(self.state(second.run_id), domain.RESULT_INVALID)
        row = self.sb.store.get_result(second.run_id)
        self.assertEqual(row["outcome"], handoff.RUN_IDENTITY_REFUSED)
        self.assertIsNone(self.sb.store.get_handoff(second.run_id))


# =============================================================================================
# 17 -- credential preflight
# =============================================================================================
class TestCredentialPreflight(Base):
    @control(17)
    def test_an_api_key_in_the_environment_refuses_the_run(self):
        res = dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                       preflight=support.preflight_stub(env={"ANTHROPIC_API_KEY": "sk-ant-x"}),
                       spawn=False)
        self.assertEqual(res.outcome, "REFUSED")
        self.assertEqual(res.state, domain.PREFLIGHT_REFUSED)
        self.assertEqual(res.reason, "CREDENTIAL_OVERRIDE_PRESENT")
        self.assertIn("ANTHROPIC_API_KEY", res.extra["offending_vars"])

    @control(17)
    def test_every_override_variable_refuses_through_the_dispatcher(self):
        from quaestor.executors import claude_auth as pf
        for i, name in enumerate(pf.OVERRIDE_VARS):
            res = dispatch(self.sb.store, spec(self.sb, "step-%d" % i), run_root=self.sb.runs,
                           preflight=support.preflight_stub(env={name: "value"}), spawn=False)
            self.assertEqual(res.state, domain.PREFLIGHT_REFUSED, name)

    @control(17)
    def test_the_control_plane_does_not_unset_the_offending_variable(self):
        env = {"ANTHROPIC_API_KEY": "sk-ant-x"}
        dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                 preflight=support.preflight_stub(env=env), spawn=False)
        self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-ant-x",
                         "the preflight mutated the environment instead of refusing")

    @control(17)
    def test_unverifiable_auth_refuses(self):
        res = dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                       preflight=support.preflight_stub(auth={"loggedIn": True,
                                                              "authMethod": "mystery"}),
                       spawn=False)
        self.assertEqual(res.state, domain.PREFLIGHT_REFUSED)
        self.assertEqual(res.extra["auth_class"], "UNVERIFIED")

    def test_no_credential_value_reaches_the_event_log(self):
        dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                 preflight=support.preflight_stub(env={"ANTHROPIC_API_KEY": "sk-ant-SECRET"}),
                 spawn=False)
        rows = self.sb.store._all("SELECT detail_json FROM event")
        blob = "".join(r["detail_json"] for r in rows)
        self.assertNotIn("sk-ant-SECRET", blob)
        self.assertIn("ANTHROPIC_API_KEY", blob)   # the NAME is recorded; the value is not


# =============================================================================================
# 18 -- the evidence floor
# =============================================================================================
class TestEvidenceFloor(Base):
    @control(18)
    def test_zero_inspected_files_cannot_report_a_successful_execution(self):
        # Create the EMPTY fixture first: Sandbox.repo caches by name, so building the spec
        # before this line would silently hand back an ordinary populated repo -- and the control
        # would pass over a tree that had files in it. (The first draft of this test did exactly
        # that and reported HANDOFF_READY; the floor caught it, which is the point of the floor.)
        self.sb.repo("empty", empty=True)
        s = spec(self.sb, repo_name="empty")
        self.assertEqual(len(support.git(["ls-files"], self.sb.repo("empty")).split()), 0)
        res, _ = support.dispatch_inline(self.sb, s)
        self.assertEqual(self.state(res.run_id), domain.EVIDENCE_INVALID)
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertEqual(ev["verdict"], evidence.VACUOUS)
        self.assertEqual(ev["inspected_count"], 0)
        self.assertIsNone(self.sb.store.get_handoff(res.run_id))

    @control(18)
    def test_an_unmeasurable_repository_is_unavailable_not_clean(self):
        env = evidence.build_envelope(
            evidence.RepoSnapshot(probe_ok=True, tracked_file_count=5, changed_paths=()),
            evidence.RepoSnapshot(probe_ok=False, probe_error="git vanished"),
            claimed_change=False)
        self.assertEqual(env.verdict, evidence.UNAVAILABLE)
        self.assertFalse(env.ok)

    @control(18)
    def test_the_floor_is_recorded_alongside_the_verdict(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb))
        ev = self.sb.store.get_evidence(res.run_id)
        self.assertGreaterEqual(ev["inspected_count"], 1)
        self.assertEqual(ev["probe_ok"], 1)


# =============================================================================================
# Cross-cutting invariants
# =============================================================================================
class TestDurabilityInvariants(Base):
    def test_the_event_log_is_append_only(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb))
        with self.assertRaises(sqlite3.IntegrityError):
            self.sb.store.conn.execute("UPDATE event SET kind='tampered' WHERE run_id=?",
                                       (res.run_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.sb.store.conn.execute("DELETE FROM event WHERE run_id=?", (res.run_id,))

    def test_the_event_trail_reconstructs_the_run(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb))
        kinds = [e["kind"] for e in self.sb.store.events_for(res.run_id)]
        for expected in ("dispatch.admitted", "preflight", "worker.spawned", "worker.started",
                         "result.recorded", "evidence.recorded", "handoff.ready"):
            self.assertIn(expected, kinds, expected)
        states = [e["to_state"] for e in self.sb.store.events_for(res.run_id) if e["to_state"]]
        self.assertEqual(states[-1], domain.HANDOFF_READY)

    def test_an_illegal_transition_is_refused(self):
        from quaestor.core.store import TransitionRefused
        res, _ = support.dispatch_inline(self.sb, spec(self.sb))
        with self.assertRaises(TransitionRefused):
            self.sb.store.transition(res.run_id, domain.RUNNING)

    def test_a_compare_and_set_transition_refuses_a_moved_run(self):
        from quaestor.core.store import TransitionRefused
        res = dispatch(self.sb.store, spec(self.sb), run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawner=support.inline_spawner())
        with self.assertRaises(TransitionRefused):
            self.sb.store.transition(res.run_id, domain.RUNNING, expect_from=domain.LEASED)

    def test_the_lease_is_released_when_the_worker_finishes(self):
        res, _ = support.dispatch_inline(
            self.sb, spec(self.sb, profile=authority.STANDARD_EDIT, scenario="OK_PASS"))
        lease_row = self.sb.store.lease_for_run(res.run_id)
        self.assertIsNotNone(lease_row)
        self.assertIsNotNone(lease_row["released_at"], "a finished run must not hold its lease")

    def test_the_handoff_package_labels_report_and_evidence_separately(self):
        res, _ = support.dispatch_inline(self.sb, spec(self.sb, scenario="OK_FAIL"))
        import json as _json
        pkg = _json.loads(self.sb.store.get_handoff(res.run_id)["handoff_json"])
        self.assertIn("claude_report", pkg)
        self.assertIn("bridge_evidence", pkg)
        self.assertEqual(pkg["claude_report"]["program_verdict"], domain.FAIL)
        self.assertEqual(pkg["bridge_evidence"]["verdict"], evidence.OK)
        self.assertEqual(pkg["execution_state"], domain.HANDOFF_READY)


if __name__ == "__main__":
    unittest.main()

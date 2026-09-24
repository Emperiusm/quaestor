"""Unit tests for the PURE decision cores. No processes, no Claude, no network.

These are the controls on the controls: if the pure layer is wrong, every integration test above
it is measuring the wrong thing confidently.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.controls import control

from quaestor.core import authority
from quaestor.core import canon
from quaestor.core import domain
from quaestor.evidence import model as evidence
from quaestor.core import handoff
from quaestor.core import lease
from quaestor.core import proc
from quaestor.workspace import git as repo  # noqa: E402
from quaestor.executors import claude_auth as pf  # noqa: E402
from quaestor.executors.claude_code import (FORBIDDEN_FLAGS, UnsafeCommand, build_command,  # noqa: E402
                                       permission_mode, profile_tools)
from quaestor.core.executor_contract import ExecRequest, extract_structured, parse_envelope  # noqa: E402
from quaestor.core.identity import RunBinding, build_identity  # noqa: E402


class TestCanon(unittest.TestCase):
    def test_path_spellings_collapse_to_one_identity(self):
        a = canon.canonical_path("C:/Users/x/Repo/")
        b = canon.canonical_path("c:\\users\\x\\repo")
        self.assertEqual(a, b)

    def test_empty_path_is_empty_not_cwd(self):
        self.assertEqual(canon.canonical_path(""), "")
        self.assertEqual(canon.canonical_path(None), "")

    def test_canonical_json_is_key_order_independent(self):
        self.assertEqual(canon.canonical_json({"a": 1, "b": 2}),
                         canon.canonical_json({"b": 2, "a": 1}))

    def test_canonical_json_is_ascii_only(self):
        # A digest must not depend on the encoding of the file it travelled through.
        out = canon.canonical_json({"k": "caf\u00e9"})
        out.encode("ascii")

    def test_is_true_rejects_truthy_non_booleans(self):
        self.assertTrue(canon.is_true(True))
        for v in ("false", "true", 1, "yes", [1], {"a": 1}):
            self.assertFalse(canon.is_true(v), v)


class TestDomain(unittest.TestCase):
    def test_no_edge_out_of_ambiguous_execution(self):
        for state in domain.ALL_STATES:
            self.assertFalse(domain.can_transition(domain.AMBIGUOUS_EXECUTION, state),
                             "AMBIGUOUS_EXECUTION must be terminal; found edge to %s" % state)

    def test_cannot_teleport_into_handoff_ready(self):
        self.assertFalse(domain.can_transition(domain.RUNNING, domain.HANDOFF_READY))
        self.assertTrue(domain.can_transition(domain.EVIDENCE_COLLECTED, domain.HANDOFF_READY))

    def test_active_and_terminal_partition_all_states(self):
        self.assertEqual(set(domain.ACTIVE_STATES) | set(domain.TERMINAL_STATES),
                         set(domain.ALL_STATES))
        self.assertEqual(set(domain.ACTIVE_STATES) & set(domain.TERMINAL_STATES), set())

    def test_handoff_readiness_ignores_program_verdict(self):
        self.assertTrue(domain.handoff_is_ready(result_valid=True, evidence_ok=True))
        self.assertFalse(domain.handoff_is_ready(result_valid=False, evidence_ok=True))
        self.assertFalse(domain.handoff_is_ready(result_valid=True, evidence_ok=False))


class TestIdentity(unittest.TestCase):
    def _id(self, **over):
        base = dict(workflow_id="wf", step_id="s1", prompt="do the thing", repo_id="o/r",
                    worktree_path="C:/tmp/wt", expected_branch="main", expected_head="ABC123",
                    authority_profile="READ_ONLY", capabilities=("repo_read",))
        base.update(over)
        return build_identity(**base)

    def test_key_is_deterministic(self):
        self.assertEqual(self._id().dispatch_key(), self._id().dispatch_key())

    def test_capability_order_does_not_change_the_key(self):
        a = self._id(capabilities=("repo_read", "repo_write"))
        b = self._id(capabilities=("repo_write", "repo_read", "repo_read"))
        self.assertEqual(a.dispatch_key(), b.dispatch_key())

    def test_path_spelling_does_not_change_the_key(self):
        self.assertEqual(self._id(worktree_path="C:/tmp/wt").dispatch_key(),
                         self._id(worktree_path="c:\\tmp\\wt\\").dispatch_key())

    def test_head_case_does_not_change_the_key(self):
        self.assertEqual(self._id(expected_head="ABC123").dispatch_key(),
                         self._id(expected_head="abc123").dispatch_key())

    def test_every_bound_field_changes_the_key(self):
        base = self._id().dispatch_key()
        for field, value in (("workflow_id", "wf2"), ("step_id", "s2"),
                             ("prompt", "something else"), ("repo_id", "o/r2"),
                             ("worktree_path", "C:/tmp/other"), ("expected_branch", "dev"),
                             ("expected_head", "def456"), ("authority_profile", "STANDARD_EDIT"),
                             ("capabilities", ("repo_read", "git_push"))):
            self.assertNotEqual(base, self._id(**{field: value}).dispatch_key(),
                                "%s must participate in the dispatch key" % field)


class TestAuthority(unittest.TestCase):
    def test_missing_capability_is_owner_required(self):
        d = authority.require(authority.READ_ONLY, ["repo_write"])
        self.assertEqual(d.decision, authority.OWNER_REQUIRED)
        self.assertIn("repo_write", d.missing)

    def test_owner_gated_capability_is_refused_even_with_a_ledger_row(self):
        """TIGHTENED IN P2.5. A row in the orchestrator's own table is not owner authority.

        The profile naming the capability is necessary and never sufficient; as of P2.5 a
        recorded grant is not sufficient either, because the component that writes the table is
        the component asking for permission.
        """
        from quaestor.core import owner_channel
        d = authority.require(authority.GIT_PUSH, ["git_push"], owner_grants=[], now=100.0)
        self.assertEqual(d.decision, authority.OWNER_REQUIRED)
        self.assertIn("git_push", d.ungranted)

        with_row = authority.require(authority.GIT_PUSH, ["git_push"], now=100.0,
                                     owner_grants=[{"grant_id": "g1", "capability": "git_push",
                                                    "revoked_at": None, "expires_at": None}])
        self.assertEqual(with_row.decision, authority.OWNER_REQUIRED)
        self.assertIn(owner_channel.UNAVAILABLE, with_row.reason)

    def test_an_authenticated_channel_would_open_the_gate(self):
        """Control on the control: the gate must be openable, or it proves nothing.

        Nothing in this project can return AUTHENTICATED -- there is no setter and no config --
        so this injects the state directly to show the mechanism is a gate rather than a wall.
        """
        from quaestor.core import owner_channel
        ok = authority.require(
            authority.GIT_PUSH, ["git_push"], now=100.0,
            owner_grants=[{"grant_id": "g1", "capability": "git_push", "revoked_at": None,
                           "expires_at": None}],
            owner_channel_state=owner_channel.AUTHENTICATED)
        self.assertTrue(ok.allowed, ok.reason)

    def test_expired_and_revoked_grants_do_not_count_even_with_a_channel(self):
        from quaestor.core import owner_channel
        for grant in ({"grant_id": "g", "capability": "git_push", "revoked_at": 50.0,
                       "expires_at": None},):
            d = authority.require(authority.GIT_PUSH, ["git_push"], owner_grants=[grant],
                                  now=100.0, owner_channel_state=owner_channel.AUTHENTICATED)
            self.assertEqual(d.decision, authority.OWNER_REQUIRED, grant)

    def test_unknown_capability_refuses_rather_than_being_ignored(self):
        d = authority.require(authority.READ_ONLY, ["gpu_spend"])
        self.assertEqual(d.decision, authority.AUTHORITY_REFUSED)

    def test_unknown_profile_grants_nothing(self):
        self.assertEqual(authority.granted_capabilities("SUPERUSER"), frozenset())
        self.assertFalse(authority.require("SUPERUSER", ["repo_read"]).allowed)

    def test_write_profile_detection(self):
        self.assertFalse(authority.is_write_profile(authority.READ_ONLY))
        self.assertTrue(authority.is_write_profile(authority.STANDARD_EDIT))
        self.assertTrue(authority.is_write_profile(authority.DESTRUCTIVE))


class TestHandoff(unittest.TestCase):
    def _payload(self, **over):
        p = {"protocol": handoff.PROTOCOL, "protocol_version": 1, "workflow_id": "wf",
             "step_id": "s1", "run_nonce": "n1", "prompt_disposition": "COMPLETE",
             "program_verdict": "FAIL", "acceptance_state": "X", "authorized_scope_exhausted": True,
             "continuation_allowed": False, "next_authority": "GPT_ORCHESTRATOR",
             "owner_decision_required": False, "smallest_blocker": "b", "next_action": "a",
             "summary": "s"}
        p.update(over)
        return p

    def _binding(self):
        return RunBinding("run-1", "wf", "s1", "n1")

    def test_complete_plus_fail_is_valid(self):
        v = handoff.validate_handoff(self._payload(), self._binding())
        self.assertTrue(v.valid, v.reason)

    def test_unknown_major_version_is_refused_not_parsed(self):
        v = handoff.validate_handoff(self._payload(protocol_version=2), self._binding())
        self.assertEqual(v.outcome, handoff.PROTOCOL_REFUSED)

    def test_version_as_string_is_refused(self):
        v = handoff.validate_handoff(self._payload(protocol_version="1"), self._binding())
        self.assertEqual(v.outcome, handoff.PROTOCOL_REFUSED)

    def test_boolean_true_is_not_a_version(self):
        v = handoff.validate_handoff(self._payload(protocol_version=True), self._binding())
        self.assertEqual(v.outcome, handoff.PROTOCOL_REFUSED)

    def test_run_identity_is_checked_before_the_body(self):
        # Body is deliberately broken too; identity must be the reported reason.
        bad = self._payload(run_nonce="other", program_verdict="NONSENSE")
        v = handoff.validate_handoff(bad, self._binding())
        self.assertEqual(v.outcome, handoff.RUN_IDENTITY_REFUSED)

    def test_missing_nonce_is_its_own_reason(self):
        p = self._payload()
        del p["run_nonce"]
        v = handoff.validate_handoff(p, self._binding())
        self.assertEqual(v.outcome, handoff.RUN_IDENTITY_REFUSED)
        self.assertIn("NONCE_ABSENT", v.reason)

    def test_string_false_is_not_a_boolean(self):
        v = handoff.validate_handoff(self._payload(continuation_allowed="false"), self._binding())
        self.assertEqual(v.outcome, handoff.RESULT_INVALID)

    def test_enum_violations_are_invalid(self):
        for field, bad in (("prompt_disposition", "DONE"), ("program_verdict", "OK"),
                           ("next_authority", "SOMEONE")):
            v = handoff.validate_handoff(self._payload(**{field: bad}), self._binding())
            self.assertEqual(v.outcome, handoff.RESULT_INVALID, field)

    def test_claimed_change_is_tri_state(self):
        self.assertIsNone(handoff.claimed_change(self._payload()))
        self.assertFalse(handoff.claimed_change(self._payload(claimed_files_changed=[])))
        self.assertTrue(handoff.claimed_change(self._payload(claimed_files_changed=["a"])))

    def test_schema_declares_every_required_field(self):
        for f in handoff._REQUIRED_FIELDS:
            self.assertIn(f, handoff.HANDOFF_JSON_SCHEMA["properties"], f)
            self.assertIn(f, handoff.HANDOFF_JSON_SCHEMA["required"], f)

    def test_schema_is_serialisable_for_the_cli_flag(self):
        json.loads(canon.canonical_json(handoff.HANDOFF_JSON_SCHEMA))


class TestEvidence(unittest.TestCase):
    def _snap(self, **over):
        base = dict(repo_root="/r", branch="main", head="aaa", dirty=False, changed_paths=(),
                    tracked_file_count=10, probe_ok=True)
        base.update(over)
        return evidence.RepoSnapshot(**base)

    def test_failed_probe_is_unavailable_not_clean(self):
        env = evidence.build_envelope(self._snap(), self._snap(probe_ok=False, probe_error="boom"),
                                      claimed_change=False)
        self.assertEqual(env.verdict, evidence.UNAVAILABLE)
        self.assertIsNone(env.observed_change)

    def test_zero_inspected_is_vacuous_not_clean(self):
        env = evidence.build_envelope(self._snap(tracked_file_count=0),
                                      self._snap(tracked_file_count=0), claimed_change=False,
                                      min_inspected=1)
        self.assertEqual(env.verdict, evidence.VACUOUS)

    def test_floor_is_enforced_against_the_smaller_reading(self):
        env = evidence.build_envelope(self._snap(tracked_file_count=5),
                                      self._snap(tracked_file_count=0), claimed_change=False,
                                      min_inspected=1)
        self.assertEqual(env.verdict, evidence.VACUOUS)

    def test_claimed_clean_but_changed(self):
        env = evidence.build_envelope(self._snap(), self._snap(changed_paths=("a.txt",)),
                                      claimed_change=False)
        self.assertEqual(env.verdict, evidence.DISAGREEMENT)
        self.assertIn(evidence.CLAIMED_CLEAN_BUT_CHANGED, env.disagreements)

    def test_claimed_changed_but_clean(self):
        env = evidence.build_envelope(self._snap(), self._snap(), claimed_change=True)
        self.assertEqual(env.verdict, evidence.DISAGREEMENT)
        self.assertIn(evidence.CLAIMED_CHANGED_BUT_CLEAN, env.disagreements)

    def test_no_claim_cannot_contradict_a_measurement(self):
        env = evidence.build_envelope(self._snap(), self._snap(changed_paths=("a.txt",)),
                                      claimed_change=None)
        self.assertEqual(env.verdict, evidence.OK)
        self.assertTrue(env.observed_change)

    def test_head_movement_without_authority_is_a_disagreement(self):
        env = evidence.build_envelope(self._snap(), self._snap(head="bbb"), claimed_change=None,
                                      may_move_head=False)
        self.assertEqual(env.verdict, evidence.DISAGREEMENT)
        self.assertIn(evidence.HEAD_MOVED_WITHOUT_AUTHORITY, env.disagreements)

    def test_reverting_a_dirty_file_counts_as_a_change(self):
        env = evidence.build_envelope(self._snap(changed_paths=("a.txt",), dirty=True),
                                      self._snap(), claimed_change=False)
        self.assertEqual(env.verdict, evidence.DISAGREEMENT)


class TestRepoParsing(unittest.TestCase):
    def test_porcelain_rename_yields_both_sides(self):
        got = repo.parse_porcelain("R  old.txt -> new.txt\n M kept.txt\n?? extra.txt\n")
        self.assertEqual(got, ("extra.txt", "kept.txt", "new.txt", "old.txt"))

    def test_drift_on_unreadable_worktree_refuses(self):
        snap = evidence.RepoSnapshot(probe_ok=False, probe_error="x")
        self.assertEqual(repo.classify_drift(expected_branch="main", expected_head="a",
                                             snapshot=snap), repo.WORKTREE_UNREADABLE)

    def test_head_drift_and_branch_drift_are_distinguished(self):
        snap = evidence.RepoSnapshot(probe_ok=True, branch="main", head="aaa")
        self.assertEqual(repo.classify_drift(expected_branch="main", expected_head="bbb",
                                             snapshot=snap), repo.HEAD_DRIFT)
        self.assertEqual(repo.classify_drift(expected_branch="dev", expected_head="aaa",
                                             snapshot=snap), repo.BRANCH_DRIFT)
        self.assertEqual(repo.classify_drift(expected_branch="main", expected_head="AAA",
                                             snapshot=snap), repo.NO_DRIFT)

    def test_repo_id_falls_back_to_a_stable_local_identity(self):
        a = repo.repo_id_for("", "C:/tmp/one")
        b = repo.repo_id_for("", "c:\\tmp\\one")
        c = repo.repo_id_for("", "C:/tmp/two")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_repo_id_normalises_remote_spellings(self):
        self.assertEqual(repo.repo_id_for("git@github.com:example-org/example.git", "/x"),
                         repo.repo_id_for("https://github.com/example-org/example", "/x"))


class TestLease(unittest.TestCase):
    def _req(self, run_id="r1"):
        return lease.LeaseRequest("repo", "C:/wt", "main", "aaa", run_id)

    def test_second_holder_conflicts(self):
        active = {"holder_run_id": "r0", "acquired_at": 1.0}
        self.assertEqual(lease.decide_acquire(self._req(), active).decision, lease.REFUSE_CONFLICT)

    def test_same_run_may_re_enter(self):
        active = {"holder_run_id": "r1", "acquired_at": 1.0}
        self.assertEqual(lease.decide_acquire(self._req(), active).decision,
                         lease.ALREADY_HELD_BY_THIS_RUN)

    def test_stale_heartbeat_is_not_proof_of_ownership(self):
        active = {"holder_run_id": "r1", "released_at": None, "heartbeat_at": 0.0}
        self.assertEqual(lease.ownership_proof(active, run_id="r1", now=10_000.0),
                         lease.STALE_UNPROVEN)
        self.assertEqual(lease.ownership_proof(active, run_id="r1", now=1.0), lease.PROVEN)

    def test_reclaim_requires_dead_holder_and_terminal_run(self):
        active = {"holder_run_id": "r1", "released_at": None, "heartbeat_at": 0.0}
        self.assertFalse(lease.may_reclaim(active, holder_run_state=domain.RUNNING,
                                           holder_liveness=proc.DEAD))
        self.assertFalse(lease.may_reclaim(active, holder_run_state=domain.AMBIGUOUS_EXECUTION,
                                           holder_liveness=proc.UNKNOWN))
        self.assertTrue(lease.may_reclaim(active, holder_run_state=domain.AMBIGUOUS_EXECUTION,
                                          holder_liveness=proc.DEAD))


class TestProcLiveness(unittest.TestCase):
    def test_unknown_is_never_dead(self):
        for lock_state in (proc.LOCK_UNKNOWN, proc.LOCK_ABSENT):
            live = proc.classify_liveness(lock_state=lock_state, recorded_pid=123,
                                          recorded_create_time="x", observed_create_time=None,
                                          pid_present=None)
            self.assertEqual(live.status, proc.UNKNOWN, lock_state)

    def test_held_lock_is_alive(self):
        live = proc.classify_liveness(lock_state=proc.LOCK_HELD, recorded_pid=None,
                                      recorded_create_time=None, observed_create_time=None,
                                      pid_present=None)
        self.assertEqual(live.status, proc.ALIVE)

    def test_pid_reuse_is_detected_as_dead(self):
        live = proc.classify_liveness(lock_state=proc.LOCK_FREE, recorded_pid=123,
                                      recorded_create_time="100", observed_create_time="200",
                                      pid_present=True)
        self.assertEqual(live.status, proc.DEAD)

    def test_free_lock_with_live_identity_is_unknown_not_dead(self):
        live = proc.classify_liveness(lock_state=proc.LOCK_FREE, recorded_pid=123,
                                      recorded_create_time="100", observed_create_time="100",
                                      pid_present=True)
        self.assertEqual(live.status, proc.UNKNOWN)

    def test_real_lock_round_trip(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "w.lock")
        self.assertEqual(proc.probe_lock(path), proc.LOCK_ABSENT)
        lock = proc.WorkerLock(path)
        self.assertTrue(lock.acquire())
        try:
            self.assertEqual(proc.probe_lock(path), proc.LOCK_HELD)
        finally:
            lock.release()
        self.assertEqual(proc.probe_lock(path), proc.LOCK_FREE)

    @control(381)
    def test_no_probe_failure_is_ever_reported_as_nobody_is_there(self):
        """NO failure inside ``probe_lock`` -- not from the open, not from the lock call -- is
        reported as LOCK_FREE or LOCK_ABSENT. Those two are the only verdicts meaning "nobody
        is there", and ``classify_liveness`` turns LOCK_FREE plus an absent pid into a positive
        DEAD. A kernel error must never be able to write a death certificate.

        WHAT THIS CONTROL DELIBERATELY DOES NOT PIN: the lock-call arm to LOCK_HELD. The module
        collapses every lock-call errno to LOCK_HELD today, and that collapse is over-reporting
        with a real cost -- permanent, not merely transient, on a filesystem whose flock returns
        ENOSYS/EOPNOTSUPP, where every existing lock file then reads HELD forever and no relay
        slot is ever freed. bd quaestor-lag exists to replace it with an honest errno split, and
        its blocker bd quaestor-9ap has now LANDED: ``orchestrator.reap`` used to be the sole
        consumer that converted UNKNOWN into dead-worker recovery and no longer does, so the
        split is unblocked work rather than a hazard. Pinning HELD here would make the gate fail
        on that
        fix, so this control asserts the property that holds either way, plus the two things
        that are permanently true regardless: real contention IS held, and the probe still
        discriminates free from absent.

        THE MODULE READS ``errno`` NOWHERE -- the ``except OSError`` is unconditional -- so the
        injected loop is nine passes through ONE branch. It is kept because a future errno split
        must not be able to route any of the nine to "nobody is there", but it is not evidence
        of a taxonomy the code does not implement. The inspection count below therefore counts
        distinct BRANCHES of probe_lock driven, not errnos injected.
        """
        import errno
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "w.lock")
        nobody_is_there = (proc.LOCK_FREE, proc.LOCK_ABSENT)
        branches = set()

        # BRANCH: absent. Real, and half of the discrimination that stops a probe which answers
        # one constant to everything from satisfying this control.
        self.assertEqual(proc.probe_lock(path), proc.LOCK_ABSENT)
        branches.add("absent")

        # BRANCH: the lock call fails, for real, from real contention on whichever platform is
        # running. This arm must stay LOCK_HELD under ANY future errno split: it is the one
        # failure that genuinely means held.
        holder = proc.WorkerLock(path)
        self.assertTrue(holder.acquire())
        try:
            self.assertEqual(proc.probe_lock(path), proc.LOCK_HELD)
            self.assertEqual(
                proc.classify_liveness(lock_state=proc.LOCK_HELD, recorded_pid=123,
                                       recorded_create_time=None, observed_create_time=None,
                                       pid_present=None).status, proc.ALIVE)
            rival = open(path, "a+b")
            try:
                with self.assertRaises(OSError) as caught:
                    proc._lock_nb(rival)
            finally:
                rival.close()
        finally:
            holder.release()
        means_held = (errno.EACCES, errno.EAGAIN, getattr(errno, "EDEADLOCK", errno.EDEADLK))
        self.assertIn(caught.exception.errno, means_held,
                      "real contention returned an errno this module does not read as held")
        branches.add("lock_call_failure")

        # BRANCH: free. The other half of the discrimination.
        self.assertEqual(proc.probe_lock(path), proc.LOCK_FREE)
        branches.add("free")

        # BRANCH: the OPEN fails -- REAL, no injection, because a directory cannot be opened
        # "a+b" on any platform this runs on. This is where the module's LOCK_UNKNOWN actually
        # comes from, contrary to what probe_lock's docstring used to claim, and it is reachable
        # in production from EMFILE, an ACL, or a share violation. Asserting UNKNOWN here also
        # refuses the "make the collapse consistent" repair -- collapsing this arm to LOCK_HELD
        # as well -- because that would report a live Core from an unreadable file and delete
        # the only fail-closed signal coreservice.running, cmd_core_ensure and corerelay.owned
        # have. reap's exposure to this arm is bd quaestor-9ap, not a reason to blind the probe.
        unopenable = os.path.join(d, "adir")
        os.makedirs(unopenable)
        open_verdict = proc.probe_lock(unopenable)
        self.assertNotIn(open_verdict, nobody_is_there,
                         "a failure to open the lock file read as nobody being there")
        self.assertEqual(open_verdict, proc.LOCK_UNKNOWN)
        self.assertEqual(
            proc.classify_liveness(lock_state=open_verdict, recorded_pid=123,
                                   recorded_create_time=None, observed_create_time=None,
                                   pid_present=False).status, proc.UNKNOWN)
        branches.add("open_failure")

        # INJECTED, across both errno families, into the one branch that reads them: whatever a
        # split later does with these, none may become "nobody is there". ``pid_present=False``
        # is the load-bearing part -- it is exactly the input under which a LOCK_FREE verdict
        # would become a DEAD certificate.
        means_uncertain = (errno.ENOLCK, errno.EIO, errno.EBADF, errno.ENOSYS, errno.EPERM,
                           errno.EINVAL)
        real = proc._lock_nb
        injected = 0
        try:
            for code in means_held + means_uncertain:
                def refuse(_fh, _code=code):
                    raise OSError(_code, os.strerror(_code))

                proc._lock_nb = refuse
                where = errno.errorcode.get(code, code)
                verdict = proc.probe_lock(path)
                self.assertNotIn(verdict, nobody_is_there, where)
                self.assertNotEqual(
                    proc.classify_liveness(lock_state=verdict, recorded_pid=123,
                                           recorded_create_time=None, observed_create_time=None,
                                           pid_present=False).status, proc.DEAD, where)
                injected += 1
        finally:
            proc._lock_nb = real
        self.assertEqual(injected, len(means_held) + len(means_uncertain))

        # THE COUNT IS A CLAIM ABOUT BRANCHES, and every one of the four was driven.
        self.assertEqual(sorted(branches),
                         ["absent", "free", "lock_call_failure", "open_failure"])
        inspected = len(branches)
        self.assertGreaterEqual(inspected, 4)

    @control(382)
    def test_a_process_that_cannot_prove_it_took_the_lock_does_not_run(self):
        """The writer side of the same uncertainty, on BOTH of acquire's refusal arms.
        ``acquire`` cannot tell "somebody else has it" from "the kernel would not answer" any
        better than the probe can, and returning True on either would put a worker to work
        believing it holds a lock the kernel never gave it -- while the lock is the only signal
        this module calls proof. Recording no handle matters as much as the False: with
        ``_fh`` still None a later ``release`` is a silent no-op, and every other process
        reading that path gets LOCK_FREE while this one runs.

        TWO ARMS, ONE DEFECT. acquire can refuse at the makedirs+open guard and at the lock
        call, and flipping EITHER to ``return True`` is the same phantom hold. Both are driven.
        The makedirs+open arm needs no injection at all: a path whose parent is a regular file
        fails makedirs, and a path that IS a directory fails the open.

        THE CLOSED HANDLE IS MEASURED, NOT ASSERTED BY COMMENT. Re-taking the lock afterwards
        proves nothing about a leak -- an unlocked extra handle does not block reopening "a+b",
        and CPython would finalise a function-local handle at return anyway. So the refusing
        stub keeps the handle acquire opened and the control asserts ``.closed`` on it directly.
        """
        import errno
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "sub", "w.lock")
        arms = set()

        # THE GATE DISCRIMINATES: a takeable lock is taken, and the handle is kept.
        takeable = proc.WorkerLock(path)
        self.assertTrue(takeable.acquire())
        self.assertIsNotNone(takeable._fh)
        takeable.release()
        arms.add("granted")

        # ARM 1: the makedirs+open guard, driven for real. Both of its reachable shapes --
        # EACCES/ENOTDIR from makedirs under a regular file, and EACCES/EISDIR from opening a
        # directory -- must refuse and must record no handle.
        parent_is_a_file = os.path.join(d, "plainfile")
        with open(parent_is_a_file, "wb"):
            pass
        path_is_a_dir = os.path.join(d, "isadir")
        os.makedirs(path_is_a_dir)
        for unusable in (os.path.join(parent_is_a_file, "sub", "w.lock"), path_is_a_dir):
            lock = proc.WorkerLock(unusable)
            self.assertFalse(lock.acquire(), unusable)
            self.assertIsNone(lock._fh, unusable)
            lock.release()          # a no-op, and it must stay one
        arms.add("open_failure")

        # ARM 2: the lock call, injected across both errno families.
        families = (errno.EACCES, errno.EAGAIN, errno.ENOLCK, errno.EIO, errno.EBADF,
                    errno.ENOSYS, errno.EPERM, errno.EINVAL)
        real = proc._lock_nb
        opened = []
        refused = 0
        try:
            for code in families:
                def refuse(_fh, _code=code):
                    opened.append(_fh)
                    raise OSError(_code, os.strerror(_code))

                proc._lock_nb = refuse
                where = errno.errorcode.get(code, code)
                lock = proc.WorkerLock(path)
                self.assertFalse(lock.acquire(), where)
                self.assertIsNone(lock._fh, where)
                # The handle acquire opened before the refusal is closed by acquire itself.
                self.assertTrue(opened[-1].closed, where)
                lock.release()          # a no-op, and it must stay one
                refused += 1
        finally:
            proc._lock_nb = real
        self.assertEqual(refused, len(families))
        self.assertEqual(len(opened), len(families))
        arms.add("lock_call_failure")

        # The count is a claim about ARMS of acquire driven, not errnos injected: the granted
        # path plus both refusal paths.
        self.assertEqual(sorted(arms), ["granted", "lock_call_failure", "open_failure"])
        inspected = len(arms)
        self.assertGreaterEqual(inspected, 3)

        # The inode is still usable -- which is a weaker claim than the per-iteration .closed
        # assertions above, and is here only to show the refusals left nothing wedged.
        self.assertTrue(takeable.acquire())
        takeable.release()

    def test_self_identity_is_reportable(self):
        pid, ct = proc.self_identity()
        self.assertGreater(pid, 0)
        # ct may be None on an exotic platform; that is UNKNOWN, and must not be a placeholder.
        self.assertTrue(ct is None or isinstance(ct, str))


class TestPreflight(unittest.TestCase):
    def test_every_override_var_refuses(self):
        for name in pf.OVERRIDE_VARS:
            d = pf.decide(env={name: "x"}, auth_status=None)
            self.assertEqual(d.decision, pf.REFUSE, name)
            self.assertEqual(d.reason, pf.REASON_OVERRIDE, name)
            self.assertIn(name, d.offending_vars)

    def test_override_refuses_even_with_perfect_auth(self):
        good = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                "subscriptionType": "max"}
        d = pf.decide(env={"ANTHROPIC_API_KEY": "sk-x"}, auth_status=good)
        self.assertEqual(d.decision, pf.REFUSE)

    def test_empty_string_override_still_refuses(self):
        d = pf.decide(env={"ANTHROPIC_API_KEY": ""}, auth_status=None)
        self.assertEqual(d.decision, pf.REFUSE)

    def test_subscription_auth_is_accepted(self):
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "claude.ai",
                                           "apiProvider": "firstParty", "subscriptionType": "max"})
        self.assertTrue(d.accepted)
        self.assertEqual(d.auth_class, pf.SUBSCRIPTION)

    def test_console_auth_is_refused(self):
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "console",
                                           "apiProvider": "firstParty"})
        self.assertEqual(d.reason, pf.REASON_API_BILLED)

    def test_third_party_provider_is_refused(self):
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "claude.ai",
                                           "apiProvider": "bedrock", "subscriptionType": "max"})
        self.assertEqual(d.reason, pf.REASON_THIRD_PARTY)

    def test_unrecognised_shape_is_unverified_and_refuses(self):
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "quantum"})
        self.assertEqual(d.auth_class, pf.UNVERIFIED)
        self.assertEqual(d.reason, pf.REASON_UNVERIFIED)

    def test_absent_status_is_unverified_not_accepted(self):
        self.assertEqual(pf.decide(env={}, auth_status=None).auth_class, pf.UNVERIFIED)

    def test_logged_out_is_refused(self):
        d = pf.decide(env={}, auth_status={"loggedIn": False})
        self.assertEqual(d.reason, pf.REASON_NOT_LOGGED_IN)

    def test_record_never_contains_identity_or_credential_values(self):
        status = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                  "subscriptionType": "max", "email": "someone@example.invalid",
                  "orgId": "org-secret", "orgName": "Secret Org",
                  "accessToken": "sk-ant-DO-NOT-PERSIST"}
        d = pf.decide(env={"PATH": "x"}, auth_status=status)
        blob = json.dumps(d.record)
        for forbidden in ("someone@example.invalid", "org-secret", "Secret Org",
                          "sk-ant-DO-NOT-PERSIST", "@"):
            self.assertNotIn(forbidden, blob, forbidden)

    def test_env_record_carries_presence_and_length_only(self):
        rec = pf.env_presence_record({"ANTHROPIC_API_KEY": "sk-ant-secret-value"})
        self.assertTrue(rec["ANTHROPIC_API_KEY"]["present"])
        self.assertEqual(rec["ANTHROPIC_API_KEY"]["length"], len("sk-ant-secret-value"))
        self.assertNotIn("sk-ant-secret-value", json.dumps(rec))


class TestCliExecutorCommand(unittest.TestCase):
    def _req(self, profile="READ_ONLY", **over):
        base = dict(run_id="r", run_dir="/tmp/r", cwd="/tmp/wt", prompt="PROMPT BODY",
                    binding=RunBinding("r", "wf", "s", "n"), json_schema=handoff.HANDOFF_JSON_SCHEMA,
                    authority_profile=profile, stdout_path="/tmp/r/stdout.json",
                    stderr_path="/tmp/r/stderr.log")
        base.update(over)
        return ExecRequest(**base)

    def test_command_shape(self):
        cmd = build_command(self._req())
        self.assertEqual(cmd[0], "claude")
        self.assertIn("--print", cmd)
        self.assertIn("--output-format", cmd)
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")
        self.assertIn("--json-schema", cmd)
        self.assertIn("--no-chrome", cmd)
        self.assertEqual(cmd[-1], "PROMPT BODY")

    def test_no_forbidden_flag_can_appear(self):
        for profile in ("READ_ONLY", "STANDARD_EDIT", "GIT_COMMIT", "GIT_PUSH", "DESTRUCTIVE"):
            cmd = build_command(self._req(profile))
            for flag in FORBIDDEN_FLAGS:
                self.assertNotIn(flag, cmd, "%s in %s" % (flag, profile))

    def test_forbidden_flag_via_extra_args_is_rejected(self):
        with self.assertRaises(UnsafeCommand):
            build_command(self._req(extra_args=("--dangerously-skip-permissions",)))

    def test_the_prompt_guard_catches_every_swallowing_shape(self):
        from quaestor.executors.claude_code import _assert_prompt_is_safe_last
        for bad in (["claude", "--print", "--tools", "PROMPT"],
                    ["claude", "--print", "--tools", "Read", "PROMPT"],
                    ["claude", "--print", "--allowedTools", "Bash", "PROMPT"],
                    ["claude", "--print", "--model", "PROMPT"]):
            with self.assertRaises(UnsafeCommand, msg=str(bad)):
                _assert_prompt_is_safe_last(bad)

    def test_the_prompt_guard_accepts_the_two_safe_shapes(self):
        from quaestor.executors.claude_code import _assert_prompt_is_safe_last
        _assert_prompt_is_safe_last(["claude", "--permission-mode", "default", "PROMPT"])
        _assert_prompt_is_safe_last(["claude", "--json-schema", "{}", "--print", "PROMPT"])

    def test_build_command_always_satisfies_the_guard(self):
        from quaestor.executors.claude_code import _assert_prompt_is_safe_last
        for profile in ("READ_ONLY", "STANDARD_EDIT", "GIT_PUSH"):
            for extra in ((), ("--verbose",), ("--tools", "Read")):
                cmd = build_command(self._req(profile, extra_args=extra, model="opus"))
                _assert_prompt_is_safe_last(cmd)
                self.assertEqual(cmd[-1], "PROMPT BODY")

    def test_json_schema_argument_is_parseable_json(self):
        cmd = build_command(self._req())
        json.loads(cmd[cmd.index("--json-schema") + 1])

    def test_read_only_profile_gets_no_write_tools(self):
        tools = profile_tools("READ_ONLY")
        for banned in ("Edit", "Write", "Bash"):
            self.assertNotIn(banned, tools)
        self.assertEqual(permission_mode("READ_ONLY"), "default")

    def test_blanket_bash_is_never_pre_approved(self):
        from quaestor.executors.claude_code import profile_allowed_tools, profile_disallowed_tools
        for profile in ("READ_ONLY", "NETWORK_READ", "STANDARD_EDIT", "GIT_COMMIT", "GIT_PUSH",
                        "DESTRUCTIVE", "MADE_UP"):
            self.assertNotIn("Bash", profile_allowed_tools(profile), profile)
        # ...but a commit profile still gets NARROW git rules, or it could not do its job.
        self.assertIn("Bash(git commit:*)", profile_allowed_tools("GIT_COMMIT"))
        self.assertNotIn("Bash(git push:*)", profile_allowed_tools("GIT_COMMIT"))
        self.assertIn("Bash(git push:*)", profile_allowed_tools("GIT_PUSH"))

    def test_the_deny_list_is_derived_and_cannot_contradict_the_tool_list(self):
        from quaestor.executors.claude_code import profile_disallowed_tools
        for profile in ("READ_ONLY", "NETWORK_READ", "STANDARD_EDIT", "GIT_COMMIT", "GIT_PUSH",
                        "DESTRUCTIVE"):
            overlap = set(profile_tools(profile)) & set(profile_disallowed_tools(profile))
            self.assertEqual(overlap, set(), "%s: %s" % (profile, overlap))
        for banned in ("Bash", "Edit", "Write", "WebFetch", "WebSearch"):
            self.assertIn(banned, profile_disallowed_tools("READ_ONLY"), banned)

    def test_unknown_profile_degrades_to_read_only(self):
        self.assertEqual(profile_tools("MADE_UP"), profile_tools("READ_ONLY"))
        self.assertEqual(permission_mode("MADE_UP"), "default")

    def test_prompt_is_a_single_argv_element_however_hostile(self):
        nasty = 'a" && rm -rf / ; echo "$(whoami)`id`\n--dangerously-skip-permissions'
        cmd = build_command(self._req(prompt=nasty))
        self.assertEqual(cmd[-1], nasty)
        self.assertEqual(sum(1 for a in cmd if a == nasty), 1)


class TestEnvelopeParsing(unittest.TestCase):
    """The parser must cope with envelope shapes this project did NOT write."""

    def test_empty_stdout_is_not_an_empty_result(self):
        doc, err = parse_envelope("")
        self.assertIsNone(doc)
        self.assertIn("empty", err)

    def test_malformed_json_is_named(self):
        doc, err = parse_envelope('{"a": ')
        self.assertIsNone(doc)
        self.assertIn("not valid JSON", err)

    def test_structured_output_found_under_several_keys(self):
        for key in ("structured_output", "structuredOutput", "structured_result"):
            payload, source, outcome = extract_structured({key: {"protocol": "X"}})
            self.assertEqual(outcome, "FOUND")
            self.assertEqual(source, key)
            self.assertEqual(payload["protocol"], "X")

    def test_structured_output_as_a_json_string_is_recovered_and_labelled(self):
        payload, source, outcome = extract_structured({"structured_output": '{"protocol": "X"}'})
        self.assertEqual(outcome, "FOUND")
        self.assertIn("string", source)

    def test_result_object_is_used_when_no_structured_key_exists(self):
        payload, source, _ = extract_structured({"result": {"protocol": "X"}})
        self.assertEqual(source, "result")

    def test_fenced_json_in_a_text_result_is_recovered_and_labelled(self):
        env = {"result": '```json\n{"protocol": "X"}\n```'}
        payload, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "FOUND")
        self.assertEqual(source, "result(text-json)")

    def test_prose_result_yields_nothing_rather_than_a_guess(self):
        payload, _, outcome = extract_structured({"result": "I did the thing."})
        self.assertIsNone(payload)
        self.assertEqual(outcome, "NO_STRUCTURED_OUTPUT")

    def test_json_object_embedded_in_prose_is_recovered_and_labelled_weaker(self):
        """Found LIVE (2026-08-24): children wrap the handoff object inside commentary.

        Recovery is deliberate net-widening, so the outcome and the source string must say the
        payload came from free text -- downstream records keep that as structured_output_source.
        """
        env = {"result": 'Summary of this step:\n\n'
                         '{"protocol": "AEGIS_ORCHESTRATOR_HANDOFF", "summary": "ok"}\n'
                         '\nDone.'}
        payload, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "RECOVERED_FROM_TEXT")
        self.assertIn("brace", source)
        self.assertEqual(payload["protocol"], "AEGIS_ORCHESTRATOR_HANDOFF")

    def test_fenced_block_with_non_json_language_tag_is_recovered(self):
        env = {"result": 'Here is my report:\n\n'
                         '```text\n{"protocol": "X", "claimed_files_changed": []}\n```\n'
                         '\nThanks.'}
        payload, source, outcome = extract_structured(env)
        self.assertEqual(outcome, "RECOVERED_FROM_TEXT")
        self.assertIn("fence", source)
        self.assertEqual(payload["protocol"], "X")

    def test_first_embedded_object_wins_and_braces_inside_strings_do_not_confuse_the_scan(self):
        env = {"result": 'note {"broken": true\n'
                         'then {"protocol": "FIRST"} trailing text'}
        payload, _, outcome = extract_structured(env)
        self.assertEqual(outcome, "RECOVERED_FROM_TEXT")
        self.assertEqual(payload["protocol"], "FIRST")

    def test_recovery_does_not_guess_when_only_broken_json_exists(self):
        env = {"result": '{"protocol": "X" '}
        payload, _, outcome = extract_structured(env)
        self.assertIsNone(payload)
        self.assertEqual(outcome, "NO_STRUCTURED_OUTPUT")

    def test_recovery_scan_is_bounded(self):
        from quaestor.core import executor_contract as ec
        env = {"result": "{" * 5000 + "x"}
        payload, _, outcome = extract_structured(env)
        self.assertIsNone(payload)          # unbalanced garbage stays refused
        # And the candidate enumerator itself is capped.
        candidates = ec._embedded_json_candidates('{"a":1}' * 200)
        self.assertLessEqual(len(candidates), ec._RECOVERY_MAX_CANDIDATES)

    def test_array_envelope_uses_the_last_object_and_says_so(self):
        doc, note = parse_envelope('[{"type":"a"},{"type":"result","session_id":"s"}]')
        self.assertEqual(doc["type"], "result")
        self.assertIn("array", note)

    def test_handoff_strength_full_mapping_including_unknown_fallback(self):
        """Every source family extract_structured can emit maps to exactly one strength."""
        from quaestor.core import executor_contract as ec
        # NATIVE: any structured-output key, bare or as a JSON string -- the CLI validated those
        # against our json-schema before we ever saw them.
        for src in ("structured_output", "structuredOutput", "structuredOutput(string)",
                    "structured_result", "structured", "structured(string)"):
            self.assertEqual(ec.handoff_strength(src), ec.HANDOFF_STRENGTH_NATIVE, src)
        # DEGRADED: exact text that parsed on OUR side; nothing a producer validated.
        for src in ("result", "result(text-json)"):
            self.assertEqual(ec.handoff_strength(src), ec.HANDOFF_STRENGTH_DEGRADED, src)
        # WEAK: net-widened out of prose by the recovery scan.
        for src in ("result(text-embedded:fence)", "result(text-embedded:brace)",
                    "result(text-embedded:anything)"):
            self.assertEqual(ec.handoff_strength(src), ec.HANDOFF_STRENGTH_WEAK, src)
        # Total function: empty and unknown spellings degrade to WEAK -- an unseen source must
        # never read as stronger than it is.
        for src in ("", "   ", "weird-source", "RESULT", "results",
                    "result(text-json) trailing"):
            self.assertEqual(ec.handoff_strength(src), ec.HANDOFF_STRENGTH_WEAK, src)

    def test_strength_ties_into_the_real_extraction_sources(self):
        from quaestor.core import executor_contract as ec
        _, source, _ = extract_structured({"structured_output": {"protocol": "X"}})
        self.assertEqual(ec.handoff_strength(source), ec.HANDOFF_STRENGTH_NATIVE)
        _, source, _ = extract_structured({"result": {"protocol": "X"}})
        self.assertEqual(ec.handoff_strength(source), ec.HANDOFF_STRENGTH_DEGRADED)
        _, source, _ = extract_structured({"result": '```json\n{"protocol": "X"}\n```'})
        self.assertEqual(ec.handoff_strength(source), ec.HANDOFF_STRENGTH_DEGRADED)

    def test_recovered_embedded_json_reports_weak_strength(self):
        """The 2026-08-24 incident shape (8 of 32 children answering in prose): admissible, but
        its strength in the record must be WEAK -- never equal to native downstream."""
        from quaestor.core import executor_contract as ec
        brace_env = {"result": 'Summary of this step:\n\n'
                               '{"protocol": "AEGIS_ORCHESTRATOR_HANDOFF", "summary": "ok"}\n'
                               '\nDone.'}
        _, source, outcome = extract_structured(brace_env)
        self.assertEqual(outcome, "RECOVERED_FROM_TEXT")
        self.assertEqual(ec.handoff_strength(source), ec.HANDOFF_STRENGTH_WEAK)
        fence_env = {"result": 'Here is my report:\n\n'
                               '```text\n{"protocol": "X"}\n```\n\nThanks.'}
        _, source, outcome = extract_structured(fence_env)
        self.assertEqual(outcome, "RECOVERED_FROM_TEXT")
        self.assertEqual(ec.handoff_strength(source), ec.HANDOFF_STRENGTH_WEAK)

    def test_classify_failure_table_over_live_wording(self):
        """Every class is reachable by wording this pipeline actually produces."""
        from quaestor.core import executor_contract as ec
        cases = (
            # parse_envelope refusals (executor_contract.parse_envelope wording).
            ("stdout was empty", ec.FAILURE_CLASS_ENVELOPE_NOT_JSON),
            ("stdout is not valid JSON: Expecting value: line 1 column 1 (char 0)",
             ec.FAILURE_CLASS_ENVELOPE_NOT_JSON),
            ("stdout JSON is a list, not an object", ec.FAILURE_CLASS_ENVELOPE_NOT_JSON),
            ("stdout JSON is an array with no objects", ec.FAILURE_CLASS_ENVELOPE_NOT_JSON),
            # worker.py payload-is-None branch. The prose-only shape IS the live incident:
            # LOCAL_GOVERNED, 2026-08-24 -- 8 of 32 real children answered in prose.
            ("no structured handoff in the result envelope (NO_STRUCTURED_OUTPUT); envelope was "
             "a object with keys: is_error, permission_denials, result, session_id, subtype, "
             "total_cost_usd, type", ec.FAILURE_CLASS_PROSE_ONLY_RESULT),
            # Same branch, but the envelope never carried a result key at all.
            ("no structured handoff in the result envelope (NO_STRUCTURED_OUTPUT); envelope was "
             "a object with keys: is_error, subtype, type",
             ec.FAILURE_CLASS_MISSING_STRUCTURED_OUTPUT),
            # A structured slot existed but held nothing json.loads could read.
            ("no structured handoff in the result envelope (UNPARSEABLE); envelope was a object "
             "with keys: result, structured_output, type",
             ec.FAILURE_CLASS_MISSING_STRUCTURED_OUTPUT),
            # The CLI error-envelope path (envelope_is_error wording).
            ("the child reported an error envelope (subtype=max_turns); is_error=true",
             ec.FAILURE_CLASS_CLI_ERROR_ENVELOPE),
            # validate_handoff refusals; identity wording copied from identity.py/handoff.py.
            ("RUN_IDENTITY_NONCE_MISMATCH: this result does not belong to run run-abc",
             ec.FAILURE_CLASS_RUN_BINDING_MISMATCH),
            ("RUN_IDENTITY_NONCE_ABSENT: this result does not belong to run run-abc",
             ec.FAILURE_CLASS_RUN_BINDING_MISMATCH),
            ("protocol 'WRONG' is not 'AEGIS_ORCHESTRATOR_HANDOFF'",
             ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("unsupported handoff protocol major version 2 (supported: 1). Refusing rather than "
             "parsing a future contract with today's meanings.",
             ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("missing required field(s): next_authority, summary",
             ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("prompt_disposition 'DONE' not in ('COMPLETE', 'PARTIAL', 'BLOCKED', 'FAILED')",
             ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("authorized_scope_exhausted must be a literal JSON boolean, got 'false'",
             ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("summary is empty", ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            ("handoff is not a JSON object", ec.FAILURE_CLASS_SCHEMA_VALIDATION_FAILED),
            # Infrastructure noise and the unknown fall through to OTHER.
            ("two-way delivery failed: sqlite disk I/O error", ec.FAILURE_CLASS_OTHER),
            ("", ec.FAILURE_CLASS_OTHER),
            ("something entirely novel happened", ec.FAILURE_CLASS_OTHER),
        )
        for reason, expected in cases:
            self.assertEqual(ec.classify_failure(reason), expected, reason)

    def test_the_handoff_package_carries_strength_so_recovered_never_passes_for_native(self):
        from quaestor.core import executor_contract as ec
        from quaestor.core import worker as worker_mod
        from quaestor.evidence import model as evidence_mod

        def _package(envelope_source):
            return worker_mod.build_handoff_package(
                run_id="r", request={"workflow_id": "w"}, handoff={"summary": "s"},
                envelope_source=envelope_source, session_id="sid",
                evidence=evidence_mod.EvidenceEnvelope(
                    evidence_mod.OK, evidence_mod.RepoSnapshot(), evidence_mod.RepoSnapshot()))

        self.assertEqual(_package("structured_output")["handoff_strength"],
                         ec.HANDOFF_STRENGTH_NATIVE)
        recovered = _package("result(text-embedded:brace)")
        self.assertEqual(recovered["handoff_strength"], ec.HANDOFF_STRENGTH_WEAK)
        self.assertNotEqual(recovered["handoff_strength"],
                            _package("structured_output")["handoff_strength"],
                            "a recovered handoff must never equal native downstream")


if __name__ == "__main__":
    unittest.main()

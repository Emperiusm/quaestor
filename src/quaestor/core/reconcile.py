"""reconcile -- decide what happened to a run whose worker we are no longer watching.

THE ONE RULE THAT OUTRANKS EVERYTHING ELSE HERE
-----------------------------------------------
    AN AMBIGUOUS WRITE EXECUTION MUST NOT AUTO-REDISPATCH.

A worker that vanished may already have edited files, committed, pushed, or started something
external. "Just try again" is how one lost message becomes two executions of a side effect. So
reconciliation produces a CLASSIFICATION and, separately, a narrow, provable
``auto_redispatch_allowed`` flag that is True in exactly one situation: we can demonstrate the
child never started, so there is nothing to duplicate.

The source deployment's lineage: ``is_fresh`` returns tri-state because collapsing UNKNOWN into False is how an
absence of evidence turns into a kill. Here, collapsing UNKNOWN into "dead, so retry" is how an
absence of evidence turns into a double write.

WHAT THE OS WILL NOT GIVE US, STATED PLAINLY
--------------------------------------------
Once a process is gone and no receipt was written, its exit code is UNRECOVERABLE on both Windows
and POSIX -- there is no supported way for an unrelated process to learn how a non-child process
terminated after the fact. This control plane does not fabricate one. That gap is exactly why
``exit.json`` is written before anything is parsed, and why its ABSENCE is meaningful rather than
merely inconvenient.

PURE core; ``reconcile_run`` wires in the readings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core import domain
from quaestor.core import proc
from quaestor.core import runfiles

# Classifications
RUNNING = "RUNNING"
RESULT_RECEIVED = "RESULT_RECEIVED"
PROCESS_FAILED = "PROCESS_FAILED"
WORKER_FAILED = "WORKER_FAILED"
INTERRUPTED = "INTERRUPTED"
AMBIGUOUS_EXECUTION = "AMBIGUOUS_EXECUTION"
TERMINAL_ALREADY = "TERMINAL_ALREADY"
#: Admitted, but the spawn step was never reached, so no worker was ever recorded and no child
#: can exist. This is a KNOWN absence, not an unknown one -- see the note in ``classify``.
NEVER_DISPATCHED = "NEVER_DISPATCHED"

#: Classification -> the execution state it maps onto. RUNNING and TERMINAL_ALREADY map to
#: nothing: the first means leave it alone, the second means it is already decided.
STATE_FOR = {
    PROCESS_FAILED: domain.CLAUDE_FAILED,
    WORKER_FAILED: domain.WORKER_FAILED,
    INTERRUPTED: domain.INTERRUPTED,
    AMBIGUOUS_EXECUTION: domain.AMBIGUOUS_EXECUTION,
}


@dataclass(frozen=True)
class Reconciliation:
    classification: str
    reason: str
    auto_redispatch_allowed: bool = False
    recovery_authority: str = domain.GPT_ORCHESTRATOR
    target_state: str | None = None
    evidence: Mapping = field(default_factory=dict)


#: States a run occupies BEFORE the dispatcher's spawn step. Reaching the spawn step is what
#: creates a worker row, so "no worker row AND still in one of these" is decidable.
PRE_SPAWN_STATES = (domain.CREATED, domain.PREFLIGHT, domain.LEASED)


def classify(*, run_state: str, is_write: bool, liveness: str, worker_started: bool,
             exit_receipt: Mapping | None, result_valid: bool | None,
             observed_change: bool | None, spawn_recorded: bool = True) -> Reconciliation:
    """What happened? PURE. NEVER raises.

    ``worker_started`` means the worker recorded its own identity -- which happens BEFORE it can
    possibly launch a child. Its absence is therefore the one honest proof that no child ran.

    ``spawn_recorded`` distinguishes "we could not establish liveness" from "there was never
    anything to establish liveness OF". Defaults True so every existing caller is unchanged.

    WHY THAT DISTINCTION EARNED ITS OWN BRANCH. A run admitted with ``spawn=False`` has no worker
    row, so ``read_liveness`` observes a lock that was never taken and returns UNKNOWN -- and the
    UNKNOWN branch below then reports AMBIGUOUS_EXECUTION, which means "a write may have landed;
    a human must inspect the worktree". For a run that structurally never executed that is a
    FALSE ALARM, and a false alarm on the one signal that must always be believed is expensive:
    it trains an operator to discount it. UNKNOWN is still never DEAD -- this branch does not
    weaken that. It says that when the dispatcher never reached the spawn step, the absence of a
    process is recorded fact, not an unresolved question.
    """
    ev = {"run_state": run_state, "is_write": bool(is_write), "liveness": liveness,
          "worker_started": bool(worker_started), "spawn_recorded": bool(spawn_recorded),
          "exit_receipt_present": exit_receipt is not None,
          "result_valid": result_valid, "observed_change": observed_change}

    if domain.is_terminal(run_state):
        return Reconciliation(TERMINAL_ALREADY, "run is already in terminal state %s" % run_state,
                              False, domain.NONE, None, ev)

    if not spawn_recorded and run_state in PRE_SPAWN_STATES and exit_receipt is None:
        return Reconciliation(
            NEVER_DISPATCHED,
            "the run was admitted but the dispatcher never reached the spawn step: no worker was "
            "recorded, no lock was ever taken, and no child can exist. Nothing was executed, so "
            "there is nothing to duplicate and nothing to inspect. This is deliberately NOT "
            "AMBIGUOUS_EXECUTION -- that verdict means a write may have landed, and spending it "
            "on a run that never started devalues the one alarm that must always be believed.",
            True, domain.GPT_ORCHESTRATOR, None, ev)

    if liveness == proc.ALIVE:
        return Reconciliation(RUNNING, "the worker still holds its lock; the run is live", False,
                              domain.NONE, None, ev)

    # ---- a terminal receipt exists: the worker observed the child end ------------------------
    if exit_receipt is not None:
        started = exit_receipt.get("started")
        code = exit_receipt.get("exit_code")
        if started is not True:
            return Reconciliation(
                WORKER_FAILED,
                "the exit receipt records that the child never started (%s); nothing was executed"
                % (exit_receipt.get("exit_class") or "unknown"),
                True, domain.GPT_ORCHESTRATOR, STATE_FOR[WORKER_FAILED], ev)
        if result_valid is True:
            return Reconciliation(
                INTERRUPTED,
                "the child completed and a valid result was recorded; the worker died afterwards. "
                "The execution is not ambiguous -- only its post-processing is incomplete.",
                False, domain.GPT_ORCHESTRATOR, STATE_FOR[INTERRUPTED], ev)
        if isinstance(code, int) and code != 0:
            return Reconciliation(
                PROCESS_FAILED, "the child exited %d" % code, False, domain.GPT_ORCHESTRATOR,
                STATE_FOR[PROCESS_FAILED], ev)
        if is_write or observed_change is True:
            return Reconciliation(
                AMBIGUOUS_EXECUTION,
                "the child ran to completion but no valid result was recorded, and this run could "
                "write. Whether side effects landed cannot be established from here, so it is "
                "AMBIGUOUS and must not be retried automatically.",
                False, domain.GPT_ORCHESTRATOR, STATE_FOR[AMBIGUOUS_EXECUTION], ev)
        return Reconciliation(
            INTERRUPTED,
            "the child ended without a usable result on a read-only run; no repository change was "
            "observed", False, domain.GPT_ORCHESTRATOR, STATE_FOR[INTERRUPTED], ev)

    # ---- no receipt --------------------------------------------------------------------------
    if liveness == proc.UNKNOWN:
        return Reconciliation(
            AMBIGUOUS_EXECUTION,
            "no terminal receipt, and the worker's liveness could not be established. UNKNOWN is "
            "not DEAD: assuming death here would license a second execution against a worker that "
            "may still be writing.",
            False, domain.GPT_ORCHESTRATOR, STATE_FOR[AMBIGUOUS_EXECUTION], ev)

    # liveness == DEAD, no receipt
    if not worker_started:
        return Reconciliation(
            WORKER_FAILED,
            "the worker is dead and never recorded its own identity, which happens before any "
            "child can be launched. Nothing was executed, so there is nothing to duplicate.",
            True, domain.GPT_ORCHESTRATOR, STATE_FOR[WORKER_FAILED], ev)

    if is_write or observed_change is True:
        return Reconciliation(
            AMBIGUOUS_EXECUTION,
            "the worker died without writing a terminal receipt, and this run could write. It may "
            "have edited, committed, or started something external before it vanished. NO BLIND "
            "RETRY: a human or GPT must inspect the worktree and decide.",
            False, domain.OWNER, STATE_FOR[AMBIGUOUS_EXECUTION], ev)

    return Reconciliation(
        INTERRUPTED,
        "the worker died without a terminal receipt on a read-only run; no repository change was "
        "observed, so the execution is incomplete rather than uncertain.",
        False, domain.GPT_ORCHESTRATOR, STATE_FOR[INTERRUPTED], ev)


def read_liveness(store, run_id: str, run: Mapping) -> str:
    """The worker's liveness, from the lock and the recorded process identity. Impure."""
    w = store.get_worker(run_id) or {}
    lock_path = str(w.get("lock_path") or runfiles.p(str(run["run_dir"]), runfiles.LOCK))
    return proc.observe(lock_path, w.get("worker_pid"), w.get("worker_create_time")).status


def reconcile_run(store, run_id: str, *, apply: bool = True) -> Reconciliation:
    """Classify one run and, by default, record the outcome. Impure. NEVER redispatches.

    ``apply`` writes the classified terminal state. It never starts anything -- there is no code
    path in this module that spawns a worker, and that absence is deliberate: an automatic
    recovery path is a blind retry wearing a better name.
    """
    run = store.get_run(run_id)
    if run is None:
        return Reconciliation(TERMINAL_ALREADY, "no such run %r" % run_id, False, domain.NONE)

    rd = str(run["run_dir"])
    worker = store.get_worker(run_id) or {}
    exit_receipt = runfiles.read_json(runfiles.p(rd, runfiles.EXIT))
    result = store.get_result(run_id)
    ev_row = store.get_evidence(run_id)
    observed = None
    if ev_row is not None and ev_row.get("observed_change") is not None:
        observed = bool(ev_row["observed_change"])

    rec = classify(
        run_state=str(run["execution_state"]), is_write=bool(run["is_write"]),
        liveness=read_liveness(store, run_id, run),
        worker_started=bool(worker.get("worker_pid")),
        # No worker ROW at all means `record_spawn` was never called -- the dispatcher returned
        # before its spawn step. That is a different fact from "a worker existed and we cannot
        # see it", and conflating them manufactured a false AMBIGUOUS_EXECUTION.
        spawn_recorded=bool(store.get_worker(run_id)),
        exit_receipt=exit_receipt if isinstance(exit_receipt, dict) else None,
        result_valid=(None if result is None else bool(result.get("valid"))),
        observed_change=observed)

    store.append_event("reconcile", run_id=run_id,
                       detail={"classification": rec.classification, "reason": rec.reason,
                               "auto_redispatch_allowed": rec.auto_redispatch_allowed,
                               "evidence": dict(rec.evidence)})

    if apply and rec.target_state:
        from quaestor.core.store import TransitionRefused
        try:
            store.transition(run_id, rec.target_state, reason=rec.reason)
        except TransitionRefused as exc:
            store.append_event("reconcile.transition_refused", run_id=run_id,
                               detail={"target": rec.target_state, "error": str(exc)})
        lease = store.lease_for_run(run_id)
        if lease and lease.get("released_at") is None:
            from quaestor.core import lease as lease_mod
            live = read_liveness(store, run_id, run)
            fresh_run = store.get_run(run_id) or run
            if lease_mod.may_reclaim(lease, holder_run_state=str(fresh_run["execution_state"]),
                                     holder_liveness=live):
                store.release_lease(str(lease["lease_id"]),
                                    reason="reclaimed by reconciliation: %s" % rec.classification)
            else:
                store.append_event("lease.reclaim_refused", run_id=run_id,
                                   detail={"liveness": live,
                                           "reason": "a lease is only reclaimed when the holder "
                                                     "is provably dead AND its run is terminal"})
    return rec


def reconcile_all(store, *, apply: bool = True) -> list:
    """Reconcile every run the store believes is still active. Impure."""
    out = []
    for run in store.runs_in_states(domain.ACTIVE_STATES):
        out.append((str(run["run_id"]), reconcile_run(store, str(run["run_id"]), apply=apply)))
    return out

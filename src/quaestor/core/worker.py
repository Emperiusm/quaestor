"""worker -- ONE dispatch, owned by ONE detached process.

WHY THE WORKER IS NOT THE SERVER
--------------------------------
If the HTTP/MCP bridge owned the Claude subprocess, a bridge restart would kill a live run or
orphan it beyond reconstruction. So:

    dispatcher/server  ->  detached run worker  ->  claude

The worker owns exactly one dispatch, holds an OS lock for its entire life (that lock is what
makes its liveness provable by anyone, later, without trusting a pid), and writes every state
transition to BOTH the database and its run directory.

THE ORDER OF OPERATIONS IS THE SAFETY ARGUMENT
----------------------------------------------
 1. take the lock FIRST. If we cannot, another worker owns this run and we exit having done
    nothing -- that is the second half of "at most one active execution".
 2. re-verify worktree drift AFTER the lock and immediately BEFORE launching. The dispatcher
    checked it too; the window between the two checks is exactly where another lane's commit
    lands, and a check that happened earlier is not a measurement of now.
 3. snapshot the repository BEFORE the child runs. Evidence taken only afterwards can describe a
    change but never prove the run caused it.
 4. write ``exit.json`` as soon as the child is observed to end, BEFORE parsing anything. The
    terminal receipt must not depend on the result being well-formed -- otherwise a malformed
    result is indistinguishable from a crash, and one of those is AMBIGUOUS while the other is
    merely invalid.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
from typing import Mapping

from quaestor.core import domain
from quaestor.evidence import model as evidence_mod
from quaestor.core import handoff as handoff_mod
from quaestor.core import proc
from quaestor.workspace import git as repo
from quaestor.core import runfiles
from quaestor.core.canon import is_true, sha256_text
from quaestor.core.executor_contract import (ExecRequest, classify_failure, describe_envelope,
                       envelope_is_error, envelope_session_id, envelope_telemetry,
                       extract_structured, handoff_strength, parse_envelope)
from quaestor.core.identity import RunBinding
from quaestor.core.store import Store, TransitionRefused

HEARTBEAT_S = 30.0


def _classified(reason: str) -> str:
    """invalid_reason as stored: "[FAILURE_CLASS] original text".

    The class is prepended machine-readably at this one choke point so every invalid result in
    the ledger is countable by failure mode without re-parsing prose -- after the live
    LOCAL_GOVERNED program (2026-08-24) needed exactly that split to see its 8-of-32
    prose-only children as one population rather than thirty-two anecdotes. PURE.
    """
    return "[%s] %s" % (classify_failure(reason), reason)


def make_executor(spec: Mapping):
    """Resolve an executor for this run. Impure (imports at call time).

    RESOLVED, NOT IMPORTED. ``core`` may not depend on a provider package -- see
    ``quaestor.executors.registry`` for why -- so the factory is looked up when it is needed.
    The spec itself lives in the durable request artifact, so a reconciling process can see WHICH
    executor a run used without re-deriving it from configuration that may since have changed.
    """
    import importlib

    registry = importlib.import_module("quaestor.executors.registry")
    return registry.build(spec)


class _Heartbeat(threading.Thread):
    """Keeps the lease heartbeat fresh while the child runs.

    Without it, a long Claude turn would make our OWN lease look stale to ``ownership_proof``,
    and a lease that cannot prove itself refuses the next step. Daemon thread: it must never keep
    a finished worker alive.
    """

    def __init__(self, store: Store, lease_id: str, interval: float = HEARTBEAT_S):
        super().__init__(daemon=True, name="lease-heartbeat")
        self.store, self.lease_id, self.interval = store, lease_id, interval
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.store.heartbeat_lease(self.lease_id)
            except Exception:  # noqa: BLE001 - a heartbeat failure must never kill the run
                pass

    def stop(self) -> None:
        self._stop.set()


def run_worker(*, db_path: str, run_id: str) -> int:
    """The worker body. Returns a process exit code. NEVER raises past the top."""
    store = Store(db_path)
    try:
        return _run(store, run_id)
    finally:
        store.close()


def _run(store: Store, run_id: str) -> int:
    run = store.get_run(run_id)
    if run is None:
        sys.stderr.write("worker: no such run %s\n" % run_id)
        return 2

    rd = str(run["run_dir"])
    runfiles.ensure(rd)
    request = runfiles.read_json(runfiles.p(rd, runfiles.REQUEST))
    if not isinstance(request, dict):
        _fail(store, run_id, domain.WORKER_FAILED,
              "request.json is absent or unreadable: the worker cannot reconstruct what it was "
              "asked to do, and refuses to invent it")
        return 3

    # -- 1. THE LOCK, before anything else -----------------------------------------------------
    lock_path = runfiles.p(rd, runfiles.LOCK)
    lock = proc.WorkerLock(lock_path)
    if not lock.acquire():
        sys.stderr.write("worker: run %s is already owned by a live worker; exiting\n" % run_id)
        return 4

    pid, create_time = proc.self_identity()
    store.record_worker_started(run_id, worker_pid=pid, worker_create_time=create_time,
                                lock_path=lock_path)
    runfiles.write_json(runfiles.p(rd, runfiles.WORKER), {
        "run_id": run_id, "worker_pid": pid, "worker_create_time": create_time,
        "lock_path": lock_path, "started_at": time.time(),
        "executor": request.get("executor", {}).get("kind"),
        "python": sys.executable,
    })

    lease = store.lease_for_run(run_id)
    hb = None
    if lease and lease.get("released_at") is None:
        hb = _Heartbeat(store, str(lease["lease_id"]))
        hb.start()

    try:
        return _execute(store, run, request, rd, lease)
    finally:
        if hb is not None:
            hb.stop()
        if lease and lease.get("released_at") is None:
            store.release_lease(str(lease["lease_id"]), reason="worker finished")
        # Released only HERE, after the run's terminal state and its exit receipt are durable.
        # The ordering is what makes it safe: a reconciler that sees the lock free from this
        # point on reads a run that is already terminal, so it returns TERMINAL_ALREADY and never
        # has to infer anything from the lock at all. Releasing any EARLIER would shorten the
        # window in which our liveness is provable; not releasing at all leaks a file handle per
        # in-process worker, which on Windows also blocks a temp directory from being removed.
        # A crash still skips this entirely -- the OS publishes that death, as designed.
        lock.release()


def _execute(store: Store, run: Mapping, request: Mapping, rd: str, lease) -> int:
    run_id = str(run["run_id"])
    cwd = str(request["cwd"])
    profile = str(request["authority_profile"])
    is_write = bool(run["is_write"])
    min_inspected = int(request.get("min_inspected", 1))

    # -- 2. drift, measured NOW ----------------------------------------------------------------
    before = repo.probe(cwd)
    drift = repo.classify_drift(expected_branch=str(request["expected_branch"]),
                                expected_head=str(request["expected_head"]), snapshot=before)
    if drift != repo.NO_DRIFT:
        _fail(store, run_id, domain.LEASE_REFUSED,
              "%s: the worktree moved between admission and dispatch (expected %s@%s, found %s@%s)"
              % (drift, request["expected_branch"], str(request["expected_head"])[:12],
                 before.branch, str(before.head or "")[:12]))
        return 5

    store.transition(run_id, domain.RUNNING, expect_from=domain.DISPATCHED)

    binding = RunBinding(run_id=run_id, workflow_id=str(request["workflow_id"]),
                         step_id=str(request["step_id"]), run_nonce=str(run["run_nonce"]))
    req = ExecRequest(
        run_id=run_id, run_dir=rd, cwd=cwd, prompt=str(request["prompt"]), binding=binding,
        json_schema=handoff_mod.HANDOFF_JSON_SCHEMA, authority_profile=profile,
        stdout_path=runfiles.p(rd, runfiles.STDOUT), stderr_path=runfiles.p(rd, runfiles.STDERR),
        claude_path=str(request.get("claude_path") or "claude"),
        model=str(request.get("model") or ""), timeout_s=float(request.get("timeout_s") or 1800.0))

    executor = make_executor(request.get("executor") or {})
    # A CONTAINERISED child runs with the container's workdir as its cwd, not the host path. The
    # host path is still what the evidence layer measures -- the bind makes them the same
    # directory -- but handing a Windows path to a Linux process would fail in a way that could
    # be mistaken for confinement working.
    if getattr(executor, "name", "") == "claude-container":
        from dataclasses import replace as _replace
        req = _replace(req, container_confined=True)
    started_at = time.time()
    outcome = executor.execute(req)

    # -- 4. the terminal receipt, written before anything is parsed ----------------------------
    runfiles.write_json(runfiles.p(rd, runfiles.EXIT), {
        "run_id": run_id, "started_at": started_at, "finished_at": time.time(),
        "started": bool(outcome.started), "exit_code": outcome.exit_code,
        "exit_class": outcome.exit_class, "error": outcome.error,
        "child_pid": outcome.child_pid, "child_create_time": outcome.child_create_time,
        "executor": executor.name,
    })
    store.record_child(run_id, child_pid=outcome.child_pid,
                       child_create_time=outcome.child_create_time)
    store.record_worker_exit(run_id, exit_code=outcome.exit_code, exit_class=outcome.exit_class)

    if not outcome.started:
        _fail(store, run_id, domain.WORKER_FAILED,
              "the child never started (%s): %s" % (outcome.exit_class, outcome.error))
        return 6

    # -- 5. the result: parse, then validate, then bind to THIS run ----------------------------
    raw = runfiles.read_text(req.stdout_path)
    raw_sha = sha256_text(raw)
    envelope, env_note = parse_envelope(raw)

    if envelope is None:
        store.record_result(run_id, raw_sha256=raw_sha, outcome=handoff_mod.RESULT_INVALID,
                            valid=False, invalid_reason=_classified(env_note))
        _collect_evidence(store, run_id, before, cwd, claimed=None, is_write=is_write,
                          min_inspected=min_inspected, rd=rd)
        _fail(store, run_id, domain.RESULT_INVALID, env_note)
        return 7

    session_id = envelope_session_id(envelope)
    errored, subtype = envelope_is_error(envelope)
    payload, source, extraction = extract_structured(envelope)

    if payload is None:
        reason = ("no structured handoff in the result envelope (%s); envelope was a %s"
                  % (extraction, describe_envelope(envelope)))
        store.record_result(run_id, raw_sha256=raw_sha, outcome=handoff_mod.RESULT_INVALID,
                            valid=False, invalid_reason=_classified(reason), session_id=session_id)
        _collect_evidence(store, run_id, before, cwd, claimed=None, is_write=is_write,
                          min_inspected=min_inspected, rd=rd)
        _fail(store, run_id, domain.RESULT_INVALID, reason)
        return 8

    validation = handoff_mod.validate_handoff(payload, binding)
    if not validation.valid:
        store.record_result(run_id, raw_sha256=raw_sha, outcome=validation.outcome, valid=False,
                            invalid_reason=_classified(validation.reason), session_id=session_id)
        _collect_evidence(store, run_id, before, cwd,
                          claimed=handoff_mod.claimed_change(payload), is_write=is_write,
                          min_inspected=min_inspected, rd=rd)
        # A protocol/identity refusal is a DIFFERENT defect from a malformed body, and the
        # execution state says which -- collapsing them would cost the diagnosis.
        state = (domain.RESULT_INVALID if validation.outcome == handoff_mod.RESULT_INVALID
                 else domain.RESULT_INVALID)
        _fail(store, run_id, state, "%s: %s" % (validation.outcome, validation.reason))
        return 9

    store.record_result(run_id, raw_sha256=raw_sha, outcome=handoff_mod.VALID, valid=True,
                        session_id=session_id,
                        claude_version=str(request.get("claude_version") or ""),
                        handoff=dict(validation.handoff or {}))
    store.transition(run_id, domain.RESULT_RECEIVED, expect_from=domain.RUNNING,
                     detail={"structured_output_source": source,
                             "handoff_strength": handoff_strength(source),
                             "envelope_note": env_note,
                             "child_reported_error": errored, "subtype": subtype})

    # -- 5b. two-way delivery: persist executor messages and the resume checkpoint --------------
    # BEFORE evidence, so a persistence failure fails THIS RUN loudly. The alternative -- logging
    # a DECISION_REQUEST into a void and handing back HANDOFF_READY -- would strand a lane in a
    # waiting state nobody is told about, which is the silent-stall failure this protocol exists
    # to prevent.
    try:
        _sync_program_state(store, request, run_id, validation.handoff or {})
    except Exception as exc:  # noqa: BLE001 - converted into a NAMED, recoverable run failure
        store.record_result(run_id, raw_sha256=raw_sha, outcome=handoff_mod.RESULT_INVALID,
                            valid=False,
                            invalid_reason=_classified("two-way delivery failed: %s" % exc),
                            session_id=session_id)
        _fail(store, run_id, domain.WORKER_FAILED,
              "program-state delivery failed (messages/checkpoint were NOT persisted): %s"
              % exc)
        return 12

    # -- 6. independent evidence ---------------------------------------------------------------
    env = _collect_evidence(store, run_id, before, cwd,
                            claimed=handoff_mod.claimed_change(validation.handoff or {}),
                            is_write=is_write, min_inspected=min_inspected, rd=rd)
    if not env.ok:
        _fail(store, run_id, domain.EVIDENCE_INVALID, "%s: %s" % (env.verdict, env.reason))
        return 10
    store.transition(run_id, domain.EVIDENCE_COLLECTED, expect_from=domain.RESULT_RECEIVED)

    # -- 7. the handoff ------------------------------------------------------------------------
    if not domain.handoff_is_ready(result_valid=is_true(validation.valid),
                                   evidence_ok=is_true(env.ok)):
        _fail(store, run_id, domain.EVIDENCE_INVALID, "handoff readiness refused")
        return 11

    telemetry = envelope_telemetry(envelope)
    store.append_event("child.telemetry", run_id=run_id, detail=telemetry)
    package = build_handoff_package(run_id=run_id, request=request, handoff=validation.handoff,
                                    envelope_source=source, session_id=session_id, evidence=env,
                                    telemetry=telemetry)
    runfiles.write_json(runfiles.p(rd, runfiles.HANDOFF), package)
    store.record_handoff(run_id, package)
    store.transition(run_id, domain.HANDOFF_READY, expect_from=domain.EVIDENCE_COLLECTED)
    return 0


def _sync_program_state(store: Store, request: Mapping, run_id: str, payload: Mapping) -> None:
    """Deliver this run's two-way traffic and checkpoint to the strategic layer. Impure.

    Runs dispatched OUTSIDE a program have no lane to pause and no inbox to land in, so they
    return immediately -- the single-dispatch contract is unchanged. For program runs:

      * every executor message becomes a durable, deduplicated row (content-digest idempotent,
        so a redelivered result cannot double-book a question);
      * the FIRST awaiting message pauses the lane -- WAITING_FOR_STRATEGIST or
        WAITING_FOR_OWNER by the message's ROUTES, never by the child's say-so;
      * the structured checkpoint is saved for resumption.

    Raises on failure. The caller turns an exception into WORKER_FAILED: losing a question
    silently is worse than failing a run recoverably.
    """
    program_id = str((request.get("context") or {}).get("program_id") or "")
    lane_id = str((request.get("context") or {}).get("lane_id") or "")
    if not (program_id and lane_id):
        return

    from quaestor.core import messages as msg_mod
    from quaestor.core import programs as prog_mod
    from quaestor.core import strategic_store as ss_mod

    sstore = ss_mod.StrategicStore(ss_mod.strategic_path_for_run_db(store.path))
    try:
        actor = "executor:%s" % str((request.get("executor") or {}).get("kind") or "unknown")
        first_awaiting = None
        for m in handoff_mod.handoff_messages(payload):
            detail = dict(m.get("detail") or {})
            if m.get("severity"):
                detail.setdefault("severity", m["severity"])
            msg = msg_mod.new_message(
                m["type"], actor_id=actor, program_id=program_id, lane_id=lane_id,
                run_id=run_id, payload=m["payload"], detail=detail,
                authority_context=(str(request.get("authority_profile") or ""),))
            sstore.record_message(msg)
            if msg.awaits_answer and first_awaiting is None:
                first_awaiting = msg
        if first_awaiting is not None:
            state = (prog_mod.LANE_WAITING_OWNER if first_awaiting.routed_to == "OWNER"
                     else prog_mod.LANE_WAITING_STRATEGIST)
            sstore.set_lane_state(lane_id, state)
        # MERGE, never replace: the scheduler already stored workspace identity in this
        # checkpoint, and a worker that overwrote it would erase the lane's ability to resume
        # where it lives. Measured exactly that way before this was written.
        ckpt = dict(sstore.get_lane_task(lane_id).get("checkpoint") or {})
        ckpt.update({
            "run_id": run_id,
            "summary": str(payload.get("summary") or ""),
            "next_action": str(payload.get("next_action") or ""),
            "smallest_blocker": str(payload.get("smallest_blocker") or ""),
            "prompt_disposition": str(payload.get("prompt_disposition") or ""),
            "program_verdict": str(payload.get("program_verdict") or ""),
            "acceptance_state": str(payload.get("acceptance_state") or ""),
            "claimed_files_changed": list(payload.get("claimed_files_changed") or ()),
            "awaiting_message": first_awaiting.message_id if first_awaiting else "",
            "saved_at": time.time(),
        })
        sstore.save_checkpoint(lane_id, ckpt, program_id=program_id, run_id=run_id)
    finally:
        sstore.close()


def build_handoff_package(*, run_id: str, request: Mapping, handoff: Mapping,
                          envelope_source: str, session_id: str,
                          evidence: evidence_mod.EvidenceEnvelope,
                          telemetry: Mapping | None = None) -> dict:
    """What GPT receives. PURE.

    The report and the measurement travel SIDE BY SIDE and are labelled as what they are. That
    labelling is the deliverable: ``claude_report`` is a claim, ``bridge_evidence`` is a
    measurement, and no consumer should ever have to guess which one it is reading.

    ``authority_discrepancy`` is a third thing again -- a REPORTED-VS-OBSERVED mismatch that is
    flagged, not adjudicated. A child can legitimately be denied a tool, adapt, and still finish
    correctly, so failing the run on a denial would produce false refusals; and a child that
    claims it exhausted its authority while the runtime was refusing it tools is worth a human
    look either way. P2 decides whether this becomes a gate. Naming it and leaving the policy
    open is the honest position, not an oversight.

    ``handoff_strength`` states HOW the structured payload was obtained -- schema-validated by
    the CLI, parsed from exact text on our side, or recovered from prose. It travels in the
    package itself so no downstream consumer can mistake a recovered handoff for a native one:
    after the 2026-08-24 LOCAL_GOVERNED program (8 of 32 children answering in prose), strength
    is part of the claim, not something a reader has to re-derive from source strings.
    """
    tel = dict(telemetry or {})
    denials = tel.get("permission_denial_count")
    discrepancy = None
    if isinstance(denials, int) and denials > 0:
        discrepancy = {
            "kind": "PERMISSION_DENIALS_OBSERVED",
            "count": denials,
            "claimed_scope_exhausted": (handoff or {}).get("authorized_scope_exhausted"),
            "prompt_disposition": (handoff or {}).get("prompt_disposition"),
            "note": ("the runtime refused the child one or more tools. Its report may describe "
                     "less capability than it believes it had. Advisory in P1."),
        }
    # SEAT IN THE MATRIX (PRD.md §7.1): every run carries which role it filled and
    # which provider actually executed. Both values are MEASURED from the durable request
    # artifact -- what the scheduler dispatched -- never self-reported by the model.
    ctx = request.get("context") or {}
    seat = {"role": ctx.get("role") or "",
            "provider": (request.get("executor") or {}).get("kind")}
    return {
        "protocol": handoff_mod.PROTOCOL,
        "protocol_version": handoff_mod.PROTOCOL_VERSION,
        "run_id": run_id,
        "workflow_id": request.get("workflow_id"),
        "step_id": request.get("step_id"),
        "execution_state": domain.HANDOFF_READY,
        "handoff_strength": handoff_strength(envelope_source),
        "claude_report": dict(handoff or {}),
        "bridge_evidence": evidence.to_dict(),
        "child_telemetry": tel,
        "authority_discrepancy": discrepancy,
        "seat": seat,
        "provenance": {
            "structured_output_source": envelope_source,
            "claude_session_id": session_id or None,
            "claude_version": request.get("claude_version") or None,
            "executor": (request.get("executor") or {}).get("kind"),
            "authority_profile": request.get("authority_profile"),
            "auth_class": request.get("auth_class"),
        },
        "interpretation": {
            "prompt_disposition": (handoff or {}).get("prompt_disposition"),
            "program_verdict": (handoff or {}).get("program_verdict"),
            "next_authority": (handoff or {}).get("next_authority"),
            "note": ("prompt_disposition and program_verdict are independent. A COMPLETE "
                     "disposition with a FAIL verdict is a successful execution reporting a "
                     "failing program, and is a valid handoff."),
        },
    }


def _collect_evidence(store: Store, run_id: str, before, cwd: str, *, claimed, is_write: bool,
                      min_inspected: int, rd: str) -> evidence_mod.EvidenceEnvelope:
    after = repo.probe(cwd)
    may_move_head = is_write
    env = evidence_mod.build_envelope(before, after, claimed_change=claimed,
                                      may_move_head=may_move_head,
                                      min_inspected=min_inspected,
                                      extra={"is_write": bool(is_write)})
    runfiles.write_json(runfiles.p(rd, runfiles.EVIDENCE), env.to_dict())
    store.record_evidence(run_id, env.to_dict())
    return env


def _fail(store: Store, run_id: str, state: str, reason: str) -> None:
    try:
        store.transition(run_id, state, reason=reason)
    except TransitionRefused as exc:
        store.append_event("transition.refused", run_id=run_id,
                           detail={"target": state, "reason": reason, "error": str(exc)})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m quaestor.core.worker")
    ap.add_argument("--db", required=True)
    ap.add_argument("--run-id", required=True)
    a = ap.parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return run_worker(db_path=a.db, run_id=a.run_id)
    except Exception as exc:  # noqa: BLE001 - a worker crash must leave a trace, not a silence
        sys.stderr.write("worker: unhandled %s: %s\n" % (type(exc).__name__, exc))
        try:
            st = Store(a.db)
            st.append_event("worker.unhandled", run_id=a.run_id,
                            detail={"error": "%s: %s" % (type(exc).__name__, exc)})
            st.close()
        except Exception:  # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

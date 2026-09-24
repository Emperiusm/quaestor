"""orchestrator -- the program engine: durable objectives, scheduled lanes, bounded loops.

WHAT THIS MODULE IS
-------------------
The operational control loop that turns ONE strategic objective into MANY governed executions:

    create_program -> plan lanes -> tick ... tick -> integrated candidate

``tick`` is the whole scheduler, and it is IDEMPOTENT per unit of durable state: reaping a run,
committing a lane, dispatching a ready lane and advancing integration each happen at most once
for a given run/lane because every one of them writes its completion into the store before it can
be observed again. A crashed tick loses nothing; the next tick redoes exactly what was not yet
recorded.

STAGE MACHINE PER IMPLEMENTATION LANE
-------------------------------------
    PLANNED --dispatch--> ACTIVE --handoff--> (waiting? pause) --commit--> VERIFIED?
        tests fail or findings survive --> FIX attempt (same lane, bounded) --> re-verify/re-review
        clean --> COMPLETE/PASS

Bounded by ``max_review_cycles``: beyond it the lane escalates to the strategist with a BLOCKER
rather than ping-ponging forever (§47).

DECISION POLICY (§20)
---------------------
Executors decide ordinary reversible implementation choices. The two-way channel exists for
choices that materially change objective, architecture, public contract, security boundary,
authority, cost, irreversible state or acceptance criteria -- which is what the prompt says,
verbatim, so the model's escalation behaviour matches the policy instead of guessing at it.

WHAT THIS MODULE IS NOT
-----------------------
It is not authority: every dispatch still passes core.dispatcher's full ladder. It is not
evidence: measurement stays in evidence/. It does not push, publish or destroy anything.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from quaestor import branding
from quaestor.core import authority as authority_mod
from quaestor.core import decisions as dec_mod
from quaestor.core import domain
from quaestor.core import events as ev_mod
from quaestor.core import messages as msg_mod
from quaestor.core import programs as prog_mod
from quaestor.core.canon import sha256_text
from quaestor.core.dispatcher import DispatchSpec, dispatch
from quaestor.core.store import Store
from quaestor.core.strategic_store import StrategicStore
from quaestor.evidence import test_collector

ORCHESTRATOR_INSTRUMENT = "orchestrator/1"

# ---- lane kinds ------------------------------------------------------------------------------
KIND_RESEARCH = "research"
KIND_IMPLEMENTATION = "implementation"
KIND_VERIFICATION = "verification"
KIND_ADVERSARIAL_REVIEW = "adversarial_review"
KIND_INTEGRATION = "integration"

LANE_KINDS = (KIND_RESEARCH, KIND_IMPLEMENTATION, KIND_VERIFICATION,
              KIND_ADVERSARIAL_REVIEW, KIND_INTEGRATION)

#: The authority envelope each kind runs under. Deliberately narrow; §18. A reviewer gets
#: READ_ONLY and nothing else, structurally -- it cannot edit, so it cannot "fix" what it found.
PROFILE_FOR_KIND: Mapping[str, str] = {
    KIND_RESEARCH: authority_mod.READ_ONLY,
    KIND_IMPLEMENTATION: authority_mod.STANDARD_EDIT,
    KIND_VERIFICATION: authority_mod.READ_ONLY,
    KIND_ADVERSARIAL_REVIEW: authority_mod.READ_ONLY,
    KIND_INTEGRATION: authority_mod.STANDARD_EDIT,
}

# ---------------------------------------------------------------------------------------------
# Reap's role-dispatch registry (§18): every declared kind maps to EXACTLY ONE handler
# ---------------------------------------------------------------------------------------------
# WHY A REGISTRY AND NOT AN if/elif CHAIN. Found LIVE: a newly added lane kind fell through
# reap()'s catch-all into a "NOTED" action -- the run was marked processed, the lane stayed
# ACTIVE, and schedule() re-dispatched it on EVERY tick, each dispatch a real paid executor
# invocation. Every tick "worked"; nothing ever completed. An if/elif hides that hole in its
# else branch; a total mapping makes it structural, and verify_lane_registry() (enforced at
# IMPORT TIME, below) turns it into a loud startup/test failure instead of a live defect.
#
# THE UNIFORM HANDLER PROTOCOL. Every value below has the signature
#
#     handler(home, sstore, store, *, program_id, lane, role, run_id, report,
#             cfg, policy, now, spawner=None) -> list[dict]   (reap actions)
#
# Adapters accept the FULL protocol and ignore what their flow does not need, so adding a
# kind never requires touching the dispatch site in _consume_run.
def _complete_report_only(sstore, *, lane, role, report) -> list:
    """Complete a REPORT-ONLY lane: the run's own verdict IS the lane's outcome.

    Research/verification/integration runs produce findings or measurements, not commits --
    there is no diff to commit and no parent-side verification to run, so the structured
    ``program_verdict`` carried in the handoff advances the lane directly to COMPLETE. This
    is the body of the old if/elif's shared report-only branch, factored out and NAMED so
    the registry can point at it and tests/test_lane_registry.py can drive it end to end.
    """
    lane_id = lane.lane_id
    verdict = str(report.get("program_verdict") or prog_mod.NOT_EVALUATED)
    sstore.set_lane_state(lane_id, prog_mod.LANE_COMPLETE, verdict=(
        prog_mod.PASS if verdict == domain.PASS else
        prog_mod.FAIL if verdict == domain.FAIL else prog_mod.NOT_EVALUATED),
        actor_id="scheduler")
    return [{"lane": lane_id, "action": "REPORT_COMPLETE", "role": role}]


def _handle_implementation(home, sstore, store, *, program_id, lane, role, run_id, report,
                           cfg, policy, now, spawner=None) -> list:
    """Registry adapter: implementation runs enter the commit->verify->review flow."""
    return _after_implementation(home, sstore, store, program_id=program_id, lane=lane,
                                 run_id=run_id, report=report, cfg=cfg, policy=policy,
                                 now=now, spawner=spawner)


def _handle_adversarial_review(home, sstore, store, *, program_id, lane, role, run_id, report,
                               cfg, policy, now, spawner=None) -> list:
    """Registry adapter: reviewer runs resolve into a bounded fix attempt or completion."""
    return _after_review(sstore, program_id=program_id, lane=lane, run_id=run_id,
                         report=report, policy=policy, now=now)


def _handle_report_only(home, sstore, store, *, program_id, lane, role, run_id, report,
                        cfg, policy, now, spawner=None) -> list:
    """Registry adapter shared by every report-only kind (research/verification/integration)."""
    return _complete_report_only(sstore, lane=lane, role=role, report=report)


#: TERMINAL-REACHABILITY DECLARATION. Each entry asserts that its kind's handler DRIVES ITS
#: LANE OUT OF THE DISPATCH CYCLE: to COMPLETE, or -- on the bounded failure paths -- into a
#: WAITING state that schedule() refuses to re-dispatch until a strategist decides otherwise.
#: Either way the loop ENDS. The live F2 defect was exactly a handler-shaped branch that did
#: neither: runs were consumed forever while the lane never moved. Declared ADJACENT to the
#: registry so the two cannot drift apart unnoticed;
#: tests/test_lane_registry.py enforces coverage of this map AND demonstrates it behaviorally.
HANDLER_REACHES_TERMINAL: Mapping[str, bool] = {
    KIND_RESEARCH: True,
    KIND_IMPLEMENTATION: True,
    KIND_VERIFICATION: True,
    KIND_ADVERSARIAL_REVIEW: True,
    KIND_INTEGRATION: True,
}

#: kind -> the one handler that consumes that kind's finished runs. TOTAL over LANE_KINDS by
#: construction: verify_lane_registry() below fails startup otherwise, so a future kind
#: (security_review/benchmark/release/incident, §18) cannot be added silently.
LANE_HANDLERS: Mapping[str, Callable[..., list]] = {
    KIND_RESEARCH: _handle_report_only,
    KIND_IMPLEMENTATION: _handle_implementation,
    KIND_VERIFICATION: _handle_report_only,
    KIND_ADVERSARIAL_REVIEW: _handle_adversarial_review,
    KIND_INTEGRATION: _handle_report_only,
}


def verify_lane_registry() -> None:
    """Fail loudly unless every declared kind has a handler that declares terminal reach.

    PURE (raises). Called once at IMPORT TIME below, per §18's "fail startup/tests rather
    than silently redispatch forever": the mismatch behind the live infinite-redispatch
    defect must be impossible to ship quietly, not merely possible to catch later.
    """
    missing = [k for k in LANE_KINDS if k not in LANE_HANDLERS]
    unknown = [k for k in LANE_HANDLERS if k not in LANE_KINDS]
    unbounded = [k for k in LANE_KINDS if not HANDLER_REACHES_TERMINAL.get(k)]
    if missing or unknown or unbounded:
        raise ValueError(
            "lane handler registry disagrees with LANE_KINDS -- "
            "declared_without_handler=%s registered_but_not_declared=%s "
            "without_terminal_semantics=%s; every kind needs exactly one LANE_HANDLERS "
            "entry whose flow drives its lane to a terminal state"
            % (missing, unknown, unbounded))


# IMPORT-TIME ENFORCEMENT (§18). One line, run before anything else in this module can be
# used: an incomplete registry is a startup failure, never a quiet redispatch loop.
verify_lane_registry()

# Program statuses
PROGRAM_DRAFT = "DRAFT"
PROGRAM_PLANNED = "PLANNED"
PROGRAM_RUNNING = "RUNNING"
PROGRAM_WAITING_STRATEGIST = "WAITING_FOR_STRATEGIST"
PROGRAM_WAITING_OWNER = "WAITING_FOR_OWNER"
PROGRAM_CANDIDATE_PASS = "CANDIDATE_PASS"
PROGRAM_CANDIDATE_FAIL = "CANDIDATE_FAIL"
PROGRAM_CANCELLED = "CANCELLED"

DEFAULT_MAX_CONCURRENT = 2          # §17: start conservatively, configurable per program
DEFAULT_MAX_REVIEW_CYCLES = 3       # §47: no infinite review/fix ping-pong
DEFAULT_RUN_TIMEOUT_S = 1800.0


@dataclass(frozen=True)
class ProgramPolicy:
    """The resource + loop bounds of one program. Persisted with it, not ambient."""

    max_concurrent_executors: int = DEFAULT_MAX_CONCURRENT
    max_review_cycles: int = DEFAULT_MAX_REVIEW_CYCLES
    run_timeout_s: float = DEFAULT_RUN_TIMEOUT_S
    require_adversarial: bool = True       # project config may widen, never narrow the floor
    auto_integrate: bool = True
    instrument: str = ORCHESTRATOR_INSTRUMENT

    def to_dict(self) -> dict:
        return {"max_concurrent_executors": self.max_concurrent_executors,
                "max_review_cycles": self.max_review_cycles,
                "run_timeout_s": self.run_timeout_s,
                "require_adversarial": self.require_adversarial,
                "auto_integrate": self.auto_integrate}


def policy_from_meta(meta: Mapping) -> ProgramPolicy:
    try:
        doc = json.loads(meta.get("policy") or "{}")
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    return ProgramPolicy(
        max_concurrent_executors=int(doc.get("max_concurrent_executors") or DEFAULT_MAX_CONCURRENT),
        max_review_cycles=int(doc.get("max_review_cycles") or DEFAULT_MAX_REVIEW_CYCLES),
        run_timeout_s=float(doc.get("run_timeout_s") or DEFAULT_RUN_TIMEOUT_S),
        require_adversarial=bool(doc.get("require_adversarial", True)),
        auto_integrate=bool(doc.get("auto_integrate", True)))


# ---------------------------------------------------------------------------------------------
# Creation and planning
# ---------------------------------------------------------------------------------------------
def create_program(sstore: StrategicStore, *, title: str, objective: str,
                   constraints: Sequence[str] = (), policy: ProgramPolicy | None = None,
                   actor_id: str = "", now: float | None = None) -> str:
    pid = sstore.create_program(title, objective=objective, now=now)
    t = float(now if now is not None else time.time())
    sstore.set_program_meta(pid, "constraints_json",
                            json.dumps([str(c) for c in (constraints or ())]))
    sstore.set_program_meta(pid, "policy", json.dumps((policy or ProgramPolicy()).to_dict()))
    sstore.set_program_status(pid, PROGRAM_DRAFT, actor_id=actor_id,
                              detail={"title": title}, now=t)
    return pid


def plan_lane(sstore: StrategicStore, program_id: str, *, title: str, task: str,
              kind: str = KIND_IMPLEMENTATION, depends_on: Sequence[str] = (),
              acceptance: Sequence[str] = (), executor: Mapping | None = None,
              writable: bool | None = None, workflow_id: str = "",
              actor_id: str = "") -> str:
    """Add ONE planned lane with its task and dependencies. Governed decomposition.

    ``executor`` is SERVER-SIDE ONLY (tests/fixtures scripting scenarios; never an MCP field --
    schemas.FORBIDDEN_FIELDS bans it on the wire). Production executors come from the project
    manifest.
    """
    if kind not in LANE_KINDS:
        raise ValueError("unknown lane kind %r; known are %s" % (kind, list(LANE_KINDS)))
    if writable is None:
        writable = kind == KIND_IMPLEMENTATION
    lane = prog_mod.new_lane(program_id, title=title, kind=kind, writable=writable,
                             workspace_id="", workflow_id=str(workflow_id))
    sstore.add_lane(lane)
    sstore.set_lane_task(lane.lane_id, task=task, acceptance=acceptance, executor=executor)
    for dep in depends_on or ():
        sstore.add_dependency(prog_mod.Dependency(lane.lane_id, str(dep), prog_mod.REQUIRES))
    if sstore.get_program_meta(program_id).get("status") in ("", PROGRAM_DRAFT):
        sstore.set_program_status(program_id, PROGRAM_PLANNED, actor_id=actor_id)
    return lane.lane_id


def answer(sstore: StrategicStore, program_id: str, message_id: str, *, decision_text: str,
           rationale: str = "", authority: str = dec_mod.BY_STRATEGIST, actor_id: str = "",
           now: float | None = None) -> str:
    """Answer an executor question: DIRECTIVE + Decision, and wake the lane.

    The DIRECTIVE is delivered by the NEXT dispatched run of the lane -- appended to the task the
    child originally received, together with its checkpoint. That is the chosen resumption
    mechanism (see StrategicStore.save_checkpoint for why not session-replay).
    """
    m = sstore.message(message_id)
    if m is None:
        raise ValueError("no such message %r" % message_id)
    lane_id = str(m["lane_id"])
    d = dec_mod.new_decision(program_id,
                             str(m["payload"])[:2000], lane_id=lane_id,
                             decision=decision_text, authority=authority,
                             rationale=rationale, evidence_refs=(message_id,),
                             actor_id=actor_id, now=now)
    sstore.record_decision(d)
    directive = msg_mod.new_message(
        msg_mod.DIRECTIVE, actor_id=actor_id or "strategist", program_id=program_id,
        lane_id=lane_id, caused_by=message_id, payload=decision_text,
        detail={"decision_id": d.decision_id, "rationale": rationale}, now=now)
    sstore.record_message(directive)
    sstore.answer_message(message_id, directive.message_id)
    sstore.append_event(ev_mod.new_event(ev_mod.DIRECTIVE_ISSUED, program_id=program_id,
                                         lane_id=lane_id, actor_id=d.actor_id,
                                         detail={"directive": directive.message_id,
                                                 "answers": message_id}, now=now))
    lane = sstore.get_lane(lane_id)
    if lane is not None and lane.state in prog_mod.WAITING_STATES:
        # Wake the lane as SCHEDULABLE, always. schedule() itself refuses lanes whose previous
        # run has not been consumed yet, so PLANNED is safe even if the paused run is still
        # finishing -- and unlike an ACTIVE guess, it cannot race reap into treating a
        # question-asking run as a finished implementation.
        sstore.set_lane_state(lane_id, prog_mod.LANE_PLANNED, verdict=None, actor_id=actor_id)
    elif lane is not None and not lane.terminal:
        # THE ANSWER ARRIVED BEFORE THE PARK. The message is recorded by reap before the lane
        # state is set, so a caller can read the question from the inbox and answer it while the
        # lane is still ACTIVE. Waking is a no-op then -- and the park that follows leaves the
        # lane WAITING with its question already answered, so open_questions is empty, the inbox
        # shows nothing, and no surface anywhere explains why the program stopped.
        #
        # Recording the intent makes the ordering irrelevant: whichever happens second, the lane
        # is woken on the next tick. Stored on the checkpoint because that is the lane's own
        # durable scratch space and it survives a restart.
        ckpt = dict(sstore.get_lane_task(lane_id)["checkpoint"] or {})
        ckpt[PENDING_WAKE_KEY] = str(message_id)
        sstore.save_checkpoint(lane_id, ckpt, program_id=program_id)
    return directive.message_id


#: Checkpoint key holding the message id whose answer could not wake its lane yet. Set by
#: ``answer`` when the lane was not parked at the time; consumed by ``apply_pending_wakes``.
PENDING_WAKE_KEY = "pending_wake"


def apply_pending_wakes(sstore: StrategicStore, program_id: str, *, now=None) -> list:
    """Wake lanes whose answer landed before they parked. Impure. Returns the lane ids woken.

    Runs every tick, AFTER reap has done its parking and BEFORE scheduling, so a lane answered
    mid-flight is schedulable on the same pass it would have been had the ordering gone the
    other way. Fixing it here rather than at each park site is deliberate: eight places park a
    lane, and a per-site guard is seven chances to miss one.

    The flag is cleared FIRST, so a wake happens at most once per answer even if the state write
    that follows fails -- a lane that stayed parked is visible in the inbox; a flag that replayed
    forever would re-wake a lane someone had deliberately re-parked.
    """
    woken = []
    for lane in sstore.lanes(program_id):
        if lane.terminal or lane.state not in prog_mod.WAITING_STATES:
            continue
        ckpt = dict(sstore.get_lane_task(lane.lane_id)["checkpoint"] or {})
        pending = str(ckpt.get(PENDING_WAKE_KEY) or "")
        if not pending:
            continue
        # CLEARED TO A SPENT SENTINEL, NOT REMOVED. save_checkpoint MERGES by design -- so a
        # caller writing {summary} cannot erase another component's {worktree_path} -- which
        # means popping a key writes nothing and the flag would replay on every tick, re-waking
        # a lane an operator had deliberately re-parked.
        ckpt[PENDING_WAKE_KEY] = ""
        sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)
        sstore.set_lane_state(lane.lane_id, prog_mod.LANE_PLANNED, verdict=None,
                              actor_id="scheduler", now=now)
        sstore.append_event(ev_mod.new_event(
            ev_mod.LANE_STATE_CHANGED, program_id=program_id, lane_id=lane.lane_id,
            actor_id="scheduler",
            detail={"why": "PENDING_WAKE_APPLIED", "answered": pending,
                    "note": "the answer arrived before the lane parked"}, now=now))
        woken.append(lane.lane_id)
    return woken


def _has_live_run(sstore: StrategicStore, lane_id: str) -> bool:
    return any(not r["processed"] for r in sstore.runs_for_lane(lane_id))


def cancel_program(sstore: StrategicStore, program_id: str, *, reason: str,
                   actor_id: str = "", now: float | None = None) -> dict:
    """Cancel every non-terminal lane. Waiting is cancelled too: a cancelled program must not
    look like one that is merely quiet."""
    lanes = sstore.lanes(program_id)
    touched = []
    for l in lanes:
        if not l.terminal:
            sstore.set_lane_state(l.lane_id, prog_mod.LANE_ABANDONED, verdict=prog_mod.FAIL,
                                  actor_id=actor_id, now=now)
            touched.append(l.lane_id)
    sstore.set_program_status(program_id, PROGRAM_CANCELLED, actor_id=actor_id,
                              detail={"reason": reason, "lanes_cancelled": len(touched)}, now=now)
    return {"cancelled_lanes": touched, "reason": reason}


# ---------------------------------------------------------------------------------------------
# Plan governance (PRD.md §7.4/§7.6): the planner seat and the proposal lifecycle
# ---------------------------------------------------------------------------------------------
def _plan_flag(meta: Mapping, key: str, default: bool) -> bool:
    """A boolean program-meta policy flag. Restrictive default; unparsable reads as default."""
    raw = str(meta.get(key) or "").strip().lower()
    if raw in ("true", "1", "yes", "on"):
        return True
    if raw in ("false", "0", "no", "off"):
        return False
    return default


def _program_governance(home, sstore, store, *, program_id, cfg, policy, preflight,
                        now=None, spawn=True, spawner=None) -> dict:
    """Consume finished planner/challenge runs; dispatch the next governance step when asked.

    Loop-safety is structural, not hoped for: the planner dispatches only while NO proposal
    document exists (re-planning is a strategist action -- clear the meta key deliberately), and
    a challenge dispatches only once per proposal (``review_runs`` is durable). A consumed run
    clears its meta key BEFORE anything else can observe it again, so every consumption happens
    at most once per run for a given piece of durable state.
    """
    from quaestor.core import review_contract as rc_mod
    import quaestor.core.planner as planner_mod
    out: dict = {}
    out["planner_consumed"] = _consume_planner_run(sstore, store, program_id=program_id, now=now)
    out["challenge_consumed"] = _consume_plan_challenge(sstore, store, program_id=program_id,
                                                        now=now)
    meta = sstore.get_program_meta(program_id)
    doc = planner_mod.load_proposal_doc(sstore, program_id)
    if (str(meta.get("planning_mode") or "") == "planner_seat" and doc is None
            and not meta.get(planner_mod.PLANNER_RUN_META_KEY)
            and not sstore.lanes(program_id)):
        out["planner_dispatched"] = dispatch_planner(home, sstore, store,
                                                     program_id=program_id, cfg=cfg,
                                                     preflight=preflight, policy=policy,
                                                     now=now, spawn=spawn, spawner=spawner)
    pending = planner_mod.pending_proposal(sstore, program_id)
    fresh_meta = sstore.get_program_meta(program_id)
    requested = pending is not None and (
        _plan_flag(fresh_meta, "plan_challenge", False)
        or any(bool(l.get("plan_review"))
               for l in ((pending.get("proposal") or {}).get("lanes") or [])
               if isinstance(l, Mapping)))
    if requested and not fresh_meta.get(planner_mod.CHALLENGE_RUN_META_KEY) \
            and not (pending.get("review_runs") or ()):
        out["challenge_dispatched"] = _dispatch_reviewer(
            home, sstore, store, program_id=program_id, lane=None, cfg=cfg, policy=policy,
            changed=(), now=now, spawner=spawner, target_class=rc_mod.TARGET_PLAN)
    # THE STRATEGIST SEAT, LAST. It reads the inbox, so it must run AFTER reap has consumed
    # finished runs (tick calls reap first) and after plan governance has had its turn --
    # otherwise the seat answers a question about a plan that is one step out of date, or
    # re-answers something the planner path was already resolving. A program with no seat
    # configured returns immediately, which is every existing deployment.
    out.update(strategist_governance_step(
        home, sstore, store, program_id=program_id, cfg=cfg, preflight=preflight,
        policy=policy, now=now, spawn=spawn, spawner=spawner))
    return out


def dispatch_planner(home, sstore, store, *, program_id, cfg, preflight, policy,
                     now=None, spawn=True, spawner=None) -> str:
    """Dispatch the PLANNER seat over the objective (PRD.md §7.4). Returns run_id or ''.

    The planner runs through EXACTLY the machinery every other seat runs: seat resolution over
    executors.roles.planner via _resolve_executor (chains included), full dispatcher admission,
    READ_ONLY authority, measured run.provenance. Its entire output is a PROPOSAL carried in the
    governed PLAN_REVISION message type; validation is deterministic (_consume_planner_run), and
    adoption lives only in planner.adopt_plan_proposal behind a named strategist actor.
    ``_planner_executor`` is the server-side fixture seam, mirroring ``review_executor``.
    """
    import quaestor.core.planner as planner_mod
    prog = sstore.get_program(program_id)
    meta = sstore.get_program_meta(program_id)
    repo = str(meta.get("repository") or "")
    if prog is None or not repo or not os.path.isdir(repo):
        return ""
    try:
        scripted = json.loads(meta.get("_planner_executor") or "{}")
    except ValueError:
        scripted = {}
    if scripted.get("kind"):
        executor, prov_source = dict(scripted), "lane-script"
    else:
        executor, prov_source = _resolve_executor(
            cfg.executor if cfg else "fake", {"executor": {}}, role_kind="planner",
            role_executor=getattr(cfg, "role_executor", None) if cfg else None,
            chains=getattr(cfg, "role_chains", None) if cfg else None,
            seat_policy=getattr(cfg, "seat_policy", None) if cfg else None,
            pairing_ctx=_independence_ctx(sstore, store, program_id, cfg))
    if executor.get("refusal"):
        # Named refusal at the governance layer: nothing spawns, and the record says why --
        # an unresolvable planner seat must stop the program loudly, never silently re-plan.
        sstore.append_event(ev_mod.new_event(
            ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
            detail={"blocker": ("planner seat refused (%s): %s"
                                % (executor["refusal"],
                                   "; ".join(str(r) for r in executor.get("rationale") or ()))
                                   [:400])[:500]}, now=now))
        return ""
    task_text = _compose_prompt(
        planner_mod.build_plan_task(objective=prog.get("objective") or "",
                                    constraints=_load_json_list(meta.get("constraints_json"))),
        KIND_RESEARCH)
    attempts = int(meta.get("_planner_attempts") or 0) + 1
    spec = DispatchSpec(
        workflow_id=program_id, step_id="%s-plan-r%d" % (program_id, attempts),
        task=task_text, worktree_path=repo, authority_profile=authority_mod.READ_ONLY,
        executor=executor, min_inspected=1, title="plan decomposition",
        timeout_s=policy.run_timeout_s, require_lease=False,
        context={"program_id": program_id, "lane_id": "", "role": "planner"})
    res = dispatch(store, spec, run_root=os.path.join(home, "runs"), preflight=preflight,
                   spawn=spawn, now=now, spawner=spawner)
    if not res.admitted:
        sstore.append_event(ev_mod.new_event(
            ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
            detail={"blocker": "planner run could not be dispatched (%s: %s)"
                               % (res.outcome, res.reason)[:400]}, now=now))
        return ""
    sstore.set_program_meta(program_id, "_planner_attempts", str(attempts))
    sstore.set_program_meta(program_id, planner_mod.PLANNER_RUN_META_KEY, res.run_id)
    store.append_event("run.provenance", run_id=res.run_id,
                       detail=_provenance_detail("planner", executor, prov_source))
    sstore.append_event(ev_mod.new_event(ev_mod.SCHEDULED, program_id=program_id,
                                         run_id=res.run_id,
                                         detail={"role": "planner", "step": spec.step_id},
                                         now=now))
    return res.run_id


def strategist_seat_questions(sstore, program_id: str) -> list:
    """The inbox items a MODEL strategist is shown. Impure (reads the inbox).

    Owner-routed items are INCLUDED so the seat can see they exist and are not its to answer --
    the packet says so, validation refuses a directive against one, and autonomy escalates it.
    Hiding them would leave the seat proposing work that silently depends on an unresolved grant,
    which is a worse failure than showing it something it must decline.
    """
    return [dict(it) for it in inbox(sstore, program_id)["items"]]


def answerable_seat_questions(sstore, program_id: str) -> list:
    """The inbox items this seat could actually ANSWER. Impure.

    A STRICT SUBSET of what it is shown, and the difference is load-bearing. The seat is shown
    owner-routed asks so it can see they exist and decline them, and shown program-level items
    (LANE_FAILED, INTEGRATION_CONFLICT) so its brief is honest -- but it may answer NONE of
    them, and dispatching a turn over only those is dispatching a turn that CANNOT succeed.

    That is not hypothetical. A program whose only open item is an AUTHORITY_REQUEST used to
    dispatch a turn; the packet correctly told the seat to answer only strategist-routed
    questions; the compliant empty response was scored DIRECTIVE_EMPTY; three ticks of correct
    behaviour exhausted the refusal budget and bricked the seat -- permanently, since the
    counter only reset on an admitted turn and no admitted turn was possible. A model doing
    exactly what it was told disabled its own seat.
    """
    return [q for q in strategist_seat_questions(sstore, program_id)
            if str(q.get("message_id") or "") and str(q.get("route") or "") != "OWNER"]


def dispatch_strategist(home, sstore, store, *, program_id, cfg, preflight, policy,
                        now=None, spawn=True, spawner=None) -> str:
    """Dispatch the STRATEGIST seat over the open questions (PRD.md §7). Returns run_id or ''.

    Structurally identical to ``dispatch_planner``: seat resolution over
    ``executors.roles.strategist`` via _resolve_executor (chains included), full dispatcher
    admission, READ_ONLY authority, measured run.provenance. Its entire output is a DIRECTIVE
    PROPOSAL; admission is deterministic (strategist.validate_directive_response) and what
    happens to an admitted directive is core.autonomy's decision, never the model's.

    READ_ONLY IS NOT DECORATIVE HERE. The seat reads a brief assembled from durable rows and
    returns a document; it has no reason to touch the repository, and giving it a write profile
    would hand repo authority to the one seat whose whole job is to be persuaded by prose.
    """
    import quaestor.core.strategist as strat_mod
    from quaestor.adapters import registry as cap_reg
    prog = sstore.get_program(program_id)
    meta = sstore.get_program_meta(program_id)
    repo = str(meta.get("repository") or "")
    if prog is None or not repo or not os.path.isdir(repo):
        return ""
    if not answerable_seat_questions(sstore, program_id):
        # LOOP SAFETY, and BRICK SAFETY. An empty inbox must not spawn a turn with nothing to
        # decide -- the re-dispatch-forever failure the reap/NOTED catch-all already taught this
        # project to design against. It is measured over the ANSWERABLE subset, not the whole
        # inbox: a turn offered only owner-routed asks cannot produce an admissible response, so
        # dispatching one burns a real provider call and then counts the correct answer as a
        # refusal (see answerable_seat_questions).
        return ""
    try:
        scripted = json.loads(meta.get(strat_mod.STRATEGIST_EXECUTOR_META_KEY) or "{}")
    except ValueError:
        scripted = {}
    if scripted.get("kind"):
        executor, prov_source = dict(scripted), "lane-script"
    else:
        executor, prov_source = _resolve_executor(
            cfg.executor if cfg else "fake", {"executor": {}}, role_kind="strategist",
            role_executor=getattr(cfg, "role_executor", None) if cfg else None,
            chains=getattr(cfg, "role_chains", None) if cfg else None,
            seat_policy=getattr(cfg, "seat_policy", None) if cfg else None,
            pairing_ctx=_independence_ctx(sstore, store, program_id, cfg))
    # SEAT SESSION CONTINUITY, for providers that DECLARED they can take one. A strategist that
    # re-reads the brief cold every turn has no memory of why it decided what it decided, and the
    # packet deliberately carries decisions rather than reasoning.
    #
    # The declaration is load-bearing, not decorative: an executor that does not know the field
    # does NOT politely ignore it. FakeConfig(**cfg) raises TypeError on an unexpected key, so
    # handing a session to a provider that never asked for one turns dispatch into a construction
    # crash that reads as a broken installation.
    session = str(meta.get(strat_mod.STRATEGIST_SESSION_KEY) or "")
    if session and not executor.get("refusal") \
            and cap_reg.resumes_session(str(executor.get("kind") or "")):
        cfg_out = dict(executor.get("config") or {})
        cfg_out.setdefault("session_id", session)
        executor = dict(executor, config=cfg_out)
    if executor.get("refusal"):
        sstore.append_event(ev_mod.new_event(
            ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
            detail={"blocker": ("strategist seat refused (%s): %s"
                                % (executor["refusal"],
                                   "; ".join(str(r) for r in executor.get("rationale") or ()))
                                   [:400])[:500]}, now=now))
        return ""
    task_text = _compose_prompt(
        strat_mod.build_strategist_task(sstore.handoff_bundle(program_id)), KIND_RESEARCH)
    attempts = int(meta.get(strat_mod.STRATEGIST_ATTEMPTS_KEY) or 0) + 1
    spec = DispatchSpec(
        workflow_id=program_id, step_id="%s-strat-r%d" % (program_id, attempts),
        task=task_text, worktree_path=repo, authority_profile=authority_mod.READ_ONLY,
        executor=executor, min_inspected=1, title="strategist turn",
        timeout_s=policy.run_timeout_s, require_lease=False,
        context={"program_id": program_id, "lane_id": "", "role": "strategist"})
    res = dispatch(store, spec, run_root=os.path.join(home, "runs"), preflight=preflight,
                   spawn=spawn, now=now, spawner=spawner)
    if not res.admitted:
        sstore.append_event(ev_mod.new_event(
            ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
            detail={"blocker": "strategist run could not be dispatched (%s: %s)"
                               % (res.outcome, res.reason)[:400]}, now=now))
        return ""
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_ATTEMPTS_KEY, str(attempts))
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_RUN_META_KEY, res.run_id)
    store.append_event("run.provenance", run_id=res.run_id,
                       detail=_provenance_detail("strategist", executor, prov_source))
    sstore.append_event(ev_mod.new_event(ev_mod.SCHEDULED, program_id=program_id,
                                         run_id=res.run_id,
                                         detail={"role": "strategist", "step": spec.step_id},
                                         now=now))
    return res.run_id


def _strategist_directives(store, run_id: str):
    """The directives a finished strategist run proposed, or None. PURE over the handoff.

    Read from the SAME place the planner reads its proposal -- the handoff package's report
    messages -- so both seats extract their output through one path. The carrier type is
    OBSERVATION rather than a new message type: the child vocabulary is frozen (core.messages),
    and a seat reporting what it concluded is precisely an observation. The planner documented
    the equivalent choice for PLAN_REVISION; this is the same reasoning, not a second policy.
    """
    h = store.get_handoff(run_id)
    if not h:
        return None
    try:
        handoff = json.loads(h["handoff_json"])
    except (ValueError, TypeError):
        return None
    report = (handoff or {}).get("claude_report") or {}
    for m in (report.get("messages") or []):
        if not isinstance(m, Mapping) or m.get("type") != msg_mod.OBSERVATION:
            continue
        cand = (m.get("detail") or {})
        if isinstance(cand, Mapping) and "directives" in cand:
            return {"directives": cand.get("directives")}
    return None


def approve_pending_directive(sstore, program_id: str, message_id: str, *,
                              actor_id: str = "", now=None) -> dict:
    """Apply ONE queued directive through the ordinary answer path. Impure. Governed op.

    This is the human half of autonomy DEFAULT. It deliberately reuses ``answer`` rather than
    writing a decision itself: approval changes WHO decided, never HOW the decision is recorded,
    and a second write path would be a second policy about what answering means.

    The directive is removed from the queue BEFORE it is applied, so a crash mid-apply cannot
    leave an entry that a later approval would apply twice. Raises ValueError when the id is not
    queued -- an approval for something nobody proposed is a bug in the caller, not a no-op.
    """
    import quaestor.core.strategist as strat_mod
    meta = sstore.get_program_meta(program_id)
    try:
        pending = json.loads(meta.get(strat_mod.PENDING_DIRECTIVES_KEY) or "{}")
    except ValueError:
        pending = {}
    queue = list((pending or {}).get("directives") or ())
    matches = [d for d in queue
               if isinstance(d, Mapping) and str(d.get("message_id")) == str(message_id)]
    if not matches:
        raise ValueError("no directive is queued for message %r" % message_id)
    hit = matches[0]
    # REMOVE EVERY RECORD FOR THIS QUESTION, not just the one applied. Removing by object
    # identity left any duplicate queued, and a second approval would answer the same question
    # again -- two decisions against one evidence ref.
    queue = [d for d in queue
             if not (isinstance(d, Mapping) and str(d.get("message_id")) == str(message_id))]
    existing = sstore.message(str(message_id)) or {}
    if existing.get("answered_by"):
        # ALREADY ANSWERED. answer() would happily record a second decision; refusing here is
        # what makes approval idempotent from the operator's side.
        sstore.set_program_meta(program_id, strat_mod.PENDING_DIRECTIVES_KEY,
                                json.dumps({"directives": queue}))
        raise ValueError("message %r has already been answered; the queued directive was "
                         "discarded rather than applied twice" % message_id)
    sstore.set_program_meta(program_id, strat_mod.PENDING_DIRECTIVES_KEY,
                            json.dumps({"directives": queue}))
    directive_id = answer(sstore, program_id, str(message_id),
                          decision_text=str(hit.get("directive") or ""),
                          rationale=str(hit.get("rationale") or ""),
                          authority=dec_mod.BY_STRATEGIST,
                          actor_id=actor_id or "strategist-approval", now=now)
    return {"approved": str(message_id), "directive_id": directive_id,
            "remaining": len(queue), "authority": dec_mod.BY_STRATEGIST}


def discard_pending_directive(sstore, program_id: str, message_id: str) -> dict:
    """Drop ONE queued directive WITHOUT applying it. Impure.

    The other half of a review surface: an operator who disagrees with a proposed directive must
    be able to reject it, and rejecting must not silently re-open the question to the same seat
    on the next tick -- so the QUESTION stays open and a human answers it themselves.
    """
    import quaestor.core.strategist as strat_mod
    meta = sstore.get_program_meta(program_id)
    try:
        pending = json.loads(meta.get(strat_mod.PENDING_DIRECTIVES_KEY) or "{}")
    except ValueError:
        pending = {}
    queue = list((pending or {}).get("directives") or ())
    keep = [d for d in queue
            if not (isinstance(d, Mapping) and str(d.get("message_id")) == str(message_id))]
    if len(keep) == len(queue):        # nothing matched
        raise ValueError("no directive is queued for message %r" % message_id)
    sstore.set_program_meta(program_id, strat_mod.PENDING_DIRECTIVES_KEY,
                            json.dumps({"directives": keep}))
    return {"discarded": str(message_id), "remaining": len(keep)}


def _count_strategist_refusal(sstore, program_id, run_id, errors, *, now=None) -> int:
    """Record ONE refused strategist turn and return the new consecutive count. Impure.

    Program-level, so the blocker is a BLOCKED event rather than a BLOCKER message: the qualified
    message contract requires every message to belong to a lane, and a refused TURN belongs to
    none (_record_blocker documents the same reasoning for its own lane-less path).
    """
    import quaestor.core.strategist as strat_mod
    meta = sstore.get_program_meta(program_id)
    # SCOPED TO THE WORK ON OFFER. A seat that could not answer question set X must not stay
    # halted once the program has moved on to set Y -- the budget means "cannot handle THIS",
    # never "broken forever", and the counter is durable meta that no surface clears.
    scope = strat_mod.answerable_fingerprint(
        answerable_seat_questions(sstore, program_id))
    previous = str(meta.get(strat_mod.STRATEGIST_REFUSAL_SCOPE_KEY) or "")
    count = (int(meta.get(strat_mod.STRATEGIST_REFUSALS_KEY) or 0) + 1) if scope == previous \
        else 1
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_REFUSALS_KEY, str(count))
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_REFUSAL_SCOPE_KEY, scope)
    _record_blocker(sstore, program_id, "", run_id,
                    "strategist response refused (%d consecutive): %s"
                    % (count, "; ".join(str(e) for e in errors)[:380]), now=now)
    return count


def _consume_strategist_run(sstore, store, *, program_id, now=None) -> dict:
    """Consume a finished strategist run into applied / queued / escalated directives. Impure.

    The meta key is cleared FIRST so consumption is exactly-once per run, exactly as
    _consume_planner_run does: a crash between validation and application must not replay the
    turn, because replaying it would re-answer questions the first pass already answered and
    record a second, contradicting decision against the same evidence ref.
    """
    import quaestor.core.autonomy as auto_mod
    import quaestor.core.strategist as strat_mod
    meta = sstore.get_program_meta(program_id)
    run_id = str(meta.get(strat_mod.STRATEGIST_RUN_META_KEY) or "")
    if not run_id:
        return {}
    run = store.get_run(run_id)
    if run is None:
        sstore.set_program_meta(program_id, strat_mod.STRATEGIST_RUN_META_KEY, "")
        return {"strategist_run": run_id}
    state = str(run["execution_state"])
    if domain.is_active(state):
        return {}          # still running; consume on a later tick
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_RUN_META_KEY, "")

    out = {"strategist_run": run_id, "applied": [], "queued": [], "escalated": [],
           "refused": []}
    # Record the session this turn ran in, BEFORE any admission decision: the thread exists
    # whether or not its answer was well-formed, and a refused turn that lost the binding would
    # start the next one cold for no reason.
    result_row = store.get_result(run_id) or {}
    landed = str(result_row.get("session_id") or "")
    if landed:
        sstore.set_program_meta(program_id, strat_mod.STRATEGIST_SESSION_KEY, landed)
        out["session_id"] = landed
    questions = strategist_seat_questions(sstore, program_id)
    by_id = {str(q.get("message_id")): q for q in questions if q.get("message_id")}
    doc = _strategist_directives(store, run_id)
    if doc is None:
        out["refused"] = ["%s: strategist run ended %s without a parseable directive response"
                          % (strat_mod.DIRECTIVE_INVALID, state)]
        _count_strategist_refusal(sstore, program_id, run_id, out["refused"], now=now)
        return out
    ok, errors = strat_mod.validate_directive_response(doc, open_questions=questions)
    if not ok:
        # REFUSED, RECORDED, ESCALATED -- never silently dropped. A seat whose output vanished
        # would look identical to a seat that had nothing to say, and the operator would wait
        # for an answer that was already thrown away.
        out["refused"] = errors
        _count_strategist_refusal(sstore, program_id, run_id, errors, now=now)
        sstore.append_event(ev_mod.new_event(
            ev_mod.EXECUTOR_MESSAGE, program_id=program_id, run_id=run_id,
            actor_id="strategist-seat",
            detail={"message_type": msg_mod.OBSERVATION, "admission_outcome": "REFUSED"},
            now=now))
        return out

    mode = meta.get(auto_mod.AUTONOMY_MODE_KEY)
    try:
        pending = json.loads(meta.get(strat_mod.PENDING_DIRECTIVES_KEY) or '{"directives": []}')
    except ValueError:
        pending = {"directives": []}
    if not isinstance(pending, Mapping) or not isinstance(pending.get("directives"), list):
        pending = {"directives": []}
    queue = list(pending["directives"])
    try:
        return _dispose_directives(sstore, program_id, run_id, doc, by_id, queue, mode,
                                   out=out, now=now)
    except Exception as exc:  # noqa: BLE001
        # NEITHER ADMITTED NOR REFUSED IS THE ONE OUTCOME THAT MUST NOT EXIST. The run key was
        # cleared at the top of this function, so an escaping exception left the turn counted
        # as nothing at all: the budget never advanced, the reset never ran, and the seat
        # re-dispatched the same doomed turn every tick forever. Counting it as a refusal is
        # what makes the budget total over outcomes.
        out["refused"] = ["%s: disposition failed: %s: %s"
                          % (strat_mod.DIRECTIVE_INVALID, type(exc).__name__, exc)]
        _count_strategist_refusal(sstore, program_id, run_id, out["refused"], now=now)
        return out


def _dispose_directives(sstore, program_id, run_id, doc, by_id, queue, mode, *, out, now):
    """Apply / queue / escalate each admitted directive. Impure. Split out so the caller can
    treat ANY failure here as a refusal rather than as a turn that never happened."""
    import quaestor.core.autonomy as auto_mod
    import quaestor.core.strategist as strat_mod
    for item in doc["directives"]:
        mid = str(item["message_id"])
        q = by_id.get(mid) or {}
        disp, why = auto_mod.disposition(mode, route=str(q.get("route") or ""),
                                         kind=str(q.get("kind") or ""))
        record = {"message_id": mid, "directive": str(item["directive"]),
                  "rationale": str(item.get("rationale") or ""), "why": why,
                  "run_id": run_id, "lane_id": str(q.get("lane_id") or "")}
        if disp == auto_mod.APPLY:
            answer(sstore, program_id, mid, decision_text=record["directive"],
                   rationale=record["rationale"], authority=dec_mod.BY_STRATEGIST,
                   actor_id="strategist-seat", now=now)
            out["applied"].append(record)
        elif disp == auto_mod.QUEUE_FOR_APPROVAL:
            # ONE PENDING DIRECTIVE PER QUESTION. Two records for one message_id let approval
            # apply the same question twice: approve removes one by identity, the other stays
            # queued, and neither answer() nor answer_message() refuses an already-answered
            # message -- so a second decision lands against the same evidence ref.
            queue = [d for d in queue
                     if not (isinstance(d, Mapping) and str(d.get("message_id")) == mid)]
            queue.append(record)
            out["queued"].append(record)
        else:
            sstore.record_message(msg_mod.new_message(
                msg_mod.OWNER_ESCALATION, actor_id="strategist-seat", program_id=program_id,
                lane_id=record["lane_id"], caused_by=mid,
                payload=("a model strategist was asked to dispose of an owner-routed item and "
                         "declined: %s" % why)[:2000], now=now))
            out["escalated"].append(record)
    sstore.set_program_meta(program_id, strat_mod.PENDING_DIRECTIVES_KEY,
                            json.dumps({"directives": queue}))
    sstore.set_program_meta(program_id, strat_mod.STRATEGIST_REFUSALS_KEY, "0")
    sstore.append_event(ev_mod.new_event(
        ev_mod.EXECUTOR_MESSAGE, program_id=program_id, run_id=run_id,
        actor_id="strategist-seat",
        detail={"message_type": msg_mod.OBSERVATION, "admission_outcome": "ADMITTED",
                "applied": len(out["applied"]), "queued": len(out["queued"]),
                "escalated": len(out["escalated"]),
                "autonomy_mode": auto_mod.resolve_mode(mode)}, now=now))
    return out


def strategist_governance_step(home, sstore, store, *, program_id, cfg, preflight, policy,
                               now=None, spawn=True, spawner=None) -> dict:
    """Consume a finished strategist turn, then dispatch the next one if warranted.

    LOOP SAFETY IS STRUCTURAL, exactly as it is for the planner: a turn dispatches only while NO
    strategist run is outstanding AND the inbox actually holds something (checked inside
    dispatch_strategist). Either guard alone is insufficient -- without the first a slow seat
    fans out, without the second a seat that answers nothing spins.
    """
    import quaestor.core.strategist as strat_mod
    out = {"strategist_consumed": {}, "strategist_dispatched": ""}
    meta = sstore.get_program_meta(program_id)
    if str(meta.get(strat_mod.STRATEGY_MODE_KEY) or "") != strat_mod.STRATEGIST_SEAT:
        return out          # the human holds the seat; this is the default for every program
    out["strategist_consumed"] = _consume_strategist_run(
        sstore, store, program_id=program_id, now=now)
    fresh = sstore.get_program_meta(program_id)
    refusals = int(fresh.get(strat_mod.STRATEGIST_REFUSALS_KEY) or 0)
    # The halt applies only while the SAME work is on offer; new answerable questions clear it.
    if refusals and strat_mod.answerable_fingerprint(
            answerable_seat_questions(sstore, program_id)) != str(
                fresh.get(strat_mod.STRATEGIST_REFUSAL_SCOPE_KEY) or ""):
        sstore.set_program_meta(program_id, strat_mod.STRATEGIST_REFUSALS_KEY, "0")
        refusals = 0
    if refusals >= strat_mod.MAX_CONSECUTIVE_REFUSALS:
        # THE SEAT IS BROKEN, NOT MERELY UNLUCKY. Stop dispatching and leave the questions for a
        # human. Retrying a fourth time would burn a real provider call per tick for a fault
        # nothing in this loop can fix -- and unattended operation is exactly when nobody is
        # watching it happen.
        out["strategist_halted"] = refusals
        return out
    if not fresh.get(strat_mod.STRATEGIST_RUN_META_KEY):
        out["strategist_dispatched"] = dispatch_strategist(
            home, sstore, store, program_id=program_id, cfg=cfg, preflight=preflight,
            policy=policy, now=now, spawn=spawn, spawner=spawner)
    return out


def _consume_planner_run(sstore, store, *, program_id, now=None) -> dict:
    """Consume a finished planner run into a PENDING proposal document. Impure.

    Deterministic admission (PRD.md §7.4): the structured result's single PLAN_REVISION message
    is validated by planner.validate_plan_proposal BEFORE anything durable changes shape. A valid
    proposal becomes a PENDING document surfaced to the strategist inbox; an invalid one is
    REFUSED with its error list recorded and escalated -- waiting is acceptable, silence is not.
    Either way the meta key is cleared FIRST, so consumption is exactly-once per run.
    """
    import quaestor.core.planner as planner_mod
    meta = sstore.get_program_meta(program_id)
    run_id = str(meta.get(planner_mod.PLANNER_RUN_META_KEY) or "")
    if not run_id:
        return {}
    run = store.get_run(run_id)
    if run is None:
        sstore.set_program_meta(program_id, planner_mod.PLANNER_RUN_META_KEY, "")
        return {"planner_run": run_id}
    state = str(run["execution_state"])
    if domain.is_active(state):
        return {}          # still running; consume on a later tick
    sstore.set_program_meta(program_id, planner_mod.PLANNER_RUN_META_KEY, "")
    prov = _provenance_provider(store, run_id)
    provenance = {"role": "planner", "provider": str(prov.get("provider") or ""),
                  "source": str(prov.get("source") or ""), "run_id": run_id,
                  "actor_id": "executor:%s" % (prov.get("provider") or "unknown")}
    h = store.get_handoff(run_id)
    handoff = json.loads(h["handoff_json"]) if h else {}
    report = handoff.get("claude_report") or {}
    proposal = None
    for m in (report.get("messages") or []):
        cand = (m.get("detail") or {}).get("proposal") \
            if isinstance(m, Mapping) and m.get("type") == msg_mod.PLAN_REVISION else None
        if isinstance(cand, dict):
            proposal = cand
            break
    out: dict = {"planner_run": run_id}
    ok, errors = (False, ["%s: planner run ended %s without a parseable PLAN_REVISION proposal"
                          % (planner_mod.PROPOSAL_INVALID, state)]) if proposal is None \
        else planner_mod.validate_plan_proposal(proposal)
    if ok:
        doc = planner_mod.new_proposal_doc(
            proposal=proposal, planner_provenance=provenance,
            require_plan_review=_plan_flag(sstore.get_program_meta(program_id),
                                           "require_plan_review", True))
        doc["created_at"] = float(now if now is not None else time.time())
        planner_mod.save_proposal_doc(sstore, program_id, doc)
        out["outcome"] = "PENDING"
    else:
        refused = planner_mod.new_proposal_doc(proposal=(proposal or {}),
                                               planner_provenance=provenance)
        refused.update({"status": planner_mod.STATUS_REFUSED, "errors": errors})
        planner_mod.save_proposal_doc(sstore, program_id, refused)
        _record_blocker(sstore, program_id, "", run_id,
                        "PLAN_PROPOSAL refused by deterministic admission: %s"
                        % ("; ".join(errors)[:400]), now=now)
        out["outcome"] = "REFUSED"
    sstore.append_event(ev_mod.new_event(ev_mod.EXECUTOR_MESSAGE, program_id=program_id,
                                         run_id=run_id, actor_id=provenance["actor_id"],
                                         detail={"message_type": msg_mod.PLAN_REVISION,
                                                 "admission_outcome": out.get("outcome")},
                                         now=now))
    return out


def _consume_plan_challenge(sstore, store, *, program_id, now=None) -> dict:
    """Attach a finished plan-challenge reviewer's findings to the PENDING proposal.

    The challenge run is program-level (no lane binding), so its REVIEW_FINDING messages are
    attached HERE, straight from the handoff package, into the proposal document -- where they
    gate adoption (planner.adopt_plan_proposal refuses while require_plan_review stands and
    CRITICAL/HIGH findings are unresolved). Each finding also lands in the event log so the
    REVIEW_FINDING vocabulary stays assertable without reading program_meta.
    """
    import quaestor.core.planner as planner_mod
    from quaestor.core import review_contract as rc_mod
    run_id = str(sstore.get_program_meta(program_id).get(
        planner_mod.CHALLENGE_RUN_META_KEY) or "")
    if not run_id:
        return {}
    run = store.get_run(run_id)
    if run is None:
        sstore.set_program_meta(program_id, planner_mod.CHALLENGE_RUN_META_KEY, "")
        return {"challenge_run": run_id}
    state = str(run["execution_state"])
    if domain.is_active(state):
        return {}
    sstore.set_program_meta(program_id, planner_mod.CHALLENGE_RUN_META_KEY, "")
    doc = planner_mod.load_proposal_doc(sstore, program_id)
    if doc is None:
        return {"challenge_run": run_id}
    findings: list = []
    if state == domain.HANDOFF_READY:
        h = store.get_handoff(run_id)
        handoff = json.loads(h["handoff_json"]) if h else {}
        for i, m in enumerate((handoff.get("claude_report") or {}).get("messages") or []):
            if not isinstance(m, Mapping) or m.get("type") != msg_mod.REVIEW_FINDING:
                continue
            # Severity rides at the message TOP level on the wire (see the worker's two-way
            # delivery); parse_finding_message expects it INSIDE detail -- join them here,
            # once, so the proposal document sees the reviewer's real severity.
            detail_for_parse = dict(m.get("detail") or {})
            if m.get("severity"):
                detail_for_parse.setdefault("severity", m["severity"])
            f = rc_mod.parse_finding_message(json.dumps(detail_for_parse),
                                             str(m.get("payload") or ""))
            findings.append({
                "finding_id": "pf_" + sha256_text("%s|%d|%s" % (run_id, i, f.title))[:12],
                "title": f.title, "severity": f.severity, "location": f.location,
                "failure_mode": f.failure_mode, "resolved": False, "run_id": run_id})
    result = rc_mod.ReviewResult(review_id="rev_" + uuid.uuid4().hex[:12], kind=rc_mod.ADVERSARIAL,
                                 outcome=rc_mod.INCONCLUSIVE,
                                 findings=tuple(rc_mod.Finding(
                                     finding_id=f["finding_id"], title=f["title"],
                                     severity=f["severity"], location=f["location"],
                                     failure_mode=f["failure_mode"]) for f in findings),
                                 reviewer_actor_id="adversarial plan challenger",
                                 inspected_count=max(1, len(findings)))
    summary = rc_mod.summarize(result)
    sstore.record_review(result.review_id, program_id=program_id, lane_id="", kind=rc_mod.ADVERSARIAL,
                         outcome=summary["outcome"], result=summary, run_id=run_id)
    doc.setdefault("findings", []).extend(findings)
    planner_mod.save_proposal_doc(sstore, program_id, doc)
    for f in findings:
        sstore.append_event(ev_mod.new_event(ev_mod.REVIEW_FINDING, program_id=program_id,
                                             run_id=run_id, detail=dict(f), now=now))
    sstore.append_event(ev_mod.new_event(ev_mod.REVIEW_COMPLETED, program_id=program_id,
                                         run_id=run_id,
                                         detail={"review_id": result.review_id,
                                                 "target_class": "PLAN",
                                                 "outcome": summary["outcome"]}, now=now))
    return {"challenge_run": run_id, "findings": len(findings), "outcome": summary["outcome"]}


# ---------------------------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------------------------
def _resolve_executor(cfg_executor: str, lane_task: Mapping, *, fix_override: Mapping | None = None,
                      attempt: int | None = None, role_kind: str | None = None,
                      role_executor: Mapping | None = None,
                      chains: Mapping | None = None,
                      seat_policy: Mapping | None = None,
                      chain_exhausted: Mapping | None = None,
                      ambiguity=None,
                      pairing_ctx: Mapping | None = None) -> tuple:
    """Resolve (executor spec, provenance source) for THIS attempt.

    Precedence (PRD.md §7): explicit fix_override, then ``attempt_variants[i]``
    (a fixture seam that lets one lane behave differently per attempt -- ask on attempt 0, act
    on attempt 1), then the lane's static script, then THIS role's seat resolution over the
    manifest's ``executors.roles`` entry -- an ordered providers.chain when one is configured
    (reconciliation-aware failover via adapters.registry.chain_next), else the plain pin --
    then the project default. The source travels with the spec because PRD.md §7.1 requires
    every run's seat to record WHY it held that provider -- a measured fact about dispatch,
    not something the child reports. There is deliberately NO wire field here: these are
    server-side fixture/testing seams only.

    The fixture seams (fix_override/attempt_variants/lane script) bypass the capability
    namespace on purpose: they are server-side test fixtures, not configuration a manifest
    author can reach. Every CONFIGURED path (chain member, roles pin, project default) is
    checked against the declared registry instead -- an unknown kind there is a NAMED
    refusal (SEAT_UNRESOLVABLE), never a silent fallback to whatever else is configured.
    """
    if isinstance(fix_override, Mapping) and fix_override.get("kind"):
        return _executor_spec(str(fix_override["kind"]), fix_override.get("config"),
                              "attempt-variant")
    scripted = dict(lane_task.get("executor") or {})
    variants = scripted.get("attempt_variants")
    if isinstance(variants, list) and variants and attempt is not None:
        pick = variants[min(int(attempt), len(variants) - 1)]
        if isinstance(pick, Mapping) and pick.get("kind"):
            return _executor_spec(str(pick["kind"]), pick.get("config"), "attempt-variant")
    if scripted.get("kind"):
        return _executor_spec(str(scripted["kind"]), scripted.get("config"), "lane-script")
    pins = role_executor if isinstance(role_executor, Mapping) else {}
    chains_map = chains if isinstance(chains, Mapping) else {}
    if role_kind and chains_map.get(str(role_kind)):
        # §3 provider-chain layer: first non-exhausted, policy-clean candidate wins.
        from quaestor.adapters import registry as cap_reg
        dead = {str(k) for k in ((chain_exhausted or {}).get(str(role_kind)) or ())} \
            if isinstance(chain_exhausted, Mapping) else set()
        amb = ambiguity if isinstance(ambiguity, cap_reg.AmbiguityState) else cap_reg.AmbiguityState()
        decision = cap_reg.chain_next(
            str(role_kind), chains_map[str(role_kind)], dead, amb,
            pairing=_pairing_gate(pairing_ctx, str(role_kind)))
        if decision.kind:
            # A chain-resolved winner takes the SAME admission gate as a pinned seat (bd
            # quaestor-ubg): declared-namespace check, seat policy, write ceiling, and
            # buildability. A chain that exhausts onto a kind this build cannot construct is
            # refused HERE, by name -- it never reaches build() to die there.
            return _seat_spec(decision.kind, None, "roles-chain", role_kind=role_kind,
                              seat_policy=seat_policy)
        # Named refusal travels to the caller as a spec the dispatcher never sees.
        return ({"kind": decision.refusal, "refusal": decision.refusal,
                 "rationale": list(decision.rationale)}, "roles-chain-refused")
    if role_kind and str(pins.get(role_kind) or ""):
        return _seat_spec(str(pins[role_kind]), None, "roles-config", role_kind=role_kind,
                          seat_policy=seat_policy)
    # NO SUBSTITUTION. This read `str(cfg_executor or "fake")`, so an undeclared executor became
    # the test double here even after config.load stopped doing it -- which would have left the
    # empty-seat refusal in _seat_spec unreachable from the default path, a guard that cannot
    # fire. An empty kind now reaches _seat_spec and is refused by name.
    return _seat_spec(str(cfg_executor or ""), {}, "default-config", role_kind=role_kind,
                      seat_policy=seat_policy)


def _provenance_detail(role: str, executor: Mapping, source: str) -> dict:
    """The MEASURED seat tuple for run.provenance: role, provider, model_family, model.

    Everything here is derived from the RESOLVED dispatch spec -- what was actually sent to the
    executor layer -- never from anything a model reports about itself (PRD.md §7.1).
    ``model_family`` is DERIVED from the kind via the capability registry (bd quaestor-kaz.11:
    it used to be claimed but never written); ``model`` is the gateway-pinned model when the
    kind names one, else the spec's configured model, else empty -- a transport with no model
    records no model rather than a plausible-looking blank-filler.
    """
    from quaestor.adapters import registry as cap_reg
    spec = executor if isinstance(executor, Mapping) else {}
    kind = str(spec.get("kind") or "")
    _base, _sep, pinned = kind.partition(":")
    cfg = spec.get("config") if isinstance(spec.get("config"), Mapping) else {}
    model = str(pinned or "").strip() or str((cfg or {}).get("model") or "").strip()
    return {"role": role, "provider": kind,
            "model_family": cap_reg.provider_family(kind),
            "model": model, "source": source}


def _pairing_gate(pairing_ctx, role: str):
    """Build the chain_next pairing callable for ONE seat from the program context.

    The gate consults the MEASURED seats already recorded this program: a chain candidate
    whose family matches a configured-pair partner's measured family is rejected BEFORE it
    can take the seat -- PRD.md §7.2: "a fallback that would violate a required
    provider-family separation must be refused rather than silently weakening review
    independence".
    """
    if not isinstance(pairing_ctx, Mapping):
        return None
    if not (pairing_ctx.get("require_distinct_between") or
            pairing_ctx.get("require_distinct_for")):
        return None
    from quaestor.adapters import registry as cap_reg

    def gate(candidate: str) -> str:
        for pair in (pairing_ctx.get("require_distinct_between") or ()):
            if role not in pair:
                continue
            other = pair[1] if pair[0] == role else pair[0]
            recorded = str((pairing_ctx.get("families") or {}).get(other) or "")
            if not recorded:
                continue
            why = cap_reg.check_pairing(pairing_ctx, role, candidate, other, recorded, ())
            if why:
                return "%s vs %s holding %s" % (candidate, other, recorded)
        return ""
    return gate


#: Seats whose runs may write to the repository. A provider declared non-write-capable is a
#: TRANSPORT -- it carries a prompt and returns text -- and seating one here would hand repo
#: authority to something that cannot exercise it, or worse, to something that can.
WRITING_SEATS = ("implementation", "integration")


def _seat_spec(kind: str, config, source: str, *, role_kind: str | None = None,
               seat_policy: Mapping | None = None) -> tuple:
    """Namespace-checked executor spec. PURE apart from the declaration and buildability
    lookups (the latter resolved through the provider seam, bd quaestor-ubg).

    A kind with no capability declaration refuses BY NAME here rather than flowing into
    dispatch: an unresolvable seat must stop the program loudly, not silently seat a
    different provider than the manifest named (PRD.md §7 matrix). So does a kind
    that is declared but has no constructible executor in this build: "routable" never
    outruns "shipped".

    THE WRITE CEILING IS ENFORCED HERE, not only in ``resolve_seat``. That function consults
    ``write_capable`` but its one production caller passes empty constraints, so a manifest
    hand-pinning a non-write-capable transport to ``implementation`` reached dispatch unchecked
    -- which made "a transport can never hold a writing seat" true of the seat-picker and false
    of the path that actually runs things. This is the path that actually runs things.
    """
    from quaestor.adapters import registry as cap_reg
    from quaestor import branding as _branding
    if not str(kind or "").strip():
        # NAMED, not a crash and not a silent substitution. The manifest declared no executor
        # for this seat and none was inherited; saying so is the whole point.
        return ({"kind": cap_reg.SEAT_UNRESOLVABLE, "refusal": cap_reg.SEAT_UNRESOLVABLE,
                 "rationale": [
                     "seat %r has no executor: the manifest declares no executor.default and "
                     "pins nothing for this seat. Run `%s` to see which agents this machine "
                     "has, then set executor.default."
                     % (role_kind or "(unnamed)", _branding.command("connect"))]},
                source + "-refused")
    if not cap_reg.is_declared(kind):
        return ({"kind": cap_reg.SEAT_UNRESOLVABLE, "refusal": cap_reg.SEAT_UNRESOLVABLE,
                 "rationale": ["kind %r has no capability declaration in the provider "
                               "registry" % kind]},
                source + "-refused")
    # BUILDABILITY IS ADMITTED, NOT DISCOVERED AT BUILD (bd quaestor-ubg). PROVIDER_REGISTRY and
    # executors.registry.KNOWN_KINDS were two vocabularies for one fact, and a seat routed to a
    # declared-but-unconstructible kind (gemini-cli, gpt-plan, local-llama) died in build() --
    # AFTER admission had said yes. The buildable set is asked through the provider seam
    # (importlib, same inversion as _preflight_for), and a declared kind this build cannot
    # construct is refused HERE, by name. "Routable" never again outruns "shipped".
    import importlib
    ex_reg = importlib.import_module("quaestor.executors.registry")
    if not ex_reg.is_buildable(kind):
        return ({"kind": cap_reg.SEAT_UNRESOLVABLE, "refusal": cap_reg.SEAT_UNRESOLVABLE,
                 "rationale": ["%s: kind %r is declared in the provider registry but this "
                               "build ships no executor for it; refusing the seat at "
                               "admission rather than failing later at build"
                               % (ex_reg.NOT_BUILDABLE_IN_THIS_BUILD, kind)]},
                source + "-refused")
    # THE DECLARED SEAT POLICY, ENFORCED WHERE RUNS ACTUALLY START. adapters.registry.resolve_seat
    # consults these too, but it has no production caller -- so before this, a manifest declaring
    # `executors.policy.credential_modes: [subscription]` was advertised, parsed, and never
    # applied to anything. One evaluator (constraint_refusals) serves both, because two
    # implementations of an admission rule is one implementation and one decoration.
    constraints = dict(seat_policy or {})
    if str(role_kind or "") in WRITING_SEATS:
        constraints["write_capable"] = True
    if constraints:
        try:
            why = cap_reg.constraint_refusals(kind, constraints)
        except ValueError as exc:
            return ({"kind": cap_reg.SEAT_UNRESOLVABLE, "refusal": cap_reg.SEAT_UNRESOLVABLE,
                     "rationale": [str(exc)]}, source + "-refused")
        if why:
            return ({"kind": cap_reg.SEAT_UNRESOLVABLE, "refusal": cap_reg.SEAT_UNRESOLVABLE,
                     "rationale": ["seat %r refuses %r: %s"
                                   % (role_kind or "(unnamed)", kind, "; ".join(why))]},
                    source + "-refused")
    return _executor_spec(kind, config, source)


def _executor_spec(kind: str, config, source: str) -> tuple:
    """Normalize one resolved spec. PURE. A bare fake still gets its deterministic scenario."""
    out: dict = {"kind": str(kind)}
    if config:
        out["config"] = dict(config)
    elif out["kind"] == "fake":
        out["config"] = {"scenario": "OK_PASS"}
    return out, source


def _executor_for(cfg_executor: str, lane_task: Mapping, fix_override: Mapping | None = None,
                  attempt: int | None = None, role_kind: str | None = None,
                  role_executor: Mapping | None = None) -> dict:
    """The executor spec alone; callers that also need the provenance source use
    _resolve_executor. Kept as a facade so existing call sites/tests stay valid."""
    return _resolve_executor(cfg_executor, lane_task, fix_override=fix_override,
                             attempt=attempt, role_kind=role_kind,
                             role_executor=role_executor)[0]


def _load_json_doc(text) -> dict:
    try:
        v = json.loads(text or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def _resume_directive(sstore: StrategicStore, lane_id: str) -> str:
    """The latest unanswered-for directive text for this lane, if resuming after a wait."""
    rows = [m for m in sstore.messages(lane_id) if m["message_type"] == msg_mod.DIRECTIVE]
    return str(rows[-1]["payload"]) if rows else ""


def schedule(home: str, sstore: StrategicStore, store: Store, *, program_id: str,
             cfg, policy: ProgramPolicy, preflight, spawn=True, now: float | None = None,
             spawner=None) -> dict:
    """Dispatch every READY lane within the concurrency ceiling. Impure.

    READY means: PLANNED, dependency-satisfied, not waiting, and no unprocessed run already
    bound. Real-child concurrency is enforced twice -- here by the ceiling, and again inside
    dispatcher.concurrency for real executors -- because a limit enforced in one place is a limit
    one refactor away from gone.

    ``spawner`` injects HOW a worker process starts. Production leaves it None (detached child);
    tests supply an in-process runner so the full ladder executes without process-spawn latency.
    """
    t = float(now if now is not None else time.time())
    lanes = sstore.lanes(program_id)
    deps = sstore.dependencies(program_id)
    blocking = prog_mod.blocking_dependencies({l.lane_id: l for l in lanes}, deps)
    # A dependency on an ABANDONED lane cannot gate work forever: abandonment was a recorded
    # DECISION (its objective was fulfilled elsewhere or withdrawn). Treat it as resolved and
    # let the record show both halves.
    abandoned_ids = {l.lane_id for l in lanes if l.state == prog_mod.LANE_ABANDONED}
    blocking = {k: [d for d in v if d not in abandoned_ids] for k, v in blocking.items()}
    blocking = {k: v for k, v in blocking.items() if v}
    active_real = [r for r in store.runs_in_states(domain.ACTIVE_STATES)]
    started, skipped = [], []
    # §3 epistemic-independence context, built ONCE per tick from MEASURED provenance: which
    # seat holds which provider is read from run.provenance events (what was dispatched),
    # never from configuration claims about what should be holding it.
    from quaestor.adapters import registry as cap_reg
    pctx = _independence_ctx(sstore, store, program_id, cfg)

    for lane in lanes:
        if len(started) + _real_active(store, active_real) >= max(1, policy.max_concurrent_executors) \
                and spawn:
            break
        # Every SCHEDULING ATTEMPT gets a fresh identity component (sched_seq): a refused
        # dispatch (e.g. the real-child concurrency ceiling) still consumes its dispatch key,
        # so a lane retrying after headroom MUST present a new key or it collides as
        # DUPLICATE forever -- measured exactly that way on the first live program.
        task_doc = sstore.get_lane_task(lane.lane_id)
        if not task_doc["task"]:
            continue
        if lane.state not in (prog_mod.LANE_PLANNED, prog_mod.LANE_ACTIVE):
            continue
        if blocking.get(lane.lane_id):
            skipped.append({"lane_id": lane.lane_id, "why": "DEPENDENCIES",
                            "blocking": blocking[lane.lane_id]})
            continue
        if any(not r["processed"] for r in sstore.runs_for_lane(lane.lane_id)):
            skipped.append({"lane_id": lane.lane_id, "why": "RUN_IN_FLIGHT"})
            continue

        wt = _ensure_lane_worktree(home, sstore, program_id, lane)
        if not wt.get("ok"):
            skipped.append({"lane_id": lane.lane_id, "why": "WORKTREE", "detail": wt.get("error")})
            continue
        synced = _sync_dependencies(home, sstore, program_id, lane)
        if not synced.get("ok"):
            skipped.append({"lane_id": lane.lane_id, "why": "DEPENDENCY_SYNC",
                            "detail": synced.get("error")})
            _escalate_sync_failure(sstore, program_id=program_id, lane=lane,
                                   error=str(synced.get("error") or ""))
            continue
        # NOTE DELIBERATE ABSENCE: the success-side counter clear does NOT live here. Clearing
        # pre-dispatch races the worker's own checkpoint save (measured: the worker rewrites
        # the whole document from its load-time snapshot, resurrecting the counter). A bound
        # unprocessed run IS the proof sync succeeded; reap clears there, after the worker
        # can no longer overwrite it. See _clear_sync_failure.

        profile = PROFILE_FOR_KIND[lane.kind]
        attempt_no = int(task_doc["attempt"])
        # Variant index = fix attempts + ask-pauses, so a resumed lane advances past its
        # asking behaviour; the REVIEW budget (§47) still counts only real fix attempts.
        ask_count = int((task_doc["checkpoint"] or {}).get("ask_count") or 0)
        variant_index = attempt_no + ask_count
        ck_amb = cap_reg.AmbiguityState(
            possible_write=bool((task_doc["checkpoint"] or {}).get("possible_write")))
        executor, prov_source = _resolve_executor(
            cfg.executor if cfg else "fake", task_doc,
            fix_override=_load_json_doc(
                sstore.get_program_meta(program_id).get("_fix_executor_json"))
            if attempt_no >= 1 else None,
            attempt=variant_index, role_kind=lane.kind,
            role_executor=getattr(cfg, "role_executor", None) if cfg else None,
            chains=getattr(cfg, "role_chains", None) if cfg else None,
            seat_policy=getattr(cfg, "seat_policy", None) if cfg else None,
            chain_exhausted={lane.kind: sorted(cap_reg.exhausted_for(
                task_doc["checkpoint"], lane.kind))},
            ambiguity=ck_amb, pairing_ctx=pctx)
        if executor.get("refusal"):
            # A named seat refusal (chain blocked/exhausted/policy, undeclared kind): the
            # dispatcher NEVER sees a fabricated spec. The lane parks for the strategist --
            # waiting is acceptable; silently seating the wrong provider is not.
            skipped.append({"lane_id": lane.lane_id, "why": str(executor["refusal"])})
            _refuse_seat(sstore, program_id, lane, str(executor["refusal"]),
                         executor.get("rationale") or (), now=t)
            continue
        # §3 ADMISSION: the seat about to dispatch must not share a family with any
        # configured-pair partner whose seat is already MEASURED (run.provenance). This runs
        # before spawn -- a policy breach is stopped at admission, not discovered after.
        pair_refusal = _pairing_admission_refusal(pctx, lane.kind,
                                                  str(executor.get("kind") or ""))
        if pair_refusal:
            skipped.append({"lane_id": lane.lane_id, "why": pair_refusal})
            _refuse_seat(sstore, program_id, lane, pair_refusal,
                         ["seat %s -> %s breaches require_distinct_provider_between"
                          % (lane.kind, executor.get("kind"))], now=t)
            continue
        task_text = task_doc["task"]
        directive = _resume_directive(sstore, lane.lane_id)
        if directive:
            task_text += ("\n\nSTRATEGIST DECISION (binding, recorded in the decision ledger):\n"
                          "%s" % directive)
        fix_findings = list(task_doc["checkpoint"].get("fix_findings") or [])
        if fix_findings:
            task_text += ("\n\nREVIEW FINDINGS TO FIX (from the previous attempt's adversarial "
                          "review / verification; address every one):\n" + "\n".join(
                              "- [%s] %s (%s)" % (f.get("severity"), f.get("title"),
                                                  f.get("failure_mode") or "")
                              for f in fix_findings))
        if attempt_no >= 1:
            # A retry exists only because a previous attempt failed or was refused. Found LIVE
            # (2026-08-24): 8 of 32 real children ended RESULT_INVALID by answering in prose
            # instead of the mandated structured handoff. The retry is the one moment the
            # contract can be restated where the child is guaranteed to re-read it -- so it is
            # stated HERE, deterministically from durable state, rather than hoped for.
            task_text += (
                "\n\nRETRY NOTICE (attempt %d): a previous attempt of this lane was refused "
                "because its final message did not carry a valid structured handoff. Your "
                "FINAL assistant message must be EXACTLY ONE JSON object conforming to the "
                "handoff schema given with this task -- echo workflow_id, step_id and "
                "RUN_NONCE verbatim inside it, include program_verdict and "
                "claimed_files_changed, and emit NO prose outside the object." % attempt_no)

        # CONTEXT CAPSULE (PRD.md §28.6, §33). Whenever THIS dispatch replaces another seat
        # holder -- a directive resume after an answer, provider failover, or crash-recovery
        # re-dispatch -- the child receives a role-shaped capsule RECONSTRUCTED FROM DURABLE
        # STATE. Seat-change detection reads MEASURED provenance (the previous attempt's
        # run.provenance), never configuration claims. NEVER A TRANSCRIPT: the capsule carries
        # bounded excerpts of durable facts only, and no transcript field exists for it to fill.
        _prev_provider = _seat_provider_from_provenance(sstore, store, lane.lane_id, lane.kind)
        _seat_changed = bool(_prev_provider) \
            and _prev_provider != str(executor.get("kind") or "")
        if directive or _seat_changed:
            from quaestor.core.strategic_store import capsule_text
            capsule = sstore.context_capsule(lane.lane_id, role=lane.kind)
            task_text += ("\n\nCONTEXT CAPSULE (role=%s; reconstructed from canonical state, "
                          "never a transcript replay; sha256=%s):\n%s"
                          % (lane.kind, capsule.get("capsule_sha256", ""),
                             capsule_text(capsule)))

        # Every SCHEDULING ATTEMPT gets a fresh identity component (sched_seq): a refused
        # dispatch (e.g. the real-child concurrency ceiling) still consumes its dispatch key,
        # so a lane retrying after headroom MUST present a new key or it collides as
        # DUPLICATE forever -- measured exactly that way on the first live program.
        sched_seq = int((task_doc["checkpoint"] or {}).get("sched_seq") or 0) + 1
        ck_seq = dict(task_doc["checkpoint"])
        ck_seq["sched_seq"] = sched_seq
        sstore.save_checkpoint(lane.lane_id, ck_seq, program_id=program_id)

        step_id = "%s-a%d-s%d" % (lane.lane_id, variant_index + 1, sched_seq)
        spec = DispatchSpec(
            workflow_id=program_id, step_id=step_id, task=_compose_prompt(task_text, lane.kind),
            worktree_path=wt["path"], authority_profile=profile, executor=executor,
            timeout_s=policy.run_timeout_s, title=lane.title or lane.kind,
            require_lease=bool(lane.writable),   # exactly one writer per lane worktree
            context={"program_id": program_id, "lane_id": lane.lane_id,
                     "role": lane.kind, "attempt": variant_index})
        res = dispatch(store, spec, run_root=os.path.join(home, "runs"),
                       preflight=preflight, spawn=spawn, now=t,
                       spawner=spawner)
        if res.admitted:
            sstore.bind_run(lane.lane_id, res.run_id, role=lane.kind)
            # SEAT PROVENANCE, MEASURED AT DISPATCH (PRD.md §7.1): which role this
            # run filled, WHICH provider was actually dispatched (from the resolved spec the
            # dispatcher received -- never from anything a model says about itself), and why
            # that provider was chosen. Acceptance/audit/UI read this one durable record.
            store.append_event("run.provenance", run_id=res.run_id,
                               detail=_provenance_detail(lane.kind, executor, prov_source))
            # Promote ONLY from PLANNED. A synchronous/in-process worker can finish -- and ask a
            # question -- before this line runs; stamping ACTIVE unconditionally would overwrite
            # WAITING_FOR_STRATEGIST and the lane would be re-dispatched into asking forever.
            fresh = sstore.get_lane(lane.lane_id)
            if fresh is not None and fresh.state == prog_mod.LANE_PLANNED:
                sstore.set_lane_state(lane.lane_id, prog_mod.LANE_ACTIVE, actor_id="scheduler")
            if fix_findings:
                # CONSUMED: the dispatched attempt carries them; leaving them in the checkpoint
                # would re-append stale findings to every future attempt of this lane.
                ck = dict(task_doc["checkpoint"])
                ck["fix_findings"] = []
                sstore.save_checkpoint(lane.lane_id, ck, program_id=program_id)
            # The integration base is the FIRST lane worktree's base head -- set once, never
            # advanced: every lane must diverge from the same commit for merges to compose.
            if not sstore.get_program_meta(program_id).get("base_head"):
                sstore.set_program_meta(program_id, "base_head", wt.get("head") or "")
            sstore.append_event(ev_mod.new_event(
                ev_mod.SCHEDULED, program_id=program_id, lane_id=lane.lane_id, run_id=res.run_id,
                detail={"profile": profile, "executor_kind": executor.get("kind"),
                        "worktree_branch": wt.get("branch"), "attempt": task_doc["attempt"]}))
            started.append({"lane_id": lane.lane_id, "run_id": res.run_id})
        elif res.outcome == "DUPLICATE":
            # A durable dispatch row already exists for this identity but never produced an
            # admitted run we track. Left alone this repeats forever; surface it once (message
            # digests dedupe repeated escalations) and pause the lane for a decision.
            sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                                  actor_id="scheduler")
            _record_blocker(sstore, program_id, lane.lane_id, "",
                            "dispatch %s repeatedly returns DUPLICATE without progressing; "
                            "strategist decision needed" % step_id)
            skipped.append({"lane_id": lane.lane_id, "why": "DUPLICATE_ESCALATED"})
        elif res.state == domain.PERMISSION_REFUSED:
            # The concurrency ceiling: NOT an error and not sticky. Leave the lane schedulable;
            # a later tick with headroom will admit it.
            skipped.append({"lane_id": lane.lane_id, "why": "CONCURRENCY_CEILING"})
        else:
            skipped.append({"lane_id": lane.lane_id, "why": res.outcome,
                            "state": res.state, "reason": res.reason})
            if res.state in (domain.AUTHORITY_REFUSED, domain.LEASE_REFUSED,
                             domain.OWNER_REQUIRED):
                sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_OWNER,
                                      actor_id="scheduler")
                _record_blocker(sstore, program_id, lane.lane_id, "",
                                "dispatch refused (%s): %s" % (res.state, res.reason))
            else:
                sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                                      verdict=prog_mod.FAIL, actor_id="scheduler")
    return {"started": started, "skipped": skipped}


def _real_active(store: Store, active_runs: Sequence[Mapping]) -> int:
    """How many active runs hold a REAL child. Fail-closed on unreadable requests, exactly as
    core.dispatcher._is_real_run is."""
    from quaestor.core import concurrency as conc_mod
    from quaestor.core import runfiles as rf
    n = 0
    for r in active_runs:
        try:
            req = rf.read_json(rf.p(str(r["run_dir"]), rf.REQUEST))
            if not isinstance(req, dict) or conc_mod.is_real_executor(req.get("executor") or {}):
                n += 1
        except Exception:  # noqa: BLE001 - unreadable counts as real (fail-closed)
            n += 1
    return n


# ---------------------------------------------------------------------------------------------
# Seat admission (PRD.md §7.1/§7.2): measured provenance -> pairing policy -> refusal
# ---------------------------------------------------------------------------------------------
def _independence_ctx(sstore: StrategicStore, store: Store, program_id: str, cfg) -> dict:
    """The program-wide pairing context, from MEASURED seats. Impure (reads).

    ``families`` maps role -> provider kind as ACTUALLY DISPATCHED per run.provenance -- the
    same durable record acceptance/audit read. Policy comes from the manifest's
    review.epistemic_independence block; both halves meet only here, at admission time.
    """
    families: dict = {}
    for lane in sstore.lanes(program_id):
        for b in sstore.runs_for_lane(lane.lane_id):
            prov = _provenance_provider(store, b["run_id"])
            if prov.get("provider"):
                families[str(prov.get("role") or b["role"])] = str(prov["provider"])
    return {"require_distinct_between": [tuple(p)
                                         for p in (getattr(cfg, "independence_pairs", ())
                                                   or ())],
            "require_distinct_for": tuple(getattr(cfg, "independence_risk_classes", ()) or ()),
            "families": families}


def _provenance_provider(store: Store, run_id: str) -> dict:
    """The measured seat {role, provider, source} of one run, '' when unrecorded."""
    for ev in store.events_for(run_id):
        if ev["kind"] != "run.provenance":
            continue
        try:
            detail = json.loads(ev["detail_json"] or "{}")
        except ValueError:
            continue
        if isinstance(detail, dict) and detail.get("provider"):
            return detail
    return {}


def _seat_provider_from_provenance(sstore: StrategicStore, store: Store, lane_id: str,
                                   role: str) -> str:
    """The most recent MEASURED provider of ``role`` on this lane ('' when never dispatched).
    This is the fact epistemic-independence admission is computed FROM -- never a claim."""
    for b in reversed(sstore.runs_for_lane(lane_id)):
        if b["role"] != role:
            continue
        prov = _provenance_provider(store, b["run_id"])
        if prov.get("provider"):
            return str(prov["provider"])
    return ""


def _pairing_admission_refusal(pctx: Mapping, role: str, kind: str,
                               risk_classes_hit=()) -> str:
    """Refusal-or-'' for dispatching ``kind`` into ``role``, checked against every configured
    pair partner ALREADY MEASURED in this program. PURE over its arguments."""
    from quaestor.adapters import registry as cap_reg
    for pair in (pctx.get("require_distinct_between") or ()):
        if role not in pair:
            continue
        other = pair[1] if pair[0] == role else pair[0]
        recorded = str((pctx.get("families") or {}).get(other) or "")
        if not recorded:
            continue
        why = cap_reg.check_pairing(pctx, role, kind, other, recorded, risk_classes_hit)
        if why:
            return why
    return ""


def _refuse_seat(sstore: StrategicStore, program_id: str, lane, refusal: str,
                 rationale, *, run_id: str = "", now=None) -> None:
    """Park a lane whose seat was refused BY NAME, routing independence refusals through the
    existing fix/escalation path. Impure.

    The BLOCKER names the refusal and carries the resolver's rationale so the strategist
    inbox answers 'why automation stopped' without anyone reading SQLite. For the two
    epistemic-independence refusals a HIGH finding titled 'epistemic independence unmet' is
    appended to the checkpoint's fix_findings -- the SAME mechanism a reviewer's finding
    rides -- because an independence breach is a defect of the candidate's governance, and
    the fix path is where defects already flow.
    """
    sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                          actor_id="scheduler", now=now)
    tail = "; ".join(str(r) for r in (rationale or ())[-2:])
    _record_blocker(sstore, program_id, lane.lane_id, run_id,
                    "%s refused seat %s%s" % (refusal, lane.kind,
                                              (" (%s)" % tail) if tail else ""), now=now)
    if refusal in (_cap().EPISTEMIC_INDEPENDENCE_UNMET, _cap().ROLE_PROVIDER_POLICY_REFUSED):
        ckpt = dict(sstore.get_lane_task(lane.lane_id)["checkpoint"] or {})
        ckpt["fix_findings"] = list(ckpt.get("fix_findings") or []) + [{
            "title": "epistemic independence unmet",
            "severity": "HIGH",
            "failure_mode": "%s: %s" % (refusal, tail or "provider pairing policy"),
            "location": "seat admission"}]
        sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)


def _cap():
    """Resolve the capability registry at call time -- the same inversion seam the preflight
    uses: core declares the NEED for provider FACTS without a static vendor edge."""
    import importlib
    return importlib.import_module("quaestor.adapters.registry")


def _sync_dependencies(home: str, sstore: StrategicStore, program_id: str, lane) -> dict:
    """Merge every COMPLETE dependency's branch into this lane's worktree. Impure.

    A lane that REQUIRES another lane's work must be able to SEE that work -- otherwise a
    downstream lane's per-lane verification fails on imports it could not possibly satisfy, and
    multi-lane composition only ever happens at final integration, too late to fix cheaply.
    Merges are parent-side, deterministic, recorded in the checkpoint (idempotent), and a
    conflict here escalates instead of being silently absorbed.
    """
    from quaestor.workspace import worktrees as wt_mod
    ckpt = sstore.get_lane_task(lane.lane_id)["checkpoint"]
    path = ckpt.get("worktree_path") or ""
    if not path or not os.path.isdir(path):
        return {"ok": True}
    merged = list(ckpt.get("merged_dependency_branches") or [])
    deps = sstore.dependencies(program_id)
    lanes = {l.lane_id: l for l in sstore.lanes(program_id)}
    # A PLANNED-for-dispatch lane may still carry UNCOMMITTED work from a previous valid run
    # that paused (question/review) before its pipeline reached the commit step. Commit it as a
    # deterministic WIP checkpoint first -- otherwise the upstream merge aborts on local changes
    # (measured), and the work would sit invisible forever.
    probe = wt_mod.probe_worktree(path)
    if probe.get("dirty"):
        wip = wt_mod.commit_all(path, message="%s: pre-sync checkpoint %s"
                                % (branding.commit_scope("wip"), lane.lane_id))
        if not wip.get("ok"):
            return {"ok": False, "error": "wip commit failed: %s" % wip.get("error")}
    changed = False
    for dep in deps:
        if dep.from_lane != lane.lane_id or dep.kind != prog_mod.REQUIRES:
            continue
        upstream = lanes.get(dep.to_lane)
        if upstream is None or upstream.state != prog_mod.LANE_COMPLETE:
            continue
        branch = wt_mod.branch_name(program_id, dep.to_lane)
        if branch in merged:
            continue
        r = wt_mod.merge_branch(path, branch, message="sync dependency %s into %s"
                                % (dep.to_lane, lane.lane_id))
        if not r.get("ok"):
            return {"ok": False, "error": "dependency merge conflict: %s -> %s: %s"
                                            % (dep.to_lane, lane.lane_id, r.get("error"))[:300]}
        merged.append(branch)
        changed = True
    if changed:
        ckpt["merged_dependency_branches"] = merged
        # The merge commits are the control plane's; claim them truthfully so evidence stays
        # consistent with what a subsequent child run reports.
        sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)
    return {"ok": True}


def _ensure_lane_worktree(home: str, sstore: StrategicStore, program_id: str, lane) -> dict:
    """Create-or-reuse this lane's worktree, recording its identity in the checkpoint."""
    from quaestor.workspace import worktrees as wt_mod
    ckpt = sstore.get_lane_task(lane.lane_id)["checkpoint"]
    path = ckpt.get("worktree_path") or wt_mod.lane_worktree_path(home, program_id, lane.lane_id)
    branch = wt_mod.branch_name(program_id, lane.lane_id)
    probe = wt_mod.probe_worktree(path)
    if probe.get("is_worktree") and probe.get("branch") in ("", branch):
        return {"ok": True, "path": path, "branch": probe.get("branch") or branch,
                "head": probe.get("head") or ""}
    base_head = sstore.get_program_meta(program_id).get("base_head", "")
    created = wt_mod.create_lane_worktree(_project_repo(sstore, program_id), path,
                                          branch=branch, base_ref=base_head or "")
    if created.get("ok"):
        ckpt.update({"worktree_path": path, "worktree_branch": branch,
                     "worktree_base_head": created.get("head") or ""})
        sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)
    return created


def _project_repo(sstore: StrategicStore, program_id: str) -> str:
    return sstore.get_program_meta(program_id).get("repository", "")


def _compose_prompt(task: str, kind: str) -> str:
    notes = (
        "\nTWO-WAY PROTOCOL: your structured output may carry a `messages` array; each entry is "
        "{type, payload}. Use DECISION_REQUEST only when the choice materially changes the "
        "objective, architecture, public contract, security boundary, authority, cost, "
        "irreversible state or acceptance criteria -- ordinary reversible implementation choices "
        "are yours to make without asking (LOCAL_TACTICAL). Asking about trivia stalls the "
        "program. An asked question pauses your lane safely; waiting is not failure.")
    if kind == KIND_ADVERSARIAL_REVIEW:
        notes += (" Emit REVIEW_FINDING messages for every defect you can substantiate, each "
                  "with severity CRITICAL|HIGH|MEDIUM|LOW, location, and failure_mode in detail.")
    return task + notes


# ---------------------------------------------------------------------------------------------
# Reaping and stage advancement
# ---------------------------------------------------------------------------------------------
#: How many CONSECUTIVE reap passes may read UNKNOWN liveness before the lane goes to the owner.
#: Bounded in PASSES, not seconds, deliberately: reap holds no clock of its own, and sleeping
#: inside it to wait out an unreadable lock would stall every other lane in the program behind
#: the one run nobody can measure. Each pass is a fresh probe at a later instant, which is what
#: separates a momentary descriptor exhaustion from a lock that is permanently unreadable.
UNKNOWN_LIVENESS_ESCALATION_PASSES = 3

#: Checkpoint key carrying the consecutive-UNKNOWN count. It has to be DURABLE: a reaper that
#: restarts between passes would otherwise reset the count every time and never reach the bound,
#: so a permanently unprobeable worker would hold its lane forever with nothing on any desk.
UNKNOWN_LIVENESS_KEY = "liveness_unknown"


def _may_wait_on_own_child(pid, recorded_create_time, observed_create_time) -> bool:
    """May this process call ``waitpid`` on ``pid``? PURE.

    OWNERSHIP IS PID *PLUS* CREATION TIME, NEVER PID ALONE. A recorded pid that has been
    recycled can name a DIFFERENT child of this same process, and collecting that one's exit
    status steals it from whoever is actually waiting on it -- which does not surface as an
    error, it surfaces as a wait that never returns. So the recorded identity must still match
    what the OS reports right now, and a pid that is non-positive, absent or uncorroborated is
    refused rather than guessed at.
    """
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    if not recorded_create_time or not observed_create_time:
        return False
    return str(recorded_create_time) == str(observed_create_time)


def _collect_own_child(pid, recorded_create_time) -> None:
    """Collect a worker this process started, so its corpse stops answering probes. Impure.

    POSIX, where this matters: ``dispatcher._spawn_worker`` starts the worker with
    ``start_new_session=True`` and drops the Popen. setsid makes a session, it does NOT reparent,
    so a worker that dies while the process that dispatched it is still alive stays a ZOMBIE of
    that process until someone waits on it -- and CPython only does so lazily, from the next
    ``Popen.__init__``. A zombie still answers ``os.kill(pid, 0)`` and still publishes its start
    time, so ``proc.classify_liveness`` reads "lock is free yet the recorded process identity is
    still present" and returns UNKNOWN, exactly as its contract requires. Without this call the
    ORDINARY crashed worker -- clean worktree, at base, nothing written -- would be held and then
    escalated to an owner instead of taking the bounded retry, purely because nobody had
    collected its status yet.

    Windows has no zombies and its ``os.waitpid`` takes a process handle rather than a pid, so
    this is a no-op there: the handle the dispatcher dropped is closed at that moment and the
    pid stops resolving on its own.

    NEVER RAISES, and never touches a process it does not own: a pid that is not our child
    answers ECHILD, which is simply the normal answer for a reaper that did not dispatch this
    run, and identity is checked first so a recycled pid is left alone.
    """
    from quaestor.core import proc as proc_mod
    if not hasattr(os, "WNOHANG"):
        return
    if not _may_wait_on_own_child(pid, recorded_create_time,
                                  proc_mod.process_create_time(pid)):
        return
    try:
        os.waitpid(int(pid), os.WNOHANG)
    except OSError:
        return          # ECHILD: not ours to collect, which is the common case and not a fault


def _hold_unknown_liveness(sstore, *, program_id: str, lane, run_id: str, liveness: str,
                           now: float) -> list:
    """UNKNOWN liveness: hold this run, count the pass, hand the lane over at the bound. Impure.

    proc.classify_liveness's contract is that UNKNOWN is a verdict in its own right and that no
    caller may convert it into DEAD, so reap cannot recover from here -- recovery releases the
    lease and re-dispatches the lane, which against a worker that is merely unmeasurable is a
    second execution on a live process.

    It cannot simply ``continue`` either. A lock that is permanently unprobeable was MEASURED --
    a read-only ACL on the lock file returns LOCK_UNKNOWN with the holder still alive and still
    holding it -- and a bare ``continue`` would skip that run on every pass forever, with nothing
    anywhere recording that the lane had stopped moving.

    So: RE-PROBE UNDER A BOUND, THEN ESCALATE. Nothing here retries the lane and nothing releases
    its lease; the escalation is a BLOCKER plus a WAITING_FOR_OWNER lane -- the same surface an
    ambiguous write uses, because "we cannot tell whether this is still running" needs a human
    exactly as much as "this may have written" does. Escalation is recorded ONCE per run: the run
    stays ACTIVE and unprocessed so this arm is re-entered every pass, and re-filing the blocker
    each tick would bury the surface it exists to raise.

    ONLY THIS FUNCTION'S OWN KEY IS WRITTEN, and that is not a style choice. This is the ONE
    checkpoint write in reap that by construction happens while the worker may still be
    EXECUTING -- that is the entire premise of the UNKNOWN arm -- and ``worker.py`` does its own
    read-modify-write of the same document at handoff. ``save_checkpoint`` merges per key, so
    writing back the whole snapshot read a moment earlier re-asserts every key in it and
    silently reverts whatever the live worker changed in the window. A reverted
    ``awaiting_message`` alone is not cosmetic: reap's own second loop reads that key to tell a
    run that PAUSED to ask a question from one that finished, and would advance the paused run
    into commit and verification of an intentionally half-formed candidate.

    The MARKER is still scoped by run_id on read: a lane that escalated on an earlier run must
    not inherit that run's spent ``escalated`` flag and silently skip the next one.
    """
    task_doc = sstore.get_lane_task(lane.lane_id)
    mark = dict(((task_doc or {}).get("checkpoint") or {}).get(UNKNOWN_LIVENESS_KEY) or {})
    if str(mark.get("run_id") or "") != str(run_id):
        mark = {}
    if mark.get("escalated"):
        return []
    passes = int(mark.get("passes") or 0) + 1
    escalate = passes >= UNKNOWN_LIVENESS_ESCALATION_PASSES
    if escalate:
        # THE ESCALATION IS PERFORMED BEFORE IT IS RECORDED AS HAVING BEEN PERFORMED, for the
        # same reason ``begin_delivery`` writes its intent before the send. Written the other way
        # round -- the marker first, the lane state and the blocker after -- a reaper that dies in
        # between, or one whose next store write raises under WAL contention, leaves a durable
        # ``escalated: True`` for an escalation that never happened. The guard above then returns
        # [] on every later pass, so the lane never reaches WAITING_OWNER, no blocker is ever
        # recorded, ``inbox`` shows nothing, the run stays ACTIVE holding its worktree lease, and
        # the lane stops moving with nothing on any desk saying why -- permanently, and exactly
        # the outcome this key is durable in order to prevent.
        #
        # This order can only cost a DUPLICATE: a crash after the lane is parked and before the
        # marker lands re-escalates on the next pass, which is bounded, visible, and recoverable.
        # An escalation that silently never happens is none of those things.
        sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_OWNER, actor_id="scheduler")
        _record_blocker(sstore, program_id, lane.lane_id, str(run_id),
                        "worker liveness has read UNKNOWN on %d consecutive reap passes: the "
                        "worker lock could not be probed, so run %s is neither provably alive "
                        "nor provably dead. No retry is safe while that holds -- the owner must "
                        "determine whether it is still executing." % (passes, run_id), now=now)
    sstore.save_checkpoint(lane.lane_id,
                           {UNKNOWN_LIVENESS_KEY: {"run_id": str(run_id), "passes": passes,
                                                   "liveness": str(liveness),
                                                   "escalated": bool(escalate)}},
                           program_id=program_id, run_id=str(run_id))
    sstore.append_event(ev_mod.new_event(
        ev_mod.RECONCILIATION_CLASSIFIED, program_id=program_id, lane_id=lane.lane_id,
        run_id=str(run_id), actor_id="scheduler",
        detail={"classification": "WORKER_LIVENESS_UNKNOWN", "liveness": str(liveness),
                "passes": passes, "bound": UNKNOWN_LIVENESS_ESCALATION_PASSES,
                "escalated": bool(escalate)}, now=now))
    if not escalate:
        return [{"lane": lane.lane_id, "action": "LIVENESS_UNKNOWN_HELD", "run_id": str(run_id)}]
    return [{"lane": lane.lane_id, "action": "LIVENESS_UNKNOWN_ESCALATED",
             "run_id": str(run_id)}]


def _clear_unknown_liveness(sstore, *, program_id: str, lane, run_id: str) -> None:
    """Drop the consecutive-UNKNOWN count once liveness reads clearly again. Impure.

    CONSECUTIVE is the whole meaning of the count: two unreadable passes followed by a clean
    ALIVE must not later add up to an escalation. ``save_checkpoint`` MERGES and so cannot delete
    a key -- the marker is reset to an empty mapping rather than popped -- and it is written only
    when one is actually present, because an unconditional write would emit a CHECKPOINT_SAVED
    event on every pass over every healthy worker in the program.
    """
    task_doc = sstore.get_lane_task(lane.lane_id)
    ckpt = dict((task_doc or {}).get("checkpoint") or {})
    if not ckpt.get(UNKNOWN_LIVENESS_KEY):
        return
    sstore.save_checkpoint(lane.lane_id, {UNKNOWN_LIVENESS_KEY: {}}, program_id=program_id,
                           run_id=str(run_id))


def reap(home: str, sstore: StrategicStore, store: Store, *, program_id: str,
         cfg, policy: ProgramPolicy, now: float | None = None, spawner=None) -> dict:
    """Consume finished runs: commits, verification, review outcomes, fix attempts.

    PRECEDED by crash recovery (§35): an ACTIVE run whose worker is provably dead is measured,
    not guessed about. If the worktree is UNCHANGED from its dispatch base, the run died without
    side effects and is failed cleanly so the normal bounded retry consumes it; if the worktree
    DID change, the execution is AMBIGUOUS and the lane escalates to the owner -- a dirty tree
    after a dead worker is exactly the state no automatic retry may touch.

    ONLY A *DEAD* VERDICT RECOVERS. proc.classify_liveness returns three verdicts and its own
    docstring forbids callers from converting UNKNOWN into DEAD; this loop used to guard on
    ``!= "ALIVE"``, which converted it. That is reachable without any fault injection: a reaper
    at its file-descriptor limit gets LOCK_UNKNOWN from probe_lock's open() arm for every run
    in the loop at once, so every LIVE worker read UNKNOWN, was measured clean-and-at-base --
    the ordinary state of a worker that has read but not yet written -- and was failed, its
    lease released and its lane retried against a still-running process. UNKNOWN now takes its
    own arm; ``_hold_unknown_liveness`` says why it holds instead of recovering.
    """
    t = float(now if now is not None else time.time())
    from quaestor.core import lease as lease_mod
    from quaestor.core import proc as proc_mod
    from quaestor.core import reconcile as reconcile_mod
    from quaestor.workspace import worktrees as wt_mod
    from quaestor.adapters import registry as cap_reg

    actions = []
    for lane in sstore.lanes(program_id):
        bindings = sstore.runs_for_lane(lane.lane_id)
        if any(not b["processed"] for b in bindings):
            # An unconsumed run means dispatch happened, and dispatch requires a clean
            # dependency sync: the consecutive-failure bookkeeping is obsolete. Clear here,
            # AFTER the worker that wrote its own checkpoint snapshot is done with it.
            _clear_sync_failure(sstore, lane)
        for binding in bindings:
            if binding["processed"]:
                continue
            run = store.get_run(binding["run_id"])
            if run is None or not domain.is_active(str(run["execution_state"])):
                continue
            worker = store.get_worker(binding["run_id"]) or {}
            if not worker.get("worker_pid"):
                continue        # never started: the dispatcher still owns this run's lifecycle
            liveness = reconcile_mod.read_liveness(store, binding["run_id"],
                                                   dict(store.get_run(binding["run_id"]) or {}))
            if liveness not in (proc_mod.ALIVE, proc_mod.DEAD):
                # Before treating UNKNOWN as uncertainty, collect this process's OWN child: an
                # uncollected POSIX zombie answers every identity query, which is precisely the
                # "lock free, recorded identity still present" shape classify_liveness calls
                # UNKNOWN. Only on this arm, because it is the only one where it can change the
                # verdict, and one extra identity read per unmeasurable run is the whole cost.
                _collect_own_child(worker.get("worker_pid"), worker.get("worker_create_time"))
                liveness = reconcile_mod.read_liveness(
                    store, binding["run_id"], dict(store.get_run(binding["run_id"]) or {}))
            if liveness == proc_mod.ALIVE:
                _clear_unknown_liveness(sstore, program_id=program_id, lane=lane,
                                        run_id=str(binding["run_id"]))
                continue
            if liveness != proc_mod.DEAD:
                # UNKNOWN: not alive, and NOT dead either. Recovering from here is a second
                # execution aimed at a process that may still be writing.
                actions.extend(_hold_unknown_liveness(
                    sstore, program_id=program_id, lane=lane,
                    run_id=str(binding["run_id"]), liveness=str(liveness), now=t))
                continue
            task_doc = sstore.get_lane_task(lane.lane_id)
            wt_path = (task_doc["checkpoint"] or {}).get("worktree_path") or ""
            probe = wt_mod.probe_worktree(wt_path) if wt_path else {"dirty": True}
            base_head = (task_doc["checkpoint"] or {}).get("worktree_base_head") or ""
            unchanged = (probe.get("dirty") is False and probe.get("head", "") == base_head)
            if unchanged:
                # Died WITHOUT effect: a clean, at-base worktree is a measurement, not a hope.
                #
                # THE RECOVERY IS DECIDED BEFORE ANY OF IT IS COMMITTED. What follows is not one
                # write: it fails the run, reclaims the worktree fence, resets that worktree to
                # base and re-dispatches the lane. The liveness reading at the top of this loop
                # predates probe_worktree's git subprocess, and a reaper can lose the ability to
                # probe its own locks inside that window, so the reading that AUTHORISES all of
                # it is taken here, on the fresher measurement, as reconcile_run decides it.
                #
                # AND A REFUSAL MUST LEAVE THE RUN RECOVERABLE. Deciding after the transition
                # strands the lease: the run is terminal with its fence still held, and nothing
                # in the tree revisits that -- this loop skips runs that are not active, the
                # loop below marks them processed, and reconcile classifies an already-terminal
                # run TERMINAL_ALREADY without ever reaching its lease block. The lane's next
                # dispatch would then refuse LEASE_CONFLICT on every tick, for good. So a holder
                # that is not provably dead means DO NOT RECOVER ON THIS PASS: the run stays
                # ACTIVE and unprocessed, the hold records why, and the next pass re-probes and
                # decides again -- and if it never can, the bounded hold escalates it to an
                # owner with the reason on it, instead of to a downstream lease conflict.
                fresh_run = dict(store.get_run(binding["run_id"]) or run)
                now_live = reconcile_mod.read_liveness(store, binding["run_id"], fresh_run)
                if now_live == proc_mod.ALIVE:
                    _clear_unknown_liveness(sstore, program_id=program_id, lane=lane,
                                            run_id=str(binding["run_id"]))
                    continue
                if not lease_mod.liveness_permits_reclaim(now_live):
                    stale = store.lease_for_run(binding["run_id"])
                    if stale is not None and stale.get("released_at") is None:
                        store.append_event(
                            "lease.reclaim_refused", run_id=binding["run_id"],
                            detail={"liveness": now_live,
                                    "reason": "reap reclaims a lease only when the holder is "
                                              "provably dead AND its run is terminal; the run "
                                              "is left ACTIVE so a later pass can re-decide"})
                        actions.append({"lane": lane.lane_id,
                                        "action": "LEASE_RECLAIM_REFUSED",
                                        "run_id": binding["run_id"]})
                    actions.extend(_hold_unknown_liveness(
                        sstore, program_id=program_id, lane=lane,
                        run_id=str(binding["run_id"]), liveness=str(now_live), now=t))
                    continue
                try:
                    store.transition(binding["run_id"], domain.WORKER_FAILED,
                                     reason="worker died with an unchanged worktree; safe to "
                                            "retry as a new dispatch identity")
                    # Release the dead run's worktree fence -- AFTER the clean-tree measurement,
                    # never before: while ambiguity remained, the fence was exactly what kept
                    # any other writer out. THROUGH lease.may_reclaim, never around it: that
                    # predicate ("provably DEAD *and* the run terminal") is the whole safety
                    # property, and calling release_lease directly is how this path came to be
                    # the one place it was not enforced. Its liveness half is the gate above,
                    # asked while the decision was still free; its terminal half is READ BACK
                    # from the store rather than assumed from the transition having returned,
                    # and a refusal here is recorded rather than passed over in silence.
                    stale = store.lease_for_run(binding["run_id"])
                    if stale is not None and stale.get("released_at") is None:
                        post = dict(store.get_run(binding["run_id"]) or fresh_run)
                        if lease_mod.may_reclaim(
                                stale, holder_run_state=str(post["execution_state"]),
                                holder_liveness=now_live):
                            store.release_lease(str(stale["lease_id"]),
                                                reason="dead-worker clean-tree recovery")
                        else:
                            store.append_event(
                                "lease.reclaim_refused", run_id=binding["run_id"],
                                detail={"liveness": now_live,
                                        "reason": "reap reclaims a lease only when the holder "
                                                  "is provably dead AND its run is terminal"})
                            actions.append({"lane": lane.lane_id,
                                            "action": "LEASE_RECLAIM_REFUSED",
                                            "run_id": binding["run_id"]})
                    sstore.append_event(ev_mod.new_event(
                        ev_mod.RECONCILIATION_CLASSIFIED, program_id=program_id,
                        lane_id=lane.lane_id, run_id=binding["run_id"],
                        detail={"classification": "DEAD_WORKER_CLEAN_TREE"}))
                    actions.append({"lane": lane.lane_id, "action": "CRASH_RECOVERED",
                                    "run_id": binding["run_id"]})
                    # §3 failover hook: this death was MEASURED effect-free (unchanged
                    # worktree), so the chain MAY switch on the next dispatch. Record the
                    # dead provider as exhausted for this seat -- the pure helper computes,
                    # the store (which owns the authoritative measurement moment) persists.
                    prov = _provenance_provider(store, binding["run_id"])
                    if prov.get("provider"):
                        sstore.save_checkpoint(
                            lane.lane_id,
                            cap_reg.mark_chain_exhaustion(task_doc["checkpoint"], lane.kind,
                                                          str(prov["provider"])),
                            program_id=program_id)
                except Exception:  # noqa: BLE001 - already terminal elsewhere
                    pass
            else:
                try:
                    store.transition(binding["run_id"], domain.AMBIGUOUS_EXECUTION,
                                     reason="worker died with changes on disk; ambiguous write")
                except Exception:  # noqa: BLE001 - already terminal elsewhere
                    pass
                sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_OWNER,
                                      actor_id="scheduler")
                # §3: stamp the ambiguity INTO the durable checkpoint so seat routing can
                # see it -- a chain consulted while this flag stands refuses with
                # CHAIN_BLOCKED_AMBIGUOUS_WRITE instead of "trying the next model".
                ckpt_amb = dict(task_doc["checkpoint"] or {})
                ckpt_amb["possible_write"] = True
                sstore.save_checkpoint(lane.lane_id, ckpt_amb, program_id=program_id)
                _record_blocker(sstore, program_id, lane.lane_id, binding["run_id"],
                                "worker crashed leaving uncommitted changes; owner must inspect "
                                "%s before any retry" % lane.lane_id, now=t)
                actions.append({"lane": lane.lane_id, "action": "AMBIGUOUS_ESCALATED",
                                "run_id": binding["run_id"]})
                sstore.mark_run_processed(lane.lane_id, binding["run_id"])

    consumed = []
    del consumed
    for lane in sstore.lanes(program_id):
        for binding in sstore.runs_for_lane(lane.lane_id):
            if binding["processed"]:
                continue
            run = store.get_run(binding["run_id"])
            if run is None:
                sstore.mark_run_processed(lane.lane_id, binding["run_id"])
                continue
            state = str(run["execution_state"])
            if domain.is_active(state):
                continue
            sstore.mark_run_processed(lane.lane_id, binding["run_id"])
            # An ABANDONED lane's leftover runs are history, not pipeline input.
            if lane.state == prog_mod.LANE_ABANDONED:
                actions.append({"lane": lane.lane_id, "action": "NOTED_ABANDONED_RUN",
                                "run_id": binding["run_id"]})
                continue
            # WAITING IS NOT FAILURE, and it is also not completion. The AUTHORITATIVE test is
            # the run's own checkpoint: if it asked a question that is still unanswered, this
            # run must not be advanced as a finished implementation -- no matter what the lane
            # row says right now (answering can race a run that is still finishing).
            task_doc = sstore.get_lane_task(lane.lane_id)
            ckpt = dict(task_doc["checkpoint"]) if task_doc else {}
            awaiting = str(ckpt.get("awaiting_message") or "")
            still_unanswered = False
            if awaiting:
                m = sstore.message(awaiting)
                still_unanswered = bool(m) and not m.get("answered_by")
            fresh = sstore.get_lane(lane.lane_id)
            if awaiting:
                # This run PAUSED to ask. Its stage pipeline ends here whether the answer has
                # arrived yet or not: the post-answer RESUME attempt is the run that continues
                # the work, and advancing this one would commit/verify an intentionally
                # half-formed candidate.
                #
                # The pause also CONSUMES a variant slot (ask_count), so the resumed run does
                # not replay the asking behaviour forever -- without this, a scripted
                # ask-then-act lane asks the same question on every attempt. Deliberately NOT
                # bump_attempt: asking is not a fix cycle and must not eat §47's review budget.
                ckpt["ask_count"] = int(ckpt.get("ask_count") or 0) + 1
                sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id,
                                       run_id=binding["run_id"])
                # Once the answer has ARRIVED this run is fully consumed history: leaving it
                # unprocessed would keep the lane in RUN_IN_FLIGHT forever and the post-answer
                # resume could never be scheduled. Measured exactly that way.
                if not still_unanswered:
                    sstore.mark_run_processed(lane.lane_id, binding["run_id"])
                actions.append({"lane": lane.lane_id,
                                "action": ("WAITING" if still_unanswered else "AWAITED"),
                                "run_id": binding["run_id"]})
                continue
            h = store.get_handoff(binding["run_id"])
            handoff = json.loads(h["handoff_json"]) if h else {}
            report = handoff.get("claude_report") or {}
            actions.extend(_consume_run(home, sstore, store, program_id=program_id, lane=lane, spawner=spawner,
                                        role=binding["role"], run_id=binding["run_id"],
                                        state=state, report=report, cfg=cfg, policy=policy,
                                        now=t))
    return {"actions": actions}


def _consume_run(home, sstore, store, *, program_id, lane, role, run_id, state, report,
                 cfg, policy, now, spawner=None) -> list:
    actions = []
    lane_id = lane.lane_id

    if state != domain.HANDOFF_READY:
        # Failed/refused execution: one bounded automatic retry via a NEW attempt (new dispatch
        # identity -- never a blind retry of an ambiguous WRITE; those states escalate).
        if state in (domain.AMBIGUOUS_EXECUTION, domain.OWNER_REQUIRED):
            sstore.set_lane_state(lane_id, prog_mod.LANE_WAITING_OWNER, actor_id="scheduler")
            _record_blocker(sstore, program_id, lane_id, run_id,
                            "execution ended %s; owner judgement required" % state, now=now)
            actions.append({"lane": lane_id, "action": "ESCALATED", "state": state})
        elif state in (domain.RESULT_INVALID, domain.WORKER_FAILED, domain.CLAUDE_FAILED,
                       domain.INTERRUPTED):
            # These runs may have written files BEFORE failing protocol validation -- the child
            # is untrusted at exactly that point, so its uncommitted leftovers are NOT work.
            # Reset the lane worktree to HEAD so the retry measures only what IT does. (A dirty
            # tree after a DEAD worker goes to the owner instead -- see reap's ambiguity path.)
            wt_path = (sstore.get_lane_task(lane_id)["checkpoint"] or {}).get("worktree_path")
            if wt_path and os.path.isdir(wt_path):
                from quaestor.workspace import worktrees as _wt
                _wt.reset_worktree(wt_path)
            attempt = sstore.bump_attempt(lane_id)
            if attempt > policy.max_review_cycles + 1:
                sstore.set_lane_state(lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                                      actor_id="scheduler")
                _record_blocker(sstore, program_id, lane_id, run_id,
                                "execution failed repeatedly (%s); strategist input needed"
                                % state, now=now)
                actions.append({"lane": lane_id, "action": "ESCALATED", "state": state})
            else:
                sstore.set_lane_state(lane_id, prog_mod.LANE_PLANNED, actor_id="scheduler")
                actions.append({"lane": lane_id, "action": "RETRY_SCHEDULED", "state": state,
                                "attempt": attempt})
        else:  # refusals (LEASE/AUTHORITY/PREFLIGHT/PERMISSION/CANCELLED): a decision, not a retry
            sstore.set_lane_state(lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                                  verdict=prog_mod.FAIL, actor_id="scheduler")
            actions.append({"lane": lane_id, "action": "FAILED", "state": state})
        return actions

    # ROLE DISPATCH -- registry lookup, total over LANE_KINDS by construction (verified at
    # import; see the registry block above PROFILE_FOR_KIND). An unknown role refuses LOUDLY
    # instead of being noted-and-forgotten: found LIVE, the old catch-all consumed such a run
    # while its lane stayed ACTIVE, and the scheduler re-dispatched real paid runs on every
    # tick forever. A role that cannot advance or park its lane must stop the tick HERE.
    handler = LANE_HANDLERS.get(role)
    if handler is None and role.startswith(KIND_IMPLEMENTATION + "-fix"):
        # Tolerated legacy spelling: fix attempts bound under "implementation-fix..." roles by
        # older versions of this module may still sit unprocessed in durable stores, and a
        # reaped backlog must keep running the SAME flow it always did. Everything else
        # unknown is refused below rather than absorbed.
        handler = LANE_HANDLERS[KIND_IMPLEMENTATION]
    if handler is None:
        raise ValueError(
            "no lane handler registered for run role %r on lane %s (declared kinds: %s); "
            "refusing to consume a run whose lane could never reach a terminal state"
            % (role, lane_id, list(LANE_KINDS)))
    actions.extend(handler(home, sstore, store, program_id=program_id, lane=lane, role=role,
                           run_id=run_id, report=report, cfg=cfg, policy=policy, now=now,
                           spawner=spawner))
    return actions


#: Consecutive DEPENDENCY_SYNC failures after which a lane escalates a BLOCKER to the
#: strategist inbox. Found LIVE (2026-08-24): a conflicted dependency merge skipped its lane on
#: EVERY tick with only a line in the tick report -- the program stalled silently until an
#: operator read raw output. Waiting is not failure; SILENCE is not waiting. The threshold is
#: small because these merges are deterministic: if it failed twice identically, a third try
#: without intervention will fail identically.
SYNC_FAIL_ESCALATE_AFTER = 2


def _escalate_sync_failure(sstore: StrategicStore, *, program_id: str, lane,
                           error: str) -> str | None:
    """Record ONE blocker for a run of identical sync failures. Impure.

    The count and the last-escalated error live in the lane checkpoint (durable, per-lane), so
    escalation is exactly-once per distinct error: a fixed-but-still-broken merge with a NEW
    error re-escalates, the same error ticking past again does not spam the inbox.
    """
    import hashlib

    ckpt = dict(sstore.get_lane_task(lane.lane_id)["checkpoint"])
    count = int(ckpt.get("sync_fail_count") or 0) + 1
    err_key = hashlib.sha256(error.encode("utf-8")).hexdigest()[:16]
    ckpt["sync_fail_count"] = count
    sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)

    if count < SYNC_FAIL_ESCALATE_AFTER:
        return None
    if ckpt.get("sync_escalated_error") == err_key:
        return None
    text = ("DEPENDENCY_SYNC failed %d consecutive times for this lane; the program cannot "
            "advance it without owner/strategist intervention. Last error: %s"
            % (count, error[:400]))
    mid = _record_blocker(sstore, program_id, lane.lane_id, "", text)
    ckpt = dict(sstore.get_lane_task(lane.lane_id)["checkpoint"])
    ckpt["sync_escalated_error"] = err_key
    sstore.save_checkpoint(lane.lane_id, ckpt, program_id=program_id)
    # Park the lane. The inbox read model surfaces BLOCKER messages ONLY for lanes in
    # WAITING_STATES -- a blocker on a PLANNED lane is invisible by construction -- and parking
    # also stops the silent per-tick retry. answer() is the wake path back to PLANNED.
    fresh = sstore.get_lane(lane.lane_id)
    if fresh is not None and fresh.state in (prog_mod.LANE_PLANNED, prog_mod.LANE_ACTIVE):
        sstore.set_lane_state(lane.lane_id, prog_mod.LANE_WAITING_STRATEGIST,
                              actor_id="scheduler")
    sstore.append_event(ev_mod.new_event(ev_mod.BLOCKED, program_id=program_id,
                                         lane_id=lane.lane_id, actor_id="scheduler",
                                         detail={"why": "DEPENDENCY_SYNC", "failures": count}))
    return mid


def _clear_sync_failure(sstore: StrategicStore, lane) -> None:
    """A dispatched run proves sync succeeded; reset the counter. Impure.

    Called from REAP, never from schedule: reap consumes runs only after the worker has
    finished writing its checkpoint, so this write cannot be overwritten by a stale snapshot.
    The reset is written as EXPLICIT NEUTRAL VALUES because save_checkpoint MERGES -- an
    absent key leaves the stored value standing (deletion-by-omission is impossible by that
    store's enforced merge rule), which is exactly why the first clear attempt silently
    did nothing.
    """
    ckpt = sstore.get_lane_task(lane.lane_id)["checkpoint"]
    if ckpt.get("sync_fail_count") or ckpt.get("sync_escalated_error"):
        sstore.save_checkpoint(lane.lane_id,
                               {"sync_fail_count": 0, "sync_escalated_error": None})


def _record_blocker(sstore, program_id, lane_id, run_id, text, *, now=None) -> str:
    """Record a blocker AGAINST A LANE. Program-level escalations (lane_id == '') are recorded
    as BLOCKED events + integration/program state instead -- the qualified message contract
    requires every message to belong to a lane, and inventing a fake lane would be worse than
    using the channel built for program facts."""
    if not lane_id:
        sstore.append_event(ev_mod.new_event(ev_mod.BLOCKED, program_id=program_id,
                                             run_id=run_id or "", actor_id="scheduler",
                                             detail={"blocker": str(text)[:500]}, now=now))
        return ""
    msg = msg_mod.new_message(msg_mod.BLOCKER, actor_id="scheduler", program_id=program_id,
                              lane_id=lane_id, run_id=run_id or "", payload=text, now=now)
    sstore.record_message(msg)
    return msg.message_id


def _after_implementation(home, sstore, store, *, program_id, lane, run_id, report,
                          cfg, policy, now, spawner=None) -> list:
    """Commit -> verify -> adversarial review -> complete, or schedule the bounded fix."""
    from quaestor.workspace import worktrees as wt_mod
    lane_id = lane.lane_id
    actions = []
    task_doc = sstore.get_lane_task(lane_id)
    ckpt = dict(task_doc["checkpoint"])

    # 1. COMMIT the measured diff, deterministically, parent-side.
    wt_path = ckpt.get("worktree_path") or ""
    commit = {"ok": False, "sha": "", "changed": 0, "already_clean": False}
    changed: list = []
    if wt_path and os.path.isdir(wt_path):
        # The candidate diff must be measured BEFORE commit_all folds it into HEAD --
        # changed_files diffs against HEAD, so measuring after the commit would report an
        # empty candidate and every downstream consumer (review targeting, §3 risk-class
        # admission) would silently see "no change".
        changed = wt_mod.changed_files(wt_path)
        commit = wt_mod.commit_all(wt_path, message="%s: attempt %d\n\n%s"
                                   % (branding.commit_scope("%s/%s" % (program_id, lane_id)),
                                      task_doc["attempt"],
                                      str(report.get("summary") or "")[:400]))

    # 2. VERIFY: independent deterministic tests, bridge-owned definition.
    receipt = _verify(home, wt_path, cfg)
    ckpt["verification"] = receipt.to_dict()
    ckpt["commit_sha"] = commit.get("sha") or ""
    sstore.save_checkpoint(lane_id, ckpt, program_id=program_id, run_id=run_id)

    findings = []
    if receipt.test_verdict == test_collector.FAIL:
        findings.append({"title": "verification failed: %d failing test(s)"
                         % (receipt.failed or 0),
                         "severity": "HIGH",
                         "failure_mode": receipt.reason or "test suite reported failures",
                         "location": "test suite", "evidence_ref": "test_collector"})
    elif receipt.test_verdict in (test_collector.VACUOUS, test_collector.NOT_EVALUATED):
        findings.append({"title": "verification inconclusive (%s)" % receipt.test_verdict,
                         "severity": "MEDIUM", "failure_mode": receipt.reason,
                         "location": "test suite", "evidence_ref": "test_collector"})

    # 3. ADVERSARIAL REVIEW where required. Every committed candidate gets one -- first pass
    #    AND post-fix re-reviews -- because "the previous review passed" says nothing about the
    #    NEW diff. The §47 bound is enforced by the fix-attempt budget, not by skipping reviews.
    #    Findings arrive on the NEXT tick when the review run completes.
    if policy.require_adversarial and commit.get("ok") and not commit.get("already_clean"):
        required, matched = _adversarial_required(changed, cfg)
        # THE FULL HIT SET, not the floor-filtered subset. `matched` answers "why a review is
        # required"; the independence escalation asks a different question -- "what did this diff
        # touch?" -- and handing it the review floor's answer let a declared risk class slip past
        # the distinct-provider requirement entirely.
        review_run = _dispatch_reviewer(home, sstore, store, program_id=program_id, lane=lane,
                                        cfg=cfg, policy=policy,
                                        changed=risk_classes_hit(changed),
                                        now=now, spawner=spawner)
        actions.append({"lane": lane_id, "action": "ADVERSARIAL_REVIEW_DISPATCHED",
                        "run_id": review_run})
        if findings:
            actions.append({"lane": lane_id, "action": "VERIFICATION_FINDINGS_HELD",
                            "count": len(findings)})
            ckpt["pending_findings"] = findings
            sstore.save_checkpoint(lane_id, ckpt, program_id=program_id)
        sstore.set_lane_state(lane_id, prog_mod.LANE_ACTIVE, actor_id="scheduler")
        return actions

    actions.extend(_resolve_findings(home, sstore, store, program_id=program_id, lane=lane,
                                     findings=findings, report=report, cfg=cfg, policy=policy,
                                     now=now))
    return actions


def _verify(home: str, wt_path: str, cfg) -> test_collector.TestReceipt:
    """Run the PROJECT'S OWN test commands parent-side. The collector owns the definition."""
    commands = tuple(getattr(cfg, "test_commands", ()) or ())
    out_dir = os.path.join(str(home), "runs", "_verification")
    os.makedirs(out_dir, exist_ok=True)
    if not commands or not wt_path or not os.path.isdir(wt_path):
        return test_collector.build_receipt(
            test_collector.TestProfile("none", ("true",), expected_floor=0),
            run_id="", cwd=wt_path or home, outcome=test_collector.LAUNCH_FAILED,
            exit_code=None, stdout="", stderr=("no test commands configured" if not commands
                                               else "worktree missing"),
            started=time.time(), finished=time.time())
    argv = _split_command(commands[0])
    profile = test_collector.TestProfile("project-test", argv, cwd_policy="workspace",
                                         timeout_s=900.0, expected_floor=1)
    rid = "ver_%s" % uuid.uuid4().hex[:12]
    receipt = test_collector.run_profile(profile, cwd=wt_path, run_id=rid,
                                         stdout_path=os.path.join(out_dir, rid + ".out"),
                                         stderr_path=os.path.join(out_dir, rid + ".err"))
    return receipt


def _split_command(cmd: str) -> tuple:
    """Config string -> argv. PURE-ish.

    On Windows ``shlex.split(posix=False)`` PRESERVES quote characters inside tokens -- measured:
    ``-p "test_*.py"`` became a pattern that included the double quotes and matched zero files,
    which surfaced as an honest-looking VACUOUS verdict manufactured by our own quoting. Strip
    one matched pair of surrounding quotes per token after splitting.
    """
    import shlex
    try:
        parts = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        parts = cmd.split()
    out = []
    for p in parts:
        if len(p) >= 2 and p[0] == p[-1] and p[0] in ("'", '"'):
            p = p[1:-1]
        if p:
            out.append(p)
    return tuple(out)


#: How a path is read as touching each risk class. A TABLE, not a chain of ifs, so that the
#: control below can assert one property that a chain cannot express: the classifier is TOTAL
#: over review_contract.RISK_CLASSES. Two classes an operator was allowed to name --
#: `authority_change` and `destructive_capability` -- had no rule at all here, so a manifest
#: declaring them produced a requirement no change could ever trigger.
#:
#: These are substring heuristics over changed paths. They are deliberately broad: a false
#: positive costs an extra independent reviewer, a false negative costs the guarantee.
RISK_KEYWORDS = {
    "authentication": ("auth", "login", "session", "token", "permission"),
    "security_sensitive": ("secret", "credential", "crypto", "key"),
    "sandbox_change": ("sandbox", "container", "confinement"),
    "deployment": ("deploy", "ci", "pipeline", "dockerfile", "release", "publish"),
    "data_migration": ("migration", "schema"),
    "authority_change": ("authority", "profile", "capability", "privilege", "role",
                         "governance", "policy"),
    "destructive_capability": ("delete", "destroy", "purge", "drop", "truncate", "rm",
                               "wipe", "prune"),
}


def risk_classes_hit(changed: Sequence[str]) -> tuple:
    """Every risk class this diff touches. PURE. Sorted, so it is stable to compare.

    SEPARATE FROM THE REVIEW FLOOR ON PURPOSE. Two different questions were being answered with
    one filtered set: "does this diff require an adversarial review?" (the floor) and "does this
    diff escalate the distinct-provider requirement?" (the operator's
    require_distinct_provider_for). Passing the floor-filtered subset to the independence check
    meant a class an operator had explicitly declared, but which the floor does not list, never
    reached it -- so the requirement failed OPEN and the seat proceeded.
    """
    classes = set()
    for p in changed or ():
        low = str(p).lower()
        for risk_class, keywords in RISK_KEYWORDS.items():
            if any(k in low for k in keywords):
                classes.add(risk_class)
    return tuple(sorted(classes))


def _adversarial_required(changed: Sequence[str], cfg) -> tuple:
    """(required, matched) for the REVIEW decision. The independence escalation does not use
    ``matched`` -- see risk_classes_hit for why that distinction is load-bearing."""
    from quaestor.core import review_contract as rc
    policy_extra = {"required_for": tuple(getattr(cfg, "adversarial_required_for", ()) or ())}
    return rc.adversarial_required(list(risk_classes_hit(changed)), policy_extra)


def _review_cycles(sstore, lane_id: str) -> int:
    return sum(1 for r in sstore.runs_for_lane(lane_id) if r["role"] == KIND_ADVERSARIAL_REVIEW)


def _dispatch_reviewer(home, sstore, store, *, program_id, lane, cfg, policy, changed,
                       now=None, spawner=None, target_class="") -> str:
    """Dispatch the adversarial reviewer over a TARGET CLASS (PRD.md §7.6).

    ``target_class`` names WHAT is under attack: CODE (the default -- the committed candidate
    diff, behaviour unchanged from before this parameter existed), or PLAN -- an adversarial
    challenge of a PENDING PLAN_PROPOSAL, dispatched BEFORE expensive implementation because one
    review call there can save thirty misdirected executions. INTEGRATION/RELEASE/SECURITY are
    declared members of the closed class set; each becomes a distinct packet by deliberate edit,
    never by an open string. No new permanent role either way: same reviewer seat, same READ_ONLY
    ceiling, same REVIEW_FINDING-only vocabulary -- only the packet changes. A PLAN challenge is
    program-level (lane=None): the proposal belongs to no lane yet, so its run is tracked in
    program meta and consumed by _consume_plan_challenge.
    """
    from quaestor.core import review_contract as rc_mod
    tc = str(target_class or rc_mod.DEFAULT_TARGET_CLASS)
    if tc not in rc_mod.REVIEW_TARGET_CLASSES:
        raise ValueError("unknown review target class %r; known are %s"
                         % (tc, list(rc_mod.REVIEW_TARGET_CLASSES)))
    is_plan = tc == rc_mod.TARGET_PLAN
    if is_plan and lane is not None:
        raise ValueError("a PLAN-target challenge is program-level; pass lane=None")
    if not is_plan and lane is None:
        raise ValueError("a CODE-target review reviews a lane's candidate; pass its lane")
    import quaestor.core.planner as planner_mod
    lane_id = lane.lane_id if lane is not None else ""
    task_doc = sstore.get_lane_task(lane_id) if lane is not None else {
        "acceptance": (), "checkpoint": {}}
    ckpt = task_doc["checkpoint"]
    prog = sstore.get_program(program_id) or {}
    meta = sstore.get_program_meta(program_id)
    constraints = _load_json_list(meta.get("constraints_json"))
    verification = (ckpt.get("verification") or {}) if lane is not None else {}
    if is_plan:
        doc = planner_mod.pending_proposal(sstore, program_id)
        if doc is None:
            return ""
        wt_path = str(meta.get("repository") or "")
        task_text = planner_mod.build_plan_challenge_task(
            objective=prog.get("objective") or "", constraints=constraints, proposal_doc=doc)
    else:
        wt_path = ckpt.get("worktree_path") or ""
        task_text = rc_mod.build_review_task(
            objective=prog.get("objective") or "",
            acceptance=task_doc["acceptance"], constraints=constraints,
            verification_receipt=verification,
            committer_identity=branding.COMMITTER_NAME)
    # Fixture/testing seam: a program may script its reviewer (server-side meta only -- there is
    # deliberately no MCP field for this; production reviewers come from the project manifest).
    # The whole spec dict is handed to _executor_for, so ``attempt_variants`` work here too: a
    # fixture reviewer can flag a defect on cycle 0 and pass on the re-review of the fix.
    try:
        scripted = json.loads(meta.get("review_executor") or "{}")
    except ValueError:
        scripted = {}
    # The reviewer seat resolves through the same §3 ladder as any lane: scripted fixture seam
    # first, then the manifest's executors.roles pin (or providers.chain) for
    # adversarial_review, then the default.
    from quaestor.adapters import registry as cap_reg
    pins = getattr(cfg, "role_executor", None) if cfg else None
    ckpt_exhausted = {KIND_ADVERSARIAL_REVIEW: sorted(cap_reg.exhausted_for(ckpt,
                                                                           KIND_ADVERSARIAL_REVIEW))}
    if scripted.get("kind"):
        executor, prov_source = dict(scripted), "lane-script"
    elif scripted.get("attempt_variants"):
        executor, prov_source = _resolve_executor(
            cfg.executor if cfg else "fake", {"executor": scripted},
            attempt=_review_cycles(sstore, lane_id), role_kind=KIND_ADVERSARIAL_REVIEW,
            role_executor=pins,
            chains=getattr(cfg, "role_chains", None) if cfg else None,
            seat_policy=getattr(cfg, "seat_policy", None) if cfg else None,
            chain_exhausted=ckpt_exhausted,
            pairing_ctx=_independence_ctx(sstore, store, program_id, cfg))
    else:
        executor, prov_source = _resolve_executor(
            cfg.executor if cfg else "fake", {"executor": {}},
            role_kind=KIND_ADVERSARIAL_REVIEW, role_executor=pins,
            chains=getattr(cfg, "role_chains", None) if cfg else None,
            seat_policy=getattr(cfg, "seat_policy", None) if cfg else None,
            chain_exhausted=ckpt_exhausted,
            pairing_ctx=_independence_ctx(sstore, store, program_id, cfg))
    if executor.get("refusal"):
        # Named seat refusal (chain blocked/exhausted/policy, undeclared kind): nothing spawns.
        if lane is not None:
            _refuse_seat(sstore, program_id, lane, str(executor["refusal"]),
                         executor.get("rationale") or (), now=now)
        else:
            sstore.append_event(ev_mod.new_event(
                ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
                detail={"blocker": ("plan challenge refused (%s): %s"
                                    % (executor["refusal"],
                                       "; ".join(str(r) for r in
                                                 executor.get("rationale") or ()))[:400])[:500]},
                now=now))
        return ""
    # §3 EPISTEMIC INDEPENDENCE AT ADMISSION -- before spawn. For a CODE target the implementer's
    # provider is a MEASURED fact (its run.provenance event); for a PLAN target the same map
    # carries the PLANNER's measured provider, so a configured ["planner", "adversarial_review"]
    # pair is enforced exactly where refusing still costs nothing -- before the challenger reads
    # the decomposition it would share a blind spot with.
    pctx = _independence_ctx(sstore, store, program_id, cfg)
    impl_prov = _seat_provider_from_provenance(sstore, store, lane_id, KIND_IMPLEMENTATION) \
        if lane is not None else ""
    pair_refusal = cap_reg.check_pairing(
        pctx, KIND_ADVERSARIAL_REVIEW, str(executor.get("kind") or ""),
        KIND_IMPLEMENTATION, impl_prov, tuple(changed or ())) \
        if lane is not None else ""
    if not pair_refusal:
        pair_refusal = _pairing_admission_refusal(pctx, KIND_ADVERSARIAL_REVIEW,
                                                  str(executor.get("kind") or ""),
                                                  tuple(changed or ()))
    if pair_refusal:
        if lane is not None:
            _refuse_seat(sstore, program_id, lane, pair_refusal,
                         ["reviewer %s vs implementer %s (%s) share a provider family"
                          % (executor.get("kind"), impl_prov, KIND_IMPLEMENTATION)], now=now)
        else:
            sstore.append_event(ev_mod.new_event(
                ev_mod.BLOCKED, program_id=program_id, actor_id="scheduler",
                detail={"blocker": "plan challenge seat refused (%s)" % pair_refusal}, now=now))
        return ""
    if is_plan:
        step_id = "%s-plan-review-r%d" % (program_id,
                                          len(doc.get("review_runs") or []) + 1)
        title = "adversarial plan challenge"
    else:
        step_id = "%s-review-r%d" % (lane_id, _review_cycles(sstore, lane_id))
        title = "adversarial review of %s" % lane.title
    spec = DispatchSpec(
        workflow_id=program_id, step_id=step_id,
        task=_compose_prompt(task_text, KIND_ADVERSARIAL_REVIEW),
        worktree_path=wt_path, authority_profile=authority_mod.READ_ONLY,
        executor=executor, min_inspected=1, title=title,
        timeout_s=policy.run_timeout_s, require_lease=False,
        context={"program_id": program_id, "lane_id": lane_id,
                 "role": KIND_ADVERSARIAL_REVIEW})
    res = dispatch(store, spec, run_root=os.path.join(home, "runs"),
                   preflight=_preflight_for(cfg), spawn=True, now=now, spawner=spawner)
    if res.admitted:
        if lane is not None:
            sstore.bind_run(lane_id, res.run_id, role=KIND_ADVERSARIAL_REVIEW)
        else:
            # A PLAN-target run has no lane to bind: it is tracked in program meta and consumed
            # once, exactly like the planner run itself.
            sstore.set_program_meta(program_id, planner_mod.CHALLENGE_RUN_META_KEY, res.run_id)
            doc.setdefault("review_runs", []).append(res.run_id)
            planner_mod.save_proposal_doc(sstore, program_id, doc)
        # Same measured seat provenance as schedule() -- the reviewer is a seat in the §3
        # matrix too, and "which provider reviewed this" is exactly what pairwise
        # independence policy will be computed FROM.
        store.append_event("run.provenance", run_id=res.run_id,
                           detail=_provenance_detail(KIND_ADVERSARIAL_REVIEW, executor,
                                                     prov_source))
        sstore.append_event(ev_mod.new_event(ev_mod.REVIEW_STARTED, program_id=program_id,
                                             lane_id=lane_id, run_id=res.run_id,
                                             detail={"kind": "ADVERSARIAL",
                                                     "target_class": tc}))
        return res.run_id
    if lane is not None:
        sstore.set_lane_state(lane_id, prog_mod.LANE_WAITING_STRATEGIST, actor_id="scheduler")
    _record_blocker(sstore, program_id, lane_id, "",
                    "adversarial review could not be dispatched (%s: %s)"
                    % (res.outcome, res.reason), now=now)
    return ""


def _preflight_for(cfg):
    """The dispatch preflight, resolved through the provider seam. Impure (imports).

    RESOLVED, NOT IMPORTED -- the same inversion as ``worker.make_executor``: whether a run's
    authentication needs a credential-broker preflight is a property of the provider, so core
    asks the provider layer at call time instead of importing it (a static control walks the
    real import graph to prove core never reaches an outer layer).
    """
    import importlib

    # An absent executor is not the test double here either; run_preflight refuses an unknown
    # kind by name (NO_PREFLIGHT_FOR_KIND), which is the honest outcome.
    kind = str(getattr(cfg, "executor", "") or "")
    registry = importlib.import_module("quaestor.executors.registry")

    def preflight(claude_path="", requires_write=False):
        return registry.run_preflight(kind, claude_path=claude_path,
                                      requires_write=requires_write)
    return preflight


def _after_review(sstore, *, program_id, lane, run_id, report, policy, now) -> list:
    """Turn the reviewer's findings into either a bounded fix attempt or a completed lane."""
    from quaestor.core import review_contract as rc
    lane_id = lane.lane_id
    findings = tuple(
        rc.Finding(finding_id=m["message_id"], title=f.title, severity=f.severity,
                   location=f.location, failure_mode=f.failure_mode)
        for m in sstore.messages(lane_id)
        if m["message_type"] == msg_mod.REVIEW_FINDING and m["run_id"] == run_id
        for f in (rc.parse_finding_message(m["detail_json"], m["payload"]),))
    result = rc.ReviewResult(review_id="rev_" + uuid.uuid4().hex[:12], kind=rc.ADVERSARIAL,
                             outcome=rc.INCONCLUSIVE, findings=findings,
                             reviewer_actor_id="adversarial reviewer",
                             inspected_count=max(1, len(findings)))
    summary = rc.summarize(result)
    sstore.record_review(result.review_id, program_id=program_id, lane_id=lane_id,
                         kind=rc.ADVERSARIAL, outcome=summary["outcome"], result=summary,
                         run_id=run_id)
    ckpt = dict(sstore.get_lane_task(lane_id)["checkpoint"])
    held = list(ckpt.get("pending_findings") or [])
    surviving = [f.to_dict() for f in findings if f.survives] + held
    ckpt["pending_findings"] = []
    ckpt["last_review"] = summary
    sstore.save_checkpoint(lane_id, ckpt, program_id=program_id, run_id=run_id)

    return _resolve_findings_from(sstore, program_id=program_id, lane=lane, findings=surviving,
                                  report=report, policy=policy, now=now)


def _resolve_findings(home, sstore, store, *, program_id, lane, findings, report, cfg, policy,
                      now) -> list:
    return _resolve_findings_from(sstore, program_id=program_id, lane=lane,
                                  findings=[f for f in findings
                                            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")],
                                  report=report, policy=policy, now=now)


def _resolve_findings_from(sstore, *, program_id, lane, findings, report, policy, now) -> list:
    """Blocking findings -> bounded fix attempt; none -> lane COMPLETE.

    THE BOUND (§47). Each fix consumes an attempt; past ``max_review_cycles`` the lane pauses for
    the strategist with everything the record knows. Reviewers and executors may not extend their
    own budget; only the strategist (via plan/answer) can reopen work beyond it.
    """
    lane_id = lane.lane_id
    actions = []
    if findings:
        attempt = sstore.bump_attempt(lane_id)
        cycles = _review_cycles(sstore, lane_id)
        if attempt > policy.max_review_cycles:
            sstore.set_lane_state(lane_id, prog_mod.LANE_WAITING_STRATEGIST, verdict=prog_mod.FAIL,
                                  actor_id="scheduler")
            _record_blocker(sstore, program_id, lane_id, "",
                            "review/fix cycle exhausted (%d attempts). Outstanding findings:\n%s"
                            % (attempt, "\n".join("- [%s] %s" % (f.get("severity"),
                                                                 f.get("title"))
                                                  for f in findings)), now=now)
            actions.append({"lane": lane_id, "action": "ESCALATED", "findings": len(findings)})
            return actions
        ckpt = dict(sstore.get_lane_task(lane_id)["checkpoint"])
        ckpt["fix_findings"] = findings
        sstore.save_checkpoint(lane_id, ckpt, program_id=program_id)
        sstore.set_lane_state(lane_id, prog_mod.LANE_PLANNED, verdict=prog_mod.NOT_EVALUATED,
                              actor_id="scheduler")
        sstore.append_event(ev_mod.new_event(ev_mod.FIX_LANE_CREATED, program_id=program_id,
                                             lane_id=lane_id,
                                             detail={"attempt": attempt,
                                                     "finding_count": len(findings)}, now=now))
        actions.append({"lane": lane_id, "action": "FIX_ATTEMPT_SCHEDULED",
                        "attempt": attempt, "findings": len(findings)})
        return actions

    verdict = str(report.get("program_verdict") or domain.PASS)
    sstore.set_lane_state(lane_id, prog_mod.LANE_COMPLETE,
                          verdict=(prog_mod.PASS if verdict != domain.FAIL else prog_mod.FAIL),
                          actor_id="scheduler")
    actions.append({"lane": lane_id, "action": "COMPLETE",
                    "verdict": prog_mod.PASS if verdict != domain.FAIL else prog_mod.FAIL})
    return actions


# ---------------------------------------------------------------------------------------------
# Integration (§31-32): conservative local convergence, never an automatic push
# ---------------------------------------------------------------------------------------------
def integrate(home: str, sstore: StrategicStore, store: Store, *, program_id: str,
              cfg, policy: ProgramPolicy, now: float | None = None) -> dict:
    """Merge committed lane branches into one integration worktree and verify the union."""
    from quaestor.workspace import worktrees as wt_mod
    st = sstore.get_integration_state(program_id)
    if st and st["state"] == "COMPLETE":
        return {"integration": st["state"]}
    # CONFLICT is RETRYABLE once the strategist has recorded exclusions/decisions; the previous
    # attempt's merge was aborted, so the workspace is clean.
    repo = _project_repo(sstore, program_id)
    if not repo or not os.path.isdir(repo):
        return {"integration": "REFUSED", "reason": "no repository"}

    lanes = [l for l in sstore.lanes(program_id)
             if l.kind in (KIND_IMPLEMENTATION,) and l.verdict == prog_mod.PASS]
    pending = [l for l in sstore.lanes(program_id)
               if not l.terminal and l.kind != KIND_INTEGRATION]
    if pending:
        return {"integration": "PENDING", "open_lanes": [l.lane_id for l in pending]}
    # A FAILED lane is never silently dropped from integration -- but an ABANDONED lane is a
    # RECORDED DECISION (operator/strategist acted on it; see events LANE_STATE_CHANGED), so it
    # is excluded BY NAME in the integration detail rather than treated as a surprise failure.
    failed = [l for l in sstore.lanes(program_id)
              if l.kind == KIND_IMPLEMENTATION and l.verdict != prog_mod.PASS
              and l.state != prog_mod.LANE_ABANDONED]
    abandoned_out = [l.lane_id for l in sstore.lanes(program_id)
                     if l.state == prog_mod.LANE_ABANDONED]
    if failed:
        sstore.set_integration_state(program_id, "REFUSED",
                                     detail={"failed_lanes": [l.lane_id for l in failed],
                                             "excluded_abandoned": abandoned_out}, now=now)
        return {"integration": "REFUSED", "reason": "failed implementation lane(s)",
                "lanes": [l.lane_id for l in failed]}

    path = os.path.join(wt_mod.worktree_root(home), str(program_id), "_integration")
    base_head = sstore.get_program_meta(program_id).get("base_head", "")
    created = wt_mod.create_lane_worktree(repo, path, branch=branding.branch(program_id,
                                                                             "_integration"),
                                          base_ref=base_head or "")
    if not created.get("ok"):
        sstore.set_integration_state(program_id, "REFUSED", workspace_path=path,
                                     detail={"error": created.get("error")}, now=now)
        return {"integration": "REFUSED", "reason": created.get("error")}

    # §32 minimum overlap protection: lockfile/schema/manifest collisions force re-evaluation
    # BEFORE the merge, because git can textually succeed at merging two incompatible schemas.
    per_lane_files = {}
    for l in lanes:
        ckpt = sstore.get_lane_task(l.lane_id)["checkpoint"]
        wtp = ckpt.get("worktree_path") or ""
        per_lane_files[l.lane_id] = set(wt_mod.changed_files(wtp)) if wtp and os.path.isdir(wtp) else set()
    risky = _overlap_risk(per_lane_files)
    if risky:
        sstore.set_integration_state(program_id, "CONFLICT", workspace_path=path,
                                     base_head=created.get("head") or "",
                                     detail={"overlap": risky}, now=now)
        _record_blocker(sstore, program_id, "", "",
                        "semantic-overlap risk between lanes; integration requires strategist "
                        "re-evaluation: %s" % risky, now=now)
        return {"integration": "CONFLICT", "overlap": risky}

    merged, conflicts = [], []
    # A recorded strategist/operator decision may EXCLUDE a conflicted or redundant branch from
    # integration (program meta `_integration_excluded`, JSON list). The exclusion travels with
    # the integration record -- it is never silent.
    excluded = set(_load_json_list(sstore.get_program_meta(program_id).get("_integration_excluded")))
    for l in sorted(lanes, key=lambda x: x.created_at):
        if l.lane_id in excluded:
            continue
        r = wt_mod.merge_branch(path, wt_mod.branch_name(program_id, l.lane_id),
                                message="integrate %s" % l.lane_id)
        (merged if r.get("ok") else conflicts).append(l.lane_id)
        if not r.get("ok"):
            break
    if conflicts:
        sstore.set_integration_state(program_id, "CONFLICT", workspace_path=path,
                                     base_head=created.get("head") or "",
                                     detail={"merged": merged, "conflicts": conflicts,
                                             "excluded": sorted(excluded)},
                                     now=now)
        _record_blocker(sstore, program_id, "", "",
                        "merge conflict integrating %s" % conflicts, now=now)
        return {"integration": "CONFLICT", "conflicts": conflicts}

    receipt = _verify(home, path, cfg)
    ok = receipt.test_verdict == test_collector.PASS
    sstore.set_integration_state(program_id, "COMPLETE" if ok else "TESTS_FAILED",
                                 workspace_path=path, base_head=created.get("head") or "",
                                 detail={"merged": merged,
                                         "verification": receipt.to_dict()}, now=now)
    status = PROGRAM_CANDIDATE_PASS if ok else PROGRAM_CANDIDATE_FAIL
    sstore.set_program_status(program_id, status, actor_id="scheduler",
                              detail={"verification": receipt.test_verdict,
                                      "lanes_merged": len(merged)}, now=now)
    return {"integration": "DONE", "verdict": status, "verification": receipt.test_verdict,
            "merged": merged}


_RISKY_FILES = ("package-lock.json", "poetry.lock", "requirements.txt", "yarn.lock",
                "schema.sql", "migrations/", "Cargo.lock")


def _overlap_risk(per_lane_files: Mapping[str, set]) -> list:
    """Cross-lane overlaps that textual merging cannot be trusted to reconcile. PURE."""
    ids = sorted(per_lane_files)
    risks = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            shared = per_lane_files[a] & per_lane_files[b]
            dangerous = {f for f in shared
                         if any(f.lower().endswith(r) or r.rstrip("/") in f.lower()
                                for r in _RISKY_FILES)}
            if dangerous:
                risks.append({"lanes": [a, b], "files": sorted(dangerous)})
    return risks


# ---------------------------------------------------------------------------------------------
# The tick
# ---------------------------------------------------------------------------------------------
def tick(home: str, sstore: StrategicStore, store: Store, *, program_id: str,
         cfg, preflight, now: float | None = None, spawn: bool = True,
         spawner=None) -> dict:
    """One scheduling pass. Idempotent against durable state; safe to call concurrently-ish
    (SQLite serialises writers; worst case a duplicate skip)."""
    t0 = time.time()
    meta = sstore.get_program_meta(program_id)
    policy = policy_from_meta(meta)
    prog = sstore.get_program(program_id)
    if prog is None:
        return {"error": "NO_SUCH_PROGRAM"}
    status = meta.get("status") or PROGRAM_DRAFT
    report: dict = {"program_id": program_id, "status_in": status}

    if status in (PROGRAM_CANCELLED,):
        report["status_out"] = status
        return report

    reap_report = reap(home, sstore, store, program_id=program_id, cfg=cfg, policy=policy,
                       now=now, spawner=spawner)
    report["reap_actions"] = reap_report["actions"]

    # PLAN GOVERNANCE (PRD.md §7.4/§7.6): the planner seat's run, the PENDING
    # PLAN_PROPOSAL it produced, and any adversarial plan challenge of it are consumed and
    # dispatched HERE. These runs belong to the PROGRAM, not to a lane -- no lane_run binding
    # exists for them, so the lane-oriented reap above cannot see them, and a consumer that
    # lived inside reap would be structurally blind to its own subject.
    # BEFORE governance and scheduling: reap has just finished parking lanes, so this is the
    # moment a lane answered while it was still running becomes schedulable again.
    report["woken"] = apply_pending_wakes(sstore, program_id, now=now)

    report["governance"] = _program_governance(home, sstore, store, program_id=program_id,
                                               cfg=cfg, policy=policy, preflight=preflight,
                                               now=now, spawn=spawn, spawner=spawner)

    lanes = sstore.lanes(program_id)
    waiting_owner = [l for l in lanes if l.state == prog_mod.LANE_WAITING_OWNER]

    integ = None
    if policy.auto_integrate and not [l for l in lanes
                                      if not l.terminal and l.kind != KIND_INTEGRATION] \
            and any(l.kind == KIND_IMPLEMENTATION for l in lanes):
        integ = integrate(home, sstore, store, program_id=program_id, cfg=cfg, policy=policy,
                          now=now)
    report["integration"] = integ

    sched = schedule(home, sstore, store, program_id=program_id, cfg=cfg, policy=policy,
                     preflight=preflight, now=now, spawn=spawn, spawner=spawner)
    report["scheduled"] = sched["started"]
    report["schedule_skips"] = sched["skipped"]

    new_status = _aggregate_status(sstore, program_id, integ)
    if new_status != status:
        sstore.set_program_status(program_id, new_status, actor_id="scheduler",
                                  detail={"tick_ms": int((time.time() - t0) * 1000)}, now=now)
    report["status_out"] = new_status
    report["duration_ms"] = int((time.time() - t0) * 1000)
    return report


def _aggregate_status(sstore, program_id: str, integ) -> str:
    meta = sstore.get_program_meta(program_id)
    if meta.get("status") == PROGRAM_CANCELLED:
        return PROGRAM_CANCELLED
    if integ and integ.get("verdict") == PROGRAM_CANDIDATE_PASS:
        return PROGRAM_CANDIDATE_PASS
    if integ and integ.get("verdict") == PROGRAM_CANDIDATE_FAIL:
        return PROGRAM_CANDIDATE_FAIL
    if integ and integ.get("integration") == "CONFLICT":
        return PROGRAM_WAITING_STRATEGIST
    lanes = sstore.lanes(program_id)
    agg = prog_mod.aggregate(lanes)
    if agg["next_authority"] == prog_mod.NEXT_OWNER:
        return PROGRAM_WAITING_OWNER
    if agg["next_authority"] == prog_mod.NEXT_STRATEGIST and agg["waiting"]:
        return PROGRAM_WAITING_STRATEGIST
    if all(l.terminal for l in lanes) and lanes:
        return PROGRAM_CANDIDATE_PASS if agg["program_verdict"] == prog_mod.PASS \
            else PROGRAM_CANDIDATE_FAIL
    return PROGRAM_RUNNING if any(not l.terminal for l in lanes) else (
        PROGRAM_PLANNED if lanes else PROGRAM_DRAFT)


# ---------------------------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------------------------
def load_constraints(sstore, program_id: str) -> tuple:
    meta = sstore.get_program_meta(program_id)
    return tuple(_load_json_list(meta.get("constraints_json")))


def _load_json_list(text) -> list:
    try:
        v = json.loads(text or "[]")
        return v if isinstance(v, list) else []
    except ValueError:
        return []


def inbox(sstore, program_id: str) -> dict:
    """Only what actually needs attention (§22). Everything else is the record, not the queue."""
    items = []
    for q in sstore.open_questions_for_program(program_id):
        mtype = q["message_type"]
        items.append({
            "kind": mtype, "message_id": q["message_id"], "lane_id": q["lane_id"],
            "payload": q["payload"], "route": ("OWNER" if mtype in (msg_mod.AUTHORITY_REQUEST,
                                                                    msg_mod.OWNER_ESCALATION)
                                               else "STRATEGIST"),
            "created_at": q["created_at"]})
    lanes = sstore.lanes(program_id)
    # Escalation blockers are NOT in messages.AWAITING_TYPES by design (the qualified vocabulary
    # reserves that set for things a single DIRECTIVE answers). They still belong in the inbox --
    # a paused-with-blocker lane is exactly what "what needs my attention?" exists to surface.
    for l in lanes:
        if l.state not in prog_mod.WAITING_STATES:
            continue
        blockers = [m for m in sstore.messages(l.lane_id)
                    if m["message_type"] == msg_mod.BLOCKER]
        if blockers:
            b = blockers[-1]
            items.append({"kind": "BLOCKER", "message_id": b["message_id"],
                          "lane_id": l.lane_id, "payload": b["payload"],
                          "route": ("OWNER" if l.state == prog_mod.LANE_WAITING_OWNER
                                    else "STRATEGIST"),
                          "created_at": b["created_at"]})
    for l in lanes:
        if l.verdict == prog_mod.FAIL and not l.waiting and not l.terminal:
            items.append({"kind": "LANE_FAILED", "lane_id": l.lane_id,
                          "payload": l.title, "route": "STRATEGIST", "created_at": l.updated_at})
    st = sstore.get_integration_state(program_id)
    if st and st["state"] == "CONFLICT":
        items.append({"kind": "INTEGRATION_CONFLICT", "lane_id": "",
                      "payload": json.dumps(st.get("detail") or {}),
                      "route": "STRATEGIST", "created_at": st["updated_at"]})
    # DIRECTIVE_PENDING_APPROVAL -- a MODEL wrote a directive and this program's autonomy mode
    # says a human clicks before it applies. Program-level like INTEGRATION_CONFLICT below: a
    # pending directive belongs to the approval queue, not to a lane, and the queue is the whole
    # point of the DEFAULT mode. Without this the directives would sit in program meta where
    # nothing surfaces them, and "propose-only" would mean "silently discarded".
    import quaestor.core.strategist as _strat_mod
    try:
        _pending = json.loads(sstore.get_program_meta(program_id).get(
            _strat_mod.PENDING_DIRECTIVES_KEY) or "{}")
    except ValueError:
        _pending = {}
    for _d in ((_pending or {}).get("directives") or ()):
        if not isinstance(_d, Mapping):
            continue
        items.append({"kind": "DIRECTIVE_PENDING_APPROVAL",
                      "message_id": str(_d.get("message_id") or ""),
                      "lane_id": str(_d.get("lane_id") or ""),
                      "payload": str(_d.get("directive") or ""),
                      "route": "STRATEGIST",
                      "created_at": 0.0})

    # PROPOSAL_PENDING_ADOPTION (PRD.md §7.4) -- the deliberate inbox-vocabulary extension.
    # The message ENVELOPE cannot carry this: core.messages requires every message to belong to
    # a lane, and a PRE-adoption proposal belongs to none (the INTEGRATION_CONFLICT precedent is
    # exactly this program-level shape). The planner proposes; this item is where the strategist
    # sees it and disposes -- via `program adopt`, never automatically.
    import quaestor.core.planner as _planner
    pdoc = _planner.pending_proposal(sstore, program_id)
    if pdoc is not None:
        unresolved = [f for f in (pdoc.get("findings") or []) if not f.get("resolved")]
        items.append({
            "kind": "PROPOSAL_PENDING_ADOPTION", "message_id": "", "lane_id": "",
            "payload": json.dumps(
                {"digest": pdoc.get("digest"),
                 "lanes": len((pdoc.get("proposal") or {}).get("lanes") or []),
                 "planner_provider": (pdoc.get("planner_provenance") or {}).get("provider"),
                 "unresolved_findings": len(unresolved),
                 "require_plan_review": bool(pdoc.get("require_plan_review", True))},
                sort_keys=True, default=str),
            "route": "STRATEGIST",
            "created_at": float(pdoc.get("created_at") or 0)})
    prog = sstore.get_program(program_id) or {}
    agg = prog_mod.aggregate(lanes)
    return {"program_id": program_id, "title": prog.get("title", ""),
            "status": sstore.get_program_meta(program_id).get("status", ""),
            "items": sorted(items, key=lambda i: -float(i["created_at"] or 0)),
            "aggregate": agg, "inspected": {"items": len(items), "lanes": len(lanes)},
            "vacuous": not items and not lanes}


#: Stated when every seat that ran was a test double. NOT a refusal -- the fake executor is a
#: legitimate dry run -- but a program that produced no code must never present as plain success.
NO_REAL_AGENT_RAN = "NO_REAL_AGENT_RAN"

#: The declared family of the test double. One name, read from the registry, not matched on the
#: kind string -- so a second test kind cannot quietly present as a real agent.
TEST_PROVIDER_FAMILY = "test"


def measured_providers(sstore, store, program_id: str) -> dict:
    """role -> sorted providers ACTUALLY dispatched on this program, per run.provenance.

    The same MEASURED fact epistemic-independence admission is computed from -- never
    configuration, never anything a model says about itself. {} when ``store`` is absent, which
    is honest: with no event store we have not measured anything.
    """
    if store is None:
        return {}
    seen: dict = {}
    for lane in sstore.lanes(program_id):
        for b in sstore.runs_for_lane(lane.lane_id):
            prov = _provenance_provider(store, b["run_id"])
            provider = str(prov.get("provider") or "")
            if provider:
                seen.setdefault(str(b["role"]), set()).add(provider)
    return {role: sorted(v) for role, v in sorted(seen.items())}


def execution_reality(providers: Mapping) -> dict:
    """Did a real agent run? PURE over measured providers.

    THE COLD-START DEFECT. A new user's first program reported "PASS (every lane completed and
    passed)" having spawned no agent and written no code, because the manifest `init` generated
    pinned the test double and nothing on the path from init to verdict ever said so. A crash
    would have been kinder: it tells you something is wrong. This states the absence instead.
    """
    from quaestor.adapters import registry as cap_reg
    every = sorted({p for v in providers.values() for p in v})
    if not every:
        return {"measured": False, "test_double_only": False, "refusal": "", "note": ""}
    families = {cap_reg.provider_family(p) for p in every}
    if families != {TEST_PROVIDER_FAMILY}:
        return {"measured": True, "test_double_only": False, "refusal": "", "note": ""}
    return {"measured": True, "test_double_only": True, "refusal": NO_REAL_AGENT_RAN,
            "note": ("no real agent ran: every seat resolved to the test double %s, so no code "
                     "was produced. Run `quaestor connect` to see which agents are installed, "
                     "then set executor.default in the manifest to one of them."
                     % ", ".join(repr(p) for p in every))}


def status_view(sstore, store, program_id: str) -> dict:
    """The operator display (§50) plus machine-readable state."""
    prog = sstore.get_program(program_id) or {}
    lanes = sstore.lanes(program_id)
    tasks = {l.lane_id: sstore.get_lane_task(l.lane_id) for l in lanes}
    rows = []
    for l in lanes:
        bindings = sstore.runs_for_lane(l.lane_id)
        live = next((b["run_id"] for b in reversed(bindings) if not b["processed"]), "")
        rows.append({"lane_id": l.lane_id, "title": l.title, "kind": l.kind, "state": l.state,
                     "verdict": l.verdict, "actor": _actor_for(sstore, l, live),
                     "attempt": tasks[l.lane_id]["attempt"],
                     "last_run": live,
                     "summary": (tasks[l.lane_id]["checkpoint"].get("summary") or "")[:160]})
    ib = inbox(sstore, program_id)
    providers = measured_providers(sstore, store, program_id)
    return {
        "program_id": program_id, "title": prog.get("title", ""),
        "objective": prog.get("objective", ""), "status": ib["status"],
        "aggregate": ib["aggregate"], "inbox_count": len(ib["items"]),
        "lanes": rows, "inspected": {"lanes": len(rows)},
        "vacuous": prog is None and not rows,
        # WHO ACTUALLY RAN. Carried in the view, not rendered by one transport, so the CLI and
        # the cockpit cannot disagree about whether real work happened.
        "providers": providers,
        "execution_reality": execution_reality(providers),
    }


def _actor_for(sstore, lane, live_run: str) -> str:
    if live_run:
        b = sstore.lane_for_run(live_run) or {}
        return str(b.get("role") or "executor")
    return "-"

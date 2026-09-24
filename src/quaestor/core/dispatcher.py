"""dispatcher -- admission control. The only door into execution.

THE ADMISSION LADDER, IN ORDER, AND WHY
---------------------------------------
    1. IDENTITY      duplicate dispatch key -> return the existing run, spawn nothing
    2. AUTHORITY     capability not in the envelope -> OWNER_REQUIRED (before any I/O)
    3. PREFLIGHT     credential/provider override, or unverifiable auth -> PREFLIGHT_REFUSED
    4. LEASE         a mutable worktree already leased -> LEASE_REFUSED
    5. DRIFT         expected HEAD/branch != actual, measured now -> LEASE_REFUSED
    6. SPAWN         detached worker, recorded by pid AND by the lock it will hold

Cheap, pure refusals come first. Authority is checked before the auth preflight because a run
that is not authorised should not cause us to shell out at all -- and because a policy refusal is
a statement about the REQUEST, which we can make without touching the world.

WHAT THIS MODULE WILL NOT DO
----------------------------
It will not retry. It will not "just try again" after an ambiguous execution. It will not create
a second attempt for a dispatch key that already has one, terminal or not. Recovering a failed or
uncertain run is a decision that belongs to GPT or the owner, and they express it by issuing a
dispatch with a DIFFERENT identity (new step, new expected HEAD) -- which is a new key, and
therefore a new, deliberate execution.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from quaestor.core import authority as authority_mod
from quaestor.core import concurrency
from quaestor.core import domain
from quaestor.core import credential_policy as cred_mod
from quaestor.core import proc
from quaestor.workspace import git as repo
from quaestor.core import runfiles
from quaestor.core.identity import DispatchIdentity, RunBinding, build_identity
from quaestor.core.prompting import build_child_prompt
from quaestor.core.store import Admission, LeaseConflict, Store

# Outcomes
ADMITTED = "ADMITTED"
DUPLICATE = "DUPLICATE"
REFUSED = "REFUSED"


@dataclass(frozen=True)
class DispatchSpec:
    """What a caller (eventually: GPT, through a transport adapter) asks for."""

    workflow_id: str
    step_id: str
    task: str
    worktree_path: str
    authority_profile: str = authority_mod.READ_ONLY
    required_capabilities: Sequence[str] = field(default_factory=tuple)
    executor: Mapping = field(default_factory=lambda: {"kind": "fake"})
    model: str = ""
    timeout_s: float = 1800.0
    min_inspected: int = 1
    title: str = ""
    claude_path: str = "claude"
    expected_head: str = ""       # empty -> bind to whatever HEAD is now, and record it
    expected_branch: str = ""
    #: Take an exclusive worktree lease even for a READ_ONLY run. Off by default -- readers do
    #: not need exclusivity and forcing it would serialise inspection behind writers for no
    #: safety gain. P4 sets it because exactly one lane may touch a real project worktree at a
    #: time, reader or not.
    require_lease: bool = False
    #: Program-level context carried VERBATIM into the durable request artifact (program_id,
    #: lane_id, role, resume directive...). Never consulted by admission -- it changes nothing
    #: about identity, authority or policy -- so a dispatch key computed with and without it is
    #: the same key. It exists so the WORKER can deliver two-way traffic and checkpoints to the
    #: strategic layer without the dispatcher learning any orchestration semantics.
    context: Mapping = field(default_factory=dict)


@dataclass(frozen=True)
class DispatchResult:
    outcome: str
    run_id: str = ""
    dispatch_key: str = ""
    state: str = ""
    reason: str = ""
    detail: str = ""
    spawned: bool = False
    extra: Mapping = field(default_factory=dict)

    @property
    def admitted(self) -> bool:
        return self.outcome == ADMITTED


def dispatch(store: Store, spec: DispatchSpec, *, run_root: str,
             preflight: Callable[..., cred_mod.PreflightDecision] | None = None,
             spawn: bool = True, now: float | None = None,
             probe: Callable[..., Any] = repo.probe,
             spawner: Callable[..., int] | None = None) -> DispatchResult:
    """Admit and (optionally) launch. Every I/O seam is injected so tests drive the real ladder.

    ``spawn=False`` stops after the run is DISPATCHED-ready, which is how the mutation suite
    proves the refusal paths without starting processes.
    """
    import time
    now = time.time() if now is None else float(now)

    # -- 0. bind the worktree identity ---------------------------------------------------------
    snap = probe(spec.worktree_path)
    if not snap.probe_ok:
        return DispatchResult(REFUSED, reason="WORKTREE_UNREADABLE",
                              detail="cannot read the worktree at %s: %s"
                                     % (spec.worktree_path, snap.probe_error))
    expected_head = (spec.expected_head or snap.head or "").lower()
    expected_branch = spec.expected_branch or (snap.branch or "")
    repo_id = repo.repo_id_for(repo.origin_url(spec.worktree_path), snap.repo_root)

    caps = tuple(spec.required_capabilities or ()) or _default_caps(spec.authority_profile)
    is_write = authority_mod.is_write_profile(spec.authority_profile, caps)

    # -- 1. identity / duplicate ---------------------------------------------------------------
    binding_id: DispatchIdentity = build_identity(
        workflow_id=spec.workflow_id, step_id=spec.step_id,
        prompt=_prompt_for(spec, run_nonce="<pending>"),   # nonce excluded; see _prompt_for
        repo_id=repo_id, worktree_path=spec.worktree_path, expected_branch=expected_branch,
        expected_head=expected_head, authority_profile=spec.authority_profile, capabilities=caps)

    adm: Admission = store.admit(binding_id, run_root=run_root, is_write=is_write,
                                 title=spec.title)
    if not adm.created:
        return DispatchResult(DUPLICATE, adm.run_id, adm.dispatch_key,
                              state=str((adm.run or {}).get("execution_state") or ""),
                              reason="DUPLICATE_DISPATCH_KEY",
                              detail=("an execution for this dispatch key already exists; "
                                      "returning it rather than starting a second one"))

    run_id = adm.run_id
    run = adm.run
    rd = runfiles.ensure(str(run["run_dir"]))
    store.transition(run_id, domain.PREFLIGHT, expect_from=domain.CREATED)

    # -- 2. authority --------------------------------------------------------------------------
    decision = authority_mod.require(spec.authority_profile, caps,
                                     owner_grants=store.owner_grants(), now=now)
    if not decision.allowed:
        state = (domain.OWNER_REQUIRED if decision.decision == authority_mod.OWNER_REQUIRED
                 else domain.AUTHORITY_REFUSED)
        store.transition(run_id, state, reason=decision.reason,
                         detail={"missing": list(decision.missing),
                                 "ungranted": list(decision.ungranted)})
        return DispatchResult(REFUSED, run_id, adm.dispatch_key, state, decision.decision,
                              decision.reason,
                              extra={"missing": list(decision.missing),
                                     "ungranted": list(decision.ungranted)})

    # -- 3. auth preflight ---------------------------------------------------------------------
    # NO VENDOR DEFAULT. This used to be `preflight or claude_preflight`, which meant a
    # deployment that configured a different executor still got Anthropic's credential
    # rules -- and got them from `core`, which is supposed to know no provider at all.
    # A missing policy now REFUSES: "which variables would redirect this run onto an
    # unauthorised billing path" has no safe default answer.
    if preflight is None:
        pf = cred_mod.decide(policy=None, env={}, auth_status=None,
                             requires_write=is_write)
    else:
        pf = preflight(claude_path=spec.claude_path, requires_write=is_write)
    store.append_event("preflight", run_id=run_id,
                       detail={"decision": pf.decision, "reason": pf.reason,
                               "auth_class": pf.auth_class,
                               "offending_vars": list(pf.offending_vars),
                               "record": dict(pf.record)})
    if not pf.accepted:
        store.transition(run_id, domain.PREFLIGHT_REFUSED, reason="%s: %s" % (pf.reason, pf.detail))
        return DispatchResult(REFUSED, run_id, adm.dispatch_key, domain.PREFLIGHT_REFUSED,
                              pf.reason, pf.detail,
                              extra={"offending_vars": list(pf.offending_vars),
                                     "auth_class": pf.auth_class})

    # -- 3b. concurrency ceiling for REAL children ---------------------------------------------
    # Placed after authority/preflight (cheap refusals first) and BEFORE the lease, so a refused
    # second child never takes a lease it would have to give back. Fake executors are exempt --
    # the mutation suite runs many at once and must keep being able to.
    active_real = [r for r in store.runs_in_states(domain.ACTIVE_STATES)
                   if str(r["run_id"]) != run_id and _is_real_run(store, r)]
    cdec = concurrency.decide(active_real_runs=active_real,
                              requested_executor=dict(spec.executor or {}))
    store.append_event("concurrency", run_id=run_id,
                       detail={"decision": cdec.decision, "active": cdec.active_count,
                               "limit": cdec.limit, "policy": dict(cdec.policy),
                               "active_run_ids": list(cdec.active_run_ids)})
    if not cdec.admitted:
        store.transition(run_id, domain.PERMISSION_REFUSED, reason=cdec.reason,
                         detail={"active_run_ids": list(cdec.active_run_ids)})
        return DispatchResult(REFUSED, run_id, adm.dispatch_key, domain.PERMISSION_REFUSED,
                              cdec.decision, cdec.reason,
                              extra={"active_run_ids": list(cdec.active_run_ids),
                                     "limit": cdec.limit})

    # -- 4. lease (mutable runs only) ----------------------------------------------------------
    # A read-only run takes NO lease, on purpose: exclusivity is a cost, and imposing it on
    # readers would serialise inspection behind writers for no safety gain. Two read-only runs
    # against one worktree are legal and the suite asserts it -- a lease that refuses everything
    # would pass the "second writer is refused" control while being useless.
    lease_row = None
    if is_write or spec.require_lease:
        try:
            lease_row = store.acquire_lease(repo_id=repo_id, worktree_path=spec.worktree_path,
                                            expected_branch=expected_branch,
                                            expected_head=expected_head, run_id=run_id)
        except LeaseConflict as exc:
            store.transition(run_id, domain.LEASE_REFUSED, reason=str(exc))
            return DispatchResult(REFUSED, run_id, adm.dispatch_key, domain.LEASE_REFUSED,
                                  "LEASE_CONFLICT", str(exc))
        store.transition(run_id, domain.LEASED, expect_from=domain.PREFLIGHT)

    # -- 5. drift, measured NOW ----------------------------------------------------------------
    fresh = probe(spec.worktree_path)
    drift = repo.classify_drift(expected_branch=expected_branch, expected_head=expected_head,
                                snapshot=fresh)
    if drift != repo.NO_DRIFT:
        detail = ("%s: expected %s@%s, worktree is %s@%s"
                  % (drift, expected_branch, expected_head[:12], fresh.branch,
                     str(fresh.head or "")[:12]))
        if lease_row is not None:
            store.release_lease(str(lease_row["lease_id"]), reason=drift)
        store.transition(run_id, domain.LEASE_REFUSED, reason=detail)
        return DispatchResult(REFUSED, run_id, adm.dispatch_key, domain.LEASE_REFUSED, drift,
                              detail)

    # -- 6. the request artifact, then the worker ----------------------------------------------
    prompt = _prompt_for(spec, run_nonce=str(run["run_nonce"]), profile=spec.authority_profile,
                         caps=caps, cwd=spec.worktree_path, binding_ids=(spec.workflow_id,
                                                                         spec.step_id))
    request = {
        "run_id": run_id, "dispatch_key": adm.dispatch_key,
        "workflow_id": spec.workflow_id, "step_id": spec.step_id,
        "run_nonce": str(run["run_nonce"]),
        "cwd": os.path.abspath(spec.worktree_path).replace("\\", "/"),
        "repo_id": repo_id, "expected_branch": expected_branch, "expected_head": expected_head,
        "authority_profile": spec.authority_profile, "capabilities": sorted(caps),
        "executor": dict(spec.executor or {"kind": "fake"}),
        "model": spec.model, "timeout_s": float(spec.timeout_s),
        "min_inspected": int(spec.min_inspected),
        "require_lease": bool(spec.require_lease),
        "claude_path": spec.claude_path,
        "claude_version": (pf.record or {}).get("claude_version", ""),
        "auth_class": pf.auth_class,
        "prompt": prompt,
        "prompt_sha256": binding_id.prompt_sha256,
        "created_at": now,
        "context": dict(spec.context or {}),
    }
    runfiles.write_json(runfiles.p(rd, runfiles.REQUEST), request)

    if not spawn:
        return DispatchResult(ADMITTED, run_id, adm.dispatch_key,
                              str(store.get_run(run_id)["execution_state"]), spawned=False)

    lock_path = runfiles.p(rd, runfiles.LOCK)

    # DISPATCHED BEFORE SPAWN, deliberately. The run must be DISPATCHED before the worker can
    # possibly observe it: the worker's first transition is RUNNING with expect_from=DISPATCHED,
    # and under the previous ordering a fast worker (in-process test spawners today; a warmed
    # process tomorrow) could observe LEASED and refuse itself. A spawn that then fails walks
    # DISPATCHED -> WORKER_FAILED, which is a legal refusal edge from every active state.
    store.transition(run_id, domain.DISPATCHED)
    spawn_fn = spawner or _spawn_worker
    try:
        spawn_pid = spawn_fn(db_path=store.path, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        # A SYNCHRONOUS spawner may have already driven the run to a terminal state before
        # raising -- in which case the run's own terminal verdict stands and this refusal would
        # be an illegal rewrite of history. Never raise past this point either way.
        try:
            store.transition(run_id, domain.WORKER_FAILED,
                             reason="worker spawn failed: %s" % exc)
        except Exception:  # noqa: BLE001 - already terminal; keep its own verdict
            pass
        return DispatchResult(REFUSED, run_id, adm.dispatch_key, domain.WORKER_FAILED,
                              "SPAWN_FAILED", str(exc))

    store.record_spawn(run_id, spawn_pid=spawn_pid, lock_path=lock_path,
                       stdout_path=runfiles.p(rd, runfiles.STDOUT),
                       stderr_path=runfiles.p(rd, runfiles.STDERR))
    return DispatchResult(ADMITTED, run_id, adm.dispatch_key, domain.DISPATCHED, spawned=True,
                          extra={"spawn_pid": spawn_pid})


def _is_real_run(store: Store, run: Mapping) -> bool:
    """Does this active run hold a REAL Claude child? Impure (reads the run artifact).

    Read from the durable request rather than inferred from the run row, because the executor
    kind is a property of what was dispatched. An unreadable request counts as REAL: fail-closed,
    since the cost of guessing wrong is an unbounded fleet of subscription-backed children.
    """
    try:
        rd = str(run.get("run_dir") or "")
        req = runfiles.read_json(runfiles.p(rd, runfiles.REQUEST))
        if not isinstance(req, dict):
            return True
        return concurrency.is_real_executor(req.get("executor") or {})
    except Exception:  # noqa: BLE001
        return True


def _default_caps(profile: str) -> tuple:
    """The capabilities a profile is expected to exercise. PURE.

    Not the same as ``granted_capabilities``: this is what the RUN declares it needs, and the
    policy engine then checks the profile against it. Declaring less than the profile grants is
    legal and good practice.
    """
    return tuple(sorted(authority_mod.granted_capabilities(profile)))


def _prompt_for(spec: DispatchSpec, *, run_nonce: str, profile: str = "", caps=(), cwd: str = "",
                binding_ids=("", "")) -> str:
    """Build the child prompt. PURE.

    NOTE ON THE DISPATCH KEY. The key is computed over a prompt built with a PLACEHOLDER nonce,
    because the nonce is generated per ATTEMPT and would otherwise make every dispatch unique --
    which would defeat deduplication completely. The key binds the TASK; the nonce binds the
    ARTIFACT to the attempt. Two different jobs, two different mechanisms.
    """
    b = RunBinding(run_id="", workflow_id=binding_ids[0] or spec.workflow_id,
                   step_id=binding_ids[1] or spec.step_id, run_nonce=run_nonce)
    return build_child_prompt(task=spec.task, binding=b,
                              profile=profile or spec.authority_profile,
                              capabilities=caps or _default_caps(spec.authority_profile),
                              cwd=cwd or spec.worktree_path)


def _spawn_worker(*, db_path: str, run_id: str) -> int:
    """Start the detached worker. Impure. Returns its pid.

    Detached (see proc.spawn_detached_kwargs) so the worker outlives this process: a dispatcher
    or bridge restart must not kill a live Claude, and must not orphan it either -- which is why
    the worker's identity is recorded here BEFORE we lose sight of it.
    """
    cmd = [proc.python_executable(), "-m", "quaestor.core.worker", "--db", str(db_path),
           "--run-id", str(run_id)]
    p = subprocess.Popen(cmd, cwd=_project_root(), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
                         **proc.spawn_detached_kwargs())
    return int(p.pid)


def _project_root() -> str:
    """The directory the detached worker is started from.

    It must be the IMPORT ROOT (the parent of the ``quaestor`` package), not the repository
    root: the worker is launched as ``-m quaestor.core.worker`` and would not resolve its own
    package from anywhere else.
    """
    here = os.path.dirname(os.path.abspath(__file__))          # .../quaestor/core
    return os.path.dirname(os.path.dirname(here))              # .../src

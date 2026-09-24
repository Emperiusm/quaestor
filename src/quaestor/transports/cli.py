"""cli -- the operator surface. Narrow BUSINESS actions, never a shell.

The MCP surface, when it eventually exists, will expose the same verbs and nothing more:

    dispatch  status  result  reconcile  cancel

There is deliberately no ``run``, ``exec``, ``bash`` or ``powershell`` verb here, and there never
will be. ChatGPT expresses INTENT; the control plane translates intent into policy-constrained
execution. A generic shell verb would make every capability boundary in this project decorative.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Sequence

from quaestor import branding
from quaestor.core import coreauth as coreauth_mod
from quaestor.core import coreid as coreid_mod
from quaestor.core import proc
from quaestor.core import authority as authority_mod
from quaestor.core import domain
from quaestor.executors import claude_auth as preflight_mod
from quaestor.core import reconcile as reconcile_mod
from quaestor.core import runfiles
from quaestor.core.dispatcher import DispatchSpec, dispatch
from quaestor.core.store import Store

#: The in-package location this project used before it was installable. Kept ONLY so an
#: existing checkout does not silently lose its programs the day packaging lands.
_LEGACY_HOME = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "var")


def _default_home() -> str:
    """Where state lives when nobody said otherwise. Impure.

    Precedence, and the reason for each step:

      1. ``QUAESTOR_HOME`` -- an explicit deployment decision outranks every convention.
      2. An EXISTING legacy ``<package>/var`` -- because changing a default must never move
         somebody's data out from under them. A checkout that already has programs keeps using
         the directory those programs are in, and the operator moves it when they choose to.
      3. ``branding.state_home()`` -- the platform's per-user data directory, which is where
         state belongs once this is installed rather than run from a source tree.
    """
    explicit = os.environ.get(branding.env_var("home"))
    if explicit:
        return explicit
    if os.path.isdir(_LEGACY_HOME):
        return _LEGACY_HOME
    return branding.state_home()


DEFAULT_HOME = _default_home()


def _paths(home: str) -> tuple:
    return os.path.join(home, "orchestrator.sqlite3"), os.path.join(home, "runs")


def _emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n")


def cmd_preflight(a) -> int:
    d = preflight_mod.run_preflight(claude_path=a.claude_path, requires_write=a.write)
    _emit({"decision": d.decision, "reason": d.reason, "detail": d.detail,
           "auth_class": d.auth_class, "offending_vars": list(d.offending_vars),
           "record": dict(d.record)})
    return 0 if d.accepted else 1


def cmd_dispatch(a) -> int:
    db, runs = _paths(a.home)
    store = Store(db)
    try:
        spec = DispatchSpec(
            workflow_id=a.workflow, step_id=a.step, task=a.task, worktree_path=a.worktree,
            authority_profile=a.profile,
            executor={"kind": a.executor} if a.executor != "fake" else
            {"kind": "fake", "config": json.loads(a.fake_config)},
            model=a.model or "", timeout_s=a.timeout, min_inspected=a.min_inspected,
            claude_path=a.claude_path, title=a.title or "")
        res = dispatch(store, spec, run_root=runs, spawn=not a.no_spawn)
        _emit({"outcome": res.outcome, "run_id": res.run_id, "dispatch_key": res.dispatch_key,
               "state": res.state, "reason": res.reason, "detail": res.detail,
               "spawned": res.spawned, "extra": dict(res.extra)})
        return 0 if res.admitted or res.outcome == "DUPLICATE" else 1
    finally:
        store.close()


def cmd_status(a) -> int:
    db, _ = _paths(a.home)
    store = Store(db)
    try:
        if a.run_id:
            run = store.get_run(a.run_id)
            if run is None:
                _emit({"error": "no such run", "run_id": a.run_id})
                return 2
            _emit({"run": run, "worker": store.get_worker(a.run_id),
                   "result": store.get_result(a.run_id),
                   "evidence": store.get_evidence(a.run_id),
                   "lease": store.lease_for_run(a.run_id)})
            return 0
        _emit({"active": store.runs_in_states(domain.ACTIVE_STATES)})
        return 0
    finally:
        store.close()


def cmd_result(a) -> int:
    db, _ = _paths(a.home)
    store = Store(db)
    try:
        h = store.get_handoff(a.run_id)
        if h is None:
            run = store.get_run(a.run_id)
            _emit({"handoff": None,
                   "execution_state": (run or {}).get("execution_state"),
                   "note": "no handoff: the execution did not reach HANDOFF_READY. This is a "
                           "statement about the EXECUTION, not about the program verdict."})
            return 2
        _emit(json.loads(h["handoff_json"]))
        if a.deliver:
            store.mark_delivered(a.run_id)
        return 0
    finally:
        store.close()


def cmd_reconcile(a) -> int:
    db, _ = _paths(a.home)
    store = Store(db)
    try:
        if a.all:
            out = [{"run_id": rid, "classification": r.classification, "reason": r.reason,
                    "auto_redispatch_allowed": r.auto_redispatch_allowed,
                    "recovery_authority": r.recovery_authority}
                   for rid, r in reconcile_mod.reconcile_all(store, apply=not a.dry_run)]
            _emit({"reconciled": out, "note": RECONCILE_NOTE})
            return 0
        r = reconcile_mod.reconcile_run(store, a.run_id, apply=not a.dry_run)
        _emit({"run_id": a.run_id, "classification": r.classification, "reason": r.reason,
               "auto_redispatch_allowed": r.auto_redispatch_allowed,
               "recovery_authority": r.recovery_authority, "evidence": dict(r.evidence),
               "note": RECONCILE_NOTE})
        return 0
    finally:
        store.close()


RECONCILE_NOTE = ("Reconciliation classifies; it never redispatches. An AMBIGUOUS_EXECUTION is a "
                  "decision for GPT or the owner after inspecting the worktree.")


def cmd_grant(a) -> int:
    """Record an OWNER capability grant -- through the CHANNEL, not just into the table.

    The owner channel must be AUTHENTICATED (an interactively provisioned attestation key) and
    the grant is SIGNED. An unsigned row in the store is a record that someone said yes; the
    signature is what makes it an owner's yes rather than the orchestrator's own handwriting.
    """
    db, _ = _paths(a.home)
    from quaestor.core import owner_channel as oc
    if oc.owner_channel_state() != oc.AUTHENTICATED:
        _emit({"error": "OWNER_REQUIRED",
               "detail": ("the owner channel is %s; provision it first with '%s' from an "
                          "interactive terminal"
                          % (oc.owner_channel_state(), branding.command("owner init"))),
               "capability": a.capability})
        return 3
    if a.capability not in authority_mod.ALL_CAPABILITIES:
        _emit({"error": "unknown capability", "capability": a.capability,
               "known": list(authority_mod.ALL_CAPABILITIES)})
        return 2
    if a.expires is not None:
        # A DEADLINE ALREADY PAST IS NOT A GRANT. ``--expires`` was written and never read, so
        # a nonsensical value was harmless; now that the gate enforces it, signing one would
        # hand the owner a receipt for a capability that was never usable for a moment.
        try:
            expires = float(a.expires)
        except (TypeError, ValueError):
            _emit({"error": "UNREADABLE_EXPIRY", "expires": a.expires,
                   "detail": "--expires is an absolute UNIX epoch time in seconds"})
            return 2
        if expires <= __import__("time").time():
            _emit({"error": "EXPIRY_ALREADY_PAST", "expires": expires,
                   "now": __import__("time").time(),
                   "detail": "this grant would be expired the moment it was signed; "
                             "--expires is an absolute UNIX epoch time in seconds"})
            return 2
    from quaestor import attestation
    key = attestation.load_key()
    doc = {"kind": "OWNER_GRANT", "capability": a.capability, "scope": a.scope,
           "expires_at": a.expires, "note": a.note or "", "granted_at_epoch": __import__("time").time()}
    signed = attestation.sign(doc, key=key,
                              key_id=_attestation_key_id())
    store = Store(db)
    try:
        gid = store.add_owner_grant(signed["capability"], scope=signed["scope"],
                                    expires_at=signed.get("expires_at"),
                                    note=json.dumps(signed, sort_keys=True))
        ok, why = attestation.verify(signed)
        _emit({"grant_id": gid, "capability": a.capability, "scope": a.scope,
               "expires_at": a.expires, "attested": ok,
               "verification": why or "signature verified",
               "key_id": signed.get("attestation_key_id", "")})
        return 0
    finally:
        store.close()


def _attestation_key_id() -> str:
    try:
        from quaestor import attestation
        st = attestation.status()
        return str(st.get("key_id") or "")
    except Exception:  # noqa: BLE001
        return ""


def cmd_events(a) -> int:
    db, _ = _paths(a.home)
    store = Store(db)
    try:
        _emit({"events": store.events_for(a.run_id)})
        return 0
    finally:
        store.close()


# =============================================================================================
# Operational surface: mode, owner channel, programs
# =============================================================================================
def _sstore(a):
    from quaestor.core import strategic_store as ss_mod
    return ss_mod.StrategicStore(ss_mod.strategic_path(a.home))


def cmd_mode(a) -> int:
    from quaestor.transports.mcp import mode as transport_mode
    if a.action == "show":
        resolved, record = transport_mode.resolve_mode(a.home)
        _emit({"transport_execution_mode": resolved, "record": record,
               "operational_executor_kinds": sorted(transport_mode.OPERATIONAL_EXECUTOR_KINDS),
               "operational_authority_profiles":
                   sorted(transport_mode.OPERATIONAL_AUTHORITY_PROFILES)})
        return 0
    # set -- a LOCAL act only; there is deliberately no transport verb behind this.
    try:
        out = transport_mode.write_mode(a.home, a.value)
    except ValueError as exc:
        _emit({"error": "UNKNOWN_MODE", "detail": str(exc)})
        return 2
    _emit({"ok": True, **out,
           "note": "takes effect the next time the MCP server or CLI resolves the deployment"})
    return 0


def cmd_owner(a) -> int:
    from quaestor import attestation

    if a.action == "status":
        st = attestation.status(getattr(a, "secret_dir", None))
        _emit(st)
        return 0 if st["channel_state"] == "AUTHENTICATED" else 1
    if a.action == "delete":
        _emit(attestation.delete(getattr(a, "secret_dir", None)))
        return 0
    out = attestation.provision_interactive(getattr(a, "secret_dir", None))
    if not out.get("ok"):
        _emit(out)
        return 2
    from quaestor.core import owner_channel as oc
    _emit({"ok": True, "key_id": out.get("key_id"),
           "owner_channel_state": oc.owner_channel_state(getattr(a, "secret_dir", None)),
           "note": ("owner decisions (grant) are now signed and distinguishable from "
                    "strategist/model statements")})
    return 0


def _resolve_project(project_arg: str) -> tuple:
    """(ProjectConfig|None, reason). A program needs a repository to work on."""
    from quaestor.projects import config as proj_cfg
    if project_arg:
        path = proj_cfg.find_config(project_arg)
        if not path:
            return None, ("no quaestor.yaml/json found at or above %r; run 'quaestor init' there "
                          "first" % project_arg)
        return proj_cfg.load(path)
    cfg, reason = proj_cfg.load_nearest(os.getcwd())
    return cfg, reason


def cmd_project_init(a) -> int:
    """Inspect a repository and write a conservative starter manifest."""
    from quaestor.projects import init as proj_init
    out = proj_init.init_repository(a.path, force=a.force)
    _emit(out)
    return 0 if out.get("ok") else 1


def cmd_connect(a) -> int:
    """Zero-config onboarding (PRD.md §47.1): detect non-authoritative facts, print JSON.

    Detection is side-effect-free unless --write-manifest is passed; the authority block in the
    output is always READ_ONLY, because a detected fact must never widen capability.
    """
    from quaestor.projects import connect as proj_connect
    out = proj_connect.connect_repository(a.path, write_manifest=a.write_manifest)
    _emit(out)
    return 0 if out.get("ok") else 1


def cmd_program_create(a) -> int:
    from quaestor.core import orchestrator as orch
    cfg, reason = _resolve_project(a.project)
    if cfg is None:
        _emit({"error": "PROJECT_CONFIG_MISSING", "detail": reason})
        return 2
    sstore = _sstore(a)
    try:
        pid = orch.create_program(sstore, title=a.title, objective=a.objective,
                                  constraints=[c for c in a.constraints.split("|") if c],
                                  policy=orch.ProgramPolicy(
                                      max_concurrent_executors=a.max_concurrent),
                                  actor_id="cli")
        sstore.set_program_meta(pid, "repository", cfg.repository)
        sstore.set_program_meta(pid, "project_name", cfg.name)
        sstore.set_program_meta(pid, "project_config", cfg.source_path)
        lane_id = orch.plan_lane(sstore, pid, title=a.title or "main",
                                 task=a.objective, kind=orch.KIND_IMPLEMENTATION,
                                 acceptance=[c for c in a.acceptance.split("|") if c],
                                 actor_id="cli")
        # SAID AT THE MOMENT OF COMMITMENT, not discovered three ticks later. A program whose
        # default seat is the test double cannot produce code; reporting the kind as a neutral
        # fact left the user to infer that, and nobody did.
        from quaestor.adapters import registry as _cap
        doc = {"program_id": pid, "lane_id": lane_id, "repository": cfg.repository,
               "executor_default": cfg.executor, "test_commands": list(cfg.test_commands),
               "next": branding.command("program tick %s" % pid)}
        if _cap.provider_family(str(cfg.executor or "")) == orch.TEST_PROVIDER_FAMILY:
            doc["warning"] = orch.NO_REAL_AGENT_RAN
            doc["warning_detail"] = (
                "executor.default is %r, a test double: this program will complete and report "
                "PASS without writing any code. Run %s to see which agents this machine has, "
                "then set executor.default in %s."
                % (cfg.executor, branding.command("connect"),
                   cfg.source_path or "the manifest"))
        _emit(doc)
        return 0
    finally:
        sstore.close()


def cmd_program_plan(a) -> int:
    from quaestor.core import orchestrator as orch
    sstore = _sstore(a)
    try:
        executor = json.loads(a.executor) if a.executor else None
        lane_id = orch.plan_lane(sstore, a.program_id, title=a.title, task=a.task,
                                 kind=a.kind, depends_on=[d for d in a.depends_on.split(",") if d],
                                 acceptance=[x for x in a.acceptance.split("|") if x],
                                 executor=executor, actor_id="cli")
        _emit({"lane_id": lane_id, "program_id": a.program_id})
        return 0
    except ValueError as exc:
        _emit({"error": "PLAN_REFUSED", "detail": str(exc)})
        return 2
    finally:
        sstore.close()


def cmd_program_tick(a) -> int:
    from quaestor.core import orchestrator as orch
    sstore = _sstore(a)
    store = Store(os.path.join(a.home, "orchestrator.sqlite3"))
    try:
        repo = sstore.get_program_meta(a.program_id).get("repository", "")
        cfg, reason = _resolve_project(repo) if repo else (None, "program has no repository")
        if cfg is None:
            _emit({"error": "PROJECT_CONFIG_MISSING", "detail": reason})
            return 2
        report = orch.tick(a.home, sstore, store, program_id=a.program_id, cfg=cfg,
                           preflight=orch._preflight_for(cfg), spawn=not a.no_spawn)
        _emit(report)
        return 0
    finally:
        sstore.close()
        store.close()


def cmd_program_serve(a) -> int:
    """Drive a program until it reaches a terminal-ish status. The hands-off loop."""
    import time as time_mod
    from quaestor.core import orchestrator as orch
    deadline = time_mod.time() + a.max_seconds
    last = ""
    while time_mod.time() < deadline:
        rc_code = _tick_once(a)
        if rc_code != 0:
            return rc_code
        sstore = _sstore(a)
        try:
            meta = sstore.get_program_meta(a.program_id)
            last = meta.get("status", "")
        finally:
            sstore.close()
        if last in (orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
                    orch.PROGRAM_CANCELLED):
            break
        if last == orch.PROGRAM_WAITING_STRATEGIST and not a.wait_for_strategist \
                and not _model_holds_the_strategist_seat(a):
            # A MODEL SEAT CHANGES WHAT WAITING MEANS. Without a seat, WAITING_FOR_STRATEGIST is
            # terminal for this loop: nothing further can happen until a human answers, so
            # spinning would burn ticks against unchanging state. With one, it is the exact
            # state the seat exists to resolve, and stopping here would make unattended
            # operation impossible by construction.
            break
        time_mod.sleep(max(1.0, a.interval))
    _emit({"serve_finished": True, "status": last})
    return 0


def _model_holds_the_strategist_seat(a) -> bool:
    """Is this program configured to let a model answer? Impure (reads program meta).

    Read per iteration rather than cached: an operator may flip a long-running program back to
    a human seat, and the loop should notice on its next pass rather than at its next restart.
    """
    import quaestor.core.strategist as strat_mod
    sstore = _sstore(a)
    try:
        meta = sstore.get_program_meta(a.program_id)
    finally:
        sstore.close()
    return str(meta.get(strat_mod.STRATEGY_MODE_KEY) or "") == strat_mod.STRATEGIST_SEAT


def _tick_once(a) -> int:
    class _A:
        pass
    args = _A()
    args.home = a.home
    args.program_id = a.program_id
    args.no_spawn = False
    return cmd_program_tick(args)


def cmd_program_briefing(a) -> int:
    """Emit the relay packet for one program. The headless twin of the dashboard's Copy button.

    Same assembly, same sanitising, same authority boundary -- ``core.briefing`` over the
    program's handoff bundle. The only difference is the relay vocabulary: with no dashboard
    running there is no dashboard URL, so that line is ABSENT rather than naming a port nothing
    is listening on.
    """
    from quaestor.core import briefing as briefing_mod
    from quaestor.transports import webui
    sstore = _sstore(a)
    try:
        if sstore.get_program(a.program_id) is None:
            _emit({"error": "NO_SUCH_PROGRAM", "program_id": a.program_id})
            return 2
        bundle = sstore.handoff_bundle(a.program_id)
    finally:
        sstore.close()
    doc = briefing_mod.briefing(bundle, surfaces=webui.relay_surfaces(a.program_id))
    if getattr(a, "json", False):
        _emit(doc)
        return 0
    if getattr(a, "message_id", ""):
        hit = [d for d in doc["directives"] if d["message_id"] == a.message_id]
        if not hit:
            _emit({"error": "NO_SUCH_OPEN_QUESTION", "message_id": a.message_id,
                   "open": [q["message_id"] for q in doc["open_questions"]]})
            return 2
        print(hit[0]["prompt"])
        return 0
    print(doc["prompt"])
    return 0


def cmd_program_status(a) -> int:
    from quaestor.core import orchestrator as orch
    sstore = _sstore(a)
    # THE EVENT STORE, not None. status_view's `store` parameter existed and no production
    # caller ever supplied it, so the measured record of WHICH provider ran was unreachable
    # from every operator surface -- which is how a program run entirely by the test double
    # came to present as a plain PASS.
    db, _runs = _paths(a.home)
    store = Store(db)
    try:
        view = orch.status_view(sstore, store, a.program_id)
        if view["vacuous"]:
            _emit({"error": "NO_SUCH_PROGRAM", "program_id": a.program_id})
            return 2
        if a.json:
            # The handoff-reliability rate travels with the status, not behind it: PRD.md §28.2
            # classifies handoff strength and §67.8 scores it from evidence. Baseline measured
            # 2026-08-24: 24/32 valid, 8 prose-invalid -- invisible numbers do not move.
            view["outcome_summary"] = read_outcome_summary(a.home, a.program_id)
            _emit(view)
        else:
            sys.stdout.write(_render_status(view) + "\n")
        return 0
    finally:
        store.close()
        sstore.close()


def _render_status(v: dict) -> str:
    lines = ["Program: %s (%s)" % (v.get("title") or v["program_id"], v["status"]),
             "", "%-18s %-24s %-22s %s" % ("Lane", "State", "Verdict", "Actor")]
    lines.append("-" * 84)
    for r in v["lanes"]:
        lines.append("%-18.18s %-24.24s %-22.22s %s"
                     % (r["title"] or r["lane_id"][:18], r["state"], r["verdict"], r["actor"]))
    ib = orch_inbox_count(v)
    agg = v.get("aggregate") or {}
    lines.append("")
    lines.append("Pending decisions/questions : %d" % v.get("inbox_count", 0))
    lines.append("Program verdict             : %s (%s)"
                 % (agg.get("program_verdict"), agg.get("reason", "")))
    reality = v.get("execution_reality") or {}
    if reality.get("refusal"):
        # STATED, not buried in JSON. A user told PASS who then finds an unchanged
        # repository has been misled by their own tools.
        lines.append("")
        lines.append("!! %s" % reality["refusal"])
        lines.append("   %s" % reality.get("note", ""))
    return "\n".join(lines)


def orch_inbox_count(view: dict) -> int:
    return view.get("inbox_count", 0)


def cmd_program_list(a) -> int:
    rows = _sstore(a)._all(
        "SELECT p.program_id, p.title, p.created_at,"
        " (SELECT v FROM program_meta m WHERE m.program_id=p.program_id AND k='status') AS status"
        " FROM program p ORDER BY p.created_at")
    _emit({"programs": rows})
    return 0


def cmd_program_inbox(a) -> int:
    from quaestor.core import orchestrator as orch
    sstore = _sstore(a)
    try:
        ib = orch.inbox(sstore, a.program_id)
        if ib["vacuous"]:
            _emit({"error": "NO_SUCH_PROGRAM", "program_id": a.program_id})
            return 2
        _emit(ib)
        return 0
    finally:
        sstore.close()


def cmd_program_answer(a) -> int:
    from quaestor.core import decisions as dec_mod
    from quaestor.core import orchestrator as orch
    authority = dec_mod.BY_OWNER if a.authority == "OWNER" else dec_mod.BY_STRATEGIST
    sstore = _sstore(a)
    try:
        directive = orch.answer(sstore, a.program_id, a.message_id, decision_text=a.text,
                                rationale=a.rationale, authority=authority,
                                actor_id=a.actor or "cli")
        _emit({"directive_id": directive, "answered": a.message_id,
               "authority": authority,
               "note": "the lane resumes from its checkpoint on the next tick"})
        return 0
    except ValueError as exc:
        _emit({"error": "ANSWER_REFUSED", "detail": str(exc)})
        return 2
    finally:
        sstore.close()


def cmd_program_cancel(a) -> int:
    from quaestor.core import orchestrator as orch
    sstore = _sstore(a)
    try:
        out = orch.cancel_program(sstore, a.program_id, reason=a.reason, actor_id="cli")
        _emit({"cancelled": True, **out})
        return 0
    finally:
        sstore.close()


def _pending_proposal_payload(sstore, program_id):
    """The pending proposal doc + its planner provenance, or None. Impure."""
    import quaestor.core.planner as planner_mod
    doc = planner_mod.pending_proposal(sstore, program_id)
    if doc is None:
        return None
    return {"doc": doc, "proposal": doc.get("proposal") or {},
            "planner_provenance": doc.get("planner_provenance") or {}}


def cmd_program_adopt(a) -> int:
    """ADOPT a pending PLAN_PROPOSAL -- the strategist/owner action, never automatic.

    PRD.md §7.4: the planner proposes; this command disposes. The named actor travels into the
    DECISION record, and an actor that IS the planner seat is refused by name.
    """
    from quaestor.core import orchestrator as orch
    import quaestor.core.planner as planner_mod
    sstore = _sstore(a)
    try:
        held = _pending_proposal_payload(sstore, a.program_id)
        if held is None:
            _emit({"error": planner_mod.PROPOSAL_NOT_PENDING,
                   "detail": "no PENDING proposal for this program"})
            return 2
        out = planner_mod.adopt_plan_proposal(
            sstore, a.program_id, held["proposal"], held["planner_provenance"],
            adopted_by_actor=a.actor or "cli")
        if not out.get("ok"):
            _emit({"error": out.get("refusal"), "detail": out.get("detail")})
            return 2
        ib = orch.inbox(sstore, a.program_id)
        _emit({"adopted": True, **{k: out[k] for k in ("lane_ids", "decision_id")},
               "inbox_items": len(ib["items"])})
        return 0
    finally:
        sstore.close()


def cmd_program_resolve_finding(a) -> int:
    """Resolve one plan-challenge finding (strategist action), un-blocking adoption."""
    import quaestor.core.planner as planner_mod
    sstore = _sstore(a)
    try:
        out = planner_mod.resolve_proposal_finding(
            sstore, a.program_id, a.finding_id, rationale=a.rationale,
            actor_id=a.actor or "cli")
        if not out.get("ok"):
            _emit({"error": out.get("refusal"), "detail": out.get("detail")})
            return 2
        _emit({"resolved": a.finding_id, "decision_id": out.get("decision_id")})
        return 0
    finally:
        sstore.close()


def coreservice_defaults() -> tuple:
    """(idle_s,) read from the service module so help text cannot drift from behaviour."""
    from quaestor.transports import coreservice
    return (coreservice.DEFAULT_IDLE_S,)


def coreservice_default_idle() -> float:
    """The shipped idle default, read from Core rather than repeated as a literal here."""
    from quaestor.transports import coreservice
    return float(coreservice.DEFAULT_IDLE_S)


def cmd_serve(a) -> int:
    """Core: the authenticated local boundary around the proven runtime.

    Foreground by default -- a service you can watch is the one you can debug. ``--detach``
    starts it independent of this terminal, which is what a UI client needs: PRD section 3
    requires that Core's lifetime not depend on Chrome, an editor, or any other client staying
    open, and a child that dies with its parent cannot satisfy that.
    """
    from quaestor.transports import coreservice
    home = getattr(a, "home", None) or DEFAULT_HOME
    if getattr(a, "detach", False):
        out, code = _detach_core(home, port=int(a.port), idle_s=float(a.idle))
        _emit(out)
        return code
    return coreservice.serve(home, port=int(a.port), idle_s=float(a.idle))


def _detach_core(home: str, *, port: int, idle_s: float) -> tuple:
    """Start a Core independent of this terminal. ``(body, exit_code)``. Impure.

    ONE detachment site, used by ``serve --detach`` and by ``core ensure``. The two had to
    agree on what "it started" means, and two copies of that answer would not stay in
    agreement.
    """
    import subprocess
    from quaestor.transports import coreservice
    argv = [proc.python_executable(), "-m", "quaestor.transports.cli", "--home", home,
            "serve", "--port", str(int(port)), "--idle", str(float(idle_s))]
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 shell=False, **proc.spawn_detached_kwargs())
    except OSError as exc:
        return {"started": False, "error": "CORE_SPAWN_FAILED",
                "detail": "%s: %s" % (type(exc).__name__, exc)}, 2
    # WAIT FOR THIS CHILD'S OWN ENDPOINT RECORD. Waiting for "a running Core" reported
    # success when an EARLIER Core was already up and the child had exited immediately --
    # the caller was told it started something it did not. The record carries the pid, so
    # the check is exact.
    deadline = time.time() + 20.0
    while time.time() < deadline:
        state = coreservice.running(home)
        endpoint = state.get("endpoint") or {}
        if state.get("running") and int(endpoint.get("pid") or 0) == int(child.pid):
            return {"started": True, "detached": True, "pid": child.pid, **endpoint}, 0
        if child.poll() is not None:
            # The child is gone. Say which Core is actually live, if any, rather than
            # reporting a success that belongs to somebody else.
            return {"started": False, "error": "CORE_ALREADY_RUNNING"
                    if state.get("running") else "CORE_EXITED",
                    "child_exit_code": child.returncode,
                    "endpoint": endpoint}, (3 if state.get("running") else 2)
        time.sleep(0.2)
    return {"started": False, "error": "CORE_DID_NOT_REPORT",
            "detail": "the detached process did not publish an endpoint within 20s",
            "pid": child.pid}, 2


def cmd_core_ensure(a) -> int:
    """Make sure Core is running, and say where it is. IDEMPOTENT -- this is the on-demand start.

    What a client actually needs before it can ask for anything: not "start a Core", which
    fails when one is already up, but "there is a Core and here is its endpoint". A UI, an
    editor plugin or a relay wrapper calls this and gets one answer whether it started
    something or found something.

    LIVENESS IS MEASURED, never read: ``running`` takes the lock rather than believing the
    endpoint file, so a Core killed with its file left behind is started again instead of being
    handed to the caller as though it were alive.
    """
    from quaestor.transports import coreservice
    home = getattr(a, "home", None) or DEFAULT_HOME
    state = coreservice.running(home)
    if state.get("running"):
        _emit({"running": True, "started": False, "reused": True,
               **(state.get("endpoint") or {})})
        return 0
    if state.get("running") is None:
        # UNREADABLE IS NOT ABSENT. ``running`` returns None for a lock it could not open and
        # says why in as many words: so that a caller does not start a SECOND Core on the
        # strength of an unreadable file. Treating None as falsy did exactly that.
        _emit({"running": None, "started": False, "reused": False,
               "error": "CORE_LIVENESS_UNKNOWN", "lock": state.get("lock"),
               "detail": "the lock could not be read, so whether a Core is running is unknown; "
                         "starting one anyway is how a home ends up with two",
               "endpoint": state.get("endpoint")})
        return 4
    out, code = _detach_core(home, port=int(a.port), idle_s=float(a.idle))
    if out.get("error") == "CORE_ALREADY_RUNNING":
        # SOMEBODY ELSE WON THE RACE, which is the very race an on-demand start exists to
        # absorb. The answer is the live Core, not a report that this attempt lost.
        live = coreservice.running(home)
        if live.get("running"):
            _emit({"running": True, "started": False, "reused": True,
                   **(live.get("endpoint") or {})})
            return 0
    _emit({"running": bool(out.get("started")), "reused": False, **out})
    return code


def cmd_relay_profile(a) -> int:
    """Register a relay shape Core may start. An OPERATOR act, like authorising a project.

    A client names a profile; it never describes one. Every endpoint, model, credential source,
    verification command and limit comes from what was registered here, so nothing a client
    sends reaches the command line.
    """
    from quaestor.core import corerelay
    home = getattr(a, "home", None) or DEFAULT_HOME
    fields = {}
    for key in corerelay.PROFILE_FIELDS:
        val = getattr(a, key, None)
        if val not in (None, ""):
            fields[key] = val
    for key in corerelay.PROFILE_FLAG_FIELDS:
        if getattr(a, key, False):
            fields[key] = True
    if getattr(a, "verify", None):
        fields["verify"] = list(a.verify)
    out = corerelay.register_profile(home, name=a.name, project_id=a.project, fields=fields)
    _emit(out)
    return 0 if out.get("ok") else 1


def cmd_relay_profiles(a) -> int:
    from quaestor.core import corerelay
    home = getattr(a, "home", None) or DEFAULT_HOME
    _emit({"profiles": corerelay.profiles(home, getattr(a, "project", "") or "")})
    return 0


def cmd_core_status(a) -> int:
    """Is Core running, and where? Measured by taking the lock, never by trusting a stale file."""
    from quaestor.transports import coreservice
    home = getattr(a, "home", None) or DEFAULT_HOME
    state = coreservice.running(home)
    obligations = coreservice.has_obligations(home)
    _emit({**state, "obligations": obligations,
           "device": coreservice.coreid.device(home),
           "projects": coreid_mod.projects(home),
           "clients": coreauth_mod.clients(home),
           "operations": list(coreservice.OPERATIONS),
           "protocol_version": coreservice.PROTOCOL_VERSION})
    return 0 if state["running"] else 1


def cmd_project_authorize(a) -> int:
    """AUTHORISING IS AN OPERATOR ACT. No Core client can do this for itself -- that is what
    makes the project boundary mean anything."""
    home = getattr(a, "home", None) or DEFAULT_HOME
    out = coreid_mod.authorize(home, a.path)
    _emit(out)
    return 0 if out.get("ok") else 1


def cmd_project_list(a) -> int:
    home = getattr(a, "home", None) or DEFAULT_HOME
    _emit({"projects": coreid_mod.projects(home)})
    return 0


def cmd_client_issue(a) -> int:
    """Mint a Core client token, scoped to named projects. The value is printed ONCE."""
    home = getattr(a, "home", None) or DEFAULT_HOME
    known = {str(r.get("project_id")) for r in coreid_mod.projects(home)}
    asked = [p for p in (a.project or ())]
    unknown = [p for p in asked if p not in known]
    if unknown:
        _emit({"issued": False, "error": "PROJECT_NOT_AUTHORIZED", "unknown": unknown,
               "detail": "authorize the project first; a client cannot be scoped to a project "
                         "no operator has authorised"})
        return 1
    _emit(coreauth_mod.issue(home, name=a.name, project_ids=asked))
    return 0


def cmd_client_revoke(a) -> int:
    home = getattr(a, "home", None) or DEFAULT_HOME
    out = coreauth_mod.revoke(home, a.client_id)
    _emit(out)
    return 0 if out.get("ok") else 1


def cmd_web(a) -> int:
    """The loopback-only local dashboard: GET reads plus POST writes mapped 1:1 onto the SAME
    governed operations this CLI invokes. It never grants authority (PRD.md §13.1, §13.3 -- the
    Local Core Console, not the primary organization-wide product UI).

    The token VALUE is never printed -- startup emits the url and the token-file PATH only, so
    the secret reaches exactly one place: the file on disk, mode 0o600.
    """
    from quaestor.transports import webui
    # This subparser carries its own --home (default None), which would shadow the global one;
    # fall back to DEFAULT_HOME here, same as cmd_tunnel does.
    return webui.serve(getattr(a, "home", None) or DEFAULT_HOME, port=a.port,
                       token_file=getattr(a, "token_file", None),
                       open_browser=bool(getattr(a, "open", False)))


def cmd_tunnel(a) -> int:
    """The Plus-tier bridge: expose the loopback MCP server past the machine's edge, READ-ONLY.

    ``serve`` provisions the remote token (once), starts the loopback server, launches a quick
    tunnel, and prints the connector setup ONCE. ``doctor`` measures a deployed URL from
    outside. ``token``/``revoke`` manage the remote secret without touching the loopback token.
    """
    from quaestor.transports import tunnel
    from quaestor.transports.mcp import auth as transport_auth

    if a.tcmd == "token":
        out = transport_auth.provision(a.secret_dir, remote=True)
        _emit({"token_id": out["token_id"], "created_at": out["created_at"],
               "value_returned_once": out["value_returned_once"],
               "note": "this value is shown ONCE. It authenticates the READ-ONLY remote "
                       "channel only."})
        return 0

    if a.tcmd == "revoke":
        _emit(transport_auth.delete(a.secret_dir, remote=True))
        return 0

    if a.tcmd == "doctor":
        out = tunnel.doctor(a.url, token=a.token or "")
        _emit(out)
        return 0 if out.get("ok") else 1

    # ---- serve -------------------------------------------------------------------------------
    repo_table = {}
    for item in (a.repo or []):
        if "=" not in item:
            _emit({"error": "invalid --repo", "detail": "expected alias=path, got %r" % item})
            return 2
        alias, path = item.split("=", 1)
        repo_table[alias.strip()] = path.strip()
    if not repo_table:
        _emit({"error": "no repositories",
               "detail": ("pass at least one --repo alias=path. A remote caller can only see "
                          "what an alias exposes; it can never name a path.")})
        return 2
    # The subparser's --home default (None) would shadow the global one; fall back here.
    return tunnel.serve(a.home or DEFAULT_HOME, repo_table=repo_table, port=a.port,
                        cloudflared=a.cloudflared, auth_dir=a.secret_dir,
                        forbidden_alias_roots=tuple(a.forbidden_root or ()))


def read_outcome_summary(home: str, program_id: str | None = None) -> dict:
    """The per-run outcome counters behind `doctor` and `program status --json`.

    WHY A HELPER: both surfaces must measure identically (one definition of "native rate" or
    the comparison between them is decorative), and neither should hold an orchestrator Store
    open just to ask. Read-only; never raises -- see Store.outcome_summary for the counting
    rules and the 24/32 baseline this instrument exists to move.
    """
    db, _ = _paths(home)
    store = Store(db)
    try:
        return store.outcome_summary(program_id)
    finally:
        store.close()


def cmd_doctor(a) -> int:
    db, runs = _paths(a.home)
    store = Store(db)
    try:
        from quaestor.transports.mcp import mode as transport_mode
        from quaestor.core import owner_channel as oc
        from quaestor import attestation
        from quaestor.secrets import store as secret_store
        # Lazy like the rest: `doctor` reports on the adapter registry without making the whole
        # CLI depend on it (§5.1 -- adapters are optional participation, not a load-bearing dep).
        from quaestor.adapters import registry_summary
        from quaestor.adapters import sweep as sweep_mod
        pf = preflight_mod.run_preflight(claude_path=a.claude_path)
        active = store.runs_in_states(domain.ACTIVE_STATES)
        resolved_mode, mode_record = transport_mode.resolve_mode(a.home)
        cred = secret_store.status(None, deep=False)
        _emit({
            "home": a.home, "db": db, "runs": runs,
            "schema_version": store._one("SELECT v FROM schema_meta WHERE k='version'"),
            "active_runs": len(active),
            "handoff_health": store.outcome_summary(),
            "transport_execution_mode": resolved_mode,
            "mode_record": mode_record,
            "owner_channel": oc.owner_channel_state(),
            "owner_attestation": attestation.status(),
            "executor_credential": {"state": cred.state, "provider": cred.provider},
            "preflight": {"decision": pf.decision, "reason": pf.reason,
                          "auth_class": pf.auth_class,
                          "claude_version": (pf.record or {}).get("claude_version")},
            "profiles": {p: sorted(c) for p, c in authority_mod.PROFILES.items()},
            "operational_profiles": sorted(transport_mode.OPERATIONAL_AUTHORITY_PROFILES),
            "owner_gated": sorted(authority_mod.OWNER_GATED),
            # LIVE MEANS LIVE. This filtered on revocation only, so once expiry became
            # load-bearing at the gate the status surface disagreed with the decision it was
            # describing -- reporting a lapsed capability as usable.
            "live_owner_grants": [g["capability"] for g in store.owner_grants()
                                  if _oc.is_live(g, time.time())],
            # REPORTED, NOT SILENTLY ABSENT. A capability that lapsed is exactly what an
            # operator is looking for when they ask why a relay will not continue.
            "expired_owner_grants": [g["capability"] for g in store.owner_grants()
                                     if g.get("revoked_at") is None
                                     and not _oc.is_live(g, time.time())],
            # §5.3: the assurance surface starts by showing WHICH adapters exist at all. An
            # empty registry renders as [] -- visible absence, not a missing key.
            "adapters": registry_summary(),
            # MEASURED, NOT DECLARED (bd quaestor-ru1.18): the sweep runs the conformance
            # probes NOW, records the computed levels durably (adapter.assurance events), and
            # reports them beside the declarations above -- which stay declarations on purpose.
            # The contrast is the honesty: a reader can see claimed vs computed per transport.
            "assurance": sweep_mod.run_assurance_sweep(store),
        })
        return 0
    finally:
        store.close()


def read_assurance_summary(home: str) -> list:
    """The latest durably RECORDED assurance per adapter -- the Settings view's source.

    Reads the ``adapter.assurance`` events ``cmd_doctor``'s sweep (or any other runner of
    ``record_assurance``) wrote, and keeps the newest row per adapter. What comes back is the
    COMPUTED level with its claim and refusals -- a measurement from the durable record, never
    a live re-declaration, so this view cannot disagree with what was measured and stored.
    """
    from quaestor.core import owner_channel as _oc
    import json
    from quaestor.adapters.record import EVENT_KIND
    db, _runs = _paths(home)
    store = Store(db)
    try:
        rows = store._all("SELECT * FROM event WHERE kind=? ORDER BY seq", (EVENT_KIND,))
    finally:
        store.close()
    latest: dict = {}
    for row in rows:
        latest[str(row["dispatch_key"] or "")] = row
    out: list = []
    for key, row in sorted(latest.items()):
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except ValueError:
            continue  # a torn record is skipped loudly-by-absence, never reinterpreted
        # The record's dispatch_key is "adapter/<kind>" (record_assurance's lane id form); the
        # Settings view names the adapter kind itself, matching the registry rows beside it.
        name = str(detail.get("lane_or_adapter") or key)
        if name.startswith("adapter/"):
            name = name[len("adapter/"):]
        out.append({"adapter": name,
                    "claimed_level": detail.get("claimed_level"),
                    "computed_level": detail.get("computed_level"),
                    "computed_within_claimed": detail.get("computed_within_claimed"),
                    "refusals": list(detail.get("refusals") or []),
                    "recorded_at": row["at"], "seq": row["seq"]})
    return out


def cmd_credential(a) -> int:
    """Owner credential broker. The SECRET is only ever read from a hidden terminal prompt."""
    import getpass
    from quaestor import dpapi
    from quaestor.secrets import store as secret_store
    from quaestor.secrets import validate as credential_validate

    if a.action == "status":
        st = secret_store.status(a.secret_dir, deep=a.deep)
        _emit(st.to_dict())
        return 0 if st.usable else 1

    if a.action == "delete":
        _emit(secret_store.delete(a.secret_dir))
        return 0

    if a.action == "validate":
        out = credential_validate.validate(image_ref=a.image, network=a.network,
                                           directory=a.secret_dir)
        _emit(out)
        return 0 if out.get("verdict") == credential_validate.PASS else 1

    # ---- provision ---------------------------------------------------------------------------
    # ORDER MATTERS, AND THE TTY CHECK IS FIRST. The stdin check is about the REQUEST -- a piped
    # secret came from a file, a script, a shell history, a CI log. The DPAPI check is about the
    # HOST. Refusing for the host reason first would mean that on a host without a usable
    # credential store a piped secret is refused with the wrong name -- and that a host which
    # later GAINS a store would silently convert the piped secret into a stored one. The input
    # gate is the one that must never degrade.
    if not sys.stdin.isatty():
        # A PIPED secret is a secret that came from somewhere -- a file, a script, a shell
        # history, a CI log. The owner path is an interactive terminal, and there is deliberately
        # no flag to bypass this: the bypass would become the way it is normally used.
        _emit({"error": "refusing: the credential must be typed/pasted into an interactive "
                        "terminal. stdin is not a TTY, so this would be a piped secret.",
               "hint": "run this command directly in a terminal window"})
        return 2
    if not dpapi.available():
        _emit({"error": "DPAPI is not usable on this host; refusing to persist a credential"})
        return 2

    sys.stderr.write(
        "\n%s credential broker -- provisioning %s\n"
        "  Paste the token from `claude setup-token` and press Enter.\n"
        "  Input is HIDDEN. It is never echoed, never logged, and never passed as an argument.\n"
        % (branding.PRODUCT_TITLE, secret_store.PROVIDER_CLAUDE_OAUTH))
    typed = getpass.getpass("  token: ")
    buf = bytearray(typed.encode("utf-8"))
    del typed
    try:
        if not buf.strip():
            _emit({"error": "empty input; nothing was written"})
            return 2
        st = secret_store.provision(buf, directory=a.secret_dir)
    finally:
        secret_store.wipe_secret(buf)

    _emit({"provider": st.provider or secret_store.PROVIDER_CLAUDE_OAUTH,
           "protection": st.protection or secret_store.PROTECTION_DPAPI_USER,
           "persisted": st.state in (secret_store.PRESENT, secret_store.VALIDATED),
           "validation": "pending",
           "credential_id": st.credential_id, "path": st.path,
           "acl_restricted": st.acl_restricted, "rotated": st.detail.get("rotated"),
           "state": st.state, "reason": st.reason})
    return 0 if st.usable else 1


def _subparser_action(parser: argparse.ArgumentParser):
    """The sub-command action of a parser, or None. PURE.

    argparse exposes no public way to ask a parser what sub-commands it accepts, so this reads
    ``_actions`` -- deliberately in ONE place. Identified by SHAPE (a choices mapping whose values
    are parsers) rather than by the private class name, so it survives an argparse internal
    rename; and the alternative -- a hand-maintained list of verbs beside ``build_parser`` -- is
    what this exists to avoid, because that list drifts silently the first time a verb is renamed.
    """
    for action in getattr(parser, "_actions", ()):
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and choices and all(
                isinstance(v, argparse.ArgumentParser) for v in choices.values()):
            return action
    return None


def command_verbs(group: str = "") -> tuple:
    """The verbs this CLI actually parses, DERIVED from ``build_parser``. PURE-ish (builds one).

    ``group=""`` yields the top-level commands; ``group="program"`` yields that command's own
    sub-verbs. Callers that print a command line for a human (the relay briefing does) use this
    to check the verb they are about to name still exists, instead of shipping a paste-ready
    command that stopped working two refactors ago.
    """
    action = _subparser_action(build_parser())
    if action is None:
        return ()
    if not group:
        return tuple(sorted(action.choices))
    sub = action.choices.get(group)
    if sub is None:
        return ()
    inner = _subparser_action(sub)
    return tuple(sorted(inner.choices)) if inner is not None else ()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m quaestor.transports.cli",
                                 description=branding.PRODUCT_TITLE + " -- " + branding.PRODUCT_TAGLINE)
    ap.add_argument("--home", default=DEFAULT_HOME)
    ap.add_argument("--claude-path", default=os.environ.get(branding.env_var("claude", "path"), "claude"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("preflight", help="auth/credential preflight only")
    p.add_argument("--write", action="store_true")
    p.set_defaults(fn=cmd_preflight)

    p = sub.add_parser("dispatch", help="admit and launch one step")
    p.add_argument("--workflow", required=True)
    p.add_argument("--step", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--worktree", required=True)
    p.add_argument("--profile", default=authority_mod.READ_ONLY,
                   choices=sorted(authority_mod.PROFILES))
    p.add_argument("--executor", default="fake", choices=("fake", "claude-cli"))
    p.add_argument("--fake-config", default="{}")
    p.add_argument("--model", default="")
    p.add_argument("--timeout", type=float, default=1800.0)
    p.add_argument("--min-inspected", type=int, default=1)
    p.add_argument("--title", default="")
    p.add_argument("--no-spawn", action="store_true")
    p.set_defaults(fn=cmd_dispatch)

    p = sub.add_parser("status", help="one run's state and evidence")
    p.add_argument("run_id", nargs="?", default="")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("result", help="record a finished run's result")
    p.add_argument("run_id")
    p.add_argument("--deliver", action="store_true")
    p.set_defaults(fn=cmd_result)

    p = sub.add_parser("reconcile", help="re-derive run state after a crash or restart")
    p.add_argument("run_id", nargs="?", default="")
    p.add_argument("--all", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_reconcile)

    p = sub.add_parser("grant", help="record an OWNER capability grant")
    p.add_argument("capability")
    p.add_argument("--scope", default="*")
    p.add_argument("--expires", type=float, default=None)
    p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_grant)

    p = sub.add_parser("events", help="the durable event log for one run")
    p.add_argument("run_id")
    p.set_defaults(fn=cmd_events)

    p = sub.add_parser("doctor", help="measure this deployment: db, adapters, credentials")
    p.set_defaults(fn=cmd_doctor)

    # ---- owner credential broker -------------------------------------------------------------
    # NOTE THE ABSENCE: there is no --token option, and there must never be one. A secret on a
    # command line is visible in the process table and in shell history. The only input path is
    # the hidden terminal prompt inside cmd_credential; `tests/test_p45_controls` asserts that no
    # option of this parser can carry a secret.
    #
    # allow_abbrev=False IS A SECURITY SETTING HERE, not tidiness. argparse resolves any
    # unambiguous prefix, so with abbreviation ON `--secret <TOKEN>` silently binds to
    # `--secret-dir` -- putting the token in the process table AND turning it into a directory
    # name on disk. Measured: the P4.5 control found exactly that. Off, it is an error.
    p = sub.add_parser("credential", allow_abbrev=False,
                       help="owner credential broker (provision/validate/status)")
    p.add_argument("action", choices=("provision", "validate", "status", "delete"))
    p.add_argument("--secret-dir", default=None,
                   help="override the credential store directory (testing)")
    p.add_argument("--image", default=branding.resource("executor") + ":latest")
    p.add_argument("--network", default="bridge")
    p.add_argument("--deep", action="store_true", help="status: also attempt a decrypt")
    p.set_defaults(fn=cmd_credential)

    # ---- deployment mode ----------------------------------------------------------------------
    p = sub.add_parser("mode", help="show or set the transport execution mode (local only)")
    p.add_argument("action", choices=("show", "set"))
    p.add_argument("value", nargs="?", default="", choices=("", "QUALIFICATION_ONLY",
                                                            "LOCAL_GOVERNED"))
    p.set_defaults(fn=cmd_mode)

    # ---- owner channel ------------------------------------------------------------------------
    p = sub.add_parser("owner", allow_abbrev=False,
                       help="owner-authority channel (init/status/delete)")
    p.add_argument("action", choices=("init", "status", "delete"))
    p.add_argument("--secret-dir", default=None, help="override directory (testing)")
    p.set_defaults(fn=cmd_owner)

    # ---- the ChatGPT tunnel --------------------------------------------------------------------
    p = sub.add_parser("tunnel", allow_abbrev=False,
                       help="expose the loopback MCP server read-only for ChatGPT (Plus OK)")
    psub = p.add_subparsers(dest="tcmd", required=True)

    pt = psub.add_parser("serve", help="run the loopback server behind a quick tunnel")
    pt.add_argument("--port", type=int, default=0, help="loopback port; 0 = pick one")
    pt.add_argument("--repo", action="append", default=[],
                    help="repo alias=path to expose (repeatable)")
    pt.add_argument("--cloudflared", default="cloudflared",
                    help="path to the cloudflared binary (any HTTPS tunnel works)")
    pt.add_argument("--secret-dir", default=None,
                    help="override the transport-token directory (testing)")
    pt.add_argument("--forbidden-root", action="append", default=[],
                    help="a root no alias may resolve into (repeatable)")
    pt.set_defaults(fn=cmd_tunnel)

    pt = psub.add_parser("doctor", help="measure a deployed tunnel URL from outside")
    pt.add_argument("--url", required=True)
    pt.add_argument("--token", default="",
                    help="the remote token; without it only unauthenticated checks run")
    pt.set_defaults(fn=cmd_tunnel)

    pt = psub.add_parser("token", help="provision/rotate the READ-ONLY remote token (shown once)")
    pt.add_argument("--secret-dir", default=None, help="override directory (testing)")
    pt.set_defaults(fn=cmd_tunnel)

    pt = psub.add_parser("revoke", help="delete the remote token; tunnel access stops at once")
    pt.add_argument("--secret-dir", default=None, help="override directory (testing)")
    pt.set_defaults(fn=cmd_tunnel)

    # ---- the local web dashboard ---------------------------------------------------------------
    # allow_abbrev=False IS A SECURITY SETTING HERE (see `credential` above): this surface is
    # bearer-gated, and a mistyped prefix must be an ERROR, never a silent bind to another
    # option. The host is deliberately NOT an option -- the server binds loopback only, by
    # construction (transports.webui.LOOPBACK_HOST).
    p = sub.add_parser("serve", allow_abbrev=False,
                       help="run Quaestor Core: the authenticated local service boundary")
    p.add_argument("--home", default=argparse.SUPPRESS,
                   help="deployment home (default: the global --home)")
    p.add_argument("--port", type=int, default=0,
                   help="loopback port; 0 = pick a free one and report it")
    p.add_argument("--idle", type=float, default=coreservice_defaults()[0],
                   help="seconds of quiet before Core shuts itself down; 0 = stay up. Core "
                        "never shuts down while a relay is live or an owner hold stands")
    p.add_argument("--detach", action="store_true",
                   help="start Core independent of this terminal and report its endpoint")
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("core", allow_abbrev=False,
                       help="inspect and administer Quaestor Core")
    csub = p.add_subparsers(dest="core_cmd", required=True)

    q = csub.add_parser("status", help="is Core running, where, and what does it owe?")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_core_status)

    q = csub.add_parser("ensure", help="make sure Core is running and print its endpoint")
    q.add_argument("--port", type=int, default=0)
    q.add_argument("--idle", type=float, default=coreservice_default_idle(),
                   help="seconds of quiet before an UNOBLIGATED Core shuts itself down")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_core_ensure)

    q = csub.add_parser("authorize", help="authorise a project Core clients may reach")
    q.add_argument("path", help="path to a git working tree")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_project_authorize)

    q = csub.add_parser("projects", help="list authorised projects")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_project_list)

    q = csub.add_parser("relay-profile", help="register a relay shape Core may start")
    q.add_argument("--name", required=True)
    q.add_argument("--project", required=True, metavar="PROJECT_ID")
    q.add_argument("--orchestrator")
    q.add_argument("--orchestrator-model", dest="orchestrator_model")
    q.add_argument("--orchestrator-base-url", dest="orchestrator_base_url")
    q.add_argument("--orchestrator-key-var", dest="orchestrator_key_var")
    q.add_argument("--orchestrator-key-file", dest="orchestrator_key_file")
    q.add_argument("--orchestrator-key-field", dest="orchestrator_key_field")
    q.add_argument("--browser-endpoint", dest="browser_endpoint")
    q.add_argument("--browser-transport", dest="browser_transport")
    q.add_argument("--conversation-id", dest="conversation_id")
    q.add_argument("--agent")
    q.add_argument("--agent-base-url", dest="agent_base_url")
    q.add_argument("--agent-model", dest="agent_model")
    q.add_argument("--session-id", dest="session_id")
    q.add_argument("--profile", help="authority profile the relay runs under")
    q.add_argument("--max-exchanges", dest="max_exchanges")
    q.add_argument("--max-duration", dest="max_duration")
    q.add_argument("--receive-timeout", dest="receive_timeout")
    q.add_argument("--verify", action="append", default=[],
                   help="an OPERATOR-supplied verification command (repeatable)")
    q.add_argument("--verify-timeout", dest="verify_timeout")
    q.add_argument("--completion-attempts", dest="completion_attempts")
    q.add_argument("--incomplete-retries", dest="incomplete_retries")
    q.add_argument("--require-repo-change", dest="require_repo_change", action="store_true")
    q.add_argument("--no-probe", dest="no_probe", action="store_true")
    q.add_argument("--no-observe", dest="no_observe", action="store_true")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_relay_profile)

    q = csub.add_parser("relay-profiles", help="list registered relay shapes")
    q.add_argument("--project", default="", metavar="PROJECT_ID")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_relay_profiles)

    q = csub.add_parser("client", help="mint a Core client token scoped to named projects")
    q.add_argument("--name", required=True, help="what this client is, for the operator")
    q.add_argument("--project", action="append", default=[], metavar="PROJECT_ID",
                   help="a project this client may reach (repeatable). No wildcard exists")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_client_issue)

    q = csub.add_parser("revoke", help="revoke a Core client")
    q.add_argument("client_id")
    q.add_argument("--home", default=argparse.SUPPRESS)
    q.set_defaults(fn=cmd_client_revoke)

    p = sub.add_parser("web", allow_abbrev=False,
                        help="loopback-only local dashboard (reads + governed writes)")
    # default=SUPPRESS, not None: a subparser default SHADOWS the global --home in the parsed
    # namespace, so `--home <h> web` (global-before-subcommand form, the documented pattern every
    # other command uses) silently lost the deployment home and the dashboard stared at
    # DEFAULT_HOME instead. SUPPRESS keeps the global value when the local flag is absent.
    p.add_argument("--home", default=argparse.SUPPRESS,
                   help="deployment home (default: the global --home)")
    p.add_argument("--port", type=int, default=0,
                   help="loopback port; 0 = pick a free one and report it")
    p.add_argument("--token-file", default=None,
                   help="where the bearer token lives (default: <home>/web-ui-token)")
    p.add_argument("--open", action="store_true",
                   help="open the one-step URL in your browser once the server is up")
    p.set_defaults(fn=cmd_web)

    # ---- project init -------------------------------------------------------------------------
    p = sub.add_parser("init", help="write a conservative starter manifest for this repository")
    p.add_argument("--path", default=".")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_project_init)

    # ---- zero-config connect (PRD.md §47.1) -----------------------------------------------------
    p = sub.add_parser("connect", help="detect repo/agents/tests without a manifest (JSON)")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--write-manifest", action="store_true",
                   help="also write init's conservative starter manifest (off by default)")
    p.set_defaults(fn=cmd_connect)

    # ---- programs ------------------------------------------------------------------------------
    p = sub.add_parser("program", allow_abbrev=False,
                       help="create and drive multi-lane programs -- START HERE").add_subparsers(dest="pcmd", required=True)

    pp = p.add_parser("create", help="create a program from an objective (then: tick)")
    pp.add_argument("--title", required=True)
    pp.add_argument("--objective", required=True)
    pp.add_argument("--project", default="", help="path to the target repository/manifest")
    pp.add_argument("--constraints", default="", help="'|'-separated immutable constraints")
    pp.add_argument("--acceptance", default="", help="'|'-separated acceptance criteria")
    pp.add_argument("--max-concurrent", type=int, default=2)
    pp.set_defaults(fn=cmd_program_create)

    pp = p.add_parser("plan", help="add a lane to an existing program")
    pp.add_argument("program_id")
    pp.add_argument("--title", required=True)
    pp.add_argument("--task", required=True)
    pp.add_argument("--kind", default="implementation",
                    choices=("research", "implementation", "verification",
                             "adversarial_review", "integration"))
    pp.add_argument("--depends-on", default="")
    pp.add_argument("--acceptance", default="")
    pp.add_argument("--executor", default="", help="server-side scripted spec JSON (testing)")
    pp.set_defaults(fn=cmd_program_plan)

    pp = p.add_parser("tick", help="advance the program one step: schedule, reap, review")
    pp.add_argument("program_id")
    pp.add_argument("--no-spawn", action="store_true")
    pp.set_defaults(fn=cmd_program_tick)

    pp = p.add_parser("serve", help="tick continuously until the program is terminal")
    pp.add_argument("program_id")
    pp.add_argument("--interval", type=float, default=10.0)
    pp.add_argument("--max-seconds", type=float, default=3600.0)
    pp.add_argument("--wait-for-strategist", action="store_true")
    pp.set_defaults(fn=cmd_program_serve)

    pp = p.add_parser("briefing",
                      help="print the relay packet for a program (no dashboard needed)")
    pp.add_argument("program_id")
    pp.add_argument("--message-id", dest="message_id", default="",
                    help="print the narrow packet for ONE open question instead")
    pp.add_argument("--json", action="store_true",
                    help="emit the whole document rather than the pasteable text")
    pp.set_defaults(fn=cmd_program_briefing)

    pp = p.add_parser("status", help="lane states, verdicts, and who actually ran")
    pp.add_argument("program_id")
    pp.add_argument("--json", action="store_true")
    pp.set_defaults(fn=cmd_program_status)

    pp = p.add_parser("list", help="every program in this state home")
    pp.set_defaults(fn=cmd_program_list)

    pp = p.add_parser("inbox", help="decisions and questions awaiting a human")
    pp.add_argument("program_id")
    pp.set_defaults(fn=cmd_program_inbox)

    pp = p.add_parser("answer", help="answer one inbox question and wake its lane")
    pp.add_argument("program_id")
    pp.add_argument("message_id")
    pp.add_argument("--text", required=True)
    pp.add_argument("--rationale", default="")
    pp.add_argument("--authority", default="STRATEGIST", choices=("STRATEGIST", "OWNER"))
    pp.add_argument("--actor", default="")
    pp.set_defaults(fn=cmd_program_answer)

    pp = p.add_parser("cancel", help="stop a program and release its leases")
    pp.add_argument("program_id")
    pp.add_argument("--reason", default="cancelled by operator")
    pp.set_defaults(fn=cmd_program_cancel)

    pp = p.add_parser("adopt",
                      help="adopt a pending PLAN_PROPOSAL (strategist/owner action)")
    pp.add_argument("program_id")
    pp.add_argument("--actor", default="cli")
    pp.set_defaults(fn=cmd_program_adopt)

    pp = p.add_parser("resolve-finding",
                      help="resolve one plan-challenge finding on a pending proposal")
    pp.add_argument("program_id")
    pp.add_argument("--finding-id", required=True)
    pp.add_argument("--rationale", required=True)
    pp.add_argument("--actor", default="cli")
    pp.set_defaults(fn=cmd_program_resolve_finding)

    # RELAY MODE (bd quaestor-pr4). A THIN delegation on purpose: the relay verbs live in
    # ``quaestor.relay.cli`` so a relay command does not pay for -- or become entangled with --
    # Program Mode's store, dispatcher and preflight, which this module imports at load time.
    # The two modes are complementary products, not two views of one state machine.
    from quaestor.relay import cli as relay_cli
    relay_cli.add_arguments(
        sub.add_parser("relay", allow_abbrev=False,
                       help="run a persistent orchestrator <-> execution-agent relay"))
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(list(argv) if argv is not None else sys.argv[1:])
    # A subparser that defines its own --home (e.g. `web`) shadows the global default with None;
    # every consumer falls back to DEFAULT_HOME, so this bootstrap must too.
    home = getattr(a, "home", None) or DEFAULT_HOME
    os.makedirs(home, exist_ok=True)
    runfiles.ensure(os.path.join(home, "runs"))
    return int(a.fn(a))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

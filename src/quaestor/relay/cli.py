"""relay.cli -- the product command surface for Relay Mode.

    <product> relay start   --orchestrator <kind> --agent <kind> --project .
    <product> relay status
    <product> relay doctor
    <product> relay stop
    <product> relay resume

WHY THIS LIVES HERE AND NOT IN ``transports.cli``
--------------------------------------------------
``transports.cli`` is Program Mode's operator surface: dispatch, reconcile, program, grant. It
already imports Program Mode's store, dispatcher and preflight at module scope. Putting the
relay verbs there would make every relay command pay for Program Mode's import graph and would
blur the one separation this work exists to make. ``transports.cli`` gets a thin ``relay``
subparser that delegates here.

THE STATUS SURFACE IS BUILT FROM THE DURABLE RECORD
---------------------------------------------------
``relay status`` runs in a different process from ``relay start``. It therefore reads the ledger
and reports what is written there -- never a live kernel object, never a re-derivation. An
operator must get the same answer whether the relay is running, paused, or was killed an hour
ago, and the architecture is explicit that they should not have to open SQLite to get it.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

from quaestor import branding
from quaestor.relay import kernel as kernel_mod
from quaestor.relay import registry as relay_registry
from quaestor.core import corerelay
from quaestor.relay import state as state_mod
from quaestor.relay.contracts import ROLE_EXECUTION, ROLE_ORCHESTRATOR, computed_assurance

RELAY_CLI_INSTRUMENT = "relay.cli/1"


def relay_paths(home: str) -> tuple:
    """``(database, workdir)``. The relay keeps its own database beside Program Mode's."""
    return (os.path.join(home, "relay.sqlite3"), os.path.join(home, "relay"))


def _emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True, default=str) + "\n")


def _owner_hooks(home: str, scope: str = "*"):
    """The authority inputs, read from the PLATFORM's ledger and owner channel.

    Deliberately the same two sources Program Mode uses. A relay with its own grant table would
    be a second, forgeable authority, and the whole point of ``core.owner_channel`` is that a
    table the orchestrator can write is not an owner.

    ``scope`` IS THE RELAY'S OWN ID, and passing it is what lets an owner grant a capability to
    ONE relay. ``Store.owner_grants`` selects ``scope IN ('*', ?)``, so a grant an owner
    deliberately signed as global still applies -- that is the product's existing model and not
    something to remove here -- while a grant signed for this relay reaches this relay and no
    other. Called with no scope, as it was, a relay could only ever see global grants, so the
    narrow option existed in the schema and was unreachable from Relay Mode.
    """
    from quaestor.core import owner_channel as oc
    from quaestor.core.store import Store

    def grants() -> list:
        db = os.path.join(home, "orchestrator.sqlite3")
        if not os.path.isfile(db):
            return []
        store = Store(db)
        try:
            return list(store.owner_grants(str(scope or "*")))
        finally:
            store.close()

    return grants, (lambda: oc.owner_channel_state(home))


# ---------------------------------------------------------------------------------------------
# ENDPOINT SPECS -- built from flags, recorded verbatim in the relay's config.
# ---------------------------------------------------------------------------------------------
def orchestrator_spec(a) -> dict:
    kind = str(getattr(a, "orchestrator", "") or "")
    cfg: dict = {}
    if kind == "openai-chat":
        cfg = {"base_url": a.orchestrator_base_url, "model": a.orchestrator_model,
               "key_var": a.orchestrator_key_var, "key_file": a.orchestrator_key_file,
               "key_file_field": a.orchestrator_key_field,
               "conversation_id": getattr(a, "conversation_id", "") or "",
               "transcript_path": getattr(a, "_transcript_path", "") or ""}
    elif kind == "chatgpt-web":
        cfg = {"conversation_id": getattr(a, "conversation_id", "") or "",
               "endpoint": getattr(a, "browser_endpoint", "") or "",
               "prefer": getattr(a, "browser_transport", "") or "auto",
               "state_path": getattr(a, "_state_path", "") or ""}
    elif kind == "fake":
        cfg = {"replies": list(getattr(a, "orchestrator_replies", None) or [])}
    return {"kind": kind, "config": cfg}


def execution_spec(a) -> dict:
    kind = str(getattr(a, "agent", "") or "")
    cfg: dict = {}
    if kind == "opencode":
        cfg = {"project_root": a.project, "base_url": a.agent_base_url,
               "session_id": getattr(a, "session_id", "") or "",
               "model": getattr(a, "agent_model", "") or "",
               "agent": getattr(a, "agent_persona", "") or "",
               "attach_latest": bool(getattr(a, "attach_latest", False)),
               "create_if_absent": not bool(getattr(a, "no_create_session", False))}
    elif kind == "fake":
        cfg = {"replies": list(getattr(a, "agent_replies", None) or [])}
    return {"kind": kind, "config": cfg}


# ---------------------------------------------------------------------------------------------
# COMMANDS
# ---------------------------------------------------------------------------------------------
def cmd_relay_doctor(a) -> int:
    """Measure whether a relay could run right now, and say exactly what is missing.

    Every line is MEASURED at call time. A kind this build ships no preflight for reports
    UNVERIFIED rather than inheriting a pass -- an unchecked endpoint must never present as a
    checked one.
    """
    db, work = relay_paths(a.home)
    o_spec, e_spec = orchestrator_spec(a), execution_spec(a)
    report = {
        "home": a.home, "relay_db": db, "relay_workdir": work,
        "buildable": {"orchestrator": list(relay_registry.ORCHESTRATOR_KINDS),
                      "execution": list(relay_registry.EXECUTION_KINDS)},
        "project": os.path.abspath(a.project) if a.project else "",
        "instrument": RELAY_CLI_INSTRUMENT,
    }
    if a.project:
        from quaestor.relay import observe as observe_mod
        snap = observe_mod.snapshot(a.project)
        report["repository"] = {"probe_ok": snap["probe_ok"], "error": snap["probe_error"],
                                "branch": snap["branch"], "head": snap["head"][:12],
                                "dirty": snap["dirty"],
                                "tracked_file_count": snap["tracked_file_count"]}
    if o_spec["kind"]:
        report["orchestrator"] = relay_registry.preflight(ROLE_ORCHESTRATOR, o_spec)
    if e_spec["kind"]:
        report["execution"] = relay_registry.preflight(ROLE_EXECUTION, e_spec)
    # AND THE MODEL, not only the endpoint. Two separate questions, reported separately, so an
    # operator can tell "my credential is fine but the provider is down" from "my key is wrong".
    if not getattr(a, "no_probe", False):
        if o_spec["kind"]:
            report["orchestrator_probe"] = relay_registry.probe(ROLE_ORCHESTRATOR, o_spec)
        if e_spec["kind"]:
            report["execution_probe"] = relay_registry.probe(ROLE_EXECUTION, e_spec)

    from quaestor.core import owner_channel as oc
    grants, channel = _owner_hooks(a.home)
    report["authority"] = {
        "profile": a.profile,
        "owner_channel": channel(),
        "live_owner_grants": [g["capability"] for g in grants()
                              if g.get("revoked_at") is None],
        "note": ("while the owner channel is %s no ledger row can unlock an owner-gated "
                 "capability; run `%s` to provision one"
                 % (oc.UNAVAILABLE, branding.command("owner init"))),
    }
    for spec, role in ((o_spec, "orchestrator"), (e_spec, "execution")):
        if not spec["kind"]:
            continue
        try:
            end = relay_registry.build(ROLE_ORCHESTRATOR if role == "orchestrator"
                                       else ROLE_EXECUTION, spec)
        except Exception as exc:  # noqa: BLE001 - doctor REPORTS failures, never raises them
            report.setdefault("build_errors", {})[role] = "%s: %s" % (type(exc).__name__, exc)
            continue
        report.setdefault("facts", {})[role] = {
            **end.facts.to_dict(), "computed_assurance": computed_assurance(end.facts) or "NONE"}
    # READY MEANS READY, INCLUDING THE MODEL. Reporting ready=true and exit 0 for a
    # configuration ``relay start`` will refuse makes this surface worse than useless: an
    # operator checks doctor precisely to avoid that. A probe that was SKIPPED or DECLINED
    # (measured False) is not a failure and must not block -- only a measured non-ok one does.
    probes_ok = all(bool(p.get("ok")) or not bool(p.get("measured"))
                    for p in (report.get("orchestrator_probe"), report.get("execution_probe"))
                    if isinstance(p, dict))
    ok = bool(report.get("orchestrator", {}).get("ok")
              and report.get("execution", {}).get("ok")
              and report.get("repository", {}).get("probe_ok", True)
              and probes_ok)
    report["ready"] = ok
    # The two answers stay SEPARATE in the report as well as combined, so an operator can read
    # "the server is up and my credential resolves, but the selected model cannot answer".
    report["ready_detail"] = {
        "endpoints_reachable": bool(report.get("orchestrator", {}).get("ok")
                                    and report.get("execution", {}).get("ok")),
        "models_answer": probes_ok,
        "repository_readable": bool(report.get("repository", {}).get("probe_ok", True)),
    }
    _emit(report)
    return 0 if ok else 1


#: Kinds that exist to prove kernel mechanics in controls. They are reachable programmatically
#: -- the test suite and the live harness build them directly -- and REFUSED here, because a
#: relay that reported a completed conversation no model participated in is the worst outcome
#: this surface could produce, and it would look exactly like a successful run.
SCRIPTED_KINDS = ("fake",)


def _refuse_scripted(o_spec: dict, e_spec: dict) -> str:
    named = [role for role, spec in (("orchestrator", o_spec), ("agent", e_spec))
             if spec["kind"] in SCRIPTED_KINDS]
    if not named:
        return ""
    return ("--%s names a scripted endpoint (%s). Scripted endpoints prove kernel mechanics in "
            "the control suite and are refused by the product command: a relay that reported a "
            "finished conversation no model took part in would be indistinguishable from a real "
            "one." % (", --".join(named), ", ".join(SCRIPTED_KINDS)))


def _build_ends(a, home: str, relay_id: str):
    o_spec, e_spec = orchestrator_spec(a), execution_spec(a)
    refusal = _refuse_scripted(o_spec, e_spec)
    if refusal:
        raise ValueError(refusal)
    if o_spec["kind"] == "openai-chat" and not o_spec["config"].get("transcript_path"):
        # WHERE THE CONVERSATION LIVES. A stateless provider means the relay's own transcript IS
        # the conversation, so it must be on disk before the first turn or "resume" would be a
        # word for starting over.
        _db, work = relay_paths(home)
        o_spec["config"]["transcript_path"] = os.path.join(work, relay_id, "conversation.json")
    if o_spec["kind"] == "chatgpt-web" and not o_spec["config"].get("state_path"):
        # NOT a transcript: the conversation lives at the VENDOR and resumes without our help.
        # This sidecar holds only what the relay itself needs to ASK the page a crash-recovery
        # question -- the content key of each delivery -- so ``holds`` can look for that exact
        # turn in the live thread instead of trusting what a dead process believed.
        _db, work = relay_paths(home)
        o_spec["config"]["state_path"] = os.path.join(work, relay_id, "chatgpt-web.json")
    return (relay_registry.build_orchestrator(o_spec),
            relay_registry.build_execution(e_spec), o_spec, e_spec)


#: The endpoint-spec fields a relay's record may carry. REFERENCES ONLY -- the NAME of an
#: environment variable, the PATH of a credential file, the field within it -- and never a
#: resolved secret. An allowlist rather than a denylist, so a spec field added later is not
#: persisted until somebody adds it here and decides it is safe to write down.
RECORDED_SPEC_FIELDS = ("base_url", "model", "key_var", "key_file", "key_file_field",
                        "endpoint", "prefer", "agent", "attach_latest", "create_if_absent")

#: Which recorded field goes back onto which flag, per role.
ORCHESTRATOR_SPEC_ATTRS = {"base_url": "orchestrator_base_url", "model": "orchestrator_model",
                           "key_var": "orchestrator_key_var",
                           "key_file": "orchestrator_key_file",
                           "key_file_field": "orchestrator_key_field",
                           "endpoint": "browser_endpoint", "prefer": "browser_transport"}
EXECUTION_SPEC_ATTRS = {"base_url": "agent_base_url", "model": "agent_model",
                        "agent": "agent_persona"}
#: Recorded booleans, and the flag whose PRESENCE means the opposite. ``--no-create-session``
#: says "attach to a session or fail"; a resume that quietly created one would bind the relay to
#: a brand-new conversation while reporting a successful resume.
EXECUTION_SPEC_FLAGS = {"create_if_absent": ("no_create_session", True),
                        "attach_latest": ("attach_latest", False)}


def recordable_spec(spec) -> dict:
    """The part of an endpoint spec that may be written down. PURE."""
    return {"kind": str((spec or {}).get("kind") or ""),
            "config": {k: v for k, v in dict((spec or {}).get("config") or {}).items()
                       if k in RECORDED_SPEC_FIELDS}}


def record_relay_shape(st, relay_id: str, config, o_spec, e_spec) -> None:
    """Bring the relay's durable record up to date with what it is ACTUALLY running. Impure.

    CALLED ON START AND ON EVERY RESUME, because a record written once at start is a record
    that goes stale the first time an operator strengthens anything. A relay started without
    corroboration and resumed with ``--verify`` ran corroborated for that process and then, on
    the next resume, read back the start-time record and silently went back to believing a
    completion claim on the model's word alone. That is the fourth policy-loss-on-resume defect
    in this file, and it is the one consolidation did not reach: the reader was fixed and the
    writer was still only ever called once.

    Writes down WHERE each end is as well, so a resume does not need the flags again.

    "The specs come from the record, not from flags" was already this module's doctrine, and it
    was only half true: the KIND, the conversation id and the session id came from the record;
    the base URL, the model and the credential source did not. A resume that passed no flags
    therefore rebuilt an end pointing at an argparse default -- which is how a relay Core
    started could never be continued by Core, and how an operator's own flagless
    ``relay resume`` would have quietly moved the agent to port 4096.

    REFERENCES ONLY, by allowlist. ``key_var`` names an environment variable and ``key_file``
    names a file; neither is a secret, and the allowlist is what stops a resolved one being
    added here later by accident.
    """
    row = st.get(relay_id)
    if row is None:
        return
    cfg = json.loads(row.get("config_json") or "{}")
    cfg.update(kernel_mod.persisted_policy(config))
    cfg["endpoint_specs"] = {"orchestrator": recordable_spec(o_spec),
                             "execution": recordable_spec(e_spec)}
    st.update(relay_id, config_json=json.dumps(cfg, sort_keys=True, default=str))


def apply_recorded_endpoints(a, saved) -> None:
    """Point a resumed relay's ends back where they were. Impure (mutates a).

    Fills only what this invocation did NOT supply: an operator whose agent server moved to a
    different port must still be able to say so, and Core -- which deliberately supplies
    nothing on a resume -- gets exactly the relay that was recorded. Returns the list of
    OVERRIDES, so a flag that re-points an end is written to the event log rather than applied
    invisibly.
    """
    specs = dict((saved or {}).get("endpoint_specs") or {})
    changed = []
    for role, attrs in (("orchestrator", ORCHESTRATOR_SPEC_ATTRS),
                        ("execution", EXECUTION_SPEC_ATTRS)):
        cfg = dict((specs.get(role) or {}).get("config") or {})
        for key, attr in attrs.items():
            if not cfg.get(key):
                continue
            current = getattr(a, attr, None)
            if not current:
                setattr(a, attr, cfg[key])
            elif str(current) != str(cfg[key]):
                # AN OVERRIDE IS RECORDED, never silent. Moving an agent server to a new port is
                # legitimate; swapping the orchestrator's model changes the VENDOR the relay is
                # talking to mid-conversation, and an operator reading the relay later must be
                # able to see that it happened.
                changed.append({"role": role, "field": key,
                                "recorded": str(cfg[key]), "used": str(current)})
    exe = dict((specs.get("execution") or {}).get("config") or {})
    for key, (attr, inverted) in EXECUTION_SPEC_FLAGS.items():
        if key in exe:
            setattr(a, attr, (not bool(exe[key])) if inverted else bool(exe[key]))
    return changed


def relay_config(a, *, objective: str, authority_profile: str) -> kernel_mod.RelayConfig:
    """The ceilings and completion policy for one relay, from ONE construction site. PURE.

    ``relay start`` and ``relay resume`` built this separately and drifted, as two copies of a
    policy always do: resume forgot ``observe_repo`` entirely, so a relay started with
    --no-observe resumed reading the repository again. Both also wrote
    ``int(getattr(a, key, default) or default)``, which cannot express a deliberate ZERO -- an
    operator who set --incomplete-retries 0 to mean "one attempt, then stop" got the default 2
    the zero was chosen to override. One site cannot drift from itself.
    """
    return kernel_mod.RelayConfig(
        objective=objective, authority_profile=authority_profile,
        max_exchanges=int(a.max_exchanges), max_duration_s=float(a.max_duration),
        receive_timeout_s=float(a.receive_timeout),
        completion_checks=tuple(getattr(a, "verify", ()) or ()),
        completion_requires_repo_change=bool(getattr(a, "require_repo_change", False)),
        completion_attempt_limit=int(getattr(a, "completion_attempts", 2)),
        check_timeout_s=float(getattr(a, "verify_timeout", 300.0)),
        incomplete_retry_limit=int(getattr(a, "incomplete_retries", 2)),
        probe_endpoints=not bool(getattr(a, "no_probe", False)),
        observe_repo=not bool(getattr(a, "no_observe", False)))


#: The record keys a resume reads back, and the flag each becomes. Named ONCE so a control can
#: compare this set against ``kernel.persisted_policy`` -- the only thing that stops the writer
#: and the reader drifting apart, which is the defect three consecutive reviews have found.
RECORDED_POLICY = (("max_exchanges", "max_exchanges", int),
                   ("max_duration_s", "max_duration", float),
                   ("receive_timeout_s", "receive_timeout", float),
                   ("completion_attempt_limit", "completion_attempts", int),
                   ("check_timeout_s", "verify_timeout", float),
                   ("incomplete_retry_limit", "incomplete_retries", int))
#: The rest of the policy is not a scalar an operator may lower: a set of checks that may only
#: grow, and two switches a flag may turn off and only the record may turn on.
RECORDED_POLICY_SWITCHES = ("completion_checks", "completion_requires_repo_change",
                            "probe_endpoints", "observe_repo")


def recorded_policy_keys() -> tuple:
    """Every record key a resume reads. PURE."""
    return tuple(key for key, _attr, _cast in RECORDED_POLICY) + RECORDED_POLICY_SWITCHES


def apply_recorded_policy(a, saved) -> None:
    """Put the relay's OWN policy back on the namespace before it is resumed. Impure (mutates a).

    THE RECORD OUTRANKS THE FLAGS, because the policy belongs to the relay and not to this
    invocation. A flag may STRENGTHEN it -- add a verification command, require the repository
    to have moved, switch probing off -- and may never silently weaken it.

    ``is not None`` rather than truthiness: a persisted zero is a policy, and a falsy test
    silently replaces it with the default it was chosen to override. That exact shape sat here
    for three fields and was the third policy-loss-on-resume defect found in as many reviews.
    """
    saved = dict(saved or {})
    shipped = kernel_mod.RelayConfig()
    for key, attr, cast in RECORDED_POLICY:
        # A CEILING IS A BUDGET AN OPERATOR MAY RAISE, and this is where the two kinds of policy
        # part company. Corroboration may only be strengthened, because dropping it silently
        # changes what the relay will believe. A ceiling is different: a relay that stopped at
        # MAX_DURATION_REACHED can only be continued by giving it more room, and ``started_at``
        # is immutable, so a record that outranked the flag made such a relay permanently
        # unresumable -- there was no flag, no operation and no column that could rescue it.
        # So: an explicitly typed flag wins, else the record, else what this build ships.
        typed = getattr(a, attr, None)
        if typed is not None:
            continue
        setattr(a, attr, cast(saved[key]) if saved.get(key) is not None
                else getattr(shipped, key))
    recorded_checks = list(saved.get("completion_checks") or ())
    setattr(a, "verify", recorded_checks
            + [c for c in (getattr(a, "verify", None) or []) if c not in recorded_checks])
    setattr(a, "require_repo_change", bool(saved.get("completion_requires_repo_change"))
            or bool(getattr(a, "require_repo_change", False)))
    # Probing and observation may be turned OFF by a flag and only ON by the record.
    if "probe_endpoints" in saved and not saved["probe_endpoints"]:
        setattr(a, "no_probe", True)
    if saved.get("observe_repo") is not None and not saved["observe_repo"]:
        setattr(a, "no_observe", True)


def cmd_relay_start(a) -> int:
    """Bind both ends to one authorised project and drive the conversation."""
    db, _work = relay_paths(a.home)
    st = state_mod.RelayState(db)
    # ONE ID PER SECOND was the previous shape, so two starts in the same second collided
    # deterministically -- and now that a relay takes a lock, the second one is refused with a
    # misleading RELAY_ALREADY_RUNNING or, if the first has finished, hits a PRIMARY KEY
    # violation on a bare INSERT.
    relay_id = str(getattr(a, "relay_id", "") or ("relay-%s" % uuid.uuid4().hex[:12]))
    # ONE PROCESS PER RELAY, enforced by the OS rather than by agreement. Held for this
    # process's lifetime and never released explicitly, so a crash publishes the release. Core
    # reads this same lock to answer "is that relay still running", which is why the answer
    # survives Core dying and is not a record either side has to maintain.
    holder = corerelay.hold(a.home, relay_id)
    if holder is None:
        st.close()
        _emit({"started": False, "error": "RELAY_ALREADY_RUNNING", "relay_id": relay_id,
               "detail": "another process holds this relay; refusing to run a second one "
                         "against the same durable session"})
        return 3
    corerelay.record_process(a.home, relay_id, pid=os.getpid(),
                             started_by=str(getattr(a, "started_by", "") or "cli"))
    try:
        orchestrator, execution, o_spec, e_spec = _build_ends(a, a.home, relay_id)
    except Exception as exc:  # noqa: BLE001
        st.close()
        _emit({"started": False, "error": "%s: %s" % (type(exc).__name__, exc)})
        return 2
    grants, channel = _owner_hooks(a.home, scope=relay_id)
    verbose = bool(getattr(a, "verbose", False))
    cfg = relay_config(a, objective=a.objective, authority_profile=a.profile)
    k = kernel_mod.RelayKernel(
        st=st, orchestrator=orchestrator, execution=execution,
        project_root=os.path.abspath(a.project), relay_id=relay_id,
        config=cfg,
        owner_grants=grants, channel_state=channel,
        log=(lambda m: sys.stderr.write("[relay] %s\n" % m)) if verbose else None)
    try:
        res = k.start()
        # AS SOON AS THE ROW EXISTS, and in both branches: a relay that was refused at start is
        # exactly the one an operator will want to resume after fixing whatever refused it.
        record_relay_shape(st, relay_id, cfg, o_spec, e_spec)
        if res.stop:
            _emit({"started": False, "relay_id": relay_id, "stop_reason": res.stop,
                   "hold": dict(res.hold or {}), "status": k.summary()})
            return 3
        out = k.run(max_steps=int(getattr(a, "max_steps", 0) or 0))
        out["started"] = True
        out["specs"] = {"orchestrator": {"kind": o_spec["kind"]},
                        "execution": {"kind": e_spec["kind"]}}
        _emit(out)
        return 0 if out.get("stop_reason") in (kernel_mod.STOP_OBJECTIVE_COMPLETE,
                                               kernel_mod.STOP_MAX_EXCHANGES, "") else 4
    finally:
        try:
            orchestrator.close()
            execution.close()
        finally:
            st.close()


def cmd_relay_resume(a) -> int:
    """Re-attach to a relay the durable record already knows, then continue it."""
    db, _work = relay_paths(a.home)
    st = state_mod.RelayState(db)
    orchestrator = execution = None
    try:
        row = st.get(a.relay_id) if getattr(a, "relay_id", "") else st.latest()
        if row is None:
            _emit({"resumed": False, "error": "no relay is recorded in %s" % db})
            return 2
        relay_id = row["relay_id"]
        # THE LOCK IS TAKEN FIRST, exactly as at start. It used to be taken after the ends were
        # built, so two concurrent resumes both attached a browser, both created an agent
        # session and both opened their transports before one of them discovered it was not the
        # one driving this relay -- and the loser returned without closing anything. It also
        # left every reader seeing the relay as ORPHANED for the whole of that build.
        holder = corerelay.hold(a.home, relay_id)
        if holder is None:
            _emit({"resumed": False, "error": "RELAY_ALREADY_RUNNING", "relay_id": relay_id})
            return 3
        corerelay.record_process(a.home, relay_id, pid=os.getpid(),
                                 started_by=str(getattr(a, "started_by", "") or "cli"))
        # THE SPECS COME FROM THE RECORD, not from flags. A resumed relay that silently changed
        # provider would make "the same conversation continued" false while looking fine.
        a.orchestrator = a.orchestrator or row["orchestrator_kind"]
        a.agent = a.agent or row["execution_kind"]
        a.project = a.project or row["project_root"]
        a.profile = row["authority_profile"]
        a.objective = row["objective"]
        setattr(a, "conversation_id", row["orchestrator_conversation"])
        setattr(a, "session_id", row["execution_session"])
        # THE COMPLETION POLICY COMES FROM THE RECORD, like the objective and the profile.
        # Flags may STRENGTHEN it -- add a check, require repo movement -- but resuming must
        # never silently drop the corroboration the relay was started with.
        saved = json.loads(row.get("config_json") or "{}")
        apply_recorded_policy(a, saved)
        # WHERE the ends are, not only WHAT they are. Without this a flagless resume rebuilds
        # an OpenAI-compatible orchestrator with no base URL, no model and no credential
        # source, and the relay dies before its first turn.
        overrides = apply_recorded_endpoints(a, saved)
        # AUTHORITY BEFORE ANY ENDPOINT IS BUILT. Building an end is not free and is not
        # read-only: the chatgpt-web end attaches to a browser and the opencode end will CREATE
        # AN AGENT SESSION. Doing that for a relay an owner has not permitted to continue
        # performs a side effect to discover that it may not proceed -- and an end that fails
        # to build then MASKS the refusal, reporting a provider problem where the truth is that
        # a human has not decided. The kernel re-gates again on resume; this is the same
        # question asked before anything is touched, through the same function.
        grants_now, channel_now = _owner_hooks(a.home, scope=relay_id)
        blocking = kernel_mod.owner_holds_blocking(
            st, relay_id, profile=str(row["authority_profile"]),
            owner_grants=grants_now(), now=time.time(), channel_state=channel_now())
        if blocking:
            _emit({"resumed": False, "relay_id": relay_id,
                   "stop_reason": kernel_mod.STOP_OWNER_HOLD,
                   "owner_holds": blocking,
                   "detail": "this relay is waiting on an explicit OWNER decision. Resuming is "
                             "not approving: grant the named capability through the owner "
                             "channel."})
            return 3
        try:
            orchestrator, execution, o_spec, e_spec = _build_ends(a, a.home, relay_id)
        except Exception as exc:  # noqa: BLE001 - the same answer shape ``start`` gives
            # A TRACEBACK IS NOT AN ANSWER. This path was unguarded, so a relay recorded before
            # endpoint specs existed came back as an uncaught ValueError on stderr -- which,
            # under Core, goes to a log file the client never sees.
            _emit({"resumed": False, "relay_id": relay_id,
                   "error": "%s: %s" % (type(exc).__name__, exc)})
            return 2
        grants, channel = _owner_hooks(a.home, scope=relay_id)
        cfg = relay_config(a, objective=row["objective"],
                           authority_profile=row["authority_profile"])
        # THE RECORD IS BROUGHT UP TO DATE with what this process will actually run, so the NEXT
        # resume inherits the strengthened policy rather than the start-time one.
        record_relay_shape(st, relay_id, cfg, o_spec, e_spec)
        if overrides:
            st.append_event(relay_id, "relay.endpoint.overridden",
                            {"overrides": overrides,
                             "note": "a flag re-pointed an end the record had already named"})
        k = kernel_mod.RelayKernel(
            st=st, orchestrator=orchestrator, execution=execution,
            project_root=row["project_root"], relay_id=relay_id, config=cfg,
            owner_grants=grants, channel_state=channel,
            log=(lambda m: sys.stderr.write("[relay] %s\n" % m))
            if getattr(a, "verbose", False) else None)
        stopped = k.resume()
        if stopped is not None:
            out = k.summary()
            out["resumed"] = False
            out["stop_reason"] = stopped.stop
            out["hold"] = dict(stopped.hold or {})
            _emit(out)
            return 3
        out = k.run(max_steps=int(getattr(a, "max_steps", 0) or 0))
        out["resumed"] = True
        _emit(out)
        return 0
    finally:
        # CLOSED THE WAY START CLOSES THEM. An openai-chat orchestrator SAVES its transcript on
        # close, and a resume that returned without closing left the conversation it had just
        # continued unwritten.
        try:
            if orchestrator is not None:
                orchestrator.close()
            if execution is not None:
                execution.close()
        finally:
            st.close()


def cmd_relay_status(a) -> int:
    """What is connected, which exchange is active, and why the relay is waiting."""
    db, _work = relay_paths(a.home)
    if not os.path.isfile(db):
        _emit({"found": False, "relay_db": db,
               "detail": "no relay has ever run against this state home"})
        return 1
    st = state_mod.RelayState(db)
    try:
        if getattr(a, "all", False):
            _emit({"relays": [kernel_mod.summarise(st, r["relay_id"])
                              for r in st.list_relays()]})
            return 0
        row = st.get(a.relay_id) if getattr(a, "relay_id", "") else st.latest(
            os.path.abspath(a.project) if getattr(a, "project", "") else "")
        if row is None:
            _emit({"found": False, "relay_db": db})
            return 1
        out = kernel_mod.summarise(st, row["relay_id"])
        if getattr(a, "events", 0):
            out["events"] = st.events(row["relay_id"], limit=int(a.events))
        if getattr(a, "transcript", False):
            out["transcript"] = [
                {"exchange": m["exchange_no"], "direction": m["direction"],
                 "message_id": m["message_id"], "delivery_state": m["delivery_state"],
                 "chars": m["chars"], "text": m["text"]}
                for m in st.messages(row["relay_id"])]
        _emit(out)
        return 0
    finally:
        st.close()


def cmd_relay_stop(a) -> int:
    """Mark a relay stopped in the durable record.

    This does NOT kill an agent session: the operator owns that server and this platform does
    not manage its lifetime. Claiming otherwise would be a lifecycle capability no endpoint here
    actually has.
    """
    db, _work = relay_paths(a.home)
    st = state_mod.RelayState(db)
    try:
        row = st.get(a.relay_id) if getattr(a, "relay_id", "") else st.latest()
        if row is None:
            _emit({"stopped": False, "error": "no relay is recorded in %s" % db})
            return 1
        # CONDITIONAL, exactly as Core's stop is. Unconditional, this raced the relay writing
        # its own terminal transition and overwrote OBJECTIVE_COMPLETE with an operator act that
        # never happened. Two stop paths that disagree about that invariant is worse than one.
        applied = st.request_stop(row["relay_id"], kernel_mod.STOP_OPERATOR)
        st.append_event(row["relay_id"], "relay.stopped",
                        {"reason": kernel_mod.STOP_OPERATOR, "by": "operator"})
        out = kernel_mod.summarise(st, row["relay_id"])
        out["stopped"] = True
        out["note"] = ("the relay is marked stopped; any agent session the operator started "
                       "keeps running -- this platform does not manage its lifetime")
        _emit(out)
        return 0
    finally:
        st.close()


def add_arguments(p) -> None:
    """Attach the relay verbs to an existing subparser. Called by ``transports.cli``."""
    sub = p.add_subparsers(dest="rcmd", required=True)

    def common(q, *, project_required=False):
        q.add_argument("--project", default="" if not project_required else None,
                       required=project_required,
                       help="the git working tree this relay is authorised for")
        q.add_argument("--profile", default="STANDARD_EDIT",
                       help="authority profile the relay runs under (default: STANDARD_EDIT)")
        q.add_argument("--orchestrator", default="",
                       help="orchestrator kind: %s"
                            % ", ".join(relay_registry.ORCHESTRATOR_KINDS))
        q.add_argument("--orchestrator-model", default="",
                       help="model the orchestrator runs, as '<vendor>/<model>' -- the VENDOR "
                            "comes from here, never from the gateway that carried the request")
        q.add_argument("--orchestrator-base-url", default="",
                       help="OpenAI-compatible chat-completions base URL")
        q.add_argument("--orchestrator-key-var", default="",
                       help="environment variable holding the orchestrator's API key")
        q.add_argument("--orchestrator-key-file", default="",
                       help="JSON file holding the key, when the provider's own tool stores one")
        q.add_argument("--orchestrator-key-field", default="",
                       help="dotted field inside --orchestrator-key-file")
        q.add_argument("--browser-endpoint", default="",
                       help="CDP endpoint of a browser the operator already started and signed "
                            "into (chatgpt-web orchestrator; default http://127.0.0.1:9222)")
        q.add_argument("--browser-transport", default="auto",
                       choices=("auto", "cdp", "playwright"),
                       help="how to reach that browser (chatgpt-web orchestrator)")
        q.add_argument("--conversation-id", default="",
                       help="bind to THIS existing ChatGPT conversation id; omitted, a new "
                            "thread is started and its id is recorded")
        q.add_argument("--agent", default="",
                       help="execution agent kind: %s"
                            % ", ".join(relay_registry.EXECUTION_KINDS))
        q.add_argument("--agent-base-url", default="http://127.0.0.1:4096",
                       help="local agent server the operator already started")
        q.add_argument("--agent-model", default="",
                       help="model the execution agent runs, as '<provider>/<model>'")
        q.add_argument("--agent-persona", default="",
                       help="named agent/persona the execution server should use")
        q.add_argument("--session-id", default="",
                       help="attach to THIS existing agent session id")
        q.add_argument("--attach-latest", action="store_true",
                       help="adopt the most recently updated session for the project")
        q.add_argument("--no-create-session", action="store_true",
                       help="refuse to create a session; attach to an existing one or fail")

    q = sub.add_parser("start", help="start a relay between an orchestrator and an agent")
    common(q, project_required=True)
    q.add_argument("--objective", required=True, help="what the relay is for, in plain prose")
    q.add_argument("--relay-id", default="")
    q.add_argument("--max-exchanges", type=int, default=40)
    q.add_argument("--max-duration", type=float, default=3600.0)
    q.add_argument("--receive-timeout", type=float, default=600.0)
    q.add_argument("--max-steps", type=int, default=0,
                   help="stop after N half-exchanges (0 = until terminal)")
    q.add_argument("--no-observe", action="store_true",
                   help="skip independent repository observation (NOT recommended: the "
                        "orchestrator then hears only the agent's account of its own work)")
    q.add_argument("--no-probe", action="store_true",
                   help="skip the model-exercising probe at start. NOT recommended: status() "
                        "only proves a credential exists or a server listens, so without this "
                        "probe an unusable model is discovered at exchange 1")
    q.add_argument("--verify", action="append", default=[], metavar="COMMAND",
                   help="a command THIS process runs in the project to corroborate the "
                        "orchestrator's completion claim (repeatable). Without one, a claim of "
                        "completion is recorded UNVERIFIED and believed anyway")
    q.add_argument("--verify-timeout", type=float, default=300.0,
                   help="ceiling on one --verify command")
    q.add_argument("--require-repo-change", action="store_true",
                   help="a completion claim additionally requires the repository to have moved")
    q.add_argument("--completion-attempts", type=int, default=2,
                   help="how many refuted completion claims are handed back before the relay "
                        "stops as COMPLETION_UNCORROBORATED")
    q.add_argument("--incomplete-retries", type=int, default=2,
                   help="how many times a STILL-USABLE endpoint may return an incomplete turn "
                        "before the relay gives up; only the receive is retried, never the send")
    q.add_argument("--started-by", dest="started_by", default="cli",
                   help="who launched this relay, recorded in the discovery hint")
    q.add_argument("--verbose", action="store_true")
    q.set_defaults(fn=cmd_relay_start)

    q = sub.add_parser("resume", help="re-attach to a recorded relay and continue it")
    common(q)
    q.add_argument("--relay-id", default="")
    # NONE, NOT A NUMBER. On a resume an argparse default is indistinguishable from a value the
    # operator typed, and the record has to be able to win against the one and lose to the
    # other. ``apply_recorded_policy`` resolves each of these to a concrete value.
    q.add_argument("--max-exchanges", type=int, default=None)
    q.add_argument("--max-duration", type=float, default=None)
    q.add_argument("--receive-timeout", type=float, default=None)
    q.add_argument("--max-steps", type=int, default=0)
    q.add_argument("--objective", default="")
    q.add_argument("--no-observe", action="store_true",
                   help="do not read the repository between turns (the record may not turn "
                        "this back on)")
    q.add_argument("--no-probe", action="store_true",
                   help="skip the model-exercising probe at start. NOT recommended: status() "
                        "only proves a credential exists or a server listens, so without this "
                        "probe an unusable model is discovered at exchange 1")
    q.add_argument("--verify", action="append", default=[], metavar="COMMAND",
                   help="a command THIS process runs in the project to corroborate the "
                        "orchestrator's completion claim (repeatable). Without one, a claim of "
                        "completion is recorded UNVERIFIED and believed anyway")
    q.add_argument("--verify-timeout", type=float, default=None,
                   help="ceiling on one --verify command")
    q.add_argument("--require-repo-change", action="store_true",
                   help="a completion claim additionally requires the repository to have moved")
    q.add_argument("--completion-attempts", type=int, default=None,
                   help="how many refuted completion claims are handed back before the relay "
                        "stops as COMPLETION_UNCORROBORATED")
    q.add_argument("--incomplete-retries", type=int, default=None,
                   help="how many times a STILL-USABLE endpoint may return an incomplete turn "
                        "before the relay gives up; only the receive is retried, never the send")
    q.add_argument("--started-by", dest="started_by", default="cli",
                   help="who launched this relay, recorded in the discovery hint")
    q.add_argument("--verbose", action="store_true")
    # ON A RESUME, AN ARGPARSE DEFAULT IS A LIE. --agent-base-url defaults to a port that is a
    # reasonable guess for a fresh start and simply wrong for a relay that recorded a different
    # one -- and a default is indistinguishable from a value the operator typed, so the record
    # could never win. Emptied here so "unset" means unset; a flag actually typed still wins.
    q.set_defaults(fn=cmd_relay_resume, agent_base_url="", browser_transport="")

    q = sub.add_parser("status", help="what is connected, which exchange, and why it is waiting")
    q.add_argument("--relay-id", default="")
    q.add_argument("--project", default="")
    q.add_argument("--all", action="store_true")
    q.add_argument("--events", type=int, default=0, help="include the last N durable events")
    q.add_argument("--transcript", action="store_true",
                   help="include every message the relay moved")
    q.set_defaults(fn=cmd_relay_status)

    q = sub.add_parser("doctor", help="measure whether a relay could run right now")
    q.add_argument("--no-probe", action="store_true",
                   help="report endpoint readiness without exercising the model")
    common(q)
    q.set_defaults(fn=cmd_relay_doctor)

    q = sub.add_parser("stop", help="mark a relay stopped in the durable record")
    q.add_argument("--relay-id", default="")
    q.set_defaults(fn=cmd_relay_stop)

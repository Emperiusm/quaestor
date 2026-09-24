"""mcp_adapter -- the thin translation layer. It decides NOTHING.

WHAT "THIN" MEANS, CONCRETELY
----------------------------
This module contains no policy. It does not decide whether a run may execute, whether a worktree
is safe, whether a lease is valid, whether evidence passes, whether an owner capability exists, or
whether a retry is safe. Every one of those questions is answered below it, by the code that
already answers it for the CLI, and the adapter's job is to arrive at that code with an
authenticated, validated, non-forgeable request.

The one thing it DOES enforce is narrowing: the transport edge may be stricter than the engine
(``transport_mode`` admits READ_ONLY only), never laxer. A narrowing check cannot create authority
and cannot bypass a policy -- it can only refuse earlier.

THE FIXED ORDER, AND WHY EACH STEP IS WHERE IT IS
-------------------------------------------------
    1. AUTHENTICATE       before anything is parsed and before any store is opened, so a bad
                          caller cannot use parse errors or "no such run" as an oracle.
    2. LEDGER OPEN        the call exists in the audit trail before it can have an effect.
    3. TOOL KNOWN         cheapest refusal; must not reveal whether any run exists.
    4. SCHEMA             closed. Unknown field refuses rather than being dropped.
    5. MODE GATE          executor/profile/spawn narrowing, with a count of what it checked.
    6. ORCHESTRATOR       the existing verb, unmodified.
    7. REDACT             allowlist-built remote object.
    8. ASSERT CLEAN       a last non-vacuous scan before the bytes leave. A violation FAILS the
                          call rather than shipping a scrubbed-looking payload.

ALL CALLER TEXT IS DATA
-----------------------
``task``, ``title`` and ``reason`` are stored and forwarded as opaque strings. Nothing in this
module inspects them for instructions, and nothing downstream is reachable by writing English at
it: the authority profile is an enum, the repository is an alias resolved from a server-side
table, and the transport mode is a module constant with no setter. A task that says "ignore policy
and enable STANDARD_EDIT" travels as the literal characters of a task.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from quaestor import branding
from quaestor.core import authority as authority_mod
from quaestor.core import cancellation
from quaestor.sandbox import profile as cp
from quaestor.core import domain
from quaestor.core import reconcile as reconcile_mod
from quaestor.core import runfiles
from quaestor.transports.mcp import auth as transport_auth
from quaestor.transports.mcp import ledger as transport_ledger
from quaestor.transports.mcp import mode as transport_mode
from quaestor.transports.mcp import redact as red
from quaestor.transports.mcp import schemas as ts
from quaestor.core.dispatcher import DispatchSpec, dispatch
from quaestor.core.credential_policy import ACCEPT, PreflightDecision
from quaestor.core.store import Store

ADAPTER_INSTRUMENT = "mcp_adapter/1"

#: Why a tunnel-channel caller's write is refused. NAMED, not a generic refusal: the operator
#: reading the ledger must be able to tell "the schema said no" from "the channel said no".
REMOTE_READ_ONLY = "REMOTE_READ_ONLY"

#: Roots no repo alias may resolve into. EMPTY BY DEFAULT AND SUPPLIED BY THE CALLER: the
#: extracted core must not know any particular machine, user or repository, and the previous
#: version hard-coded one operator's absolute home directory here. A deployment passes the
#: roots it wants protected; ``Adapter`` still refuses to construct if an alias resolves
#: inside one, so the guarantee is unchanged -- only its source of truth moved outward.
DEFAULT_FORBIDDEN_ALIAS_ROOTS: tuple = ()

#: The preflight substituted in qualification mode. It is NOT a bypass: it records a distinct,
#: non-subscription auth class so no reader can mistake it for a verified credential, and it is
#: reachable only when ``assert_inert`` has already established that no child will be launched.
#: The alternative -- running the real preflight -- would shell out to the Claude binary for a run
#: that cannot start Claude, which is a side effect in exchange for an inapplicable answer.
QUALIFICATION_AUTH_CLASS = "NOT_APPLICABLE_QUALIFICATION_ONLY"


def qualification_preflight(**_kw) -> PreflightDecision:
    return PreflightDecision(
        ACCEPT, "", ("transport is in %s mode: no Claude child can be launched by this dispatch, "
                     "so the subscription-vs-API-billing question this gate exists to answer does "
                     "not arise. No credential was read and the Claude binary was not invoked."
                     % transport_mode.TRANSPORT_EXECUTION_MODE),
        QUALIFICATION_AUTH_CLASS, (),
        {"transport_execution_mode": transport_mode.TRANSPORT_EXECUTION_MODE,
         "claude_binary_invoked": False, "credential_broker_opened": False})


@dataclass(frozen=True)
class CallResult:
    ok: bool
    tool: str
    payload: Mapping = field(default_factory=dict)
    reason: str = ""
    detail: str = ""
    transport_request_id: str = ""
    instrument: str = ADAPTER_INSTRUMENT

    def to_dict(self) -> dict:
        d = {"ok": self.ok, "tool": self.tool, "instrument": self.instrument,
             "transport_request_id": self.transport_request_id}
        if self.ok:
            d.update(dict(self.payload))
        else:
            d["reason"] = self.reason
            d["detail"] = self.detail
        return d


class Adapter:
    """One instance per server process. Holds no policy and caches no decision.

    The transport's EXECUTION MODE is resolved ONCE, at construction, from the deployment file in
    ``home`` -- never from a request, a header or an environment variable. A remote caller can
    narrow nothing and widen nothing about it; see transports.mcp.mode.
    """

    def __init__(self, home: str, *, repo_table: Mapping[str, str],
                 ledger: transport_ledger.TransportLedger | None = None,
                 dispatch_fn: Callable = dispatch,
                 forbidden_alias_roots: Sequence[str] | None = None,
                 claude_path: str = "claude"):
        self.home = home
        self.mode, self.mode_record = transport_mode.resolve_mode(home)
        self.claude_path = str(claude_path)
        self.forbidden_alias_roots = tuple(forbidden_alias_roots
                                           if forbidden_alias_roots is not None
                                           else DEFAULT_FORBIDDEN_ALIAS_ROOTS)
        self.repo_table = self._validate_table(repo_table, self.forbidden_alias_roots)
        self.alias_of = red.alias_map(self.repo_table)
        self.ledger = ledger or transport_ledger.TransportLedger(
            transport_ledger.ledger_path(home))
        self._dispatch = dispatch_fn

    # -- construction guards -------------------------------------------------------------------
    @staticmethod
    def _validate_table(table: Mapping[str, str], forbidden_roots: Sequence[str] = ()) -> dict:
        """Refuse AT CONSTRUCTION to alias a protected root. Raises ValueError.

        A constructor that cannot be built wrongly beats a check that has to be remembered at
        every call site: an adapter pointed at a repository the deployment protects simply cannot
        be instantiated.

        The protected roots are supplied by the caller rather than compiled in. The extracted core
        knows no particular machine or repository, so an empty set is the honest default -- and a
        deployment that wants a repository protected says so, which is also the only way this can
        be correct for a user who is not the original author.
        """
        out = {}
        for alias, host in (table or {}).items():
            # RESOLVE, then compare on a separator boundary. A lexical prefix test on the string
            # the caller supplied is defeated by a junction, a symlink, an 8.3 short name, an
            # extended-length prefix, a UNC spelling, or redundant separators -- all of which name
            # the same directory. `realpath` collapses them; `path_is_within` is this project's
            # own boundary-aware containment test, already used by the confinement policy.
            # Strip the extended-length / device prefixes first: `realpath` preserves them, so
            # `\\?\C:\...` and `C:\...` would otherwise compare as different roots while naming
            # the same directory.
            raw = str(host)
            stripped = raw
            for prefix in ("\\\\?\\UNC\\", "\\\\?\\", "\\\\.\\"):
                if stripped.upper().startswith(prefix.upper()):
                    stripped = stripped[len(prefix):]
                    break
            h = os.path.realpath(os.path.abspath(stripped)).replace("\\", "/").rstrip("/")
            for forbidden in forbidden_roots:
                f = os.path.realpath(os.path.abspath(forbidden)).replace("\\", "/").rstrip("/")
                if cp.path_is_within(h, f) or cp.path_is_within(raw, forbidden):
                    raise ValueError(
                        "refusing to expose %r: it resolves inside %s, which this deployment "
                        "protects" % (alias, forbidden))
            if not str(alias).replace("-", "").replace("_", "").isalnum():
                raise ValueError("repo alias %r must be a plain identifier" % alias)
            out[str(alias)] = h
        return out

    def close(self) -> None:
        self.ledger.close()

    # -- the surface ---------------------------------------------------------------------------
    def tools(self, *, channel: str = "") -> list:
        """The MCP ``tools/list`` payload, filtered BY CHANNEL. PURE given the repo table.

        A remote (tunnel) caller is advertised only what it can actually call: advertising a
        write tool to a caller that will only be refused teaches the model to retry into a wall.
        The loopback surface is unfiltered.
        """
        defs = ts.tool_definitions(repo_table=self.repo_table, mode=self.mode)
        if channel == transport_auth.CHANNEL_HTTP_REMOTE:
            read_only = ts.READ_ONLY_TOOLS
            defs = [d for d in defs if d["name"] in read_only]
        return defs

    def call(self, tool: str, args: Any, *, auth: transport_auth.AuthResult,
             protocol_version: str = "", now: float | None = None) -> CallResult:
        """Execute one tools/call. NEVER raises: a crash is an absent verdict, and an absent
        verdict is how a caller ends up retrying into the gap."""
        # 1. AUTHENTICATE -- before parsing, before any store is opened.
        if auth is None or not auth.ok:
            rid = self.ledger.open_request(
                channel=(auth.channel if auth else ""), tool=str(tool),
                tool_schema_version=ts.SCHEMA_VERSION, payload={"redacted": True},
                protocol_version=protocol_version,
                caller_identity=(auth.identity_class if auth else ""),
                transport_mode=self.mode, now=now)
            self.ledger.close_request(rid, disposition=transport_ledger.UNAUTHENTICATED,
                                      reason=transport_auth.REFUSAL, now=now)
            # Identical wording for every failure mode. No hint about tools or runs.
            return CallResult(False, str(tool), reason="UNAUTHENTICATED",
                              detail=transport_auth.REFUSAL, transport_request_id=rid)

        # 2. LEDGER -- the call exists before it can have an effect.
        rid = self.ledger.open_request(
            channel=auth.channel, tool=str(tool), tool_schema_version=ts.SCHEMA_VERSION,
            payload=args, protocol_version=protocol_version,
            caller_identity=auth.identity_class, caller_token_id=auth.token_id,
            transport_mode=self.mode, now=now)

        try:
            # 3-4. TOOL + CLOSED SCHEMA (validated against THIS deployment's resolved mode)
            v = ts.validate(tool, args, repo_table=self.repo_table, mode=self.mode)
            if not v.ok:
                self.ledger.close_request(rid, disposition=transport_ledger.REFUSED,
                                          reason=v.reason, now=now)
                return CallResult(False, str(tool), reason=v.reason, detail=v.detail,
                                  transport_request_id=rid)

            handler = {
                ts.T_STATUS: self._status, ts.T_RESULT: self._result,
                ts.T_DISPATCH: self._dispatch_tool, ts.T_CANCEL: self._cancel,
                ts.T_RECONCILE: self._reconcile,
                ts.T_PROGRAM_CREATE: self._program_create,
                ts.T_PROGRAM_STATUS: self._program_status,
                ts.T_PROGRAM_INBOX: self._program_inbox,
                ts.T_PROGRAM_DECIDE: self._program_decide,
                ts.T_PROGRAM_CANCEL: self._program_cancel,
                ts.T_SEARCH: self._search, ts.T_FETCH: self._fetch,
            }[v.tool]

            # THE REMOTE CEILING. A caller authenticated by the TUNNEL token gets the read-only
            # surface and nothing else -- refused BY CHANNEL, before any handler runs, and
            # ledgered like any other refusal. The ceiling follows from which secret was shared
            # (the owner hands the tunnel client the remote token and only it), so a remote
            # caller cannot talk its way into a write, and no header or argument can move it.
            if (auth.channel == transport_auth.CHANNEL_HTTP_REMOTE
                    and v.tool not in ts.READ_ONLY_TOOLS):
                self.ledger.close_request(rid, disposition=transport_ledger.REFUSED,
                                          reason=REMOTE_READ_ONLY, now=now)
                return CallResult(False, v.tool, reason=REMOTE_READ_ONLY,
                                  detail=("this channel is read-only: a remote caller can "
                                          "search, fetch and inspect, but every state change "
                                          "happens through the local owner channel"),
                                  transport_request_id=rid)

            out = handler(v.args, now=now)

            # 7-8. REDACT ALREADY DONE BY THE HANDLER; now prove it -- against REAL needles.
            # An earlier version called assert_clean with no `secrets`, so the secret dimension
            # compared nothing and reported no leaks. That is the P4.5 empty-needle defect
            # reappearing in new code; it was caught by adversarial review rather than by any
            # control here, which is why `secret_scan_vacuous` is now surfaced explicitly.
            scan = red.assert_clean(out.get("payload", {}), secrets=red.host_secret_values())
            out.setdefault("payload", {})["redaction_scan"] = scan
            if scan["vacuous"] or not scan["clean"]:
                self.ledger.close_request(rid, disposition=transport_ledger.FAILED,
                                          reason="REDACTION_FAILED", now=now)
                return CallResult(False, v.tool, reason="REDACTION_FAILED",
                                  detail=("the response did not pass its own redaction scan and "
                                          "was withheld rather than sent: %s"
                                          % {k: scan[k] for k in ("forbidden_keys", "host_paths",
                                                                  "leaked_secrets", "vacuous")}),
                                  transport_request_id=rid)

            self.ledger.close_request(
                rid, disposition=(transport_ledger.ACCEPTED if out.get("ok", True)
                                  else transport_ledger.REFUSED),
                result=out.get("payload"), reason=str(out.get("reason") or ""),
                workflow_id=str(v.args.get("workflow_id") or ""),
                step_id=str(v.args.get("step_id") or ""),
                run_id=str(out.get("run_id") or v.args.get("run_id") or ""),
                dispatch_key=str(out.get("dispatch_key") or ""), now=now)
            return CallResult(bool(out.get("ok", True)), v.tool, out.get("payload", {}),
                              reason=str(out.get("reason") or ""),
                              detail=str(out.get("detail") or ""), transport_request_id=rid)
        except Exception as exc:  # noqa: BLE001
            self.ledger.close_request(rid, disposition=transport_ledger.FAILED,
                                      reason=type(exc).__name__, now=now)
            # The exception TEXT is not returned: it can carry host paths and internal structure.
            return CallResult(False, str(tool), reason="TRANSPORT_ERROR",
                              detail="the call failed and was recorded; see the local ledger",
                              transport_request_id=rid)

    # -- scope ---------------------------------------------------------------------------------
    def owned_run_ids(self) -> set:
        """Runs this TRANSPORT created. Impure (reads its own ledger).

        THE TRANSPORT MAY ONLY SEE AND AFFECT ITS OWN RUNS. The store is shared with the CLI and
        with every prior phase, so an unscoped ``orchestrator_reconcile`` with no arguments would
        classify -- and persist a classification for -- runs the transport never created, and an
        unscoped ``orchestrator_status`` would disclose them. Neither is a decision the transport
        is entitled to make.

        Scope is derived from the ledger rather than from a flag on the run, so it is durable,
        survives a restart, and cannot be set by a caller: a run is in scope only because a
        transport request that this ledger recorded produced it.
        """
        return {str(r["run_id"]) for r in self.ledger.all_rows()
                if r["run_id"] and r["disposition"] == transport_ledger.ACCEPTED}

    def _in_scope(self, run_id: str) -> bool:
        return str(run_id) in self.owned_run_ids()

    @staticmethod
    def _not_found(run_id: str) -> dict:
        """One shape for 'no such run' and 'not yours'.

        Deliberately identical: distinguishing them would turn the transport into an existence
        oracle for runs created by other surfaces.
        """
        return {"ok": False, "reason": "NOT_FOUND",
                "detail": "no run with that identifier is visible to this transport",
                "payload": {"run_id": str(run_id), "found": False}}

    # -- handlers ------------------------------------------------------------------------------
    def _store(self) -> Store:
        return Store(os.path.join(self.home, "orchestrator.sqlite3"))

    def _status(self, args: Mapping, *, now=None) -> dict:
        store = self._store()
        try:
            mine = self.owned_run_ids()
            rid = str(args.get("run_id") or "")
            if not rid:
                active = [r for r in store.runs_in_states(domain.ACTIVE_STATES)
                          if str(r["run_id"]) in mine]
                return {"ok": True, "payload": {
                    "active": [red.remote_run(r, alias_of=self.alias_of) for r in active],
                    "active_count": len(active),
                    "scope": "runs created through this transport only"}}
            run = store.get_run(rid) if rid in mine else None
            if run is None:
                return self._not_found(rid)
            return {"ok": True, "run_id": rid, "payload": {
                "run": red.remote_run(run, alias_of=self.alias_of),
                "worker": red.remote_worker(store.get_worker(rid)),
                "result": red.remote_result(store.get_result(rid), alias_of=self.alias_of),
                "evidence": red.remote_evidence(store.get_evidence(rid), alias_of=self.alias_of),
                "lease": red.remote_lease(store.lease_for_run(rid))}}
        finally:
            store.close()

    def _result(self, args: Mapping, *, now=None) -> dict:
        import json as _json
        store = self._store()
        try:
            rid = str(args["run_id"])
            if not self._in_scope(rid):
                return self._not_found(rid)
            h = store.get_handoff(rid)
            if h is None:
                run = store.get_run(rid)
                return {"ok": False, "reason": "NO_HANDOFF",
                        "detail": ("the execution did not reach HANDOFF_READY. This is a "
                                   "statement about the EXECUTION, not about a program verdict."),
                        "run_id": rid,
                        "payload": {"run_id": rid, "handoff": None,
                                    "execution_state": (run or {}).get("execution_state")}}
            doc = _json.loads(h["handoff_json"])
            return {"ok": True, "run_id": rid, "payload": {
                "run_id": rid,
                "handoff": red.remote_handoff(doc, alias_of=self.alias_of),
                "note": ("this is the CHILD'S REPORT. The bridge's own evidence is a separate "
                         "object and a report claiming success is not proof of one.")}}
        finally:
            store.close()

    # -- the retrieval surface -----------------------------------------------------------------
    #: Cap on search hits. A bound stated here is a promise kept in the handler below; without
    #: it a two-letter query would stream the whole attempt table to a remote caller.
    SEARCH_LIMIT = 25

    def _search(self, args: Mapping, *, now=None) -> dict:
        tokens = [t for t in str(args.get("query") or "").lower().split() if t]
        if not tokens:
            return {"ok": False, "reason": "EMPTY_QUERY",
                    "detail": "a query of no words matches nothing",
                    "payload": {"matches": [], "count": 0}}
        store = self._store()
        sstore = self._sstore()
        try:
            mine = self.owned_run_ids()
            matches = []
            from quaestor.core import runfiles
            for r in store.runs_in_states(domain.ALL_STATES):
                if str(r["run_id"]) not in mine:
                    continue
                disp = store.get_dispatch(str(r.get("dispatch_key") or "")) or {}
                req = runfiles.read_json(runfiles.p(str(r.get("run_dir") or ""),
                                                    runfiles.REQUEST)) or {}
                hay = " ".join(str(x or "") for x in
                               (r.get("run_id"), r.get("execution_state"),
                                disp.get("workflow_id"), disp.get("step_id"),
                                req.get("title"), req.get("prompt"))).lower()
                if all(t in hay for t in tokens):
                    matches.append({"kind": "run", "id": str(r["run_id"]),
                                    "title": red.scrub_text(str(req.get("title") or ""),
                                                            alias_of=self.alias_of),
                                    "state": str(r.get("execution_state") or ""),
                                    "workflow_id": str(disp.get("workflow_id") or ""),
                                    "step_id": str(disp.get("step_id") or "")})
            from quaestor.core import orchestrator as orch
            for p in sstore.list_programs():
                hay = " ".join(str(p.get(k) or "") for k in
                               ("program_id", "title", "objective", "status")).lower()
                if all(t in hay for t in tokens):
                    matches.append({"kind": "program", "id": str(p["program_id"]),
                                    "title": red.scrub_text(str(p.get("title") or ""),
                                                            alias_of=self.alias_of),
                                    "state": str(p.get("status") or ""),
                                    "workflow_id": "", "step_id": ""})
            truncated = len(matches) > self.SEARCH_LIMIT
            return {"ok": True, "payload": {
                "matches": matches[:self.SEARCH_LIMIT],
                "count": len(matches[:self.SEARCH_LIMIT]),
                "total_found": len(matches), "truncated": truncated,
                "scope": ("runs created through this transport, plus every program this "
                          "deployment tracks")}}
        finally:
            store.close()
            sstore.close()

    def _fetch(self, args: Mapping, *, now=None) -> dict:
        import json as _json
        rid = str(args["id"])
        if rid.startswith("prog_"):
            return self._fetch_program(rid)
        store = self._store()
        try:
            if not self._in_scope(rid):
                return self._not_found(rid)
            run = store.get_run(rid)
            h = store.get_handoff(rid)
            if h is None:
                return {"ok": False, "reason": "NO_HANDOFF",
                        "detail": ("the execution did not reach HANDOFF_READY. This is a "
                                   "statement about the EXECUTION, not about a program verdict."),
                        "run_id": rid,
                        "payload": {"id": rid, "found": True,
                                    "execution_state": (run or {}).get("execution_state") or ""}}
            doc = _json.loads(h["handoff_json"])
            doc = red.remote_handoff(doc, alias_of=self.alias_of)
            text = _json.dumps(doc, indent=2, sort_keys=True, default=str)
            return {"ok": True, "run_id": rid, "payload": {
                "id": rid,
                "title": red.scrub_text(str((doc.get("claude_report") or {}).get("summary")
                                            or rid), alias_of=self.alias_of),
                "execution_state": str((run or {}).get("execution_state") or ""),
                "text": red.scrub_text(text, alias_of=self.alias_of),
                "document": doc,
                "note": ("claude_report is the CHILD'S CLAIM; bridge_evidence is this bridge's "
                         "own measurement. A report claiming success is not proof of one.")}}
        finally:
            store.close()

    def _fetch_program(self, pid: str) -> dict:
        from quaestor.core import orchestrator as orch
        sstore = self._sstore()
        try:
            if sstore.get_program(pid) is None:
                return {"ok": False, "reason": "NOT_FOUND",
                        "detail": "no program with that identifier is visible to this transport",
                        "payload": {"id": pid, "found": False}}
            import json as _json
            doc = self._remote_program_view(orch.status_view(sstore, None, pid))
            text = _json.dumps(doc, indent=2, sort_keys=True, default=str)
            return {"ok": True, "payload": {
                "id": pid,
                "title": red.scrub_text(str(doc.get("title") or pid), alias_of=self.alias_of),
                "text": red.scrub_text(text, alias_of=self.alias_of),
                "document": doc,
                "note": ("the durable program record. It is canonical; no conversation is.")}}
        finally:
            sstore.close()

    def _dispatch_tool(self, args: Mapping, *, now=None) -> dict:
        profile = str(args.get("authority_profile") or authority_mod.READ_ONLY)

        if self.mode == transport_mode.LOCAL_GOVERNED:
            return self._dispatch_operational(args, profile=profile, now=now)

        executor = dict(transport_mode.QUALIFICATION_EXECUTOR)

        # 5. THE MODE GATE. Narrowing only -- it can refuse, never authorise.
        inert = transport_mode.assert_inert(authority_profile=profile, executor=executor,
                                            spawn=False)
        if not inert.ok:
            return {"ok": False, "reason": inert.reason, "detail": inert.detail,
                    "payload": {"transport_execution_mode":
                                transport_mode.TRANSPORT_EXECUTION_MODE,
                                "inert_check": inert.to_dict()}}

        alias = str(args["repo_alias"])
        worktree = self.repo_table[alias]          # server-side resolution; never caller-supplied

        store = self._store()
        try:
            spec = DispatchSpec(
                workflow_id=str(args["workflow_id"]), step_id=str(args["step_id"]),
                task=str(args["task"]), worktree_path=worktree, authority_profile=profile,
                executor=executor, title=str(args.get("title") or ""))
            res = self._dispatch(store, spec, run_root=os.path.join(self.home, "runs"),
                                 preflight=qualification_preflight,
                                 spawn=False,                # <-- STRUCTURAL: no worker, ever
                                 now=now)
            payload = {
                "outcome": res.outcome,
                "run_id": res.run_id,
                "dispatch_key": res.dispatch_key,
                "execution_state": res.state,
                "repo_alias": alias,
                "authority_profile": profile,
                "transport_execution_mode": transport_mode.TRANSPORT_EXECUTION_MODE,
                "executor_started": False,
                "claude_invoked": False,
                "inert_check": inert.to_dict(),
                "reason": red.scrub_text(res.reason, alias_of=self.alias_of),
                "detail": red.scrub_text(res.detail, alias_of=self.alias_of),
                "note": ("EXECUTOR-INERT. The request passed the real identity, authority, "
                         "preflight, lease and drift ladder and a durable record exists, but no "
                         "worker was spawned, so no executor was ever constructed."),
                "side_effects": ("admission runs a bounded set of READ-ONLY git commands "
                                 "(rev-parse, status, ls-files, diff, config --get) against the "
                                 "aliased repository to bind identity and measure drift. They "
                                 "are chosen by the orchestrator, never by the caller, and run "
                                 "with GIT_OPTIONAL_LOCKS=0 so a read does not rewrite the "
                                 "index. Stating this because 'no side effects' would be false."),
            }
            return {"ok": res.admitted or res.outcome == "DUPLICATE", "run_id": res.run_id,
                    "dispatch_key": res.dispatch_key, "reason": res.reason, "payload": payload}
        finally:
            store.close()

    # -- the LOCAL_GOVERNED dispatch path -------------------------------------------------------
    #: Executor spec for a fake run in operational mode. A CONSTANT, like its qualification
    #: sibling: the caller names the AUTHORITY PROFILE, never the executor. The scripted scenario
    #: is the honest default (a successful no-op); program-level orchestration chooses richer
    #: scenarios server-side, never from a request field.
    OPERATIONAL_FAKE_EXECUTOR: Mapping = {"kind": "fake",
                                          "config": {"scenario": "OK_PASS"}}

    def _project_config_for(self, worktree: str):
        """The manifest governing this repository, or None. Impure."""
        from quaestor.projects import config as proj_cfg
        cfg, _reason = proj_cfg.load_nearest(worktree)
        return cfg

    def _dispatch_operational(self, args: Mapping, *, profile: str, now=None) -> dict:
        """Real dispatch under LOCAL_GOVERNED. Same ladder, live worker.

        What is DIFFERENT from qualification: the worker is spawned and an executor is
        constructed. What is NOT different: identity, authority, preflight, concurrency, lease
        and drift all still gate the run, in the same order, in core.dispatcher -- which is the
        point of an operational mode that preserves the qualified invariants.
        """
        from quaestor.executors import claude_auth

        alias = str(args["repo_alias"])
        worktree = self.repo_table[alias]          # server-side resolution; never caller-supplied

        # The EXECUTOR comes from the project's own manifest, never from the request: a caller
        # cannot select -- or even name -- the process model used against a repository.
        cfg = self._project_config_for(worktree)
        exec_kind = str((cfg.executor if cfg else "fake") or "fake")
        if exec_kind == "claude-cli":
            executor = {"kind": "claude-cli"}
        elif exec_kind == "fake":
            executor = dict(self.OPERATIONAL_FAKE_EXECUTOR)
        else:
            return {"ok": False, "reason": transport_mode.EXECUTOR_KIND_REFUSED,
                    "detail": ("project %r declares executor %r; admitted kinds in %s mode are "
                               "%s" % ((cfg.name if cfg else alias), exec_kind,
                                       transport_mode.LOCAL_GOVERNED,
                                       sorted(transport_mode.OPERATIONAL_EXECUTOR_KINDS))),
                    "payload": {"transport_execution_mode": self.mode}}

        admissible = transport_mode.assert_admissible(self.mode, authority_profile=profile,
                                                      executor=executor, spawn=True)
        if not admissible.ok:
            return {"ok": False, "reason": admissible.reason, "detail": admissible.detail,
                    "payload": {"transport_execution_mode": self.mode,
                                "inert_check": admissible.to_dict()}}

        store = self._store()
        try:
            spec = DispatchSpec(
                workflow_id=str(args["workflow_id"]), step_id=str(args["step_id"]),
                task=str(args["task"]), worktree_path=worktree, authority_profile=profile,
                executor=executor, title=str(args.get("title") or ""),
                claude_path=self.claude_path)

            def preflight(claude_path="", requires_write=False):
                if exec_kind != "claude-cli":
                    return PreflightDecision(
                        "ACCEPT", "", ("executor %r performs no credential-bearing network "
                                       "authentication, so the subscription-vs-API question "
                                       "does not arise" % exec_kind),
                        "NOT_APPLICABLE_FAKE_EXECUTOR", (),
                        {"claude_binary_invoked": False, "credential_broker_opened": False})
                return claude_auth.run_preflight(claude_path=claude_path or self.claude_path,
                                                 requires_write=requires_write)

            res = self._dispatch(store, spec, run_root=os.path.join(self.home, "runs"),
                                 preflight=preflight,
                                 spawn=True,                 # <-- OPERATIONAL: the real path
                                 now=now)
            payload = {
                "outcome": res.outcome,
                "run_id": res.run_id,
                "dispatch_key": res.dispatch_key,
                "execution_state": res.state,
                "repo_alias": alias,
                "authority_profile": profile,
                "executor_kind": exec_kind,
                "transport_execution_mode": self.mode,
                "worker_spawned": bool(res.spawned),
                "spawn_pid": int(res.extra.get("spawn_pid") or 0) if res.spawned else 0,
                "reason": red.scrub_text(res.reason, alias_of=self.alias_of),
                "detail": red.scrub_text(res.detail, alias_of=self.alias_of),
                "note": ("GOVERNED EXECUTION. The run was admitted through the full ladder and "
                         "a detached worker owns it from here. The worker constructs the "
                         "executor inside the profile's tool surface; independent evidence is "
                         "collected by the control plane when the child ends."),
            }
            return {"ok": res.admitted or res.outcome == "DUPLICATE", "run_id": res.run_id,
                    "dispatch_key": res.dispatch_key, "reason": res.reason, "payload": payload}
        finally:
            store.close()

    def _cancel(self, args: Mapping, *, now=None) -> dict:
        store = self._store()
        try:
            rid = str(args["run_id"])
            run = store.get_run(rid) if self._in_scope(rid) else None
            if run is None:
                return self._not_found(rid)
            state = str(run["execution_state"])
            worker = store.get_worker(rid) or {}
            stage = cancellation.stage_for(state, container_created=False,
                                           child_started=bool(worker.get("spawn_pid")))
            dec = cancellation.classify_cancel(
                run_state=state, stage=stage, is_write_capable=bool(run.get("is_write")),
                child_started=bool(worker.get("spawn_pid")),
                target_measurable=None, target_changed=None)
            store.append_event("transport.cancel", run_id=rid,
                               detail={"decision": dec.to_dict(),
                                       "reason": str(args.get("reason") or "")})
            if dec.outcome in (domain.CANCELLED, cancellation.CANCELLED_UNCHANGED) \
                    and not domain.is_terminal(state):
                try:
                    store.transition(rid, domain.CANCELLED, reason="cancelled via MCP transport")
                except Exception:  # noqa: BLE001
                    pass
            after = store.get_run(rid)
            return {"ok": True, "run_id": rid, "payload": {
                "run_id": rid, "decision": dec.to_dict(),
                "execution_state": str((after or {}).get("execution_state") or state),
                "note": ("cancellation is CLASSIFIED, never guaranteed: this records what a "
                         "cancel can honestly claim at this stage. It rolls nothing back.")}}
        finally:
            store.close()

    def _reconcile(self, args: Mapping, *, now=None) -> dict:
        store = self._store()
        try:
            dry = bool(args.get("dry_run", False))
            rid = str(args.get("run_id") or "")
            mine = self.owned_run_ids()
            if rid and not self._in_scope(rid):
                return self._not_found(rid)
            # SCOPED, ALWAYS. `reconcile_all` walks every run in a store shared with the CLI and
            # with every prior phase; an argument-less transport call must not classify -- let
            # alone PERSIST a classification for -- work the transport never created.
            targets = [rid] if rid else sorted(mine)
            items = []
            for t in targets:
                if store.get_run(t) is None:
                    continue
                r = reconcile_mod.reconcile_run(store, t, apply=not dry)
                items.append({"run_id": t, "classification": r.classification,
                              "reason": red.scrub_text(r.reason, alias_of=self.alias_of),
                              "auto_redispatch_allowed": r.auto_redispatch_allowed,
                              "recovery_authority": r.recovery_authority})
            return {"ok": True, "payload": {
                "reconciled": items, "count": len(items), "dry_run": dry,
                "executions_started": 0,
                "scope": "runs created through this transport only",
                "runs_in_scope": len(mine),
                "note": ("Reconciliation CLASSIFIES; it never redispatches and never starts an "
                         "execution. An ambiguous write is a decision for the owner.")}}
        finally:
            store.close()

    # =========================================================================================
    # The program surface (MCP v2). Every handler delegates to core.orchestrator; this adapter
    # adds NO policy -- it narrows inputs, resolves the alias server-side, and redacts output.
    # =========================================================================================
    def _sstore(self):
        from quaestor.core import strategic_store as ss_mod
        return ss_mod.StrategicStore(ss_mod.strategic_path(self.home))

    def _program_config(self, worktree: str):
        from quaestor.projects import config as proj_cfg
        cfg, reason = proj_cfg.load_nearest(worktree)
        return cfg, reason

    def _program_create(self, args: Mapping, *, now=None) -> dict:
        if self.mode != transport_mode.LOCAL_GOVERNED:
            return {"ok": False, "reason": "EXECUTION_MODE_REFUSED",
                    "detail": ("programs execute in %s mode; this deployment is %s"
                               % (transport_mode.LOCAL_GOVERNED, self.mode)),
                    "payload": {"transport_execution_mode": self.mode}}
        from quaestor.core import orchestrator as orch

        worktree = self.repo_table[str(args["repo_alias"])]
        cfg, reason = self._program_config(worktree)
        if cfg is None:
            return {"ok": False, "reason": "PROJECT_CONFIG_MISSING",
                    "detail": red.scrub_text(reason, alias_of=self.alias_of),
                    "payload": {}}
        sstore = self._sstore()
        try:
            pid = orch.create_program(sstore, title=str(args["title"]),
                                      objective=str(args["objective"]),
                                      constraints=[c.strip() for c in
                                                   str(args.get("constraints") or "").split("|")
                                                   if c.strip()],
                                      policy=orch.ProgramPolicy(
                                          max_concurrent_executors=int(
                                              args.get("max_concurrent") or 2)),
                                      actor_id="mcp:strategist")
            sstore.set_program_meta(pid, "repository", cfg.repository)
            sstore.set_program_meta(pid, "project_name", cfg.name)
            sstore.set_program_meta(pid, "project_config", cfg.source_path)
            lane_id = orch.plan_lane(sstore, pid, title=str(args["title"])[:60],
                                     task=str(args["objective"]),
                                     kind=orch.KIND_IMPLEMENTATION,
                                     acceptance=[c.strip() for c in
                                                 str(args.get("acceptance") or "").split("|")
                                                 if c.strip()], actor_id="mcp:strategist")
            return {"ok": True, "payload": {
                "program_id": pid, "lane_id": lane_id, "status": orch.PROGRAM_PLANNED,
                "project": cfg.name, "executor_default": cfg.executor,
                "note": ("the first implementation lane is planned with your objective as its "
                         "task. program_status tick=true (or '%s') starts execution."
                         % branding.command("program serve"))}}
        finally:
            sstore.close()

    def _remote_program_view(self, view: Mapping) -> dict:
        """Allowlist-built remote view of a program. Host paths never appear."""
        rows = []
        for r in view.get("lanes") or ():
            rows.append({k: red.scrub_text(r.get(k), alias_of=self.alias_of)
                         for k in ("lane_id", "title", "kind", "state", "verdict", "actor",
                                   "attempt", "last_run", "summary")})
        agg = dict(view.get("aggregate") or {})
        agg.pop("waiting", None)
        return {"program_id": view.get("program_id"), "title": view.get("title"),
                "status": view.get("status"), "aggregate": agg,
                "lanes": rows, "inbox_count": view.get("inbox_count"),
                "inspected": view.get("inspected")}

    def _program_status(self, args: Mapping, *, now=None) -> dict:
        from quaestor.core import orchestrator as orch
        pid = str(args["program_id"])
        sstore = self._sstore()
        try:
            prog = sstore.get_program(pid)
            if prog is None:
                return self._not_found(pid)
            ticked = None
            if args.get("tick") and self.mode == transport_mode.LOCAL_GOVERNED:
                repo = sstore.get_program_meta(pid).get("repository", "")
                cfg, _reason = self._program_config(repo)
                if cfg is not None:
                    store = self._store()
                    try:
                        report = orch.tick(self.home, sstore, store, program_id=pid, cfg=cfg,
                                           preflight=orch._preflight_for(cfg))
                        ticked = {k: report.get(k) for k in
                                  ("status_in", "status_out", "scheduled", "integration")}
                    finally:
                        store.close()
            view = self._remote_program_view(orch.status_view(sstore, None, pid))
            if ticked:
                view["tick"] = ticked
            return {"ok": True, "payload": view}
        finally:
            sstore.close()

    def _program_inbox(self, args: Mapping, *, now=None) -> dict:
        from quaestor.core import orchestrator as orch
        pid = str(args["program_id"])
        sstore = self._sstore()
        try:
            ib = orch.inbox(sstore, pid)
            if ib["vacuous"]:
                return self._not_found(pid)
            items = [{k: red.scrub_text(i.get(k), alias_of=self.alias_of)
                      for k in ("kind", "message_id", "lane_id", "payload", "route")}
                     for i in ib["items"]]
            return {"ok": True, "payload": {
                "program_id": pid, "status": ib["status"], "items": items,
                "count": len(items),
                "note": ("answer with program_decide. Each item names the message that must be "
                         "answered and who holds authority over the answer.")}}
        finally:
            sstore.close()

    def _program_decide(self, args: Mapping, *, now=None) -> dict:
        from quaestor.core import decisions as dec_mod
        from quaestor.core import messages as msg_mod
        from quaestor.core import orchestrator as orch
        if self.mode != transport_mode.LOCAL_GOVERNED:
            return {"ok": False, "reason": "EXECUTION_MODE_REFUSED",
                    "detail": "decisions apply to programs; this deployment is %s" % self.mode,
                    "payload": {"transport_execution_mode": self.mode}}
        authority = dec_mod.BY_OWNER if str(args.get("authority")) == "OWNER" \
            else dec_mod.BY_STRATEGIST
        if authority == dec_mod.BY_OWNER:
            # A remote caller claiming OWNER gets a RECORDED CLAIM only. Attestation requires
            # the local interactive channel; see core.owner_channel + quaestor.attestation.
            actor = "mcp:owner-claimed"
        else:
            actor = "mcp:strategist"
        pid = str(args["program_id"])
        sstore = self._sstore()
        try:
            if sstore.get_program(pid) is None:
                return self._not_found(pid)
            directive = orch.answer(sstore, pid, str(args["message_id"]),
                                    decision_text=str(args["text"]), rationale="",
                                    authority=authority, actor_id=actor)
            m = sstore.message(str(args["message_id"]))
            routed_owner = (m or {}).get("message_type") in (msg_mod.AUTHORITY_REQUEST,
                                                             msg_mod.OWNER_ESCALATION)
            return {"ok": True, "payload": {
                "program_id": pid, "directive_id": directive, "answered": args["message_id"],
                "authority": authority,
                "owner_attested": False if authority == dec_mod.BY_OWNER else None,
                "note": ("OWNER-authority answers recorded through the transport are durable "
                         "CLAIMS, attested only when made through the local owner channel."
                         if authority == dec_mod.BY_OWNER else
                         "decision recorded; the lane resumes from checkpoint on next tick.")}}
        except ValueError as exc:
            return {"ok": False, "reason": "DECISION_REFUSED",
                    "detail": str(exc), "payload": {"program_id": pid}}
        finally:
            sstore.close()

    def _program_cancel(self, args: Mapping, *, now=None) -> dict:
        from quaestor.core import orchestrator as orch
        pid = str(args["program_id"])
        sstore = self._sstore()
        try:
            if sstore.get_program(pid) is None:
                return self._not_found(pid)
            out = orch.cancel_program(sstore, pid, reason=str(args.get("reason") or ""),
                                      actor_id="mcp:strategist")
            return {"ok": True, "payload": {
                "program_id": pid, **out,
                "note": ("lanes are ABANDONED and the status records why. Completed work and "
                         "evidence remain; nothing was rolled back or deleted.")}}
        finally:
            sstore.close()


def qualification_repo_table(fixture_root: str) -> dict:
    """The P5-A alias table: exactly one disposable fixture, and never the governed repository."""
    return {"qualification-fixture": os.path.abspath(fixture_root).replace("\\", "/")}


def ensure_runs_dir(home: str) -> str:
    return runfiles.ensure(os.path.join(home, "runs"))

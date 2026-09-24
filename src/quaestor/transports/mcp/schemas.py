"""transport_schemas -- closed, versioned, semantic MCP input contracts.

CLOSED MEANS CLOSED
-------------------
Unknown field -> ``SCHEMA_REFUSED``. Unknown schema version -> ``PROTOCOL_REFUSED``. Neither is a
warning and neither is ignored, because an ignored field is how an attacker discovers that a
future field name is already accepted.

THE FIELDS THAT ARE ABSENT ARE THE DESIGN
-----------------------------------------
There is no ``command``, ``argv``, ``executable``, ``shell``, ``docker_args``, ``claude_flags``,
``git``, ``env``, ``sql``, ``path`` or ``worktree_path``. A caller cannot name a host path at all:
it names a REPO ALIAS from a server-side table, and the server resolves it. That inverts the usual
mistake -- validating a path the caller supplied -- into never accepting one.

``authority_profile`` is an enum whose members are decided here and cross-checked against
``authority.PROFILES``; a profile the orchestrator does not know refuses, and a profile the
transport does not admit refuses even when the orchestrator knows it.

WHY VALIDATION IS HAND-WRITTEN
------------------------------
Standard library only, deliberately, and a validator small enough to read is a validator whose
refusals can be reasoned about. It is also the reason every rule below is one named branch: the
control suite asserts each refusal by NAME, which a generic schema engine would flatten into
"validation error".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from quaestor.core import authority as authority_mod
from quaestor.transports.mcp import mode as transport_mode
from quaestor.core.canon import canonical_json, sha256_text

SCHEMA_INSTRUMENT = "transport_schemas/1"

#: The transport's own contract version, independent of the MCP protocol revision. Bumped when a
#: tool's input contract changes shape; the draft-rescan control in P5-A compares this against
#: what ChatGPT reports it can see.
SCHEMA_VERSION = "p5a.1"
SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})

#: ADVERTISEMENT ONLY. Bumped when the published tool METADATA changes -- a description, a title,
#: a `_meta` value -- with no change to any input contract.
#:
#: IT IS DELIBERATELY NOT ``SCHEMA_VERSION``, and that separation is the whole point. That
#: constant is dual-purpose: it is advertised to the client AND it is the request gate
#: (``SUPPORTED_SCHEMA_VERSIONS``). ChatGPT snapshots a draft app's tool definitions, so a client
#: keeps sending the enum value it scanned. Bumping the gated constant would therefore make every
#: call from an un-rescanned snapshot fail ``PROTOCOL_REFUSED`` -- precisely during the window a
#: refresh test exists to observe, and it would read as a transport regression rather than as the
#: intended "the client has not refreshed yet".
#:
#: So: this revision is observable and inert. ``validate()`` never reads it, and a control asserts
#: that a request carrying the OLD advertised schema_version still succeeds after it moves.
TOOL_SURFACE_REVISION = 4

# Refusal reasons
SCHEMA_REFUSED = "SCHEMA_REFUSED"
PROTOCOL_REFUSED = "PROTOCOL_REFUSED"
UNKNOWN_TOOL = "UNKNOWN_TOOL"

# Tools
T_STATUS = "orchestrator_status"
T_RESULT = "orchestrator_result"
T_DISPATCH = "orchestrator_dispatch"
T_CANCEL = "orchestrator_cancel"
T_RECONCILE = "orchestrator_reconcile"
T_PROGRAM_CREATE = "program_create"
T_PROGRAM_STATUS = "program_status"
T_PROGRAM_INBOX = "program_inbox"
T_PROGRAM_DECIDE = "program_decide"
T_PROGRAM_CANCEL = "program_cancel"
#: The retrieval verbs. Named exactly what ChatGPT deep research calls, because a Plus-tier
#: account's connector path speaks ONLY these two -- but they are ordinary governed tools, not a
#: second protocol: same closed schema, same ledger, same redaction scan as everything else.
T_SEARCH = "search"
T_FETCH = "fetch"

TOOLS = (T_STATUS, T_RESULT, T_DISPATCH, T_CANCEL, T_RECONCILE,
         T_PROGRAM_CREATE, T_PROGRAM_STATUS, T_PROGRAM_INBOX, T_PROGRAM_DECIDE,
         T_PROGRAM_CANCEL, T_SEARCH, T_FETCH)

#: Honest mutability classification. These map to MCP tool annotations, and they are what they
#: say: nothing here is mislabelled read-only to avoid a confirmation prompt. Buying a quieter UI
#: with a false annotation would be lying to the only party that can still say no.
READ_ONLY_TOOLS = frozenset({T_STATUS, T_RESULT, T_PROGRAM_STATUS, T_PROGRAM_INBOX,
                             T_SEARCH, T_FETCH})
STATE_MUTATING_TOOLS = frozenset({T_RECONCILE, T_CANCEL, T_PROGRAM_DECIDE, T_PROGRAM_CANCEL})
EXECUTION_CREATING_TOOLS = frozenset({T_DISPATCH, T_PROGRAM_CREATE})


@dataclass(frozen=True)
class Validated:
    ok: bool
    tool: str = ""
    args: Mapping = field(default_factory=dict)
    reason: str = ""
    detail: str = ""
    offending: tuple = ()
    inspected_count: int = 0
    instrument: str = SCHEMA_INSTRUMENT

    def to_dict(self) -> dict:
        return {"ok": self.ok, "tool": self.tool, "reason": self.reason, "detail": self.detail,
                "offending": list(self.offending), "inspected_count": self.inspected_count,
                "instrument": self.instrument}


# ---------------------------------------------------------------------------------------------
# Field tables. (name, type, required, max_len)
# ---------------------------------------------------------------------------------------------
_STR = "string"
_INT = "integer"
_ENUM = "enum"

_COMMON = (("schema_version", _STR, False, 32),)

_FIELDS: Mapping[str, tuple] = {
    T_STATUS: _COMMON + (
        ("run_id", _STR, False, 64),
    ),
    T_RESULT: _COMMON + (
        ("run_id", _STR, True, 64),
    ),
    T_DISPATCH: _COMMON + (
        ("workflow_id", _STR, True, 128),
        ("step_id", _STR, True, 128),
        ("task", _STR, True, 8000),
        ("repo_alias", _ENUM, True, 64),
        ("authority_profile", _ENUM, False, 64),
        ("title", _STR, False, 200),
    ),
    T_CANCEL: _COMMON + (
        ("run_id", _STR, True, 64),
        ("reason", _STR, False, 500),
    ),
    T_RECONCILE: _COMMON + (
        ("run_id", _STR, False, 64),
        ("dry_run", "boolean", False, 0),
    ),
    # ---- the program surface (MCP v2) ----------------------------------------------------------
    # NOTE THE ABSENCES: no executor field, no authority_profile on program tools (lane profiles
    # are decided by LANE KIND in the engine), no paths anywhere. A strategist names WHAT and
    # WHY; the platform decides HOW and WITH WHAT AUTHORITY.
    T_PROGRAM_CREATE: _COMMON + (
        ("title", _STR, True, 200),
        ("objective", _STR, True, 16000),
        ("repo_alias", _ENUM, True, 64),
        ("constraints", _STR, False, 4000),      # '|'-separated; a single string keeps the
        #                                          closed schema scalar-only by design
        ("acceptance", _STR, False, 4000),
        ("max_concurrent", _INT, False, 8),
    ),
    T_PROGRAM_STATUS: _COMMON + (
        ("program_id", _STR, True, 64),
        ("tick", "boolean", False, 0),           # LOCAL_GOVERNED: advance the program too
    ),
    T_PROGRAM_INBOX: _COMMON + (
        ("program_id", _STR, True, 64),
    ),
    T_PROGRAM_DECIDE: _COMMON + (
        ("program_id", _STR, True, 64),
        ("message_id", _STR, True, 80),
        ("text", _STR, True, 8000),
        ("authority", _ENUM, False, 16),
    ),
    T_PROGRAM_CANCEL: _COMMON + (
        ("program_id", _STR, True, 64),
        ("reason", _STR, False, 500),
    ),
    # ---- the retrieval surface -----------------------------------------------------------------
    # A query is DATA, the same way a task is: it selects what to read back and can do nothing
    # else. ``id`` accepts only plain identifiers -- the same shape run_id already had -- so a
    # path or URL cannot smuggle itself into a lookup field.
    T_SEARCH: _COMMON + (
        ("query", _STR, True, 200),
    ),
    T_FETCH: _COMMON + (
        ("id", _STR, True, 64),
    ),
}

#: Field names that must NEVER be accepted by any tool, even if a future edit adds them to a
#: table above. A denylist beside the allowlist is redundant on purpose: the allowlist is the
#: mechanism, and this is the tripwire that fires if someone widens it without thinking.
FORBIDDEN_FIELDS = frozenset({
    "command", "cmd", "argv", "args", "shell", "exec", "executable", "script", "code",
    "docker", "docker_args", "container", "image", "claude_flags", "flags", "claude_path",
    "git", "git_command", "sql", "env", "environment", "path", "worktree",
    "worktree_path", "cwd", "file", "filename", "url", "executor", "owner_grant", "grant",
    "owner_approval", "approved", "capabilities", "required_capabilities", "spawn",
    "transport_mode", "dispatch_key", "run_nonce", "model", "timeout_s", "prompt",
    # NOT LISTED: "query". The retrieval verb's field of that name is free-text DATA matched in
    # Python against already-fetched rows -- it never reaches SQL (store access is parameterized
    # and fixed), exactly the class of caller text `task` already is. The deep-research contract
    # names the field `query`; banning the word would break the one read path a Plus-tier
    # connector is allowed while protecting nothing the allowlist does not already protect.
})


def repo_aliases(table: Mapping[str, str] | None = None) -> tuple:
    """The alias names a caller may use. The VALUES (host paths) never leave the server."""
    return tuple(sorted((table or {}).keys()))


def authority_profile_enum(mode: str | None = None) -> tuple:
    """Profiles the transport admits, intersected with profiles the orchestrator defines.

    The INTERSECTION matters: a name in only one of the two is a bug in whichever list is stale,
    and admitting it would mean the transport advertising an authority the engine cannot honour
    (or worse, honouring one the transport never reviewed).

    ``mode`` selects WHICH transport allowlist applies. Absent, it falls back to the module
    default (QUALIFICATION_ONLY) -- so every existing caller keeps its exact behaviour, and an
    operational deployment passes its RESOLVED mode explicitly rather than inheriting whatever a
    module constant says.
    """
    if str(mode or "") == transport_mode.LOCAL_GOVERNED:
        allowed = transport_mode.OPERATIONAL_AUTHORITY_PROFILES
    else:
        allowed = transport_mode.ALLOWED_AUTHORITY_PROFILES
    return tuple(sorted(set(allowed) & set(authority_mod.PROFILES)))


def validate(tool: str, args: Any, *, repo_table: Mapping[str, str] | None = None,
             mode: str | None = None) -> Validated:
    """Validate one tools/call payload. PURE. NEVER raises.

    Order matters and is asserted by controls: unknown TOOL first (cheapest, and it must not leak
    whether a run exists), then version, then unknown fields, then missing, then types/values.

    ``mode`` is the deployment's RESOLVED transport mode. It only ever NARROWS: the enum for
    ``authority_profile`` is the intersection of the mode's allowlist and the engine's profiles.
    """
    inspected = 0

    if tool not in TOOLS:
        return Validated(False, str(tool), reason=UNKNOWN_TOOL,
                         detail="no such tool; this server exposes exactly %s" % (list(TOOLS),),
                         inspected_count=1)

    if args is None:
        args = {}
    if not isinstance(args, Mapping):
        return Validated(False, tool, reason=SCHEMA_REFUSED,
                         detail="arguments must be an object, got %s" % type(args).__name__,
                         inspected_count=1)

    spec = _FIELDS[tool]
    known = {name for name, _t, _r, _m in spec}

    # PRESENT MEANS CHECKED. `args.get(...) or DEFAULT` silently accepted "", 0 and null as
    # "unspecified", so a caller could send schema_version="" and skip the version gate entirely.
    # An absent key defaults; a present key is validated as written.
    version = SCHEMA_VERSION if "schema_version" not in args else str(args["schema_version"])
    inspected += 1
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        return Validated(False, tool, reason=PROTOCOL_REFUSED,
                         detail="schema_version %r is not supported; this server speaks %s"
                                % (version, sorted(SUPPORTED_SCHEMA_VERSIONS)),
                         offending=("schema_version",), inspected_count=inspected)

    unknown = sorted(set(args) - known)
    inspected += len(args)
    if unknown:
        forbidden = sorted(set(unknown) & FORBIDDEN_FIELDS)
        return Validated(False, tool, reason=SCHEMA_REFUSED,
                         detail=("unknown field(s) %s; this schema is closed%s"
                                 % (unknown,
                                    (" and %s can never be accepted by any tool" % forbidden)
                                    if forbidden else "")),
                         offending=tuple(unknown), inspected_count=inspected)

    out = {}
    for name, kind, required, maxlen in spec:
        inspected += 1
        if name not in args:
            if required:
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail="missing required field %r" % name,
                                 offending=(name,), inspected_count=inspected)
            continue
        v = args[name]
        if kind == "boolean":
            if not isinstance(v, bool):
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail="%r must be a boolean" % name, offending=(name,),
                                 inspected_count=inspected)
            out[name] = v
            continue
        if kind == _INT:
            if not isinstance(v, int) or isinstance(v, bool):
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail="%r must be an integer" % name, offending=(name,),
                                 inspected_count=inspected)
            out[name] = v
            continue
        if not isinstance(v, str):
            return Validated(False, tool, reason=SCHEMA_REFUSED,
                             detail="%r must be a string" % name, offending=(name,),
                             inspected_count=inspected)
        if len(v) > maxlen:
            return Validated(False, tool, reason=SCHEMA_REFUSED,
                             detail="%r exceeds its %d character limit" % (name, maxlen),
                             offending=(name,), inspected_count=inspected)
        if name == "repo_alias":
            if v not in (repo_table or {}):
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail=("unknown repo_alias %r; permitted aliases are %s. A "
                                         "host path is never accepted from a caller."
                                         % (v, list(repo_aliases(repo_table)))),
                                 offending=(name,), inspected_count=inspected)
        if name in ("program_id", "message_id", "id") and not _looks_like_id(v):
            return Validated(False, tool, reason=SCHEMA_REFUSED,
                             detail="%s must be a plain identifier" % name,
                             offending=(name,), inspected_count=inspected)
        if name == "authority":
            if v not in ("STRATEGIST", "OWNER"):
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail="authority %r must be STRATEGIST or OWNER" % v,
                                 offending=(name,), inspected_count=inspected)
        if name == "authority_profile":
            allowed = authority_profile_enum(mode)
            if v not in allowed:
                return Validated(False, tool, reason=SCHEMA_REFUSED,
                                 detail=("authority_profile %r is not admitted; permitted: %s"
                                         % (v, list(allowed))),
                                 offending=(name,), inspected_count=inspected)
        if name == "run_id" and not _looks_like_id(v):
            return Validated(False, tool, reason=SCHEMA_REFUSED,
                             detail="run_id must be a plain identifier",
                             offending=(name,), inspected_count=inspected)
        out[name] = v

    out.setdefault("schema_version", SCHEMA_VERSION)
    if tool == T_DISPATCH:
        out.setdefault("authority_profile", authority_mod.READ_ONLY)
    return Validated(True, tool, out, inspected_count=inspected)


def _looks_like_id(v: str) -> bool:
    """Identifiers only. Keeps path/URL/SQL shapes out of a field used for lookup."""
    return bool(v) and all(c.isalnum() or c in "-_" for c in v)


def tool_definitions(*, repo_table: Mapping[str, str] | None = None,
                     mode: str | None = None) -> list:
    """The MCP ``tools/list`` payload. PURE.

    Descriptions state what each tool CAN CAUSE, in this mode. ``orchestrator_dispatch`` says
    plainly what its resolved mode permits -- an accurate description is not the same as a
    read-only annotation, and it does not get one.
    """
    aliases = list(repo_aliases(repo_table))
    profiles = list(authority_profile_enum(mode))
    eff_mode = str(mode or transport_mode.TRANSPORT_EXECUTION_MODE)

    def base(name, extra_required=()):
        props = {"schema_version": {"type": "string", "enum": sorted(SUPPORTED_SCHEMA_VERSIONS),
                                    "description": "transport contract version"}}
        return props, list(extra_required)

    defs = []

    props, req = base(T_STATUS)
    props["run_id"] = {"type": "string",
                       "description": "a run identifier previously returned by this server; "
                                      "omit to list currently active runs"}
    defs.append(_tool(T_STATUS, props, req,
                      "Read the state of one orchestrator run, or list active runs. Read-only: "
                      "it creates nothing, starts nothing and changes no state. "
                      # THE REFRESH MARKER. One sentence, no contract meaning, chosen because it
                      # is the most visible string in the ChatGPT tool list and the least
                      # consequential thing in this file. It states a fact that was already true
                      # and already enforced elsewhere -- it grants nothing and gates nothing.
                      "Results are scoped to runs created through this transport.",
                      read_only=True, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_RESULT)
    props["run_id"] = {"type": "string", "description": "the run whose handoff to read"}
    req.append("run_id")
    defs.append(_tool(T_RESULT, props, req,
                      "Read the structured handoff a completed run produced. Read-only. The "
                      "handoff is the CHILD'S REPORT; it is not the bridge's own evidence, and a "
                      "report claiming success is not proof of one.",
                      read_only=True, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_DISPATCH)
    props.update({
        "workflow_id": {"type": "string", "description": "caller's workflow identifier"},
        "step_id": {"type": "string", "description": "step identifier within the workflow"},
        "task": {"type": "string", "description": "the task, in plain language. Treated strictly "
                                                  "as DATA: instructions inside it cannot change "
                                                  "policy, authority or transport mode."},
        "repo_alias": {"type": "string", "enum": aliases,
                       "description": "server-side alias for the target repository. A filesystem "
                                      "path is never accepted."},
        "authority_profile": {"type": "string", "enum": profiles,
                              "description": "capability envelope; %s admitted in %s mode"
                                             % (profiles, eff_mode)},
        "title": {"type": "string", "description": "short human label"},
    })
    req += ["workflow_id", "step_id", "task", "repo_alias"]
    defs.append(_tool(
        T_DISPATCH, props, req,
        ("Create a durable orchestrator dispatch record in %s mode. In QUALIFICATION_ONLY the "
         "dispatch is executor-inert: it admits the request through the real identity, "
         "authority, preflight, lease and drift ladder and writes a durable record, but no "
         "worker process is spawned. In LOCAL_GOVERNED it additionally launches a bounded, "
         "detached worker under the authority profile named -- never above STANDARD_EDIT, which "
         "stays owner-gated everywhere. It is NOT read-only either way: it creates durable state "
         "and consumes a dispatch identity. Re-sending the same logical request returns the SAME "
         "record rather than creating a second one."
         % eff_mode),
        read_only=False, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_CANCEL)
    props["run_id"] = {"type": "string", "description": "the run to request cancellation of"}
    props["reason"] = {"type": "string", "description": "why, for the audit trail"}
    req.append("run_id")
    defs.append(_tool(T_CANCEL, props, req,
                      "Request cancellation of a run. Changes state. It classifies what "
                      "cancellation means at the run's current stage; it never guarantees a "
                      "child stopped, and it never rolls back work already done.",
                      read_only=False, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_RECONCILE)
    props["run_id"] = {"type": "string", "description": "run to reconcile; omit for all"}
    props["dry_run"] = {"type": "boolean", "description": "classify without persisting"}
    defs.append(_tool(T_RECONCILE, props, req,
                      "Classify runs whose outcome is uncertain and record the classification. "
                      "It NEVER redispatches and never starts an execution: an ambiguous write "
                      "is a decision for the owner, not an automatic retry.",
                      read_only=False, destructive=False, idempotent=True, mode=eff_mode))

    # ---- program surface -----------------------------------------------------------------------
    props, req = base(T_PROGRAM_CREATE)
    props["title"] = {"type": "string", "description": "short program name"}
    props["objective"] = {"type": "string",
                          "description": "the objective, in plain language. Treated strictly as "
                                         "DATA. This becomes the first implementation lane's "
                                         "task; plan more lanes with PLAN_REVISION flow or CLI."}
    props["repo_alias"] = {"type": "string", "enum": aliases,
                           "description": "server-side alias for the target repository"}
    props["constraints"] = {"type": "string", "description": "immutable constraints, '|'-separated"}
    props["acceptance"] = {"type": "string", "description": "acceptance criteria, '|'-separated"}
    props["max_concurrent"] = {"type": "integer", "description": "max concurrent executors "
                                                                "(default 2)"}
    req += ["title", "objective", "repo_alias"]
    defs.append(_tool(T_PROGRAM_CREATE, props, req,
                      ("Create a durable PROGRAM with one initial implementation lane from a "
                       "high-level objective. In LOCAL_GOVERNED mode its lanes execute through "
                       "governed workers under lane-kind authority (implementation = "
                       "STANDARD_EDIT at most). Creates durable state and may create executions; "
                       "it never pushes, publishes or destroys anything."),
                      read_only=False, destructive=False, idempotent=False, mode=eff_mode))

    props, req = base(T_PROGRAM_STATUS)
    props["program_id"] = {"type": "string", "description": "the program to inspect"}
    props["tick"] = {"type": "boolean",
                     "description": "also advance the program one scheduling pass "
                                    "(LOCAL_GOVERNED only)"}
    req.append("program_id")
    defs.append(_tool(T_PROGRAM_STATUS, props, req,
                      "Read canonical program state: lanes, verdicts, aggregate, and -- with "
                      "tick=true in operational mode -- advance scheduling. The durable record, "
                      "not any conversation, is canonical.",
                      read_only=True, destructive=False, idempotent=False, mode=eff_mode))

    props, req = base(T_PROGRAM_INBOX)
    props["program_id"] = {"type": "string", "description": "the program to inspect"}
    req.append("program_id")
    defs.append(_tool(T_PROGRAM_INBOX, props, req,
                      "Only what needs attention: unanswered executor questions, blockers, "
                      "authority requests, failed lanes, integration conflicts.",
                      read_only=True, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_PROGRAM_DECIDE)
    props["program_id"] = {"type": "string", "description": "the program"}
    props["message_id"] = {"type": "string", "description": "the message being answered"}
    props["text"] = {"type": "string", "description": "the binding answer/directive"}
    props["authority"] = {"type": "string", "enum": ["STRATEGIST", "OWNER"],
                          "description": "whose decision this records; OWNER requires the "
                                         "attested owner channel"}
    req += ["program_id", "message_id", "text"]
    defs.append(_tool(T_PROGRAM_DECIDE, props, req,
                      "Answer an executor question or record a decision. Persists a DIRECTIVE "
                      "and a decision-ledger row; the waiting lane resumes from its checkpoint "
                      "on the next tick. Recording a decision grants no capability by itself.",
                      read_only=False, destructive=False, idempotent=False, mode=eff_mode))

    props, req = base(T_PROGRAM_CANCEL)
    props["program_id"] = {"type": "string", "description": "the program to cancel"}
    props["reason"] = {"type": "string", "description": "why, for the audit trail"}
    req.append("program_id")
    defs.append(_tool(T_PROGRAM_CANCEL, props, req,
                      "Cancel every non-terminal lane of a program. Records the cancellation; "
                      "it cannot un-run work that already happened and rolls nothing back.",
                      read_only=False, destructive=False, idempotent=True, mode=eff_mode))

    # ---- the retrieval surface -----------------------------------------------------------------
    # Shaped for ChatGPT deep research (which calls ONLY these two verbs) and for any caller
    # that benefits from one round trip over tools/list + orchestrator_status. Read-only, in
    # scope of THIS transport's ledger, and redaction-scanned like everything else.
    props, req = base(T_SEARCH)
    props["query"] = {"type": "string",
                      "description": "plain words matched against run and program identifiers, "
                                     "titles, objectives and states"}
    req.append("query")
    defs.append(_tool(T_SEARCH, props, req,
                      "Search this control plane's own runs and programs for identifiers worth "
                      "fetching. Read-only: it reads recorded state and returns matches with "
                      "their ids. Results are scoped to runs this transport created.",
                      read_only=True, destructive=False, idempotent=True, mode=eff_mode))

    props, req = base(T_FETCH)
    props["id"] = {"type": "string",
                   "description": "a run identifier previously returned by this server"}
    req.append("id")
    defs.append(_tool(T_FETCH, props, req,
                      "Read one run's complete record: the child's report, the independent "
                      "evidence measured beside it, and the execution state. Read-only. The "
                      "report is a CLAIM; the evidence is the MEASUREMENT.",
                      read_only=True, destructive=False, idempotent=True, mode=eff_mode))
    return defs


def _tool(name, props, required, description, *, read_only, destructive, idempotent,
          mode: str | None = None) -> dict:
    return {
        "name": name,
        "title": name.replace("orchestrator_", "Orchestrator ").replace("_", " "),
        "description": description,
        "inputSchema": {"type": "object", "properties": props,
                        "required": sorted(set(required)), "additionalProperties": False},
        "annotations": {"readOnlyHint": bool(read_only), "destructiveHint": bool(destructive),
                        "idempotentHint": bool(idempotent), "openWorldHint": False},
        "_meta": {"transport_schema_version": SCHEMA_VERSION,
                  "tool_surface_revision": TOOL_SURFACE_REVISION,
                  "transport_execution_mode": str(mode or transport_mode.TRANSPORT_EXECUTION_MODE)},
    }


def tool_surface_fingerprint(defs: Sequence[Mapping] | None = None, *,
                             repo_table: Mapping[str, str] | None = None) -> dict:
    """A digest of the PUBLISHED tool surface, declaring what it measured. PURE.

    This is the refresh test's instrument, so it obeys the same rule as every other gate here: it
    emits counts, and a fingerprint over nothing is VACUOUS rather than a clean-looking digest.

    It covers exactly what a client scans -- names, titles, descriptions, input schemas,
    annotations and `_meta`. It deliberately does NOT cover the repo alias table's VALUES, which
    are host paths: a fingerprint that changes when the operator moves a directory would report
    "the published surface changed" for something no client can see.
    """
    defs = list(defs if defs is not None else tool_definitions(repo_table=repo_table))
    payload = canonical_json(defs)
    props = sum(len(d.get("inputSchema", {}).get("properties", {})) for d in defs)
    return {
        "digest": sha256_text(payload),
        "tool_surface_revision": TOOL_SURFACE_REVISION,
        "transport_schema_version": SCHEMA_VERSION,
        "tools": [str(d.get("name")) for d in defs],
        "inspected_tools": len(defs),
        "inspected_properties": props,
        "measured_bytes": len(payload),
        "vacuous": not defs,
        "scope": ("name, title, description, inputSchema, annotations and _meta of every "
                  "published tool; NOT host paths"),
        "instrument": SCHEMA_INSTRUMENT,
    }


def mutability(tool: str) -> str:
    if tool in READ_ONLY_TOOLS:
        return "READ_ONLY"
    if tool in EXECUTION_CREATING_TOOLS:
        return "EXECUTION_CREATING"
    if tool in STATE_MUTATING_TOOLS:
        return "STATE_MUTATING"
    return "UNKNOWN"


def declared_tool_names(defs: Sequence[Mapping]) -> tuple:
    return tuple(str(d.get("name")) for d in defs)

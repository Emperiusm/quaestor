"""planner -- the PLANNER seat: PLAN_PROPOSAL admission, challenge and adoption.

WHAT THIS MODULE IS (PRD.md §7.4)
---------------------------------
The planner is just another governed role -- it "does not receive a capability lattice merely
because it is strategically important". An LLM in the planner seat emits a PLAN_PROPOSAL --
proposed lanes, tasks, dependencies, acceptance criteria. The proposal is DATA: admission here is
a PURE, deterministic validation (legal lane kinds, acyclic dependencies, acceptance present, size
bounds, no authority embedded outside the governed vocabulary). Adoption is a separate recorded
strategist/owner DECISION carrying planner provenance. THE INVARIANT IS ONE LINE: the planner
proposes, Quaestor disposes. A planner that could adopt, execute or approve its own plan would not
be a planner; it would be an ungoverned controller wearing one.

VOCABULARY DECISION FOR THE PROPOSAL PACKET (deliberate, documented)
--------------------------------------------------------------------
The issue offered two routings for "validated proposal reaches the strategist inbox":
an OBSERVATION with meta, or a deliberate extension of the closed vocabulary. We chose NEITHER
envelope change, for one structural reason: the qualified message contract REQUIRES every message
to belong to a lane (core.messages.validate refuses an empty lane_id), and a PRE-ADOPTION proposal
belongs to no lane -- inventing one would break the contract that _record_blocker already documents
("inventing a fake lane would be worse than using the channel built for program facts"). Instead:

  * ON THE WIRE the planner emits its proposal through the EXISTING governed type PLAN_REVISION
    ("the plan should change; here is the proposed change"), riding detail.proposal -- no new
    executor-emittable type, so the child-facing vocabulary stays exactly as frozen;
  * ON THE STRATEGIST SURFACE the pending proposal appears in orchestrator.inbox() under the
    dedicated item kind ``PROPOSAL_PENDING_ADOPTION``, following the established program-level
    item precedent (INTEGRATION_CONFLICT, which also carries lane_id ""). The inbox IS the
    strategist queue; extending ITS vocabulary is the deliberate extension, and it is the only
    place an adoption decision can be surfaced without forging a lane.

ADOPTION PATH
-------------
Only strategist/owner action adopts (the CLI ``program adopt`` command or a direct call with a
human actor id). The planner's own actor identity ("executor:<provider>", the same convention the
worker uses for executor messages) is refused at the adoption door: PROPOSAL_PLANNER_SELF_ADOPT.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from quaestor.core.canon import sha256_obj
from quaestor.core.canon import canonical_json

PLANNER_INSTRUMENT = "planner/1"

PROPOSAL_SCHEMA_VERSION = 1

# ---- named refusal paths ----------------------------------------------------------------------
PROPOSAL_INVALID = "PROPOSAL_INVALID"
PROPOSAL_CYCLE = "PROPOSAL_CYCLE"
PROPOSAL_UNKNOWN_KIND = "PROPOSAL_UNKNOWN_KIND"
PROPOSAL_AUTHORITY_FIELD = "PROPOSAL_AUTHORITY_FIELD"
PROPOSAL_UNKNOWN_FIELD = "PROPOSAL_UNKNOWN_FIELD"
PROPOSAL_EMPTY = "PROPOSAL_EMPTY"
PROPOSAL_NOT_PENDING = "PROPOSAL_ALREADY_DECIDED"
PROPOSAL_PLANNER_SELF_ADOPT = "PROPOSAL_PLANNER_SELF_ADOPT"
PROPOSAL_BLOCKED_BY_FINDINGS = "PROPOSAL_BLOCKED_BY_FINDINGS"

# ---- the schema, enforced structurally --------------------------------------------------------
#: Closed top-level shape. Anything else is refused BY NAME below -- a closed shape is what turns
#: "no authority-bearing fields" from a promise into a property: an authority claim has nowhere to
#: sit that validation would accept.
TOP_LEVEL_KEYS = ("title", "objective", "lanes")

#: Closed per-lane shape. ``plan_review`` is a POLICY REQUEST (per-lane plan challenge, section
#: 3.3), not authority: it can only cause MORE scrutiny of the proposer's own plan.
LANE_KEYS = ("key", "title", "task", "kind", "depends_on", "acceptance", "plan_review")

#: Keys whose NAME carries an authority claim. Present at any level -> refused with
#: PROPOSAL_AUTHORITY_FIELD rather than the generic unknown-field error, because "typo" and
#: "power grab" deserve different entries in the record.
AUTHORITY_FIELD_NAMES = frozenset({
    "authority", "authority_profile", "capabilities", "grants", "permissions", "profile",
    "owner", "owner_approval", "auto_adopt", "auto_approve", "write_capable", "requires_write",
    "elevate", "escalate_authority",
})

#: All five lane kinds are legal in a proposal, INCLUDING integration: a planner may decompose a
#: program that ends in a governed integration lane. Legality here is about SCHEMA; every kind
#: still runs under PROFILE_FOR_KIND at dispatch, so proposing "integration" grants nothing.
ALLOWED_LANE_KINDS_ALL = True

# ---- size bounds ------------------------------------------------------------------------------
MAX_LANES = 64
MAX_KEY_CHARS = 80
MAX_TITLE_CHARS = 200
MAX_TASK_CHARS = 8000
MAX_ACCEPTANCE_PER_LANE = 32
MAX_ACCEPTANCE_CHARS = 500
MAX_DEPENDS_PER_LANE = 16


def _is_str(v) -> bool:
    return isinstance(v, str)


def _check_keys(where: str, doc: Mapping, allowed: Sequence[str], errors: list) -> None:
    """Closed-shape key check for one mapping level. PURE; appends named errors."""
    for k in sorted(str(k) for k in doc):
        if k in allowed:
            continue
        if k in AUTHORITY_FIELD_NAMES:
            errors.append(
                "%s: field %r on %s carries authority outside the governed message "
                "vocabulary; proposals are DATA and cannot widen any envelope"
                % (PROPOSAL_AUTHORITY_FIELD, k, where))
        else:
            errors.append("%s: unknown field %r on %s (allowed: %s)"
                          % (PROPOSAL_UNKNOWN_FIELD, k, where, list(allowed)))


def validate_plan_proposal(doc) -> tuple:
    """(ok, errors). PURE. NEVER raises.

    Deterministic validation, in a fixed order so the SAME defective proposal always yields the
    SAME error list: envelope shape -> closed keys -> lane count/keys -> scalar bounds -> kinds ->
    acceptance presence -> dependency references -> acyclicity. Errors are prefixed with their
    named refusal so callers and tests can assert the PATH, not just the boolean.
    """
    errors: list = []
    if not isinstance(doc, Mapping):
        return False, ["%s: proposal must be a JSON object" % PROPOSAL_INVALID]
    _check_keys("proposal", doc, TOP_LEVEL_KEYS, errors)

    lanes = doc.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        return (False, errors + ["%s: lanes must be a non-empty array" % PROPOSAL_EMPTY])
    if len(lanes) > MAX_LANES:
        errors.append("%s: %d lanes exceeds the bound of %d"
                      % (PROPOSAL_INVALID, len(lanes), MAX_LANES))

    keys_seen: dict = {}
    shapes: list = []
    for i, lane in enumerate(lanes):
        where = "lanes[%d]" % i
        if not isinstance(lane, Mapping):
            errors.append("%s: each lane must be an object" % PROPOSAL_INVALID)
            continue
        _check_keys(where, lane, LANE_KEYS, errors)
        key = lane.get("key")
        if not _is_str(key) or not key.strip():
            errors.append("%s: key is required and must be a non-empty string" % where)
        elif key in keys_seen:
            errors.append("%s: duplicate lane key %r (first seen on lanes[%d])"
                          % (where, key, keys_seen[key]))
        else:
            keys_seen[key] = i
        title = lane.get("title")
        if not _is_str(title) or not title.strip():
            errors.append("%s: title is required" % where)
        elif len(title) > MAX_TITLE_CHARS:
            errors.append("%s: title exceeds %d characters" % (where, MAX_TITLE_CHARS))
        task = lane.get("task")
        if not _is_str(task) or not task.strip():
            errors.append("%s: task is required" % where)
        elif len(task) > MAX_TASK_CHARS:
            errors.append("%s: task exceeds %d characters" % (where, MAX_TASK_CHARS))
        kind = lane.get("kind")
        if not _is_str(kind) or not kind.strip():
            errors.append("%s: kind is required" % where)
        shapes.append((where, lane))

    if all(_is_str(lane.get("kind")) and lane.get("kind") for _, lane in shapes):
        from quaestor.core import orchestrator as orch  # lazy: orch lazily imports this module
        for where, lane in shapes:
            if lane.get("kind") not in orch.LANE_KINDS:
                errors.append("%s: %s: unknown lane kind %r; legal kinds are %s"
                              % (PROPOSAL_UNKNOWN_KIND, where, lane.get("kind"),
                                 list(orch.LANE_KINDS)))
            acc = lane.get("acceptance")
            if lane.get("kind") == orch.KIND_IMPLEMENTATION:
                if not isinstance(acc, list) or not acc:
                    errors.append(
                        "%s: %s: acceptance criteria are required and non-empty for an "
                        "implementation lane" % (PROPOSAL_INVALID, where))

    for where, lane in shapes:
        acc = lane.get("acceptance", [])
        if acc is None:
            continue
        if not isinstance(acc, list):
            errors.append("%s: acceptance must be an array of strings" % where)
            continue
        if len(acc) > MAX_ACCEPTANCE_PER_LANE:
            errors.append("%s: acceptance exceeds %d entries" % (where, MAX_ACCEPTANCE_PER_LANE))
        for j, a in enumerate(acc):
            if not _is_str(a) or not a.strip():
                errors.append("%s: acceptance[%d] must be a non-empty string" % (where, j))
            elif len(a) > MAX_ACCEPTANCE_CHARS:
                errors.append("%s: acceptance[%d] exceeds %d characters"
                              % (where, j, MAX_ACCEPTANCE_CHARS))
        deps = lane.get("depends_on", [])
        if deps is None:
            continue
        if not isinstance(deps, list) or any(not _is_str(d) or not d.strip() for d in deps):
            errors.append("%s: depends_on must be an array of lane keys" % where)
            continue
        if len(deps) > MAX_DEPENDS_PER_LANE:
            errors.append("%s: depends_on exceeds %d entries" % (where, MAX_DEPENDS_PER_LANE))
        for d in deps:
            if d not in keys_seen:
                errors.append("%s: depends_on references unknown lane key %r" % (where, d))

    errors.extend(_cycle_errors(shapes))
    return (not errors), errors


def _cycle_errors(shapes: list) -> list:
    """Kahn topo over depends_on edges; a residue IS a cycle. PURE. Names the involved keys."""
    keys = {lane.get("key") for _, lane in shapes if _is_str(lane.get("key"))}
    edges: dict = {}
    for _, lane in shapes:
        key = lane.get("key")
        if not _is_str(key):
            continue
        deps = lane.get("depends_on")
        edges[key] = [d for d in (deps if isinstance(deps, list) else ())
                      if d in keys] if isinstance(deps, list) else []
    indeg = {k: 0 for k in edges}
    for k, ds in edges.items():
        for d in ds:
            indeg[k] += 1
    queue = sorted([k for k, n in indeg.items() if n == 0])
    seen = []
    while queue:
        n = queue.pop(0)
        seen.append(n)
        for k, ds in sorted(edges.items()):
            if n in ds and k not in seen and k not in queue:
                indeg[k] -= 1
                if indeg[k] == 0:
                    queue.append(k)
    stuck = sorted(set(edges) - set(seen))
    if not stuck:
        return []
    return ["%s: dependency cycle detected involving %s; a proposed plan must be a DAG "
            "(section 3.1: admission is deterministic)" % (PROPOSAL_CYCLE, stuck)]


# ---------------------------------------------------------------------------------------------
# Pending-proposal document (durable, program_meta; server-side like every underscore key)
# ---------------------------------------------------------------------------------------------
PROPOSAL_META_KEY = "_plan_proposal_json"
PLANNER_RUN_META_KEY = "_planner_run_id"
CHALLENGE_RUN_META_KEY = "_plan_challenge_run_id"

STATUS_PENDING = "PENDING"
STATUS_ADOPTED = "ADOPTED"
STATUS_REFUSED = "REFUSED"


def proposal_digest(proposal: Mapping) -> str:
    """Content digest of a proposal. PURE. Two proposals are THE SAME iff this matches."""
    return sha256_obj(dict(proposal))


def load_proposal_doc(sstore, program_id: str) -> dict | None:
    """The stored proposal document, or None. Impure (reads)."""
    import json
    raw = sstore.get_program_meta(program_id).get(PROPOSAL_META_KEY)
    if not raw:
        return None
    try:
        v = json.loads(raw)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def pending_proposal(sstore, program_id: str) -> dict | None:
    """The PENDING proposal document, or None. Impure."""
    doc = load_proposal_doc(sstore, program_id)
    if doc and doc.get("status") == STATUS_PENDING:
        return doc
    return None


def save_proposal_doc(sstore, program_id: str, doc: Mapping) -> None:
    import json
    sstore.set_program_meta(program_id, PROPOSAL_META_KEY,
                            canonical_json(dict(doc)))


def new_proposal_doc(*, proposal: Mapping, planner_provenance: Mapping,
                     require_plan_review: bool = True) -> dict:
    """Fresh PENDING document around a validated proposal. PURE."""
    return {
        "schema_version": PROPOSAL_SCHEMA_VERSION,
        "status": STATUS_PENDING,
        "digest": proposal_digest(proposal),
        "proposal": dict(proposal),
        "planner_provenance": dict(planner_provenance or {}),
        "require_plan_review": bool(require_plan_review),
        "findings": [],
        "review_runs": [],
        "lane_map": {},
        "decision_id": "",
        "adopted_by": "",
    }


# ---------------------------------------------------------------------------------------------
# Adoption -- the strategist/owner DECISION
# ---------------------------------------------------------------------------------------------
def adopt_plan_proposal(sstore, program_id: str, proposal: Mapping, planner_provenance: Mapping,
                        adopted_by_actor: str, *, authority: str = "", now=None) -> dict:
    """Adopt a validated proposal: create its lanes, record the DECISION. Impure.

    Returns {"ok": True, "lane_ids": {key: lane_id}, "decision_id": ...} or
    {"ok": False, "refusal": <NAMED>, "detail": ...}. Refusals, in order of check:
      invalid proposal -> planner self-adoption -> already decided -> blocking findings.
    Adoption is the one moment the proposal gains existence; the DECISION carries the planner's
    provenance so the record shows WHOSE plan was adopted, not merely THAT one was.
    """
    from quaestor.core import decisions as dec_mod
    from quaestor.core import orchestrator as orch
    from quaestor.core import programs as prog_mod
    ok, errors = validate_plan_proposal(proposal)
    if not ok:
        return {"ok": False, "refusal": _named(errors), "detail": "; ".join(errors)}
    prov = dict(planner_provenance or {})
    actor = str(adopted_by_actor or "").strip()
    if not actor:
        return {"ok": False, "refusal": PROPOSAL_PLANNER_SELF_ADOPT,
                "detail": "adoption requires a named strategist/owner actor"}
    planner_actor = str(prov.get("actor_id") or "")
    if actor == planner_actor or (planner_actor and actor.endswith(str(prov.get("provider") or "@@"))
                                  and actor.startswith("executor:")):
        return {"ok": False, "refusal": PROPOSAL_PLANNER_SELF_ADOPT,
                "detail": ("%s holds the planner seat and cannot adopt its own proposal; "
                           "the planner proposes, Quaestor disposes (section 3.1)" % planner_actor)}

    digest = proposal_digest(proposal)
    doc = load_proposal_doc(sstore, program_id)
    carried = None
    if doc is not None:
        if doc.get("digest") == digest and doc.get("status") == STATUS_ADOPTED:
            return {"ok": False, "refusal": PROPOSAL_NOT_PENDING,
                    "detail": "this exact proposal was already adopted (%s)" % doc.get("decision_id")}
        if doc.get("digest") == digest and doc.get("status") == STATUS_PENDING:
            carried = doc
    if carried is not None:
        blocking = [f for f in (carried.get("findings") or [])
                    if not f.get("resolved") and f.get("severity") in ("CRITICAL", "HIGH")]
        if blocking and carried.get("require_plan_review", True):
            return {"ok": False, "refusal": PROPOSAL_BLOCKED_BY_FINDINGS,
                    "detail": "%d unresolved plan-challenge finding(s): %s"
                              % (len(blocking), ", ".join(sorted(f.get("finding_id", "?")
                                                                 for f in blocking)))}

    # Create ALL lanes first, then wire dependencies between REAL lane ids -- depends_on keys are
    # proposal-local, lane ids are global, and only a second pass can join them.
    lane_ids: dict = {}
    for lane in proposal["lanes"]:
        lid = orch.plan_lane(
            sstore, program_id, title=str(lane.get("title") or lane.get("key")),
            task=str(lane.get("task")), kind=str(lane.get("kind")),
            acceptance=[str(a) for a in (lane.get("acceptance") or ())],
            actor_id=actor)
        lane_ids[str(lane["key"])] = lid
    for lane in proposal["lanes"]:
        for dep in (lane.get("depends_on") or ()):
            sstore.add_dependency(prog_mod.Dependency(lane_ids[str(lane["key"])],
                                                      lane_ids[str(dep)], prog_mod.REQUIRES))

    prov_tail = ", ".join("%s=%s" % (k, prov.get(k)) for k in
                          ("role", "provider", "source", "run_id") if prov.get(k))
    d = dec_mod.new_decision(
        program_id,
        "Adopt PLAN_PROPOSAL %s (%d lane(s))?" % (digest[:12], len(proposal["lanes"])),
        decision="ADOPTED %d lane(s): %s" % (len(lane_ids), ", ".join(sorted(lane_ids))),
        authority=authority or dec_mod.BY_STRATEGIST,
        rationale=("planner provenance: %s | adopted by %s" % (prov_tail or "unrecorded", actor)),
        evidence_refs=(digest,) + ((str(prov.get("run_id")),) if prov.get("run_id") else ()),
        actor_id=actor, now=now)
    sstore.record_decision(d)

    saved = carried if carried is not None else \
        new_proposal_doc(proposal=proposal, planner_provenance=prov)
    saved.update({"status": STATUS_ADOPTED, "digest": digest, "proposal": dict(proposal),
                  "planner_provenance": prov, "lane_map": lane_ids,
                  "decision_id": d.decision_id, "adopted_by": actor})
    save_proposal_doc(sstore, program_id, saved)
    return {"ok": True, "lane_ids": lane_ids, "decision_id": d.decision_id}


def resolve_proposal_finding(sstore, program_id: str, finding_id: str, *, rationale: str,
                             actor_id: str, now=None) -> dict:
    """Mark one plan-challenge finding RESOLVED by strategist action. Impure.

    Resolution is a DECISION like everything else that changes what the program may do: the
    reviewer said the plan was defective, and only a recorded human-side judgement -- never a
    timeout, never silence -- un-blocks adoption.
    """
    from quaestor.core import decisions as dec_mod
    doc = load_proposal_doc(sstore, program_id)
    if doc is None:
        return {"ok": False, "refusal": PROPOSAL_NOT_PENDING, "detail": "no proposal document"}
    hits = [f for f in (doc.get("findings") or []) if f.get("finding_id") == finding_id]
    if not hits:
        return {"ok": False, "refusal": PROPOSAL_NOT_PENDING,
                "detail": "unknown finding %r" % finding_id}
    if not str(rationale or "").strip():
        return {"ok": False, "refusal": PROPOSAL_INVALID,
                "detail": "resolving a finding requires a rationale"}
    hits[0]["resolved"] = True
    hits[0]["resolved_by"] = str(actor_id)
    d = dec_mod.new_decision(program_id, "Resolve plan-challenge finding %s?" % finding_id,
                             decision="RESOLVED: %s" % hits[0].get("title", ""),
                             rationale=str(rationale), actor_id=str(actor_id), now=now)
    sstore.record_decision(d)
    save_proposal_doc(sstore, program_id, doc)
    return {"ok": True, "decision_id": d.decision_id}


def _named(errors: Sequence[str]) -> str:
    """The first NAMED refusal in an error list ('NAME: text' spelling). PURE."""
    for e in errors:
        if ": " in e:
            head = e.split(": ", 1)[0]
            if head.startswith("PROPOSAL_"):
                return head
    return PROPOSAL_INVALID


# ---------------------------------------------------------------------------------------------
# Task-text builders (PURE) -- what the seats are actually asked to do
# ---------------------------------------------------------------------------------------------
def build_plan_task(*, objective: str, constraints: Sequence[str]) -> str:
    """The planner seat's TASK TEXT. PURE.

    Spells the PLAN_PROPOSAL contract inline: the child answers through the standard handoff's
    governed messages channel, emitting EXACTLY ONE PLAN_REVISION whose detail.proposal is the
    machine-validated object. Everything the validator enforces is stated here verbatim, because
    a model told the rules loosely fails expensively.
    """
    return (
        "PLANNING SEAT. Decompose the objective into governed lanes. You are READ-ONLY: you "
        "propose; you cannot execute, approve, or adopt anything -- your entire power is that a "
        "strategist may adopt your plan.\n\n"
        "ORIGINAL OBJECTIVE:\n%s\n\nIMMUTABLE CONSTRAINTS:\n%s\n\n"
        "OUTPUT CONTRACT -- emit EXACTLY ONE message in your structured handoff:\n"
        '{"type": "PLAN_REVISION", "payload": "<one-line plan title>", '
        '"detail": {"proposal": <PLAN_PROPOSAL object>}}\n'
        "The PLAN_PROPOSAL object: {\"title\": str, \"objective\": str, \"lanes\": [<LANE>...]}. "
        "Each LANE: {\"key\": unique short id, \"title\": str, \"task\": str (<=8000 chars), "
        "\"kind\": one of research|implementation|verification|adversarial_review|integration, "
        "\"depends_on\": [lane key...], \"acceptance\": [non-empty string...], "
        "\"plan_review\": bool(optional)}. Rules the validator ENFORCES: 1..64 lanes; keys "
        "unique; dependencies must reference existing keys and MUST BE ACYCLIC; implementation "
        "lanes REQUIRE non-empty acceptance; no other fields are accepted -- any authority-"
        "bearing field is refused and your proposal discarded.\n\n"
        "Emit no other messages."
        % (str(objective or "(not stated)"),
           "\n".join("- " + str(c) for c in constraints) or "(none)"))


def build_plan_challenge_task(*, objective: str, constraints: Sequence[str],
                              proposal_doc: Mapping) -> str:
    """The reviewer's PLAN-target task text (PRD.md §7.6). PURE.

    Same reviewer seat, same READ_ONLY ceiling, same REVIEW_FINDING-only output vocabulary -- the
    TARGET changes: the candidate under attack is a DECOMPOSITION, before any expensive execution.
    """
    import json

    from quaestor.core import review_contract as rc
    prov = dict(proposal_doc.get("planner_provenance") or {})
    return (
        "ADVERSARIAL PLAN CHALLENGE (target class PLAN). You are READ-ONLY. Attack the "
        "DECOMPOSITION below BEFORE it is adopted and before any implementation run spends "
        "anything: one review call here can save thirty misdirected executions.\n\n"
        "ORIGINAL OBJECTIVE:\n%s\n\nIMMUTABLE CONSTRAINTS:\n%s\n\n"
        "THE PROPOSED PLAN (planner provenance: %s):\n%s\n\n"
        "HUNT SPECIFICALLY FOR: %s -- judged AGAINST A PLAN: wrong lane boundaries, missing "
        "verification lanes, cyclic or pointless dependencies, acceptance criteria that cannot "
        "be measured, constraint violations baked into tasks, authority assumptions the plan "
        "cannot legally grant.\n\n"
        "OUTPUT: emit one REVIEW_FINDING message per SUBSTANTIATED defect, exactly as for a code "
        "review ({\"type\": \"REVIEW_FINDING\", \"payload\": title, \"severity\": "
        "\"CRITICAL|HIGH|MEDIUM|LOW\", \"detail\": {\"location\": \"<lane key>\", "
        "\"failure_mode\": \"<how it fails, concretely>\"}}). If the decomposition survives your "
        "attack, say so plainly in `summary` and emit no messages."
        % (str(objective or "(not stated)"),
           "\n".join("- " + str(c) for c in constraints) or "(none)",
           ", ".join("%s=%s" % (k, prov[k]) for k in ("provider", "source") if prov.get(k))
           or "unrecorded",
           json.dumps(proposal_doc.get("proposal") or {}, sort_keys=True, default=str)[:20000],
           ", ".join(rc.ADVERSARIAL_LENSES)))

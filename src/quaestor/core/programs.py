"""programs -- the multi-lane model, and the ownership that makes concurrency safe.

THE HIERARCHY, AND WHY IT IS ONLY FOUR LEVELS
---------------------------------------------
    PROGRAM    a durable body of work with objectives, decisions and an owner
      WORKFLOW a coherent slice of it
        LANE   a single line of work with ONE writer and its own workspace
          RUN  one bounded execution (the existing, already-qualified unit)

Four levels because each answers a question the others cannot: a PROGRAM is what a strategist
resumes, a WORKFLOW is what gets accepted or rejected together, a LANE is what owns a workspace
and can be blocked, and a RUN is what a worker actually performs. A fifth level was considered and
rejected -- "task" between lane and run added an identifier with no distinct semantics, and §37's
rule is that an identifier without a distinct purpose is a liability.

OUTCOMES DO NOT COLLAPSE
------------------------
A lane completing is not the program succeeding. ``aggregate`` deliberately refuses to reduce the
tree to a boolean: a program with one failed lane and one blocked lane is NOT_EVALUATED with the
strategist as next authority, because "did it work?" is genuinely unanswerable until someone
decides what to do about the blocked one. Collapsing that into False would throw away the only
information a strategist needs.

ONE ACTIVE STRATEGIC WRITER PER LANE
------------------------------------
Two strategist sessions may connect to the same program -- that is the point of durable state.
They must not both drive the same lane, so a lane carries a durable, fenced ownership lease with
the same shape the worktree lease already uses: an owner token, an expiry, and a monotonic FENCE
that makes a stale writer's late call detectable rather than merely unlikely.

A NOTE ON WHAT THIS IS NOT: the lease is a COORDINATION mechanism, not an authentication one. It
prevents two cooperating writers from racing. It does not prove who a writer is, and a caller that
can forge an owner token can take a lane. Identity has to come from the transport, and where the
transport cannot supply it, the honest record is that it is unverified.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Mapping, Sequence

PROGRAM_INSTRUMENT = "programs/1"

# ---- lane lifecycle --------------------------------------------------------------------------
LANE_PLANNED = "PLANNED"
LANE_ACTIVE = "ACTIVE"
LANE_WAITING_STRATEGIST = "WAITING_FOR_STRATEGIST"
LANE_WAITING_OWNER = "WAITING_FOR_OWNER"
LANE_WAITING_LANE = "WAITING_FOR_LANE"
LANE_WAITING_EXTERNAL = "WAITING_FOR_EXTERNAL_EVENT"
LANE_COMPLETE = "COMPLETE"
LANE_ABANDONED = "ABANDONED"

LANE_STATES = (LANE_PLANNED, LANE_ACTIVE, LANE_WAITING_STRATEGIST, LANE_WAITING_OWNER,
               LANE_WAITING_LANE, LANE_WAITING_EXTERNAL, LANE_COMPLETE, LANE_ABANDONED)

#: WAITING IS NOT FAILURE. Kept as its own set because the distinction is the whole point of a
#: two-way protocol: a lane that asked a question and stopped has behaved correctly, and a model
#: that cannot represent that will report it as either success or failure, both of them lies.
WAITING_STATES = frozenset({LANE_WAITING_STRATEGIST, LANE_WAITING_OWNER, LANE_WAITING_LANE,
                            LANE_WAITING_EXTERNAL})
TERMINAL_LANE_STATES = frozenset({LANE_COMPLETE, LANE_ABANDONED})

# ---- lane dependency kinds -------------------------------------------------------------------
BLOCKS = "BLOCKS"
REQUIRES = "REQUIRES"
PRODUCES_FOR = "PRODUCES_FOR"
VALIDATES = "VALIDATES"
REVIEWS = "REVIEWS"
SUPERSEDES = "SUPERSEDES"
MERGES_AFTER = "MERGES_AFTER"
DEPENDENCY_KINDS = (BLOCKS, REQUIRES, PRODUCES_FOR, VALIDATES, REVIEWS, SUPERSEDES, MERGES_AFTER)

# ---- verdicts ---------------------------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
NOT_EVALUATED = "NOT_EVALUATED"

NEXT_NONE = "NONE"
NEXT_STRATEGIST = "STRATEGIST"
NEXT_OWNER = "OWNER"
NEXT_EXTERNAL = "EXTERNAL_EVENT"


@dataclass(frozen=True)
class Lane:
    lane_id: str
    program_id: str
    workflow_id: str = ""
    title: str = ""
    kind: str = "implementation"
    state: str = LANE_PLANNED
    verdict: str = NOT_EVALUATED
    #: The workspace this lane owns. Two WRITE lanes must never share one.
    workspace_id: str = ""
    writable: bool = False
    created_at: float = 0.0
    updated_at: float = 0.0
    instrument: str = PROGRAM_INSTRUMENT

    @property
    def waiting(self) -> bool:
        return self.state in WAITING_STATES

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_LANE_STATES

    def to_dict(self) -> dict:
        return {"lane_id": self.lane_id, "program_id": self.program_id,
                "workflow_id": self.workflow_id, "title": self.title, "kind": self.kind,
                "state": self.state, "verdict": self.verdict, "workspace_id": self.workspace_id,
                "writable": self.writable, "waiting": self.waiting, "terminal": self.terminal,
                "created_at": self.created_at, "updated_at": self.updated_at,
                "instrument": self.instrument}


def _lane_ctor_fields(self: Lane) -> dict:
    """The constructor-shaped fields only.

    ``to_dict`` adds derived keys (``waiting``, ``terminal``) that the constructor rejects, so a
    caller building a modified copy needs this instead.
    """
    return {"lane_id": self.lane_id, "program_id": self.program_id,
            "workflow_id": self.workflow_id, "title": self.title, "kind": self.kind,
            "state": self.state, "verdict": self.verdict, "workspace_id": self.workspace_id,
            "writable": self.writable, "created_at": self.created_at,
            "updated_at": self.updated_at}


Lane.to_dict_ctor = _lane_ctor_fields


@dataclass(frozen=True)
class LaneLease:
    """Fenced, durable ownership of a lane by ONE strategic writer."""

    lane_id: str
    owner_token: str
    actor_id: str
    fence: int
    acquired_at: float
    expires_at: float
    released_at: float = 0.0

    def active(self, now: float) -> bool:
        return not self.released_at and now < self.expires_at

    def to_dict(self) -> dict:
        return {"lane_id": self.lane_id, "actor_id": self.actor_id, "fence": self.fence,
                "acquired_at": self.acquired_at, "expires_at": self.expires_at,
                "released_at": self.released_at,
                "owner_token_present": bool(self.owner_token)}


# Lease outcomes
ACQUIRED = "ACQUIRED"
RENEWED = "RENEWED"
HELD_BY_OTHER = "HELD_BY_OTHER"
STALE_FENCE = "STALE_FENCE"
NOT_HELD = "NOT_HELD"

DEFAULT_LEASE_S = 900.0


def evaluate_claim(existing: LaneLease | None, *, actor_id: str, now: float,
                   owner_token: str = "", lease_s: float = DEFAULT_LEASE_S) -> tuple:
    """(outcome, lease_or_None, reason). PURE.

    Re-entrant for the SAME token -- a writer renewing its own lease must not be told the lane is
    taken -- and refuses a different actor while the lease is live. An EXPIRED lease is takeable,
    and the taker gets a HIGHER fence, which is what makes the previous writer's late call
    detectable instead of silently accepted.
    """
    if existing is not None and existing.active(now):
        if owner_token and owner_token == existing.owner_token:
            return RENEWED, LaneLease(existing.lane_id, existing.owner_token, existing.actor_id,
                                      existing.fence, existing.acquired_at,
                                      now + lease_s), ""
        return HELD_BY_OTHER, existing, (
            "lane is held by actor %s until %.0f; one active strategic writer per lane"
            % (existing.actor_id, existing.expires_at))
    fence = (existing.fence + 1) if existing is not None else 1
    return ACQUIRED, LaneLease(existing.lane_id if existing else "", "tok_" + uuid.uuid4().hex,
                               str(actor_id), fence, now, now + lease_s), ""


def check_fence(existing: LaneLease | None, presented_fence: int) -> tuple:
    """(ok, reason). PURE. A write from a superseded writer must be REFUSED, not merged.

    Without this, a strategist whose lease expired mid-thought writes over the one that replaced
    it, and the record shows no conflict at all -- the most expensive kind of concurrency bug,
    because nothing looks wrong afterwards.
    """
    if existing is None:
        return False, NOT_HELD
    if int(presented_fence) < int(existing.fence):
        return False, ("%s: presented fence %s is older than the current %s"
                       % (STALE_FENCE, presented_fence, existing.fence))
    return True, ""


@dataclass(frozen=True)
class Dependency:
    from_lane: str
    to_lane: str
    kind: str

    def to_dict(self) -> dict:
        return {"from_lane": self.from_lane, "to_lane": self.to_lane, "kind": self.kind}


def blocking_dependencies(lanes: Mapping[str, Lane], deps: Sequence[Dependency]) -> dict:
    """lane_id -> the lanes it is still waiting on. PURE.

    Only REQUIRES and MERGES_AFTER actually block. REVIEWS and VALIDATES describe a relationship
    without gating it, and treating them as blockers would deadlock a program whose reviewer lane
    is, correctly, waiting for the thing it reviews.
    """
    blocking = {}
    for d in deps or ():
        if d.kind not in (REQUIRES, MERGES_AFTER):
            continue
        upstream = lanes.get(d.to_lane)
        if upstream is None or upstream.state != LANE_COMPLETE:
            blocking.setdefault(d.from_lane, []).append(d.to_lane)
    return {k: sorted(v) for k, v in blocking.items()}


def aggregate(lanes: Sequence[Lane]) -> dict:
    """Program-level outcome WITHOUT collapsing the layers. PURE.

    The rules, and why each exists:
      * any lane still waiting  -> NOT_EVALUATED. Something is owed to someone; a verdict now
                                   would be a guess about work that has not happened.
      * any lane FAIL           -> FAIL, but the next authority is the STRATEGIST, not NONE: a
                                   failed lane is a decision to make, not an ending.
      * all COMPLETE and PASS   -> PASS.
      * anything else           -> NOT_EVALUATED.
    """
    lanes = list(lanes or ())
    counts = {}
    for l in lanes:
        counts[l.state] = counts.get(l.state, 0) + 1
    waiting = [l for l in lanes if l.waiting]
    failed = [l for l in lanes if l.verdict == FAIL]
    incomplete = [l for l in lanes if not l.terminal]

    if not lanes:
        verdict, nxt, why = NOT_EVALUATED, NEXT_STRATEGIST, "the program has no lanes"
    elif failed:
        verdict, nxt = FAIL, NEXT_STRATEGIST
        why = ("%d lane(s) failed; a failed lane is a decision for the strategist, not a "
               "terminal state for the program" % len(failed))
    elif waiting:
        owner_waits = [l for l in waiting if l.state == LANE_WAITING_OWNER]
        verdict = NOT_EVALUATED
        nxt = NEXT_OWNER if owner_waits else NEXT_STRATEGIST
        why = "%d lane(s) waiting: %s" % (len(waiting), sorted({l.state for l in waiting}))
    elif incomplete:
        verdict, nxt = NOT_EVALUATED, NEXT_STRATEGIST
        why = "%d lane(s) not yet terminal" % len(incomplete)
    elif all(l.verdict == PASS for l in lanes):
        verdict, nxt, why = PASS, NEXT_NONE, "every lane completed and passed"
    else:
        verdict, nxt = NOT_EVALUATED, NEXT_STRATEGIST
        why = "all lanes terminal but not all passed"

    return {"program_verdict": verdict, "next_authority": nxt, "reason": why,
            "lane_count": len(lanes), "state_counts": counts,
            "waiting": [l.lane_id for l in waiting], "failed": [l.lane_id for l in failed],
            "inspected_count": len(lanes), "vacuous": not lanes,
            "instrument": PROGRAM_INSTRUMENT}


def new_lane(program_id: str, *, title: str, kind: str = "implementation",
             workflow_id: str = "", writable: bool = False, workspace_id: str = "",
             now: float | None = None) -> Lane:
    t = float(now if now is not None else time.time())
    return Lane(lane_id="lane_" + uuid.uuid4().hex[:16], program_id=str(program_id),
                workflow_id=str(workflow_id), title=str(title), kind=str(kind),
                writable=bool(writable), workspace_id=str(workspace_id),
                created_at=t, updated_at=t)


def workspace_conflicts(lanes: Sequence[Lane]) -> list:
    """Writable lanes sharing one workspace. PURE.

    Two write workers in one mutable worktree corrupt each other's evidence and each other's
    diffs, and the damage is discovered later as an unexplained conflict. Detect it as a
    structural fact instead.
    """
    seen, bad = {}, []
    for l in lanes or ():
        if not (l.writable and l.workspace_id) or l.terminal:
            continue
        if l.workspace_id in seen:
            bad.append({"workspace_id": l.workspace_id,
                        "lanes": sorted([seen[l.workspace_id], l.lane_id])})
        else:
            seen[l.workspace_id] = l.lane_id
    return bad

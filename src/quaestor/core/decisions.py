"""decisions -- the durable answer to "why is it like this?"

THE PROBLEM THIS SOLVES
-----------------------
Strategic state currently lives in a chat window. When that window ends, the reasoning ends with
it: the next session inherits the code but not the decisions, so it re-litigates settled questions
or -- worse -- silently reverses one because nothing recorded that it was ever decided.

A decision is therefore a first-class durable record, and the vocabulary is deliberately small:

    question    what was actually being decided
    decision    what was chosen
    authority   WHO was entitled to choose it
    rationale   why, in one place, forever
    evidence    what it was based on

NOTHING IS EVER FORGOTTEN, ONLY SUPERSEDED
------------------------------------------
``supersede`` writes a NEW row that points at the old one and marks the old ``SUPERSEDED``. It
never edits or deletes. That matters for the same reason an append-only ledger matters: "we used
to think X, then we learned Y" is itself the most valuable thing in the record, and a store that
overwrites decisions destroys exactly the history a resuming strategist needs.

A decision also carries the authority that made it. "The executor decided to skip the tests" and
"the owner decided to skip the tests" are different facts, and a schema that cannot tell them
apart cannot answer the only question that matters after an incident.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Sequence

DECISION_INSTRUMENT = "decisions/1"

# Status
OPEN = "OPEN"                 # the question is recorded; no answer yet
DECIDED = "DECIDED"
SUPERSEDED = "SUPERSEDED"
WITHDRAWN = "WITHDRAWN"       # the question stopped being relevant; kept for the record

STATUSES = (OPEN, DECIDED, SUPERSEDED, WITHDRAWN)

#: Who was entitled to decide. Mirrors the actor roles, but recorded per-decision because the
#: entitlement is a property of the DECISION, not of whoever happens to be connected now.
BY_OWNER = "OWNER"
BY_STRATEGIST = "STRATEGIST"
BY_POLICY = "POLICY"          # decided automatically by a rule, which is itself auditable
AUTHORITIES = (BY_OWNER, BY_STRATEGIST, BY_POLICY)


@dataclass(frozen=True)
class Decision:
    decision_id: str
    program_id: str
    question: str
    decision: str = ""
    authority: str = BY_STRATEGIST
    rationale: str = ""
    evidence_refs: tuple = ()
    lane_id: str = ""
    status: str = OPEN
    supersedes: str = ""
    superseded_by: str = ""
    created_at: float = 0.0
    decided_at: float = 0.0
    actor_id: str = ""
    #: Was the OWNER authority on this record attested by the owner channel, or merely
    #: claimed by whoever wrote it? Computed at mint time from the channel, never from a
    #: caller argument. Always True for non-owner authorities, which nobody impersonates.
    owner_attested: bool = False
    instrument: str = DECISION_INSTRUMENT

    @property
    def live(self) -> bool:
        return self.status in (OPEN, DECIDED)

    @property
    def authority_is_claimed(self) -> bool:
        """True when this record says OWNER but nothing attested it.

        "The executor decided to skip the tests" and "the owner decided to skip the
        tests" are different facts, and this schema exists to tell them apart -- but the
        field alone could not, because any caller could type OWNER. A reader now sees
        WHICH of the two kinds of owner-authority they are looking at.
        """
        return self.authority == BY_OWNER and not self.owner_attested

    def to_dict(self) -> dict:
        return {"decision_id": self.decision_id, "program_id": self.program_id,
                "lane_id": self.lane_id, "question": self.question, "decision": self.decision,
                "authority": self.authority, "rationale": self.rationale,
                "evidence_refs": list(self.evidence_refs), "status": self.status,
                "supersedes": self.supersedes, "superseded_by": self.superseded_by,
                "created_at": self.created_at, "decided_at": self.decided_at,
                "actor_id": self.actor_id, "live": self.live,
                "owner_attested": self.owner_attested,
                "authority_is_claimed": self.authority_is_claimed,
                "instrument": self.instrument}


def _owner_attested(authority: str) -> bool:
    """Did the OWNER CHANNEL attest this authority? PURE. Never a caller argument.

    Non-owner authorities are attested trivially: nothing gains by impersonating a strategist.
    OWNER is the one claim worth forging, so it is the one that must be checked against the
    channel -- which today returns UNAVAILABLE by construction, so every owner decision this
    build can mint is honestly recorded as CLAIMED rather than attested.
    """
    from quaestor.core import owner_channel
    if authority != BY_OWNER:
        return True
    return owner_channel.owner_channel_state() == owner_channel.AUTHENTICATED


def new_decision(program_id: str, question: str, *, lane_id: str = "", decision: str = "",
                 authority: str = BY_STRATEGIST, rationale: str = "",
                 evidence_refs: Sequence[str] = (), actor_id: str = "",
                 now: float | None = None) -> Decision:
    """Mint a decision, OPEN unless an answer is supplied. Raises ValueError on bad authority."""
    if authority not in AUTHORITIES:
        raise ValueError("unknown decision authority %r; known are %s"
                         % (authority, list(AUTHORITIES)))
    if not str(question).strip():
        raise ValueError("a decision must record the QUESTION; an answer without one is a note")
    t = float(now if now is not None else time.time())
    return Decision(
        decision_id="dec_" + uuid.uuid4().hex[:16], program_id=str(program_id),
        lane_id=str(lane_id), question=str(question), decision=str(decision),
        authority=authority, rationale=str(rationale),
        evidence_refs=tuple(str(e) for e in (evidence_refs or ())),
        status=DECIDED if str(decision).strip() else OPEN,
        created_at=t, decided_at=(t if str(decision).strip() else 0.0), actor_id=str(actor_id),
        owner_attested=_owner_attested(authority))


def supersede(previous: Decision, *, decision: str, rationale: str,
              authority: str = BY_STRATEGIST, actor_id: str = "",
              evidence_refs: Sequence[str] = (), now: float | None = None) -> tuple:
    """(new_decision, updated_previous). PURE.

    Returns BOTH rows. The caller persists both, so the link is written atomically or not at all;
    a superseding record whose predecessor was never marked would leave two live answers to one
    question, which is worse than having no record.
    """
    if not str(rationale).strip():
        raise ValueError("superseding a decision requires a rationale: the reason the previous "
                         "answer stopped being right IS the valuable part of the record")
    t = float(now if now is not None else time.time())
    fresh = Decision(
        owner_attested=_owner_attested(authority),
        decision_id="dec_" + uuid.uuid4().hex[:16], program_id=previous.program_id,
        lane_id=previous.lane_id, question=previous.question, decision=str(decision),
        authority=authority, rationale=str(rationale),
        evidence_refs=tuple(str(e) for e in (evidence_refs or ())),
        status=DECIDED, supersedes=previous.decision_id, created_at=t, decided_at=t,
        actor_id=str(actor_id))
    old = Decision(**{**previous.to_dict_for_replace(), "status": SUPERSEDED,
                      "superseded_by": fresh.decision_id})
    return fresh, old


def _to_dict_for_replace(self: Decision) -> dict:
    """The constructor-shaped fields only -- ``to_dict`` adds derived keys the ctor rejects."""
    return {"decision_id": self.decision_id, "program_id": self.program_id,
            "question": self.question, "decision": self.decision, "authority": self.authority,
            "rationale": self.rationale, "evidence_refs": self.evidence_refs,
            "lane_id": self.lane_id, "status": self.status, "supersedes": self.supersedes,
            "superseded_by": self.superseded_by, "created_at": self.created_at,
            "decided_at": self.decided_at, "actor_id": self.actor_id}


Decision.to_dict_for_replace = _to_dict_for_replace


def live_decisions(rows: Sequence[Decision]) -> tuple:
    """The decisions still in force. PURE.

    What a resuming strategist should read: everything not superseded or withdrawn, newest first.
    """
    return tuple(sorted([d for d in rows if d.live], key=lambda d: -d.created_at))

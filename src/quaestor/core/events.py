"""events -- the canonical, append-only account of what happened.

NOT EVENT SOURCING. State is not rebuilt by replaying these; the store remains authoritative. The
event log exists so that after a crash, a disagreement, or an incident, the sequence of facts is
RECONSTRUCTABLE -- which is a much weaker requirement than event sourcing and costs almost nothing,
while over-engineering it would put every state transition behind a projection nobody can debug.

The vocabulary is closed on purpose. An event name that any caller can invent is a log line, and
log lines are not evidence: you cannot assert over them, and two components will spell the same
fact differently. A name absent from ``EVENT_TYPES`` is refused.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping

EVENT_INSTRUMENT = "events/1"

# run lifecycle
RUN_CREATED = "RUN_CREATED"
DISPATCH_ADMITTED = "DISPATCH_ADMITTED"
DISPATCH_DUPLICATE = "DISPATCH_DUPLICATE"
LEASE_ACQUIRED = "LEASE_ACQUIRED"
LEASE_RELEASED = "LEASE_RELEASED"
EXECUTOR_STARTED = "EXECUTOR_STARTED"
RESULT_RECEIVED = "RESULT_RECEIVED"
EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
HANDOFF_READY = "HANDOFF_READY"
CANCEL_REQUESTED = "CANCEL_REQUESTED"
RECONCILIATION_CLASSIFIED = "RECONCILIATION_CLASSIFIED"

# two-way protocol
EXECUTOR_MESSAGE = "EXECUTOR_MESSAGE"
CLARIFICATION_REQUESTED = "CLARIFICATION_REQUESTED"
DECISION_RECORDED = "DECISION_RECORDED"
DECISION_SUPERSEDED = "DECISION_SUPERSEDED"
AUTHORITY_REQUESTED = "AUTHORITY_REQUESTED"
AUTHORITY_GRANTED = "AUTHORITY_GRANTED"
BLOCKED = "BLOCKED"
OWNER_ESCALATED = "OWNER_ESCALATED"

# lanes
LANE_CREATED = "LANE_CREATED"
LANE_STATE_CHANGED = "LANE_STATE_CHANGED"
LANE_CLAIMED = "LANE_CLAIMED"
LANE_RELEASED = "LANE_RELEASED"
LANE_HANDOFF_RECORDED = "LANE_HANDOFF_RECORDED"

# review
REVIEW_STARTED = "REVIEW_STARTED"
REVIEW_FINDING = "REVIEW_FINDING"
REVIEW_COMPLETED = "REVIEW_COMPLETED"

# programs (operational layer). Additive: the closed vocabulary grows by deliberate edit, the
# same way every other name here arrived.
PROGRAM_CREATED = "PROGRAM_CREATED"
PROGRAM_STATUS_CHANGED = "PROGRAM_STATUS_CHANGED"
LANE_TASK_SET = "LANE_TASK_SET"
RUN_BOUND = "RUN_BOUND"
CHECKPOINT_SAVED = "CHECKPOINT_SAVED"
DIRECTIVE_ISSUED = "DIRECTIVE_ISSUED"
SCHEDULED = "SCHEDULED"
SCHEDULE_SKIPPED = "SCHEDULE_SKIPPED"
FIX_LANE_CREATED = "FIX_LANE_CREATED"
INTEGRATION_STATE_CHANGED = "INTEGRATION_STATE_CHANGED"

EVENT_TYPES = (
    RUN_CREATED, DISPATCH_ADMITTED, DISPATCH_DUPLICATE, LEASE_ACQUIRED, LEASE_RELEASED,
    EXECUTOR_STARTED, RESULT_RECEIVED, EVIDENCE_COLLECTED, HANDOFF_READY, CANCEL_REQUESTED,
    RECONCILIATION_CLASSIFIED,
    EXECUTOR_MESSAGE, CLARIFICATION_REQUESTED, DECISION_RECORDED, DECISION_SUPERSEDED,
    AUTHORITY_REQUESTED, AUTHORITY_GRANTED, BLOCKED, OWNER_ESCALATED,
    LANE_CREATED, LANE_STATE_CHANGED, LANE_CLAIMED, LANE_RELEASED, LANE_HANDOFF_RECORDED,
    REVIEW_STARTED, REVIEW_FINDING, REVIEW_COMPLETED,
    PROGRAM_CREATED, PROGRAM_STATUS_CHANGED, LANE_TASK_SET, RUN_BOUND, CHECKPOINT_SAVED,
    DIRECTIVE_ISSUED, SCHEDULED, SCHEDULE_SKIPPED, FIX_LANE_CREATED,
    INTEGRATION_STATE_CHANGED,
)

#: Events that record a REQUEST rather than an effect. Kept explicit because the difference is
#: the platform's central invariant: asking for authority and receiving it are two events, and a
#: reader must never be able to mistake the first for the second.
REQUEST_ONLY = frozenset({AUTHORITY_REQUESTED, CLARIFICATION_REQUESTED, CANCEL_REQUESTED,
                          OWNER_ESCALATED})


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    at: float
    program_id: str = ""
    lane_id: str = ""
    run_id: str = ""
    actor_id: str = ""
    detail: Mapping = field(default_factory=dict)
    instrument: str = EVENT_INSTRUMENT

    @property
    def is_request_only(self) -> bool:
        return self.event_type in REQUEST_ONLY

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "event_type": self.event_type, "at": self.at,
                "program_id": self.program_id, "lane_id": self.lane_id, "run_id": self.run_id,
                "actor_id": self.actor_id, "detail": dict(self.detail),
                "is_request_only": self.is_request_only, "instrument": self.instrument}


def new_event(event_type: str, *, program_id: str = "", lane_id: str = "", run_id: str = "",
              actor_id: str = "", detail: Mapping | None = None,
              now: float | None = None) -> Event:
    """Mint an event. Raises ValueError on an unknown type -- never invents one."""
    if event_type not in EVENT_TYPES:
        raise ValueError("unknown event type %r; the vocabulary is closed so that events can be "
                         "asserted over rather than merely read" % (event_type,))
    return Event(event_id="ev_" + uuid.uuid4().hex[:16], event_type=event_type,
                 at=float(now if now is not None else time.time()),
                 program_id=str(program_id), lane_id=str(lane_id), run_id=str(run_id),
                 actor_id=str(actor_id), detail=dict(detail or {}))

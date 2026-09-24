"""messages -- the governed two-way protocol between a strategist and an executor.

WHY THIS IS A TYPE AND NOT A CONVENTION
---------------------------------------
The old shape was one-way: objective in, result out. Anything the executor needed to say on the
way -- "this is ambiguous", "I am blocked", "I need write access to finish" -- had nowhere to go
except prose inside the final answer, where a machine cannot route it and a human has to read the
whole thing to find it.

Prose conventions also fail silently. A message type that exists only as "start the line with
BLOCKER:" is a message type that stops existing the moment a model paraphrases. So the envelope is
STRUCTURED and the payload is natural language:

    envelope   machine-routable, closed vocabulary, validated      <- this module
    payload    whatever the actor actually wants to say            <- opaque text

THE ENVELOPE NEVER CARRIES AUTHORITY
------------------------------------
``AUTHORITY_REQUEST`` is the important one. It is a REQUEST -- a durable record that an executor
asked for something -- and recording it grants nothing at all. The grant, if it ever comes, is a
separate owner-authored record in the authority engine. An executor that could raise its own
capabilities by emitting a message would be an executor that grants itself authority, which is the
one thing this platform exists to prevent.

Likewise ``caused_by``: it makes the conversation a DAG rather than a transcript, so a strategist
resuming later can reconstruct what answered what without replaying chat history.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core.canon import canonical_json, sha256_text

MESSAGE_INSTRUMENT = "messages/1"
MESSAGE_PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------------------------
# The closed vocabulary
# ---------------------------------------------------------------------------------------------
#: Executor -> strategist: the objective admits more than one reading.
CLARIFICATION_REQUEST = "CLARIFICATION_REQUEST"
#: Executor -> strategist: a choice with consequences the executor may not make alone.
DECISION_REQUEST = "DECISION_REQUEST"
#: Executor -> control plane: "I need capability X to proceed." A REQUEST. Grants nothing.
AUTHORITY_REQUEST = "AUTHORITY_REQUEST"
#: Executor -> strategist: progress is not possible until something external changes.
BLOCKER = "BLOCKER"
#: Executor -> strategist: something true and worth knowing that was not asked for.
OBSERVATION = "OBSERVATION"
#: Executor -> strategist: the plan should change; here is the proposed change.
PLAN_REVISION = "PLAN_REVISION"
#: Executor -> control plane: the bounded objective is finished (or definitively is not).
RESULT = "RESULT"
#: Reviewer/adversarial reviewer -> control plane: a specific defect claim.
REVIEW_FINDING = "REVIEW_FINDING"
#: Anyone -> owner: this needs a human.
OWNER_ESCALATION = "OWNER_ESCALATION"
#: Strategist -> executor: the bounded objective itself.
OBJECTIVE = "OBJECTIVE"
#: Strategist/owner -> executor: the answer to a CLARIFICATION_REQUEST or DECISION_REQUEST.
DIRECTIVE = "DIRECTIVE"

MESSAGE_TYPES = (
    OBJECTIVE, DIRECTIVE,
    CLARIFICATION_REQUEST, DECISION_REQUEST, AUTHORITY_REQUEST, BLOCKER, OBSERVATION,
    PLAN_REVISION, RESULT, REVIEW_FINDING, OWNER_ESCALATION,
)

#: Types that PAUSE a lane until someone answers. Waiting is a first-class state, not a failure:
#: an executor that asked a question and stopped has behaved correctly, and a control plane that
#: cannot represent that will either hang or lie about it.
AWAITING_TYPES = frozenset({CLARIFICATION_REQUEST, DECISION_REQUEST, AUTHORITY_REQUEST,
                            OWNER_ESCALATION})

#: Who each type is FOR. Used to route, never to authorise.
ROUTES: Mapping[str, str] = {
    OBJECTIVE: "EXECUTOR",
    DIRECTIVE: "EXECUTOR",
    CLARIFICATION_REQUEST: "STRATEGIST",
    DECISION_REQUEST: "STRATEGIST",
    PLAN_REVISION: "STRATEGIST",
    BLOCKER: "STRATEGIST",
    OBSERVATION: "STRATEGIST",
    RESULT: "STRATEGIST",
    REVIEW_FINDING: "STRATEGIST",
    AUTHORITY_REQUEST: "OWNER",
    OWNER_ESCALATION: "OWNER",
}

# Validation outcomes
VALID = "VALID"
UNKNOWN_TYPE = "UNKNOWN_MESSAGE_TYPE"
PROTOCOL_REFUSED = "PROTOCOL_REFUSED"
MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class Message:
    """One governed utterance. Envelope typed; payload opaque."""

    message_id: str
    message_type: str
    actor_id: str
    #: Identity hierarchy, smallest that is correct. A message always belongs to a lane; run_id is
    #: present only when the message came from (or is about) a specific execution.
    program_id: str = ""
    lane_id: str = ""
    run_id: str = ""
    #: The message this one answers or follows from. Makes the exchange a DAG, not a transcript.
    caused_by: str = ""
    #: What the control plane believed the actor could do WHEN THE MESSAGE WAS RECORDED. Evidence
    #: about the past; never consulted to decide the present.
    authority_context: tuple = ()
    payload: str = ""
    detail: Mapping = field(default_factory=dict)
    created_at: float = 0.0
    protocol_version: int = MESSAGE_PROTOCOL_VERSION
    instrument: str = MESSAGE_INSTRUMENT

    @property
    def awaits_answer(self) -> bool:
        return self.message_type in AWAITING_TYPES

    @property
    def routed_to(self) -> str:
        return ROUTES.get(self.message_type, "STRATEGIST")

    def digest(self) -> str:
        """Content digest, excluding the id and timestamp. PURE.

        Two messages with the same content and cause are the same message: this is what lets a
        retried delivery be recognised instead of duplicated.

        ``authority_context`` IS part of the content. It was omitted, which meant two messages
        differing only in the authority recorded against them produced the same digest -- and
        since the digest carries a UNIQUE index, the second was silently dropped. Losing the
        authority-bearing copy of a message is the worst possible direction for that failure.

        MEASURED DEFECT IN THE FIRST FIX: ``dict(self.authority_context)`` over a TUPLE OF
        STRINGS raised ValueError for every non-empty context -- so recording an executor
        message that named its authority profile crashed instead of persisting. A digest must
        never be the code path that decides whether evidence exists; serialise the sequence as
        a sequence.
        """
        return sha256_text(canonical_json({
            "type": self.message_type, "actor": self.actor_id, "program": self.program_id,
            "lane": self.lane_id, "run": self.run_id, "caused_by": self.caused_by,
            "payload": self.payload, "detail": dict(self.detail),
            "authority_context": [str(c) for c in (self.authority_context or ())],
            "protocol_version": self.protocol_version}))

    def to_dict(self) -> dict:
        return {"message_id": self.message_id, "message_type": self.message_type,
                "actor_id": self.actor_id, "program_id": self.program_id,
                "lane_id": self.lane_id, "run_id": self.run_id, "caused_by": self.caused_by,
                "authority_context": list(self.authority_context), "payload": self.payload,
                "detail": dict(self.detail), "created_at": self.created_at,
                "protocol_version": self.protocol_version, "awaits_answer": self.awaits_answer,
                "routed_to": self.routed_to, "digest": self.digest(),
                "instrument": self.instrument}



def _message_ctor_fields(self: Message) -> dict:
    """Constructor-shaped fields only -- ``to_dict`` adds derived keys the ctor rejects."""
    return {"message_id": self.message_id, "message_type": self.message_type,
            "actor_id": self.actor_id, "program_id": self.program_id, "lane_id": self.lane_id,
            "run_id": self.run_id, "caused_by": self.caused_by,
            "authority_context": self.authority_context, "payload": self.payload,
            "detail": self.detail, "created_at": self.created_at,
            "protocol_version": self.protocol_version}


Message.to_dict_ctor = _message_ctor_fields


def new_message(message_type: str, *, actor_id: str, lane_id: str = "", program_id: str = "",
                run_id: str = "", caused_by: str = "", payload: str = "",
                detail: Mapping | None = None, authority_context=(),
                now: float | None = None) -> Message:
    """Mint a message. Raises ValueError on an unknown type -- never defaults it."""
    if message_type not in MESSAGE_TYPES:
        raise ValueError("unknown message type %r; known types are %s"
                         % (message_type, list(MESSAGE_TYPES)))
    return Message(
        message_id="msg_" + uuid.uuid4().hex, message_type=message_type, actor_id=str(actor_id),
        program_id=str(program_id), lane_id=str(lane_id), run_id=str(run_id),
        caused_by=str(caused_by), payload=str(payload), detail=dict(detail or {}),
        authority_context=tuple(str(c) for c in (authority_context or ())),
        created_at=float(now if now is not None else time.time()))


def validate(doc: Mapping) -> tuple:
    """(outcome, reason). PURE. NEVER raises.

    Validates the ENVELOPE only. The payload is never inspected -- it is data, and a control plane
    that parses natural language for instructions has reintroduced prompt injection at the layer
    that was supposed to prevent it.
    """
    if not isinstance(doc, Mapping):
        return MALFORMED, "message must be an object"
    mt = str(doc.get("message_type") or "")
    if mt not in MESSAGE_TYPES:
        return UNKNOWN_TYPE, "unknown message type %r" % mt
    try:
        version = int(doc.get("protocol_version", MESSAGE_PROTOCOL_VERSION))
    except (TypeError, ValueError):
        return MALFORMED, "protocol_version must be an integer"
    if version != MESSAGE_PROTOCOL_VERSION:
        return PROTOCOL_REFUSED, ("message protocol %r is not supported; this build speaks %d"
                                  % (doc.get("protocol_version"), MESSAGE_PROTOCOL_VERSION))
    if not str(doc.get("actor_id") or ""):
        return MALFORMED, "actor_id is required: an unattributable message is not evidence"
    if not str(doc.get("lane_id") or ""):
        return MALFORMED, "lane_id is required: every message belongs to a lane"
    return VALID, ""


def authority_request_grants_nothing(msg: Message) -> dict:
    """The explicit statement that recording a request is not granting it. PURE.

    Returned into evidence so the record itself says so, rather than relying on a reader knowing
    it. An AUTHORITY_REQUEST is the executor asking; the answer is an owner grant elsewhere.
    """
    return {
        "message_id": msg.message_id,
        "requested": list(msg.detail.get("capabilities") or ()),
        "granted": [],
        "grants_authority": False,
        "note": ("recording an AUTHORITY_REQUEST creates an auditable record that the executor "
                 "asked. It confers nothing. A capability appears only via an owner grant in the "
                 "authority engine, which this message cannot write."),
    }

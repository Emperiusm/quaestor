"""domain -- the state model. Three ORTHOGONAL axes, and the legal transitions between them.

THE CENTRAL SEPARATION (spec section 4)
---------------------------------------
    EXECUTION STATE     what happened to the PROCESS
    PROMPT DISPOSITION  did Claude exhaust the authority this prompt granted?
    PROGRAM VERDICT     did the thing being investigated actually pass?

Collapsing these is the defect this file exists to prevent. A run can legitimately be::

    execution_state    = HANDOFF_READY
    prompt_disposition = COMPLETE
    program_verdict    = FAIL
    next_authority     = GPT_ORCHESTRATOR

and that is a SUCCESSFUL execution reporting a FAILING program. The orchestrator must never
translate ``PROGRAM_VERDICT=FAIL`` into "Claude did not finish", nor a refusal into "the gate
passed".

Everything here is PURE: no clock, no filesystem, no database.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------------------------
# EXECUTION STATE -- the transport/process axis
# ---------------------------------------------------------------------------------------------
CREATED = "CREATED"
PREFLIGHT = "PREFLIGHT"
LEASED = "LEASED"
DISPATCHED = "DISPATCHED"
RUNNING = "RUNNING"
RESULT_RECEIVED = "RESULT_RECEIVED"
EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
HANDOFF_READY = "HANDOFF_READY"
HANDED_TO_ORCHESTRATOR = "HANDED_TO_ORCHESTRATOR"

# Exceptional / terminal
PREFLIGHT_REFUSED = "PREFLIGHT_REFUSED"
LEASE_REFUSED = "LEASE_REFUSED"
AUTHORITY_REFUSED = "AUTHORITY_REFUSED"
PERMISSION_REFUSED = "PERMISSION_REFUSED"
CLAUDE_FAILED = "CLAUDE_FAILED"
INTERRUPTED = "INTERRUPTED"
WORKER_FAILED = "WORKER_FAILED"
RESULT_INVALID = "RESULT_INVALID"
EVIDENCE_INVALID = "EVIDENCE_INVALID"
AMBIGUOUS_EXECUTION = "AMBIGUOUS_EXECUTION"
OWNER_REQUIRED = "OWNER_REQUIRED"
CANCELLED = "CANCELLED"

ALL_STATES = (
    CREATED, PREFLIGHT, LEASED, DISPATCHED, RUNNING, RESULT_RECEIVED, EVIDENCE_COLLECTED,
    HANDOFF_READY, HANDED_TO_ORCHESTRATOR,
    PREFLIGHT_REFUSED, LEASE_REFUSED, AUTHORITY_REFUSED, PERMISSION_REFUSED, CLAUDE_FAILED,
    INTERRUPTED, WORKER_FAILED, RESULT_INVALID, EVIDENCE_INVALID, AMBIGUOUS_EXECUTION,
    OWNER_REQUIRED, CANCELLED,
)

#: States in which the execution MAY STILL BE RUNNING or may still spawn work. The
#: ``attempt_one_active`` partial UNIQUE index in store.py is built from exactly this tuple, so
#: "at most one active execution per dispatch key" is enforced by the DATABASE, not by an if
#: statement someone can forget to write.
ACTIVE_STATES = (CREATED, PREFLIGHT, LEASED, DISPATCHED, RUNNING, RESULT_RECEIVED,
                 EVIDENCE_COLLECTED)

TERMINAL_STATES = tuple(s for s in ALL_STATES if s not in ACTIVE_STATES)

#: An execution whose SIDE EFFECTS ARE UNKNOWN. The single hardest rule in the spec attaches
#: here: this must never auto-redispatch. See reconcile.may_redispatch.
UNCERTAIN_STATES = (AMBIGUOUS_EXECUTION,)


def is_active(state: str) -> bool:
    """PURE."""
    return state in ACTIVE_STATES


def is_terminal(state: str) -> bool:
    """PURE."""
    return state in TERMINAL_STATES


# The legal graph. Written out rather than derived, because an implicit graph is one nobody can
# review. Any refusal state is reachable from any active state -- a refusal is always legal.
_REFUSALS = (PREFLIGHT_REFUSED, LEASE_REFUSED, AUTHORITY_REFUSED, PERMISSION_REFUSED,
             OWNER_REQUIRED, CANCELLED, WORKER_FAILED, CLAUDE_FAILED, INTERRUPTED,
             RESULT_INVALID, EVIDENCE_INVALID, AMBIGUOUS_EXECUTION)

TRANSITIONS: dict = {
    CREATED: (PREFLIGHT,) + _REFUSALS,
    PREFLIGHT: (LEASED, DISPATCHED) + _REFUSALS,
    LEASED: (DISPATCHED,) + _REFUSALS,
    DISPATCHED: (RUNNING,) + _REFUSALS,
    RUNNING: (RESULT_RECEIVED,) + _REFUSALS,
    RESULT_RECEIVED: (EVIDENCE_COLLECTED,) + _REFUSALS,
    EVIDENCE_COLLECTED: (HANDOFF_READY,) + _REFUSALS,
    HANDOFF_READY: (HANDED_TO_ORCHESTRATOR,),
    HANDED_TO_ORCHESTRATOR: (),
}
for _s in TERMINAL_STATES:
    TRANSITIONS.setdefault(_s, ())


def can_transition(src: str, dst: str) -> bool:
    """Is ``src -> dst`` legal? PURE.

    Note what is deliberately absent: there is no edge OUT of AMBIGUOUS_EXECUTION,
    RESULT_INVALID, or any other terminal state back into an active one. Recovery from an
    uncertain execution is a NEW dispatch made by a human or by GPT after inspection -- it is
    never a state transition this process can perform on its own.
    """
    if src not in TRANSITIONS or dst not in ALL_STATES:
        return False
    return dst in TRANSITIONS[src]


# ---------------------------------------------------------------------------------------------
# PROMPT DISPOSITION -- did Claude exhaust the authority this prompt granted?
# ---------------------------------------------------------------------------------------------
COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
PROMPT_DISPOSITIONS = (COMPLETE, PARTIAL, BLOCKED, FAILED)

# ---------------------------------------------------------------------------------------------
# PROGRAM VERDICT -- did the thing under investigation pass?
# ---------------------------------------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
NOT_EVALUATED = "NOT_EVALUATED"
PROGRAM_VERDICTS = (PASS, FAIL, NOT_EVALUATED)

# ---------------------------------------------------------------------------------------------
# NEXT AUTHORITY -- who decides what happens next?
# ---------------------------------------------------------------------------------------------
NONE = "NONE"
GPT_ORCHESTRATOR = "GPT_ORCHESTRATOR"
OWNER = "OWNER"
EXTERNAL_EVENT = "EXTERNAL_EVENT"
NEXT_AUTHORITIES = (NONE, GPT_ORCHESTRATOR, OWNER, EXTERNAL_EVENT)


def handoff_is_ready(*, result_valid: bool, evidence_ok: bool) -> bool:
    """Can this run reach HANDOFF_READY? PURE.

    ``program_verdict`` is DELIBERATELY NOT A PARAMETER. That absence is the whole point of the
    orthogonal state model: whether the project gate passed has no bearing on whether the bridge
    has a deliverable handoff. Adding it here would silently reintroduce the collapse this
    module exists to prevent, so the omission is load-bearing and must not be "fixed".

    Both inputs are checked as LITERAL booleans (see canon.is_true) by the caller.
    """
    return result_valid is True and evidence_ok is True

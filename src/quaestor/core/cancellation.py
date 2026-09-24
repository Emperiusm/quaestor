"""cancellation -- stopping a process is not the same as the side effects never having happened.

THE ONE CONFUSION THIS MODULE EXISTS TO PREVENT
------------------------------------------------
    "we killed it"      is a statement about a PROCESS.
    "nothing happened"  is a statement about the WORLD.

They coincide only when you can prove no write-capable execution began, or when you measured the
target afterwards and found it unchanged. Everywhere else, calling a cancellation CLEAN is a
fabricated success -- and it is worse than an ordinary bug, because the operator's next action is
chosen on the strength of it.

THE LADDER, and what each rung may honestly claim
-------------------------------------------------
    BEFORE THE WORKER             nothing was dispatched            -> CANCELLED
    BEFORE THE CONTAINER          no execution environment existed  -> CANCELLED
    CONTAINER UP, NO CHILD        a container ran no child          -> CANCELLED, if measured
    CHILD RUNNING, READ_ONLY      terminate, measure, classify      -> CANCELLED / INTERRUPTED
    CHILD RUNNING, WRITE-CAPABLE  terminate, THEN measure the target
                                    measured unchanged              -> CANCELLED_UNCHANGED
                                    measured changed                -> INTERRUPTED (side effects)
                                    could not measure               -> AMBIGUOUS_EXECUTION

CANCELLATION NEVER TRIGGERS REDISPATCH. Nothing in this module or its callers restarts anything;
recovery is a new, deliberate dispatch with a new identity, exactly as for any other uncertain
run.

DUPLICATE CANCEL IS IDEMPOTENT. A second cancel of an already-terminal run reports the existing
outcome and destroys nothing -- an operator hitting cancel twice must not escalate a clean stop
into a forced teardown.

PURE module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core import domain

CANCELLATION_INSTRUMENT = "cancellation/1"

# Stages at which a cancel can arrive
STAGE_BEFORE_WORKER = "BEFORE_WORKER"
STAGE_BEFORE_CONTAINER = "BEFORE_CONTAINER"
STAGE_CONTAINER_NO_CHILD = "CONTAINER_STARTED_NO_CHILD"
STAGE_CHILD_RUNNING = "CHILD_RUNNING"
STAGE_ALREADY_TERMINAL = "ALREADY_TERMINAL"

# Outcomes
CANCELLED = domain.CANCELLED
CANCELLED_UNCHANGED = "CANCELLED"          # same durable state; the reason string carries proof
INTERRUPTED = domain.INTERRUPTED
AMBIGUOUS = domain.AMBIGUOUS_EXECUTION
NOOP = "ALREADY_TERMINAL"


@dataclass(frozen=True)
class CancelDecision:
    outcome: str
    stage: str
    reason: str
    may_redispatch: bool = False
    target_measured: bool | None = None
    idempotent_noop: bool = False
    evidence: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "stage": self.stage, "reason": self.reason,
                "may_redispatch": self.may_redispatch,
                "target_measured": self.target_measured,
                "idempotent_noop": self.idempotent_noop,
                "instrument": CANCELLATION_INSTRUMENT, "evidence": dict(self.evidence)}


def classify_cancel(*, run_state: str, stage: str, is_write_capable: bool,
                    child_started: bool, target_measurable: bool | None,
                    target_changed: bool | None) -> CancelDecision:
    """What may this cancellation honestly claim? PURE. NEVER raises.

    ``target_measurable`` is tri-state on purpose. False and None are different: "we looked and
    could not read it" and "we never looked" are both refusals to claim cleanliness, but they
    point an operator at different next steps.
    """
    ev = {"run_state": run_state, "stage": stage, "is_write_capable": bool(is_write_capable),
          "child_started": bool(child_started), "target_measurable": target_measurable,
          "target_changed": target_changed}

    if domain.is_terminal(run_state):
        return CancelDecision(NOOP, STAGE_ALREADY_TERMINAL,
                              "run is already terminal in state %s; cancel is a no-op and "
                              "destroys nothing" % run_state,
                              False, None, True, ev)

    if stage in (STAGE_BEFORE_WORKER, STAGE_BEFORE_CONTAINER):
        return CancelDecision(CANCELLED, stage,
                              "cancelled before any execution environment existed; no side "
                              "effect was possible", False, None, False, ev)

    if stage == STAGE_CONTAINER_NO_CHILD and not child_started:
        if target_measurable is True and target_changed is False:
            return CancelDecision(CANCELLED, stage,
                                  "a container existed but no child ran, and the target was "
                                  "measured unchanged", False, True, False, ev)
        return CancelDecision(INTERRUPTED, stage,
                              "a container existed but the target could not be measured; the "
                              "stop is honest, the cleanliness is not established",
                              False, target_measurable, False, ev)

    # A child was running.
    if not is_write_capable:
        if target_measurable is True and target_changed is False:
            return CancelDecision(CANCELLED, stage,
                                  "read-only child terminated and the target measured unchanged",
                                  False, True, False, ev)
        if target_changed is True:
            return CancelDecision(INTERRUPTED, stage,
                                  "a read-only child was terminated and the target CHANGED; that "
                                  "contradicts the profile and is not a clean cancel",
                                  False, True, False, ev)
        return CancelDecision(INTERRUPTED, stage,
                              "read-only child terminated but the target could not be measured",
                              False, target_measurable, False, ev)

    # Write-capable child.
    if target_measurable is not True:
        return CancelDecision(AMBIGUOUS, stage,
                              "a write-capable child was terminated and its target could NOT be "
                              "measured. Whether side effects landed is unknown, so this is "
                              "AMBIGUOUS and must not be retried automatically.",
                              False, target_measurable, False, ev)
    if target_changed is True:
        return CancelDecision(INTERRUPTED, stage,
                              "a write-capable child was terminated AFTER it had already changed "
                              "the target; the process stopped, the side effects did not "
                              "un-happen", False, True, False, ev)
    return CancelDecision(CANCELLED, stage,
                          "write-capable child terminated and the target was measured unchanged; "
                          "cleanliness is asserted from the MEASUREMENT, not from the kill",
                          False, True, False, ev)


def stage_for(run_state: str, *, container_created: bool, child_started: bool) -> str:
    """Map observable facts to a cancellation stage. PURE."""
    if domain.is_terminal(run_state):
        return STAGE_ALREADY_TERMINAL
    if child_started:
        return STAGE_CHILD_RUNNING
    if container_created:
        return STAGE_CONTAINER_NO_CHILD
    if run_state in (domain.CREATED, domain.PREFLIGHT, domain.LEASED):
        return STAGE_BEFORE_WORKER
    return STAGE_BEFORE_CONTAINER

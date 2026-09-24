"""retention -- a container is disposable; the evidence it produced is not.

THREE THINGS THAT ARE ROUTINELY CONFLATED
------------------------------------------
    execution completion   the child finished
    container teardown     the execution environment was removed
    evidence retention     the record of what happened still exists

Cleanup code that treats them as one deletes the run directory of exactly the runs whose
directories matter most -- the ambiguous ones, the security failures, the ones where somebody
will later need to know precisely what was on disk.

FOR P2.5: AUTOMATIC EVIDENCE DELETION IS OFF. This module is REPORT-ONLY. ``sweep`` returns what
*would* be eligible and deletes nothing; there is no code path here that removes a file. That is
not a stub to be filled in later -- an unattended garbage collector that gets liveness or
classification wrong destroys the only account of a run, and the source deployment has already paid once for a
sweep that would have deleted an 11.7 KB document existing in no commit anywhere.

PURE module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor.core import domain

RETENTION_INSTRUMENT = "retention/1"

ACTIVE = "ACTIVE"
RETAIN = "RETAIN"
ELIGIBLE_FOR_GC = "ELIGIBLE_FOR_GC"
OWNER_HOLD = "OWNER_HOLD"

#: Automatic evidence deletion, for this phase. Not a tunable: a constant so that turning it on
#: is a code change somebody reviews.
AUTOMATIC_EVIDENCE_GC = False

#: States whose evidence must NEVER become automatically disposable. Each is a state in which the
#: run directory is the only place the truth lives.
OWNER_HOLD_STATES = (
    domain.AMBIGUOUS_EXECUTION,   # side effects unknown -- the fixture and logs are the record
    domain.EVIDENCE_INVALID,      # the measurement disagreed with the report
    domain.OWNER_REQUIRED,        # an authority decision is pending
)
SECURITY_HOLD_REASONS = ("SECURITY_BOUNDARY_FAIL", "CONTAINER_POLICY_REFUSED")


@dataclass(frozen=True)
class RetentionDecision:
    run_id: str
    retention_class: str
    reason: str
    container_removable: bool = False
    auth_volume_removable: bool = False
    evidence_removable: bool = False
    detail: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "retention_class": self.retention_class,
                "reason": self.reason, "container_removable": self.container_removable,
                "auth_volume_removable": self.auth_volume_removable,
                "evidence_removable": self.evidence_removable,
                "instrument": RETENTION_INSTRUMENT, "detail": dict(self.detail)}


def classify(*, run_id: str, execution_state: str, refusal_reason: str = "",
             min_age_s: float = 0.0, age_s: float | None = None) -> RetentionDecision:
    """What may be reclaimed for this run? PURE. NEVER raises.

    ``evidence_removable`` is the only field that could destroy information, and it is False for
    every hold class. Note that even ELIGIBLE_FOR_GC does not mean "delete it": with
    AUTOMATIC_EVIDENCE_GC off, eligibility is a report, and ``sweep`` acts on nothing.

    The AUTH VOLUME is never removable from here. It holds subscription credentials whose
    re-provisioning needs the owner, so an automated cleanup that drops it converts a tidy-up
    into an outage.
    """
    detail = {"execution_state": execution_state, "refusal_reason": refusal_reason,
              "age_s": age_s, "min_age_s": min_age_s}

    if execution_state in OWNER_HOLD_STATES:
        return RetentionDecision(run_id, OWNER_HOLD,
                                 "state %s: the run directory is the only account of what "
                                 "happened; it is never automatically disposable"
                                 % execution_state,
                                 container_removable=True, detail=detail)

    if any(k in str(refusal_reason or "") for k in SECURITY_HOLD_REASONS):
        return RetentionDecision(run_id, OWNER_HOLD,
                                 "a confinement/security refusal is recorded; evidence is held "
                                 "for review", container_removable=True, detail=detail)

    if not domain.is_terminal(execution_state):
        return RetentionDecision(run_id, ACTIVE,
                                 "run is still active in state %s; nothing may be reclaimed"
                                 % execution_state, detail=detail)

    if age_s is None or float(age_s) < float(min_age_s):
        return RetentionDecision(run_id, RETAIN,
                                 "terminal but younger than the retention window "
                                 "(age=%s, min=%s)" % (age_s, min_age_s),
                                 container_removable=True, detail=detail)

    return RetentionDecision(run_id, ELIGIBLE_FOR_GC,
                             "terminal, clean, and older than the retention window -- ELIGIBLE "
                             "is a report, not an instruction; AUTOMATIC_EVIDENCE_GC is %s"
                             % ("ON" if AUTOMATIC_EVIDENCE_GC else "OFF"),
                             container_removable=True, evidence_removable=False, detail=detail)


def sweep(runs: Sequence[Mapping], *, min_age_s: float = 0.0,
          now: float = 0.0) -> dict:
    """REPORT-ONLY eligibility across many runs. PURE. Deletes nothing, ever."""
    decisions = []
    for r in runs or ():
        terminal_at = r.get("terminal_at")
        age = (float(now) - float(terminal_at)) if terminal_at else None
        decisions.append(classify(run_id=str(r.get("run_id") or ""),
                                  execution_state=str(r.get("execution_state") or ""),
                                  refusal_reason=str(r.get("refusal_reason") or ""),
                                  min_age_s=min_age_s, age_s=age))
    counts = {}
    for d in decisions:
        counts[d.retention_class] = counts.get(d.retention_class, 0) + 1
    return {
        "automatic_evidence_gc": AUTOMATIC_EVIDENCE_GC,
        "deleted": [],
        "inspected_count": len(decisions),
        "counts": counts,
        "decisions": [d.to_dict() for d in decisions],
        "note": ("report-only: this function has no delete path. Eligibility is an observation "
                 "for an operator, not an action."),
    }

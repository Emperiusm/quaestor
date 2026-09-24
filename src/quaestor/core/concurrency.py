"""concurrency -- an explicit ceiling on REAL Claude children, recorded with every run.

WHY A CEILING BEFORE A TRANSPORT EXISTS
---------------------------------------
Today a human starts each run, so "how many at once" is answered by how fast someone can type.
The moment a transport can dispatch, that answer becomes "as many as arrive", and an unattended
fleet of real children is both a spend problem and a safety problem: every one of them holds a
lease, a container, and write authority.

The policy is therefore made explicit NOW, while it is cheap, and PERSISTED WITH EACH RUN so a
later reader can see which ceiling governed a given execution rather than inferring today's
constant applied historically.

FAKE EXECUTORS ARE NOT COUNTED, and that is deliberate: the mutation suite runs many of them
concurrently and must keep being able to. The ceiling is about real subscription-backed children
-- the things that cost money, hold leases, and touch a worktree.

PURE decision core; the caller supplies the current census from the durable store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

CONCURRENCY_INSTRUMENT = "concurrency/1"

#: One. Not a performance number -- a blast-radius number.
DEFAULT_MAX_ACTIVE_REAL_CHILDREN = 1

ADMIT = "ADMIT"
CONCURRENCY_REFUSED = "CONCURRENCY_REFUSED"

#: Executor kinds that consume subscription capacity and hold real resources.
REAL_EXECUTOR_KINDS = ("claude-cli", "claude-container")


@dataclass(frozen=True)
class ConcurrencyPolicy:
    max_active_real_children: int = DEFAULT_MAX_ACTIVE_REAL_CHILDREN
    instrument: str = CONCURRENCY_INSTRUMENT
    note: str = ("fake executors are exempt on purpose: the ceiling governs subscription-backed "
                 "children that hold leases, containers and write authority")

    def to_dict(self) -> dict:
        return {"max_active_real_children": int(self.max_active_real_children),
                "instrument": self.instrument, "note": self.note}


@dataclass(frozen=True)
class ConcurrencyDecision:
    decision: str
    active_count: int
    limit: int
    active_run_ids: tuple = ()
    reason: str = ""
    policy: Mapping = field(default_factory=dict)

    @property
    def admitted(self) -> bool:
        return self.decision == ADMIT


def is_real_executor(executor: Mapping | None) -> bool:
    """PURE. Unknown kinds count as REAL.

    Fail-closed: a new executor nobody classified is more likely to be a real one than a fake,
    and being wrong in the permissive direction here means an unbounded fleet.
    """
    kind = str((executor or {}).get("kind") or "").strip()
    if not kind:
        return True
    return kind != "fake"


def decide(*, active_real_runs: Sequence[Mapping], requested_executor: Mapping | None,
           policy: ConcurrencyPolicy | None = None) -> ConcurrencyDecision:
    """May another real child start? PURE. NEVER raises.

    A refusal is a DURABLE state, not a silent skip. The specification is explicit that the
    second request must become CONCURRENCY_REFUSED or a queued state and must not quietly launch
    anything -- a caller that ignores this decision and spawns anyway would be defeating the one
    control that bounds real-child fan-out.
    """
    pol = policy or ConcurrencyPolicy()
    if not is_real_executor(requested_executor):
        return ConcurrencyDecision(ADMIT, 0, pol.max_active_real_children, (),
                                   "fake executor: not subject to the real-child ceiling",
                                   pol.to_dict())
    ids = tuple(str(r.get("run_id") or "") for r in (active_real_runs or ()))
    count = len(ids)
    if count >= int(pol.max_active_real_children):
        return ConcurrencyDecision(
            CONCURRENCY_REFUSED, count, int(pol.max_active_real_children), ids,
            ("%d real Claude child/children are already active and the ceiling is %d. The second "
             "request is refused rather than queued silently: a queue nobody drains looks "
             "identical to a run that never happened."
             % (count, int(pol.max_active_real_children))),
            pol.to_dict())
    return ConcurrencyDecision(ADMIT, count, int(pol.max_active_real_children), ids, "",
                               pol.to_dict())

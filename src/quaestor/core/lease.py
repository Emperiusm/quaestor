"""lease -- exclusive, path-keyed, drift-checked ownership of a mutable worktree.

ONE WRITER PER WORKTREE. That is the operating doctrine and it exists because the repository
has measured incidents of multiple writers moving branches and swallowing edits. This module is
that doctrine expressed as machine state.

THE JOIN KEY IS THE CANONICAL WORKTREE PATH (canon.canonical_path), for the identity reason:
the identity a lease is written under must be the exact identity the next request is looked up
by. The UNIQUE partial index in store.py sits on that column, so the second lease is refused by
the DATABASE and not by an ``if`` that a future code path can route around.

THREE THINGS A LEASE IS NOT
---------------------------
 1. A lease is NOT proof the tree is unchanged. It is re-verified against live HEAD/branch
    immediately before the child launches -- the window between admission and dispatch is exactly
    where another lane's commit lands.
 2. A STALE lease is NOT proof of ownership. A heartbeat that stopped is an absence of evidence.
    ``ownership_proof`` returns STALE_UNPROVEN and dispatch refuses on it.
 3. A stale lease is NOT permission to reclaim, either. Reclamation requires the holder to be
    provably DEAD *and* its run to be terminal. UNKNOWN reclaims nothing.

PURE module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from quaestor.core import domain
from quaestor.core import proc
from quaestor.core.canon import canonical_path

# Acquisition decisions
GRANT = "GRANT"
ALREADY_HELD_BY_THIS_RUN = "ALREADY_HELD_BY_THIS_RUN"
REFUSE_CONFLICT = "REFUSE_CONFLICT"

# Ownership proof
PROVEN = "PROVEN"
STALE_UNPROVEN = "STALE_UNPROVEN"
NOT_HELD = "NOT_HELD"

#: A lease whose heartbeat is older than this is no longer self-evidently owned. Generous: a
#: worker blocked on a long Claude turn writes nothing, and calling that lease dead would evict a
#: live writer. It never authorises reclamation on its own -- see may_reclaim.
DEFAULT_HEARTBEAT_STALE_S = 900.0


@dataclass(frozen=True)
class LeaseRequest:
    repo_id: str
    worktree_path: str
    expected_branch: str
    expected_head: str
    run_id: str
    mutable: bool = True

    @property
    def key(self) -> str:
        return canonical_path(self.worktree_path)


@dataclass(frozen=True)
class LeaseDecision:
    decision: str
    reason: str = ""
    conflicting_run_id: str = ""

    @property
    def granted(self) -> bool:
        return self.decision in (GRANT, ALREADY_HELD_BY_THIS_RUN)


def decide_acquire(request: LeaseRequest, active: Mapping | None) -> LeaseDecision:
    """May ``request`` take the lease, given the currently ACTIVE lease on that path? PURE.

    ``active`` is the row with ``released_at IS NULL`` for this path, or None.

    Re-entrancy is explicit: a run that already holds the lease gets ALREADY_HELD_BY_THIS_RUN
    rather than a conflict, because a reconciling dispatcher must be able to re-enter its own
    lease without evicting itself. Every OTHER holder conflicts, unconditionally -- there is no
    "but the holder looks idle" branch here, and there must never be one: idleness is judged in
    ``may_reclaim`` against real liveness, not inferred at acquisition time.
    """
    if active is None:
        return LeaseDecision(GRANT)
    holder = str(active.get("holder_run_id") or "")
    if holder == str(request.run_id):
        return LeaseDecision(ALREADY_HELD_BY_THIS_RUN, "this run already holds the lease", holder)
    return LeaseDecision(
        REFUSE_CONFLICT,
        ("worktree %s is already leased to run %s (acquired %s). One writer per worktree: the "
         "second execution is refused, not queued behind a lock that could deadlock it."
         % (canonical_path(request.worktree_path), holder, active.get("acquired_at"))),
        holder)


def ownership_proof(active: Mapping | None, *, run_id: str, now: float,
                    heartbeat_stale_s: float = DEFAULT_HEARTBEAT_STALE_S) -> str:
    """Can this run PROVE it still owns the lease right now? PURE.

    Called immediately before dispatch. A lease row is a record that ownership was granted at
    some past instant; this asks whether that record is still evidence. It is not, once the
    heartbeat has gone quiet -- at which point the run must reconcile rather than proceed on the
    strength of a row it wrote itself.
    """
    if active is None:
        return NOT_HELD
    if str(active.get("holder_run_id") or "") != str(run_id):
        return NOT_HELD
    if active.get("released_at") is not None:
        return NOT_HELD
    hb = active.get("heartbeat_at")
    if hb is None:
        return STALE_UNPROVEN
    if (float(now) - float(hb)) > float(heartbeat_stale_s):
        return STALE_UNPROVEN
    return PROVEN


def liveness_permits_reclaim(holder_liveness: str) -> bool:
    """The half of ``may_reclaim`` that a caller may ask BEFORE it acts. PURE.

    ``may_reclaim`` joins two conditions, and only one of them is ever in doubt at the moment a
    caller has to commit. A reaper that is about to recover a dead worker MAKES the run terminal
    itself, so asking the terminal half afterwards is asking a question it has already answered;
    asking the whole predicate BEFORE the transition answers False for a reason that says
    nothing about the worker. This is the half that is nobody's choice: is the holder PROVABLY
    DEAD? A caller that reads False here must not enter the destructive path at all -- no
    reclaim will be permitted for that reading, and a lease left held by a run that has already
    gone terminal is reachable by no release path in the tree.

    ``proc.UNKNOWN`` is False, exactly as in ``may_reclaim``: absence of evidence is not
    evidence the worker is gone.
    """
    return holder_liveness == proc.DEAD


def may_reclaim(active: Mapping | None, *, holder_run_state: str, holder_liveness: str) -> bool:
    """May the lease be released on the holder's behalf? PURE.

    BOTH conditions, and neither alone:

      * the holder's RUN is in a terminal execution state (the control plane's own record says
        the execution is over), AND
      * the holder PROCESS is provably DEAD (proc.classify_liveness, which never says DEAD on one
        signal).

    ``proc.UNKNOWN`` reclaims nothing. That is the entire safety property: a worker that is
    quietly running a 40-minute Claude turn looks identical, from the outside, to one that
    vanished -- and only one of those may have its lease taken away.
    """
    if active is None:
        return False
    if not liveness_permits_reclaim(holder_liveness):
        return False
    return domain.is_terminal(str(holder_run_state))

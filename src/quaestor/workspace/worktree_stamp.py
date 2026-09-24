"""worktree_stamp -- validate a worktree's ownership marker.

WHOSE FORMAT THIS IS
--------------------
The marker is written by a DEPLOYMENT's worktree helper, not by this platform: something like
`scripts/worktree-new.sh` writes `<worktree>/.worktree-owner.json` as part of CREATING the
worktree, so ownership is produced by construction. This module does not replace that mechanism
-- it CONSUMES it, because a control plane that leases a directory on the strength of "we ran
the helper and it exited 0" is trusting a mechanism instead of verifying a result. (It was
measured that exact distinction: a `sparse-checkout set` that exits 0 proves only that git
accepted a string.)

The KEY NAMES below are therefore a wire format belonging to whichever helper writes the marker,
and `task_ref` accepts the generic key as well as the issue-tracker-specific one the first
deployment used. A platform that hard-codes one shop's ticket vocabulary is not a platform; a
platform that refuses to read the marker a real deployment already writes is not usable. Reading
both, and exposing the generic name, is the seam.

THE FOUND-AT-vs-DECLARED ASSERTION
----------------------------------
`marker_is_for` requires the marker's own declared `worktree_path` to be the same directory as
the path it was FOUND at. A marker naming another directory is FOREIGN and licenses nothing --
a copied worktree, a renamed directory, or a `cp -r` must not let one session's stamp vouch for a
directory it has never heard of. The GPU reaper killed a live box because a heartbeat was written
under one identity and looked up under another; this is that probe inverted into a gate.

PURE decision core; one I/O reader at the bottom.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core.canon import canonical_path

MARKER_NAME = ".worktree-owner.json"

VALID = "VALID"
NO_MARKER = "NO_MARKER"
MARKER_UNREADABLE = "MARKER_UNREADABLE"
MARKER_FOREIGN = "MARKER_FOREIGN"
SESSION_MISMATCH = "SESSION_MISMATCH"
BRANCH_MISMATCH = "BRANCH_MISMATCH"
NOT_ATTRIBUTABLE = "NOT_ATTRIBUTABLE"


@dataclass(frozen=True)
class StampVerdict:
    outcome: str
    reason: str = ""
    session_id: str = ""
    #: The work item this worktree was created for. Read from the marker's `task_ref` key, or
    #: from the `bead` key the first deployment's helper wrote -- one deployment's issue tracker
    #: is not part of this platform's vocabulary, but its files already exist.
    task_ref: str = ""
    branch: str = ""
    created_by: str = ""
    marker: Mapping = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return self.outcome == VALID


def marker_is_for(marker: Mapping | None, enumerated_path: str) -> bool:
    """True iff the marker's declared path IS the directory it was found at. PURE.

    Fail-safe: a missing or empty declaration is NOT a match. An absence of evidence must never
    read as permission.
    """
    if not marker:
        return False
    declared = canonical_path(marker.get("worktree_path"))
    if not declared:
        return False
    return declared == canonical_path(enumerated_path)


def validate_stamp(marker: Mapping | None, *, path: str, expected_session: str = "",
                   expected_branch: str = "") -> StampVerdict:
    """Is this worktree stamped, and stamped for US? PURE. NEVER raises.

    ``expected_session`` is what makes the verdict ATTRIBUTABLE rather than merely present. A
    stamped worktree whose owner is somebody else is exactly the foreign live state this run must
    not touch, and it is indistinguishable from ours unless the session id is compared.

    An EMPTY declared session is refused when a session was expected: `worktree-new.sh` writes an
    empty `session_id` when it cannot derive one, which the sweeper reads as "ownership unknown".
    Unknown ownership is a legitimate state for the sweeper to fall back from; it is NOT a basis
    for this control plane to claim the directory as its own.
    """
    if marker is None:
        return StampVerdict(NO_MARKER,
                            "no %s at %s: the worktree was not created by the canonical helper, "
                            "or the stamp was removed" % (MARKER_NAME, path))
    if not isinstance(marker, Mapping) or not marker:
        return StampVerdict(MARKER_UNREADABLE, "the marker at %s is not a JSON object" % path)

    if not marker_is_for(marker, path):
        return StampVerdict(
            MARKER_FOREIGN,
            "the marker declares worktree_path=%r but was found at %r; a stamp that does not name "
            "where it lives licenses nothing"
            % (marker.get("worktree_path"), canonical_path(path)),
            marker=dict(marker))

    session = str(marker.get("session_id") or "").strip()
    branch = str(marker.get("branch") or "").strip()
    task_ref = str(marker.get("task_ref") or marker.get("bead") or "").strip()
    created_by = str(marker.get("created_by") or "").strip()

    if expected_session:
        if not session:
            return StampVerdict(NOT_ATTRIBUTABLE,
                                "the marker records no session_id, so this worktree cannot be "
                                "attributed to this execution", "", task_ref, branch, created_by,
                                dict(marker))
        if session != str(expected_session):
            return StampVerdict(SESSION_MISMATCH,
                                "the marker is owned by session %r, not %r -- FOREIGN LIVE STATE"
                                % (session, expected_session), session, task_ref, branch, created_by,
                                dict(marker))

    if expected_branch and branch != str(expected_branch):
        return StampVerdict(BRANCH_MISMATCH,
                            "the marker names branch %r, expected %r" % (branch, expected_branch),
                            session, task_ref, branch, created_by, dict(marker))

    return StampVerdict(VALID, "", session, task_ref, branch, created_by, dict(marker))


def read_marker(worktree_path: str) -> Mapping | None:
    """The marker dict, or None when absent/unreadable. Impure. NEVER raises."""
    try:
        with open(os.path.join(str(worktree_path), MARKER_NAME), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def inspect(worktree_path: str, *, expected_session: str = "",
            expected_branch: str = "") -> StampVerdict:
    """``validate_stamp`` with the marker read from disk. Impure."""
    return validate_stamp(read_marker(worktree_path), path=worktree_path,
                          expected_session=expected_session, expected_branch=expected_branch)

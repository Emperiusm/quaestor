"""evidence -- what the BRIDGE measured, as opposed to what Claude reported.

THE INSTRUMENT DOCTRINE, APPLIED
--------------------------------
the source deployment paid for these four clauses with seven independent incidents; they are the whole design of
this file.

 1. AN EVIDENCE RECORD CARRIES A COUNT OF WHAT IT INSPECTED, and a probe that inspected nothing
    is VACUOUS, never CLEAN. ``inspected_count`` is the count and ``min_inspected`` is the floor.
    A gate with no floor cannot tell "the tree is clean" from "I did not look at the tree".
 2. A CONTROL THAT CONSUMES ONLY YOUR OWN OUTPUT TESTS SERIALIZATION, NOT VERIFICATION. So the
    executor's ``claimed_files_changed`` is never the input to the change decision; it is only
    ever COMPARED against a measurement taken from git by a different code path.
 3. THE VERDICT STATES ITS ENVIRONMENT. ``probe_ok`` is a literal boolean and a failed probe
    yields UNAVAILABLE -- a refusal -- rather than an empty change set that reads as "nothing
    changed".
 4. ABSENT IS NOT ZERO. ``None`` and ``[]`` are different answers everywhere in this module.

PURE module. ``repo.py`` does the git I/O and hands snapshots in.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping, Sequence

from quaestor.core.canon import canonical_json, is_true, sha256_text

# Evidence verdicts
OK = "OK"
UNAVAILABLE = "UNAVAILABLE"        # the probe failed -> we never looked
VACUOUS = "VACUOUS"                # the probe ran but inspected below the floor
DISAGREEMENT = "DISAGREEMENT"      # report and measurement contradict each other

# Named disagreements
CLAIMED_CLEAN_BUT_CHANGED = "CLAIMED_CLEAN_BUT_CHANGED"
CLAIMED_CHANGED_BUT_CLEAN = "CLAIMED_CHANGED_BUT_CLEAN"
HEAD_MOVED_WITHOUT_AUTHORITY = "HEAD_MOVED_WITHOUT_AUTHORITY"
BRANCH_MOVED_WITHOUT_AUTHORITY = "BRANCH_MOVED_WITHOUT_AUTHORITY"


@dataclass(frozen=True)
class RepoSnapshot:
    """One independent reading of a repository at one instant.

    ``probe_ok=False`` means git could not be interrogated. Every other field is then
    meaningless and MUST NOT be read as a measurement -- which is why ``changed_paths`` defaults
    to None (unknown) rather than () (measured empty).
    """

    repo_root: str = ""
    branch: str | None = None
    head: str | None = None
    dirty: bool | None = None
    changed_paths: tuple | None = None      # tracked modifications + untracked, porcelain order
    tracked_file_count: int = 0             # THE FLOOR: how many files this probe actually saw
    status_digest: str | None = None
    diff_sha256: str | None = None
    probe_ok: bool = False
    probe_error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["changed_paths"] = None if self.changed_paths is None else list(self.changed_paths)
        return d


@dataclass(frozen=True)
class EvidenceEnvelope:
    """The bridge's independent account of one run."""

    verdict: str
    before: RepoSnapshot
    after: RepoSnapshot
    observed_changed: tuple = ()
    observed_change: bool | None = None
    inspected_count: int = 0
    disagreements: tuple = ()
    reason: str = ""
    extra: Mapping = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.verdict == OK

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "observed_changed": list(self.observed_changed),
            "observed_change": self.observed_change,
            "inspected_count": self.inspected_count,
            "disagreements": list(self.disagreements),
            "reason": self.reason,
            "extra": dict(self.extra),
        }


def snapshot_digest(paths: Sequence[str]) -> str:
    """Stable digest of a porcelain path set. PURE."""
    return sha256_text(canonical_json(sorted(str(p) for p in paths)))


def observed_change_set(before: RepoSnapshot, after: RepoSnapshot) -> tuple:
    """Paths that differ between two readings. PURE.

    The union of the symmetric difference, not ``after`` alone: a file that was dirty before and
    is clean after has ALSO been changed by the run (it was reverted or committed), and reporting
    only ``after`` would call that "no change".
    """
    b = set(before.changed_paths or ())
    a = set(after.changed_paths or ())
    return tuple(sorted(b.symmetric_difference(a)))


def build_envelope(before: RepoSnapshot, after: RepoSnapshot, *,
                   claimed_change: bool | None,
                   may_move_head: bool = False,
                   min_inspected: int = 1,
                   extra: Mapping | None = None) -> EvidenceEnvelope:
    """Turn two readings plus a report claim into a verdict. PURE. NEVER raises.

    Order, and why each step comes where it does:

      1. PROBE FAILURE FIRST -> UNAVAILABLE. A failed probe has no change set, and an empty
         change set from a failed probe is the "PASS over three unread LFS pointers" defect.
      2. THE FLOOR -> VACUOUS. A probe that saw fewer than ``min_inspected`` tracked files did
         not look at a repository, whatever it returned. Reporting that as "clean" is the
         ``unresolved 0`` over zero files incident, exactly.
      3. UNAUTHORISED MOVEMENT. HEAD or branch moving on a run that was not granted commit
         authority is a disagreement with the ENVELOPE, independent of anything Claude said.
      4. CLAIM VS MEASUREMENT, both directions. Tri-state claim: None means the report made no
         claim, and no claim can contradict a measurement.
    """
    extra = dict(extra or {})
    inspected = int(min(before.tracked_file_count, after.tracked_file_count)
                    if (is_true(before.probe_ok) and is_true(after.probe_ok))
                    else max(before.tracked_file_count, after.tracked_file_count))

    if not (is_true(before.probe_ok) and is_true(after.probe_ok)):
        which = []
        if not is_true(before.probe_ok):
            which.append("before(%s)" % (before.probe_error or "probe failed"))
        if not is_true(after.probe_ok):
            which.append("after(%s)" % (after.probe_error or "probe failed"))
        return EvidenceEnvelope(
            UNAVAILABLE, before, after, observed_change=None, inspected_count=inspected,
            reason=("repository could not be measured: %s. An unmeasured tree is UNAVAILABLE, "
                    "never clean." % "; ".join(which)),
            extra=extra)

    if inspected < int(min_inspected):
        return EvidenceEnvelope(
            VACUOUS, before, after, observed_change=None, inspected_count=inspected,
            reason=("evidence floor not met: inspected %d tracked file(s), floor is %d. A probe "
                    "that inspected nothing cannot distinguish 'clean' from 'did not look'."
                    % (inspected, int(min_inspected))),
            extra=extra)

    changed = observed_change_set(before, after)
    head_moved = (before.head or "") != (after.head or "")
    branch_moved = (before.branch or "") != (after.branch or "")
    observed = bool(changed) or head_moved

    problems = []
    if head_moved and not may_move_head:
        problems.append(HEAD_MOVED_WITHOUT_AUTHORITY)
    if branch_moved:
        problems.append(BRANCH_MOVED_WITHOUT_AUTHORITY)
    if claimed_change is False and observed:
        problems.append(CLAIMED_CLEAN_BUT_CHANGED)
    if claimed_change is True and not observed:
        problems.append(CLAIMED_CHANGED_BUT_CLEAN)

    if problems:
        return EvidenceEnvelope(
            DISAGREEMENT, before, after, observed_changed=changed, observed_change=observed,
            inspected_count=inspected, disagreements=tuple(problems),
            reason=("the report and the measurement disagree: %s. The measurement is the "
                    "evidence; the report is a claim." % ", ".join(problems)),
            extra=extra)

    return EvidenceEnvelope(OK, before, after, observed_changed=changed, observed_change=observed,
                            inspected_count=inspected, extra=extra)

"""floors -- an evidence floor is only trustworthy if you can say where the NUMBER came from.

P2 derived a floor of 6396 from the commit tree and enforced it. Correct, but the floor travelled
as a bare integer: nothing recorded how it was derived, from which revision, by which instrument,
or when. A bare integer can be replaced by another bare integer and no reader could tell.

So a floor is a RECORD:

    floor_value · derivation_method · derivation_inputs · source_revision · source_digest
    derived_at  · instrument_version · inspected_count · verdict

THREE PROPERTIES THIS BUYS, each with a required failure
--------------------------------------------------------
  * THE CHILD CANNOT SET THE BAR IT MUST CLEAR. A floor arriving from the executed child, or from
    any untrusted party, is refused -- ``derivation_method`` must be one this module knows.
  * THE DISPATCHER CANNOT SILENTLY REPLACE A DERIVATION AFTER EXECUTION. A floor derived against
    revision A cannot be used to judge a run bound to revision B; that is STALE_DERIVATION.
  * A MISSING DERIVATION IS NOT A ZERO FLOOR. It is EVIDENCE_FLOOR_UNPROVEN, which refuses --
    because "we never worked out how much to look at" must not read as "any amount will do".

PURE module. Derivation itself lives in control_fact; this stores, validates and adjudicates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core.canon import canonical_json, sha256_text

FLOOR_INSTRUMENT = "floors/1"

# Derivation methods this module will accept. An unrecognised method is refused rather than
# trusted: the set of methods is exactly the set someone has reasoned about.
METHOD_REVISION_TREE = "REVISION_TREE_MINUS_EXCLUSIONS"
METHOD_FIXED_MINIMUM = "FIXED_MINIMUM"
METHOD_CONTAINER_WORKSPACE = "CONTAINER_WORKSPACE_INVENTORY"
KNOWN_METHODS = (METHOD_REVISION_TREE, METHOD_FIXED_MINIMUM, METHOD_CONTAINER_WORKSPACE)

#: No floor may be lower than this, whatever the derivation says. A floor of 0 cannot distinguish
#: "clean" from "did not look", which is the entire failure this concept exists to prevent.
ABSOLUTE_MINIMUM = 1

# Verdicts
FLOOR_MET = "FLOOR_MET"
FLOOR_NOT_MET = "FLOOR_NOT_MET"
FLOOR_UNPROVEN = "EVIDENCE_FLOOR_UNPROVEN"
FLOOR_STALE = "EVIDENCE_FLOOR_STALE_DERIVATION"
VACUOUS = "VACUOUS"


@dataclass(frozen=True)
class FloorDerivation:
    """How a floor came to have its value."""

    floor_value: int
    derivation_method: str
    derivation_inputs: Mapping = field(default_factory=dict)
    source_revision: str = ""
    source_digest: str = ""
    derived_at: float = 0.0
    instrument_version: str = FLOOR_INSTRUMENT
    derived_by: str = "bridge"
    note: str = ""

    def to_dict(self) -> dict:
        return {"floor_value": int(self.floor_value),
                "derivation_method": self.derivation_method,
                "derivation_inputs": dict(self.derivation_inputs),
                "source_revision": self.source_revision or None,
                "source_digest": self.source_digest or None,
                "derived_at": self.derived_at,
                "instrument_version": self.instrument_version,
                "derived_by": self.derived_by,
                "note": self.note or None}

    def digest(self) -> str:
        return sha256_text(canonical_json(self.to_dict()))


@dataclass(frozen=True)
class FloorVerdict:
    verdict: str
    floor_value: int | None
    inspected_count: int | None
    reason: str
    derivation: Mapping = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.verdict == FLOOR_MET


def validate_derivation(derivation: FloorDerivation | None, *,
                        expected_revision: str = "") -> tuple:
    """(ok, reason). Is this derivation trustworthy for the run about to be judged? PURE."""
    if derivation is None:
        return False, ("no floor derivation exists; a missing derivation is not a floor of zero, "
                       "it is an unproven floor")
    if derivation.derivation_method not in KNOWN_METHODS:
        return False, ("derivation_method %r is not one this bridge derives; a floor supplied by "
                       "any other party -- including the executed child -- is refused"
                       % derivation.derivation_method)
    if str(derivation.derived_by or "") != "bridge":
        return False, ("floor was derived by %r; the child cannot set the bar it must clear"
                       % derivation.derived_by)
    if int(derivation.floor_value) < ABSOLUTE_MINIMUM:
        return False, ("floor_value=%d is below the absolute minimum of %d; a zero floor cannot "
                       "distinguish clean from unlooked-at"
                       % (int(derivation.floor_value), ABSOLUTE_MINIMUM))
    if expected_revision and derivation.source_revision \
            and derivation.source_revision.lower() != str(expected_revision).lower():
        return False, ("derivation was taken at revision %s but this run is bound to %s -- a "
                       "floor from another tree is not a floor for this one"
                       % (derivation.source_revision[:12], str(expected_revision)[:12]))
    # EVERY derivation must be anchored to something immutable -- but WHICH anchor depends on the
    # method, and demanding the wrong one is how a sound derivation gets rejected as unproven.
    # A revision-tree floor is anchored by a commit; a workspace-inventory floor has no commit and
    # is anchored by the digest of the material it counted. Requiring a git revision from a
    # directory-based method was a bug in the first version, and it refused a floor that was in
    # fact fully provenanced.
    if derivation.derivation_method == METHOD_REVISION_TREE and not derivation.source_revision:
        return False, ("derivation method %s is anchored to a commit and none was recorded"
                       % derivation.derivation_method)
    if derivation.derivation_method == METHOD_CONTAINER_WORKSPACE and not derivation.source_digest:
        return False, ("derivation method %s is anchored to a content digest of the material it "
                       "counted and none was recorded" % derivation.derivation_method)
    return True, ""


def adjudicate(derivation: FloorDerivation | None, inspected_count: int | None, *,
               expected_revision: str = "") -> FloorVerdict:
    """The floor decision. PURE. NEVER raises.

    Order: is the DERIVATION sound, then is the READING sufficient. Reversing them would let a
    generous reading paper over a floor nobody can vouch for.
    """
    ok, reason = validate_derivation(derivation, expected_revision=expected_revision)
    d = derivation.to_dict() if derivation is not None else {}
    if not ok:
        verdict = FLOOR_STALE if "bound to" in reason else FLOOR_UNPROVEN
        return FloorVerdict(verdict, (derivation.floor_value if derivation else None),
                            inspected_count, reason, d)
    if inspected_count is None:
        return FloorVerdict(FLOOR_UNPROVEN, derivation.floor_value, None,
                            "no inspected_count was measured; an unmeasured reading is not a "
                            "passing one", d)
    if int(inspected_count) <= 0:
        return FloorVerdict(VACUOUS, derivation.floor_value, int(inspected_count),
                            "inspected_count=0: the instrument looked at nothing", d)
    if int(inspected_count) < int(derivation.floor_value):
        return FloorVerdict(FLOOR_NOT_MET, derivation.floor_value, int(inspected_count),
                            "inspected %d, floor is %d"
                            % (int(inspected_count), int(derivation.floor_value)), d)
    return FloorVerdict(FLOOR_MET, derivation.floor_value, int(inspected_count), "", d)


def revision_tree_floor(*, tree_entries: int, excluded_count: int, source_revision: str,
                        exclusions: tuple = (), derived_at: float = 0.0) -> FloorDerivation:
    """Build the P2-style floor with full provenance. PURE."""
    value = int(tree_entries) - int(excluded_count)
    return FloorDerivation(
        floor_value=value, derivation_method=METHOD_REVISION_TREE,
        derivation_inputs={"tree_entries": int(tree_entries),
                           "excluded_count": int(excluded_count),
                           "exclusions": list(exclusions)},
        source_revision=str(source_revision).lower(), derived_at=derived_at,
        note=("anchored to the commit, not to the checkout it polices: a floor derived from the "
              "working tree would let a thin checkout lower its own bar"))


def workspace_floor(*, file_count: int, source_digest: str = "",
                    derived_at: float = 0.0) -> FloorDerivation:
    """Floor for a container workspace: the host fixture's own file inventory. PURE."""
    return FloorDerivation(
        floor_value=max(int(file_count), ABSOLUTE_MINIMUM),
        derivation_method=METHOD_CONTAINER_WORKSPACE,
        derivation_inputs={"host_file_count": int(file_count)},
        source_revision="", source_digest=source_digest, derived_at=derived_at,
        note="derived from the HOST fixture before the container started")


def child_supplied_floor(value: int) -> FloorDerivation:
    """A floor claiming to come from the executed child. Exists ONLY so a control can refuse it."""
    return FloorDerivation(floor_value=int(value), derivation_method=METHOD_FIXED_MINIMUM,
                           derived_by="claude-child",
                           note="fixture for the control that proves this is refused")

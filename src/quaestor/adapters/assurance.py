"""adapters.assurance -- integration assurance levels, COMPUTED from probe evidence (§5.3).

The levels name what Quaestor can honestly say about an agent lane:

    OBSERVED < DIALOGUE < MANAGED < GOVERNED < CONFINED

The one rule that makes the ladder mean anything is direction §31: "ADAPTER ASSURANCE IS
MEASURED, NOT SELF-DECLARED ... an adapter can never declare its own level." So ``claimed`` is
only ever an input to compare against; the returned level is DERIVED from which probes actually
passed, and every claimed-but-unproven rung comes back as a refusal naming the missing probes.
This is where CONTROL_DECLARED != CONTROL_EFFECTIVE is barred at the adapter edge: a clipboard
bridge may be DIALOGUE and will be recorded as DIALOGUE no matter how confidently it says
CONFINED.

PURE: no I/O, no clock, no imports beyond typing/dataclasses.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

ASSURANCE_INSTRUMENT = "adapters.assurance/1"

#: Ordered low -> high. Index order IS authority order; never sort these alphabetically.
OBSERVED = "OBSERVED"
DIALOGUE = "DIALOGUE"
MANAGED = "MANAGED"
GOVERNED = "GOVERNED"
CONFINED = "CONFINED"

ASSURANCE_LEVELS: tuple = (OBSERVED, DIALOGUE, MANAGED, GOVERNED, CONFINED)

#: The NEW probes each rung adds to the one below (§5.3 tiers). ``required_for`` accumulates
#: them, so a higher level always implies everything its inferiors needed.
LEVEL_NEW_PROBES: Mapping[str, tuple] = {
    OBSERVED: ("observe_probe",),
    DIALOGUE: ("roundtrip", "message_id_preserved"),
    MANAGED: ("cancel_works", "lifecycle"),
    GOVERNED: ("workspace_containment", "readonly_holds"),
    # "additionally" -- confinement proves the external boundary on top of governance (§5.2 T4).
    CONFINED: ("container_validation",),
}


def required_for(level: str) -> tuple:
    """Every probe the named level must have passed, accumulated up the ladder."""
    if level not in ASSURANCE_LEVELS:
        raise ValueError("unknown assurance level %r; the vocabulary is %s"
                         % (level, list(ASSURANCE_LEVELS)))
    out: list = []
    for lvl in ASSURANCE_LEVELS:
        for probe in LEVEL_NEW_PROBES[lvl]:
            if probe not in out:
                out.append(probe)
        if lvl == level:
            break
    return tuple(out)


@dataclass(frozen=True)
class AssuranceClaim:
    """A claim AS RECORDED: the asserted level plus the probe-result names behind it.

    Kept as data rather than dissolved into strings so a later audit can ask "which evidence
    backed this?" without re-running anything.
    """
    level: str
    evidence: tuple


def compute_assurance(probes: Mapping[str, bool], claimed: str) -> tuple:
    """Derive the highest assurance level the PASSED probes prove, vs what was claimed.

    Returns ``(computed_level, refusals)``. ``computed_level`` is the highest rung whose whole
    required probe set passed, or ``""`` when even OBSERVED is unproven. ``refusals`` is empty
    unless ``claimed`` exceeds proof, in which case it names every unproven claimed-or-above
    rung WITH the probes it is missing -- a refusal that does not name the gap teaches nothing.
    PURE.
    """
    if claimed not in ASSURANCE_LEVELS:
        raise ValueError("unknown claimed assurance level %r; the vocabulary is %s"
                         % (claimed, list(ASSURANCE_LEVELS)))
    passed = {name: bool(ok) for name, ok in dict(probes or {}).items()}

    computed = ""
    computed_idx = -1
    missing_by_level: dict = {}
    for idx, level in enumerate(ASSURANCE_LEVELS):
        missing = [p for p in required_for(level) if not passed.get(p)]
        if not missing and idx == computed_idx + 1:
            # The ladder only climbs by consecutive proof: a rung whose inferior failed is not
            # rescued by stronger evidence arriving out of order.
            computed = level
            computed_idx = idx
        elif missing:
            missing_by_level[level] = missing

    claimed_idx = ASSURANCE_LEVELS.index(claimed)
    refusals: list = []
    for level in ASSURANCE_LEVELS:
        if ASSURANCE_LEVELS.index(level) <= computed_idx:
            continue
        if ASSURANCE_LEVELS.index(level) > claimed_idx:
            break
        # Only rungs the caller actually reached for get refused; evidence short of OBSERVED
        # still refuses OBSERVED itself when that was the claim.
        missing = missing_by_level.get(level)
        if missing:
            refusals.append("%s unproven: missing %s" % (level, ", ".join(missing)))
    return computed, tuple(refusals)

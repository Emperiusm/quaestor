"""adapters.record -- durable assurance records per lane/adapter (§5.3).

"The UI, API, audit record, and review policy should all be able to see this assurance level."
A level that is computed and then evaporates is a status page; this module writes the
computation -- claimed, computed, refusals, probe-by-probe detail -- into the store's append-only
event log under the closed kind ``adapter.assurance``, so a later reader can check the recorded
level against its evidence instead of trusting whoever ran the probes.

The event carries BOTH numbers deliberately: an audit that sees only ``computed`` cannot notice
an over-claim; one that sees only ``claimed`` is back to CONTROL_DECLARED != CONTROL_EFFECTIVE,
the exact failure class §31 bars at the adapter edge.
"""
from __future__ import annotations

from quaestor.adapters.assurance import ASSURANCE_LEVELS, AssuranceClaim, compute_assurance
from quaestor.adapters.probes import ProbeResult

RECORD_INSTRUMENT = "adapters.record/1"

#: Closed event vocabulary addition (cf. core.events doctrine: names are edited in deliberately).
EVENT_KIND = "adapter.assurance"


def _passed_map(probes_result) -> tuple:
    """Normalize {name: ProbeResult|bool} -> ({name: bool}, {name: json-detail})."""
    passed: dict = {}
    details: dict = {}
    for name, res in dict(probes_result or {}).items():
        if isinstance(res, ProbeResult):
            passed[str(name)] = bool(res.passed)
            details[str(name)] = {"passed": bool(res.passed), "detail": str(res.detail)}
        else:
            passed[str(name)] = bool(res)
            details[str(name)] = {"passed": bool(res), "detail": ""}
    return passed, details


def record_assurance(store_like, lane_or_adapter_id, claim: str, probes_result) -> int:
    """Compute + durably record the assurance of one lane/adapter. Returns the event row id.

    ``store_like`` needs only Store.append_event's signature (kind, *, dispatch_key, detail).
    The claim is recorded as CLAIMED; the level written as authoritative is always the COMPUTED
    one, so a reader never has to trust the adapter's word to reconstruct what was proven.
    """
    passed, details = _passed_map(probes_result)
    computed, refusals = compute_assurance(passed, str(claim))
    evidence = AssuranceClaim(level=str(claim),
                              evidence=tuple(sorted(name for name, ok in passed.items() if ok)))
    # MEASURED, not asserted: the flag records whether proof stayed within the claim. It is
    # computed from the ladder, never hard-coded -- a constant True would itself be a
    # self-declared control.
    within_claimed = (ASSURANCE_LEVELS.index(computed) if computed else -1) \
        <= ASSURANCE_LEVELS.index(evidence.level)
    return int(store_like.append_event(
        EVENT_KIND,
        dispatch_key=str(lane_or_adapter_id or ""),
        detail={
            "lane_or_adapter": str(lane_or_adapter_id or ""),
            "instrument": RECORD_INSTRUMENT,
            "claimed_level": evidence.level,
            "computed_level": computed,
            "computed_within_claimed": within_claimed,
            "refusals": list(refusals),
            "evidence_names": list(evidence.evidence),
            "probes": details,
        }))

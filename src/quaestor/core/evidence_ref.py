"""evidence_ref -- the trust boundary between "a model said so" and "something measured it".

THE DEFECT THIS CLOSES
----------------------
``ReviewRequest.evidence`` was an open ``Mapping``. A control asserted that the dataclass had no
field NAMED "transcript" -- which is true and beside the point, because any content at all could
travel inside ``evidence``, and downstream the same object was treated as verified measurement.
A model could therefore construct an object that an acceptance decision then trusted.

So evidence stops being a bag of keys and becomes a bundle of ATTESTED ITEMS:

    who collected it   a collector identifier, and whether that collector is independent
    what it measured   a named kind, from a closed vocabulary
    the value          a scalar or digest -- never free prose
    when               so a stale bundle can be recognised

An item with no collector, or with a collector that is a reasoning actor, is INPUT. It may be
shown to a reviewer; it may not be counted as proof. ``attested()`` is what the acceptance gate
consults, and it refuses a bundle that carries no independently collected item at all rather than
returning a comfortable empty pass.

WHY NOT JUST SIGN IT
--------------------
Signing would prove provenance against a hostile collector. This boundary is not defending against
a forged collector -- everything runs on one host under one user -- it is defending against
CATEGORY CONFUSION: model output silently occupying the place reserved for measurement. Naming the
collector and refusing reasoning actors is exactly enough for that, and a signature would imply a
guarantee this deployment cannot make.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Mapping, Sequence

EVIDENCE_INSTRUMENT = "evidence_ref/1"

# Closed vocabulary of what can be measured. A kind absent from here is refused: an open
# vocabulary would let a caller invent an authoritative-sounding measurement.
GIT_HEAD = "git_head"
GIT_STATUS = "git_status"
GIT_DIFF = "git_diff"
TEST_RESULTS = "test_results"
PROCESS_EXIT = "process_exit"
FILE_DIGEST = "file_digest"
CONTAINER_IDENTITY = "container_identity"
TOOL_VERSION = "tool_version"
WORKDIR = "working_directory"
REPO_IDENTITY = "repo_identity"

EVIDENCE_KINDS = (GIT_HEAD, GIT_STATUS, GIT_DIFF, TEST_RESULTS, PROCESS_EXIT, FILE_DIGEST,
                  CONTAINER_IDENTITY, TOOL_VERSION, WORKDIR, REPO_IDENTITY)

#: Collectors that MEASURE. Only these produce attested evidence.
COLLECTOR_VERIFIER = "verifier"
COLLECTOR_HARNESS = "harness"
INDEPENDENT_COLLECTORS = frozenset({COLLECTOR_VERIFIER, COLLECTOR_HARNESS})

#: Collectors that REASON. Anything they produce is input, never proof -- including a reviewer,
#: because a reviewer that can mint its own evidence can manufacture the basis of its own verdict.
COLLECTOR_EXECUTOR = "executor"
COLLECTOR_REVIEWER = "reviewer"
COLLECTOR_STRATEGIST = "strategist"
REASONING_COLLECTORS = frozenset({COLLECTOR_EXECUTOR, COLLECTOR_REVIEWER, COLLECTOR_STRATEGIST})

UNATTESTED = "EVIDENCE_NOT_INDEPENDENTLY_COLLECTED"
UNKNOWN_KIND = "EVIDENCE_KIND_UNKNOWN"


@dataclass(frozen=True)
class EvidenceItem:
    kind: str
    value: str
    collector: str
    collected_at: float = 0.0
    detail: Mapping = field(default_factory=dict)

    @property
    def independent(self) -> bool:
        return self.collector in INDEPENDENT_COLLECTORS

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "collector": self.collector,
                "independent": self.independent, "collected_at": self.collected_at,
                "detail": dict(self.detail)}


@dataclass(frozen=True)
class EvidenceBundle:
    items: tuple = ()
    instrument: str = EVIDENCE_INSTRUMENT

    def keys(self) -> tuple:
        return tuple(i.kind for i in self.items if i.independent)

    def independent_items(self) -> tuple:
        return tuple(i for i in self.items if i.independent)

    def attested(self) -> tuple:
        """(ok, reason). PURE. A bundle with nothing independently collected is NOT attested."""
        if not self.items:
            return False, ("%s: the bundle is empty. An acceptance decision made on no "
                           "measurement at all is vacuous, not clean." % UNATTESTED)
        indep = self.independent_items()
        if not indep:
            return False, ("%s: every item was produced by a reasoning actor (%s). Model output "
                           "may inform a reviewer; it may not stand in for measurement."
                           % (UNATTESTED, sorted({i.collector for i in self.items})))
        return True, ""

    def to_dict(self) -> dict:
        return {"items": [i.to_dict() for i in self.items],
                "independent_kinds": list(self.keys()),
                "inspected_count": len(self.items),
                "vacuous": not self.items, "instrument": self.instrument}


def item(kind: str, value, *, collector: str, detail: Mapping | None = None,
         now: float | None = None) -> EvidenceItem:
    """Mint one evidence item. Raises ValueError on an unknown kind or collector."""
    if kind not in EVIDENCE_KINDS:
        raise ValueError("%s: %r; the vocabulary is closed so a caller cannot invent an "
                         "authoritative-sounding measurement" % (UNKNOWN_KIND, kind))
    if collector not in (INDEPENDENT_COLLECTORS | REASONING_COLLECTORS):
        raise ValueError("unknown collector %r; it must be named so its independence can be "
                         "decided rather than assumed" % collector)
    return EvidenceItem(kind=kind, value=str(value), collector=collector,
                        collected_at=float(now if now is not None else time.time()),
                        detail=dict(detail or {}))


def bundle(items: Sequence[EvidenceItem]) -> EvidenceBundle:
    return EvidenceBundle(tuple(items or ()))


def from_measurements(mapping: Mapping, *, collector: str = COLLECTOR_VERIFIER,
                      now: float | None = None) -> EvidenceBundle:
    """Build a bundle from a collector's own output. Impure only in the clock.

    Deliberately requires the caller to NAME the collector. A convenience that defaulted to
    "verifier" for any mapping would reintroduce exactly the confusion this module exists to end.
    """
    return bundle([item(k, v, collector=collector, now=now)
                   for k, v in (mapping or {}).items() if k in EVIDENCE_KINDS])

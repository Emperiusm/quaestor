"""acceptance -- the gate a candidate must pass before a lane may be strategically accepted.

WHAT THIS FIXES
---------------
The review floor was a constant in a package nothing imported. Adversarial review put it plainly:
the whole review package had zero non-test callers, so "a security-sensitive change requires
adversarial review" described a function, not a rule. A requirement nothing consults is a comment.

This is the consultation point. Every path to `PASS` for a lane goes through ``decide``, and it
refuses to return acceptance when a required review is missing, unfinished, self-declared or
vacuous.

THREE THINGS THIS GATE REFUSES TO TRUST
---------------------------------------
1. **A reviewer's own verdict.** ``review.summarize`` recomputes the outcome from the findings;
   this consults the RECOMPUTED value, never the reviewer's ``outcome`` field. A reviewer that
   inspected nothing and declared ACCEPTED gets VACUOUS.
2. **Evidence a model constructed.** Only evidence carrying an independent collector's
   attestation counts. A mapping assembled by a reviewer or executor is INPUT, not proof.
3. **Configuration that wants less review than the floor.** A project may widen the floor. It
   cannot lower it, and the only way past it is an explicit owner waiver that is itself recorded.

WAIVERS ARE RECORDS, NOT FLAGS
------------------------------
A waiver names who granted it and why, and it is returned in the verdict so it appears in the
audit trail. "Someone passed a boolean" is not an authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

ACCEPTANCE_INSTRUMENT = "acceptance/1"

# Verdicts
ACCEPT = "ACCEPT"
REFUSE = "REFUSE"

# Refusal reasons
REVIEW_MISSING = "REQUIRED_REVIEW_MISSING"
REVIEW_NOT_ACCEPTED = "REQUIRED_REVIEW_NOT_ACCEPTED"
REVIEW_VACUOUS = "REQUIRED_REVIEW_VACUOUS"
EVIDENCE_UNATTESTED = "EVIDENCE_NOT_INDEPENDENTLY_COLLECTED"
EVIDENCE_MISSING = "REQUIRED_EVIDENCE_MISSING"
WAIVER_UNAUTHORIZED = "WAIVER_NOT_OWNER_AUTHORED"
WAIVER_UNATTESTED = "WAIVER_NOT_ATTESTED_BY_OWNER_CHANNEL"


@dataclass(frozen=True)
class Waiver:
    """An explicit, attributed exception to the review floor."""

    change_class: str
    granted_by_role: str
    rationale: str
    decision_ref: str = ""

    @property
    def valid(self) -> bool:
        # ONLY the owner may waive the platform floor. A strategist waiving its own requirement
        # is the executor-grants-itself-authority shape wearing a different hat.
        return (self.granted_by_role == "OWNER" and bool(self.rationale.strip())
                and bool(self.decision_ref))

    def to_dict(self) -> dict:
        return {"change_class": self.change_class, "granted_by_role": self.granted_by_role,
                "rationale": self.rationale, "decision_ref": self.decision_ref,
                "valid": self.valid}


@dataclass(frozen=True)
class AcceptanceVerdict:
    verdict: str
    reason: str = ""
    detail: str = ""
    required_reviews: tuple = ()
    satisfied_reviews: tuple = ()
    waivers: tuple = ()
    inspected_count: int = 0
    instrument: str = ACCEPTANCE_INSTRUMENT

    @property
    def accepted(self) -> bool:
        return self.verdict == ACCEPT

    @property
    def vacuous(self) -> bool:
        return self.inspected_count <= 0

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "reason": self.reason, "detail": self.detail,
                "required_reviews": list(self.required_reviews),
                "satisfied_reviews": list(self.satisfied_reviews),
                "waivers": [w.to_dict() for w in self.waivers],
                "inspected_count": self.inspected_count, "vacuous": self.vacuous,
                "instrument": self.instrument}


def decide(*, change_classes: Sequence[str], reviews: Sequence, evidence,
           required_evidence: Sequence[str] = (), waivers: Sequence[Waiver] = (),
           project_policy: Mapping | None = None,
           owner_attestation: bool = False) -> AcceptanceVerdict:
    """May this candidate be accepted? PURE. NEVER raises.

    ``reviews`` are ``review.ReviewResult`` objects. ``evidence`` is an
    ``evidence_ref.EvidenceBundle`` -- deliberately NOT an open mapping, so a model cannot hand
    this gate an object it assembled and have it treated as measurement.

    ``owner_attestation`` is the same argument applied to waivers. A ``Waiver`` is an object, and
    an object saying ``granted_by_role="OWNER"`` is a string a model can type. So the attestation
    is a SEPARATE argument the caller must supply from the owner channel, and it DEFAULTS TO
    ABSENT: a waiver alone can no longer buy its way past the review floor.
    """
    from quaestor.core import evidence_ref
    from quaestor.core import review_contract as review_mod

    checked = 0

    # 1. EVIDENCE MUST BE INDEPENDENTLY COLLECTED ----------------------------------------------
    checked += 1
    if not isinstance(evidence, evidence_ref.EvidenceBundle):
        return AcceptanceVerdict(
            REFUSE, EVIDENCE_UNATTESTED,
            "acceptance evidence must be an EvidenceBundle carrying a collector attestation; a "
            "plain mapping is model input, and treating it as measurement is how a reviewer's "
            "story becomes a fact", inspected_count=checked)
    ev_ok, ev_reason = evidence.attested()
    checked += 1
    if not ev_ok:
        return AcceptanceVerdict(REFUSE, EVIDENCE_UNATTESTED, ev_reason,
                                 inspected_count=checked)
    missing = [k for k in (required_evidence or ()) if k not in evidence.keys()]
    checked += len(required_evidence or ())
    if missing:
        return AcceptanceVerdict(
            REFUSE, EVIDENCE_MISSING,
            "the project requires evidence %s which was not collected" % missing,
            inspected_count=checked)

    # 2. THE REVIEW FLOOR ------------------------------------------------------------------------
    required, matched = review_mod.adversarial_required(change_classes, project_policy)
    checked += 1
    satisfied, unsatisfied = [], []
    if required:
        adversarial = [r for r in reviews if getattr(r, "kind", "") == review_mod.ADVERSARIAL]
        checked += len(adversarial)
        if not adversarial:
            live_waivers = [w for w in (waivers or ())
                            if w.valid and w.change_class in matched and owner_attestation]
            bad_waivers = [w for w in (waivers or ()) if not w.valid]
            if (waivers and not bad_waivers and not owner_attestation):
                return AcceptanceVerdict(
                    REFUSE, WAIVER_UNATTESTED,
                    "a well-formed owner waiver was supplied but the owner channel did not "
                    "attest it. `granted_by_role=\"OWNER\"` is a string any caller can type; "
                    "the attestation is what makes it an authorization, and this build's owner "
                    "channel returns UNAVAILABLE by construction.",
                    required_reviews=tuple(matched), waivers=tuple(waivers or ()),
                    inspected_count=checked)
            if bad_waivers:
                return AcceptanceVerdict(
                    REFUSE, WAIVER_UNAUTHORIZED,
                    "a waiver must be owner-authored, carry a rationale, and reference a recorded "
                    "decision; %d did not" % len(bad_waivers),
                    required_reviews=tuple(matched), waivers=tuple(waivers or ()),
                    inspected_count=checked)
            if len(live_waivers) < len(matched):
                return AcceptanceVerdict(
                    REFUSE, REVIEW_MISSING,
                    "adversarial review is required for %s and none was performed" % list(matched),
                    required_reviews=tuple(matched), waivers=tuple(live_waivers),
                    inspected_count=checked)
        for r in adversarial:
            # RECOMPUTED, never the reviewer's own field: a reviewer does not grade itself.
            summary = review_mod.summarize(r)
            if summary["outcome"] == review_mod.VACUOUS:
                return AcceptanceVerdict(
                    REFUSE, REVIEW_VACUOUS,
                    "the required adversarial review inspected nothing; an empty review is not a "
                    "clean one", required_reviews=tuple(matched), inspected_count=checked)
            if summary["outcome"] != review_mod.ACCEPTED:
                return AcceptanceVerdict(
                    REFUSE, REVIEW_NOT_ACCEPTED,
                    "the required adversarial review returned %s with %d surviving finding(s)"
                    % (summary["outcome"], summary["findings_surviving"]),
                    required_reviews=tuple(matched), inspected_count=checked)
            satisfied.append(r.review_id)

    return AcceptanceVerdict(ACCEPT, "", "", tuple(matched), tuple(satisfied),
                             tuple(w for w in (waivers or ()) if w.valid),
                             inspected_count=checked)

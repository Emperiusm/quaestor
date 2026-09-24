"""review_contract -- standard and adversarial review as first-class roles.

THE CONTRACT LIVES IN CORE. Reviewer IMPLEMENTATIONS belong in ``review/``;
the types, the floor and the recomputation rule are policy the acceptance
gate depends on, and core may not import an outer layer to reach them --
the same argument that put the executor contract here.

NO LAYER GRADES ITS OWN HOMEWORK
--------------------------------
The executor's report is a CLAIM. The reviewer's report is also a claim. Neither is evidence.
Deterministic measurement -- exit codes, git state, test results, file hashes -- is the only
ground truth, and it is collected by a component that has no stake in the answer.

So a review here is not "ask a model if the diff is good". It is a bounded role with:

    an independent INPUT SET      (never the executor's conversation)
    a minimal AUTHORITY           (read-only, structurally)
    a typed OUTPUT                (findings that can be counted and refuted)
    an explicit ACTIVATION POLICY (which changes require which review)

INDEPENDENCE IS A CONSTRUCTION, NOT AN INSTRUCTION
--------------------------------------------------
``ReviewRequest`` cannot carry the executor's transcript: there is no field for it, and
``build_request`` refuses input it was not designed to take. That matters because handing a
reviewer the reasoning it is meant to check is how correlated errors happen -- the reviewer adopts
the executor's framing and "verifies" the same mistake. Independent context is the entire value.

The adversarial reviewer additionally DEFAULTS TO REFUTED. A finding survives only if the reviewer
can substantiate it; an inconclusive adversarial review is not a pass, it is an absent verdict.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor.core import actors as actors_mod

REVIEW_INSTRUMENT = "review/1"

# Review kinds
STANDARD = "STANDARD"
ADVERSARIAL = "ADVERSARIAL"
REVIEW_KINDS = (STANDARD, ADVERSARIAL)

# ---- reviewer TARGET CLASSES (PRD.md §7.6) ----------------------------------------------------
# PRD.md §7.6: "review targets may include: PLAN, CODE, INTEGRATION, RELEASE, SECURITY, BUSINESS
# WORKFLOW", and "reviewer authority remains read-only unless a separately defined workflow
# explicitly creates a new implementation task". HEAD declares five of those six classes below;
# BUSINESS WORKFLOW is PRD contract with no code here yet. The rationale, as first written in
# the now superseded direction doc (historical, kept because it explains the shape):
# "PLAN_PROPOSAL admission is deterministic; it can also be ADVERSARIAL. The existing reviewer
# seat gains target classes -- PLAN, CODE, INTEGRATION, RELEASE, SECURITY -- so one cross-vendor
# challenge of a 40-task decomposition can run before 30 expensive executions. No new permanent
# role: same reviewer seat, same READ_ONLY ceiling, different target." The class names WHAT is
# under attack, never WHO may attack or WHAT they may change -- authority stays READ_ONLY for
# every class, which is why this is a parameter and not a new role.
TARGET_PLAN = "PLAN"
TARGET_CODE = "CODE"
TARGET_INTEGRATION = "INTEGRATION"
TARGET_RELEASE = "RELEASE"
TARGET_SECURITY = "SECURITY"
REVIEW_TARGET_CLASSES = (TARGET_PLAN, TARGET_CODE, TARGET_INTEGRATION, TARGET_RELEASE,
                         TARGET_SECURITY)
DEFAULT_TARGET_CLASS = TARGET_CODE

# Outcomes
ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
INCONCLUSIVE = "INCONCLUSIVE"
VACUOUS = "VACUOUS"

# Severities
CRITICAL, HIGH, MEDIUM, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"
SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW)

#: What an adversarial reviewer is asked to hunt for. Not prose in a prompt -- a checklist the
#: platform owns, so it is the same for every project and can be extended deliberately.
ADVERSARIAL_LENSES = (
    "incorrect assumptions", "missing tests", "authority bypass", "secret exposure",
    "sandbox escape", "unsafe retry semantics", "race conditions", "state-machine defects",
    "repository contamination", "evidence gaps", "security regressions",
    "unintended side effects", "acceptance-criteria failures",
)

#: THE risk-class vocabulary. Declared ONCE, here. projects.config validates operator manifests
#: against it and core.orchestrator must be able to produce every member from a real diff -- a
#: class an operator can name but no change can ever hit is a policy that cannot fire, which is
#: indistinguishable to the operator from one that is being enforced.
RISK_CLASSES = (
    "security_sensitive", "authentication", "authority_change", "sandbox_change",
    "deployment", "destructive_capability", "data_migration",
)

#: Change classes that REQUIRE an adversarial review. A project may add to this; it may not
#: remove from it without an explicit, recorded decision -- which is why the platform owns the
#: floor rather than leaving it entirely to configuration.
#:
#: A STRICT SUBSET of RISK_CLASSES, and deliberately so: `data_migration` escalates provider
#: independence without compelling an adversarial review. That gap is exactly what made passing
#: the floor-filtered class set to the independence check fail open -- see
#: orchestrator.risk_classes_hit.
ADVERSARIAL_REQUIRED_FLOOR = frozenset({
    "security_sensitive", "authentication", "authority_change", "sandbox_change",
    "deployment", "destructive_capability",
})

assert ADVERSARIAL_REQUIRED_FLOOR <= set(RISK_CLASSES), (
    "the adversarial floor names a class outside the vocabulary")


@dataclass(frozen=True)
class ReviewRequest:
    """The reviewer's ONLY inputs. Note what is absent: the executor's conversation."""

    review_id: str
    kind: str
    objective: str
    constraints: tuple = ()
    #: The candidate under review, as a reference -- a diff id, a run id, an artifact digest.
    candidate_ref: str = ""
    #: INDEPENDENT measurement, collected by the verifier, not reported by the executor.
    evidence: Mapping = field(default_factory=dict)
    #: Decisions in force, so a reviewer does not re-litigate settled questions.
    decisions: tuple = ()
    acceptance_criteria: tuple = ()
    lane_id: str = ""
    run_id: str = ""
    created_at: float = 0.0
    instrument: str = REVIEW_INSTRUMENT

    def to_dict(self) -> dict:
        return {"review_id": self.review_id, "kind": self.kind, "objective": self.objective,
                "constraints": list(self.constraints), "candidate_ref": self.candidate_ref,
                "evidence": dict(self.evidence), "decisions": list(self.decisions),
                "acceptance_criteria": list(self.acceptance_criteria), "lane_id": self.lane_id,
                "run_id": self.run_id, "created_at": self.created_at,
                "instrument": self.instrument}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    #: Where. A finding without a location is an opinion.
    location: str = ""
    #: How it fails, concretely. "Could be clearer" is not a finding.
    failure_mode: str = ""
    evidence_ref: str = ""
    refuted: bool = False
    refutation_reason: str = ""

    @property
    def survives(self) -> bool:
        return not self.refuted

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "title": self.title, "severity": self.severity,
                "location": self.location, "failure_mode": self.failure_mode,
                "evidence_ref": self.evidence_ref, "refuted": self.refuted,
                "refutation_reason": self.refutation_reason, "survives": self.survives}


@dataclass(frozen=True)
class ReviewResult:
    review_id: str
    kind: str
    outcome: str
    findings: tuple = ()
    reviewer_actor_id: str = ""
    inspected_count: int = 0
    reason: str = ""
    instrument: str = REVIEW_INSTRUMENT

    @property
    def vacuous(self) -> bool:
        return self.inspected_count <= 0

    def to_dict(self) -> dict:
        return {"review_id": self.review_id, "kind": self.kind, "outcome": self.outcome,
                "findings": [f.to_dict() for f in self.findings],
                "surviving_findings": [f.to_dict() for f in self.findings if f.survives],
                "reviewer_actor_id": self.reviewer_actor_id,
                "inspected_count": self.inspected_count, "vacuous": self.vacuous,
                "reason": self.reason, "instrument": self.instrument}


def build_request(kind: str, *, objective: str, evidence: Mapping,
                  constraints: Sequence[str] = (), candidate_ref: str = "",
                  decisions: Sequence[str] = (), acceptance_criteria: Sequence[str] = (),
                  lane_id: str = "", run_id: str = "", now: float | None = None) -> ReviewRequest:
    """Assemble a review request. Raises ValueError on an unknown kind or absent evidence.

    Absent evidence is refused rather than defaulted: a review conducted without independent
    measurement is a second opinion on the executor's own story, which is the exact failure this
    role exists to prevent.
    """
    if kind not in REVIEW_KINDS:
        raise ValueError("unknown review kind %r; known are %s" % (kind, list(REVIEW_KINDS)))
    if not evidence:
        raise ValueError("a review requires INDEPENDENT evidence; reviewing an executor's claim "
                         "against itself tests agreement, not correctness")
    return ReviewRequest(
        review_id="rev_" + uuid.uuid4().hex[:16], kind=kind, objective=str(objective),
        constraints=tuple(str(c) for c in constraints), candidate_ref=str(candidate_ref),
        evidence=dict(evidence), decisions=tuple(str(d) for d in decisions),
        acceptance_criteria=tuple(str(a) for a in acceptance_criteria),
        lane_id=str(lane_id), run_id=str(run_id),
        created_at=float(now if now is not None else time.time()))


def reviewer_actor(kind: str, *, display_name: str = "") -> actors_mod.Actor:
    """A reviewer actor whose ROLE CEILING is read-only. Raises on an unknown kind."""
    role = (actors_mod.ADVERSARIAL_REVIEWER if kind == ADVERSARIAL else actors_mod.REVIEWER)
    return actors_mod.new_actor(role, display_name=display_name or kind.lower() + " reviewer")


def adversarial_required(change_classes: Sequence[str],
                         policy: Mapping | None = None) -> tuple:
    """(required, matched). PURE.

    The platform FLOOR always applies; a project's policy may only widen it. Returning what
    matched -- not just a boolean -- means the record says WHY a review was demanded, which is
    what makes the requirement auditable rather than mysterious.
    """
    classes = {str(c) for c in (change_classes or ())}
    extra = {str(c) for c in ((policy or {}).get("required_for") or ())}
    matched = sorted(classes & (ADVERSARIAL_REQUIRED_FLOOR | extra))
    return bool(matched), tuple(matched)


def summarize(result: ReviewResult) -> dict:
    """Counts, and an outcome that refuses to launder an empty review into a pass. PURE."""
    surviving = [f for f in result.findings if f.survives]
    blocking = [f for f in surviving if f.severity in (CRITICAL, HIGH)]
    if result.vacuous:
        outcome = VACUOUS
    elif blocking:
        outcome = REJECTED
    elif surviving:
        outcome = INCONCLUSIVE
    else:
        outcome = ACCEPTED
    return {"review_id": result.review_id, "kind": result.kind, "outcome": outcome,
            "declared_outcome": result.outcome,
            "findings_total": len(result.findings), "findings_surviving": len(surviving),
            "findings_blocking": len(blocking), "inspected_count": result.inspected_count,
            "vacuous": result.vacuous, "instrument": REVIEW_INSTRUMENT}


def build_review_task(*, objective: str, acceptance=(), constraints=(),
                      verification_receipt=None,
                      committer_identity: str = "the control plane",
                      extra_context: str = "") -> str:
    """The adversarial reviewer's TASK TEXT. PURE. Lives in core because the engine composes it.

    Deliberately EXCLUDES the implementer's report or transcript. Independence is a property of
    the input set -- ReviewRequest cannot carry the conversation -- not an instruction to "be
    independent", which is exactly the kind of prose convention that fails silently when a model
    paraphrases it away.
    """
    import json
    receipt = {}
    if isinstance(verification_receipt, Mapping):
        receipt = {k: verification_receipt.get(k) for k in
                   ("test_verdict", "discovered", "failed", "errors", "skipped", "reason")}
    return (
        "ADVERSARIAL REVIEW of one implementation candidate. You are READ-ONLY: you inspect and "
        "report; you cannot modify anything.\n\n"
        "ORIGINAL OBJECTIVE:\n%s\n\n"
        "ACCEPTANCE CRITERIA:\n%s\n\n"
        "IMMUTABLE CONSTRAINTS:\n%s\n\n"
        "INDEPENDENT VERIFICATION (collected by the control plane, not by the implementer):\n%s\n"
        "%s"
        "THE CANDIDATE: the worktree you are in. Inspect the last commit authored by '%s' "
        "(git show / git diff HEAD~1) plus any uncommitted state. Verify claims against the code "
        "yourself.\n\n"
        "HUNT SPECIFICALLY FOR: %s.\n\n"
        "OUTPUT: emit one REVIEW_FINDING message per SUBSTANTIATED defect "
        '{"type": "REVIEW_FINDING", "payload": "<one-line title>", '
        '"severity": "CRITICAL|HIGH|MEDIUM|LOW", '
        '"detail": {"location": "<path(:line)>", "failure_mode": "<how it fails, concretely>"}}. '
        "A finding without a concrete failure mode is an opinion, not a finding. If nothing "
        "substantiable survives your attack, say so plainly in `summary` and emit no messages. "
        "Do NOT grade effort or style."
        % (str(objective or "(not stated)"),
           "\n".join("- " + str(a) for a in acceptance) or "(none stated)",
           "\n".join("- " + str(c) for c in constraints) or "(none)",
           json.dumps(receipt, default=str),
           (extra_context + "\n\n") if extra_context else "",
           committer_identity, ", ".join(ADVERSARIAL_LENSES)))


def parse_finding_message(detail_json: str, payload: str) -> Finding:
    """One persisted REVIEW_FINDING message -> a typed Finding. PURE. NEVER raises.

    Severity defaults to MEDIUM when omitted: an unnamed severity must not make a finding
    invisible, and must not make it blocking either -- summarize blocks only CRITICAL/HIGH.
    """
    import json
    try:
        detail = json.loads(detail_json or "{}")
        if not isinstance(detail, Mapping):
            detail = {}
    except ValueError:
        detail = {}
    sev = str(detail.get("severity") or "")
    return Finding(finding_id="", title=str(payload or "")[:200],
                   severity=sev if sev in SEVERITIES else MEDIUM,
                   location=str(detail.get("location") or ""),
                   failure_mode=str(detail.get("failure_mode") or ""))

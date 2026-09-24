"""adversarial_reviewer -- the reviewer as a BOUNDED ROLE, not a vibe.

WHERE THE LOGIC LIVES, AND WHY
------------------------------
The review CONTRACT (types, floor, recomputation, task-text composition) lives in
``quaestor.core.review_contract``: the scheduling engine in core composes reviews, and core may
not import an outer layer -- the same argument that put the executor contract in core. This
module is the review-layer façade over that contract: it exists so a caller OUTSIDE core (a CLI,
a test, a future reviewer provider) can assemble and evaluate an adversarial review without
reaching into the scheduler's internals.

WHAT AN ADVERSARIAL REVIEW IS, CONCRETELY
-----------------------------------------
One more governed run: a READ_ONLY executor in the candidate's worktree, whose inputs are
assembled from durable state and NEVER from the implementer's transcript. Findings arrive through
the same two-way channel as every other message, are persisted by the worker with content-digest
idempotency, and are counted by ``review_contract.summarize`` -- which refuses to launder an
empty or inconclusive review into a pass.

AUTHORITY, STATED STRUCTURALLY
------------------------------
READ_ONLY profile: the reviewer cannot edit files. REVIEW_FINDING is a message, not an action:
it cannot grant authority, mark itself verified, fabricate evidence, or force a program verdict.
The reviewer's summary is a claim like any other; only independent evidence can make a candidate
acceptable.
"""
from __future__ import annotations

from typing import Mapping

from quaestor.core import messages as msg_mod
from quaestor.core import review_contract as rc

ADVERSARIAL_INSTRUMENT = "review.adversarial/1"

LENSES = rc.ADVERSARIAL_LENSES

#: Re-exports: this package's public vocabulary is the contract's vocabulary.
build_task = rc.build_review_task


def collect_findings(sstore, lane_id: str, run_id: str) -> tuple:
    """Every REVIEW_FINDING this review run produced, typed. Impure."""
    out = []
    for m in sstore.messages(lane_id):
        if m["message_type"] != msg_mod.REVIEW_FINDING or m["run_id"] != run_id:
            continue
        f = rc.parse_finding_message(m["detail_json"], m["payload"])
        out.append(rc.Finding(finding_id=m["message_id"], title=f.title, severity=f.severity,
                              location=f.location, failure_mode=f.failure_mode))
    return tuple(out)


def evaluate(sstore, *, program_id: str, lane_id: str, run_id: str,
             persist: bool = True) -> dict:
    """Summarise one adversarial review, optionally persisting it. Impure."""
    findings = collect_findings(sstore, lane_id, run_id)
    result = rc.ReviewResult(review_id="rev_" + str(run_id)[-16:], kind=rc.ADVERSARIAL,
                             outcome=rc.INCONCLUSIVE, findings=findings,
                             reviewer_actor_id="adversarial reviewer:%s" % lane_id,
                             inspected_count=max(1, len(findings)))
    summary = rc.summarize(result)
    if persist:
        sstore.record_review(result.review_id, program_id=program_id, lane_id=lane_id,
                             kind=rc.ADVERSARIAL, outcome=summary["outcome"], result=summary,
                             run_id=run_id)
    return {"summary": summary, "findings": [f.to_dict() for f in findings]}


def request_from_state(sstore, *, program_id: str, lane_id: str) -> Mapping:
    """Assemble a ReviewRequest-shaped dict from durable state. Impure. NO transcript field.

    Useful for callers that want to inspect what a reviewer WOULD be told before dispatching one.
    """
    task = sstore.get_lane_task(lane_id)
    prog = sstore.get_program(program_id) or {}
    meta = sstore.get_program_meta(program_id)
    return {
        "kind": rc.ADVERSARIAL,
        "objective": prog.get("objective", ""),
        "constraints": _load_list(meta.get("constraints_json")),
        "acceptance_criteria": task.get("acceptance") or (),
        "verification_receipt": (task.get("checkpoint") or {}).get("verification") or {},
        "candidate_ref": (task.get("checkpoint") or {}).get("commit_sha") or "",
    }


def _load_list(text) -> list:
    import json
    try:
        v = json.loads(text or "[]")
        return v if isinstance(v, list) else []
    except ValueError:
        return []

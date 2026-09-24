"""identity -- deterministic dispatch identity, and the duplicate-execution defence built on it.

WHAT THE DISPATCH KEY IS FOR
----------------------------
Two identical dispatches from GPT must resolve to ONE execution. The key is the join on which
that deduplication happens, so it must be:

  * deterministic  -- same inputs, same key, forever, on any platform (see canon.canonical_json);
  * complete       -- binding everything that would make two dispatches genuinely different;
  * narrow         -- binding nothing incidental (a timestamp in the key defeats deduplication
                      entirely, which is the failure mode that makes a "unique key" decorative).

THE CLAIM WE DO NOT MAKE
------------------------
This is NOT literal exactly-once execution; distributed systems cannot promise that across
arbitrary crashes and this control plane does not pretend to. The contract is:

    at-most-one ACTIVE execution per dispatch key
      + durable reconciliation
      + no blind retry of ambiguous write executions

PURE module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from quaestor import compat
from quaestor.core.canon import canonical_json, canonical_path, sha256_obj, sha256_text

#: FROZEN. Imported, not spelled, so renaming the product cannot silently change every
#: dispatch key. See ``quaestor.compat`` for why this value may never move.
PROTOCOL_SALT = compat.DISPATCH_KEY_SALT


@dataclass(frozen=True)
class DispatchIdentity:
    """Everything that makes one dispatch distinguishable from another.

    ``expected_head`` and ``expected_branch`` are IN the key on purpose. The same prompt against
    a different commit is a different job -- and binding them here means a stale replay of an old
    dispatch cannot silently deduplicate onto a run that was admitted against another tree.
    """

    workflow_id: str
    step_id: str
    prompt_sha256: str
    repo_id: str
    worktree_path: str
    expected_branch: str
    expected_head: str
    authority_profile: str
    capabilities: Sequence[str] = field(default_factory=tuple)

    def key_material(self) -> dict:
        """The exact dict that gets hashed. PURE.

        Capabilities are SORTED and de-duplicated: a caller listing the same grants in a
        different order is making the same request, and if order changed the key it would spawn
        a second execution against the same worktree -- the precise thing the key prevents.
        """
        return {
            "salt": PROTOCOL_SALT,
            "workflow_id": str(self.workflow_id),
            "step_id": str(self.step_id),
            "prompt_sha256": str(self.prompt_sha256),
            "repo_id": str(self.repo_id),
            "worktree_path": canonical_path(self.worktree_path),
            "expected_branch": str(self.expected_branch),
            "expected_head": str(self.expected_head).lower(),
            "authority_profile": str(self.authority_profile),
            "capabilities": sorted({str(c) for c in (self.capabilities or ())}),
        }

    def dispatch_key(self) -> str:
        """The UNIQUE key. PURE."""
        return sha256_obj(self.key_material())

    def to_json(self) -> str:
        return canonical_json(self.key_material())


def prompt_digest(prompt: str) -> str:
    """The prompt's identity. PURE.

    Digest rather than the prompt itself so the key stays fixed-width, and so a dispatch key can
    be logged and compared without reproducing prompt text into places prompts should not go.
    """
    return sha256_text(prompt)


def build_identity(*, workflow_id: str, step_id: str, prompt: str, repo_id: str,
                   worktree_path: str, expected_branch: str, expected_head: str,
                   authority_profile: str,
                   capabilities: Sequence[str] = ()) -> DispatchIdentity:
    """Convenience constructor that digests the prompt for you. PURE."""
    return DispatchIdentity(
        workflow_id=workflow_id, step_id=step_id, prompt_sha256=prompt_digest(prompt),
        repo_id=repo_id, worktree_path=worktree_path, expected_branch=expected_branch,
        expected_head=expected_head, authority_profile=authority_profile,
        capabilities=tuple(capabilities))


# ---------------------------------------------------------------------------------------------
# RUN BINDING -- "does this artifact belong to THIS run?"
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RunBinding:
    """The identity a result artifact must prove it belongs to.

    Ported from the source deployment: on a persistent runner every artifact path is
    reused, so a receipt that says ``acquired: true`` may belong to yesterday's job and NOTHING
    INSIDE IT WOULD LOOK WRONG. Run identity is therefore checked FIRST -- a stale result is
    rejected for BEING STALE, before anything in it is believed.

    ``run_nonce`` is the half that makes this provable from the artifact ALONE: the prompt asks
    Claude to echo it verbatim, so a result carrying the wrong nonce is a foreign artifact even
    when its workflow_id and step_id match (i.e. an earlier ATTEMPT of the same dispatch).
    """

    run_id: str
    workflow_id: str
    step_id: str
    run_nonce: str


MISMATCH_WORKFLOW = "RUN_IDENTITY_WORKFLOW_MISMATCH"
MISMATCH_STEP = "RUN_IDENTITY_STEP_MISMATCH"
MISMATCH_NONCE = "RUN_IDENTITY_NONCE_MISMATCH"
MISSING_NONCE = "RUN_IDENTITY_NONCE_ABSENT"


def check_run_identity(payload: Mapping[str, Any], binding: RunBinding) -> str | None:
    """``None`` when the payload belongs to this run, else a NAMED mismatch reason. PURE.

    A missing nonce is its own reason, distinct from a wrong one: "the producer never stamped
    identity" and "the producer stamped somebody else's" are different defects and collapsing
    them costs the diagnosis.
    """
    if str(payload.get("workflow_id") or "") != str(binding.workflow_id):
        return MISMATCH_WORKFLOW
    if str(payload.get("step_id") or "") != str(binding.step_id):
        return MISMATCH_STEP
    got = payload.get("run_nonce")
    if got is None or str(got).strip() == "":
        return MISSING_NONCE
    if str(got) != str(binding.run_nonce):
        return MISMATCH_NONCE
    return None

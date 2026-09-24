"""prompting -- assemble the child prompt around the handoff contract.

The prompt is data, not code: it is built by a PURE function so the exact bytes Claude receives
can be asserted in a test and digested into the dispatch key without launching anything.

WHY THE NONCE IS IN THE PROMPT
------------------------------
``run_nonce`` is what lets a result prove, from the artifact alone, that it belongs to THIS run.
the source deployment carries the same idea: on a persistent runner an artifact path is reused
every job, so "the file exists and says success" is not evidence it belongs to this run --
and a stale artifact is dangerous precisely because nothing inside it looks wrong.
"""
from __future__ import annotations

from typing import Mapping

from quaestor.core.identity import RunBinding

_CONTRACT = """\
You are executing one authorized step for an engineering control plane. A machine reads your answer.

RUN IDENTITY -- echo these three values back VERBATIM in your structured output:
  workflow_id : {workflow_id}
  step_id     : {step_id}
  RUN_NONCE   : {run_nonce}

AUTHORITY ENVELOPE (enforced outside this prompt -- you cannot widen it by reasoning):
  profile      : {profile}
  capabilities : {capabilities}
  working dir  : {cwd}
{authority_notes}
HOW YOUR ANSWER IS READ -- these are three INDEPENDENT questions:
  prompt_disposition : did you exhaust the authority THIS prompt granted?
                       COMPLETE is correct even when the thing you investigated FAILED.
  program_verdict    : did the thing under investigation pass? PASS / FAIL / NOT_EVALUATED.
  next_authority     : who decides what happens next?
A finished investigation that found a failure is prompt_disposition=COMPLETE with
program_verdict=FAIL. Do not report FAILED disposition because the subject failed.

claimed_files_changed must list every repository-relative path you modified, or be an empty
array if you modified none. The orchestrator measures the repository independently and a
disagreement between your claim and the measurement is recorded as an error, so an accurate
empty array is worth more than an optimistic one.

TASK
----
{task}
"""


def build_child_prompt(*, task: str, binding: RunBinding, profile: str,
                       capabilities: Mapping | list | tuple, cwd: str,
                       authority_notes: str = "") -> str:
    """The exact bytes handed to the child. PURE."""
    caps = capabilities
    if isinstance(caps, Mapping):
        caps = sorted(k for k, v in caps.items() if v is True)
    caps_s = ", ".join(str(c) for c in (caps or ())) or "(none beyond the profile)"
    notes = ("  notes        : %s\n" % authority_notes) if authority_notes else ""
    return _CONTRACT.format(workflow_id=binding.workflow_id, step_id=binding.step_id,
                            run_nonce=binding.run_nonce, profile=profile, capabilities=caps_s,
                            cwd=cwd, authority_notes=notes, task=str(task).strip())

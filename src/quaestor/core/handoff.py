"""handoff -- the structured-handoff contract, its JSON Schema, and its validator.

The protocol discriminator itself is a FROZEN WIRE CONSTANT held in ``quaestor.compat``:
a captured real-executor fixture contains the literal, so renaming it would force editing
the only test input this project did not generate.

WHAT THIS IS AND IS NOT
-----------------------
Claude's handoff is a REPORT. It is the subject's own account of what it did and what it
concluded. It is not evidence, and this module never treats it as such -- ``evidence.py`` makes
independent measurements and ``reconcile.py`` puts the two side by side.

The machine contract is kept SHALLOW on purpose. A deep schema is a schema a model fills in
plausibly rather than accurately; every field here is one a model can answer from what it
actually did. Claude's prose report rides along in ``report_markdown`` where its length costs the
machine path nothing.

VERSIONING. ``protocol_version`` is a MAJOR version. An unknown major is REFUSED, not
best-effort parsed -- the failure mode of best-effort parsing a future contract is that new
semantics get read with old meanings, which is worse than not reading them.

PURE module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from quaestor.core import domain
from quaestor import compat
from quaestor.core.identity import RunBinding, check_run_identity

#: FROZEN. A captured real-executor fixture contains this literal; renaming it would force
#: editing the only test input this project did not generate. See ``quaestor.compat``.
PROTOCOL = compat.HANDOFF_PROTOCOL
PROTOCOL_VERSION = 1
SUPPORTED_MAJORS = (1,)

# Validation outcomes
VALID = "VALID"
RESULT_INVALID = "RESULT_INVALID"
PROTOCOL_REFUSED = "PROTOCOL_REFUSED"
RUN_IDENTITY_REFUSED = "RUN_IDENTITY_REFUSED"

_REQUIRED_FIELDS = (
    "protocol", "protocol_version", "workflow_id", "step_id", "run_nonce",
    "prompt_disposition", "program_verdict", "acceptance_state",
    "authorized_scope_exhausted", "continuation_allowed",
    "next_authority", "owner_decision_required",
    "smallest_blocker", "next_action", "summary",
)

#: What is handed to `claude --json-schema`. Shallow, closed, and every enum spelled out so the
#: CLI's own structured-output validation rejects a malformed answer before we ever see it --
#: which makes this a defence in depth, not the only defence: validate_handoff re-checks all of
#: it, because a schema enforced by the producer is a control that consumes its own output.
HANDOFF_JSON_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": list(_REQUIRED_FIELDS),
    "properties": {
        "protocol": {"const": PROTOCOL},
        "protocol_version": {"type": "integer", "enum": [PROTOCOL_VERSION]},
        "workflow_id": {"type": "string", "minLength": 1,
                        "description": "Echo the workflow_id given in the prompt, verbatim."},
        "step_id": {"type": "string", "minLength": 1,
                    "description": "Echo the step_id given in the prompt, verbatim."},
        "run_nonce": {"type": "string", "minLength": 1,
                      "description": "Echo the RUN_NONCE token from the prompt, verbatim. It "
                                     "proves this result belongs to this run."},
        "prompt_disposition": {"type": "string", "enum": list(domain.PROMPT_DISPOSITIONS),
                               "description": "Did you exhaust the authority THIS PROMPT granted? "
                                              "COMPLETE even if the thing you investigated failed."},
        "program_verdict": {"type": "string", "enum": list(domain.PROGRAM_VERDICTS),
                            "description": "Did the thing under investigation pass? Independent "
                                           "of whether you finished."},
        "acceptance_state": {"type": "string",
                             "description": "Short machine-ish token naming what is or is not "
                                            "accepted, or empty."},
        "authorized_scope_exhausted": {"type": "boolean"},
        "continuation_allowed": {"type": "boolean"},
        "next_authority": {"type": "string", "enum": list(domain.NEXT_AUTHORITIES)},
        "owner_decision_required": {"type": "boolean"},
        "smallest_blocker": {"type": "string"},
        "next_action": {"type": "string"},
        "summary": {"type": "string", "minLength": 1},
        "report_markdown": {"type": "string"},
        "claimed_files_changed": {
            "type": "array", "items": {"type": "string"},
            "description": "Repository-relative paths you changed. Empty array means you changed "
                           "nothing. The bridge measures this independently and disagreement is "
                           "an error.",
        },
        # OPTIONAL, added for P2 and reusable beyond it. A flat name->scalar bag rather than a
        # typed structure: the machine contract stays shallow (a deep schema is one a model fills
        # in plausibly rather than accurately), and the bridge -- which knows what it asked --
        # does the typing. Optional means every existing protocol-v1 payload stays valid, so this
        # is an extension rather than a version bump.
        #
        # additionalProperties is left OPEN rather than typed as a union. MEASURED: the installed
        # CLI validates the schema with AJV in strict mode, which rejects the union form --
        # `strict mode: use allowUnionTypes to allow union type keyword at
        # "#/properties/measured_facts/additionalProperties"` appeared on the child's stderr.
        # It was non-fatal, but a schema the producer complains about is one step from a schema it
        # refuses, and the scalar constraint does not need to live here: validate_handoff enforces
        # it on OUR side, where the check is ours to trust.
        "measured_facts": {
            "type": "object",
            "description": "Flat name->scalar answers to any facts the task asked you to "
                           "determine, using exactly the key names the task specified. Values "
                           "must be scalars (string, number, boolean or null) -- not objects or "
                           "arrays. Report what you actually measured: the orchestrator measures "
                           "the same facts independently and any disagreement is an error.",
        },
        # OPTIONAL. The two-way channel: messages the executor emits DURING its bounded objective,
        # delivered with the result and persisted by the control plane. An AWAITING type
        # (DECISION_REQUEST etc.) is what pauses a lane; see core.messages for the closed
        # vocabulary. Emitting one grants nothing by itself -- AUTHORITY_REQUEST in particular is
        # recorded as a request and never as a grant.
        "messages": {
            "type": "array",
            "description": "Governed messages to deliver alongside this result, each an object "
                           "{type, payload} (optional severity). Types are from the closed "
                           "executor vocabulary: CLARIFICATION_REQUEST, DECISION_REQUEST, "
                           "AUTHORITY_REQUEST, BLOCKER, OBSERVATION, PLAN_REVISION, RESULT, "
                           "REVIEW_FINDING.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type", "payload"],
                "properties": {
                    "type": {"type": "string"},
                    "payload": {"type": "string", "minLength": 1},
                    "severity": {"type": "string"},
                    "detail": {"type": "object"},
                },
            },
        },
    },
}

#: Message types an EXECUTOR may emit through the two-way channel. CLOSED: a strategist-facing or
#: owner-facing type that appears here would let a child mint directives to itself.
EXECUTOR_EMITTABLE = (
    "CLARIFICATION_REQUEST", "DECISION_REQUEST", "AUTHORITY_REQUEST",
    "BLOCKER", "OBSERVATION", "PLAN_REVISION", "RESULT", "REVIEW_FINDING",
)


@dataclass(frozen=True)
class HandoffValidation:
    """``outcome`` in (VALID|RESULT_INVALID|PROTOCOL_REFUSED|RUN_IDENTITY_REFUSED)."""

    outcome: str
    reason: str = ""
    handoff: Mapping | None = None

    @property
    def valid(self) -> bool:
        return self.outcome == VALID


def _is_bool(v: Any) -> bool:
    return v is True or v is False


def validate_handoff(payload: Any, binding: RunBinding | None = None) -> HandoffValidation:
    """Validate a candidate handoff. PURE. NEVER raises.

    ORDER IS THE POLICY, and it mirrors the source deployment:

      protocol -> version -> run identity -> shape -> enums

    Run identity is checked BEFORE the body is believed, so a stale artifact from an earlier run
    is rejected for BEING STALE rather than being parsed and trusted. A well-formed result from
    the wrong run is the dangerous case precisely because nothing inside it looks wrong.
    """
    if not isinstance(payload, Mapping):
        return HandoffValidation(RESULT_INVALID, "handoff is not a JSON object")

    if str(payload.get("protocol") or "") != PROTOCOL:
        return HandoffValidation(
            PROTOCOL_REFUSED,
            "protocol %r is not %s" % (payload.get("protocol"), PROTOCOL))

    raw_version = payload.get("protocol_version")
    if not isinstance(raw_version, int) or isinstance(raw_version, bool):
        return HandoffValidation(
            PROTOCOL_REFUSED,
            "protocol_version %r is not an integer major version" % (raw_version,))
    if raw_version not in SUPPORTED_MAJORS:
        return HandoffValidation(
            PROTOCOL_REFUSED,
            "unsupported handoff protocol major version %d (supported: %s). Refusing rather than "
            "parsing a future contract with today's meanings."
            % (raw_version, ", ".join(str(v) for v in SUPPORTED_MAJORS)))

    if binding is not None:
        mismatch = check_run_identity(payload, binding)
        if mismatch:
            return HandoffValidation(
                RUN_IDENTITY_REFUSED,
                "%s: this result does not belong to run %s" % (mismatch, binding.run_id))

    missing = [f for f in _REQUIRED_FIELDS if f not in payload]
    if missing:
        return HandoffValidation(RESULT_INVALID,
                                 "missing required field(s): %s" % ", ".join(sorted(missing)))

    if payload.get("prompt_disposition") not in domain.PROMPT_DISPOSITIONS:
        return HandoffValidation(RESULT_INVALID,
                                 "prompt_disposition %r not in %s"
                                 % (payload.get("prompt_disposition"), domain.PROMPT_DISPOSITIONS))
    if payload.get("program_verdict") not in domain.PROGRAM_VERDICTS:
        return HandoffValidation(RESULT_INVALID,
                                 "program_verdict %r not in %s"
                                 % (payload.get("program_verdict"), domain.PROGRAM_VERDICTS))
    if payload.get("next_authority") not in domain.NEXT_AUTHORITIES:
        return HandoffValidation(RESULT_INVALID,
                                 "next_authority %r not in %s"
                                 % (payload.get("next_authority"), domain.NEXT_AUTHORITIES))

    for flag in ("authorized_scope_exhausted", "continuation_allowed", "owner_decision_required"):
        if not _is_bool(payload.get(flag)):
            # LITERAL booleans, per canon.is_true: the string "false" would otherwise sail
            # through as a truthy value and invert the meaning of the field.
            return HandoffValidation(RESULT_INVALID,
                                     "%s must be a literal JSON boolean, got %r"
                                     % (flag, payload.get(flag)))

    claimed = payload.get("claimed_files_changed")
    if claimed is not None and not (isinstance(claimed, list)
                                    and all(isinstance(x, str) for x in claimed)):
        return HandoffValidation(RESULT_INVALID,
                                 "claimed_files_changed must be an array of strings")

    facts = payload.get("measured_facts")
    if facts is not None:
        if not isinstance(facts, Mapping):
            return HandoffValidation(RESULT_INVALID, "measured_facts must be an object")
        for k, v in facts.items():
            if isinstance(v, (list, dict)):
                return HandoffValidation(
                    RESULT_INVALID,
                    "measured_facts[%r] must be a scalar, got %s" % (k, type(v).__name__))

    msgs = payload.get("messages")
    if msgs is not None:
        if not isinstance(msgs, list):
            return HandoffValidation(RESULT_INVALID, "messages must be an array")
        for i, m in enumerate(msgs):
            if not isinstance(m, Mapping):
                return HandoffValidation(RESULT_INVALID, "messages[%d] must be an object" % i)
            mt = str(m.get("type") or "")
            if mt not in EXECUTOR_EMITTABLE:
                return HandoffValidation(
                    RESULT_INVALID,
                    "messages[%d].type %r is not in the executor-emittable vocabulary %s"
                    % (i, mt, list(EXECUTOR_EMITTABLE)))
            if not str(m.get("payload") or "").strip():
                return HandoffValidation(RESULT_INVALID,
                                         "messages[%d].payload is empty" % i)
            sev = m.get("severity")
            if sev is not None and str(sev).upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                                            ""):
                return HandoffValidation(RESULT_INVALID,
                                         "messages[%d].severity %r is not a known severity"
                                         % (i, sev))
            det = m.get("detail")
            if det is not None and not isinstance(det, Mapping):
                return HandoffValidation(RESULT_INVALID,
                                         "messages[%d].detail must be an object" % i)

    if not str(payload.get("summary") or "").strip():
        return HandoffValidation(RESULT_INVALID, "summary is empty")

    return HandoffValidation(VALID, "", dict(payload))


def claimed_change(payload: Mapping) -> bool | None:
    """Did the report CLAIM a file change? True / False / None (it did not say). PURE.

    Tri-state, following the source deployment's freshness check: "the report is silent" is not "the report said no".
    Collapsing them would manufacture a disagreement against a report that never made a claim.
    """
    claimed = payload.get("claimed_files_changed")
    if claimed is None:
        return None
    return bool(len(claimed) > 0)


def handoff_messages(payload: Mapping) -> tuple:
    """The validated two-way messages of this handoff, normalised. PURE.

    Returns a tuple of {type, payload, severity, detail} dicts, in the order the child emitted
    them. Validation already happened in ``validate_handoff``; this re-checks cheaply because a
    caller that skips validation must still get refusal-shaped output rather than a crash.
    """
    msgs = payload.get("messages")
    if not isinstance(msgs, list):
        return ()
    out = []
    for m in msgs:
        if not isinstance(m, Mapping):
            continue
        mt = str(m.get("type") or "")
        pl = str(m.get("payload") or "")
        if mt not in EXECUTOR_EMITTABLE or not pl.strip():
            continue
        # MEASURED on a live program: real models emit "high"/"info" more readily than the
        # canonical upper case. Severity is normalised here -- once, at extraction, so every
        # downstream comparison sees one spelling -- rather than failing runs over casing.
        sev = str(m.get("severity") or "").strip().upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = ""
        out.append({"type": mt, "payload": pl,
                    "severity": sev,
                    "detail": dict(m.get("detail") or {})})
    return tuple(out)

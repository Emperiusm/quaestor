"""executor_contract -- the executor interface, and the PURE parsing of whatever the CLI hands back.

ONE INTERFACE, TWO IMPLEMENTATIONS
----------------------------------
``FakeClaudeExecutor`` proves the state machine deterministically and for free.
``ClaudeCliExecutor`` runs the real child.

Almost every control in the mutation suite uses the fake. Burning subscription capacity to prove
that a database row changes is waste, and worse, a suite that needs a real agent to run is a
suite nobody runs.

THE ENVELOPE PROBLEM, AND WHY THE PARSER IS PARANOID
----------------------------------------------------
``claude -p --output-format json`` returns an envelope, and where a ``--json-schema`` structured
result lands inside it is a property of the INSTALLED BINARY, not of this prompt or of anything
we can assert from documentation. instrument doctrine clause 2 is exactly about this: *a control
that consumes only your own output tests serialization, not verification.* If the fake executor
defined the envelope shape and the parser were written to match the fake, the parser would be
proven against bytes we generated and would tell us nothing about the real CLI.

So:

  * ``extract_structured`` searches SEVERAL plausible locations, and RECORDS WHICH ONE MATCHED
    (``source``), so the verdict states its environment;
  * finding nothing is a REFUSAL that names the keys it did see -- never an empty handoff;
  * and the P1 smoke's real ``stdout.json`` is kept as a test fixture, so from that point on the
    parser is tested against bytes this project did not write.

PURE, except that ``Executor.execute`` implementations do I/O by definition.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from quaestor.core.identity import RunBinding

# Exit classifications
EXIT_OK = "NORMAL_EXIT"
EXIT_NONZERO = "NONZERO_EXIT"
EXIT_TIMEOUT = "TIMEOUT"
EXIT_SPAWN_FAILED = "SPAWN_FAILED"
EXIT_NOT_OBSERVED = "NOT_OBSERVED"

# Structured-output extraction outcomes
FOUND = "FOUND"
RECOVERED = "RECOVERED_FROM_TEXT"
NO_STRUCTURED_OUTPUT = "NO_STRUCTURED_OUTPUT"
UNPARSEABLE = "UNPARSEABLE"

# Handoff strength: what the extraction SOURCE says about how much the payload is worth as
# evidence. MEASURED against the live LOCAL_GOVERNED program (2026-08-24), where 8 of 32 real
# children answered in prose and only text recovery could have read them at all -- so the
# durable record must never let a recovered handoff pass for one the CLI validated against our
# json-schema. A recovered handoff is admissible; it is just never NATIVE.
HANDOFF_STRENGTH_NATIVE = "NATIVE_SCHEMA_VALIDATED"
HANDOFF_STRENGTH_DEGRADED = "EXACT_TEXT_JSON"
HANDOFF_STRENGTH_WEAK = "FENCED_JSON_RECOVERED_FROM_PROSE"

# Failure taxonomy for the durable record. ``classify_failure`` maps the invalid_reason strings
# this pipeline actually produces onto exactly one class, machine-readably, so post-mortems over
# many runs do not have to re-parse prose to count failure modes.
FAILURE_CLASS_ENVELOPE_NOT_JSON = "ENVELOPE_NOT_JSON"
FAILURE_CLASS_MISSING_STRUCTURED_OUTPUT = "MISSING_STRUCTURED_OUTPUT"
FAILURE_CLASS_PROSE_ONLY_RESULT = "PROSE_ONLY_RESULT"
FAILURE_CLASS_SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
FAILURE_CLASS_RUN_BINDING_MISMATCH = "RUN_BINDING_MISMATCH"
FAILURE_CLASS_CLI_ERROR_ENVELOPE = "CLI_ERROR_ENVELOPE"
FAILURE_CLASS_OTHER = "OTHER"

#: Bounds for embedded-JSON recovery. Recovery is a best-effort NET-WIDENING pass over text the
#: CLI did not validate, so it must be cheap, deterministic and unable to run away: a cap on the
#: candidate count and on the scanned prefix keeps a pathological stdout from costing more than
#: the scan itself. Measured against the live LOCAL_GOVERNED program (2026-08-24): 8 of 32 real
#: children answered in prose with NO recoverable object at all -- so this widens the net for
#: the common fenced-JSON-in-prose shape without pretending it rescues pure prose.
_RECOVERY_MAX_TEXT = 200_000
_RECOVERY_MAX_CANDIDATES = 50
_RECOVERY_MAX_OPENS = 25
_RECOVERY_MAX_SPANS_PER_OPEN = 8

#: Any fenced block, any language tag. Group 1 is the body.
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)


@dataclass(frozen=True)
class ExecRequest:
    """Everything an executor needs. No secrets, no ambient state."""

    run_id: str
    run_dir: str
    cwd: str
    prompt: str
    binding: RunBinding
    json_schema: Mapping
    authority_profile: str
    stdout_path: str
    stderr_path: str
    claude_path: str = "claude"
    model: str = ""
    timeout_s: float = 1800.0
    env: Mapping[str, str] | None = None
    extra_args: Sequence[str] = field(default_factory=tuple)
    #: Set ONLY by an executor that has validated a container confinement boundary. Profiles in
    #: cli_executor.CONFINEMENT_REQUIRED_PROFILES refuse to build a command without it, so the
    #: default of False is what makes "edit-capable child on the native host" unreachable by
    #: omission rather than by remembering.
    container_confined: bool = False


@dataclass(frozen=True)
class ExecOutcome:
    """What the executor OBSERVED. It renders no verdict on the run's meaning."""

    started: bool
    exit_code: int | None
    exit_class: str
    child_pid: int | None = None
    child_create_time: str | None = None
    error: str = ""
    note: str = ""


class Executor:
    """Interface. ``execute`` must write the child's stdout to ``req.stdout_path``."""

    name = "abstract"

    def execute(self, req: ExecRequest) -> ExecOutcome:  # pragma: no cover - interface
        raise NotImplementedError


# ---------------------------------------------------------------------------------------------
# PURE parsing of the result envelope
# ---------------------------------------------------------------------------------------------
_STRUCTURED_KEYS = ("structured_output", "structuredOutput", "structured_result", "structured")


def parse_envelope(raw: str) -> tuple:
    """(envelope|None, error). PURE. NEVER raises.

    A stdout that is not JSON is not an empty result -- it is an UNPARSEABLE one, and the two get
    different handling everywhere downstream.

    THREE accepted shapes, each answered with a note naming what was done (bd quaestor-lh0 added
    the third): ONE document; ONE array (the LAST object is the conventional terminal message);
    NEWLINE-DELIMITED JSON -- how ``codex exec --json`` actually streams its events. The JSONL
    branch applies the SAME last-complete-object rule, so a torn final write (a child killed
    mid-line) is skipped and COUNTED rather than believed.
    """
    text = (raw or "").strip()
    if not text:
        return None, "stdout was empty"
    try:
        doc = json.loads(text)
    except ValueError:
        return _parse_jsonl(text)
    if not isinstance(doc, (dict, list)):
        return None, "stdout JSON is a %s, not an object" % type(doc).__name__
    if isinstance(doc, list):
        # stream-json misconfiguration, or a future envelope shape. The LAST object is the
        # conventional terminal message; say so in the note rather than silently picking one.
        objs = [d for d in doc if isinstance(d, dict)]
        if not objs:
            return None, "stdout JSON is an array with no objects"
        return objs[-1], "envelope was an array; used the last object"
    return doc, ""


def _parse_jsonl(text: str) -> tuple:
    """The streamed-events fallback: parse line-by-line, keep the LAST complete object. PURE.

    Reached ONLY when the whole-text parse already failed, so a pretty-printed single document
    can never be mistaken for a stream. Lines that fail to parse OR are not objects are skipped
    and counted into the note -- an omitted line is stated as omitted (the capsule rule), which
    is what makes a torn tail visible instead of silently redefining the envelope.
    """
    objects = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
        else:
            skipped += 1
    if not objects:
        return None, ("stdout is not valid JSON as one document and carries no complete "
                      "JSONL object line")
    note = "envelope was newline-delimited JSONL; used the last of %d objects" % len(objects)
    if skipped:
        note += "; %d non-object/incomplete line(s) skipped" % skipped
    return objects[-1], note


def extract_structured(envelope: Mapping) -> tuple:
    """(payload|None, source, outcome). PURE. NEVER raises.

    ``source`` names WHERE the payload was found -- the verdict states its environment, so a
    future CLI that moves the field shows up as a changed source string in the ledger instead of
    as a silent behaviour change.
    """
    if not isinstance(envelope, Mapping):
        return None, "", NO_STRUCTURED_OUTPUT

    for key in _STRUCTURED_KEYS:
        if key in envelope:
            val = envelope[key]
            if isinstance(val, Mapping):
                return dict(val), key, FOUND
            if isinstance(val, str) and val.strip():
                try:
                    parsed = json.loads(val)
                except ValueError:
                    return None, key, UNPARSEABLE
                if isinstance(parsed, Mapping):
                    return dict(parsed), key + "(string)", FOUND
                return None, key, UNPARSEABLE

    result = envelope.get("result")
    if isinstance(result, Mapping):
        return dict(result), "result", FOUND
    if isinstance(result, str) and result.strip():
        # A model asked for JSON often returns it as text. Accept it, but SAY SO: a payload
        # recovered from free text is weaker evidence than one the CLI validated, and the
        # difference belongs in the record rather than in somebody's memory.
        try:
            parsed = json.loads(_strip_code_fence(result))
        except ValueError:
            parsed = None
        if isinstance(parsed, Mapping):
            return dict(parsed), "result(text-json)", FOUND
        for candidate, where in _embedded_json_candidates(result):
            try:
                parsed = json.loads(candidate)
            except ValueError:
                continue
            if isinstance(parsed, Mapping):
                return (dict(parsed), "result(text-embedded:%s)" % where, RECOVERED)
    return None, "", NO_STRUCTURED_OUTPUT


def _embedded_json_candidates(text: str) -> list:
    """Deterministic, bounded candidates for a JSON object embedded in prose. PURE.

    Two shapes, fences first (any language tag -- the model that writes ```json also writes
    ```text around valid JSON), then brace spans: every ``{`` up to a bounded number of opens,
    paired with each ``}`` its span reaches, nearest first. Lenient pairing is deliberate --
    measured live prose wraps a valid object INSIDE an unbalanced outer span (`{"broken":
    ...\nthen {"protocol": ...}`) which strict balancing can never see -- and safety lives in
    the caller: nothing is trusted until ``json.loads`` accepts the span AND the handoff
    validator accepts the result.
    """
    out = []
    t = (text or "")[:_RECOVERY_MAX_TEXT]

    for block in _FENCE_RE.findall(t):
        stripped = block.strip()
        if stripped.startswith("{"):
            out.append((stripped, "fence"))
            if len(out) >= _RECOVERY_MAX_CANDIDATES:
                return out

    opens = [i for i, ch in enumerate(t) if ch == "{"][:_RECOVERY_MAX_OPENS]
    for i in opens:
        depth = 0
        in_str = False
        esc = False
        taken = 0
        for j in range(i, len(t)):
            ch = t[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                out.append((t[i:j + 1], "brace"))
                taken += 1
                if depth <= 0 or taken >= _RECOVERY_MAX_SPANS_PER_OPEN:
                    break
        if len(out) >= _RECOVERY_MAX_CANDIDATES:
            break
    return out


def _strip_code_fence(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


# ---------------------------------------------------------------------------------------------
# Handoff strength and the failure taxonomy: source/reason STRINGS -> enums
# ---------------------------------------------------------------------------------------------
def handoff_strength(source: str) -> str:
    """Map an ``extract_structured`` source string to the evidence strength of its payload. PURE,
    total -- an unknown source degrades to WEAK rather than raising, because an unseen spelling
    must never read as stronger than it is.

    Mapping (the spellings are exactly what ``extract_structured`` above can produce):

      * anything under a structured-output key (``_STRUCTURED_KEYS``), bare or "(string)" --
        NATIVE: the CLI validated that payload against our json-schema before we ever saw it;
      * ``result`` (mapping form) and ``result(text-json)`` -- DEGRADED: exact text that parsed
        as JSON on OUR side, but nothing a producer ever validated;
      * ``result(text-embedded...)`` -- WEAK: net-widened out of prose by the recovery scan;
      * empty / unknown -- WEAK: no source means no claim of validation.
    """
    s = str(source or "").strip()
    if s.startswith(_STRUCTURED_KEYS):
        return HANDOFF_STRENGTH_NATIVE
    if s in ("result", "result(text-json)"):
        return HANDOFF_STRENGTH_DEGRADED
    if s.startswith("result(text-embedded"):
        return HANDOFF_STRENGTH_WEAK
    return HANDOFF_STRENGTH_WEAK


def classify_failure(invalid_reason: str) -> str:
    """Map an ``invalid_reason`` string onto one FAILURE_CLASS. PURE, total -> OTHER.

    The wording contract is the strings THIS pipeline produces, and nothing else:

      * ``parse_envelope`` refusals all open by naming stdout ("stdout was empty", "stdout is
        not valid JSON: ...") -> ENVELOPE_NOT_JSON;
      * the worker's payload-is-None branch emits "no structured handoff in the result envelope
        (EXTRACTION); envelope was a object with keys: ...". A structured slot that held nothing
        usable is MISSING_STRUCTURED_OUTPUT; an envelope that carried only a free-text ``result``
        key with no recoverable object is PROSE_ONLY_RESULT -- the live LOCAL_GOVERNED shape
        (2026-08-24: 8 of 32 children answered in prose), which deserves its own class because
        "the child never used the contract" and "the contract was absent" are different defects;
      * the CLI error-envelope path (``envelope_is_error``) -> CLI_ERROR_ENVELOPE, keyed on the
        "is_error"/"error envelope" wording such a refusal carries;
      * identity refusals carry the RUN_IDENTITY_ markers from check_run_identity ->
        RUN_BINDING_MISMATCH. Checked BEFORE shape markers, because a missing-field list can
        name run_nonce too, and "stamped somebody else's nonce" is not a schema defect;
      * everything that reads like validator output ("protocol", "missing required field(s)",
        "must be", "not in", "is empty", non-object handoff) -> SCHEMA_VALIDATION_FAILED;
      * infrastructure noise ("two-way delivery failed") and the truly unknown -> OTHER.
    """
    r = str(invalid_reason or "")
    if not r.strip() or "two-way delivery failed" in r:
        return FAILURE_CLASS_OTHER
    if r.startswith("stdout"):
        return FAILURE_CLASS_ENVELOPE_NOT_JSON
    if "no structured handoff in the result envelope" in r:
        if "(UNPARSEABLE)" in r:
            # A structured slot existed but held nothing json.loads could read: no usable
            # structured output reached us, whatever the producer thought it sent.
            return FAILURE_CLASS_MISSING_STRUCTURED_OUTPUT
        keys_part = r.split("keys:", 1)[1] if "keys:" in r else ""
        has_result_key = re.search(r"\bresult\b", keys_part) is not None
        has_structured_key = any(k in keys_part for k in _STRUCTURED_KEYS)
        if has_result_key and not has_structured_key:
            return FAILURE_CLASS_PROSE_ONLY_RESULT
        return FAILURE_CLASS_MISSING_STRUCTURED_OUTPUT
    if "is_error" in r or "error envelope" in r:
        return FAILURE_CLASS_CLI_ERROR_ENVELOPE
    if "RUN_IDENTITY_" in r or "does not belong to run" in r:
        return FAILURE_CLASS_RUN_BINDING_MISMATCH
    schema_markers = ("handoff is not a JSON object", "protocol", "missing required field(s)",
                      "must be", "not in", "is empty")
    if any(m in r for m in schema_markers):
        return FAILURE_CLASS_SCHEMA_VALIDATION_FAILED
    return FAILURE_CLASS_OTHER


def envelope_session_id(envelope: Mapping) -> str:
    """Claude's session id, if the installed CLI emits one. PURE."""
    if not isinstance(envelope, Mapping):
        return ""
    for key in ("session_id", "sessionId", "session"):
        v = envelope.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def envelope_is_error(envelope: Mapping) -> tuple:
    """(is_error, subtype). PURE.

    ``is_error`` is checked as a LITERAL boolean: an envelope carrying the string "false" must
    not read as an error, and one carrying "true" must not be dismissed because it is not a bool.
    """
    if not isinstance(envelope, Mapping):
        return False, ""
    v = envelope.get("is_error")
    subtype = str(envelope.get("subtype") or "")
    if v is True:
        return True, subtype
    if isinstance(v, str) and v.strip().lower() == "true":
        return True, subtype or "is_error-as-string"
    return False, subtype


def envelope_telemetry(envelope: Mapping) -> dict:
    """Independently-observable facts the CLI reports about the run. PURE.

    MEASURED against a real 2.1.185 envelope (see tests/fixtures/real_claude_stdout.json), not
    assumed. Three of these earn their place:

      * ``permission_denials`` -- the RUNTIME's own record of tools it refused the child. This is
        a bridge-side observation, not a claim by the model, and it is the only way to notice
        that a child reporting COMPLETE was actually working with less authority than it thought.
      * ``stop_reason`` / ``terminal_reason`` / ``subtype`` -- termination evidence independent
        of the exit code.
      * ``total_cost_usd`` -- recorded VERBATIM and deliberately NOT interpreted. The field is
        present even when the auth preflight classified the run as subscription-backed, so it is
        a cost-equivalent figure rather than proof of a billed charge. Reading it as "this run
        cost money" would be exactly the kind of inference this control plane refuses to make;
        the auth preflight, not this number, is the billing-path evidence.
    """
    if not isinstance(envelope, Mapping):
        return {}
    denials = envelope.get("permission_denials")
    models = envelope.get("modelUsage")
    return {
        "subtype": envelope.get("subtype"),
        "stop_reason": envelope.get("stop_reason"),
        "terminal_reason": envelope.get("terminal_reason"),
        "num_turns": envelope.get("num_turns"),
        "duration_ms": envelope.get("duration_ms"),
        "api_error_status": envelope.get("api_error_status"),
        "permission_denials": list(denials) if isinstance(denials, list) else None,
        "permission_denial_count": (len(denials) if isinstance(denials, list) else None),
        "models_reported": sorted(models) if isinstance(models, Mapping) else None,
        "total_cost_usd_reported": envelope.get("total_cost_usd"),
        "cost_note": ("reported by the CLI and NOT interpreted as a billed charge; the auth "
                      "preflight is what establishes the billing path"),
    }


def describe_envelope(envelope: Any) -> str:
    """A short, non-sensitive description of what we got, for a refusal message. PURE."""
    if isinstance(envelope, Mapping):
        return "object with keys: %s" % ", ".join(sorted(str(k) for k in envelope)[:20])
    return type(envelope).__name__

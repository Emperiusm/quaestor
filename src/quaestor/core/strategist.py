"""strategist -- the STRATEGIST seat: directive proposal, admission, disposition.

WHAT THIS MODULE IS (PRD.md §7, extending §7.4)
------------------------------------------------
``planner.py`` established the shape one seat earlier: "the planner proposes, Quaestor disposes."
This is the same shape further along. A model in the STRATEGIST seat reads the durable brief and
proposes DIRECTIVES -- answers to the questions currently open. The proposal is DATA. Admission
here is a PURE, deterministic validation; what happens to an admitted directive is decided by
``core.autonomy``, never by the model that wrote it.

The stakes are higher than the planner's, which is why the checks are stricter. A plan proposal
changes nothing until a human adopts it. A directive ANSWERS a question and writes a decision
into a ledger that later runs read as binding -- ``orchestrator.answer`` appends it to the task
text of the next dispatched run under the heading "STRATEGIST DECISION (binding)". A bad
directive is therefore not a bad suggestion; it is an instruction a builder will follow.

THE MESSAGE ID IS THE ONLY BINDING
-----------------------------------
A directive means nothing except in reference to the question it answers, and the model's only
handle on that question is an id it was shown. An id that is not currently OPEN is refused
outright: invented, stale and already-answered ids are indistinguishable from one another here,
and all three would write a decision against a question nobody asked.

WHY OWNER-ROUTED ASKS ARE REFUSED *AGAIN*
------------------------------------------
``autonomy.disposition`` already escalates anything owner-routed. This module refuses it a second
time, independently, on a different input -- the message's own recorded route rather than the
caller's classification of it. That redundancy is deliberate: the two checks fail differently, so
neither is load-bearing alone, and a future refactor that removes one leaves the boundary
standing. Same reasoning ``transports.mcp.mode`` documents for its three barriers.

CLOSED VOCABULARY, BOTH WAYS
-----------------------------
Unknown fields are REFUSED rather than ignored, at the top level and per directive. An ignored
field is a field that can be added later by anyone who can influence the model's output, and the
interesting ones are exactly the ones nobody has decided are safe yet. Authority-shaped names are
refused by their own named error so the record distinguishes "the model tried to grant itself
something" from "the model emitted a typo".
"""
from __future__ import annotations

from typing import Mapping, Sequence

STRATEGIST_INSTRUMENT = "strategist/1"

# ---- program meta keys ------------------------------------------------------------------------
#: Set to STRATEGIST_SEAT to let a model hold the seat. Absent means the human holds it, which is
#: the behaviour every existing deployment already has -- this feature is opt-in per program.
STRATEGY_MODE_KEY = "strategy_mode"
STRATEGIST_SEAT = "strategist_seat"

#: Mirrors planner's keys. The run key makes consumption exactly-once; the attempts key makes the
#: dispatch step id unique so a retry is a new run rather than an id collision.
STRATEGIST_RUN_META_KEY = "_strategist_run_id"
STRATEGIST_ATTEMPTS_KEY = "_strategist_attempts"
#: Directives awaiting a human click (autonomy DEFAULT, or SAFE on a non-routine item).
PENDING_DIRECTIVES_KEY = "_pending_directives_json"
#: The server-side fixture seam, mirroring ``_planner_executor`` and ``review_executor``.
STRATEGIST_EXECUTOR_META_KEY = "_strategist_executor"
#: Consecutive refused turns. Reset to 0 by any turn that admits.
STRATEGIST_REFUSALS_KEY = "_strategist_refusals"
#: The provider session this seat is bound to -- ChatGPT calls it a conversation, Claude Code
#: calls it a session, and the platform already had one name for it (``result.session_id``,
#: extracted from the envelope by the worker). Binding on THAT rather than on a vendor-specific
#: field means every provider emitting a session id gains continuity across turns, instead of
#: one vendor getting a bespoke path nothing else can use.
#:
#: Continuity matters here more than for a builder lane: a strategist that re-reads the whole
#: brief from scratch each turn has no memory of why it decided what it decided last time, and
#: the packet deliberately carries decisions rather than reasoning.
STRATEGIST_SESSION_KEY = "_strategist_session_id"

#: The answerable-question fingerprint the refusal budget was counted against. A seat that
#: could not answer question set X must not stay halted once the program has moved on to set Y:
#: the budget means "this seat cannot handle THIS", never "this seat is broken forever". Without
#: it there is no reset path at all -- the counter is durable program meta and no surface clears
#: it, so one bad stretch bricked the seat for the life of the program.
STRATEGIST_REFUSAL_SCOPE_KEY = "_strategist_refusal_scope"


def answerable_fingerprint(questions) -> str:
    """A stable fingerprint of the STRATEGIST-routed message ids on offer. PURE.

    Sorted, so it does not change with inbox ordering; ids only, so re-wording a question does
    not silently forgive a seat that could not answer it.
    """
    ids = sorted({_safe_str((q or {}).get("message_id") or "")
                  for q in (questions or ())
                  if isinstance(q, Mapping)
                  and _safe_str(q.get("message_id") or "")
                  and _safe_str(q.get("route") or "") != "OWNER"})
    return "|".join(ids)


#: How many consecutive REFUSED turns before the seat stops dispatching and escalates.
#:
#: Without this the loop is: dispatch -> model emits something unparseable -> refuse -> dispatch
#: again, forever, burning a real provider call every tick. That is not hypothetical -- it is the
#: same shape as the reap/NOTED catch-all that once re-dispatched live executor runs indefinitely,
#: and it is exactly the failure mode unattended operation cannot tolerate. A model that has
#: failed to produce a valid response three times running is not going to produce one on the
#: fourth attempt for reasons that will change by themselves; a human needs to look.
MAX_CONSECUTIVE_REFUSALS = 3

# ---- named refusals ---------------------------------------------------------------------------
DIRECTIVE_INVALID = "DIRECTIVE_INVALID"
DIRECTIVE_EMPTY = "DIRECTIVE_EMPTY"
DIRECTIVE_UNKNOWN_FIELD = "DIRECTIVE_UNKNOWN_FIELD"
DIRECTIVE_UNKNOWN_MESSAGE = "DIRECTIVE_UNKNOWN_MESSAGE"
DIRECTIVE_OWNER_ROUTED = "DIRECTIVE_OWNER_ROUTED"
DIRECTIVE_AUTHORITY_FIELD = "DIRECTIVE_AUTHORITY_FIELD"
DIRECTIVE_TOO_LONG = "DIRECTIVE_TOO_LONG"
DIRECTIVE_DUPLICATE = "DIRECTIVE_DUPLICATE"

TOP_LEVEL_KEYS = ("directives",)
DIRECTIVE_KEYS = ("message_id", "directive", "rationale")

#: Field names that would embed authority in a directive. Same intent as
#: ``planner.AUTHORITY_FIELD_NAMES``: a seat proposes WHAT to do, never what it may do. Matched
#: case-insensitively, because a denylist matched case-sensitively is a denylist with a trivial
#: bypass. ``executor``/``spawn``/``worktree_path`` are here too -- they do not grant authority by
#: themselves, but they are the fields that would REDIRECT where a directive takes effect.
AUTHORITY_FIELD_NAMES = frozenset({
    "authority", "authority_profile", "capabilities", "capability", "grant", "grants",
    "owner_token", "token", "profile", "executor", "worktree_path", "spawn", "run_id",
    "actor_id", "authority_context"})

MAX_DIRECTIVES = 32
MAX_DIRECTIVE_CHARS = 4000
MAX_RATIONALE_CHARS = 2000


def _err(code: str, detail: str) -> str:
    return "%s: %s" % (code, detail)


def _safe_str(value) -> str:
    """str() that cannot raise. Hostile input reaches this module by construction."""
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return "<unstringable>"


def validate_directive_response(doc, *, open_questions: Sequence[Mapping]) -> tuple:
    """(ok, errors) for one strategist response. PURE. NEVER raises.

    ``open_questions`` are the items the seat was SHOWN -- each a mapping carrying at least
    ``message_id`` and ``route``. Validation is CLOSED over that set: nothing outside it can be
    answered, which is what makes an invented id a refusal rather than a decision.

    Errors accumulate rather than short-circuiting: a seat that got three things wrong should be
    told all three, because it will be re-dispatched and a one-at-a-time correction loop burns a
    turn per mistake.
    """
    errors: list = []
    if not isinstance(doc, Mapping):
        return False, [_err(DIRECTIVE_INVALID,
                            "response is %s, not an object" % type(doc).__name__)]
    unknown_top = sorted(_safe_str(k) for k in doc if _safe_str(k) not in TOP_LEVEL_KEYS)
    if unknown_top:
        errors.append(_err(DIRECTIVE_UNKNOWN_FIELD,
                           "top-level %s outside %s" % (unknown_top, list(TOP_LEVEL_KEYS))))
    items = doc.get("directives")
    if not isinstance(items, (list, tuple)) or not items:
        errors.append(_err(DIRECTIVE_EMPTY,
                           "a response with no directives is vacuous, not a success"))
        return False, errors
    if len(items) > MAX_DIRECTIVES:
        errors.append(_err(DIRECTIVE_TOO_LONG,
                           "%d directives exceeds the bound of %d"
                           % (len(items), MAX_DIRECTIVES)))
    # ONLY REAL MESSAGES ARE ANSWERABLE. The inbox carries program-level items that are not
    # messages at all -- LANE_FAILED and INTEGRATION_CONFLICT have no message_id key, and
    # PROPOSAL_PENDING_ADOPTION carries "". Keying on those turned the literal strings "None"
    # and "" into answerable ids routed STRATEGIST, so a directive naming one validated, then
    # dispositioned with NO route and NO kind -- the one input under which AUTO applies -- and
    # reached answer() with an id no message has, raising out of the governance step.
    #
    # A directive can only ever mean "answer THIS message", so an item without a message id is
    # not something this seat can be asked to answer, whatever else it is.
    routes = {}
    for q in (open_questions or ()):
        if not isinstance(q, Mapping):
            continue
        mid = _safe_str(q.get("message_id") or "")
        if not mid:
            continue
        routes[mid] = _safe_str(q.get("route") or "")
    seen = set()
    for i, item in enumerate(items):
        where = "directives[%d]" % i
        if not isinstance(item, Mapping):
            errors.append(_err(DIRECTIVE_INVALID,
                               "%s is %s, not an object" % (where, type(item).__name__)))
            continue
        banned = sorted(_safe_str(k) for k in item
                        if _safe_str(k).lower() in AUTHORITY_FIELD_NAMES)
        if banned:
            errors.append(_err(DIRECTIVE_AUTHORITY_FIELD,
                               "%s carries %s; a directive says WHAT to do, never what the seat "
                               "may do or where it takes effect" % (where, banned)))
        unknown = sorted(_safe_str(k) for k in item
                         if _safe_str(k) not in DIRECTIVE_KEYS
                         and _safe_str(k).lower() not in AUTHORITY_FIELD_NAMES)
        if unknown:
            errors.append(_err(DIRECTIVE_UNKNOWN_FIELD,
                               "%s carries %s outside %s" % (where, unknown,
                                                             list(DIRECTIVE_KEYS))))
        mid = _safe_str(item.get("message_id") or "")
        if not mid:
            # Named separately from UNKNOWN_MESSAGE: "you named nothing" and "you named
            # something that is not open" are different mistakes, and a seat correcting itself
            # needs to know which one it made.
            errors.append(_err(DIRECTIVE_EMPTY,
                               "%s names no message_id; a directive means nothing except in "
                               "reference to the question it answers" % where))
            continue
        if mid in seen:
            errors.append(_err(DIRECTIVE_DUPLICATE,
                               "%s answers %s twice; two directives for one question is an "
                               "ambiguity, not an answer" % (where, mid)))
        seen.add(mid)
        if mid not in routes:
            errors.append(_err(DIRECTIVE_UNKNOWN_MESSAGE,
                               "%s answers %r, which is not an open question this seat was shown"
                               % (where, mid)))
        elif routes[mid] == "OWNER":
            errors.append(_err(DIRECTIVE_OWNER_ROUTED,
                               "%s answers %s, which is routed to the OWNER; a model seat cannot "
                               "dispose of owner authority" % (where, mid)))
        text = _safe_str(item.get("directive") or "").strip()
        if not text:
            errors.append(_err(DIRECTIVE_EMPTY, "%s has no directive text" % where))
        elif len(text) > MAX_DIRECTIVE_CHARS:
            errors.append(_err(DIRECTIVE_TOO_LONG,
                               "%s directive is %d chars (bound %d)"
                               % (where, len(text), MAX_DIRECTIVE_CHARS)))
        if len(_safe_str(item.get("rationale") or "")) > MAX_RATIONALE_CHARS:
            errors.append(_err(DIRECTIVE_TOO_LONG,
                               "%s rationale exceeds %d chars" % (where, MAX_RATIONALE_CHARS)))
    return (not errors), errors


def build_strategist_task(bundle: Mapping, *, surfaces: Mapping | None = None) -> str:
    """The prompt for one strategist turn. PURE.

    Reuses ``core.briefing`` rather than composing a second document. The packet already
    assembles the brief from durable rows and sanitises every free-text field on the way out; a
    separate prompt builder here would be a second reading of program state, and the two would
    drift. The seat carrier swaps the human-relay language for the response schema this module
    validates -- so the document the model is shown and the rules it is judged by come from the
    same place by construction.
    """
    from quaestor.core import briefing as briefing_mod
    return briefing_mod.briefing(bundle, surfaces=surfaces,
                                 carrier=briefing_mod.CARRIER_SEAT)["prompt"]

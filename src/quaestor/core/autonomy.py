"""autonomy -- how much a MODEL holding the strategist seat decides without a human.

WHY THIS IS A SEPARATE PURE MODULE
-----------------------------------
The strategist seat is the first place a model DISPOSES of governed state rather than proposing
work for a human to dispose of. ``planner.py`` could afford to be relaxed about this because a
plan proposal changes nothing until someone adopts it; a directive answers a question and writes
a decision into a ledger that later runs read as binding. So the rule deciding what a model may
dispose of alone is the highest-value thing in this codebase to keep readable, testable and free
of I/O: it is a pure function over three strings, and a control can enumerate its ENTIRE domain.

THE ONE INVARIANT
-----------------
An owner-routed ask escalates in EVERY mode, AUTO included. Owner capability is "always human,
never configurable, never delegated" (direction section 3); an autonomy setting that could reach
it would not be an autonomy setting, it would be a delegation of ownership.

That branch is checked FIRST, before the mode is even resolved, so no future edit to the mode
table can accidentally shadow it. It fires on EITHER signal -- the inbox's routing OR the
message's own type -- because those two inputs come from different places, and requiring both to
agree would let a disagreement between them resolve toward autonomy. It is then checked a second
time, independently, in ``strategist.validate_directive_response``, on the message's own record.
Two checks, two modules, two inputs: neither is load-bearing alone, and a refactor that removes
one leaves the boundary standing. Same reasoning ``transports.mcp.mode`` documents for its three
barriers.

FAIL-SAFE, NOT FAIL-OPEN
------------------------
An unrecognised mode resolves to QUEUE_FOR_APPROVAL, never APPLY. The failure mode of a corrupted
settings file must be "the operator is asked more often than they chose", never "a model was
granted more than they chose". Absent evidence of a choice is not evidence of consent.

WHAT THIS MODULE DOES NOT DECIDE
--------------------------------
Whether the directive is well-formed (``core.strategist``), whether the seat could be resolved at
all (``adapters.registry``), or whether the run that produced it was admissible (``dispatcher``).
A second opinion on any of those would be a second policy.
"""
from __future__ import annotations

AUTONOMY_INSTRUMENT = "autonomy/1"

#: PROGRAM META key holding the chosen mode. Deliberately per-program rather than a deployment
#: file: a deployment file would have to be read by a transport module and handed down, which
#: means ``core`` importing an outer layer to evaluate its own policy -- the one edge the
#: layering rule exists to forbid. Program meta is durable state core already owns, and the
#: granularity is better anyway: a well-understood refactor can run AUTO while the program that
#: touches the payment path runs SAFE. Absent resolves to FALLBACK_MODE, so an untouched program
#: is propose-only.
AUTONOMY_MODE_KEY = "autonomy_mode"

#: Routine only; the owner gates everything else. Auto-applies the asks a single directive
#: answers, queues anything that changes plan shape or reports a failure.
SAFE = "SAFE"
#: Propose-only. The model drafts every directive; nothing applies until a human approves.
#: THE FALLBACK, because a deployment that has not chosen should not be deciding on its own.
DEFAULT = "DEFAULT"
#: Full autonomy below owner capability. Everything strategist-routed applies unattended.
AUTO = "AUTO"

KNOWN_MODES = (SAFE, DEFAULT, AUTO)

#: What an unreadable, absent or unrecognised setting resolves to. Deliberately the middle mode.
FALLBACK_MODE = DEFAULT

APPLY = "APPLY"
QUEUE_FOR_APPROVAL = "QUEUE_FOR_APPROVAL"
ESCALATE_TO_OWNER = "ESCALATE_TO_OWNER"
DISPOSITIONS = (APPLY, QUEUE_FOR_APPROVAL, ESCALATE_TO_OWNER)

#: Inbox kinds ONE directive answers. Deliberately an ALLOWLIST, not a denylist: a kind the
#: vocabulary grows later queues by default rather than inheriting permission nobody granted it.
ROUTINE_KINDS = ("CLARIFICATION_REQUEST", "DECISION_REQUEST")

#: Kinds belonging to the OWNER seat. Mirrors ``orchestrator.inbox``'s routing rule; named here
#: too because this module must be able to refuse WITHOUT importing the orchestrator (which
#: imports half the platform, and a policy that cannot be evaluated in isolation cannot be
#: audited in isolation either).
OWNER_KINDS = ("AUTHORITY_REQUEST", "OWNER_ESCALATION")

_OWNER_WHY = ("owner-routed asks escalate to the human owner in every autonomy mode; owner "
              "capability is never delegated to a model")


def resolve_mode(value) -> str:
    """The mode a raw value denotes, or FALLBACK_MODE. PURE. Never raises.

    Accepts anything -- a settings file can hold any bytes, and a resolver that raised on the
    interesting inputs would push the fail-open decision up to whoever forgot the try block.
    """
    try:
        text = str(value)
    except Exception:  # noqa: BLE001 - a value whose __str__ throws is simply unrecognised
        return FALLBACK_MODE
    return text if text in KNOWN_MODES else FALLBACK_MODE


def disposition(mode, *, route, kind) -> tuple:
    """(disposition, why) for one inbox item under one mode. PURE and TOTAL.

    Total by construction: every path returns, so there is no triple for which this function has
    no answer. A policy with a hole fails open exactly at the hole, and the hole is always the
    case nobody thought of.
    """
    route_text = "" if route is None else str(route)
    kind_text = "" if kind is None else str(kind)
    # OWNER FIRST, unconditionally, on either signal -- see the module docstring.
    if route_text == "OWNER" or kind_text in OWNER_KINDS:
        return ESCALATE_TO_OWNER, _OWNER_WHY
    resolved = resolve_mode(mode)
    unrecognised = resolved != (str(mode) if mode is not None else None)
    if resolved == AUTO:
        return APPLY, "AUTO: strategist-routed items apply without a human"
    if resolved == SAFE:
        if kind_text in ROUTINE_KINDS:
            return APPLY, "SAFE: %s is answered by a single directive" % kind_text
        return QUEUE_FOR_APPROVAL, (
            "SAFE: %s changes plan shape or reports a failure, so it waits for approval"
            % (kind_text or "an unnamed item"))
    if unrecognised:
        return QUEUE_FOR_APPROVAL, (
            "autonomy mode %r is unrecognised; falling back to %s (propose-only) rather than "
            "widening what a model may do" % (mode, FALLBACK_MODE))
    return QUEUE_FOR_APPROVAL, "DEFAULT: every directive is proposed for one-click approval"

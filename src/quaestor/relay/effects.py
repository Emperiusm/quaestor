"""effects -- the governance boundary of Relay Mode. GATE THE ACT, NOT THE SENTENCE.

THE FAILURE THIS MODULE REFUSES TO BE
-------------------------------------
The tempting design is a keyword scanner: watch the Orchestrator's prose for "push", "deploy",
"rm -rf", and stop the relay when one appears. That design is worthless in both directions. It
fires on "do not push this yet", and it misses every phrasing nobody thought of. Worse, it makes
the model's WORDS the security boundary, which is precisely the property this platform exists to
deny -- a model must never be able to widen its own envelope by choosing a sentence.

So authority here comes from exactly two places, neither of which a model can write:

    1. the RELAY'S AUTHORITY PROFILE, fixed at start by the operator
    2. a live OWNER GRANT corroborated by an AUTHENTICATED owner channel

and the model's text can only ever REQUEST.

THE THREE GATES
---------------
``gate_start``      A profile ceiling, evaluated ONCE, before the first message moves. Binding
                    a repo-mutating execution end under a READ_ONLY profile is refused here --
                    at start, where an operator can fix it, not mid-conversation.

``gate_directive``  Per message. An Orchestrator may append a machine-readable effect REQUEST
                    (see ``parse_effect_request``). A request is not a grant: it is mapped onto
                    capabilities and run through ``core.authority.require``. OWNER_REQUIRED
                    becomes an owner hold. NOTE THE ASYMMETRY -- a directive with NO declared
                    effect gets the profile's ordinary ceiling and nothing more. Silence never
                    buys authority, and neither does confident prose.

``gate_observation``  After the fact, from INDEPENDENT git observation. If the repository shows
                    an owner-gated effect that the profile does not grant -- new commits under
                    STANDARD_EDIT, a moved remote ref -- the relay stops with an owner hold. This
                    is the gate that still works when the execution agent is unconfined, because
                    it reads the repository rather than believing the agent.

The third gate is why Relay Mode can honestly admit a weak integration. We cannot PREVENT an
unconfined agent from running ``git push``; we can refuse to instruct it to, and we can DETECT
that it happened and stop. Claiming prevention we do not have would be the dishonest option.

PURE module. Callers supply grants, the channel state and the clock.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import authority as auth

EFFECTS_INSTRUMENT = "relay.effects/1"

# ---------------------------------------------------------------------------------------------
# EFFECT CLASSES -- the structural vocabulary, identical to Program Mode's.
# ---------------------------------------------------------------------------------------------
READ_ONLY = "READ_ONLY"
STANDARD_EDIT = "STANDARD_EDIT"
GIT_COMMIT = "GIT_COMMIT"
GIT_PUSH = "GIT_PUSH"
DESTRUCTIVE = "DESTRUCTIVE"
EXTERNAL_WRITE = "EXTERNAL_WRITE"

#: Each class -> the capabilities performing it consumes. One table, so a new effect class
#: cannot be added without stating what it costs.
EFFECT_CAPABILITIES: Mapping[str, tuple] = {
    READ_ONLY: (auth.CAP_REPO_READ,),
    STANDARD_EDIT: (auth.CAP_REPO_READ, auth.CAP_REPO_WRITE),
    GIT_COMMIT: (auth.CAP_REPO_READ, auth.CAP_REPO_WRITE, auth.CAP_GIT_COMMIT),
    GIT_PUSH: (auth.CAP_REPO_READ, auth.CAP_REPO_WRITE, auth.CAP_GIT_COMMIT, auth.CAP_GIT_PUSH),
    DESTRUCTIVE: (auth.CAP_REPO_READ, auth.CAP_DESTRUCTIVE),
    EXTERNAL_WRITE: (auth.CAP_REPO_READ, auth.CAP_EXTERNAL_WRITE),
}

EFFECT_CLASSES = tuple(EFFECT_CAPABILITIES)

# Named holds.
HOLD_OWNER_REQUIRED = "OWNER_REQUIRED"
HOLD_UNKNOWN_EFFECT = "UNKNOWN_EFFECT_CLASS"
HOLD_OBSERVED_UNGRANTED_EFFECT = "OBSERVED_UNGRANTED_EFFECT"
HOLD_PROFILE_CEILING = "PROFILE_CEILING"
#: The repository could not be read on both sides of a turn, so what the agent did is UNKNOWN.
#: Not the same as "it did nothing": a clean turn measures as READ_ONLY.
HOLD_OBSERVATION_UNMEASURABLE = "OBSERVATION_UNMEASURABLE"

#: THE ONE MACHINE CHANNEL. Ordinary dialogue is ordinary text -- the architecture is explicit
#: that normal engineering conversation must not be forced into a directive schema. This block
#: exists only where a governed machine boundary is actually crossed: the Orchestrator asking
#: for an effect beyond routine editing.
#:
#: It is parsed from a FENCED block with a fixed tag, not from free prose, and the ONLY thing
#: it can do is name a class from ``EFFECT_CLASSES``. There is deliberately no field for a
#: rationale that could talk a gate into opening, no field naming a profile, and no field
#: naming a capability directly -- those would be prose reaching for authority again.
#:
#: THE TAG COMES FROM ``branding``, not from a literal here. It is text this platform SENDS to a
#: model and then parses back, so a product rename that missed it would leave the charter
#: teaching one tag while the parser recognised another: the effect channel would go quiet and
#: every request would silently read as an ordinary edit.
EFFECT_BLOCK_TAG = branding.resource("effect")

_EFFECT_BLOCK = re.compile(
    r"```[ \t]*" + re.escape(EFFECT_BLOCK_TAG) + r"[ \t]*\r?\n(?P<body>.*?)```",
    re.S | re.I)
_EFFECT_FIELD = re.compile(r"^[ \t]*effect[ \t]*[:=][ \t]*(?P<value>[A-Za-z_]+)[ \t]*$",
                           re.M)


@dataclass(frozen=True)
class EffectRequest:
    """What a directive ASKED FOR. ``source`` records how we know, so a status surface never
    has to wonder whether a class came from a machine block or was inferred (it is never
    inferred)."""

    effect_class: str
    source: str            # DECLARED_BLOCK | NONE
    raw: str = ""
    recognised: bool = True

    @property
    def capabilities(self) -> tuple:
        return EFFECT_CAPABILITIES.get(self.effect_class, ())


@dataclass(frozen=True)
class Gate:
    """A gate verdict. ``allowed`` False always carries a ``hold`` name and a ``reason``."""

    allowed: bool
    effect_class: str
    hold: str = ""
    reason: str = ""
    required: tuple = ()
    decision: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "effect_class": self.effect_class, "hold": self.hold,
                "reason": self.reason, "required": list(self.required),
                "decision": dict(self.decision or {}), "instrument": EFFECTS_INSTRUMENT}


def hold_id(relay_id: str, gate: str, effect_class: str, required) -> str:
    """The identity of ONE outstanding authority requirement. PURE.

    CONTENT-ADDRESSED, from the four things that decide whether a grant discharges it: which
    relay is asking, WHICH GATE stopped it, what class of effect was reached for, and exactly
    which capabilities were missing. The gate is in there because a directive REQUESTING a push
    and an observation finding a push already made are different requirements even when they
    name the same class -- an owner approving the request should not silently also approve a
    push that has already happened and was never asked about. That makes the identity stable across a restart without persisting a counter, and
    it makes the narrowness structural -- a hold for GIT_PUSH cannot collide with a hold for
    GIT_COMMIT, and a hold on one relay cannot collide with the same effect on another, because
    a different input produces a different id rather than a different row that has to be
    compared carefully by hand.

    It is deliberately NOT derived from the reason text. Prose is written for a human, gets
    rewritten, and would silently re-raise a hold that had already been discharged.
    """
    caps = ",".join(sorted(str(c) for c in (required or ())))
    raw = "\0".join((str(relay_id), str(gate), str(effect_class), caps))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def parse_effect_request(text: str) -> EffectRequest:
    """Read the machine effect block out of an Orchestrator turn. PURE and TOTAL.

    NO BLOCK -> ``STANDARD_EDIT`` with source NONE. That default is the routine relay act: the
    kernel is about to instruct an execution agent that can edit files, and the profile ceiling
    (``gate_start``) has already decided whether that is permitted at all. It is deliberately
    NOT ``READ_ONLY`` -- pretending an ordinary directive is read-only would make the ceiling
    check meaningless, since every unlabelled message would slip under it.

    An UNRECOGNISED class name is not ignored and is not mapped to something plausible. It comes
    back ``recognised=False`` and the caller holds: a policy engine that quietly discards a
    capability request it does not model is how "gpu_spend" gets approved by accident.
    """
    m = _EFFECT_BLOCK.search(str(text or ""))
    if not m:
        return EffectRequest(STANDARD_EDIT, "NONE")
    body = m.group("body") or ""
    f = _EFFECT_FIELD.search(body)
    if not f:
        return EffectRequest("", "DECLARED_BLOCK", raw=body.strip()[:400], recognised=False)
    value = (f.group("value") or "").strip().upper()
    if value not in EFFECT_CAPABILITIES:
        return EffectRequest(value, "DECLARED_BLOCK", raw=body.strip()[:400], recognised=False)
    return EffectRequest(value, "DECLARED_BLOCK", raw=body.strip()[:400])


def _require(profile: str, capabilities: Sequence[str], *, owner_grants: Sequence[Mapping],
             now: float, channel_state: str | None):
    return auth.require(profile, capabilities, owner_grants=owner_grants, now=now,
                        owner_channel_state=channel_state)


def gate_start(*, profile: str, execution_can_mutate: bool, owner_grants: Sequence[Mapping] = (),
               now: float = 0.0, channel_state: str | None = None) -> Gate:
    """The CEILING, evaluated once before any message moves.

    Binding an execution end that can change the repository to a profile that does not grant
    ``repo_write`` is refused HERE. Discovering it at exchange nine -- after the agent has
    already edited files -- would be a governance surface that reports a breach instead of
    preventing one.
    """
    needed = (auth.CAP_REPO_READ, auth.CAP_REPO_WRITE) if execution_can_mutate \
        else (auth.CAP_REPO_READ,)
    d = _require(profile, needed, owner_grants=owner_grants, now=now, channel_state=channel_state)
    if d.allowed:
        return Gate(True, STANDARD_EDIT if execution_can_mutate else READ_ONLY,
                    required=tuple(needed), decision={"decision": d.decision,
                                                      "granted": list(d.granted)})
    return Gate(False, STANDARD_EDIT if execution_can_mutate else READ_ONLY,
                hold=HOLD_PROFILE_CEILING,
                reason=("the selected execution end can change the repository, but profile %s "
                        "does not grant that. %s" % (profile, d.reason))
                if execution_can_mutate else d.reason,
                required=tuple(needed),
                decision={"decision": d.decision, "missing": list(d.missing),
                          "ungranted": list(d.ungranted)})


def gate_directive(text: str, *, profile: str, owner_grants: Sequence[Mapping] = (),
                   now: float = 0.0, channel_state: str | None = None) -> Gate:
    """Per-directive gate. The Orchestrator's text can only REQUEST; this decides."""
    req = parse_effect_request(text)
    if not req.recognised:
        return Gate(False, req.effect_class or "", hold=HOLD_UNKNOWN_EFFECT,
                    reason=("the orchestrator declared an effect class this build does not "
                            "model (%r); refusing rather than ignoring a capability request "
                            "nobody has modelled. Known classes: %s"
                            % (req.effect_class or req.raw, ", ".join(EFFECT_CLASSES))),
                    decision={"source": req.source, "raw": req.raw})
    d = _require(profile, req.capabilities, owner_grants=owner_grants, now=now,
                 channel_state=channel_state)
    if d.allowed:
        return Gate(True, req.effect_class, required=tuple(req.capabilities),
                    decision={"decision": d.decision, "source": req.source})
    return Gate(False, req.effect_class, hold=HOLD_OWNER_REQUIRED, reason=d.reason,
                required=tuple(req.capabilities),
                decision={"decision": d.decision, "missing": list(d.missing),
                          "ungranted": list(d.ungranted), "source": req.source})


#: What an observed repository change IMPLIES was performed. Ordered most severe first: a push
#: that also committed is reported as a push.
def observed_effect_class(before: Mapping, after: Mapping) -> str:
    """Which effect class the repository itself shows. PURE.

    Reads only fields both snapshots carry, and treats a MISSING measurement as unknown rather
    than as "no change": ``probe_ok=False`` on either side yields "" so a failed probe can never
    be mistaken for a clean repository.
    """
    b, a = dict(before or {}), dict(after or {})
    if not (b.get("probe_ok") and a.get("probe_ok")):
        return ""
    if str(b.get("upstream_head") or "") != str(a.get("upstream_head") or "") \
            and a.get("upstream_head"):
        return GIT_PUSH
    if str(b.get("head") or "") != str(a.get("head") or ""):
        return GIT_COMMIT
    if str(b.get("status_digest") or "") != str(a.get("status_digest") or "") \
            or str(b.get("diff_sha256") or "") != str(a.get("diff_sha256") or ""):
        return STANDARD_EDIT
    return READ_ONLY


def gate_observation(before: Mapping, after: Mapping, *, profile: str,
                     owner_grants: Sequence[Mapping] = (), now: float = 0.0,
                     channel_state: str | None = None) -> Gate:
    """THE GATE THAT STILL WORKS AGAINST AN UNCONFINED AGENT.

    It does not ask the agent what it did. It compares two independent readings of the
    repository and holds when the difference implies a capability the profile does not carry.
    An unproven confinement boundary does not make this check weaker -- it is exactly why the
    check exists.
    """
    cls = observed_effect_class(before, after)
    if not cls:
        # UNMEASURED IS NOT PERMITTED. ``observed_effect_class`` returns READ_ONLY for a turn
        # that changed nothing, so "" means only one thing: a probe failed and what the agent
        # did is unknown. Returning an ALLOWING gate here was the single place in this codebase
        # that read "could not ask" as "answered yes" -- while ``corroborate`` refuses an
        # unmeasured check and ``workspace.git`` refuses an unreadable worktree. An unconfined
        # agent could commit, delete or push through the blind spot with no gate at all.
        return Gate(False, "", hold=HOLD_OBSERVATION_UNMEASURABLE,
                    reason=("the repository could not be read on both sides of this turn, so "
                            "what the agent did is UNKNOWN. An unmeasured effect is not an "
                            "absent one, and this gate refuses rather than assuming."),
                    decision={"measured": False})
    caps = EFFECT_CAPABILITIES.get(cls, ())
    d = _require(profile, caps, owner_grants=owner_grants, now=now, channel_state=channel_state)
    if d.allowed:
        return Gate(True, cls, required=tuple(caps), decision={"measured": True})
    return Gate(False, cls, hold=HOLD_OBSERVED_UNGRANTED_EFFECT,
                reason=("the repository shows a %s that profile %s does not grant. This was "
                        "OBSERVED independently, not reported by the agent. %s"
                        % (cls, profile, d.reason)),
                required=tuple(caps),
                decision={"measured": True, "decision": d.decision,
                          "missing": list(d.missing), "ungranted": list(d.ungranted)})

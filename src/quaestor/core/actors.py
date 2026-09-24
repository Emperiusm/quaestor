"""actors -- who is speaking, and what that does NOT entitle them to.

THE ONE RULE THIS MODULE EXISTS TO ENFORCE
------------------------------------------
An actor's ROLE is a description of what it is for. It is not a grant. ``STRATEGIST`` does not
imply permission to dispatch; ``EXECUTOR`` does not imply permission to write; ``OWNER`` is the
only role that can be the *source* of a grant, and even then the grant is a separate durable
record, not an attribute of the speaker.

This is deliberately the opposite of the usual shape, where a message from a privileged sender is
treated as a privileged message. That shape fails the moment a sender can be forged, guessed, or
persuaded -- and a language model can be persuaded. So authority is looked up, never inferred:

    role      -> what this actor is FOR          (this module)
    authority -> what this actor may CAUSE       (``quaestor.core.authority`` + owner grants)

``authority_for`` is the seam, and it takes the role only to REFUSE faster. It never widens.

WHY A REVIEWER IS AN ACTOR AND NOT A FUNCTION
---------------------------------------------
Review must be attributable. "The reviewer said it was fine" is worth nothing unless the record
says which reviewer, under which authority, looking at what. Making reviewers first-class actors
means their findings carry the same provenance as an executor's result -- and it means an
adversarial reviewer can be given deliberately *less* authority than the thing it is reviewing,
which is the only way its independence is structural rather than promised.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from quaestor.core import authority as authority_mod
from typing import Mapping, Sequence

ACTOR_INSTRUMENT = "actors/1"

# ---------------------------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------------------------
#: Sets objectives and decides what happens next. Typically a strategic model or a human.
STRATEGIST = "STRATEGIST"
#: Performs bounded work inside a workspace under an explicit capability envelope.
EXECUTOR = "EXECUTOR"
#: Collects DETERMINISTIC evidence. Never forms an opinion; measures.
VERIFIER = "VERIFIER"
#: Judges a candidate result against the objective and the evidence.
REVIEWER = "REVIEWER"
#: Judges a candidate result by trying to BREAK it. Independent context, minimal authority.
ADVERSARIAL_REVIEWER = "ADVERSARIAL_REVIEWER"
#: The human. The only source of an owner grant, and the terminal escalation target.
OWNER = "OWNER"

ROLES = (STRATEGIST, EXECUTOR, VERIFIER, REVIEWER, ADVERSARIAL_REVIEWER, OWNER)

#: What each role is FOR. Documentation, not permission -- see the module docstring.
ROLE_PURPOSE: Mapping[str, str] = {
    STRATEGIST: "sets bounded objectives and decides the next action",
    EXECUTOR: "performs bounded work in a workspace under an explicit capability envelope",
    VERIFIER: "collects deterministic evidence; forms no opinion",
    REVIEWER: "judges a candidate result against objective and evidence",
    ADVERSARIAL_REVIEWER: "attempts to refute a candidate result from independent context",
    OWNER: "the human authority; the only source of an owner grant",
}

#: Roles that may never be granted a mutating capability by policy, whatever a grant says.
#: A reviewer that can edit the thing it reviews is not a reviewer, and an adversarial reviewer
#: that can edit it is an attacker with a job title. This is a CEILING, not a grant: being absent
#: from this set confers nothing.
READ_ONLY_ROLES = frozenset({VERIFIER, REVIEWER, ADVERSARIAL_REVIEWER})

#: Capabilities that reach OUTSIDE the artefact under review. A read-only role may hold none of
#: them. Deliberately wider than ``authority.MUTATING``: spending money and writing to an external
#: system are not repository mutations, and a ceiling that only knew about repository mutation let
#: a reviewer hold both.
#:
#: ``network_read`` is intentionally NOT here -- a reviewer that cannot read anything cannot
#: review, and a ceiling that refuses everything is indistinguishable from a broken one.
OUTWARD_CAPABILITIES = frozenset(authority_mod.MUTATING) | frozenset({
    authority_mod.CAP_EXTERNAL_WRITE,
    authority_mod.CAP_PAID_EXECUTION,
})


@dataclass(frozen=True)
class Actor:
    """An identified participant. Carries NO capability of its own."""

    actor_id: str
    role: str
    display_name: str = ""
    #: Free-form provider/transport detail -- e.g. which adapter produced it. Never trusted for
    #: an authority decision; it exists so a record can say where a message came from.
    provenance: Mapping = field(default_factory=dict)
    instrument: str = ACTOR_INSTRUMENT

    @property
    def valid(self) -> bool:
        return bool(self.actor_id) and self.role in ROLES

    @property
    def read_only_by_role(self) -> bool:
        return self.role in READ_ONLY_ROLES

    def to_dict(self) -> dict:
        return {"actor_id": self.actor_id, "role": self.role,
                "display_name": self.display_name, "provenance": dict(self.provenance),
                "read_only_by_role": self.read_only_by_role, "instrument": self.instrument}


def new_actor(role: str, *, display_name: str = "", provenance: Mapping | None = None,
              actor_id: str = "") -> Actor:
    """Mint an actor. PURE except for the id. Raises ValueError on an unknown role.

    An unknown role is refused rather than defaulted: defaulting would let a typo produce an
    actor whose ceiling checks silently do not apply.
    """
    if role not in ROLES:
        raise ValueError("unknown actor role %r; known roles are %s" % (role, list(ROLES)))
    return Actor(actor_id or ("actor_" + uuid.uuid4().hex[:16]), role,
                 display_name=display_name, provenance=dict(provenance or {}))


def authority_ceiling(actor: Actor, requested: Sequence[str]) -> tuple:
    """(allowed, refused_reason). PURE. NEVER widens what was requested.

    Applies the ROLE CEILING only. It can remove a capability; it can never add one, and it is not
    a substitute for the authority engine -- a capability that survives here still has to be
    granted there. Two independent gates, and this is the cheaper one.
    """
    from quaestor.core import authority as authority_mod

    caps = tuple(dict.fromkeys(str(c) for c in (requested or ())))
    if not actor.valid:
        return (), "actor is not valid (id=%r role=%r)" % (actor.actor_id, actor.role)
    if actor.read_only_by_role:
        # NOT just MUTATING. The first version refused only repository mutation, so an
        # ADVERSARIAL_REVIEWER could hold `external_write` or `paid_execution` -- capabilities
        # documented as leaving the workspace entirely. A reviewer that can spend money or write
        # to an external system is not read-only in any sense that matters; the ceiling has to
        # cover every capability that reaches OUTSIDE the thing under review, not only the ones
        # that edit it.
        outward = tuple(c for c in caps if c in OUTWARD_CAPABILITIES)
        if outward:
            return (), ("role %s may never hold a capability that reaches outside the artefact "
                        "under review; refused %s. A reviewer that can change the world it is "
                        "judging is not a reviewer." % (actor.role, list(outward)))
    return caps, ""

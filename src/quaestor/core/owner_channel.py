"""owner_channel -- the difference between a RECORDED CLAIM of approval and AUTHENTICATED AUTHORITY.

THE CORRECTION THIS MODULE MAKES TO P0/P1
------------------------------------------
P0 shipped an owner-grant ledger: a row in SQLite naming a capability, with an expiry and a
revocation column. The policy engine then treated a live row as the second lock on an owner-gated
capability. That was a reasonable first cut and it is WRONG as a security boundary, for a reason
worth stating plainly:

    the orchestrator writes that table.

So does anything that can reach the database file. A component cannot authenticate a decision by
writing down that the decision was made -- that is the shape of every self-licensing interlock
this project has had to kill (evidence manufactured by the party it exonerates). A boolean is not an
owner. A JSON file the orchestrator wrote is not an owner. A database row is not an owner.

WHAT IS KEPT, AND WHAT CHANGES
------------------------------
The ledger is KEPT -- it is a genuinely useful audit trail of *claimed* approvals, and P3+ will
want exactly that record once a real channel exists to corroborate it. What changes is its
STANDING: while ``owner_channel_state() == UNAVAILABLE``, no ledger row can make an owner-gated
capability usable. The capability resolves to OWNER_REQUIRED no matter what the table says, and
``test_p25_controls`` mutation-proves it by forging a row directly in SQLite.

WHAT MAKES THE CHANNEL REAL NOW
-------------------------------
It is real, and it is LOCAL. ``quaestor.attestation`` holds an HMAC key that is DPAPI-protected
to the human user and can only be CREATED from an interactive terminal (``quaestor owner init``).
Executors have no path to it; remote strategists have no filesystem at all; so a signed decision
is one the model cannot produce and a confined child cannot forge.

The honest boundary, stated rather than implied: this is the LOCAL_SINGLE_OWNER deployment class.
DPAPI protects to the OS user, and this process runs as that user, so "owner" means "the human
who can act as this OS user". That defends against category confusion -- a model or executor
occupying the place of owner authority -- not against a hostile process already running as the
user. See docs/THREAT-MODEL.md. Multi-user deployments need an out-of-band channel; nothing here
pretends otherwise.

PURE module with ONE impure seam: ``owner_channel_state`` consults the attestation store's
PRESENCE. With no provisioning -- the default everywhere, including every test fixture -- it is
exactly as unavailable as it has always been.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

CHANNEL_INSTRUMENT = "owner_channel/1"

UNAVAILABLE = "UNAVAILABLE"
AUTHENTICATED = "AUTHENTICATED"


def owner_channel_state(directory: str | None = None) -> str:
    """The live owner-channel state. Impure ONLY in reading attestation presence.

    AUTHENTICATED requires a usable DPAPI-protected attestation key provisioned interactively by
    the owner (``quaestor owner init``). Absent, corrupt or foreign key -> UNAVAILABLE: the
    failure direction is away from authority, never toward it. There is deliberately no setter,
    no environment override and no configuration file that flips this state directly -- those
    would be ways for the orchestrator to grant itself authority, which is the exact property
    this module exists to deny.
    """
    try:
        from quaestor import attestation
        return AUTHENTICATED if attestation.present(directory) else UNAVAILABLE
    except Exception:  # noqa: BLE001 - fail CLOSED: any doubt is UNAVAILABLE
        return UNAVAILABLE


@dataclass(frozen=True)
class OwnerDecision:
    """Why an owner-gated capability is or is not usable."""

    usable: bool
    channel_state: str
    reason: str
    capability: str = ""
    recorded_claims: tuple = ()

    def to_dict(self) -> dict:
        return {"usable": self.usable, "channel_state": self.channel_state,
                "reason": self.reason, "capability": self.capability,
                "recorded_claims": list(self.recorded_claims),
                "instrument": CHANNEL_INSTRUMENT}


def is_live(row: Mapping, now: float = 0.0) -> bool:
    """Is this grant row still a decision? PURE.

    REVOKED IS NOT A DECISION, and neither is EXPIRED. ``expires_at`` was written by
    ``quaestor grant --expires`` from the beginning and consulted nowhere, so an owner who
    deliberately time-boxed a capability got a permanent one. A grant that has run out is
    exactly the "stale grant" an authority model must not let discharge anything.

    ``now`` of 0 means the caller did not say what time it is, and an expiry cannot be judged
    without one; the row is then treated as live, which is the behaviour every caller had
    before. The production path (``core.authority.require``) always passes a real clock.
    """
    if row.get("revoked_at") is not None:
        return False
    expires = row.get("expires_at")
    if expires is None or not now:
        return True
    try:
        return float(expires) > float(now)
    except (TypeError, ValueError):
        return False          # an unreadable expiry is not a live grant


def evaluate(capability: str, *, ledger_rows: Sequence[Mapping] = (),
             channel_state: str | None = None, now: float = 0.0) -> OwnerDecision:
    """Can this owner-gated capability be used right now? PURE.

    The ledger rows are read and REPORTED -- an operator should see that someone recorded an
    approval -- but they never change the verdict while the channel is unavailable.
    """
    state = channel_state or owner_channel_state()
    claims = tuple(sorted({str(r.get("grant_id") or "") for r in (ledger_rows or ())
                           if str(r.get("capability") or "") == str(capability)
                           and is_live(r, now)} - {""}))
    if state != AUTHENTICATED:
        return OwnerDecision(
            False, state,
            ("owner-gated capability %r cannot be activated: the owner channel is %s. %d recorded "
             "ledger claim(s) were found and are NOT authority -- the orchestrator writes that "
             "table, so a row in it is a record that someone said yes, not a verified decision "
             "by the owner." % (capability, state, len(claims))),
            str(capability), claims)
    return OwnerDecision(bool(claims), state,
                         "authenticated owner channel confirmed the capability"
                         if claims else "no owner decision exists for this capability",
                         str(capability), claims)


def gate(required: Sequence[str], owner_gated: Sequence[str], *,
         ledger_rows: Sequence[Mapping] = (),
         channel_state: str | None = None, now: float = 0.0) -> tuple:
    """(blocked_capabilities, decisions). PURE.

    Returns every owner-gated capability in ``required`` that cannot be used. Callers turn a
    non-empty result into OWNER_REQUIRED.
    """
    gated = {str(c) for c in (owner_gated or ())}
    decisions, blocked = {}, []
    for cap in sorted({str(c) for c in (required or ())} & gated):
        d = evaluate(cap, ledger_rows=ledger_rows, channel_state=channel_state, now=now)
        decisions[cap] = d
        if not d.usable:
            blocked.append(cap)
    return tuple(blocked), decisions

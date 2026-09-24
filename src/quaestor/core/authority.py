"""authority -- capability policy that exists in MACHINE STATE, not only in prose.

THE PROPERTY THIS FILE BUYS
---------------------------
A prompt that says "do not launch r6" is useful. It is not a boundary. A boundary is a thing
Claude cannot cross by ignoring a sentence, because the capability was never in the envelope.

So authority is modelled twice, and both locks must open:

  1. THE PROFILE GRANT -- a named profile grants a set of capabilities. A capability the profile
     does not grant is simply absent, and requesting it yields OWNER_REQUIRED.
  2. THE OWNER GATE    -- a capability in OWNER_GATED is never granted by a profile ALONE. It
     additionally requires a live, unexpired, unrevoked owner grant recorded in the durable
     store. So a dispatch cannot escalate itself into paid or destructive territory by naming a
     bigger profile, which is the whole point: the escalation path runs through the owner, not
     through the request.

The asymmetry is deliberate and is the same shape as the source deployment: there is no
branch that returns ALLOW for a gated capability without BOTH a grant and a profile. Every other
state falls through to refusal.

PURE module. The store supplies grants; nothing here reads a clock or a database.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

# ---------------------------------------------------------------------------------------------
# CAPABILITIES -- the atoms. Profiles are named sets of these.
# ---------------------------------------------------------------------------------------------
CAP_REPO_READ = "repo_read"
CAP_REPO_WRITE = "repo_write"
CAP_GIT_COMMIT = "git_commit"
CAP_GIT_PUSH = "git_push"
CAP_NETWORK_READ = "network_read"
CAP_EXTERNAL_WRITE = "external_write"
CAP_PAID_EXECUTION = "paid_execution"
CAP_DESTRUCTIVE = "destructive"

ALL_CAPABILITIES = (CAP_REPO_READ, CAP_REPO_WRITE, CAP_GIT_COMMIT, CAP_GIT_PUSH,
                    CAP_NETWORK_READ, CAP_EXTERNAL_WRITE, CAP_PAID_EXECUTION, CAP_DESTRUCTIVE)

#: Capabilities whose side effects LEAVE THE MACHINE or cannot be undone. A profile naming one of
#: these is necessary but never sufficient -- see require().
OWNER_GATED = frozenset({CAP_GIT_PUSH, CAP_EXTERNAL_WRITE, CAP_PAID_EXECUTION, CAP_DESTRUCTIVE})

#: Capabilities that can change the repository under the lease. A run holding any of these is a
#: WRITE EXECUTION, which is what makes an interrupted run AMBIGUOUS rather than merely stopped.
MUTATING = frozenset({CAP_REPO_WRITE, CAP_GIT_COMMIT, CAP_GIT_PUSH, CAP_DESTRUCTIVE})

# ---------------------------------------------------------------------------------------------
# PROFILES
# ---------------------------------------------------------------------------------------------
READ_ONLY = "READ_ONLY"
STANDARD_EDIT = "STANDARD_EDIT"
#: Same capability set as STANDARD_EDIT, but the NAME carries a precondition: this profile may
#: only be executed inside a validated container confinement boundary. ``cli_executor`` refuses
#: to build a command for it otherwise, so "run an edit-capable child natively on Windows" is a
#: refusal rather than a decision anyone can make by omission.
STANDARD_EDIT_CONFINED = "STANDARD_EDIT_CONFINED"
GIT_COMMIT = "GIT_COMMIT"
GIT_PUSH = "GIT_PUSH"
NETWORK_READ = "NETWORK_READ"
EXTERNAL_WRITE = "EXTERNAL_WRITE"
PAID_EXECUTION = "PAID_EXECUTION"
DESTRUCTIVE = "DESTRUCTIVE"

PROFILES: Mapping[str, frozenset] = {
    READ_ONLY: frozenset({CAP_REPO_READ}),
    STANDARD_EDIT: frozenset({CAP_REPO_READ, CAP_REPO_WRITE}),
    STANDARD_EDIT_CONFINED: frozenset({CAP_REPO_READ, CAP_REPO_WRITE}),
    GIT_COMMIT: frozenset({CAP_REPO_READ, CAP_REPO_WRITE, CAP_GIT_COMMIT}),
    GIT_PUSH: frozenset({CAP_REPO_READ, CAP_REPO_WRITE, CAP_GIT_COMMIT, CAP_GIT_PUSH}),
    NETWORK_READ: frozenset({CAP_REPO_READ, CAP_NETWORK_READ}),
    EXTERNAL_WRITE: frozenset({CAP_REPO_READ, CAP_NETWORK_READ, CAP_EXTERNAL_WRITE}),
    PAID_EXECUTION: frozenset({CAP_REPO_READ, CAP_NETWORK_READ, CAP_PAID_EXECUTION}),
    DESTRUCTIVE: frozenset({CAP_REPO_READ, CAP_REPO_WRITE, CAP_DESTRUCTIVE}),
}

# THE CREDENTIAL-EXEMPTION CEILING MOVED, AND GOT STRONGER.
#
# This used to be `EXEMPTIBLE_PROVIDER_ENV = frozenset({"CLAUDE_CODE_OAUTH_TOKEN"})`,
# with a control asserting that ANTHROPIC_API_KEY was not in it. That protects exactly
# two strings. A second provider adding OPENAI_API_KEY inherits none of it, silently,
# because nothing in the mechanism understood WHY the name was forbidden.
#
# `core.credential_policy.forbids_exemption` now refuses any variable whose name carries
# an API-credential or endpoint-override SHAPE, for every provider, and
# `ProviderCredentialPolicy` validates at construction -- so a policy that would breach
# the ceiling cannot be built, let alone reached at dispatch time. The vendor's own
# exemptible set lives with the vendor, in `executors/claude_auth.py`.

# Decisions
ALLOW = "ALLOW"
OWNER_REQUIRED = "OWNER_REQUIRED"
AUTHORITY_REFUSED = "AUTHORITY_REFUSED"


@dataclass(frozen=True)
class AuthorityDecision:
    """``decision`` in (ALLOW|OWNER_REQUIRED|AUTHORITY_REFUSED); ``missing``/``ungranted`` name
    exactly which capabilities caused it, so a refusal is actionable rather than a mood."""

    decision: str
    profile: str
    granted: tuple = ()
    required: tuple = ()
    missing: tuple = ()        # required but the PROFILE does not grant it
    ungranted: tuple = ()      # profile grants it, but no live OWNER grant exists
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


def granted_capabilities(profile: str) -> frozenset:
    """What this profile grants. An UNKNOWN profile grants NOTHING. PURE.

    Fail-closed on the unknown name rather than raising: a typo'd profile must refuse the run,
    not crash the admission path. A crash is not a refusal -- it is an absent verdict, and an
    absent verdict is how a caller ends up retrying into the gap.
    """
    return PROFILES.get(str(profile), frozenset())


def is_write_profile(profile: str, extra: Iterable[str] = ()) -> bool:
    """Does this envelope permit mutating the repository? PURE."""
    caps = set(granted_capabilities(profile)) | {str(c) for c in (extra or ())}
    return bool(caps & MUTATING)


def live_grant_capabilities(grants: Sequence[Mapping], *, now: float) -> frozenset:
    """Capabilities covered by an owner grant that is live at ``now``. PURE.

    A grant is live only when it is not revoked and not expired. ``expires_at`` of None means
    "no expiry", which is a real answer; a MISSING grant is not an expired grant and neither is
    an unreadable one -- callers pass what they read, and what they did not read is simply not
    in the list. ("absent is not zero".)
    """
    live = set()
    for g in grants or ():
        if g.get("revoked_at") is not None:
            continue
        exp = g.get("expires_at")
        if exp is not None and float(exp) <= float(now):
            continue
        cap = str(g.get("capability") or "")
        if cap:
            live.add(cap)
    return frozenset(live)


def require(profile: str, required: Iterable[str], *,
            owner_grants: Sequence[Mapping] = (), now: float = 0.0,
            owner_channel_state: str | None = None) -> AuthorityDecision:
    """THE decision. PURE -- every input injected, no clock read here.

    Order matters and is chosen so the message names the FIRST wall you hit:

      1. an unknown capability name          -> AUTHORITY_REFUSED (never silently ignored)
      2. a capability the profile lacks      -> OWNER_REQUIRED    (escalation needs the owner)
      3. an OWNER_GATED capability           -> OWNER_REQUIRED unless an AUTHENTICATED owner
                                                channel says otherwise (the second lock)
      4. otherwise                           -> ALLOW

    Step 1 is not pedantry. Silently ignoring an unrecognised capability means a future caller
    can request ``"gpu_spend"``, get ALLOW because nothing matched it, and believe the policy
    engine approved something it never modelled.

    STEP 3 WAS TIGHTENED IN P2.5. It used to accept a live row in the orchestrator's own
    ``owner_grant`` table as the second lock. That is not authority: the orchestrator writes
    that table, so the grant was evidence manufactured by the party it exonerated. The ledger is
    still read and still reported -- an operator should see that an approval was recorded -- but
    while ``owner_channel.owner_channel_state()`` is UNAVAILABLE, no row can unlock an
    owner-gated capability. See ``orchestrator/owner_channel.py``.
    """
    prof = str(profile)
    req = tuple(sorted({str(c) for c in (required or ())}))
    grants = granted_capabilities(prof)

    unknown = tuple(c for c in req if c not in ALL_CAPABILITIES)
    if unknown:
        return AuthorityDecision(
            AUTHORITY_REFUSED, prof, tuple(sorted(grants)), req, missing=unknown,
            reason=("unknown capability requested: %s -- this policy engine refuses rather than "
                    "ignoring a capability it does not model" % ", ".join(unknown)))

    if prof not in PROFILES:
        return AuthorityDecision(
            AUTHORITY_REFUSED, prof, (), req, missing=req,
            reason="unknown authority profile %r grants nothing" % prof)

    missing = tuple(c for c in req if c not in grants)
    if missing:
        return AuthorityDecision(
            OWNER_REQUIRED, prof, tuple(sorted(grants)), req, missing=missing,
            reason=("profile %s does not grant: %s. Capability expansion is an OWNER decision; "
                    "the dispatch cannot widen its own envelope." % (prof, ", ".join(missing))))

    from quaestor.core import owner_channel as _oc
    # ``now`` reaches the owner gate so an EXPIRED grant stops counting. It was accepted here
    # and dropped on the floor, which made --expires decorative.
    blocked, decisions = _oc.gate(req, OWNER_GATED, ledger_rows=owner_grants,
                                  channel_state=owner_channel_state, now=now)
    if blocked:
        first = decisions[blocked[0]]
        return AuthorityDecision(
            OWNER_REQUIRED, prof, tuple(sorted(grants)), req, ungranted=tuple(blocked),
            reason=("owner-gated capability not usable: %s. %s"
                    % (", ".join(blocked), first.reason)))

    return AuthorityDecision(ALLOW, prof, tuple(sorted(grants)), req)

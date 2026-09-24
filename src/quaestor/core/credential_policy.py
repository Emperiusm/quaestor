"""credential_policy -- the PROVIDER-NEUTRAL billing/auth preflight.

WHY THIS MODULE EXISTS
----------------------
Adversarial review of the extraction produced a finding worth quoting, because it was the one
claim in the extraction's own documentation that was simply false:

    "Claude/Anthropic-specific policy, defaults, state names and process execution live in
     core/, not in adapters -- and no control tests the claim."

It was correct. ``core/preflight.py`` hard-coded nine Anthropic environment variables, parsed one
vendor's ``auth status`` JSON, and shelled out to a binary named ``claude`` -- from the layer that
is supposed to know no provider at all. The dispatch path then reached that vendor code by
DEFAULT, so a deployment with a different executor got Anthropic's credential policy whether it
wanted one or not.

THE SPLIT
---------
This module keeps what is genuinely platform policy:

  * the QUESTION -- "would this run execute on a billing or auth path the owner did not
    authorise?" -- and the vocabulary for answering it;
  * the RULE that a credential provider may not inject an API key past the override check;
  * the record shape, which never contains a credential value.

A ``ProviderCredentialPolicy`` supplies the provider-specific half: which variables redirect
billing, which single variable a broker may legitimately inject, how to read one vendor's auth
status. ``executors/claude_auth.py`` is the first instance of one. There is nothing in this file
that names a vendor.

THE EXEMPTION CEILING IS A SHAPE RULE, NOT A LIST
-------------------------------------------------
The old design protected "``ANTHROPIC_API_KEY`` can never be exempted" with a frozenset and a test
asserting the frozenset's contents. That protects one string. A second provider adds
``OPENAI_API_KEY`` and the protection does not extend to it, silently, because nothing in the
mechanism understood WHY the name was forbidden.

So the ceiling is now structural: a policy may not exempt a variable whose name carries an
API-credential or endpoint-override shape, whoever wrote the policy and whatever provider it is
for. ``CLAUDE_CODE_OAUTH_TOKEN`` survives because ``OAUTH`` is a distinct name part from ``AUTH``
-- the rule matches adjacent underscore-separated parts, not substrings, precisely so that the
brokered automation credential stays legal while ``ANTHROPIC_AUTH_TOKEN`` does not.

Policies validate at CONSTRUCTION. A policy that violates the ceiling cannot be built, so it
cannot be reached at dispatch time by any path.

PURE. The I/O lives with the provider.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

CREDENTIAL_POLICY_INSTRUMENT = "credential_policy/1"

# Auth classifications. These name BILLING PATHS, which every commercial model provider has;
# they are not one vendor's vocabulary.
SUBSCRIPTION = "subscription"
API_CONSOLE = "api_console"
THIRD_PARTY = "third_party"
UNVERIFIED = "UNVERIFIED"
LOGGED_OUT = "logged_out"

# Decisions
ACCEPT = "ACCEPT"
REFUSE = "REFUSE"

# Named refusal reasons
REASON_OVERRIDE = "CREDENTIAL_OVERRIDE_PRESENT"
REASON_NOT_LOGGED_IN = "NOT_LOGGED_IN"
REASON_API_BILLED = "API_BILLED_AUTH"
REASON_THIRD_PARTY = "THIRD_PARTY_PROVIDER"
REASON_UNVERIFIED = "AUTH_CLASS_UNVERIFIED"
REASON_STATUS_UNREADABLE = "AUTH_STATUS_UNREADABLE"
REASON_NO_POLICY = "NO_CREDENTIAL_POLICY_CONFIGURED"

#: Adjacent underscore-separated name parts that mark a variable as an API credential or an
#: endpoint override. A variable whose name contains one of these SEQUENCES may never be exempted
#: from the override check by any provider policy.
#:
#: Matched on PARTS, never on substrings: ``CLAUDE_CODE_OAUTH_TOKEN`` splits to
#: (CLAUDE, CODE, OAUTH, TOKEN) and contains no ``(AUTH, TOKEN)`` pair, while
#: ``ANTHROPIC_AUTH_TOKEN`` splits to (ANTHROPIC, AUTH, TOKEN) and does. A substring rule would
#: forbid both and make the brokered automation credential unusable -- which is how a safety rule
#: gets switched off.
FORBIDDEN_EXEMPTION_SHAPES = (
    ("API", "KEY"),
    ("AUTH", "TOKEN"),
    ("SECRET", "KEY"),
    ("ACCESS", "KEY"),
    ("BASE", "URL"),
    ("API", "URL"),
    ("BEARER", "TOKEN"),
)


def forbids_exemption(name: str) -> str:
    """"" if the name may be exempted, else the shape that forbids it. PURE. NEVER raises."""
    parts = [p for p in str(name).upper().split("_") if p]
    for shape in FORBIDDEN_EXEMPTION_SHAPES:
        n = len(shape)
        for i in range(len(parts) - n + 1):
            if tuple(parts[i:i + n]) == shape:
                return "_".join(shape)
    return ""


class PolicyError(ValueError):
    """A credential policy that would breach the platform's exemption ceiling."""


@dataclass(frozen=True)
class ProviderCredentialPolicy:
    """One provider's credential rules, validated against the platform ceiling at construction.

    ``classifier`` maps a parsed auth status to ``(auth_class, detail)``. It is the only place a
    vendor's status format is understood, and it must fail CLOSED -- anything it does not
    positively recognise as first-party subscription auth is ``UNVERIFIED``, and ``UNVERIFIED``
    refuses.
    """

    provider: str
    override_env: tuple
    exemptible_env: frozenset = frozenset()
    classifier: Callable[[Mapping | None], tuple] | None = None
    redact_allowlist: tuple = ()

    def __post_init__(self):
        if not str(self.provider).strip():
            raise PolicyError("a credential policy must name its provider")
        if not self.override_env:
            raise PolicyError(
                "%s declares no override variables. A policy that forbids nothing is not a "
                "policy, and defaulting to 'nothing redirects billing' is exactly the silent "
                "degradation this gate exists to prevent." % self.provider)
        for name in sorted(self.exemptible_env):
            shape = forbids_exemption(name)
            if shape:
                raise PolicyError(
                    "%s tries to exempt %s, whose name carries the %s shape. A credential "
                    "provider may hand the child a brokered automation token; it may never hand "
                    "it an API key or an endpoint override, because that changes the billing "
                    "path under the name of 'providing a credential'."
                    % (self.provider, name, shape))
            if name not in self.override_env:
                raise PolicyError(
                    "%s exempts %s, which is not one of its override variables -- the exemption "
                    "would be a no-op and reads as protection that is not there"
                    % (self.provider, name))

    def to_dict(self) -> dict:
        return {"provider": self.provider, "override_env": list(self.override_env),
                "exemptible_env": sorted(self.exemptible_env),
                "redact_allowlist": list(self.redact_allowlist),
                "instrument": CREDENTIAL_POLICY_INSTRUMENT}


@dataclass(frozen=True)
class PreflightDecision:
    decision: str
    reason: str = ""
    detail: str = ""
    auth_class: str = UNVERIFIED
    offending_vars: tuple = ()
    record: Mapping = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.decision == ACCEPT


def env_overrides_present(env: Mapping[str, str], policy: ProviderCredentialPolicy,
                          provider_injected: Sequence[str] = ()) -> tuple:
    """Which override variables are SET and NOT deliberately injected? PURE.

    ``provider_injected`` names variables a credential broker supplied on purpose. Only names in
    ``policy.exemptible_env`` can ever be exempted, and the policy could not have been constructed
    with an API-key-shaped name in that set -- so "the provider injected it" can never become a
    route to API billing. Values are never read and never returned.
    """
    exempt = {str(n) for n in (provider_injected or ())} & set(policy.exemptible_env)
    return tuple(n for n in policy.override_env if env.get(n) is not None and n not in exempt)


def env_presence_record(env: Mapping[str, str], names: Sequence[str]) -> dict:
    """A persistable record of the credential environment: names, presence, LENGTH ONLY. PURE.

    Length is recorded because "set to the empty string" and "set to a real key" are different
    operator intents and both are worth having in the audit trail. The value never is.
    """
    out = {}
    for n in names:
        v = env.get(n)
        out[n] = {"present": v is not None, "length": (len(v) if v is not None else 0)}
    return out


def redact_auth(status: Mapping | None, allowlist: Sequence[str]) -> dict:
    """The ONLY fields of a provider's auth status that may be persisted. PURE.

    Allowlist, not denylist. A denylist silently admits every field a future CLI version adds --
    and the fields a future version adds are exactly the ones nobody has decided are safe yet.
    Identity fields (email, org) are classification-irrelevant and are dropped here.
    """
    if not isinstance(status, Mapping):
        return {}
    return {k: status.get(k) for k in allowlist if k in status}


def decide(*, policy: ProviderCredentialPolicy | None, env: Mapping[str, str],
           auth_status: Mapping | None, requires_write: bool = False,
           provider_injected: Sequence[str] = ()) -> PreflightDecision:
    """THE preflight decision. PURE -- policy, env and status are injected. NEVER raises.

    A MISSING POLICY REFUSES. It does not fall back to a shipped provider: that fallback is how
    the platform came to apply one vendor's credential rules to every deployment.

    Override variables are checked FIRST and refuse unconditionally, including for read-only runs.
    The reason is that the variable's effect is on BILLING and AUTH, not on what the child is
    permitted to touch -- a read-only run that quietly bills an API has still violated the owner's
    requirement.

    ``requires_write`` only widens the refusal: UNVERIFIED is fatal for a write run and fatal for
    a read run too in this version. The parameter is kept because the two are different policies
    and a future relaxation must be an explicit edit here, not an accident.
    """
    if policy is None:
        return PreflightDecision(
            REFUSE, REASON_NO_POLICY,
            "no provider credential policy was supplied, so this control plane cannot tell which "
            "environment variables would redirect the run onto an unauthorised billing path. "
            "Refusing is the only honest answer; guessing a provider's rules is not.",
            UNVERIFIED, (), {})

    record = {"env": env_presence_record(env, policy.override_env),
              "auth": redact_auth(auth_status, policy.redact_allowlist),
              "provider": policy.provider}

    offenders = env_overrides_present(env, policy, provider_injected=provider_injected)
    record["provider_injected"] = sorted({str(n) for n in (provider_injected or ())})
    if offenders:
        return PreflightDecision(
            REFUSE, REASON_OVERRIDE,
            ("credential/provider override present in the environment: %s. Refusing to launch a "
             "non-interactive child: these take precedence over subscription auth, so the run "
             "would execute on a billing/auth path the owner did not authorise. This control "
             "plane does NOT unset them -- unset them yourself, in the shell that set them, or "
             "grant an explicit exception." % ", ".join(offenders)),
            UNVERIFIED, offenders, record)

    classify = policy.classifier
    if classify is None:
        return PreflightDecision(
            REFUSE, REASON_UNVERIFIED,
            "%s supplies no auth classifier, so the billing path cannot be established"
            % policy.provider, UNVERIFIED, (), record)
    auth_class, detail = classify(auth_status)
    record["auth_class"] = auth_class

    if auth_class == SUBSCRIPTION:
        return PreflightDecision(ACCEPT, "", detail, auth_class, (), record)
    if auth_class == LOGGED_OUT:
        return PreflightDecision(REFUSE, REASON_NOT_LOGGED_IN, detail, auth_class, (), record)
    if auth_class == API_CONSOLE:
        return PreflightDecision(REFUSE, REASON_API_BILLED, detail, auth_class, (), record)
    if auth_class == THIRD_PARTY:
        return PreflightDecision(REFUSE, REASON_THIRD_PARTY, detail, auth_class, (), record)
    return PreflightDecision(
        REFUSE, REASON_UNVERIFIED,
        ("%s -- the installed provider's auth status does not let this control plane distinguish "
         "subscription-backed login from API-billed authentication. That is an instrument "
         "limitation and it is recorded as one; it is not a guess and it is not a pass." % detail),
        UNVERIFIED, (), record)

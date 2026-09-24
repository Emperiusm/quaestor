"""claude_auth -- the Anthropic/Claude Code instance of the platform credential policy.

Everything a vendor-specific credential rule needs lives here, in the EXECUTORS layer, where a
provider belongs. ``core.credential_policy`` holds the question and the ceiling; this file holds
one provider's answer, and swapping providers means adding a sibling to this file rather than
editing core.

THE OWNER'S REQUIREMENT
-----------------------
Subscription-backed Claude Code. NOT accidental Anthropic API billing, and NOT a cloud-provider
route. Anthropic's credential precedence puts provider routing and environment credentials AHEAD
of subscription OAuth, and in non-interactive ``-p`` mode ``ANTHROPIC_API_KEY`` is used whenever
it is present. So the environment decides the billing path, silently, and the only safe place to
notice is before the process starts.

TWO RULES, BOTH LOAD-BEARING
----------------------------
 1. **REFUSE AND NAME THE CONDITION. NEVER SILENTLY UNSET.** Unsetting a variable the operator
    deliberately exported makes this control plane the thing that lies about the billing path. A
    refusal is recoverable in one sentence; a silent mutation is not discoverable at all.
 2. **NEVER PERSIST A CREDENTIAL VALUE.** Presence and length are the only facts recorded about
    an override variable, and the redaction allowlist keeps identity fields out of the ledger.

WHEN THE INSTRUMENT CANNOT TELL
-------------------------------
If ``claude auth status`` cannot distinguish subscription-backed login from API-billed Console
auth, the classification is ``UNVERIFIED`` and automation is REFUSED. That is an honest instrument
limitation, not a guess. (Measured on this box, CLI 2.1.185: ``auth status`` emits JSON carrying
``loggedIn``/``authMethod``/``apiProvider``/``subscriptionType``, which IS sufficient -- but the
refusal path stays, because the field set is a property of the installed version and versions
move.)
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Mapping

from quaestor.core import credential_policy as cp
from quaestor.core.credential_policy import (  # re-exported: the vocabulary is the platform's
    ACCEPT, API_CONSOLE, LOGGED_OUT, PreflightDecision, REASON_API_BILLED, REASON_NOT_LOGGED_IN,
    REASON_OVERRIDE, REASON_STATUS_UNREADABLE, REASON_THIRD_PARTY, REASON_UNVERIFIED, REFUSE,
    SUBSCRIPTION, THIRD_PARTY, UNVERIFIED)

#: Environment variables that redirect Claude Code off subscription auth or onto another billing
#: path. Presence alone is a refusal -- we do not inspect the value, because the value is a
#: credential and because "present but empty" is itself an operator statement we should not
#: second-guess.
OVERRIDE_VARS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
)

#: The only fields of ``claude auth status`` that may be persisted. ``email``, ``orgId`` and
#: ``orgName`` are identity, not classification, and are dropped.
AUTH_STATUS_ALLOWLIST = ("loggedIn", "authMethod", "apiProvider", "subscriptionType")

#: The platform vocabulary this module republishes, so a provider caller imports ONE module.
#: Declared rather than implied: an unreferenced import is normally a defect, and the way to say
#: "this one is a public re-export" is to say it.
__all__ = [
    "ACCEPT", "API_CONSOLE", "AUTH_STATUS_ALLOWLIST", "CLAUDE_POLICY", "LOGGED_OUT",
    "OVERRIDE_VARS", "PreflightDecision", "REASON_API_BILLED", "REASON_NOT_LOGGED_IN",
    "REASON_OVERRIDE", "REASON_STATUS_UNREADABLE", "REASON_THIRD_PARTY", "REASON_UNVERIFIED",
    "REFUSE", "SUBSCRIPTION", "THIRD_PARTY", "UNVERIFIED", "claude_version", "classify_auth",
    "decide", "env_overrides_present", "env_presence_record", "read_auth_status", "redact_auth",
    "run_preflight",
]


def classify_auth(status: Mapping | None) -> tuple:
    """(auth_class, detail) from a parsed ``claude auth status``. PURE. NEVER raises.

    Conservative by construction: anything this function does not positively recognise as
    first-party subscription auth is UNVERIFIED, and UNVERIFIED refuses. A new CLI version that
    renames a field therefore fails CLOSED rather than being read optimistically.
    """
    if not isinstance(status, Mapping) or not status:
        return UNVERIFIED, "auth status was absent or unparseable"

    logged_in = status.get("loggedIn")
    if logged_in is not True:
        return LOGGED_OUT, "claude auth status reports loggedIn=%r" % (logged_in,)

    provider = str(status.get("apiProvider") or "").strip()
    method = str(status.get("authMethod") or "").strip()
    sub = str(status.get("subscriptionType") or "").strip()

    if provider and provider != "firstParty":
        return THIRD_PARTY, "apiProvider=%r routes to a non-first-party billing path" % provider
    if method in ("oauth_token", "oauthToken"):
        # THE BROKERED AUTOMATION CREDENTIAL. MEASURED, not assumed: CLI 2.1.185 authenticated
        # from CLAUDE_CODE_OAUTH_TOKEN reports exactly three fields --
        # {apiProvider: firstParty, authMethod: oauth_token, loggedIn: true} -- and emits NO
        # subscriptionType for token auth at all. Requiring one here would make this branch
        # permanently unsatisfiable for the one credential class the broker exists to supply.
        #
        # This is NOT a relaxation of what the gate protects. The gate exists to refuse API-key
        # billing and non-first-party routing, and BOTH are positively excluded by this record:
        # an API key reports console/apiKey, and Bedrock/Vertex/Foundry report a non-firstParty
        # provider. So the condition here is STRICTER than the claude.ai branch below, which
        # tolerates an absent provider: firstParty must be stated EXPLICITLY.
        #
        # HONEST RESIDUE: subscription TIER is inferred from method+provider, not observed --
        # this CLI version does not report it for token auth. If a future version starts
        # emitting subscriptionType, prefer it over this inference.
        if provider == "firstParty":
            return SUBSCRIPTION, ("authMethod=%s apiProvider=firstParty (brokered OAuth "
                                  "automation token; no subscriptionType is reported for token "
                                  "auth by this CLI)" % method)
        return UNVERIFIED, ("authMethod=%r without an explicit apiProvider=firstParty: "
                            "non-first-party routing cannot be excluded" % method)
    if method in ("claude.ai", "claudeai", "oauth"):
        if not sub:
            # Logged in through claude.ai but with no subscription named: that is not proof of
            # API billing, and it is not proof of a subscription either. Unverified.
            return UNVERIFIED, "authMethod=%r but no subscriptionType was reported" % method
        return SUBSCRIPTION, "authMethod=%s subscriptionType=%s" % (method, sub)
    if method in ("console", "apiKey", "api_key", "anthropic"):
        return API_CONSOLE, "authMethod=%r is Console/API-key authentication" % method
    return UNVERIFIED, ("authMethod=%r is not a classification this version recognises" % method)


#: The shipped policy. Construction VALIDATES it against the platform ceiling in
#: ``core.credential_policy``: ``CLAUDE_CODE_OAUTH_TOKEN`` is exemptible because a broker is meant
#: to inject it, and no API-key-shaped name could be added here without the import failing.
CLAUDE_POLICY = cp.ProviderCredentialPolicy(
    provider="anthropic/claude-code",
    override_env=OVERRIDE_VARS,
    exemptible_env=frozenset({"CLAUDE_CODE_OAUTH_TOKEN"}),
    classifier=classify_auth,
    redact_allowlist=AUTH_STATUS_ALLOWLIST,
)


def decide(*, env: Mapping[str, str], auth_status: Mapping | None,
           requires_write: bool = False, provider_injected=()) -> PreflightDecision:
    """``credential_policy.decide`` bound to this provider. PURE."""
    return cp.decide(policy=CLAUDE_POLICY, env=env, auth_status=auth_status,
                     requires_write=requires_write, provider_injected=provider_injected)


def env_overrides_present(env: Mapping[str, str], provider_injected=()) -> tuple:
    """This provider's override check. PURE."""
    return cp.env_overrides_present(env, CLAUDE_POLICY, provider_injected=provider_injected)


def env_presence_record(env: Mapping[str, str], names=None) -> dict:
    """Presence and LENGTH of this provider's override variables. Never a value. PURE."""
    return cp.env_presence_record(env, OVERRIDE_VARS if names is None else names)


def redact_auth(status: Mapping | None) -> dict:
    """This provider's persistable auth fields. PURE."""
    return cp.redact_auth(status, AUTH_STATUS_ALLOWLIST)


# ---------------------------------------------------------------------------------------------
# I/O adapters
# ---------------------------------------------------------------------------------------------
def read_auth_status(claude_path: str = "claude", *, timeout: float = 60.0) -> Mapping | None:
    """Parsed ``claude auth status`` JSON, or None. Impure. NEVER raises.

    Bytes, then explicit UTF-8 decode -- never ``text=True``. It was measured that subprocess text
    mode decodes with the locale codepage on Windows and silently mojibakes non-ASCII.
    """
    try:
        p = subprocess.run([claude_path, "auth", "status"], capture_output=True, timeout=timeout,
                           shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    try:
        doc = json.loads(p.stdout.decode("utf-8", "replace"))
    except (ValueError, UnicodeError):
        return None
    return doc if isinstance(doc, dict) else None


def claude_version(claude_path: str = "claude", *, timeout: float = 60.0) -> str:
    """Installed CLI version string, or "". Impure. NEVER raises."""
    try:
        p = subprocess.run([claude_path, "--version"], capture_output=True, timeout=timeout,
                           shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else ""


def run_preflight(*, claude_path: str = "claude", env: Mapping[str, str] | None = None,
                  requires_write: bool = False) -> PreflightDecision:
    """``decide`` with the real readings wired in. Impure."""
    env = os.environ if env is None else env
    status = read_auth_status(claude_path)
    d = decide(env=env, auth_status=status, requires_write=requires_write)
    rec = dict(d.record)
    rec["claude_version"] = claude_version(claude_path)
    rec["claude_path"] = str(claude_path)
    return PreflightDecision(d.decision, d.reason, d.detail, d.auth_class, d.offending_vars, rec)

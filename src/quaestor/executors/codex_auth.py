"""codex_auth -- the OpenAI/Codex CLI instance of the platform credential policy.

The sibling of ``claude_auth.py`` (bd quaestor-1ng). Everything vendor-specific lives HERE, in
the EXECUTORS layer: ``core.credential_policy`` holds the question and the ceiling; this file
holds one provider's answer. Adding a provider means adding a sibling, never editing core.

THE RULES, IDENTICAL TO THE ANTHROPIC SIDE
------------------------------------------
 1. REFUSE AND NAME THE CONDITION; NEVER SILENTLY UNSET. ``OPENAI_API_KEY`` /
    ``CODEX_API_KEY`` / endpoint overrides take precedence over subscription auth exactly the
    way Anthropic's environment variables do -- so presence alone is a refusal.
 2. NEVER PERSIST A CREDENTIAL VALUE. Presence and length only; the redaction allowlist keeps
    identity fields out of the ledger.

FAIL-CLOSED CLASSIFICATION
--------------------------
Codex reports login state via ``codex login status``; its exact output shape is a property of
the installed version and versions move. Anything this classifier does not POSITIVELY recognise
as subscription-backed (ChatGPT-plan) auth is UNVERIFIED, and UNVERIFIED refuses -- a new
output spelling fails closed rather than being read optimistically. Both a parsed JSON object
and the human-readable text form are recognised; neither is invented here.
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

#: Variables that redirect Codex off subscription auth or onto another billing path. Presence
#: alone refuses; values are never inspected (they are credentials).
OVERRIDE_VARS = (
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_AUTH_TOKEN",
)

#: The only fields of a parsed ``codex login status`` that may be persisted.
AUTH_STATUS_ALLOWLIST = ("method", "logged_in")

#: Text markers in the non-JSON form of ``codex login status``. Positive recognitions only.
_SUBSCRIPTION_MARKERS = ("logged in using chatgpt", "chatgpt subscription", "plan: chatgpt")
_API_MARKERS = ("api key", "apikey")
_LOGGED_OUT_MARKERS = ("not logged in", "logged out")

#: The platform vocabulary this module republishes, so a provider caller imports ONE module.
__all__ = [
    "ACCEPT", "API_CONSOLE", "AUTH_STATUS_ALLOWLIST", "CODEX_POLICY", "LOGGED_OUT",
    "OVERRIDE_VARS", "PreflightDecision", "REASON_API_BILLED", "REASON_NOT_LOGGED_IN",
    "REASON_OVERRIDE", "REASON_STATUS_UNREADABLE", "REASON_THIRD_PARTY", "REASON_UNVERIFIED",
    "REFUSE", "SUBSCRIPTION", "THIRD_PARTY", "UNVERIFIED", "classify_auth", "codex_version",
    "decide", "env_overrides_present", "env_presence_record", "read_login_status", "redact_auth",
    "run_preflight",
]


def classify_auth(status: Mapping | None) -> tuple:
    """(auth_class, detail) from parsed/observed ``codex login status``. PURE. NEVER raises."""
    if not isinstance(status, Mapping) or not status:
        return UNVERIFIED, "login status was absent or unparseable"
    if status.get("logged_in") is False:
        return LOGGED_OUT, "codex login status reports logged_in=False"
    method = str(status.get("method") or "").strip().lower()
    if method in ("chatgpt", "subscription", "oauth"):
        return SUBSCRIPTION, "method=%s (subscription-backed ChatGPT plan)" % method
    if method in ("api_key", "apikey", "api-key", "console"):
        return API_CONSOLE, "method=%r is API-key authentication" % method
    text = str(status.get("text") or "").strip().lower()
    if not text:
        # A structured status we do not recognise the fields of is an instrument limitation,
        # recorded as one -- never guessed through.
        return UNVERIFIED, ("login status fields %s are not a classification this build "
                            "recognises" % sorted(str(k) for k in status))
    if any(m in text for m in _LOGGED_OUT_MARKERS):
        return LOGGED_OUT, "login status reports logged out"
    if any(m in text for m in _SUBSCRIPTION_MARKERS):
        return SUBSCRIPTION, "login status names a ChatGPT (subscription) login"
    if any(m in text for m in _API_MARKERS):
        return API_CONSOLE, "login status names API-key authentication"
    return UNVERIFIED, "login status text is not positively recognised; refusing fail-closed"


#: The shipped policy, validated at construction against the platform's exemption ceiling.
#: Nothing here is exemptible: an OpenAI-side brokered automation token would need a name free
#: of every forbidden credential shape BEFORE it could be added, by construction.
CODEX_POLICY = cp.ProviderCredentialPolicy(
    provider="openai/codex-cli",
    override_env=OVERRIDE_VARS,
    exemptible_env=frozenset(),
    classifier=classify_auth,
    redact_allowlist=AUTH_STATUS_ALLOWLIST,
)


def decide(*, env: Mapping[str, str], auth_status: Mapping | None,
           requires_write: bool = False) -> PreflightDecision:
    """``credential_policy.decide`` bound to this provider. PURE."""
    return cp.decide(policy=CODEX_POLICY, env=env, auth_status=auth_status,
                     requires_write=requires_write)


def env_overrides_present(env: Mapping[str, str]) -> tuple:
    """This provider's override check. PURE."""
    return cp.env_overrides_present(env, CODEX_POLICY)


def env_presence_record(env: Mapping[str, str], names=None) -> dict:
    """Presence and LENGTH of this provider's override variables. Never a value. PURE."""
    return cp.env_presence_record(env, OVERRIDE_VARS if names is None else names)


def redact_auth(status: Mapping | None) -> dict:
    """This provider's persistable auth fields. PURE."""
    return cp.redact_auth(status, AUTH_STATUS_ALLOWLIST)


# ---------------------------------------------------------------------------------------------
# I/O adapters
# ---------------------------------------------------------------------------------------------
def read_login_status(codex_path: str = "codex", *, timeout: float = 60.0) -> Mapping | None:
    """Parsed ``codex login status``, or None. Impure. NEVER raises.

    Bytes then explicit UTF-8 decode -- never ``text=True`` (the locale-codepage mojibake the
    claude adapter measured applies verbatim here). JSON output is passed through as an object;
    human-readable output is wrapped as {"text": ...} for the classifier to recognise.
    """
    try:
        p = subprocess.run([codex_path, "login", "status"], capture_output=True, timeout=timeout,
                           shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    raw = p.stdout.decode("utf-8", "replace")
    try:
        doc = json.loads(raw)
        if isinstance(doc, dict):
            return doc
    except ValueError:
        pass
    text = raw.strip() or (p.stderr.decode("utf-8", "replace").strip())
    return {"text": text} if text else None


def codex_version(codex_path: str = "codex", *, timeout: float = 60.0) -> str:
    """Installed CLI version string, or "". Impure. NEVER raises."""
    try:
        p = subprocess.run([codex_path, "--version"], capture_output=True, timeout=timeout,
                           shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else ""


def run_preflight(*, codex_path: str = "codex", env: Mapping[str, str] | None = None,
                  requires_write: bool = False) -> PreflightDecision:
    """``decide`` with the real readings wired in. Impure. THE measured preflight."""
    env = os.environ if env is None else env
    status = read_login_status(codex_path)
    d = decide(env=env, auth_status=status, requires_write=requires_write)
    rec = dict(d.record)
    rec["codex_version"] = codex_version(codex_path)
    rec["codex_path"] = str(codex_path)
    return PreflightDecision(d.decision, d.reason, d.detail, d.auth_class, d.offending_vars, rec)

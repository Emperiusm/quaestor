"""openrouter_auth -- the MEASURED credential preflight for the OpenRouter gateway.

WHAT THIS ESTABLISHES, AND WHAT IT REFUSES TO CLAIM
----------------------------------------------------
``credential_policy`` exists so a run can state which BILLING PATH it used. For OpenRouter that
answer is settled and unflattering: it is an API key, billed per token, and this module reports
``API_CONSOLE`` and nothing else. It will never report ``SUBSCRIPTION``, even though the gateway
can front models an operator also pays a subscription for elsewhere -- the money for THIS call
leaves through the key, and saying otherwise would falsify the one fact the whole credential
apparatus exists to establish.

That matters concretely: a deployment enforcing ``credential_modes={"subscription"}`` must refuse
to route seats here, and it can only do that if this module tells the truth.

NO NETWORK UNLESS THERE IS SOMETHING TO CHECK
----------------------------------------------
An absent key is answered WITHOUT a request. A preflight that phoned home to discover it had no
credential would leak the existence of the deployment to a third party in exchange for
information it already had.

THE KEY VALUE NEVER LEAVES THIS MODULE
---------------------------------------
It is read from the environment, used in one Authorization header, and never returned, logged,
recorded or placed in any ``record`` field. What the record carries is whether a key was PRESENT
and what the provider said about it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Mapping

from quaestor.core import credential_policy as cp

OPENROUTER_AUTH_INSTRUMENT = "openrouter_auth/1"

#: The environment variable holding the key. One name, read in one place.
API_KEY_VAR = "OPENROUTER_API_KEY"

#: The cheapest authenticated endpoint that proves a key works. Chosen over a completion because
#: a preflight must not consume tokens the operator is paying for.
CREDITS_URL = "https://openrouter.ai/api/v1/credits"

#: Named refusals.
REASON_NO_KEY = "NO_OPENROUTER_API_KEY"
REASON_KEY_REJECTED = "OPENROUTER_KEY_REJECTED"
REASON_UNREACHABLE = "OPENROUTER_UNREACHABLE"

PREFLIGHT_TIMEOUT_S = 15.0


def _default_opener(url: str, key: str, timeout: float):
    """The real HTTP read. Replaced wholesale by controls so no test touches the network."""
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - fixed https URL
        return int(r.status), r.read().decode("utf-8", "replace")


def run_preflight(*, env: Mapping[str, str] | None = None,
                  opener=None, timeout_s: float = PREFLIGHT_TIMEOUT_S) -> cp.PreflightDecision:
    """THE measured preflight. Impure (env + one HTTPS read). NEVER raises.

    Returns the same ``PreflightDecision`` shape ``claude_auth`` and ``codex_auth`` return, so
    one Settings panel can read every provider through one shape rather than growing a branch
    per vendor.
    """
    env = os.environ if env is None else env
    key = str((env or {}).get(API_KEY_VAR) or "").strip()
    record = {"provider": "openrouter", "key_var": API_KEY_VAR,
              "key_present": bool(key), "instrument": OPENROUTER_AUTH_INSTRUMENT}
    if not key:
        # No request: see the module docstring. Nothing to check, and checking would tell a
        # third party this deployment exists in exchange for what we already know.
        return cp.PreflightDecision(
            cp.REFUSE, REASON_NO_KEY,
            "%s is not set; OpenRouter seats cannot be dispatched" % API_KEY_VAR,
            cp.LOGGED_OUT, (), record)

    call = opener or _default_opener
    try:
        status, body = call(CREDITS_URL, key, timeout_s)
    except urllib.error.HTTPError as exc:                        # noqa: PERF203
        status, body = int(getattr(exc, "code", 0) or 0), ""
    except Exception as exc:                                     # noqa: BLE001
        # UNREACHABLE IS NOT REJECTED. An outage, a proxy or an unplugged cable must not be
        # recorded as "your key is bad" -- the operator would go and rotate a working key.
        return cp.PreflightDecision(
            cp.REFUSE, REASON_UNREACHABLE,
            "could not reach OpenRouter: %s: %s" % (type(exc).__name__, exc),
            cp.UNVERIFIED, (), record)

    record["http_status"] = int(status)
    if status == 200:
        record.update(_credit_facts(body))
        return cp.PreflightDecision(
            cp.ACCEPT, "", "OpenRouter key accepted (API-billed)", cp.API_CONSOLE, (), record)
    if status in (401, 403):
        return cp.PreflightDecision(
            cp.REFUSE, REASON_KEY_REJECTED,
            "OpenRouter rejected the key with HTTP %d" % status, cp.LOGGED_OUT, (), record)
    return cp.PreflightDecision(
        cp.REFUSE, REASON_UNREACHABLE,
        "OpenRouter answered HTTP %d" % status, cp.UNVERIFIED, (), record)


def _credit_facts(body: str) -> dict:
    """The non-secret facts from a credits response. PURE. Never raises.

    An ALLOWLIST of two numbers, not a passthrough of the response: a future field on that
    endpoint must not reach a durable record because nobody thought about it.
    """
    try:
        doc = json.loads(body or "{}")
    except (ValueError, TypeError):
        return {}
    data = doc.get("data") if isinstance(doc, Mapping) else None
    if not isinstance(data, Mapping):
        return {}
    out = {}
    for key in ("total_credits", "total_usage"):
        value = data.get(key)
        if isinstance(value, (int, float)):
            out[key] = float(value)
    return out

"""chatgpt_web_auth -- the preflight for a browser-held seat, and the one thing it refuses to say.

WHAT IT CANNOT ESTABLISH, PERMANENTLY
--------------------------------------
``credential_policy`` exists so a run can state which BILLING PATH it used, and every other
provider on this platform can answer: ``claude_auth`` reads ``claude auth status``, ``codex_auth``
matches a ChatGPT-plan login string, ``openrouter_auth`` knows an API key is an API key.

A browser session yields no such evidence. The page does not tell an automation which plan is
paying, and inferring it from what the UI happens to render would be a guess dressed as a
measurement. So this module reports ``UNVERIFIED`` and will never report ``SUBSCRIPTION`` --
even though a subscription is almost certainly what is paying, and even though saying so would
make the feature look better.

That refusal has a concrete consequence, which is the point: a deployment enforcing
``credential_modes={"subscription"}`` gets no proof from this seat. An unverifiable claim must
not satisfy a policy that exists to verify, or the policy is decoration.

WHAT IT CAN ESTABLISH
---------------------
Whether a browser is attached, whether a page is signed in, and which transport reached it.
Those are the facts an operator actually needs when the seat will not run, and all three are
observable.
"""
from __future__ import annotations

from typing import Mapping

from quaestor.core import credential_policy as cp

CHATGPT_WEB_AUTH_INSTRUMENT = "chatgpt_web_auth/1"

REASON_NOT_ATTACHED = "BROWSER_NOT_ATTACHED"
REASON_SIGNED_OUT = "CHATGPT_SIGNED_OUT"
REASON_PAGE_UNREADABLE = "CHATGPT_PAGE_UNREADABLE"

#: Said in every accepting decision, so the honest limit travels with the good news rather than
#: living only in a docstring nobody opens while debugging.
UNVERIFIED_NOTE = (
    "a browser session carries no evidence of which plan is paying; this seat is routable but "
    "its billing path is UNVERIFIED and will never be reported as subscription")


def decide(*, probe_result: Mapping | None, transport_why: str = "") -> cp.PreflightDecision:
    """The preflight decision from one page snapshot. PURE. NEVER raises."""
    record = {"provider": "chatgpt-web", "transport": str(transport_why or ""),
              "instrument": CHATGPT_WEB_AUTH_INSTRUMENT}
    if not isinstance(probe_result, Mapping) or not probe_result:
        return cp.PreflightDecision(
            cp.REFUSE, REASON_NOT_ATTACHED,
            "no browser is attached, or the page answered nothing", cp.UNVERIFIED, (), record)

    from quaestor.executors import chatgpt_web_page as page_mod
    state = page_mod.classify(probe_result)
    record["page_state"] = state
    record["conversation_id"] = page_mod.conversation_id(probe_result.get("href"))
    if state == page_mod.STATE_LOGGED_OUT:
        return cp.PreflightDecision(
            cp.REFUSE, REASON_SIGNED_OUT,
            "the attached browser is not signed in to ChatGPT; sign in once in that window "
            "(Quaestor never handles the credential)", cp.UNVERIFIED, (), record)
    if state == page_mod.STATE_NO_COMPOSER:
        return cp.PreflightDecision(
            cp.REFUSE, REASON_PAGE_UNREADABLE,
            "the attached page has no composer: either it is not a ChatGPT conversation, or the "
            "selectors in chatgpt_web_page.SELECTORS have rotted", cp.UNVERIFIED, (), record)
    # ACCEPTED, and UNVERIFIED anyway. Those are not in tension: the seat can run, and what it
    # cannot do is prove how it was billed.
    return cp.PreflightDecision(cp.ACCEPT, "", UNVERIFIED_NOTE, cp.UNVERIFIED, (), record)


def run_preflight(*, probe=None, endpoint: str = "", prefer: str = "auto",
                  timeout_s: float = 20.0) -> cp.PreflightDecision:
    """THE measured preflight. Impure (attaches a browser). NEVER raises.

    ``probe`` is the control seam: supplied, no browser is opened at all.
    """
    if probe is not None:
        try:
            snapshot = probe()
        except Exception as exc:  # noqa: BLE001
            return cp.PreflightDecision(
                cp.REFUSE, REASON_NOT_ATTACHED, "%s: %s" % (type(exc).__name__, exc),
                cp.UNVERIFIED, (), {"provider": "chatgpt-web"})
        return decide(probe_result=snapshot, transport_why="injected probe")

    from quaestor.executors import browser_transport as bt
    from quaestor.executors import chatgpt_web_page as page_mod
    kwargs = {"prefer": prefer, "timeout": timeout_s, "match": page_mod.CHATGPT_ORIGIN}
    if endpoint:
        kwargs["endpoint"] = endpoint
    try:
        transport, why = bt.open_transport(**kwargs)
    except bt.BrowserUnavailable as exc:
        return cp.PreflightDecision(
            cp.REFUSE, exc.reason, str(exc), cp.UNVERIFIED, (),
            {"provider": "chatgpt-web", "instrument": CHATGPT_WEB_AUTH_INSTRUMENT})
    try:
        return decide(probe_result=page_mod.probe(transport), transport_why=why)
    except Exception as exc:  # noqa: BLE001
        return cp.PreflightDecision(
            cp.REFUSE, REASON_PAGE_UNREADABLE, "%s: %s" % (type(exc).__name__, exc),
            cp.UNVERIFIED, (), {"provider": "chatgpt-web", "transport": why})
    finally:
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            pass

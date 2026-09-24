"""registry -- the provider-neutral endpoint factory. THE INVERSION SEAM FOR RELAY MODE.

Same discipline as ``executors.registry``, for the same reason: a kernel that statically imports
a provider cannot be provider-neutral however loudly its docstring says so. The kernel declares
the NEED ("give me an OrchestratorEnd for this spec"); this module, which lives in the provider
layer, satisfies it, and every provider import happens inside a branch here.

NO DEFAULT ENDPOINT, EVER. An unknown or empty kind is a NAMED REFUSAL. Silently falling back to
the scripted endpoint would let a relay report a completed conversation that no model
participated in -- the worst available outcome, because it looks like work happened.
"""
from __future__ import annotations

from typing import Mapping

from quaestor.relay.contracts import (END_KIND_NOT_BUILDABLE, ROLE_EXECUTION,
                                      ROLE_ORCHESTRATOR)

RELAY_REGISTRY_INSTRUMENT = "relay.registry/1"

#: Every Orchestrator this build can construct. ``openai-chat`` is the PROTOCOL, not a vendor:
#: OpenRouter, OpenCode Zen, OpenAI and any compatible gateway all speak it, and the vendor
#: identity comes from the MODEL, never from the endpoint that carried the request -- the same
#: rule ``adapters.registry.GATEWAY_KINDS`` enforces for Program Mode seats.
#:
#: ``chatgpt-web`` is a SURFACE, not a protocol: one conversation in a browser the operator
#: already signed into. It is listed beside the others precisely because the kernel cannot tell
#: the difference -- every browser-shaped fact stops inside the endpoint.
ORCHESTRATOR_KINDS = ("openai-chat", "chatgpt-web", "fake")

#: Every Execution Agent this build can attach to.
EXECUTION_KINDS = ("opencode", "fake")


def buildable(role: str) -> tuple:
    return ORCHESTRATOR_KINDS if role == ROLE_ORCHESTRATOR else EXECUTION_KINDS


def build_orchestrator(spec: Mapping):
    """Construct an ``OrchestratorEnd``. Impure (imports a provider)."""
    kind = str((spec or {}).get("kind") or "").strip()
    cfg = dict((spec or {}).get("config") or {})
    if kind == "openai-chat":
        from quaestor.relay.ends.http_chat import HttpChatOrchestratorEnd
        return HttpChatOrchestratorEnd(**cfg)
    if kind == "chatgpt-web":
        from quaestor.relay.ends.chatgpt_web import ChatGptWebOrchestratorEnd
        return ChatGptWebOrchestratorEnd(**cfg)
    if kind == "fake":
        from quaestor.relay.ends.fake import FakeOrchestratorEnd
        return FakeOrchestratorEnd(**cfg)
    raise ValueError(
        "%s: orchestrator kind %r is not one of %s. There is deliberately no default: a relay "
        "that silently used a scripted endpoint would report a conversation no model had."
        % (END_KIND_NOT_BUILDABLE, kind, list(ORCHESTRATOR_KINDS)))


def build_execution(spec: Mapping):
    """Construct an ``ExecutionEnd``. Impure (imports a provider)."""
    kind = str((spec or {}).get("kind") or "").strip()
    cfg = dict((spec or {}).get("config") or {})
    if kind == "opencode":
        from quaestor.relay.ends.opencode import OpenCodeExecutionEnd
        return OpenCodeExecutionEnd(**cfg)
    if kind == "fake":
        from quaestor.relay.ends.fake import FakeExecutionEnd
        return FakeExecutionEnd(**cfg)
    raise ValueError(
        "%s: execution agent kind %r is not one of %s. There is deliberately no default."
        % (END_KIND_NOT_BUILDABLE, kind, list(EXECUTION_KINDS)))


def build(role: str, spec: Mapping):
    if role == ROLE_ORCHESTRATOR:
        return build_orchestrator(spec)
    if role == ROLE_EXECUTION:
        return build_execution(spec)
    raise ValueError("unknown relay role %r; the vocabulary is %s"
                     % (role, [ROLE_ORCHESTRATOR, ROLE_EXECUTION]))


def preflight(role: str, spec: Mapping) -> dict:
    """Can this endpoint be used right now, and how do we know? Impure.

    MEASURED, never assumed. A kind with no measured preflight answers UNKNOWN rather than
    inheriting a blanket pass -- the exact failure ``executors.registry.run_preflight`` was
    tightened to close, repeated here so it is not re-learned.
    """
    kind = str((spec or {}).get("kind") or "").strip()
    cfg = dict((spec or {}).get("config") or {})
    if kind == "openai-chat":
        from quaestor.relay.ends.http_chat import preflight as _p
        return _p(**cfg)
    if kind == "chatgpt-web":
        from quaestor.relay.ends.chatgpt_web import preflight as _p
        return _p(**cfg)
    if kind == "opencode":
        from quaestor.relay.ends.opencode import preflight as _p
        return _p(**cfg)
    if kind == "fake":
        return {"ok": True, "kind": kind, "detail": "scripted endpoint needs nothing",
                "proves": "NOT_APPLICABLE_SCRIPTED_ENDPOINT"}
    return {"ok": False, "kind": kind, "detail":
            "this build ships no preflight for relay endpoint kind %r, so its readiness is "
            "unassessed; refusing rather than reporting an unchecked endpoint as healthy" % kind,
            "proves": "UNVERIFIED"}


def probe(role: str, spec: Mapping) -> dict:
    """Build the endpoint and EXERCISE ITS PROVIDER. Impure. NEVER raises.

    ``preflight`` proves the endpoint's local situation -- a credential resolves, a server
    answers, the model is listed. That is not the same question as "does a turn come back", and
    the gap between them is where an operator loses a relay: a gateway returning 503 to every
    request still lists its models, and a model that errors on every inference still appears in
    the catalogue. Both were live-observed reporting healthy.

    An endpoint that declines to be probed reports PROBE_UNSUPPORTED and ``measured`` False --
    honest, and never mistakable for a pass.
    """
    from quaestor.relay.contracts import EndProbe, PROBE_REFUSED
    builder = build_orchestrator if role == ROLE_ORCHESTRATOR else build_execution
    try:
        end = builder(spec)
    except Exception as exc:  # noqa: BLE001
        return dict(EndProbe(PROBE_REFUSED,
                             "the endpoint could not be built: %s: %s"
                             % (type(exc).__name__, exc)).to_dict(),
                    kind=str((spec or {}).get("kind") or ""))
    try:
        result = end.probe()
    except Exception as exc:  # noqa: BLE001
        result = EndProbe(PROBE_REFUSED,
                          "the endpoint's own probe raised %s: %s" % (type(exc).__name__, exc))
    # NO close() HERE. probe() opens nothing, so there is nothing to release -- and close() is
    # not free: HttpChatOrchestratorEnd.close() SAVES its transcript, and this endpoint was
    # built without ever loading one, so an empty in-memory conversation would be written over
    # the operator's real one. Measured: a transcript holding 7 turns became {"turn": 0,
    # "messages": []} after a single probe. For a stateless provider that transcript IS the
    # conversation, so resume would have silently started over.
    return dict(result.to_dict(), kind=str((spec or {}).get("kind") or ""))

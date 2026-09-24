"""adapters.base -- the minimum agent contract (direction §5.1).

The whole universal-agent-end bet is that a new coding agent participates with

    send(message)
    receive()

and NOTHING else is required. Everything beyond that pair is optional capability discovery:
Quaestor adapts its guarantees to what an adapter actually exposes, and -- per direction §31 --
never to what it merely claims. A declared capability this class does not know the name of is
refused rather than passed through: an open capability vocabulary would let any adapter invent
whatever guarantee it wanted spelled however it liked.
"""
from __future__ import annotations

import abc
from typing import Mapping

BASE_INSTRUMENT = "adapters.base/1"

#: The closed OPTIONAL-capability vocabulary (§5.1). Required send/receive live on the ABC as
#: abstract methods; everything here is discoverable, never assumed.
CAPABILITIES: tuple = (
    "start", "stop", "pause", "resume", "status",
    "structured_output", "tool_events", "usage", "workspace_identity", "cancellation")

#: Named refusal (bd quaestor-ru1.21): the class-level DECLARED_CAPABILITIES attribute and the
#: constructor's ``declared`` mapping were two channels for one fact, and nothing reconciled
#: them -- the registry surface advertised what the running object did not have. They now must
#: agree, or construction refuses BY NAME.
CAPABILITY_CHANNELS_DISAGREE = "CAPABILITY_CHANNELS_DISAGREE"


class AgentAdapter(abc.ABC):
    """Base class for agent adapters.

    Constructor takes ``adapter_id`` plus the DECLARED capability mapping. Declaration is only
    the adapter's word -- ``capabilities()`` reports it so callers can gate optional hooks, while
    ``assurance.compute_assurance`` exists precisely because declaration is not measurement.
    """

    #: Optional provider-set kind used by the registry; defaults to the class name.
    ADAPTER_KIND = ""

    def __init__(self, adapter_id: str, declared: Mapping[str, bool] | None = None):
        if not str(adapter_id or "").strip():
            raise ValueError("adapter_id is required: an assurance record without a lane/adapter "
                             "identity measures nothing in particular")
        unknown = sorted(set(declared or {}) - set(CAPABILITIES))
        if unknown:
            raise ValueError(
                "adapter %r declares unknown capabilities %s; the vocabulary is %s. There is "
                "deliberately no passthrough for invented guarantees."
                % (adapter_id, unknown, list(CAPABILITIES)))
        # ONE FACT, ONE CHANNEL (bd quaestor-ru1.21). When the concrete class carries a
        # DECLARED_CAPABILITIES attribute, that attribute IS the declaration -- it is what the
        # registry surface (doctor / Settings) shows, so it is what the running object must
        # honour. A constructor mapping is allowed only in EXACT agreement with it; a
        # disagreement refuses BY NAME here, because an adapter that reaches a registry summary
        # advertising capabilities its instance never declared is self-declaration through the
        # back door (§31, at registry scale). Classes WITHOUT the attribute keep the plain
        # constructor mapping as their single channel -- unchanged behaviour for test doubles
        # and provider adapters that never opted into the class-level form.
        class_declared = getattr(type(self), "DECLARED_CAPABILITIES", None)
        if class_declared is not None:
            unknown_class = sorted({str(cap) for cap in class_declared} - set(CAPABILITIES))
            if unknown_class:
                raise ValueError(
                    "adapter %r class declares unknown capabilities %s; the vocabulary is %s"
                    % (adapter_id, unknown_class, list(CAPABILITIES)))
            class_set = {str(cap) for cap in class_declared}
            if declared is None:
                declared = {cap: cap in class_set for cap in CAPABILITIES}
            else:
                instance_set = {cap for cap in CAPABILITIES if (declared or {}).get(cap)}
                if instance_set != class_set:
                    raise ValueError(
                        "%s: adapter %r class declares %s but its constructor declares %s. "
                        "The registry surface shows the class attribute, so the running object "
                        "must honour exactly that set -- refusing rather than advertising a "
                        "capability the instance does not have."
                        % (CAPABILITY_CHANNELS_DISAGREE, adapter_id, sorted(class_set),
                           sorted(instance_set)))
        self.adapter_id = str(adapter_id)
        self._declared: dict = {cap: bool((declared or {}).get(cap, False))
                                for cap in CAPABILITIES}

    # -- REQUIRED (§5.1 minimum contract) ------------------------------------------------------
    @abc.abstractmethod
    def send(self, message) -> None:
        """Deliver one message toward the agent."""

    @abc.abstractmethod
    def receive(self):
        """Receive the next message from the agent (blocking or None-per-policy)."""

    # -- OPTIONAL capability discovery ---------------------------------------------------------
    def capabilities(self) -> Mapping[str, bool]:
        """What this adapter CLAIMS it can do. The truth lives in probes, not here."""
        return dict(self._declared)

    def _require_declared(self, cap: str) -> None:
        if not self._declared.get(cap):
            raise NotImplementedError(
                "adapter %r does not declare capability %r; refusing to pretend"
                % (self.adapter_id, cap))

    # Optional hooks. Each refuses unless the capability was declared, and raises NotImplementedError
    # when declared but not implemented by the concrete adapter -- an inherited silent no-op would
    # be exactly the declared!=effective drift §31 bars at the adapter edge.
    def start(self):
        self._require_declared("start")
        raise NotImplementedError("adapter %r declares 'start' but does not implement it"
                                  % self.adapter_id)

    def stop(self):
        self._require_declared("stop")
        raise NotImplementedError("adapter %r declares 'stop' but does not implement it"
                                  % self.adapter_id)

    def pause(self):
        self._require_declared("pause")
        raise NotImplementedError("adapter %r declares 'pause' but does not implement it"
                                  % self.adapter_id)

    def resume(self):
        self._require_declared("resume")
        raise NotImplementedError("adapter %r declares 'resume' but does not implement it"
                                  % self.adapter_id)

    def status(self):
        self._require_declared("status")
        raise NotImplementedError("adapter %r declares 'status' but does not implement it"
                                  % self.adapter_id)

    def structured_output(self):
        self._require_declared("structured_output")
        raise NotImplementedError("adapter %r declares 'structured_output' but does not "
                                  "implement it" % self.adapter_id)

    def tool_events(self):
        self._require_declared("tool_events")
        raise NotImplementedError("adapter %r declares 'tool_events' but does not implement it"
                                  % self.adapter_id)

    def usage(self):
        self._require_declared("usage")
        raise NotImplementedError("adapter %r declares 'usage' but does not implement it"
                                  % self.adapter_id)

    def workspace_identity(self):
        self._require_declared("workspace_identity")
        raise NotImplementedError("adapter %r declares 'workspace_identity' but does not "
                                  "implement it" % self.adapter_id)

    def cancellation(self):
        self._require_declared("cancellation")
        raise NotImplementedError("adapter %r declares 'cancellation' but does not implement it"
                                  % self.adapter_id)

"""adapters -- the universal agent-end (direction §5-§5.3).

ANY AGENT reaches Quaestor through the minimal contract in ``base``; how much that integration
can honestly promise is COMPUTED from measured conformance probes (``probes``), never taken from
the adapter's word (``assurance``), and every computation is recorded durably per lane
(``record``). Direction §31: "Adapter assurance is MEASURED by conformance probes ... an adapter
can never declare its own level."

This package is deliberately provider-free: it names the CONTRACT and the MEASUREMENT, not any
one agent. The concrete adapters imported below are the stdlib-only REFERENCE transports of
direction §5.2 (file inbox/outbox, command/stdin, clipboard, transcript) -- they live beside the
contract because they ARE the contract's worked examples, not because they are privileged; real
vendor integrations remain a provider-layer change and register themselves from outside.
"""
from __future__ import annotations


ADAPTERS_INSTRUMENT = "adapters/1"

#: Every adapter class this process knows about, keyed by adapter kind. Closed on purpose: a
#: doctor surface that invents entries is a status page, not a measurement.
_REGISTRY: dict = {}


def register(cls):
    """Class decorator: put ``cls`` in the module-level registry under its adapter kind.

    The kind comes from ``cls.ADAPTER_KIND`` when declared, else the class name -- so a provider
    registers itself with one line and no factory edit. Re-registering the SAME class is
    idempotent (modules get re-imported); two different classes claiming one kind is a naming
    collision we refuse rather than silently overwrite, because a summary that quietly points at
    whichever class imported last is CONTROL_DECLARED != CONTROL_EFFECTIVE at registry scale.
    """
    key = str(getattr(cls, "ADAPTER_KIND", "") or cls.__name__)
    existing = _REGISTRY.get(key)
    if existing is not None and existing is not cls:
        raise ValueError(
            "adapter kind %r is already registered by %s; refusing to overwrite"
            % (key, existing.__name__))
    _REGISTRY[key] = cls
    return cls


def registered_adapters() -> tuple:
    """Summary of registered adapter classes, stable order. Empty registry renders []."""
    return tuple({"adapter": key, "class": cls.__name__, "module": cls.__module__,
                  "capabilities": sorted(getattr(cls, "DECLARED_CAPABILITIES", ()) or ())}
                 for key, cls in sorted(_REGISTRY.items()))


def registry_summary() -> list:
    """JSON-shaped view for `doctor`. Read-only; never raises."""
    return [dict(entry) for entry in registered_adapters()]


from quaestor.adapters.base import AgentAdapter  # noqa: E402

# Reference adapters self-register via @register at import; kinds collide loudly rather than
# overwrite, so importing this package is what makes `doctor` see them.
from quaestor.adapters.filebox import (  # noqa: E402,F401
    COMPLETION_MARKER, FileFieldNotTransportable, FileInboxOutboxAdapter, apply_response)
from quaestor.adapters.command import (  # noqa: E402,F401
    ClipboardAdapter, ClipboardUnsupportedError, CommandAdapter, CommandTimeoutError)
from quaestor.adapters.transcript import (  # noqa: E402,F401
    AdapterReadOnlyError, TranscriptObserverAdapter)

__all__ = [
    "AgentAdapter", "register", "registered_adapters", "registry_summary",
    "FileInboxOutboxAdapter", "FileFieldNotTransportable", "apply_response",
    "COMPLETION_MARKER", "CommandAdapter", "CommandTimeoutError", "ClipboardAdapter",
    "ClipboardUnsupportedError", "TranscriptObserverAdapter", "AdapterReadOnlyError",
]

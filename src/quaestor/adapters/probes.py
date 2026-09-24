"""adapters.probes -- conformance probes that MEASURE adapter behavior (§5.3, §5.12, §5.13).

A probe is a callable(adapter) -> ProbeResult. Probes encode the JUDGEMENT ("does read-only
actually hold under provocation?"); the adapter supplies the observed outcome through an
optional harness dict (``adapter.conformance_harness``), which keeps the whole suite runnable
against fakes with no real agent on the other end. A real integration runs these SAME probes --
the harness is replaced by actual behavior, never by different code.

Direction §31 draws the line this module enforces: "Adapter assurance is MEASURED by
conformance probes (can it cancel? does send/receive round-trip? does it leak prompts via argv?
does read-only stay read-only?); an adapter can never declare its own level." A probe that
cannot measure -- absent declaration, missing harness fact -- FAILS; an unmeasured dimension is
never silently scored as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

PROBES_INSTRUMENT = "adapters.probes/1"

#: PROMPT_TRANSPORT vocabulary (§5.13). ARGV is readable from the process table by any local
#: process, so it can never pass the leak check.
TRANSPORTS = ("STDIN", "PIPE", "TEMP_FILE", "IPC", "ARGV")
#: Transports that do NOT publish the prompt to every process-table reader.
NON_LEAKING_TRANSPORTS = ("STDIN", "PIPE", "TEMP_FILE", "IPC")


@dataclass(frozen=True)
class ProbeResult:
    """One measured fact about one adapter. ``name`` doubles as assurance evidence name."""
    name: str
    passed: bool
    detail: str = ""


def _harness(adapter) -> dict:
    return dict(getattr(adapter, "conformance_harness", None) or {})


# ---- built-ins -------------------------------------------------------------------------------

def observe_probe(adapter) -> ProbeResult:
    """OBSERVED tier: Quaestor can see output/state at all."""
    if _harness(adapter).get("observe") is True:
        return ProbeResult("observe_probe", True, "output/state observable")
    return ProbeResult("observe_probe", False,
                       "no observation channel measured (harness 'observe' is not true)")


def send_receive_roundtrip(adapter) -> ProbeResult:
    """DIALOGUE tier: what Quaestor sends comes back intact through send/receive."""
    marker = {"probe": "roundtrip", "nonce": "qr-1"}
    adapter.send(marker)
    back = adapter.receive()
    if back == marker:
        return ProbeResult("roundtrip", True, "payload survived the round trip")
    return ProbeResult("roundtrip", False,
                       "received %r, sent %r" % (back, marker))


def message_id_preserved(adapter) -> ProbeResult:
    """§5.12 mailbox contract: the message id survives transport AND reconnect."""
    msg = {"message_id": "qm-1", "payload": "id-preservation"}
    adapter.send(msg)
    received = adapter.receive()
    got = (received or {}).get("message_id") if isinstance(received, dict) else None
    if got == msg["message_id"]:
        return ProbeResult("message_id_preserved", True,
                           "message_id qm-1 preserved across reconnect")
    return ProbeResult("message_id_preserved", False,
                       "sent message_id qm-1, received %r -- ids are being dropped, so "
                       "dedup/replay semantics are unprovable" % (got,))


def cancel_actually_cancels(adapter) -> ProbeResult:
    """MANAGED tier: a cancel that leaves the work running is decoration."""
    if not adapter.capabilities().get("cancellation"):
        return ProbeResult("cancel_works", False, "cancellation capability not declared")
    adapter.cancellation()
    if _harness(adapter).get("cancelled_after_cancel") is True:
        return ProbeResult("cancel_works", True, "work stopped after cancellation()")
    return ProbeResult("cancel_works", False,
                       "cancel was accepted but work kept running -- CONTROL_DECLARED != "
                       "CONTROL_EFFECTIVE")


def lifecycle_probe(adapter) -> ProbeResult:
    """MANAGED tier: declared start/pause/resume/stop/status hooks actually work."""
    caps = adapter.capabilities()
    exercised: list = []
    for cap in ("start", "pause", "resume", "stop"):
        if caps.get(cap):
            getattr(adapter, cap)()
            exercised.append(cap)
    if caps.get("status"):
        st = adapter.status()
        if not isinstance(st, Mapping):
            return ProbeResult("lifecycle", False,
                               "status() returned %r, not a mapping" % (st,))
        exercised.append("status")
    if not exercised:
        return ProbeResult("lifecycle", False, "no lifecycle capability declared to exercise")
    return ProbeResult("lifecycle", True, "exercised %s without contradiction" % exercised)


def readonly_stays_readonly(adapter) -> ProbeResult:
    """GOVERNED tier: a read-only adapter refuses a provoked mutation. Measured, not assumed."""
    h = _harness(adapter)
    if h.get("read_only") is not True:
        return ProbeResult("readonly_holds", False,
                           "adapter does not claim read-only; this probe cannot stand as "
                           "readonly evidence for a mutable lane")
    attempted = adapter.attempt_mutation()
    if attempted is False:
        return ProbeResult("readonly_holds", True, "provoked write refused")
    return ProbeResult("readonly_holds", False,
                       "read-only DECLARED, provoked write went through (%r)" % (attempted,))


def workspace_write_containment(adapter) -> ProbeResult:
    """GOVERNED tier: a write aimed outside the claimed workspace root must fail."""
    root = str(_harness(adapter).get("workspace_root") or "")
    if not root:
        return ProbeResult("workspace_containment", False,
                           "no workspace_root claimed; containment cannot be measured against "
                           "nothing")
    if _harness(adapter).get("outside_write_succeeded") is True:
        return ProbeResult("workspace_containment", False,
                           "write outside claimed root %r succeeded -- boundary is prose"
                           % root)
    return ProbeResult("workspace_containment", True,
                       "outside-root write refused (root=%r)" % root)


def container_validation_probe(adapter) -> ProbeResult:
    """CONFINED tier: an INDEPENDENTLY verified containment boundary (§5.2 Tier 4)."""
    if _harness(adapter).get("container_validated") is True:
        return ProbeResult("container_validation", True,
                           "external boundary independently verified")
    return ProbeResult("container_validation", False,
                       "confinement asserted but never validated by anything outside the "
                       "adapter")


def prompt_transport_leak_check(adapter) -> ProbeResult:
    """§5.13 PROMPT_TRANSPORT dimension: ARGV publishes the prompt to the process table."""
    transport = str(_harness(adapter).get("prompt_transport") or "")
    if transport not in TRANSPORTS:
        return ProbeResult("prompt_transport_leak_check", False,
                           "prompt_transport %r is not one of %s; an unmeasured transport fails"
                           % (transport, list(TRANSPORTS)))
    if transport in NON_LEAKING_TRANSPORTS:
        return ProbeResult("prompt_transport_leak_check", True,
                           "transport %s does not expose the prompt via argv" % transport)
    return ProbeResult("prompt_transport_leak_check", False,
                       "ARGV transport: any local process can read the prompt from the process "
                       "table")


def resume_after_reconnect(adapter) -> ProbeResult:
    """§5.12 offline spool + reconnect replay: resume restores delivery honestly."""
    h = _harness(adapter)
    if h.get("resumed_after_reconnect") is not True:
        return ProbeResult("resume_after_reconnect", False,
                           "reconnect/resume did not restore delivery")
    if h.get("ack_cursor_restored") is False:
        return ProbeResult("resume_after_reconnect", False,
                           "reconnected but the ack cursor was lost -- replay would duplicate")
    return ProbeResult("resume_after_reconnect", True,
                       "delivery resumed with ack cursor intact")


# ---- registry --------------------------------------------------------------------------------

#: Canonical evidence name -> probe callable. The keys are exactly the evidence names
#: ``assurance.required_for`` consumes; adding a level in assurance.py and forgetting its probe
#: here leaves the rung unmeasurable, which tests catch as a KeyError rather than silently.
_PROBES: dict = {
    "observe_probe": observe_probe,
    "roundtrip": send_receive_roundtrip,
    "message_id_preserved": message_id_preserved,
    "cancel_works": cancel_actually_cancels,
    "lifecycle": lifecycle_probe,
    "workspace_containment": workspace_write_containment,
    "readonly_holds": readonly_stays_readonly,
    "container_validation": container_validation_probe,
    "prompt_transport_leak_check": prompt_transport_leak_check,
    "resume_after_reconnect": resume_after_reconnect,
}

#: Function names are accepted as aliases for their canonical keys, so callers may name a probe
#: either way; results are ALWAYS keyed canonically so assurance never sees two spellings of
#: one measurement.
_ALIASES: dict = {fn.__name__: key for key, fn in _PROBES.items() if fn.__name__ != key}

CANONICAL_PROBE_NAMES: tuple = tuple(_PROBES)


def _key_of(probe) -> str:
    for key, fn in _PROBES.items():
        if fn is probe:
            return key
    return getattr(probe, "__name__", "unknown")


def run_probes(adapter, names) -> dict:
    """Run the named probes against ``adapter`` -> {canonical name: ProbeResult}.

    A probe that RAISES is recorded as a failed measurement naming the exception -- a crashing
    probe must never abort the ladder into an unknown state, and must never look like a pass.
    Unknown probe names refuse loudly rather than degrade.
    """
    out: dict = {}
    for requested in tuple(names or ()):
        requested = str(requested)
        key = _ALIASES.get(requested, requested)
        probe = _PROBES.get(key)
        if probe is None:
            raise KeyError("unknown conformance probe %r; known: %s"
                           % (requested, sorted(set(_ALIASES) | set(_PROBES))))
        try:
            result = probe(adapter)
        except Exception as exc:  # noqa: BLE001 - a probe reports; it does not crash the suite
            result = ProbeResult(key, False, "probe raised: %r" % (exc,))
        canonical = _key_of(probe)
        out[canonical] = (result if result.name == canonical
                          else ProbeResult(canonical, result.passed, result.detail))
    return out


__all__ = ["ProbeResult", "TRANSPORTS", "CANONICAL_PROBE_NAMES", "run_probes"]

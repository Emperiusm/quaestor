"""sweep -- run the conformance probes, record the COMPUTED levels, feed the shipped surfaces.

WHY THIS MODULE EXISTS (bd quaestor-ru1.18)
-------------------------------------------
EPIC P1 promises integration assurance "recorded durably and honestly derived". The derivation
(``assurance``) and the durable record (``record``) were honest and well built -- and had ZERO
callers in src/. No CLI verb ran a probe; doctor and Settings emitted only
``registry_summary()``, which is what adapters SELF-DECLARE. In a real deployment no assurance
level was ever computed, recorded, or shown. This module is the caller: it measures every
reference transport with the SAME probes the control suite uses, records the computation
durably via ``record_assurance``, and returns rows for `doctor` and the Settings view.

CLAIMS, HONESTLY PLACED (§31)
-----------------------------
An adapter can never declare its own level, so the claims here are NOT the adapters': they are
the PRODUCT's tier claims about its own reference transports (direction §5.2 -- filebox and
command are DIALOGUE transports, the transcript observer is observe-only), written once in
``REFERENCE_CLAIMS``. The claim is an INPUT to ``compute_assurance``; the row's authoritative
level is always the COMPUTED one, and every claimed-but-unproven rung is recorded as a refusal
naming its missing probes.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from quaestor.adapters.assurance import DIALOGUE, OBSERVED, compute_assurance
from quaestor.adapters.probes import CANONICAL_PROBE_NAMES, run_probes
from quaestor.adapters.record import record_assurance

SWEEP_INSTRUMENT = "adapters.sweep/1"

#: See the module docstring: the product's tier claims for its OWN reference transports.
REFERENCE_CLAIMS: dict = {
    "file-inbox-outbox": DIALOGUE,
    "command": DIALOGUE,
    "clipboard": DIALOGUE,
    "transcript-observer": OBSERVED,
}

#: Transports the AUTOMATED sweep deliberately does not measure, with the named reason recorded
#: instead of a fabricated row. The clipboard is MANUAL MODE (§5.2 Tier 1): its round-trip needs
#: a human to paste -- and measuring it automatically would write the probe marker into the
#: operator's clipboard, a hostile side effect for a diagnostic command. Its claim stands
#: recorded; its level stays unproven until a probe is run deliberately.
SWEEP_SKIPS: dict = {
    "clipboard": "manual-mode transport: the dialogue round-trip needs a human paste, so the "
                 "automated sweep does not measure it (and must not touch the operator's "
                 "clipboard)",
}

#: A real stdin/stdout echo agent for the command seat's probe fixture -- same shape as the
#: control suite's, so the measured path and the tested path are the same code.
_ECHO_AGENT = ("import sys\n"
               "data = sys.stdin.read()\n"
               "sys.stdout.write(data)\n")


def _fixture(kind: str, tmp: str):
    """Construct the probe instance for a reference transport, or None. Impure (spawns/files)."""
    from quaestor.adapters import _REGISTRY
    cls = _REGISTRY.get(kind)
    if cls is None or kind in SWEEP_SKIPS:
        return None
    if kind == "file-inbox-outbox":
        return cls(tempfile.mkdtemp(prefix="sweep-fb-", dir=tmp),
                   responder=lambda env: env["payload"])
    if kind == "command":
        return cls([sys.executable, "-c", _ECHO_AGENT],
                   cwd=tempfile.mkdtemp(prefix="sweep-cmd-", dir=tmp), timeout_s=30)
    if kind == "transcript-observer":
        d = tempfile.mkdtemp(prefix="sweep-tr-", dir=tmp)
        (Path(d) / "sweep.jsonl").write_text(
            json.dumps({"role": "assistant", "content": "sweep"}) + "\n", encoding="utf-8")
        return cls(str(Path(d) / "*.jsonl"))
    return None


def _measure(adapter, claim: str) -> tuple:
    """(results, row body) for one adapter. Impure (probes run). Runs each probe ONCE."""
    results = run_probes(adapter, CANONICAL_PROBE_NAMES)
    passed = {name: res.passed for name, res in results.items()}
    computed, refusals = compute_assurance(passed, str(claim))
    body = {"claimed_level": str(claim),
            "computed_level": computed,
            "refusals": list(refusals),
            "probes": {name: {"passed": res.passed, "detail": res.detail}
                       for name, res in results.items()}}
    return results, body


def sweep_adapter(adapter, claim: str) -> dict:
    """Measure ONE adapter against the FULL canonical probe set. Impure (probes run).

    Every probe runs: one that cannot measure FAILS with a named reason, it never aborts the
    sweep -- and an unmeasured dimension is never silently scored as a pass (§5.3).
    """
    _results, body = _measure(adapter, claim)
    return body


def run_assurance_sweep(store_like=None) -> list:
    """Measure every registered reference adapter; record durably; return the rows.

    ``store_like`` needs only ``Store.append_event``'s signature. A kind this build has no
    probe fixture for is reported as NOT MEASURED -- visible absence, never a fabricated row.
    """
    from quaestor.adapters import _REGISTRY
    tmp = tempfile.mkdtemp(prefix="sweep-")
    rows: list = []
    for kind in sorted(_REGISTRY):
        claim = REFERENCE_CLAIMS.get(kind, OBSERVED)
        if kind in SWEEP_SKIPS:
            rows.append({"adapter": kind, "measured": False, "claimed_level": claim,
                         "computed_level": "", "detail": SWEEP_SKIPS[kind]})
            continue
        adapter = _fixture(kind, tmp)
        if adapter is None:
            rows.append({"adapter": kind, "measured": False, "claimed_level": claim,
                         "computed_level": "",
                         "detail": "no probe fixture for this adapter kind; declared but "
                                   "unmeasured by this sweep"})
            continue
        results, body = _measure(adapter, claim)
        row = {"adapter": kind, "measured": True}
        row.update(body)
        if store_like is not None:
            row["recorded_event"] = record_assurance(store_like, "adapter/%s" % kind,
                                                     claim, results)
        rows.append(row)
    return rows

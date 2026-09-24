"""ASSURANCE SURFACE CONTROLS (242-243) -- bd quaestor-ru1.18, quaestor-ru1.21.

    CONTROL_DECLARED  does not imply
    CONTROL_REACHABLE does not imply
    CONTROL_EFFECTIVE

Two unreachable-honesty defects. ru1.18: compute_assurance/record_assurance were honest and
well built, with ZERO src callers -- no surface ever showed a COMPUTED level, only
self-declarations. ru1.21: the registry surface read the CLASS capability attribute while the
runtime gate read the constructor mapping; a verifier measured doctor advertising capabilities
the running object returned all-False for. These controls prove the PRODUCT properties: the
shipped surfaces report measured levels from durable records, and the two capability channels
cannot disagree silently.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.adapters import register, registered_adapters  # noqa: E402
from quaestor.adapters.assurance import CONFINED, DIALOGUE, OBSERVED  # noqa: E402
from quaestor.adapters.base import CAPABILITY_CHANNELS_DISAGREE, AgentAdapter  # noqa: E402
from quaestor.adapters.sweep import (REFERENCE_CLAIMS, run_assurance_sweep,  # noqa: E402
                                     sweep_adapter)
from quaestor.core.store import Store  # noqa: E402
from quaestor.transports import cli as cli_mod  # noqa: E402
from quaestor.transports import webui as webui_mod  # noqa: E402
from tests.controls import control  # noqa: E402


# =============================================================================================
# 242 -- the shipped surfaces report a COMPUTED level, not a declaration
# =============================================================================================
class TestAssuranceSurface(unittest.TestCase):
    def test_sweep_measures_records_and_the_settings_view_shows_computed(self):
        @control(242)
        def body():
            home = tempfile.mkdtemp(prefix="quaestor-assurance-")
            db, _runs = cli_mod._paths(home)
            store = Store(db)
            try:
                rows = run_assurance_sweep(store)          # what cmd_doctor runs
            finally:
                store.close()
            by_kind = {row["adapter"]: row for row in rows}
            # Every reference transport has an HONEST row: measured with probe evidence, or
            # unmeasured with a named reason (the clipboard is manual mode -- the automated
            # sweep must not write into the operator's clipboard).
            for kind in sorted(REFERENCE_CLAIMS):
                row = by_kind[kind]
                self.assertIn("measured", row, kind)
                if kind in ("clipboard",):
                    self.assertFalse(row["measured"], kind)
                    self.assertIn("manual-mode", row["detail"], kind)
                    continue
                self.assertTrue(row["measured"], kind)
                self.assertTrue(row["probes"], "%s: no probes ran" % kind)
            # The two dialogue transports and the observer compute EXACTLY their product tier
            # -- from probes, not from the declaration table.
            self.assertEqual(by_kind["file-inbox-outbox"]["computed_level"], DIALOGUE)
            self.assertEqual(by_kind["command"]["computed_level"], DIALOGUE)
            self.assertEqual(by_kind["transcript-observer"]["computed_level"], OBSERVED)
            # The computation was RECORDED durably (the defect was "never computed, recorded,
            # or shown"), and the Settings surface reads the durable record, showing the
            # COMPUTED level with its claim -- a measurement, not a registry declaration.
            for kind in ("file-inbox-outbox", "command", "transcript-observer"):
                self.assertIn("recorded_event", by_kind[kind], kind)
            payload = webui_mod.settings_payload(home)
            shown = {row["adapter"]: row for row in payload["assurance"]}
            for kind in ("file-inbox-outbox", "command", "transcript-observer"):
                self.assertEqual(shown[kind]["computed_level"],
                                 by_kind[kind]["computed_level"], kind)
                self.assertEqual(shown[kind]["claimed_level"], REFERENCE_CLAIMS[kind], kind)
            # The durable rows exist on disk, one per MEASURED reference transport.
            import sqlite3
            conn = sqlite3.connect(db)
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM event WHERE kind='adapter.assurance'").fetchone()[0]
            finally:
                conn.close()
            self.assertEqual(count, 3)
        body()

    def test_an_over_claiming_sweep_row_reports_measured_level_and_names_the_gap(self):
        """§31's teeth, at the surface: claim above proof computes DOWN and refuses by name."""
        @control(242)
        def body():
            with tempfile.TemporaryDirectory() as tmp:
                from quaestor.adapters import _REGISTRY
                fb = _REGISTRY["file-inbox-outbox"](
                    tmp, responder=lambda env: env["payload"])
                row = sweep_adapter(fb, CONFINED)   # claim the TOP of the ladder
            self.assertEqual(row["claimed_level"], CONFINED)
            self.assertNotEqual(row["computed_level"], CONFINED,
                                "unproven confinement must not compute as proven")
            self.assertTrue(row["refusals"],
                            "an over-claim with no refusal teaches nothing")
            joined = " ".join(row["refusals"])
            self.assertIn("container_validation", joined)
        body()


# =============================================================================================
# 243 -- one capability fact, one channel (or a named refusal)
# =============================================================================================
class _ConsistentAdapter(AgentAdapter):
    """Class channel and constructor channel say the same thing."""

    ADAPTER_KIND = "consistent-probe"
    DECLARED_CAPABILITIES = ("cancellation",)

    def __init__(self):
        super().__init__("consistent-1", declared={"cancellation": True})

    def send(self, message) -> None:
        raise NotImplementedError

    def receive(self):
        return None


class _OverclaimingAdapter(AgentAdapter):
    """The verifier's measured defect, reproduced: class advertises, instance does not."""

    ADAPTER_KIND = "overclaim-probe"
    DECLARED_CAPABILITIES = ("cancellation", "start", "stop")

    def __init__(self):
        super().__init__("overclaim-1")   # constructor channel says NOTHING

    def send(self, message) -> None:
        raise NotImplementedError

    def receive(self):
        return None


class _UnderclaimingAdapter(AgentAdapter):
    """The mirror defect: class says nothing, constructor claims the world."""

    ADAPTER_KIND = "underclaim-probe"
    DECLARED_CAPABILITIES = ()

    def __init__(self):
        super().__init__("underclaim-1", declared={"start": True, "stop": True})

    def send(self, message) -> None:
        raise NotImplementedError

    def receive(self):
        return None


class _ConflictingAdapter(AgentAdapter):
    """Explicit constructor mapping that disagrees with the class channel."""

    ADAPTER_KIND = "conflicting-probe"
    DECLARED_CAPABILITIES = ("cancellation", "start", "stop")

    def __init__(self):
        super().__init__("conflicting-1", declared={"cancellation": True})

    def send(self, message) -> None:
        raise NotImplementedError

    def receive(self):
        return None


class TestCapabilityChannels(unittest.TestCase):
    def setUp(self):
        from quaestor.adapters import _REGISTRY
        self._added = []
        for cls in (_ConsistentAdapter, _OverclaimingAdapter, _UnderclaimingAdapter,
                    _ConflictingAdapter):
            _REGISTRY.pop(cls.ADAPTER_KIND, None)
            register(cls)
            self._added.append(cls.ADAPTER_KIND)

    def tearDown(self):
        from quaestor.adapters import _REGISTRY
        for kind in self._added:
            _REGISTRY.pop(kind, None)

    @control(243)
    def test_disagreeing_channels_refuse_by_name_and_the_surface_cannot_advertise(self):
        # THE VERIFIER'S DEFECT, RETIRED TWICE OVER. Constructed with no constructor mapping,
        # the instance now DERIVES its declaration from the class attribute -- so the runtime
        # capabilities() equal what the registry surface shows, and the "unbacked capability"
        # the surface used to advertise is backed by the running object itself.
        drifted = _OverclaimingAdapter()
        self.assertTrue(drifted.capabilities().get("cancellation"))
        self.assertTrue(drifted.capabilities().get("start"))
        summary = {entry["adapter"]: entry for entry in registered_adapters()}
        shown = sorted(cap for cap, ok in drifted.capabilities().items() if ok)
        self.assertEqual(summary["overclaim-probe"]["capabilities"], shown)
        # An EXPLICIT constructor mapping that DISAGREES with the class channel refuses BY
        # NAME -- the one remaining way the two channels could diverge.
        with self.assertRaises(ValueError) as ctx:
            _ConflictingAdapter()
        self.assertIn(CAPABILITY_CHANNELS_DISAGREE, str(ctx.exception))
        self.assertIn("start", str(ctx.exception))
        # The mirror direction refuses too: an instance claiming what its class does not.
        with self.assertRaises(ValueError) as ctx2:
            _UnderclaimingAdapter()
        self.assertIn(CAPABILITY_CHANNELS_DISAGREE, str(ctx2.exception))
        # A conforming adapter constructs, and its runtime capabilities() EQUAL what the
        # registry surface shows for its class -- one fact, one channel, no drift.
        adapter = _ConsistentAdapter()
        self.assertTrue(adapter.capabilities().get("cancellation"))
        self.assertFalse(adapter.capabilities().get("start"))
        self.assertEqual(summary["consistent-probe"]["capabilities"], ["cancellation"])

    def test_an_unknown_capability_in_the_class_channel_is_refused(self):
        class _Bad(AgentAdapter):
            ADAPTER_KIND = "bad-probe"
            DECLARED_CAPABILITIES = ("make_me_immortal",)

            def __init__(self):
                super().__init__("bad-1")

            def send(self, message) -> None:
                raise NotImplementedError

            def receive(self):
                return None
        with self.assertRaises(ValueError) as ctx:
            _Bad()
        self.assertIn("make_me_immortal", str(ctx.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

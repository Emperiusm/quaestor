"""ADAPTER ASSURANCE CONTROLS (221-230) -- measured levels, never self-declared.

Direction §31: "Adapter assurance is MEASURED by conformance probes (can it cancel? does
send/receive round-trip? does it leak prompts via argv? does read-only stay read-only?); an
adapter can never declare its own level." Every control here drives that rule from both sides:
a conforming FakeAdapter must EARN its rung, and a sabotaged one must have its over-claim named,
because an assurance ladder that only ever hears "yes" is CONTROL_DECLARED != CONTROL_EFFECTIVE
wearing a lab coat.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.adapters import (  # noqa: E402
    AgentAdapter, register, registered_adapters, registry_summary)
from quaestor.adapters.assurance import (  # noqa: E402
    ASSURANCE_LEVELS, compute_assurance, required_for)
from quaestor.adapters.probes import ProbeResult, run_probes  # noqa: E402
from quaestor.adapters.record import EVENT_KIND, record_assurance  # noqa: E402
from tests.controls import control  # noqa: E402

#: The full conforming evidence set: every probe every level needs, all passed.
ALL_PASS = {name: True for name in required_for("CONFINED")}
#: §5.13 dimensions the fake answers through its harness.
CONFORMING_HARNESS = {
    "observe": True, "prompt_transport": "STDIN", "read_only": True,
    "workspace_root": "/workspace", "outside_write_succeeded": False,
    "container_validated": True, "cancelled_after_cancel": True,
    "resumed_after_reconnect": True, "ack_cursor_restored": True,
}


class FakeAdapter(AgentAdapter):
    """A dialogue+managed+governed adapter driven entirely by harness facts."""

    ADAPTER_KIND = "fake-dialogue"

    def __init__(self, harness=None, sabotage=None):
        super().__init__("fake-1", declared={
            "start": True, "stop": True, "pause": True, "resume": True, "status": True,
            "cancellation": True})
        self.conformance_harness = dict(CONFORMING_HARNESS)
        self.conformance_harness.update(harness or {})
        self.sabotage = set(sabotage or ())
        self._inbox = []
        self._drop_ids = "drop_ids" in self.sabotage
        self._state = "idle"

    def send(self, message):
        self._inbox.append(dict(message))

    def receive(self):
        if not self._inbox:
            return None
        msg = dict(self._inbox.pop(0))
        if self._drop_ids and isinstance(msg, dict):
            msg.pop("message_id", None)
        return msg

    def attempt_mutation(self):
        # A read-only adapter REFUSES; the sabotage variant "succeeds", which is exactly the
        # drift the readonly probe exists to catch.
        if "readonly_violation" in self.sabotage:
            return "wrote-anyway"
        return False

    def cancellation(self):
        if "fake_cancel" in self.sabotage:
            self.conformance_harness["cancelled_after_cancel"] = False
            return
        self.conformance_harness["cancelled_after_cancel"] = True

    def start(self):
        self._state = "started"

    def pause(self):
        self._state = "paused"

    def resume(self):
        self._state = "running"

    def stop(self):
        self._state = "stopped"

    def status(self):
        return {"state": self._state, "adapter": self.adapter_id}


class RecordingStore:
    """store_like: captures append_event kwargs the way Store would persist them."""

    def __init__(self):
        self.events = []

    def append_event(self, kind, *, run_id="", dispatch_key="", from_state=None,
                     to_state=None, detail=None) -> int:
        self.events.append({"kind": kind, "run_id": run_id, "dispatch_key": dispatch_key,
                            "detail": dict(detail or {})})
        return len(self.events)


class TestAssuranceTable(unittest.TestCase):
    @control(221)
    def test_each_levels_full_probe_set_computes_exactly_that_level(self):
        """Happy path per rung: feed required_for(level) all-passed, get exactly that level."""
        for level in ASSURANCE_LEVELS:
            evidence = {name: True for name in required_for(level)}
            computed, refusals = compute_assurance(evidence, claimed=level)
            self.assertEqual(computed, level, "claimed %s computed %s" % (level, computed))
            self.assertEqual(refusals, (), "a claim AT proof must not be refused")

    @control(222)
    def test_every_over_claim_refusal_names_the_missing_probes(self):
        """Claiming above proof is refused BY NAME -- 'no' without the gap teaches nothing."""
        for idx, claimed in enumerate(ASSURANCE_LEVELS):
            for proven in ASSURANCE_LEVELS[:idx]:
                missing = [p for p in required_for(claimed) if p not in required_for(proven)]
                evidence = {name: True for name in required_for(proven)}
                computed, refusals = compute_assurance(evidence, claimed=claimed)
                self.assertTrue(ASSURANCE_LEVELS.index(computed)
                                < ASSURANCE_LEVELS.index(claimed))
                joined = "\n".join(refusals)
                self.assertTrue(refusals, "%s over %s produced no refusal at all"
                                % (claimed, proven))
                for probe in missing:
                    self.assertIn(probe, joined,
                                  "%s claimed over %s: refusal does not name %s"
                                  % (claimed, proven, probe))

    @control(223)
    def test_claim_at_proof_is_clean_and_below_observed_refuses_observed(self):
        """Under-claiming records the HIGHER proven level and refuses nothing; proving NOTHING
        refuses even OBSERVED -- by naming observe_probe."""
        computed, refusals = compute_assurance(ALL_PASS, claimed="OBSERVED")
        self.assertEqual((computed, refusals), ("CONFINED", ()),
                         "proof above the claim is recorded honestly, not clipped down")
        computed, refusals = compute_assurance({"roundtrip": True}, claimed="OBSERVED")
        self.assertEqual(computed, "")
        self.assertIn("observe_probe", "\n".join(refusals))


class TestProbes(unittest.TestCase):
    @control(224)
    def test_prompt_transport_leak_check_fails_argv_passes_stdin_pipe(self):
        """§5.13: ARGV publishes the prompt to any local process-table reader; STDIN/PIPE do
        not. An undeclared transport fails too -- unmeasured is never a pass."""
        for transport, want in (("ARGV", False), ("STDIN", True), ("PIPE", True),
                                ("IPC", True), ("TEMP_FILE", True), ("TELEPATHY", False)):
            r = run_probes(FakeAdapter(harness={"prompt_transport": transport}),
                           ["prompt_transport_leak_check"])["prompt_transport_leak_check"]
            self.assertEqual(r.passed, want, "%s -> %s (%s)" % (transport, r.passed, r.detail))

    @control(225)
    def test_roundtrip_and_message_ids_survive_and_drops_are_detected(self):
        """Conforming adapter round-trips payloads AND ids across reconnect; the id-dropping
        sabotage is caught by name rather than silently absorbed."""
        good = run_probes(FakeAdapter(), ["send_receive_roundtrip", "message_id_preserved"])
        self.assertTrue(all(r.passed for r in good.values()), str(good))
        bad = run_probes(FakeAdapter(sabotage={"drop_ids"}), ["message_id_preserved"])
        self.assertFalse(bad["message_id_preserved"].passed)
        self.assertIn("qm-1", bad["message_id_preserved"].detail)

    @control(226)
    def test_cancel_actually_cancels_and_a_decorative_cancel_is_caught(self):
        """MANAGED tier: cancel must stop work. A cancel that leaves work running fails --
        that IS the CONTROL_DECLARED != CONTROL_EFFECTIVE class, caught at the edge."""
        ok = run_probes(FakeAdapter(), ["cancel_actually_cancels", "lifecycle_probe"])
        self.assertTrue(ok["cancel_works"].passed, ok["cancel_works"].detail)
        self.assertTrue(ok["lifecycle"].passed, ok["lifecycle"].detail)
        bad = run_probes(FakeAdapter(sabotage={"fake_cancel"}), ["cancel_works"])
        self.assertFalse(bad["cancel_works"].passed)
        self.assertIn("CONTROL_DECLARED", bad["cancel_works"].detail)

    @control(227)
    def test_readonly_holds_under_provocation_and_violations_are_detected(self):
        """GOVERNED tier: provoked mutation refused -> pass; write goes through -> fail."""
        ok = run_probes(FakeAdapter(), ["readonly_stays_readonly"])["readonly_holds"]
        self.assertTrue(ok.passed, ok.detail)
        bad = run_probes(FakeAdapter(sabotage={"readonly_violation"}),
                         ["readonly_holds"])["readonly_holds"]
        self.assertFalse(bad.passed)
        self.assertIn("DECLARED", bad.detail)

    @control(228)
    def test_no_write_outside_the_claimed_workspace_succeeds(self):
        """GOVERNED tier: containment is measured against the CLAIMED root; an escape that
        succeeded flips the result instead of being argued away."""
        ok = run_probes(FakeAdapter(), ["workspace_write_containment"])
        self.assertTrue(ok["workspace_containment"].passed, ok["workspace_containment"].detail)
        bad = run_probes(FakeAdapter(harness={"outside_write_succeeded": True}),
                         ["workspace_containment"])["workspace_containment"]
        self.assertFalse(bad.passed)
        self.assertIn("/workspace", bad.detail)


class TestRecordAndRegistry(unittest.TestCase):
    @control(229)
    def test_resume_holds_and_the_durable_record_carries_computed_le_claimed(self):
        """§5.12 resume-after-reconnect passes conforming; the recorded event shows BOTH levels
        plus refusals, and computed never exceeds what the probes proved."""
        ok = run_probes(FakeAdapter(), ["resume_after_reconnect"])["resume_after_reconnect"]
        self.assertTrue(ok.passed, ok.detail)

        store = RecordingStore()
        over_results = run_probes(FakeAdapter(), ["observe_probe", "roundtrip",
                                                  "message_id_preserved"])
        record_assurance(store, "lane/clipboard-cursor", "GOVERNED", over_results)
        ev = store.events[-1]
        self.assertEqual(ev["kind"], EVENT_KIND)
        self.assertEqual(ev["dispatch_key"], "lane/clipboard-cursor")
        d = ev["detail"]
        self.assertEqual(d["claimed_level"], "GOVERNED")
        self.assertEqual(d["computed_level"], "DIALOGUE")
        self.assertTrue(d["computed_within_claimed"] is False or d["refusals"],
                        "an over-claim must be visible as refusals in the durable record")
        self.assertIn("workspace_containment", "\n".join(d["refusals"]))
        # And a conforming CONFINED lane records computed == claimed with no refusals.
        record_assurance(store, "lane/container-x", "CONFINED",
                         {k: ProbeResult(k, True, "") for k in ALL_PASS}
                         | {"prompt_transport_leak_check": ProbeResult(
                             "prompt_transport_leak_check", True, "STDIN")})
        good = store.events[-1]["detail"]
        self.assertEqual(good["computed_level"], "CONFINED")
        self.assertEqual(good["refusals"], [])
        self.assertTrue(good["computed_within_claimed"])

    @control(230)
    def test_registry_feeds_doctor_and_empty_registry_renders_empty_list(self):
        """`doctor` shows WHICH adapters exist; absence renders as [] rather than vanishing.
        Wiring is asserted against the real cmd_doctor source so the key cannot silently die."""
        import inspect
        from quaestor.transports import cli as cli_mod

        @register
        class _ProbeAdapter(FakeAdapter):
            ADAPTER_KIND = "probe-only"

        try:
            summary = registry_summary()
            self.assertIn("probe-only", [e["adapter"] for e in summary])
            src = inspect.getsource(cli_mod.cmd_doctor)
            self.assertIn('"adapters"', src)
            self.assertIn("registry_summary", src)
        finally:
            from quaestor.adapters import _REGISTRY
            _REGISTRY.pop("probe-only", None)
        self.assertNotIn("probe-only", [e["adapter"] for e in registered_adapters()])
        self.assertIsInstance(registry_summary(), list)
        self.assertEqual(AgentAdapter.__module__, "quaestor.adapters.base")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

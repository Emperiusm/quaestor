"""test_context_capsule -- CONTROLS for CONTEXT CAPSULES: token-budgeted, role-shaped seat
replacement reconstructed from durable state alone (direction section 14.1; bd quaestor-kaz.7).

THE INVARIANTS THESE CONTROLS PIN
---------------------------------
  * REPRODUCIBLE AND HASHABLE. Same durable state -> byte-identical capsule AND identical
    capsule_sha256; any durable change moves the hash. A capsule a seat cannot re-derive is a
    rumour, not canonical state.

  * BUDGETED WITH AN HONEST MARKER. Sections emit oldest-first under a hard character budget;
    what does not fit is DROPPED and REPLACED BY AN EXPLICIT TRUNCATION MARKER -- an omitted
    fact is stated as omitted, never silently absent.

  * WIRED INTO SEAT CHANGE. The resume / crash-recovery re-dispatch path injects the capsule
    into the child's task when a directive is outstanding OR the provider differs from the
    previous attempt's MEASURED run.provenance ("Claude disappears; Codex takes the seat;
    Quaestor constructs the capsule").

  * NEVER A TRANSCRIPT. There is no transcript field in a capsule; message payloads enter only
    as bounded excerpts; long transcripts appear only truncated.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import messages as msg_mod                    # noqa: E402
from quaestor.core import orchestrator as orch                   # noqa: E402
from quaestor.core import strategic_store as ss_mod              # noqa: E402
from quaestor.core.strategic_store import capsule_text           # noqa: E402
from tests.test_operational_e2e import EngineHarness, fake_preflight  # noqa: E402


def _lane_with_history(h):
    """One implementation lane carrying decisions, observations, a blocker and a question."""
    pid, lanes = h.new_program(
        "capsules", "Build the widget",
        [{"key": "main", "title": "build-widget", "task": "Build it.", "acceptance": ("ok",)}])
    lane_id = lanes["main"]
    from quaestor.core import decisions as dec_mod
    h.sstore.record_decision(dec_mod.new_decision(
        pid, "Widget format?", decision="JSON, versioned",
        rationale="consumers need stable contracts", actor_id="strategist-A"))
    m_obs = msg_mod.new_message(msg_mod.OBSERVATION, actor_id="executor:fake",
                                program_id=pid, lane_id=lane_id,
                                payload="The vendor library needs a shim.")
    h.sstore.record_message(m_obs)
    m_block = msg_mod.new_message(msg_mod.BLOCKER, actor_id="scheduler",
                                  program_id=pid, lane_id=lane_id,
                                  payload="dependency sync failed twice")
    h.sstore.record_message(m_block)
    m_q = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="executor:fake",
                              program_id=pid, lane_id=lane_id,
                              payload="Should the shim be lazy or eager?")
    h.sstore.record_message(m_q)
    return pid, lane_id


class TestDeterminism(unittest.TestCase):
    """CONTROLS: reproducibility from canonical state; hash stability."""

    def test_same_state_yields_identical_capsule_and_hash(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid, lane_id = _lane_with_history(h)
        c1 = h.sstore.context_capsule(lane_id)
        c2 = h.sstore.context_capsule(lane_id)
        self.assertEqual(c1, c2)
        self.assertEqual(c1["capsule_sha256"], c2["capsule_sha256"])
        self.assertTrue(c1["capsule_sha256"])
        self.assertGreater(c1["budget_used_chars"], 0)

    def test_any_durable_change_moves_the_hash(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid, lane_id = _lane_with_history(h)
        base_sha = h.sstore.context_capsule(lane_id)["capsule_sha256"]
        newer = msg_mod.new_message(msg_mod.OBSERVATION, actor_id="executor:fake",
                                    program_id=pid, lane_id=lane_id,
                                    payload="A later fact changed the picture.")
        h.sstore.record_message(newer)
        self.assertNotEqual(base_sha, h.sstore.context_capsule(lane_id)["capsule_sha256"])

    def test_role_shaping_changes_the_capsule(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        _, lane_id = _lane_with_history(h)
        builder = h.sstore.context_capsule(lane_id, role="implementation")
        reviewer = h.sstore.context_capsule(lane_id, role="adversarial_review")
        self.assertNotEqual(builder["capsule_sha256"], reviewer["capsule_sha256"])
        # The order IS the shaping: a reviewer sees findings before history.
        self.assertLess(list(reviewer).index("review_findings"),
                        list(reviewer).index("decisions"))
        ckpt = h.sstore.get_lane_task(lane_id)["checkpoint"]
        ckpt["fix_findings"] = [{"title": "missing test", "severity": "HIGH",
                                 "failure_mode": "acceptance unverified"}]
        h.sstore.save_checkpoint(lane_id, ckpt)
        shaped = h.sstore.context_capsule(lane_id, role="adversarial_review")
        self.assertTrue(any("missing test" in e for e in shaped["review_findings"]))
        self.assertEqual(shaped["role"], "adversarial_review")


class TestBudgetTruncation(unittest.TestCase):
    """CONTROLS: oldest-first emission under budget, with an explicit truncation marker."""

    def test_tiny_budget_truncates_and_marks(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        _, lane_id = _lane_with_history(h)
        tiny = h.sstore.context_capsule(lane_id, token_budget=64)
        markers = [e for sec in ("decisions", "recent_observations", "blockers",
                                 "open_questions", "dependency_outputs")
                   for e in tiny.get(sec, ()) if e.startswith("[...truncated:")]
        self.assertTrue(markers, "a starved budget must say what it omitted")
        self.assertTrue(tiny["truncated_sections"])
        self.assertLessEqual(tiny["budget_used_chars"],
                             64 * ss_mod.StrategicStore.CHARS_PER_TOKEN + 4096,
                             "budget_used_chars must stay near the enforced bound")

    def test_roomy_budget_truncates_nothing(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        _, lane_id = _lane_with_history(h)
        roomy = h.sstore.context_capsule(lane_id, token_budget=100_000)
        self.assertEqual(roomy["truncated_sections"], [])
        self.assertIn("JSON, versioned", "\n".join(roomy["decisions"]))
        self.assertTrue(any("vendor library" in e for e in roomy["recent_observations"]))
        self.assertTrue(any("lazy or eager" in e for e in roomy["open_questions"]))
        rendered = capsule_text(roomy)
        self.assertIn("OBJECTIVE:", rendered)
        self.assertIn("never a transcript", rendered)


class TestNoTranscriptRule(unittest.TestCase):
    """CONTROLS: capsules never carry transcript material."""

    def test_payloads_enter_only_as_bounded_excerpts(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid, lane_id = _lane_with_history(h)
        huge = "".join("%d: some transcript line.\n" % i for i in range(500))
        h.sstore.record_message(msg_mod.new_message(
            msg_mod.OBSERVATION, actor_id="executor:fake", program_id=pid, lane_id=lane_id,
            payload=huge))
        cap = h.sstore.context_capsule(lane_id)
        entries = "\n".join(cap["recent_observations"])
        self.assertNotIn(huge, entries)
        for e in cap["recent_observations"]:
            self.assertLessEqual(len(e), ss_mod.StrategicStore.CAPSULE_EXCERPT_CHARS + 8)
        # No transcript-shaped field may exist at all.
        banned = ("transcript", "stdout", "stderr", "report_markdown", "session")
        for key in cap:
            self.assertFalse(any(b in key.lower() for b in banned), key)
        self.assertLess(len(cap["recent_observations"]),
                        ss_mod.StrategicStore.CAPSULE_OBSERVATION_WINDOW + 1)


class TestSeatChangeWiring(unittest.TestCase):
    """CONTROLS: the resume path injects the capsule on directive OR measured seat change."""

    def test_resume_after_directive_injects_capsule(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Should divide-by-zero raise or return None?"}]}}
        finish = {"kind": "fake", "config": {"scenario": "OK_PASS"}}
        variants = [ask, finish]
        pid, lanes = h.new_program(
            "capsule resume", "Implement div after clarifying.",
            [{"key": "main", "title": "ask-then-finish",
              "executor": {"kind": "fake", "attempt_variants": variants},
              "acceptance": ("div works",)}])
        h.tick(pid)
        ib = orch.inbox(h.sstore, pid)
        mid = next(i["message_id"] for i in ib["items"] if i["kind"] == "DECISION_REQUEST")
        orch.answer(h.sstore, pid, mid, decision_text="Raise ValueError.", actor_id="s1")
        h.tick(pid)          # reap the answered run -> PLANNED again
        r = h.tick(pid)      # resume dispatch carries the directive AND the capsule
        del r
        bindings = h.sstore.runs_for_lane(lanes["main"])
        prompts = []
        from quaestor.core import runfiles as rf
        for b in bindings:
            run = h.store.get_run(b["run_id"])
            req = rf.read_json(rf.p(str(run["run_dir"]), rf.REQUEST))
            prompts.append(str(req.get("prompt") or ""))
        resumed = [p for p in prompts if "STRATEGIST DECISION" in p]
        self.assertTrue(resumed, "the resumed dispatch must exist")
        self.assertIn("CONTEXT CAPSULE", resumed[-1])
        self.assertIn("capsule_sha256", resumed[-1])

    def test_provider_change_from_measured_provenance_injects_capsule(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        # Attempt 0 asks a question under `fake` (measured provenance: provider=fake) and pauses
        # safely. The scripted attempt 1 names a DIFFERENT provider kind -- gpt-plan is
        # declared-but-unconstructible, so the tolerant spawner below is used and NOTHING real
        # can ever launch; the control reads the REQUEST artifact the new holder would receive.
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Should divide-by-zero raise or return None?"}]}}
        pid, lanes = h.new_program(
            "capsule failover", "Do the thing.",
            [{"key": "main", "title": "swap-seat",
              "executor": {"kind": "fake",
                           "attempt_variants": [ask, {"kind": "gpt-plan"}]},
              "acceptance": ("done",)}])
        h.tick(pid)      # attempt 0: fake asks; lane WAITING_FOR_STRATEGIST
        ib = orch.inbox(h.sstore, pid)
        mid = next(i["message_id"] for i in ib["items"] if i["kind"] == "DECISION_REQUEST")
        orch.answer(h.sstore, pid, mid, decision_text="Raise.", actor_id="s1")

        def tolerant_spawner(*, db_path, run_id):
            # Records the spawn WITHOUT constructing any executor child.
            return os.getpid()

        r2 = orch.tick(h.home, h.sstore, h.store, program_id=pid, cfg=h.cfg,
                       preflight=fake_preflight, spawner=tolerant_spawner)
        del r2
        binding = next(b for b in reversed(h.sstore.runs_for_lane(lanes["main"])))
        from quaestor.core import runfiles as rf
        run = h.store.get_run(binding["run_id"])
        req = rf.read_json(rf.p(str(run["run_dir"]), rf.REQUEST))
        prompt = str(req.get("prompt") or "")
        self.assertIn("STRATEGIST DECISION", prompt)
        self.assertIn("CONTEXT CAPSULE", prompt,
                      "a provider change must hand the new seat a capsule")
        self.assertIn("role=implementation", prompt)
        self.assertIn("capsule_sha256=", prompt)
        provs = [json.loads(e["detail_json"]) for e in h.store.events_for(binding["run_id"])
                 if e["kind"] == "run.provenance"]
        self.assertEqual(provs[-1]["provider"], "gpt-plan")

    def test_first_dispatch_of_a_lane_carries_no_capsule(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid, lanes = h.new_program(
            "first dispatch", "Do it.",
            [{"key": "main", "title": "t", "task": "t", "acceptance": ("a",)}])
        h.tick(pid)
        from quaestor.core import runfiles as rf
        b = h.sstore.runs_for_lane(lanes["main"])[0]
        run = h.store.get_run(b["run_id"])
        req = rf.read_json(rf.p(str(run["run_dir"]), rf.REQUEST))
        self.assertNotIn("CONTEXT CAPSULE", str(req.get("prompt")),
                         "a brand-new seat holder needs no replacement briefing")


if __name__ == "__main__":
    unittest.main()

"""test_planner_seat -- CONTROLS for the PLANNER seat: PLAN_PROPOSAL admission, the adversarial
plan challenge, and governed adoption (direction doc sections 3.1/3.3; bd quaestor-kaz.3/.8).

THE INVARIANTS THESE CONTROLS PIN
---------------------------------
Section 3.1: "the planner proposes, Quaestor disposes."

  * ADMISSION IS DETERMINISTIC AND PURE. Legal lane kinds only; dependencies acyclic and
    resolvable; acceptance present on implementation lanes; size bounds; and NO
    authority-bearing field anywhere outside the governed vocabulary -- a proposal is DATA.

  * THE PLANNER IS A SEAT, NOT A CONTROLLER. Its run goes through the SAME dispatch machinery,
    READ_ONLY, with measured run.provenance (role=planner). Its valid proposal becomes a
    PENDING document surfaced to the strategist inbox as PROPOSAL_PENDING_ADOPTION; adoption
    happens ONLY by a named strategist/owner actor and lands as a recorded DECISION carrying
    planner provenance.

  * THE PLANNER CANNOT SELF-ADOPT. The actor that held the planner seat is refused by name at
    the adoption door (PROPOSAL_PLANNER_SELF_ADOPT).

  * PLAN CHALLENGE (section 3.3). When policy asks (program_meta plan_challenge=true or a
    per-lane plan_review flag), _dispatch_reviewer targets the PROPOSAL packet with target
    class PLAN instead of a code diff; findings attach to the proposal; an unresolved CRITICAL/
    HIGH finding blocks adoption while require_plan_review stands; resolution is a recorded
    strategist DECISION.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import events as ev_mod                      # noqa: E402
from quaestor.core import orchestrator as orch                  # noqa: E402
from quaestor.core import review_contract as rc                 # noqa: E402
import quaestor.core.planner as planner_mod                     # noqa: E402
from tests.test_operational_e2e import EngineHarness            # noqa: E402


def _proposal(**overrides):
    """A minimal VALID proposal. Overrides replace whole lanes or fields."""
    doc = {
        "title": "Add sub() and cover it",
        "objective": "Add sub to mathlib with tests",
        "lanes": [
            {"key": "impl", "title": "implement sub", "kind": "implementation",
             "task": "Extend app/mathlib.py with sub(a, b).",
             "depends_on": [], "acceptance": ["sub(a, b) exists"]},
            {"key": "verify", "title": "verify sub", "kind": "verification",
             "task": "Run the project tests against sub().",
             "depends_on": ["impl"], "acceptance": ["tests pass"]},
        ],
    }
    doc.update(overrides)
    return doc


def _scripted_planner(proposal):
    return {"kind": "fake", "config": {
        "scenario": "OK_PASS",
        "messages": [{"type": "PLAN_REVISION", "payload": "Decomposition",
                      "detail": {"proposal": proposal}}]}}


def _new_planning_program(h):
    pid, _ = h.new_program("planner seat", "Add sub to mathlib with tests", [],
                           extra_meta={"planning_mode": "planner_seat"})
    h.sstore.set_program_meta(pid, "_planner_executor",
                              json.dumps(_scripted_planner(_proposal())))
    return pid


def _request_prompt(h, run_id):
    from quaestor.core import runfiles as rf
    run = h.store.get_run(run_id)
    req = rf.read_json(rf.p(str(run["run_dir"]), rf.REQUEST))
    return str(req.get("prompt") or "")


# ---------------------------------------------------------------------------------------------
# Pure admission
# ---------------------------------------------------------------------------------------------
class TestValidatePlanProposal(unittest.TestCase):
    """CONTROLS: deterministic admission of the proposal DOCUMENT itself."""

    def test_valid_proposal_admits_with_no_errors(self):
        ok, errors = planner_mod.validate_plan_proposal(_proposal())
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])

    def test_dependency_cycle_refused_by_name(self):
        bad = _proposal(lanes=[
            {"key": "a", "title": "A", "task": "t", "kind": "research",
             "depends_on": ["b"], "acceptance": []},
            {"key": "b", "title": "B", "task": "t", "kind": "research",
             "depends_on": ["a"], "acceptance": []}])
        ok, errors = planner_mod.validate_plan_proposal(bad)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(planner_mod.PROPOSAL_CYCLE) for e in errors), errors)

    def test_unknown_lane_kind_refused_by_name(self):
        bad = _proposal()
        bad["lanes"][0]["kind"] = "deployment"
        ok, errors = planner_mod.validate_plan_proposal(bad)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(planner_mod.PROPOSAL_UNKNOWN_KIND) for e in errors))

    def test_authority_bearing_field_refused_by_name(self):
        top = _proposal(authority="OWNER")           # top-level grab
        lane = _proposal()
        lane["lanes"][0]["capabilities"] = ["git_push"]   # per-lane grab
        for bad in (top, lane):
            ok, errors = planner_mod.validate_plan_proposal(bad)
            self.assertFalse(ok)
            self.assertTrue(any(e.startswith(planner_mod.PROPOSAL_AUTHORITY_FIELD)
                                for e in errors), errors)

    def test_implementation_lane_without_acceptance_refused(self):
        bad = _proposal()
        del bad["lanes"][0]["acceptance"]
        ok, errors = planner_mod.validate_plan_proposal(bad)
        self.assertFalse(ok)
        self.assertTrue(any("acceptance" in e for e in errors), errors)

    def test_unknown_dependency_reference_and_duplicate_keys_refused(self):
        bad = _proposal()
        bad["lanes"][1]["depends_on"] = ["nonexistent"]
        ok, errors = planner_mod.validate_plan_proposal(bad)
        self.assertFalse(ok)
        self.assertTrue(any("unknown lane key" in e for e in errors))
        worse = _proposal()
        worse["lanes"][1]["key"] = "impl"
        ok2, errors2 = planner_mod.validate_plan_proposal(worse)
        self.assertFalse(ok2)
        self.assertTrue(any("duplicate lane key" in e for e in errors2))

    def test_size_bounds_are_enforced(self):
        bad = _proposal()
        bad["lanes"][0]["task"] = "x" * 9000
        ok, errors = planner_mod.validate_plan_proposal(bad)
        self.assertFalse(ok)
        self.assertTrue(any("exceeds" in e for e in errors))
        ok2, _ = planner_mod.validate_plan_proposal({"title": "t", "lanes": []})
        self.assertFalse(ok2)


# ---------------------------------------------------------------------------------------------
# Adoption
# ---------------------------------------------------------------------------------------------
class TestAdoption(unittest.TestCase):
    """CONTROLS: adoption creates lanes + records the DECISION; refusals are named."""

    def test_valid_proposal_adopts_creating_lanes_and_decision_with_provenance(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        h.tick(pid)                                   # dispatch planner
        h.tick(pid)                                   # consume -> PENDING
        doc = planner_mod.pending_proposal(h.sstore, pid)
        self.assertIsNotNone(doc)
        out = planner_mod.adopt_plan_proposal(
            h.sstore, pid, doc["proposal"], doc["planner_provenance"],
            adopted_by_actor="strategist-A")
        self.assertTrue(out["ok"], out)
        # Lanes exist, keyed as proposed, with REAL dependency edges between them.
        lanes = {l.title: l for l in h.sstore.lanes(pid)}
        self.assertEqual(len(lanes), 2)
        dep = next(d for d in h.sstore.dependencies(pid))
        self.assertEqual(dep.kind, "REQUIRES")
        self.assertEqual({dep.from_lane, dep.to_lane},
                         {out["lane_ids"]["impl"], out["lane_ids"]["verify"]})
        # The DECISION carries the planner provenance and the adopting actor.
        d = h.sstore.get_decision(out["decision_id"])
        self.assertIsNotNone(d)
        self.assertEqual(d.authority, "STRATEGIST")
        self.assertIn("provider=fake", d.rationale)
        self.assertIn(doc["planner_provenance"]["run_id"], d.evidence_refs)
        self.assertEqual(d.actor_id, "strategist-A")
        # The document says ADOPTED and names who disposed.
        adopted = planner_mod.load_proposal_doc(h.sstore, pid)
        self.assertEqual(adopted["status"], "ADOPTED")
        self.assertEqual(adopted["adopted_by"], "strategist-A")

    def test_cycle_unknown_kind_and_authority_field_are_named_adoption_refusals(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        cases = [
            (_proposal(lanes=[
                {"key": "a", "title": "A", "task": "t", "kind": "research",
                 "depends_on": ["b"], "acceptance": []},
                {"key": "b", "title": "B", "task": "t", "kind": "research",
                 "depends_on": ["a"], "acceptance": []}]), planner_mod.PROPOSAL_CYCLE),
            (_proposal(), None),      # replaced below with unknown kind
            (_proposal(), None),
        ]
        cyclic = cases[0][0]
        unknown = _proposal()
        unknown["lanes"][0]["kind"] = "deployment"
        authority = _proposal()
        authority["lanes"][0]["requires_write"] = True
        for bad, name in ((cyclic, planner_mod.PROPOSAL_CYCLE),
                          (unknown, planner_mod.PROPOSAL_UNKNOWN_KIND),
                          (authority, planner_mod.PROPOSAL_AUTHORITY_FIELD)):
            out = planner_mod.adopt_plan_proposal(h.sstore, pid, bad, {}, "strategist-A")
            self.assertFalse(out["ok"], out)
            self.assertEqual(out["refusal"], name, out)
        # NOTHING was created by any refused adoption.
        self.assertEqual(h.sstore.lanes(pid), [])
        self.assertEqual(h.sstore.decisions(pid), [])

    def test_planner_cannot_self_adopt(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        h.tick(pid)
        h.tick(pid)
        doc = planner_mod.pending_proposal(h.sstore, pid)
        prov = dict(doc["planner_provenance"])
        self.assertEqual(prov["actor_id"], "executor:%s" % prov["provider"])
        out = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"], prov,
                                              adopted_by_actor=prov["actor_id"])
        self.assertFalse(out["ok"])
        self.assertEqual(out["refusal"], planner_mod.PROPOSAL_PLANNER_SELF_ADOPT)
        self.assertEqual(h.sstore.lanes(pid), [],
                         "the planner seat must not be able to create its own lanes")
        self.assertEqual([d.status for d in h.sstore.decisions(pid)], [])

    def test_double_adoption_of_the_same_proposal_is_refused(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        h.tick(pid)
        h.tick(pid)
        doc = planner_mod.pending_proposal(h.sstore, pid)
        first = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"],
                                                doc["planner_provenance"], "s1")
        second = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"],
                                                 doc["planner_provenance"], "s2")
        self.assertTrue(first["ok"])
        self.assertEqual(second["refusal"], planner_mod.PROPOSAL_NOT_PENDING)
        self.assertEqual(len(h.sstore.lanes(pid)), 2, "no duplicate lanes were minted")


# ---------------------------------------------------------------------------------------------
# The seat end to end
# ---------------------------------------------------------------------------------------------
class TestPlannerSeatEndToEnd(unittest.TestCase):
    """CONTROLS: the planner runs through the EXISTING dispatch machinery as role=planner."""

    def test_planner_run_is_dispatched_through_the_standard_ladder(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        r1 = h.tick(pid)
        self.assertTrue(r1["governance"]["planner_dispatched"], json.dumps(r1["governance"]))
        meta = h.sstore.get_program_meta(pid)
        run_id = meta[planner_mod.PLANNER_RUN_META_KEY]
        # Measured seat provenance: role=planner, provider from the resolved spec.
        provs = [json.loads(e["detail_json"]) for e in h.store.events_for(run_id)
                 if e["kind"] == "run.provenance"]
        self.assertEqual(provs[-1]["role"], "planner")
        self.assertEqual(provs[-1]["provider"], "fake")
        self.assertEqual(provs[-1]["source"], "lane-script")
        # The task went through the standard child contract (handoff identity echo).
        prompt = _request_prompt(h, run_id)
        self.assertIn("RUN_NONCE", prompt)
        self.assertIn("PLAN_PROPOSAL", prompt)
        h.tick(pid)
        doc = planner_mod.pending_proposal(h.sstore, pid)
        self.assertIsNotNone(doc, "the proposal must become PENDING after consumption")
        self.assertEqual(doc["status"], "PENDING")
        ib = orch.inbox(h.sstore, pid)
        kinds = [i["kind"] for i in ib["items"]]
        self.assertIn("PROPOSAL_PENDING_ADOPTION", kinds)
        item = next(i for i in ib["items"] if i["kind"] == "PROPOSAL_PENDING_ADOPTION")
        payload = json.loads(item["payload"])
        self.assertEqual(payload["lanes"], 2)
        self.assertEqual(payload["route"] if "route" in payload else item["route"],
                         "STRATEGIST")

    def test_invalid_planner_output_refuses_by_name_and_escalates(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = _new_planning_program(h)
        cyclic = _proposal(lanes=[
            {"key": "a", "title": "A", "task": "t", "kind": "research",
             "depends_on": ["b"], "acceptance": []},
            {"key": "b", "title": "B", "task": "t", "kind": "research",
             "depends_on": ["a"], "acceptance": []}])
        h.sstore.set_program_meta(pid, "_planner_executor",
                                  json.dumps(_scripted_planner(cyclic)))
        h.tick(pid)
        report = h.tick(pid)
        self.assertEqual(report["governance"]["planner_consumed"]["outcome"], "REFUSED")
        doc = planner_mod.load_proposal_doc(h.sstore, pid)
        self.assertEqual(doc["status"], "REFUSED")
        self.assertIsNone(planner_mod.pending_proposal(h.sstore, pid))
        # Program-level refusal rides the event log (a message would need a lane to belong to):
        blocked = [e for e in h.sstore.events(program_id=pid)
                   if e["event_type"] == ev_mod.BLOCKED
                   and planner_mod.PROPOSAL_CYCLE in e["detail_json"]]
        self.assertTrue(blocked, "the refusal must be escalated, not silent")


# ---------------------------------------------------------------------------------------------
# Plan challenge (bd quaestor-kaz.8, direction section 3.3)
# ---------------------------------------------------------------------------------------------
class TestPlanChallenge(unittest.TestCase):
    """CONTROLS: reviewer TARGET CLASSES; the challenge runs on the PROPOSAL packet."""

    def _pending_with_challenge(self, h, *, review_messages, require_plan_review=None,
                                plan_challenge="true"):
        pid = _new_planning_program(h)
        h.tick(pid)                                   # dispatch planner
        if require_plan_review is not None:
            h.sstore.set_program_meta(pid, "require_plan_review",
                                      "true" if require_plan_review else "false")
        h.sstore.set_program_meta(pid, "plan_challenge", plan_challenge)
        h.sstore.set_program_meta(pid, "review_executor", json.dumps({
            "kind": "fake", "config": {"scenario": "OK_PASS",
                                       "messages": review_messages}}))
        h.tick(pid)                                   # consume planner; dispatch challenge
        return pid

    def test_target_class_vocabulary_and_validation(self):
        self.assertEqual(set(rc.REVIEW_TARGET_CLASSES),
                         {"PLAN", "CODE", "INTEGRATION", "RELEASE", "SECURITY"})
        self.assertEqual(rc.DEFAULT_TARGET_CLASS, "CODE")
        h = EngineHarness()
        self.addCleanup(h.close)
        with self.assertRaises(ValueError):
            orch._dispatch_reviewer(h.home, h.sstore, h.store, program_id="x", lane=None,
                                    cfg=None, policy=orch.ProgramPolicy(), changed=(),
                                    target_class="BOGUS")
        with self.assertRaises(ValueError):
            orch._dispatch_reviewer(h.home, h.sstore, h.store, program_id="x", lane=None,
                                    cfg=None, policy=orch.ProgramPolicy(), changed=(),
                                    target_class="CODE")
        with self.assertRaises(ValueError):
            orch._dispatch_reviewer(h.home, h.sstore, h.store, program_id="x", lane=object(),
                                    cfg=None, policy=orch.ProgramPolicy(), changed=(),
                                    target_class="PLAN")

    def test_challenge_dispatched_on_pending_proposal_targets_the_packet(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = self._pending_with_challenge(h, review_messages=[
            {"type": "REVIEW_FINDING", "payload": "Acceptance criterion is unmeasurable",
             "severity": "HIGH",
             "detail": {"location": "impl", "failure_mode": "no observable check"}}])
        run_id = h.sstore.get_program_meta(pid)[planner_mod.CHALLENGE_RUN_META_KEY]
        self.assertTrue(run_id, "policy requested a challenge; none was dispatched")
        started = [e for e in h.sstore.events(program_id=pid)
                   if e["event_type"] == "REVIEW_STARTED"]
        self.assertTrue(started)
        detail = json.loads(started[0]["detail_json"])
        self.assertEqual(detail.get("target_class"), "PLAN")
        prov = [json.loads(e["detail_json"]) for e in h.store.events_for(run_id)
                if e["kind"] == "run.provenance"]
        self.assertEqual((prov[-1]["role"], prov[-1]["source"]),
                         ("adversarial_review", "lane-script"))
        # The reviewer was pointed at the PROPOSAL PACKET, not a code diff.
        prompt = _request_prompt(h, run_id)
        self.assertIn("ADVERSARIAL PLAN CHALLENGE", prompt)
        self.assertIn('"key": "impl"', prompt.replace("'", '"'))
        self.assertNotIn("git show", prompt)

    def test_finding_blocks_adoption_until_resolved(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = self._pending_with_challenge(h, review_messages=[
            {"type": "REVIEW_FINDING", "payload": "Plan has no verification lane",
             "severity": "HIGH",
             "detail": {"location": "impl", "failure_mode": "unverified acceptance"}}])
        h.tick(pid)          # consume the challenge -> finding attaches
        doc = planner_mod.pending_proposal(h.sstore, pid)
        self.assertEqual(len(doc["findings"]), 1)
        finding = doc["findings"][0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertFalse(finding["resolved"])
        out = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"],
                                              doc["planner_provenance"], "strategist-A")
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["refusal"], planner_mod.PROPOSAL_BLOCKED_BY_FINDINGS)
        self.assertEqual(h.sstore.lanes(pid), [], "a challenged plan must not create lanes")
        # RESOLUTION is a recorded strategist decision, and it un-blocks adoption.
        res = planner_mod.resolve_proposal_finding(h.sstore, pid, finding["finding_id"],
                                                   rationale="split into follow-up program",
                                                   actor_id="strategist-A")
        self.assertTrue(res["ok"], res)
        doc = planner_mod.pending_proposal(h.sstore, pid)
        self.assertTrue(doc["findings"][0]["resolved"])
        out2 = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"],
                                               doc["planner_provenance"], "strategist-A")
        self.assertTrue(out2["ok"], out2)
        self.assertEqual(len(h.sstore.lanes(pid)), 2)

    def test_require_plan_review_false_allows_despite_unresolved_findings(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        pid = self._pending_with_challenge(h, require_plan_review=False, review_messages=[
            {"type": "REVIEW_FINDING", "payload": "Minor sequencing concern",
             "severity": "MEDIUM",
             "detail": {"location": "verify", "failure_mode": "ordering"}}])
        h.tick(pid)
        doc = planner_mod.pending_proposal(h.sstore, pid)
        self.assertFalse(doc["require_plan_review"])
        out = planner_mod.adopt_plan_proposal(h.sstore, pid, doc["proposal"],
                                              doc["planner_provenance"], "strategist-A")
        self.assertTrue(out["ok"], out)

    def test_per_lane_plan_review_flag_requests_the_challenge(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        proposal = _proposal()
        proposal["lanes"][0]["plan_review"] = True
        pid, _ = h.new_program("per-lane challenge", "objective", [],
                               extra_meta={"planning_mode": "planner_seat"})
        h.sstore.set_program_meta(pid, "_planner_executor",
                                  json.dumps(_scripted_planner(proposal)))
        h.sstore.set_program_meta(pid, "review_executor", json.dumps({
            "kind": "fake", "config": {"scenario": "OK_PASS", "messages": []}}))
        h.tick(pid)
        h.tick(pid)
        self.assertTrue(h.sstore.get_program_meta(pid).get(
            planner_mod.CHALLENGE_RUN_META_KEY),
            "a per-lane plan_review=true must request the challenge without the global flag")


if __name__ == "__main__":
    unittest.main()

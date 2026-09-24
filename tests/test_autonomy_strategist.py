"""test_autonomy_strategist -- CONTROLS for the automated STRATEGIST seat.

The seat is the first place a MODEL disposes of governed state rather than proposing work for a
human to dispose of. ``planner.py`` established the shape one seat earlier -- "the planner
proposes, Quaestor disposes" -- and these controls exist to prove the same sentence stays true
when the thing being disposed of is a DECISION rather than a plan.

They attack the two ways that could be false:

    * A MODEL REACHING AUTHORITY IT MUST NEVER HAVE. Owner-routed asks escalate in every
      autonomy mode including AUTO; a directive naming a message id the seat was never shown is
      refused; a directive carrying an authority field is refused. The owner boundary is checked
      TWICE, in two modules, on two different inputs, so neither check is load-bearing alone.
    * AN AUTONOMY SETTING THAT FAILS OPEN. An unreadable, absent or unrecognised mode must
      resolve to the propose-only mode, never to the permissive one: absent evidence of a choice
      is not evidence of consent to autonomy.

It also carries the controls on the ORCHESTRATOR-side half of unattended operation:
TestUncertainIsNotDead pins what ``reap`` may do to a worker it cannot measure, which
is the same question one layer down -- absent evidence that a worker is gone is not
evidence that its lane may be run a second time.
"""
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import autonomy as auto_mod  # noqa: E402
from quaestor.core import domain  # noqa: E402
from quaestor.core import events as ev_mod  # noqa: E402
from quaestor.core import lease as lease_mod  # noqa: E402
from quaestor.core import messages as msg_mod  # noqa: E402
from quaestor.core import orchestrator as orch  # noqa: E402
from quaestor.core import proc  # noqa: E402
from quaestor.core import programs as prog_mod  # noqa: E402
from quaestor.core import reconcile as reconcile_mod  # noqa: E402
from quaestor.core import runfiles as rf_mod  # noqa: E402
from quaestor.core import store as store_mod  # noqa: E402
from quaestor.core import strategic_store as ss_mod  # noqa: E402
from quaestor.workspace import worktrees as wt_mod  # noqa: E402
from tests import procsafe  # noqa: E402
from tests.controls import control  # noqa: E402


def _read_repo_file(repo, rel):
    with open(os.path.join(repo, rel), encoding="utf-8") as fh:
        return fh.read()


class TestAutonomyPolicy(unittest.TestCase):
    def test_owner_routed_escalates_in_every_mode_including_auto(self):
        """THE INVARIANT THAT MAKES 'AUTO' SAFE TO OFFER. No mode reaches owner capability."""
        for mode in auto_mod.KNOWN_MODES:
            for kind in auto_mod.OWNER_KINDS:
                disp, why = auto_mod.disposition(mode, route="OWNER", kind=kind)
                self.assertEqual(disp, auto_mod.ESCALATE_TO_OWNER, "%s/%s" % (mode, kind))
                self.assertTrue(why)

    def test_owner_routing_wins_on_either_signal(self):
        """Route OR kind is enough. The two inputs come from different places (the inbox's
        classification and the message's own type); requiring both would let a disagreement
        between them resolve toward autonomy."""
        disp, _ = auto_mod.disposition(auto_mod.AUTO, route="OWNER", kind="DECISION_REQUEST")
        self.assertEqual(disp, auto_mod.ESCALATE_TO_OWNER)
        disp, _ = auto_mod.disposition(auto_mod.AUTO, route="STRATEGIST",
                                       kind="AUTHORITY_REQUEST")
        self.assertEqual(disp, auto_mod.ESCALATE_TO_OWNER)

    def test_safe_applies_routine_and_queues_everything_else(self):
        for kind in auto_mod.ROUTINE_KINDS:
            disp, _ = auto_mod.disposition(auto_mod.SAFE, route="STRATEGIST", kind=kind)
            self.assertEqual(disp, auto_mod.APPLY, kind)
        for kind in ("BLOCKER", "LANE_FAILED", "INTEGRATION_CONFLICT"):
            disp, _ = auto_mod.disposition(auto_mod.SAFE, route="STRATEGIST", kind=kind)
            self.assertEqual(disp, auto_mod.QUEUE_FOR_APPROVAL, kind)

    def test_default_queues_every_strategist_item(self):
        for kind in auto_mod.ROUTINE_KINDS + ("BLOCKER", "LANE_FAILED"):
            disp, _ = auto_mod.disposition(auto_mod.DEFAULT, route="STRATEGIST", kind=kind)
            self.assertEqual(disp, auto_mod.QUEUE_FOR_APPROVAL, kind)

    def test_auto_applies_every_strategist_item(self):
        for kind in auto_mod.ROUTINE_KINDS + ("BLOCKER", "LANE_FAILED"):
            disp, _ = auto_mod.disposition(auto_mod.AUTO, route="STRATEGIST", kind=kind)
            self.assertEqual(disp, auto_mod.APPLY, kind)

    def test_an_unknown_mode_fails_to_propose_only_never_open(self):
        """A typo'd or corrupted mode must not become the most permissive setting."""
        for bad in ("", "auto", "AUTOMATIC", None, "ADMIN", "SAFE_ISH", 3, object()):
            disp, why = auto_mod.disposition(bad, route="STRATEGIST", kind="DECISION_REQUEST")
            self.assertEqual(disp, auto_mod.QUEUE_FOR_APPROVAL, repr(bad))
            self.assertIn("unrecognised", why.lower(), repr(bad))

    def test_resolve_mode_is_total_and_never_raises(self):
        for bad in ("", None, 3, object(), [], {}):
            self.assertEqual(auto_mod.resolve_mode(bad), auto_mod.FALLBACK_MODE, repr(bad))
        for good in auto_mod.KNOWN_MODES:
            self.assertEqual(auto_mod.resolve_mode(good), good)

    def test_the_fallback_is_not_the_permissive_mode(self):
        """Stated as its own control because it is the whole fail-safe argument in one line."""
        self.assertNotEqual(auto_mod.FALLBACK_MODE, auto_mod.AUTO)
        self.assertIn(auto_mod.FALLBACK_MODE, auto_mod.KNOWN_MODES)

    def test_the_policy_is_pure_and_total(self):
        """Every (mode, route, kind) triple returns a KNOWN disposition -- never None, never an
        exception. A policy with a hole fails open exactly at the hole."""
        for mode in auto_mod.KNOWN_MODES + ("nonsense", "", None):
            for route in ("STRATEGIST", "OWNER", "", "weird", None):
                for kind in auto_mod.ROUTINE_KINDS + auto_mod.OWNER_KINDS + ("NOVEL_KIND", ""):
                    disp, why = auto_mod.disposition(mode, route=route, kind=kind)
                    self.assertIn(disp, auto_mod.DISPOSITIONS,
                                  "%r/%r/%r" % (mode, route, kind))
                    self.assertTrue(why, "%r/%r/%r" % (mode, route, kind))

    def test_a_novel_inbox_kind_is_never_auto_applied_under_safe(self):
        """SAFE names what it will apply; anything the vocabulary grows later queues by
        default. A future inbox kind must not inherit permission nobody granted it."""
        disp, _ = auto_mod.disposition(auto_mod.SAFE, route="STRATEGIST",
                                       kind="SOME_FUTURE_KIND")
        self.assertEqual(disp, auto_mod.QUEUE_FOR_APPROVAL)


class TestStrategistIsAssignable(unittest.TestCase):
    """Adding STRATEGIST to the assignable seats is the governance line this work crosses.

    It was absent from the original five not because it is owner-like but because nothing could
    fill it: every decision path ended at a human. Now that a model may hold it, the OWNER
    exclusion beside it stops being a formality and becomes the whole boundary -- STRATEGIST
    disposes of questions, OWNER disposes of capability, and only the first is delegable.
    """

    def _manifest(self, seat: str) -> tuple:
        from quaestor.projects import config as cfg_mod
        d = tempfile.mkdtemp(prefix="quaestor-seat-")
        with open(os.path.join(d, "quaestor.yaml"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join([
                "project:", "  name: seat-test", "  repository: .", "",
                "executor:", "  default: fake", "",
                "executors:", "  default: fake", "  roles:",
                "    %s: fake" % seat, ""]) + "\n")
        return cfg_mod.load_nearest(d)

    def test_strategist_joins_the_assignable_seats_and_owner_never_does(self):
        from quaestor.projects import config as cfg_mod
        self.assertIn("strategist", cfg_mod.ASSIGNABLE_ROLES)
        self.assertNotIn("owner", cfg_mod.ASSIGNABLE_ROLES)

    def test_a_manifest_may_pin_the_strategist_seat(self):
        cfg, reason = self._manifest("strategist")
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.role_executor.get("strategist"), "fake")

    def test_a_manifest_still_refuses_to_assign_the_owner_seat(self):
        cfg, reason = self._manifest("owner")
        self.assertIsNone(cfg, "the owner seat became assignable")
        self.assertIn("OWNER is always human", reason)

    def test_every_other_seat_still_parses(self):
        """Adding a member must not disturb the existing vocabulary."""
        for seat in ("planner", "implementation", "verification", "adversarial_review",
                     "integration"):
            cfg, reason = self._manifest(seat)
            self.assertIsNotNone(cfg, "%s: %s" % (seat, reason))
            self.assertEqual(cfg.role_executor.get(seat), "fake")

    def test_the_seat_vocabulary_has_exactly_one_declaration(self):
        """The config parser and the seat router MUST agree, and the cheapest way to guarantee
        that is for there to be nothing to disagree with. They were separately maintained until
        adding STRATEGIST made them diverge: the manifest parsed a seat the router then refused
        as non-existent, which is the most confusing shape a governance bug can take."""
        from quaestor.adapters import registry as cap_reg
        from quaestor.projects import config as cfg_mod
        self.assertIs(cfg_mod.ASSIGNABLE_ROLES, cap_reg.ASSIGNABLE_SEATS,
                      "the vocabularies are copies again, not one declaration")
        self.assertNotIn("owner", cap_reg.ASSIGNABLE_SEATS)

    def test_the_router_resolves_the_strategist_seat(self):
        """The failure this unification fixed: a seat a manifest accepts must be a seat the
        router can fill."""
        from quaestor.adapters import registry as cap_reg
        d = cap_reg.resolve_seat("strategist", {}, {"strategist": "fake"})
        self.assertEqual(d.refusal, "", d.rationale)
        self.assertEqual(d.kind, "fake")
        # ...and an unpinned strategist seat still resolves from the preference order rather
        # than refusing, so a deployment gets a seat without hand-editing a manifest first.
        unpinned = cap_reg.resolve_seat("strategist", {}, {})
        self.assertEqual(unpinned.refusal, "", unpinned.rationale)

    def test_an_unknown_seat_is_still_refused_by_name(self):
        cfg, reason = self._manifest("stratgist")
        self.assertIsNone(cfg, "a typo'd seat was accepted")
        self.assertIn("stratgist", reason)


class TestBriefingCarrier(unittest.TestCase):
    """The packet built for the human relay is already the right strategist prompt.

    Only two things are wrong for a machine seat: it says a human pasted the text, and it
    explains how a human will carry the answer back. One parameter fixes both and keeps ONE
    renderer -- a forked second builder would be a second reading of program state, and the
    half that drifted would be the half nobody was reading.
    """

    BUNDLE = {
        "program": {"program_id": "prog_x", "title": "T"},
        "objective": "ship it", "constraints": ["no new deps"], "status": "PLANNED",
        "lanes": [{"lane_id": "lane_a", "title": "impl", "kind": "implementation",
                   "state": "WAITING_FOR_STRATEGIST", "verdict": "NOT_EVALUATED",
                   "task": "do the thing", "acceptance": ["tests pass"], "attempt": 1}],
        "decisions": [], "blocking": {},
        "open_questions": [{"lane_id": "lane_a", "message_id": "msg_1",
                            "message_type": "DECISION_REQUEST", "payload": "raise or return?",
                            "created_at": 1.0}],
        "next_authority": "STRATEGIST", "inspected": {"lanes": 1}, "vacuous": False,
    }

    def test_the_human_carrier_is_unchanged_and_remains_the_default(self):
        from quaestor.core import briefing as b
        doc = b.briefing(self.BUNDLE)
        self.assertEqual(doc["carrier"], b.CARRIER_HUMAN)
        self.assertIn("A human operator pasted this text to you", doc["prompt"])

    def test_the_seat_carrier_drops_the_human_relay_language(self):
        from quaestor.core import briefing as b
        doc = b.briefing(self.BUNDLE, carrier=b.CARRIER_SEAT)
        self.assertEqual(doc["carrier"], b.CARRIER_SEAT)
        self.assertNotIn("pasted this text to you", doc["prompt"])
        self.assertNotIn("by hand", doc["prompt"])
        self.assertIn("dispatched into this seat", doc["prompt"])

    def test_the_seat_carrier_states_the_response_schema(self):
        """The seat's whole output is one JSON document; the packet has to say its shape or
        validation refuses every turn for a reason the model was never told."""
        from quaestor.core import briefing as b
        doc = b.briefing(self.BUNDLE, carrier=b.CARRIER_SEAT)
        for needle in ('"directives"', '"message_id"', '"directive"', '"rationale"'):
            self.assertIn(needle, doc["prompt"], needle)

    def test_the_seat_carrier_keeps_every_authority_boundary(self):
        """The carrier changes HOW the answer travels, never WHAT the seat may decide."""
        from quaestor.core import briefing as b
        doc = b.briefing(self.BUNDLE, carrier=b.CARRIER_SEAT)
        self.assertIn("grants nothing", doc["prompt"])
        self.assertIn("STRATEGIST authority only", doc["prompt"])
        self.assertEqual(doc["boundary"], b.BOUNDARY)

    def test_the_seat_carrier_still_sanitises(self):
        """A machine carrier is not a reason to ship a credential: the packet crosses a process
        boundary either way, and under the browser adapter it crosses a network too."""
        from quaestor.core import briefing as b
        bundle = json.loads(json.dumps(self.BUNDLE))
        bundle["lanes"][0]["task"] = "use sk-ant-api03-" + ("A" * 48)
        doc = b.briefing(bundle, carrier=b.CARRIER_SEAT)
        self.assertNotIn("sk-ant-api03-AAAA", doc["prompt"])
        self.assertTrue(doc["classification"]["modified"])

    def test_an_unknown_carrier_is_refused_not_defaulted(self):
        from quaestor.core import briefing as b
        for bad in ("telepathy", "", None, 3):
            with self.assertRaises(ValueError, msg=repr(bad)):
                b.briefing(self.BUNDLE, carrier=bad)


class TestDirectiveValidation(unittest.TestCase):
    """Admission for a strategist response: deterministic, closed over what the seat was SHOWN.

    A directive means nothing except in reference to the question it answers, and the model's
    only handle on that question is an id it was given. So an id that is not currently open is
    refused outright -- invented, stale and already-answered ids are indistinguishable from one
    another, and all three would write a decision against a question nobody asked.
    """

    OPEN = ({"message_id": "msg_1", "route": "STRATEGIST", "kind": "DECISION_REQUEST"},
            {"message_id": "msg_owner", "route": "OWNER", "kind": "AUTHORITY_REQUEST"})

    def ok_doc(self):
        return {"directives": [{"message_id": "msg_1", "directive": "Raise ValueError.",
                                "rationale": "explicit failure beats a sentinel"}]}

    def test_a_well_formed_response_validates(self):
        from quaestor.core import strategist as s
        ok, errors = s.validate_directive_response(self.ok_doc(), open_questions=self.OPEN)
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])

    def test_a_directive_for_an_unknown_message_is_refused(self):
        from quaestor.core import strategist as s
        doc = self.ok_doc()
        doc["directives"][0]["message_id"] = "msg_invented"
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_UNKNOWN_MESSAGE) for e in errors), errors)

    def test_a_directive_answering_an_owner_routed_ask_is_refused(self):
        """SECOND, INDEPENDENT REFUSAL. autonomy.disposition would also escalate this; both
        must refuse so that neither is load-bearing alone."""
        from quaestor.core import strategist as s
        doc = self.ok_doc()
        doc["directives"][0]["message_id"] = "msg_owner"
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_OWNER_ROUTED) for e in errors), errors)

    def test_an_embedded_authority_field_is_refused(self):
        from quaestor.core import strategist as s
        for field in ("authority", "capabilities", "grant", "authority_profile", "owner_token",
                      "executor", "spawn", "worktree_path"):
            doc = self.ok_doc()
            doc["directives"][0][field] = "GIT_PUSH"
            ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
            self.assertFalse(ok, field)
            self.assertTrue(any(e.startswith(s.DIRECTIVE_AUTHORITY_FIELD) for e in errors),
                            "%s: %s" % (field, errors))

    def test_an_authority_field_is_refused_whatever_its_case(self):
        """A denylist matched case-sensitively is a denylist with a trivial bypass."""
        from quaestor.core import strategist as s
        for field in ("Authority", "CAPABILITIES", "Grant"):
            doc = self.ok_doc()
            doc["directives"][0][field] = "x"
            ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
            self.assertFalse(ok, field)
            self.assertTrue(any(e.startswith(s.DIRECTIVE_AUTHORITY_FIELD) for e in errors),
                            "%s: %s" % (field, errors))

    def test_an_unknown_field_is_refused_not_ignored(self):
        from quaestor.core import strategist as s
        doc = self.ok_doc()
        doc["directives"][0]["priority"] = "urgent"
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_UNKNOWN_FIELD) for e in errors), errors)

    def test_an_unknown_top_level_field_is_refused(self):
        from quaestor.core import strategist as s
        doc = self.ok_doc()
        doc["notes"] = "some prose"
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_UNKNOWN_FIELD) for e in errors), errors)

    def test_an_empty_response_is_vacuous_not_success(self):
        from quaestor.core import strategist as s
        for doc in ({"directives": []}, {}, None, "not a mapping", [], 7):
            ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
            self.assertFalse(ok, repr(doc))
            self.assertTrue(errors, repr(doc))

    def test_oversize_directives_and_rationales_are_refused(self):
        from quaestor.core import strategist as s
        doc = self.ok_doc()
        doc["directives"][0]["directive"] = "x" * (s.MAX_DIRECTIVE_CHARS + 1)
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_TOO_LONG) for e in errors), errors)
        doc = self.ok_doc()
        doc["directives"][0]["rationale"] = "y" * (s.MAX_RATIONALE_CHARS + 1)
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)

    def test_more_directives_than_the_bound_are_refused(self):
        from quaestor.core import strategist as s
        doc = {"directives": [{"message_id": "msg_1", "directive": "d", "rationale": "r"}
                              for _ in range(s.MAX_DIRECTIVES + 1)]}
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)

    def test_a_duplicate_message_id_is_refused(self):
        """Two directives for one question is an ambiguity, and applying both would record two
        contradicting decisions against the same evidence ref."""
        from quaestor.core import strategist as s
        doc = {"directives": [{"message_id": "msg_1", "directive": "a", "rationale": "r"},
                              {"message_id": "msg_1", "directive": "b", "rationale": "r"}]}
        ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
        self.assertFalse(ok)
        self.assertTrue(any(e.startswith(s.DIRECTIVE_DUPLICATE) for e in errors), errors)

    def test_an_empty_directive_text_is_refused(self):
        from quaestor.core import strategist as s
        for text in ("", "   ", None):
            doc = self.ok_doc()
            doc["directives"][0]["directive"] = text
            ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
            self.assertFalse(ok, repr(text))

    def test_answering_a_subset_is_legitimate(self):
        """Omitting a question the packet could not settle is the CORRECT behaviour -- it
        escalates. Requiring an answer to everything would reward guessing."""
        from quaestor.core import strategist as s
        many = self.OPEN + ({"message_id": "msg_2", "route": "STRATEGIST",
                             "kind": "CLARIFICATION_REQUEST"},)
        ok, errors = s.validate_directive_response(self.ok_doc(), open_questions=many)
        self.assertTrue(ok, errors)

    def test_validation_never_raises_on_hostile_input(self):
        from quaestor.core import strategist as s
        for doc in ({"directives": [None]}, {"directives": ["str"]},
                    {"directives": [{"message_id": object()}]},
                    {"directives": {"not": "a list"}}):
            ok, errors = s.validate_directive_response(doc, open_questions=self.OPEN)
            self.assertFalse(ok, repr(doc))
            self.assertTrue(errors)

    def test_the_task_builder_reuses_the_briefing_in_seat_form(self):
        from quaestor.core import strategist as s
        text = s.build_strategist_task(TestBriefingCarrier.BUNDLE)
        self.assertIn("dispatched into this seat", text)
        self.assertIn('"directives"', text)
        self.assertIn("ship it", text)


def _scripted_strategist(directives):
    """A fake executor whose run reports one OBSERVATION carrying directives -- the same
    server-side scripting seam ``_planner_executor`` and ``review_executor`` use."""
    return {"kind": "fake", "config": {
        "scenario": "OK_PASS",
        "messages": [{"type": "OBSERVATION", "payload": "strategist turn",
                      "detail": {"directives": directives}}]}}


class TestStrategistSeatEndToEnd(unittest.TestCase):
    """The decisive controls: what a model's answer actually DOES to durable state.

    Every assertion is against durable rows (open questions, decisions, program meta), never
    against the return value alone -- the return value is the thing under test, and a control
    that trusts its subject's self-report measures nothing.
    """

    def setUp(self):
        from tests.test_operational_e2e import EngineHarness
        self.h = EngineHarness()
        self.addCleanup(self.h.close)

    # -- fixture -------------------------------------------------------------------------------
    def _seed(self, *, autonomy=None, owner_ask=False, directives=None, seat=True):
        """A program with one open question and a scripted strategist. Returns (pid, mid)."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import messages as msg_mod
        from quaestor.core import strategist as strat_mod
        meta = {}
        if seat:
            meta[strat_mod.STRATEGY_MODE_KEY] = strat_mod.STRATEGIST_SEAT
        if autonomy is not None:
            meta[auto_mod.AUTONOMY_MODE_KEY] = autonomy
        pid, lanes = self.h.new_program(
            "seat", "answer the question",
            [{"key": "impl", "title": "impl", "task": "do the thing"}], extra_meta=meta)
        lane = lanes["impl"]
        m = msg_mod.new_message(
            msg_mod.AUTHORITY_REQUEST if owner_ask else msg_mod.DECISION_REQUEST,
            actor_id="ex", lane_id=lane, program_id=pid,
            payload="may I push?" if owner_ask else "raise or return None?")
        self.h.sstore.record_message(m)
        if directives is None:
            directives = [{"message_id": m.message_id, "directive": "Raise ValueError.",
                           "rationale": "explicit failure beats a sentinel"}]
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
                                       json.dumps(_scripted_strategist(directives)))
        return pid, m.message_id

    def _turn(self, pid):
        """One full seat turn: dispatch, let the in-process worker finish, then consume."""
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        first = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawner=in_process_spawner)
        second = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawner=in_process_spawner)
        return first, second

    def _open_ids(self, pid):
        return [q["message_id"] for q in self.h.sstore.open_questions_for_program(pid)]

    def _decisions(self, pid):
        return [d.decision for d in self.h.sstore.decisions(pid)]

    def _queue(self, pid):
        from quaestor.core import strategist as strat_mod
        raw = self.h.sstore.get_program_meta(pid).get(strat_mod.PENDING_DIRECTIVES_KEY) or "{}"
        return (json.loads(raw) or {}).get("directives") or []

    # -- dispatch ------------------------------------------------------------------------------
    def test_the_seat_dispatches_read_only_with_measured_provenance(self):
        from quaestor.core import authority as authority_mod
        pid, _mid = self._seed()
        first, _ = self._turn(pid)
        run_id = first["strategist_dispatched"]
        self.assertTrue(run_id, "the seat did not dispatch")
        run = self.h.store.get_run(run_id)
        # TWO independent measurements of the same guarantee. is_write is the structural one --
        # it is what the store itself branches on -- and the admission event carries the profile
        # the dispatcher actually admitted, which is what a later audit reads.
        self.assertFalse(bool(run["is_write"]),
                         "the strategist run was admitted as a WRITING run")
        # NOTE the column name: the execution Store's event table uses "kind"; the
        # StrategicStore's uses "event_type". Two tables, two vocabularies.
        admitted = [e for e in self.h.store.events_for(run_id)
                    if e["kind"] == "dispatch.admitted"]
        self.assertTrue(admitted)
        self.assertEqual(json.loads(admitted[0]["detail_json"])["authority_profile"],
                         authority_mod.READ_ONLY,
                         "a strategist seat must never hold a write profile")
        prov = [e for e in self.h.store.events_for(run_id)
                if e["kind"] == "run.provenance"]
        self.assertTrue(prov, "no measured provenance for the seat run")
        self.assertEqual(json.loads(prov[0]["detail_json"])["role"], "strategist")

    def test_the_seat_does_not_dispatch_when_nothing_is_waiting(self):
        """Loop safety: an empty inbox must not spawn a turn that has nothing to decide."""
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        pid, _lanes = self.h.new_program(
            "quiet", "nothing to do", [],
            extra_meta={strat_mod.STRATEGY_MODE_KEY: strat_mod.STRATEGIST_SEAT})
        out = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawner=in_process_spawner)
        self.assertEqual(out["strategist_dispatched"], "")

    def test_a_program_without_the_seat_never_dispatches_one(self):
        """The feature is opt-in per program: every existing deployment keeps a human seat."""
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        pid, _mid = self._seed(seat=False)
        out = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawner=in_process_spawner)
        self.assertEqual(out["strategist_dispatched"], "")
        self.assertEqual(out["strategist_consumed"], {})

    def test_a_second_turn_does_not_dispatch_while_one_is_in_flight(self):
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        pid, _mid = self._seed()
        first = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawn=False)
        self.assertTrue(first["strategist_dispatched"])
        self.assertTrue(self.h.sstore.get_program_meta(pid)[strat_mod.STRATEGIST_RUN_META_KEY])
        second = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawn=False)
        self.assertEqual(second["strategist_dispatched"], "",
                         "a slow seat fanned out into a second concurrent turn")

    # -- disposition ---------------------------------------------------------------------------
    def test_auto_applies_the_directive_and_clears_the_question(self):
        from quaestor.core import autonomy as auto_mod
        pid, mid = self._seed(autonomy=auto_mod.AUTO)
        _first, second = self._turn(pid)
        consumed = second["strategist_consumed"]
        self.assertEqual([d["message_id"] for d in consumed["applied"]], [mid], consumed)
        self.assertNotIn(mid, self._open_ids(pid), "the question was not cleared")
        self.assertIn("Raise ValueError.", self._decisions(pid))
        self.assertEqual(self._queue(pid), [])

    def test_default_queues_the_directive_and_changes_nothing_durable(self):
        from quaestor.core import autonomy as auto_mod
        pid, mid = self._seed(autonomy=auto_mod.DEFAULT)
        _first, second = self._turn(pid)
        consumed = second["strategist_consumed"]
        self.assertEqual([d["message_id"] for d in consumed["queued"]], [mid], consumed)
        self.assertEqual(consumed["applied"], [])
        self.assertIn(mid, self._open_ids(pid), "DEFAULT answered without a human")
        self.assertNotIn("Raise ValueError.", self._decisions(pid))
        self.assertEqual([d["message_id"] for d in self._queue(pid)], [mid])

    def test_an_absent_autonomy_setting_behaves_as_default(self):
        """An untouched program is propose-only: absent evidence of a choice is not consent."""
        pid, mid = self._seed(autonomy=None)
        _first, second = self._turn(pid)
        self.assertEqual([d["message_id"] for d in second["strategist_consumed"]["queued"]],
                         [mid])
        self.assertIn(mid, self._open_ids(pid))

    def test_a_corrupt_autonomy_setting_does_not_widen_what_the_model_may_do(self):
        pid, mid = self._seed(autonomy="TOTALLY_AUTOMATIC")
        _first, second = self._turn(pid)
        self.assertEqual(second["strategist_consumed"]["applied"], [])
        self.assertIn(mid, self._open_ids(pid))

    def test_safe_applies_a_routine_ask(self):
        from quaestor.core import autonomy as auto_mod
        pid, mid = self._seed(autonomy=auto_mod.SAFE)
        _first, second = self._turn(pid)
        self.assertEqual([d["message_id"] for d in second["strategist_consumed"]["applied"]],
                         [mid])
        self.assertNotIn(mid, self._open_ids(pid))

    def test_an_owner_only_inbox_never_dispatches_a_turn_at_all(self):
        """STRONGER THAN 'refuses'. The seat used to be DISPATCHED over an owner-only inbox,
        correctly answer nothing, and have that compliance scored as a refusal -- three ticks
        of correct behaviour then exhausted the budget and bricked the seat permanently, since
        the counter only reset on an admitted turn and no admitted turn was possible.

        So the guard now measures what the seat can ACT on, not what it is shown: a turn that
        cannot succeed is never started, and no provider call is burned."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        for mode in auto_mod.KNOWN_MODES:
            with self.subTest(mode=mode):
                h_prev = self.h
                from tests.test_operational_e2e import EngineHarness
                self.h = EngineHarness()
                self.addCleanup(self.h.close)
                pid, mid = self._seed(autonomy=mode, owner_ask=True)
                first, second = self._turn(pid)
                self.assertEqual(first["strategist_dispatched"], "", mode)
                self.assertEqual(second["strategist_dispatched"], "", mode)
                self.assertIn(mid, self._open_ids(pid), mode)
                self.assertEqual(self._decisions(pid), [], mode)
                self.assertEqual(
                    int(self.h.sstore.get_program_meta(pid).get(
                        strat_mod.STRATEGIST_REFUSALS_KEY) or 0), 0,
                    "correct behaviour was charged against the refusal budget")
                self.h = h_prev

    def test_owner_and_strategist_asks_together_still_dispatch_and_refuse_the_owner_one(self):
        """The guard must not become a blanket 'never run while an owner ask exists'. With BOTH
        kinds open the turn is worth running, and a directive against the owner item is refused
        by deterministic admission -- the original invariant, now on a case that reaches it."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import messages as msg_mod
        from quaestor.core import strategist as strat_mod
        pid, mid = self._seed(autonomy=auto_mod.AUTO)
        lane = self.h.sstore.lanes(pid)[0]
        owner = msg_mod.new_message(msg_mod.AUTHORITY_REQUEST, actor_id="ex",
                                    lane_id=lane.lane_id, program_id=pid,
                                    payload="may I push?")
        self.h.sstore.record_message(owner)
        self.h.sstore.set_program_meta(
            pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
            json.dumps(_scripted_strategist(
                [{"message_id": owner.message_id, "directive": "go ahead",
                  "rationale": "r"}])))
        first, second = self._turn(pid)
        self.assertTrue(first["strategist_dispatched"], "a mixed inbox must still dispatch")
        consumed = second["strategist_consumed"]
        self.assertEqual(consumed["applied"], [])
        self.assertTrue(any(e.startswith(strat_mod.DIRECTIVE_OWNER_ROUTED)
                            for e in consumed["refused"]), consumed)
        self.assertIn(owner.message_id, self._open_ids(pid))
        self.assertIn(mid, self._open_ids(pid))
        self.assertEqual(self._decisions(pid), [])

    def test_a_non_message_inbox_item_is_not_answerable(self):
        """LANE_FAILED and INTEGRATION_CONFLICT carry no message id; PROPOSAL_PENDING_ADOPTION
        carries "". Keying the answerable set on those turned the literal strings "None" and ""
        into ids routed STRATEGIST, so a directive naming one validated, dispositioned with no
        route and no kind -- the one input under which AUTO applies -- and reached answer() with
        an id no message has."""
        from quaestor.core import strategist as strat_mod
        shown = [{"kind": "LANE_FAILED", "lane_id": "lane_x", "payload": "impl",
                  "route": "STRATEGIST"},
                 {"kind": "PROPOSAL_PENDING_ADOPTION", "message_id": "", "lane_id": "",
                  "route": "STRATEGIST"},
                 {"message_id": "msg_real", "route": "STRATEGIST",
                  "kind": "DECISION_REQUEST"}]
        for bad in ("None", "", "none"):
            ok, errors = strat_mod.validate_directive_response(
                {"directives": [{"message_id": bad, "directive": "do it", "rationale": "r"}]},
                open_questions=shown)
            self.assertFalse(ok, repr(bad))
            self.assertTrue(errors, repr(bad))
        ok, _e = strat_mod.validate_directive_response(
            {"directives": [{"message_id": "msg_real", "directive": "do it",
                             "rationale": "r"}]}, open_questions=shown)
        self.assertTrue(ok, "the one real message became unanswerable")

    def test_the_refusal_budget_resets_when_the_work_on_offer_changes(self):
        """The budget means 'this seat cannot handle THIS', never 'broken forever'. The counter
        is durable program meta and no surface clears it, so without scoping, one bad stretch
        bricked the seat for the life of the program."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import messages as msg_mod
        from quaestor.core import strategist as strat_mod
        pid, _mid = self._seed(
            autonomy=auto_mod.AUTO,
            directives=[{"message_id": "msg_never_open", "directive": "d", "rationale": "r"}])
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        for _ in range(strat_mod.MAX_CONSECUTIVE_REFUSALS * 2 + 2):
            out = orch.strategist_governance_step(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(),
                spawner=in_process_spawner)
            if out.get("strategist_halted"):
                break
        self.assertTrue(out.get("strategist_halted"), "the seat never halted")
        # New answerable work arrives: the halt must lift.
        lane = self.h.sstore.lanes(pid)[0]
        fresh = msg_mod.new_message(msg_mod.CLARIFICATION_REQUEST, actor_id="ex",
                                    lane_id=lane.lane_id, program_id=pid, payload="and this?")
        self.h.sstore.record_message(fresh)
        after = orch.strategist_governance_step(
            self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
            preflight=fake_preflight, policy=orch.ProgramPolicy(), spawner=in_process_spawner)
        self.assertFalse(after.get("strategist_halted"),
                         "the seat stayed halted after the work it failed on changed")

    def test_an_exception_while_dispositioning_counts_as_a_refusal(self):
        """NEITHER ADMITTED NOR REFUSED IS THE ONE OUTCOME THAT MUST NOT EXIST. The run key is
        cleared at the top of consumption, so an escaping exception left the turn counted as
        nothing: the budget never advanced, the reset never ran, and the seat re-dispatched the
        same doomed turn every tick forever."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        pid, _mid = self._seed(autonomy=auto_mod.AUTO)
        self._turn(pid)                      # produce a consumable run
        before = int(self.h.sstore.get_program_meta(pid).get(
            strat_mod.STRATEGIST_REFUSALS_KEY) or 0)
        original = orch._dispose_directives

        def _boom(*_a, **_k):
            raise RuntimeError("disposition exploded")

        orch._dispose_directives = _boom
        try:
            pid2, _m2 = self._seed(autonomy=auto_mod.AUTO)
            self._turn(pid2)
            after = int(self.h.sstore.get_program_meta(pid2).get(
                strat_mod.STRATEGIST_REFUSALS_KEY) or 0)
        finally:
            orch._dispose_directives = original
        self.assertGreater(after, 0,
                           "an exception mid-disposition was counted as neither admission nor "
                           "refusal, so the budget can never trip")
        self.assertGreaterEqual(before, 0)

    # -- refusal and exactly-once ---------------------------------------------------------------
    def test_an_invalid_response_is_refused_and_recorded_not_silently_dropped(self):
        """A seat whose output vanished looks identical to a seat that had nothing to say, and
        the operator would wait for an answer that was already thrown away."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        pid, mid = self._seed(
            autonomy=auto_mod.AUTO,
            directives=[{"message_id": "msg_invented", "directive": "do it",
                         "rationale": "because"}])
        _first, second = self._turn(pid)
        consumed = second["strategist_consumed"]
        self.assertTrue(any(e.startswith(strat_mod.DIRECTIVE_UNKNOWN_MESSAGE)
                            for e in consumed["refused"]), consumed)
        self.assertEqual(consumed["applied"], [])
        self.assertIn(mid, self._open_ids(pid))
        blocked = [e for e in self.h.sstore.events(program_id=pid)
                   if e["event_type"] == "BLOCKED"]
        self.assertTrue(blocked, "the refusal left no durable trace")
        self.assertTrue(any("refused" in str(e["detail_json"]) for e in blocked))

    def test_a_directive_carrying_an_authority_field_is_refused_end_to_end(self):
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        pid, mid = self._seed(
            autonomy=auto_mod.AUTO,
            directives=[{"message_id": "MID", "directive": "do it", "rationale": "r",
                         "authority": "OWNER"}])
        # patch the placeholder id to the real one so ONLY the authority field is wrong
        raw = self.h.sstore.get_program_meta(pid)[strat_mod.STRATEGIST_EXECUTOR_META_KEY]
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
                                       raw.replace("MID", mid))
        _first, second = self._turn(pid)
        consumed = second["strategist_consumed"]
        self.assertTrue(any(e.startswith(strat_mod.DIRECTIVE_AUTHORITY_FIELD)
                            for e in consumed["refused"]), consumed)
        self.assertEqual(consumed["applied"], [])
        self.assertIn(mid, self._open_ids(pid))

    def test_consumption_is_exactly_once_per_run(self):
        """A replayed turn would re-answer questions the first pass answered, recording a second
        contradicting decision against the same evidence ref."""
        from quaestor.core import autonomy as auto_mod
        pid, mid = self._seed(autonomy=auto_mod.AUTO)
        _first, second = self._turn(pid)
        self.assertEqual(len(second["strategist_consumed"]["applied"]), 1)
        before = len(self._decisions(pid))
        third, fourth = self._turn(pid)
        self.assertEqual(third["strategist_consumed"], {},
                         "a consumed run was consumed again")
        self.assertEqual(len(self._decisions(pid)), before,
                         "a second decision was recorded for one turn")

    def test_a_seat_that_keeps_failing_stops_dispatching(self):
        """LOOP SAFETY UNDER UNATTENDED OPERATION. A model that cannot produce a valid response
        will not start producing one because it was asked a fourth time, and each attempt is a
        real provider call. Unattended operation is precisely when nobody is watching that
        happen, so the seat halts and leaves the questions for a human."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        pid, mid = self._seed(
            autonomy=auto_mod.AUTO,
            directives=[{"message_id": "msg_never_open", "directive": "d", "rationale": "r"}])
        halted = None
        for _ in range(strat_mod.MAX_CONSECUTIVE_REFUSALS + 3):
            out = orch.strategist_governance_step(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(),
                spawner=in_process_spawner)
            if out.get("strategist_halted"):
                halted = out
                break
        self.assertIsNotNone(halted, "the seat never stopped re-dispatching a failing turn")
        self.assertGreaterEqual(halted["strategist_halted"],
                                strat_mod.MAX_CONSECUTIVE_REFUSALS)
        self.assertEqual(halted["strategist_dispatched"], "")
        # The questions are untouched and still waiting for a human.
        self.assertIn(mid, self._open_ids(pid))
        self.assertEqual(self._decisions(pid), [])

    def test_one_good_turn_clears_the_refusal_budget(self):
        """The budget counts CONSECUTIVE failures. A seat that recovers must not carry a
        permanent penalty from an earlier bad turn -- otherwise a long unattended run halts on
        the accumulated noise of transient faults it already recovered from."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        pid, mid = self._seed(
            autonomy=auto_mod.AUTO,
            directives=[{"message_id": "msg_never_open", "directive": "d", "rationale": "r"}])
        # One refused turn...
        for _ in range(2):
            orch.strategist_governance_step(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(),
                spawner=in_process_spawner)
        self.assertGreater(
            int(self.h.sstore.get_program_meta(pid).get(
                strat_mod.STRATEGIST_REFUSALS_KEY) or 0), 0)
        # ...then repoint the scripted seat at the REAL open question and let it succeed.
        self.h.sstore.set_program_meta(
            pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
            json.dumps(_scripted_strategist(
                [{"message_id": mid, "directive": "Raise ValueError.", "rationale": "r"}])))
        for _ in range(2):
            orch.strategist_governance_step(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(),
                spawner=in_process_spawner)
        self.assertEqual(
            int(self.h.sstore.get_program_meta(pid).get(
                strat_mod.STRATEGIST_REFUSALS_KEY) or 0), 0,
            "a recovered seat kept a penalty from an earlier failure")
        self.assertNotIn(mid, self._open_ids(pid))


class TestUnattendedOperation(unittest.TestCase):
    """THE ACCEPTANCE TEST FOR THE WHOLE FEATURE.

    Everything before this proves a piece works. This proves the pieces compose: an executor
    asks a question mid-run, ordinary ``tick`` dispatches the seat, the seat answers, the lane
    resumes, and the program reaches a terminal verdict with NO human touching it. If this
    passes, "the human is interrupted only for owner-level decisions" is a measured fact rather
    than an architecture diagram.
    """

    def setUp(self):
        from tests.test_operational_e2e import EngineHarness
        self.h = EngineHarness()
        self.addCleanup(self.h.close)

    def test_a_program_drives_itself_through_a_question_without_a_human(self):
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import in_process_spawner

        app = _read_repo_file(self.h.repo, os.path.join("app", "mathlib.py"))
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Should divide-by-zero raise or return None?"}]}}
        finish = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py":
                            app + "\n\ndef div(a, b):\n    if b == 0:\n"
                                  "        raise ValueError('div by zero')\n"
                                  "    return a / b\n"},
            "claimed_files": ["app/mathlib.py"]}}
        pid, lanes = self.h.new_program(
            "unattended", "add div with tests",
            [{"key": "impl", "title": "implement div", "task": "Add div(a, b).",
              "acceptance": ["div exists"],
              "executor": {"kind": "fake", "attempt_variants": [ask, finish]}}],
            extra_meta={strat_mod.STRATEGY_MODE_KEY: strat_mod.STRATEGIST_SEAT,
                        auto_mod.AUTONOMY_MODE_KEY: auto_mod.AUTO})

        # The seat answers whatever DECISION_REQUEST is open, by id, at the time it runs. It
        # cannot be pre-scripted with the id because the id does not exist until the child asks.
        answered = {"n": 0}
        real_build = strat_mod.build_strategist_task

        def _script_seat():
            open_q = [q for q in self.h.sstore.open_questions_for_program(pid)
                      if q["message_type"] == "DECISION_REQUEST"]
            if not open_q:
                return
            self.h.sstore.set_program_meta(
                pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
                json.dumps(_scripted_strategist(
                    [{"message_id": open_q[0]["message_id"],
                      "directive": "Raise ValueError on divide by zero.",
                      "rationale": "explicit failure beats a silent sentinel"}])))
            answered["n"] += 1

        last = {}
        for _ in range(40):
            _script_seat()
            last = self.h.tick(pid, spawner=in_process_spawner)
            status = last.get("status_out") or ""
            if status in (orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
                          orch.PROGRAM_CANCELLED):
                break

        self.assertGreater(answered["n"], 0, "the child never asked anything")
        # THE POINT: the question was answered by the SEAT, and the decision carries its actor.
        decisions = self.h.sstore.decisions(pid)
        self.assertTrue(decisions, "no decision was recorded at all")
        self.assertIn("strategist-seat", [d.actor_id for d in decisions],
                      "the decision was not made by the model seat")
        self.assertEqual(self.h.sstore.open_questions_for_program(pid), [],
                         "a question was left open in an unattended run")
        self.assertEqual(last.get("status_out"), orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last.get("integration"), default=str)[:600])

    def test_the_same_program_without_a_seat_stops_and_waits_for_a_human(self):
        """The control that gives the one above its meaning: without the seat, the identical
        program parks at WAITING_FOR_STRATEGIST. The seat is doing the work, not the fixture."""
        from quaestor.core import orchestrator as orch
        from tests.test_operational_e2e import in_process_spawner

        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST", "payload": "raise or return None?"}]}}
        pid, _lanes = self.h.new_program(
            "attended", "add div with tests",
            [{"key": "impl", "title": "implement div", "task": "Add div(a, b).",
              "acceptance": ["div exists"],
              "executor": {"kind": "fake", "attempt_variants": [ask, ask]}}])
        for _ in range(6):
            self.h.tick(pid, spawner=in_process_spawner)
        self.assertEqual(self.h.sstore.get_program_meta(pid).get("status"),
                         orch.PROGRAM_WAITING_STRATEGIST)
        self.assertTrue(self.h.sstore.open_questions_for_program(pid),
                        "the question should still be waiting for a human")
        self.assertEqual(self.h.sstore.decisions(pid), [])


class TestSeatSessionContinuity(TestStrategistSeatEndToEnd):
    """One conversation per program (requirement 5), expressed generically.

    ChatGPT calls it a conversation, Claude Code calls it a session, and the platform already
    had ONE name for it -- ``result.session_id``, extracted from the envelope by the worker. So
    the binding rides on that rather than on a vendor field, and any provider that emits a
    session id gains continuity instead of one vendor getting a bespoke path.
    """

    def test_resuming_is_a_DECLARED_capability_not_an_assumption(self):
        """The declaration is load-bearing. An executor that does not know the field does NOT
        politely ignore it -- FakeConfig(**cfg) raises TypeError on an unexpected key, so
        handing a session to a provider that never asked turns dispatch into a construction
        crash that reads as a broken installation. (This control exists because that is
        exactly what happened when the field was injected unconditionally.)"""
        from quaestor.adapters import registry as cap_reg
        self.assertTrue(cap_reg.resumes_session("chatgpt-web"))
        for kind in ("fake", "claude-cli", "codex-cli", "openrouter", "unknown-cli", ""):
            self.assertFalse(cap_reg.resumes_session(kind), kind)

    def test_a_provider_that_cannot_resume_is_never_handed_a_session(self):
        """REWRITTEN: the previous version asserted only that the turn still applied a
        directive, which stayed green with the resumes_session gate deleted -- FakeConfig
        happens to declare a session_id field, so the fake tolerated the injection the gate
        exists to prevent. This inspects the SPEC the dispatcher actually built."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight
        pid, _mid = self._seed(autonomy=auto_mod.AUTO)
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_SESSION_KEY, "sess-abc")
        captured = {}
        original = orch.dispatch

        def _capture(store, spec, **kw):
            captured["executor"] = dict(spec.executor or {})
            return original(store, spec, **kw)

        orch.dispatch = _capture
        try:
            orch.dispatch_strategist(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(), spawn=False)
        finally:
            orch.dispatch = original
        self.assertTrue(captured, "the dispatcher was never reached")
        cfg_out = dict(captured["executor"].get("config") or {})
        self.assertEqual(captured["executor"].get("kind"), "fake")
        self.assertNotIn("session_id", cfg_out,
                         "a session was handed to a provider that never declared it could "
                         "resume one; FakeConfig(**cfg) raises TypeError on an unexpected key, "
                         "so this is a dispatch-time crash, not a tolerated extra")

    def test_a_provider_that_CAN_resume_is_handed_the_session(self):
        """The other half: the gate must not simply refuse everyone."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import fake_preflight
        pid, _mid = self._seed(autonomy=auto_mod.AUTO)
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_SESSION_KEY, "sess-xyz")
        self.h.sstore.set_program_meta(
            pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
            json.dumps({"kind": "chatgpt-web", "config": {}}))
        captured = {}
        original = orch.dispatch

        def _capture(store, spec, **kw):
            captured["executor"] = dict(spec.executor or {})
            raise RuntimeError("stop before spawning a browser seat")

        orch.dispatch = _capture
        try:
            orch.dispatch_strategist(
                self.h.home, self.h.sstore, self.h.store, program_id=pid, cfg=self.h.cfg,
                preflight=fake_preflight, policy=orch.ProgramPolicy(), spawn=False)
        except RuntimeError:
            pass
        finally:
            orch.dispatch = original
        self.assertEqual(dict(captured["executor"].get("config") or {}).get("session_id"),
                         "sess-xyz", "a declared resumer was not handed its own session")

    def test_a_session_id_in_the_envelope_is_recorded_against_the_program(self):
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import strategist as strat_mod
        pid, _mid = self._seed(autonomy=auto_mod.AUTO)
        _first, second = self._turn(pid)
        # END TO END: the worker extracted session_id from the envelope into result.session_id,
        # and consumption bound it to the program. The next turn resumes that thread.
        landed = second["strategist_consumed"].get("session_id") or ""
        self.assertTrue(landed, "no session was bound from a run that reported one")
        self.assertEqual(self.h.sstore.get_program_meta(pid)[strat_mod.STRATEGIST_SESSION_KEY],
                         landed)

    def test_an_empty_session_id_is_never_bound(self):
        """REWRITTEN: the previous version pointed _consume_strategist_run at a nonexistent run
        id, so it returned on the `run is None` branch several statements before the `if landed:`
        guard it claimed to exercise -- it proved nothing about that guard. This drives a REAL
        consumed run whose result carries an empty session id."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        pid, _mid = self._seed(autonomy=auto_mod.AUTO)
        first, _second = self._turn(pid)
        run_id = first["strategist_dispatched"]
        self.assertTrue(run_id)
        # The sentinel goes in AFTER the turn: the turn legitimately binds its own session, and
        # setting it first would only prove that a later real binding overwrote an earlier one.
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_SESSION_KEY, "keep-me")
        # Blank the recorded session on the finished run, then re-consume it. Written straight
        # to the row rather than through record_result, whose full signature is not this
        # control's subject.
        self.h.store.conn.execute("UPDATE result SET session_id=NULL WHERE run_id=?", (run_id,))
        self.h.store.conn.commit()
        self.h.sstore.set_program_meta(pid, strat_mod.STRATEGIST_RUN_META_KEY, run_id)
        orch._consume_strategist_run(self.h.sstore, self.h.store, program_id=pid)
        self.assertEqual(self.h.sstore.get_program_meta(pid)[strat_mod.STRATEGIST_SESSION_KEY],
                         "keep-me",
                         "an empty session id overwrote a good binding, so the next turn would "
                         "resume nothing while believing it resumed")

    def test_the_chatgpt_envelope_carries_both_spellings(self):
        """``conversation_id`` is what a human reading that file expects; ``session_id`` is what
        the platform already calls it, and is the key the worker extracts with no core change."""
        from quaestor.executors import chatgpt_web as cwx
        env = cwx.synthesise_envelope("hi", conversation_id="conv-1", transport="cdp")
        self.assertEqual(env["conversation_id"], "conv-1")
        self.assertEqual(env["session_id"], "conv-1")
        from quaestor.core import executor_contract as ec
        self.assertEqual(ec.envelope_session_id(env), "conv-1",
                         "the platform's own extractor could not read it")

    def test_the_executor_accepts_either_spelling_on_the_way_in(self):
        from quaestor.executors import registry as ex_reg
        by_conv = ex_reg.build({"kind": "chatgpt-web",
                                "config": {"conversation_id": "c-1"}})
        by_sess = ex_reg.build({"kind": "chatgpt-web", "config": {"session_id": "c-1"}})
        self.assertEqual(by_conv._conversation_id, "c-1")
        self.assertEqual(by_sess._conversation_id, "c-1")


class TestAnsweredBeforeParkedWakesAnyway(unittest.TestCase):
    """quaestor-239.6. answer() woke a lane only if it was ALREADY parked, and the codebase's
    own comment calls answer() 'the wake path back to PLANNED'. So an answer that landed FIRST
    -- the message is recorded by reap before the lane state is set, so a caller can read the
    question and answer it while the lane is still running -- left the lane parked with its
    question already answered: open_questions empty, inbox silent, nothing to wake it, program
    stalled forever with no surface explaining why.

    Measured as a load-dependent failure of test_answer_resolves_a_scripted_decision_request
    (passes 3/3 in ~25s alone; exceeds a 240s deadline under load, reporting
    WAITING_FOR_STRATEGIST beside an EMPTY inbox -- the signature of answered-but-not-woken,
    not of slow). The automated strategist seat answers within one tick, so it meets that
    window routinely rather than rarely.
    """

    def setUp(self):
        from tests.test_operational_e2e import EngineHarness
        self.h = EngineHarness()
        self.addCleanup(self.h.close)

    def _program_with_open_question(self):
        from quaestor.core import messages as msg_mod
        pid, lanes = self.h.new_program(
            "wake", "answer before the park",
            [{"key": "impl", "title": "impl", "task": "do the thing"}])
        lane = lanes["impl"]
        m = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="ex", lane_id=lane,
                                program_id=pid, payload="raise or return?")
        self.h.sstore.record_message(m)
        return pid, lane, m.message_id

    def test_answering_a_lane_that_has_not_parked_yet_still_wakes_it(self):
        """THE REGRESSION. The lane is ACTIVE when the answer lands, then parks -- exactly the
        ordering that used to strand it."""
        from quaestor.core import orchestrator as orch
        from quaestor.core import programs as prog_mod
        pid, lane, mid = self._program_with_open_question()
        # The lane is running when the answer arrives.
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_ACTIVE, actor_id="t")
        orch.answer(self.h.sstore, pid, mid, decision_text="Raise ValueError.",
                    rationale="explicit failure", actor_id="strategist")
        self.assertEqual(self.h.sstore.get_lane(lane).state, prog_mod.LANE_ACTIVE,
                         "fixture assumption: the lane was not parked when answered")
        # Only NOW does the park happen, as reap would do it.
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST,
                                     actor_id="scheduler")
        self.assertEqual(self.h.sstore.open_questions_for_program(pid), [],
                         "the question is answered, so nothing surfaces it in the inbox")
        woken = orch.apply_pending_wakes(self.h.sstore, pid)
        self.assertEqual(woken, [lane], "the lane was left parked on an answered question")
        self.assertEqual(self.h.sstore.get_lane(lane).state, prog_mod.LANE_PLANNED)

    def test_the_ordinary_ordering_is_unchanged(self):
        """Answer AFTER the park still wakes immediately, with no pending flag left behind."""
        from quaestor.core import orchestrator as orch
        from quaestor.core import programs as prog_mod
        pid, lane, mid = self._program_with_open_question()
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST, actor_id="t")
        orch.answer(self.h.sstore, pid, mid, decision_text="d", rationale="r", actor_id="s")
        self.assertEqual(self.h.sstore.get_lane(lane).state, prog_mod.LANE_PLANNED)
        ckpt = self.h.sstore.get_lane_task(lane)["checkpoint"] or {}
        self.assertNotIn(orch.PENDING_WAKE_KEY, ckpt,
                         "a flag was recorded for a wake that already happened")
        self.assertEqual(orch.apply_pending_wakes(self.h.sstore, pid), [])

    def test_the_wake_happens_at_most_once(self):
        """A flag that replayed would re-wake a lane someone deliberately re-parked."""
        from quaestor.core import orchestrator as orch
        from quaestor.core import programs as prog_mod
        pid, lane, mid = self._program_with_open_question()
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_ACTIVE, actor_id="t")
        orch.answer(self.h.sstore, pid, mid, decision_text="d", rationale="r", actor_id="s")
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST, actor_id="s")
        self.assertEqual(orch.apply_pending_wakes(self.h.sstore, pid), [lane])
        # Re-park deliberately; the spent flag must not raise it again.
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST, actor_id="s")
        self.assertEqual(orch.apply_pending_wakes(self.h.sstore, pid), [])
        self.assertEqual(self.h.sstore.get_lane(lane).state,
                         prog_mod.LANE_WAITING_STRATEGIST)

    def test_a_terminal_lane_is_never_woken(self):
        from quaestor.core import orchestrator as orch
        from quaestor.core import programs as prog_mod
        pid, lane, mid = self._program_with_open_question()
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_ACTIVE, actor_id="t")
        orch.answer(self.h.sstore, pid, mid, decision_text="d", rationale="r", actor_id="s")
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_ABANDONED, verdict=prog_mod.FAIL,
                                     actor_id="s")
        self.assertEqual(orch.apply_pending_wakes(self.h.sstore, pid), [])

    def test_tick_applies_the_wake_so_the_program_resumes_on_its_own(self):
        """End to end: an unattended loop must recover without anyone noticing the stall."""
        from quaestor.core import orchestrator as orch
        from quaestor.core import programs as prog_mod
        from tests.test_operational_e2e import in_process_spawner
        pid, lane, mid = self._program_with_open_question()
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_ACTIVE, actor_id="t")
        orch.answer(self.h.sstore, pid, mid, decision_text="d", rationale="r", actor_id="s")
        self.h.sstore.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST,
                                     actor_id="scheduler")
        report = self.h.tick(pid, spawner=in_process_spawner)
        self.assertIn(lane, report.get("woken") or [],
                      "tick did not apply the pending wake, so the program stayed stalled")
        self.assertNotEqual(self.h.sstore.get_lane(lane).state,
                            prog_mod.LANE_WAITING_STRATEGIST)


# =============================================================================================
# EPIC P0 / quaestor-3nl.2 -- the UNATTENDED loop
# =============================================================================================
class TestUnattendedSoak(unittest.TestCase):
    """The existing soak proves 20+ durable transitions, crash recovery and strategist takeover
    -- all with a HUMAN in the seat. EPIC P6 replaced that human with a model, which changes the
    failure modes worth soaking:

      * the seat answers within ONE TICK of a question appearing, so it meets orderings a human
        never would (quaestor-239.6 stranded a program on exactly that);
      * it carries a refusal budget that must not trip on correct behaviour;
      * it binds a provider session that must be reused, not re-established per turn;
      * every decision it makes must stay attributable to it in the durable record.

    So this drives MANY question-answer-resume cycles with nobody watching, and asserts the loop
    neither stalls nor silently degrades.
    """

    LANES = 5
    MAX_TICKS = 90

    def setUp(self):
        from tests.test_operational_e2e import EngineHarness
        self.h = EngineHarness()
        self.addCleanup(self.h.close)

    def _ask_then_finish(self, question: str):
        """An executor that asks once, then completes on its next attempt."""
        return {"kind": "fake", "attempt_variants": [
            {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
                {"type": "DECISION_REQUEST", "payload": question}]}},
            {"kind": "fake", "config": {"scenario": "OK_PASS"}},
        ]}

    def _seat_answers_everything_open(self, pid):
        """Re-script the seat each tick against whatever is open RIGHT NOW.

        The ids do not exist until the children ask, so the seat cannot be pre-scripted -- which
        is also the honest shape: a real seat is handed the packet built from current state.
        """
        from quaestor.core import strategist as strat_mod
        open_q = [q for q in self.h.sstore.open_questions_for_program(pid)
                  if q["message_type"] in ("DECISION_REQUEST", "CLARIFICATION_REQUEST")]
        if not open_q:
            return 0
        self.h.sstore.set_program_meta(
            pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
            json.dumps(_scripted_strategist(
                [{"message_id": q["message_id"],
                  "directive": "Raise ValueError on the degenerate input.",
                  "rationale": "explicit failure beats a silent sentinel"}
                 for q in open_q])))
        return len(open_q)

    def test_many_cycles_run_to_a_verdict_with_nobody_watching(self):
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import in_process_spawner

        specs = [{"key": "impl%d" % i, "title": "lane %d" % i,
                  "task": "Add helper %d." % i, "acceptance": ["helper %d exists" % i],
                  "executor": self._ask_then_finish("how should helper %d fail?" % i)}
                 for i in range(self.LANES)]
        pid, _lanes = self.h.new_program(
            "unattended soak", "add helpers, deciding as you go", specs,
            extra_meta={strat_mod.STRATEGY_MODE_KEY: strat_mod.STRATEGIST_SEAT,
                        auto_mod.AUTONOMY_MODE_KEY: auto_mod.AUTO})

        offered = 0
        last = {}
        for _ in range(self.MAX_TICKS):
            offered += self._seat_answers_everything_open(pid)
            last = self.h.tick(pid, spawner=in_process_spawner)
            status = last.get("status_out") or ""
            if status in (orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
                          orch.PROGRAM_CANCELLED):
                break

        # -- the loop actually did work, rather than terminating early -----------------------
        self.assertGreaterEqual(offered, self.LANES,
                                "the children never asked, so nothing was soaked")
        decisions = self.h.sstore.decisions(pid)
        self.assertGreaterEqual(len(decisions), self.LANES,
                                "fewer decisions than questions: some were never answered")

        # -- EVERY decision is the seat's, and attributable ----------------------------------
        actors = {d.actor_id for d in decisions}
        self.assertEqual(actors, {"strategist-seat"},
                         "a decision was recorded by something other than the model seat: %s"
                         % actors)

        # -- nothing was left parked on an answered question (quaestor-239.6) ----------------
        self.assertEqual(self.h.sstore.open_questions_for_program(pid), [],
                         "a question was left open in an unattended run")
        from quaestor.core import programs as prog_mod
        stranded = [l.lane_id for l in self.h.sstore.lanes(pid)
                    if l.state in prog_mod.WAITING_STATES and not l.terminal]
        self.assertEqual(stranded, [],
                         "lane(s) %s are parked with nothing in the inbox to explain why"
                         % stranded)

        # -- correct behaviour never charged against the refusal budget ----------------------
        meta = self.h.sstore.get_program_meta(pid)
        self.assertEqual(int(meta.get(strat_mod.STRATEGIST_REFUSALS_KEY) or 0), 0,
                         "the seat accrued refusals while answering correctly")

        # -- the provider session was bound once and carried forward -------------------------
        self.assertTrue(meta.get(strat_mod.STRATEGIST_SESSION_KEY),
                        "no provider session was ever bound across turns")

        # -- and it finished -----------------------------------------------------------------
        self.assertEqual(last.get("status_out"), orch.PROGRAM_CANDIDATE_PASS,
                         json.dumps(last.get("integration"), default=str)[:600])

    def test_a_fresh_handle_continues_an_unattended_program_from_durable_state(self):
        """The takeover property, now with a MODEL in the seat: a new process must pick the
        program up from canonical rows alone, with no transcript and no live conversation."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategic_store as ss_mod2
        from quaestor.core import strategist as strat_mod
        from quaestor.core import store as store_mod
        from tests.test_operational_e2e import fake_preflight, in_process_spawner

        pid, _lanes = self.h.new_program(
            "takeover soak", "decide and continue",
            [{"key": "impl", "title": "impl", "task": "Add div.",
              "acceptance": ["div exists"],
              "executor": self._ask_then_finish("raise or return None?")}],
            extra_meta={strat_mod.STRATEGY_MODE_KEY: strat_mod.STRATEGIST_SEAT,
                        auto_mod.AUTONOMY_MODE_KEY: auto_mod.AUTO})
        for _ in range(8):
            self._seat_answers_everything_open(pid)
            self.h.tick(pid, spawner=in_process_spawner)
            if self.h.sstore.decisions(pid):
                break
        self.assertTrue(self.h.sstore.decisions(pid), "no decision was reached before takeover")
        bound = self.h.sstore.get_program_meta(pid).get(strat_mod.STRATEGIST_SESSION_KEY)

        # A COMPLETELY FRESH pair of handles over the same durable state.
        self.h.sstore.close()
        self.h.store.close()
        self.h.sstore = ss_mod2.StrategicStore(ss_mod2.strategic_path(self.h.home))
        self.h.store = store_mod.Store(os.path.join(self.h.home, "orchestrator.sqlite3"))

        meta = self.h.sstore.get_program_meta(pid)
        self.assertEqual(meta.get(strat_mod.STRATEGY_MODE_KEY), strat_mod.STRATEGIST_SEAT,
                         "the seat configuration did not survive the handle change")
        self.assertEqual(meta.get(strat_mod.STRATEGIST_SESSION_KEY), bound,
                         "the bound provider session did not survive; the next turn would "
                         "start cold while believing it resumed")
        bundle = self.h.sstore.handoff_bundle(pid)
        self.assertFalse(bundle["vacuous"])
        self.assertTrue(bundle["decisions"], "the new holder cannot see what was decided")

        last = {}
        for _ in range(40):
            self._seat_answers_everything_open(pid)
            last = self.h.tick(pid, spawner=in_process_spawner)
            if (last.get("status_out") or "") in (orch.PROGRAM_CANDIDATE_PASS,
                                                  orch.PROGRAM_CANDIDATE_FAIL):
                break
        self.assertEqual(last.get("status_out"), orch.PROGRAM_CANDIDATE_PASS,
                         "a fresh handle could not drive the unattended program home")
        self.assertEqual(self.h.sstore.open_questions_for_program(pid), [])

    def test_a_seat_that_answers_nothing_halts_instead_of_spinning_forever(self):
        """The other side of the soak: an unattended loop must STOP when the seat is broken,
        not burn a provider call every tick for the life of the deployment."""
        from quaestor.core import autonomy as auto_mod
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from tests.test_operational_e2e import in_process_spawner

        pid, _lanes = self.h.new_program(
            "broken seat", "never answerable",
            [{"key": "impl", "title": "impl", "task": "Add div.",
              "acceptance": ["div exists"],
              "executor": self._ask_then_finish("raise or return None?")}],
            extra_meta={strat_mod.STRATEGY_MODE_KEY: strat_mod.STRATEGIST_SEAT,
                        auto_mod.AUTONOMY_MODE_KEY: auto_mod.AUTO})
        # A seat that always names a message that is not open.
        self.h.sstore.set_program_meta(
            pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
            json.dumps(_scripted_strategist(
                [{"message_id": "msg_never_open", "directive": "d", "rationale": "r"}])))
        halted = False
        for _ in range(self.MAX_TICKS):
            report = self.h.tick(pid, spawner=in_process_spawner)
            gov = report.get("governance") or {}
            if gov.get("strategist_halted"):
                halted = True
                break
        self.assertTrue(halted, "a seat that can never answer spun without ever halting")
        self.assertLessEqual(
            int(self.h.sstore.get_program_meta(pid).get(
                strat_mod.STRATEGIST_REFUSALS_KEY) or 0),
            strat_mod.MAX_CONSECUTIVE_REFUSALS + 1,
            "the budget kept climbing after the halt, so turns were still being burned")
        self.assertTrue(self.h.sstore.open_questions_for_program(pid),
                        "the question must stay open for the human the seat escalated to")


# =============================================================================================
# 391, 392, 393 -- UNCERTAIN IS NOT DEAD: reap's crash-recovery arm (bd quaestor-9ap)
# =============================================================================================
#: Where a lock file is parked while a directory stands in its place. Same directory, so the
#: move is a rename -- one inode, kept -- and never a copy.
_MOVED_ASIDE = ".moved-aside"


def _deny_fresh_open(path):
    """Make a FRESH ``open(path, 'a+b')`` fail with a REAL OSError, WITHOUT disturbing whoever
    is holding the lock on that file. No mock, no monkeypatch, no descriptor exhaustion.

    Those two halves pull against each other, which is why this is a function and not a line.
    ``probe_lock``'s UNKNOWN arm is reached only when the open fails, and the states worth
    measuring are the ones where a live worker is still holding the lock -- so the file has to
    be unopenable and simultaneously still locked by a running process.

    TWO MECHANISMS, because the platforms do not offer the same lever.

    WINDOWS -- the read-only FILE ATTRIBUTE. It is not an ACL and no privilege overrides it:
    ``CreateFile`` for write against ``FILE_ATTRIBUTE_READONLY`` is refused for Administrator
    and for SYSTEM alike, and the holder's already-open handle is unaffected.

    POSIX -- EISDIR. The permission bits are NOT usable here, and that is not a hypothetical:
    CI runs this suite as root inside a container, ``CAP_DAC_OVERRIDE`` ignores the mode, so a
    0400 lock file opens fine, the probe reaches its lock arm and answers LOCK_HELD. (Measured
    as root on ext4 and on overlayfs: ``chmod 0400`` then ``open(p, 'a+b')`` SUCCEEDS.) Root has
    no bypass for "a directory cannot be opened for writing", so the lock file is moved aside
    and a directory is put in its place -- ``IsADirectoryError``, errno 21, for every uid.

    MOVED ASIDE, NOT REPLACED, and that is the whole trick rather than a detail. POSIX will let
    a file be unlinked out from under its holder, but the holder's ``flock`` then lives on an
    inode with no name, so a file recreated at that path probes LOCK_FREE while the worker is
    still running. That would silently destroy the restoring half of these controls, where a
    lock that reads again must read HELD for a live worker (391's discriminating half, and the
    flapping control's reset) and FREE for a dead one (393's re-attempted reclaim). ``rename``
    carries the inode, its lock and the holder's descriptor together, and renaming it back
    restores the very lock the control started with. Measured both ways on Linux: after
    unlink-and-recreate a still-held lock probes LOCK_FREE; after the rename round trip it
    probes LOCK_HELD, and the holder's descriptor still writes to the same file.
    """
    if os.name == "nt":
        os.chmod(path, stat.S_IREAD)
        return
    if os.path.isdir(path):
        return                      # already denied; every deny here is paired with a permit
    # Two steps, and briefly neither: nothing else reads this path while it is in between,
    # because every caller is the single thread that is driving reap.
    os.rename(path, path + _MOVED_ASIDE)
    os.mkdir(path)


def _permit_fresh_open(path):
    """Undo ``_deny_fresh_open``, putting back the ORIGINAL file and so the original lock."""
    if os.name == "nt":
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        return
    aside = path + _MOVED_ASIDE
    if os.path.isdir(path):
        os.rmdir(path)
    if os.path.exists(aside):
        os.rename(aside, path)


class _LosesItsProbeMidTick(ss_mod.StrategicStore):
    """A store that stops being able to probe a worker lock partway through the tick.

    THE INJECTION IS THE TIMING, NOT THE FAILURE. The failure is real and unmocked:
    ``_deny_fresh_open`` makes the lock file unopenable, so ``probe_lock``'s ``open(p, 'a+b')``
    raises for real and returns LOCK_UNKNOWN, exactly as it does at a reaper's descriptor limit.
    What this class chooses is only WHEN that begins -- inside the window between reap reading
    the worker DEAD and reap deciding what to do about it. That window is real and is not small:
    ``probe_worktree`` shells out to git in it. ``get_lane_task`` is the call reap makes inside
    that window (it is what reads the worktree path git is about to be run against), and
    ``after`` is how many earlier calls the pass makes before it. Nothing about ``reap``,
    ``may_reclaim`` or ``probe_lock`` is replaced.

    IT RECORDS BOTH HALVES, because they fail differently and the caller asserts each. ``broke``
    says the window was entered at all -- a reap that stopped making these calls would otherwise
    inject nothing, quietly. ``verdicts`` says the mechanism actually took: an injection that
    ran against a platform it does not work on would otherwise leave the probe readable and the
    control measuring the ordinary DEAD path while claiming to measure the lost one.
    """

    def __init__(self, path, locks, *, after):
        ss_mod.StrategicStore.__init__(self, path)
        self._locks = dict(locks)
        self._after = int(after)
        self._calls = 0
        self.broke = []
        self.verdicts = {}

    def get_lane_task(self, lane_id):
        out = ss_mod.StrategicStore.get_lane_task(self, lane_id)
        self._calls += 1
        if self._calls == self._after + 1:
            for run_id, path in sorted(self._locks.items()):
                if os.path.exists(path):
                    _deny_fresh_open(path)
                    self.broke.append(run_id)
                    self.verdicts[run_id] = proc.probe_lock(path)
        return out


class _AWorkerWritesInTheWindow(ss_mod.StrategicStore):
    """A store whose next checkpoint write is preceded, once, by the live worker's own.

    THE INJECTION IS THE TIMING, NOT THE WRITE. The write itself is what ``worker.py`` puts in
    the lane checkpoint at handoff, performed by the real ``save_checkpoint``; what this class
    chooses is only that it lands where reap leaves a window -- after reap has read the lane
    task and before reap writes back. That window is the entire premise of the UNKNOWN arm: the
    worker reap cannot measure may still be running, and a worker that is running is a worker
    that writes.
    """

    def __init__(self, path, payload):
        ss_mod.StrategicStore.__init__(self, path)
        self._payload = dict(payload)
        self.armed = False

    def save_checkpoint(self, lane_id, checkpoint, *, program_id="", run_id=""):
        if self.armed:
            self.armed = False
            ss_mod.StrategicStore.save_checkpoint(self, lane_id, self._payload)
        return ss_mod.StrategicStore.save_checkpoint(self, lane_id, checkpoint,
                                                     program_id=program_id, run_id=run_id)


class _DiesParkingTheLane(ss_mod.StrategicStore):
    """A store whose FIRST attempt to park a lane on the owner's desk does not survive.

    THE INJECTION IS A REAL STORE FAILURE, NOT A SKIPPED CALL. ``set_lane_state`` raises once,
    which is what a reaper meets when the process is signalled between two writes, or when the
    next statement hits ``sqlite3.OperationalError`` after the busy timeout under WAL
    contention. What it models is the window between DECIDING to escalate and RECORDING that the
    escalation happened -- the window that decides whether a permanently unprobeable lane ever
    reaches a human.
    """

    def __init__(self, path):
        ss_mod.StrategicStore.__init__(self, path)
        self.armed = True
        self.parked = []

    def set_lane_state(self, lane_id, state, *args, **kwargs):
        if self.armed and str(state) == prog_mod.LANE_WAITING_OWNER:
            self.armed = False
            raise RuntimeError("reaper died parking the lane")
        self.parked.append(str(state))
        return ss_mod.StrategicStore.set_lane_state(self, lane_id, state, *args, **kwargs)


class TestUncertainIsNotDead(unittest.TestCase):
    """reap must not turn an UNMEASURABLE worker into a dead one (bd quaestor-9ap).

    ``proc.classify_liveness`` returns three verdicts and its docstring says outright that
    "UNKNOWN is a legitimate verdict and callers MUST NOT convert it to DEAD". reap's crash
    recovery guarded on ``liveness == "ALIVE"`` and recovered on everything else, so UNKNOWN
    took the dead-worker path: the run was failed, its lease released, its provider marked
    exhausted and its lane retried -- a SECOND execution aimed at a process that was still
    running.

    That is reachable with no fault injection at all. ``probe_lock`` returns LOCK_UNKNOWN for
    any OSError out of ``open()``, so a reaper at its file-descriptor limit reads UNKNOWN for
    every run in its loop at once, and a worker that has read but not yet written is measured
    clean-and-at-base -- the exact shape reap calls "died without effect". These controls reach
    the same arm through _deny_fresh_open, which makes the lock file genuinely unopenable
    while its holder keeps running: a REAL, unmocked and permanent version of that OSError, with
    no monkeypatching and no need to exhaust this process's descriptors inside a test suite.

    The second defect lived on the same path: recovery called ``store.release_lease`` directly
    instead of going through ``lease.may_reclaim``, whose ``holder_liveness == proc.DEAD`` check
    that module's docstring calls "the entire safety property". Control 393 covers that.
    """

    def setUp(self):
        from tests.test_operational_e2e import EngineHarness
        self.h = EngineHarness()
        self.addCleanup(self.h.close)
        #: (WorkerLock or None, path) for every run lock this test made. Registered AFTER the
        #: harness cleanup so it RUNS BEFORE it: a held lock and a read-only file each stop
        #: Windows removing the temp tree.
        self.locks = []
        self.addCleanup(self._release_locks)
        self.fleet = procsafe.Fleet(deadline_s=300.0)
        self.addCleanup(self.fleet.close)

    def _release_locks(self):
        for lock, path in self.locks:
            if lock is not None:
                lock.release()
            try:
                _permit_fresh_open(path)
            except OSError:
                pass

    # -- construction --------------------------------------------------------------------------
    def _make_lock(self, run_id, *, hold):
        """Create the run's REAL worker lock. ``hold`` keeps it held by this live process."""
        rd = rf_mod.run_dir(os.path.join(self.h.home, "runs"), run_id)
        rf_mod.ensure(rd)
        path = rf_mod.p(rd, rf_mod.LOCK)
        lock = proc.WorkerLock(path)
        self.assertTrue(lock.acquire(), "could not take the run's own worker lock")
        if hold:
            self.locks.append((lock, path))
        else:
            lock.release()          # the file survives, free -- what a dead worker leaves
            self.locks.append((None, path))
        return path

    def _record_worker(self, db_path, run_id, pid, create_time, lock_path):
        s = store_mod.Store(db_path)
        try:
            s.record_worker_started(run_id, worker_pid=pid, worker_create_time=create_time,
                                    lock_path=lock_path)
        finally:
            s.close()

    def _live_worker_spawner(self):
        """A spawner that leaves a GENUINELY LIVE worker: this process takes the run's own
        WorkerLock and records its own process identity, so ``proc.observe`` reads ALIVE off the
        kernel rather than off anything the test asserts."""
        def spawner(*, db_path, run_id):
            path = self._make_lock(run_id, hold=True)
            pid, create_time = proc.self_identity()
            self._record_worker(db_path, run_id, pid, create_time, path)
            return pid
        return spawner

    def _dead_worker_spawner(self, dead_pid, dead_create_time):
        """A spawner that leaves what a crashed worker leaves: a lock file nobody holds, and a
        recorded process identity that has exited."""
        def spawner(*, db_path, run_id):
            path = self._make_lock(run_id, hold=False)
            self._record_worker(db_path, run_id, dead_pid, dead_create_time, path)
            return dead_pid
        return spawner

    def _a_process_that_has_exited(self):
        """A pid + creation time belonging to a process that is really gone. Returns (pid, ct).

        The child reports its OWN identity and exits, and ``Fleet.run`` is synchronous, so no
        handle to it survives the call -- which matters, because a killed child whose parent
        still holds its handle keeps answering identity queries on Windows exactly as a POSIX
        zombie keeps answering ``kill(pid, 0)``. Measured while writing this: with the handle
        still open the pid read as PRESENT and liveness came back UNKNOWN, not DEAD.

        Pid reuse cannot make this flaky in either direction: if the number is recycled, the
        recorded creation time no longer matches the observed one, and classify_liveness calls
        that DEAD by its pid-reuse rule instead of by absence.
        """
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
        program = ("import sys\n"
                   "sys.path.insert(0, %r)\n"
                   "from quaestor.core import proc\n"
                   "pid, created = proc.self_identity()\n"
                   "sys.stdout.write('%%s %%s' %% (pid, created))\n" % src)
        done = self.fleet.run([sys.executable, "-c", program], what="identity-then-exit",
                              timeout_s=60.0)
        self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace"))
        pid_s, created = done.stdout.decode("utf-8", "replace").strip().split()
        return int(pid_s), created

    def _start_one_lane(self, spawner, title):
        """One program, one lane, dispatched through the REAL scheduler with ``spawner``."""
        pid, lanes = self.h.new_program(
            title, "reap must not convert UNKNOWN liveness into a dead worker",
            [{"key": "impl", "title": title,
              "executor": {"kind": "fake", "config": {"scenario": "OK_PASS"}},
              "acceptance": ("the lane finishes",)}])
        self.h.tick(pid, spawner=spawner)
        lane_id = lanes["impl"]
        bindings = self.h.sstore.runs_for_lane(lane_id)
        self.assertEqual(len(bindings), 1, "expected exactly one dispatched run")
        return pid, lane_id, str(bindings[0]["run_id"])

    # -- measurement ---------------------------------------------------------------------------
    def _reap(self, program_id, store=None, sstore=None):
        policy = orch.policy_from_meta(self.h.sstore.get_program_meta(program_id))
        return orch.reap(self.h.home, sstore or self.h.sstore, store or self.h.store,
                         program_id=program_id, cfg=self.h.cfg, policy=policy)

    def _actions(self, report):
        return [str(a.get("action") or "") for a in report["actions"]]

    def _liveness(self, run_id):
        return reconcile_mod.read_liveness(self.h.store, run_id,
                                           dict(self.h.store.get_run(run_id)))

    def _blockers(self, lane_id):
        return [m["payload"] for m in self.h.sstore.messages(lane_id)
                if m["message_type"] == msg_mod.BLOCKER]

    def _unprobeable(self, path):
        """Break probe_lock's open() arm FOR REAL -- and PROVE it broke before relying on it.

        THE ASSERTIONS ARE THE LOAD-BEARING PART OF THIS HELPER. The first version of these
        controls forced the OSError with ``chmod(path, S_IREAD)``, which is exactly right on the
        machine they were written on and a NO-OP for root; CI runs as root, ``open()`` succeeded,
        ``probe_lock`` reached its lock arm and answered LOCK_HELD -- and this assertion is what
        said so, rather than letting two controls pass while silently measuring the ALIVE path.
        So both facts are checked, not just the verdict: that a fresh ``open()`` really raises
        (the arm is entered because of a real failure) and that the reachable path really does
        answer LOCK_UNKNOWN. ``_deny_fresh_open`` may change per platform; this may not.
        """
        _deny_fresh_open(path)
        with self.assertRaises(OSError):
            open(path, "a+b").close()
        self.assertEqual(proc.probe_lock(path), proc.LOCK_UNKNOWN)

    def _probeable(self, path):
        _permit_fresh_open(path)

    # -- the controls --------------------------------------------------------------------------
    @control(391)
    def test_an_unprobeable_lock_leaves_a_live_worker_untouched(self):
        """CONTROL (bd quaestor-9ap): a LIVE worker whose lock cannot be probed keeps its run,
        its lease and its lane. The old guard recovered every non-ALIVE verdict, so this exact
        state -- alive, holding its lock, clean and at base because it has read but not yet
        written -- was failed and retried against the running process."""
        pid, lane_id, run_id = self._start_one_lane(self._live_worker_spawner(), "live-worker")
        lock_path = self.locks[-1][1]
        self.assertEqual(self._liveness(run_id), proc.ALIVE)

        # The clean-and-at-base measurement the recovery arm reads as "died without effect" is
        # TRUE here, of a worker that is alive: that is what made the old guard fatal.
        ckpt = self.h.sstore.get_lane_task(lane_id)["checkpoint"]
        probe = wt_mod.probe_worktree(str(ckpt["worktree_path"]))
        self.assertIs(probe["dirty"], False)
        self.assertEqual(probe["head"], ckpt["worktree_base_head"])

        self._unprobeable(lock_path)
        self.assertEqual(self._liveness(run_id), proc.UNKNOWN)
        state_before = str(self.h.store.get_run(run_id)["execution_state"])
        lane_before = self.h.sstore.get_lane(lane_id).state

        actions = self._actions(self._reap(pid))

        self.assertIn("LIVENESS_UNKNOWN_HELD", actions)
        self.assertNotIn("CRASH_RECOVERED", actions)
        self.assertNotIn("AMBIGUOUS_ESCALATED", actions)
        self.assertNotIn("LEASE_RECLAIM_REFUSED", actions,
                         "the UNKNOWN arm fell through into the recovery path and got "
                         "as far as asking whether a live worker's fence could be "
                         "taken")
        self.assertEqual(str(self.h.store.get_run(run_id)["execution_state"]), state_before,
                         "an unmeasurable LIVE worker's run was transitioned")
        lease = self.h.store.lease_for_run(run_id)
        self.assertIsNotNone(lease)
        self.assertIsNone(lease["released_at"],
                          "a LIVE worker's lease was reclaimed on an UNKNOWN verdict")
        self.assertEqual(self.h.sstore.get_lane(lane_id).state, lane_before)
        self.assertEqual([b["processed"] for b in self.h.sstore.runs_for_lane(lane_id)], [0],
                         "the run was consumed while its worker was still running")
        self.assertIsNone(
            self.h.sstore.get_lane_task(lane_id)["checkpoint"].get("possible_write"))

        # It HELD, and it SAID so: silence here is the other half of the failure mode.
        classified = [json.loads(e["detail_json"] or "{}")
                      for e in self.h.sstore.events(program_id=pid)
                      if e["event_type"] == ev_mod.RECONCILIATION_CLASSIFIED]
        unknown = [d for d in classified if d.get("classification") == "WORKER_LIVENESS_UNKNOWN"]
        self.assertEqual(len(unknown), 1, classified)
        self.assertEqual(unknown[0]["liveness"], proc.UNKNOWN)
        self.assertEqual(unknown[0]["passes"], 1)
        self.assertFalse(unknown[0]["escalated"])

        # DISCRIMINATING: the hold is tied to the unreadable probe, not a blanket refusal to
        # act. Once the lock reads again the arm is not entered and the count is cleared.
        self._probeable(lock_path)
        self.assertEqual(self._liveness(run_id), proc.ALIVE)
        actions = self._actions(self._reap(pid))
        self.assertNotIn("LIVENESS_UNKNOWN_HELD", actions)
        self.assertEqual(
            self.h.sstore.get_lane_task(lane_id)["checkpoint"].get(orch.UNKNOWN_LIVENESS_KEY),
            {}, "the consecutive-UNKNOWN count survived a clean ALIVE reading")

        # AND IT MUST NOT ROLL THAT LIVE WORKER BACK. Holding is the ONE reap write that by
        # construction happens while the worker may still be executing, and worker.py does its
        # own read-modify-write of this same document at handoff. save_checkpoint merges per
        # key, so a hold that wrote back the whole snapshot it read a moment earlier would
        # re-assert every key in it and revert the handoff. Not cosmetic: reap's second loop
        # reads awaiting_message to tell a run that PAUSED to ask from one that finished, and a
        # reverted sentinel sends a paused run into commit and verification.
        self.h.sstore.save_checkpoint(lane_id, {"summary": "the PREVIOUS attempt's summary",
                                                "awaiting_message": ""}, program_id=pid)
        self._unprobeable(lock_path)
        landing = _AWorkerWritesInTheWindow(
            ss_mod.strategic_path(self.h.home),
            {"summary": "the worker finished and reported", "awaiting_message": "msg-live"})
        self.addCleanup(landing.close)
        landing.armed = True
        actions = self._actions(self._reap(pid, sstore=landing))
        self.assertIn("LIVENESS_UNKNOWN_HELD", actions)
        self.assertFalse(landing.armed, "the worker's write never landed inside reap's window")
        ckpt = self.h.sstore.get_lane_task(lane_id)["checkpoint"]
        self.assertEqual(ckpt.get("summary"), "the worker finished and reported",
                         "the hold reverted a live worker's checkpoint to a stale snapshot")
        self.assertEqual(ckpt.get("awaiting_message"), "msg-live",
                         "the hold reverted the paused-run sentinel the worker had just written")
        self.assertEqual(ckpt[orch.UNKNOWN_LIVENESS_KEY]["run_id"], run_id)
        saved = [json.loads(e["detail_json"] or "{}")
                 for e in self.h.sstore.events(program_id=pid)
                 if e["event_type"] == ev_mod.CHECKPOINT_SAVED]
        mixed = [d.get("keys") for d in saved
                 if orch.UNKNOWN_LIVENESS_KEY in (d.get("keys") or [])
                 and len(d.get("keys") or []) > 1]
        self.assertEqual(mixed, [], "a hold wrote its marker together with a stale snapshot of "
                                    "everything else in the checkpoint: %s" % mixed)
        self._probeable(lock_path)

    @control(392)
    def test_a_permanently_unreadable_worker_escalates_at_the_bound_exactly_once(self):
        """CONTROL (bd quaestor-9ap): 'neither continue nor recover' must not mean 'hang'. A
        worker whose lock is PERMANENTLY unprobeable is held for a bounded number of passes and
        then handed to the owner as a BLOCKER on a WAITING_FOR_OWNER lane -- once, no matter how
        many passes follow -- and is never retried and never has its lease taken."""
        pid, lane_id, run_id = self._start_one_lane(self._live_worker_spawner(), "unreadable")
        lock_path = self.locks[-1][1]
        self._unprobeable(lock_path)

        bound = orch.UNKNOWN_LIVENESS_ESCALATION_PASSES
        self.assertGreaterEqual(bound, 2, "a bound of one is not a re-probe")
        for i in range(bound - 1):
            actions = self._actions(self._reap(pid))
            self.assertIn("LIVENESS_UNKNOWN_HELD", actions, "pass %d" % (i + 1))
            self.assertNotIn("LIVENESS_UNKNOWN_ESCALATED", actions, "pass %d" % (i + 1))
        self.assertNotEqual(self.h.sstore.get_lane(lane_id).state, prog_mod.LANE_WAITING_OWNER)
        self.assertEqual(self._blockers(lane_id), [])

        actions = self._actions(self._reap(pid))
        self.assertIn("LIVENESS_UNKNOWN_ESCALATED", actions)
        self.assertEqual(self.h.sstore.get_lane(lane_id).state, prog_mod.LANE_WAITING_OWNER)
        blockers = self._blockers(lane_id)
        self.assertEqual(len(blockers), 1, blockers)
        self.assertIn(run_id, blockers[0])
        self.assertIn("UNKNOWN", blockers[0])
        self.assertIn("BLOCKER", [i["kind"] for i in orch.inbox(self.h.sstore, pid)["items"]])

        # ONCE. The run stays ACTIVE and unprocessed on purpose, so this arm is re-entered on
        # every later pass; re-filing the blocker each tick would bury the surface it raises.
        for _ in range(4):
            actions = self._actions(self._reap(pid))
            self.assertNotIn("LIVENESS_UNKNOWN_ESCALATED", actions)
            self.assertNotIn("LIVENESS_UNKNOWN_HELD", actions)
            self.assertNotIn("CRASH_RECOVERED", actions)
        self.assertEqual(len(self._blockers(lane_id)), 1)
        self.assertIsNone(self.h.store.lease_for_run(run_id)["released_at"])
        self.assertTrue(domain.is_active(str(self.h.store.get_run(run_id)["execution_state"])))
        self.assertEqual(self._liveness(run_id), proc.UNKNOWN)

        # ESCALATE-ONCE IS SCOPED TO THE RUN, NOT TO THE LANE. The marker is durable in the lane
        # checkpoint and no arm of reap clears it, so a lane that escalated on run A carries A's
        # spent ``escalated`` flag into run B. An unscoped read makes B's hold return silently
        # -- no action, no event, no blocker, the lane simply stops moving with nothing anywhere
        # saying why: the exact failure this arm exists to prevent, and one that "not more than
        # one escalation" cannot catch, because zero escalations satisfies it too.
        dead_pid, dead_created = self._a_process_that_has_exited()
        pid, lane_id, run_a = self._start_one_lane(
            self._dead_worker_spawner(dead_pid, dead_created), "inherits-a-marker")
        lock_a = self.locks[-1][1]

        # Run A: unreadable to the bound, so the lane really does carry a spent marker.
        self._unprobeable(lock_a)
        for _ in range(orch.UNKNOWN_LIVENESS_ESCALATION_PASSES):
            self._reap(pid)
        mark = self.h.sstore.get_lane_task(lane_id)["checkpoint"][orch.UNKNOWN_LIVENESS_KEY]
        self.assertEqual((mark["run_id"], mark["escalated"]), (run_a, True))

        # A reads DEAD again, is recovered, and the lane retries -- which is what puts a NEW run
        # on a lane whose checkpoint still holds A's marker. Nothing clears it on this path.
        self._probeable(lock_a)
        self.assertIn("CRASH_RECOVERED", self._actions(self._reap(pid)))
        self.h.tick(pid, spawner=self._live_worker_spawner())
        run_b = [str(b["run_id"]) for b in self.h.sstore.runs_for_lane(lane_id)
                 if str(b["run_id"]) != run_a]
        self.assertEqual(len(run_b), 1, "the lane did not retry, so there is no second run")
        run_b = run_b[0]
        self.assertEqual(
            self.h.sstore.get_lane_task(lane_id)["checkpoint"][orch.UNKNOWN_LIVENESS_KEY]
            ["run_id"], run_a, "A's marker was cleared, so this proves nothing about scoping")

        self._unprobeable(self.locks[-1][1])
        self.assertEqual(self._liveness(run_b), proc.UNKNOWN)
        before = len(self._blockers(lane_id))
        actions = self._actions(self._reap(pid))

        self.assertIn("LIVENESS_UNKNOWN_HELD", actions,
                      "run B was silently skipped on run A's spent escalation flag")
        mark = self.h.sstore.get_lane_task(lane_id)["checkpoint"][orch.UNKNOWN_LIVENESS_KEY]
        self.assertEqual(mark["run_id"], run_b)
        self.assertEqual(mark["passes"], 1, "run B inherited run A's consecutive count")
        self.assertFalse(mark["escalated"])
        held = [json.loads(e["detail_json"] or "{}")
                for e in self.h.sstore.events(program_id=pid, lane_id=lane_id)
                if e["event_type"] == ev_mod.RECONCILIATION_CLASSIFIED
                and str(e["run_id"] or "") == run_b]
        self.assertEqual([d.get("passes") for d in held], [1], held)
        self.assertEqual(len(self._blockers(lane_id)), before,
                         "B's first unreadable pass escalated straight away")
        self._probeable(self.locks[-1][1])

    def test_the_count_is_consecutive_so_one_clean_reading_resets_it(self):
        """Control on the control: the bound counts CONSECUTIVE unreadable passes. A flapping
        probe -- unreadable, unreadable, clean, unreadable, unreadable -- must never accumulate
        into an escalation of a worker that keeps proving itself alive in between."""
        pid, lane_id, _run_id = self._start_one_lane(self._live_worker_spawner(), "flapping")
        lock_path = self.locks[-1][1]
        bound = orch.UNKNOWN_LIVENESS_ESCALATION_PASSES
        for _ in range(bound - 1):
            self._unprobeable(lock_path)
            self._reap(pid)
        self._probeable(lock_path)
        self._reap(pid)
        for _ in range(bound - 1):
            self._unprobeable(lock_path)
            actions = self._actions(self._reap(pid))
            self.assertNotIn("LIVENESS_UNKNOWN_ESCALATED", actions)
        self.assertNotEqual(self.h.sstore.get_lane(lane_id).state, prog_mod.LANE_WAITING_OWNER)
        self.assertEqual(self._blockers(lane_id), [])
        self._probeable(lock_path)

    @control(393)
    def test_reap_releases_a_lease_only_through_may_reclaim(self):
        """CONTROL (bd quaestor-9ap): reap's dead-worker recovery reclaims the worktree lease
        THROUGH lease.may_reclaim, never around it. A reaper that loses the ability to probe
        between measuring the worker dead and releasing its fence must record a refusal and
        leave the lease standing -- which is exactly what calling store.release_lease directly
        cannot do."""
        dead_pid, dead_created = self._a_process_that_has_exited()

        # An ordinary crashed worker has to READ dead, not merely BE dead. On POSIX a worker
        # this process dispatched is still its CHILD -- start_new_session makes a session, it
        # does not reparent -- and an uncollected zombie answers every identity query, which is
        # the "lock free, recorded identity still present" shape classify_liveness calls
        # UNKNOWN. reap collects its own child before measuring; the guard on that collection
        # refuses anything it cannot prove it owns, because a recycled pid can name a DIFFERENT
        # child of this process and taking that one's exit status is a hang, not an error.
        self.assertTrue(orch._may_wait_on_own_child(dead_pid, dead_created, dead_created))
        self.assertFalse(orch._may_wait_on_own_child(dead_pid, dead_created, "999999999"),
                         "a recycled pid was owned on the strength of the number alone")
        self.assertFalse(orch._may_wait_on_own_child(dead_pid, dead_created, None))
        self.assertFalse(orch._may_wait_on_own_child(dead_pid, None, dead_created))
        self.assertFalse(orch._may_wait_on_own_child(0, dead_created, dead_created))
        self.assertFalse(orch._may_wait_on_own_child(-1, dead_created, dead_created))
        self.assertFalse(orch._may_wait_on_own_child("not-a-pid", dead_created, dead_created))

        # The ordinary recovery still reclaims. Without this half, a reap that released nothing
        # at all would pass the second half and be worthless.
        pid_a, lane_a, run_a = self._start_one_lane(
            self._dead_worker_spawner(dead_pid, dead_created), "dead-worker-reclaims")
        self.assertEqual(self._liveness(run_a), proc.DEAD)
        actions = self._actions(self._reap(pid_a))
        self.assertIn("CRASH_RECOVERED", actions)
        self.assertNotIn("LEASE_RECLAIM_REFUSED", actions)
        self.assertEqual(str(self.h.store.get_run(run_a)["execution_state"]),
                         domain.WORKER_FAILED)
        self.assertIsNotNone(self.h.store.lease_for_run(run_a)["released_at"],
                             "a provably dead worker's lease was not reclaimed at all")
        self.assertEqual(lane_a, self.h.sstore.lane_for_run(run_a)["lane_id"])

        # The same recovery, with the probe lost in the window between measuring the death and
        # deciding on it -- the window probe_worktree's git subprocess really opens.
        pid_b, lane_b, run_b = self._start_one_lane(
            self._dead_worker_spawner(dead_pid, dead_created), "dead-worker-unprobeable")
        self.assertEqual(self._liveness(run_b), proc.DEAD)
        lock_b = self.locks[-1][1]
        attempt_before = self.h.sstore.get_lane_task(lane_b)["attempt"]
        losing = _LosesItsProbeMidTick(ss_mod.strategic_path(self.h.home), {run_b: lock_b},
                                       after=1)
        self.addCleanup(losing.close)
        actions = self._actions(self._reap(pid_b, sstore=losing))
        self.assertEqual(losing.broke, [run_b], "the probe was never lost inside reap's window")
        self.assertEqual(losing.verdicts, {run_b: proc.LOCK_UNKNOWN},
                         "the injection ran inside the window but the lock stayed readable, so "
                         "this measures the ordinary DEAD path and proves nothing about a lost "
                         "probe")

        # NOTHING DESTRUCTIVE HAPPENED. Failing the run, taking its fence, resetting its
        # worktree and retrying its lane are ONE decision, and the reading that authorises it is
        # taken before any of them is committed. Deciding afterwards leaves a terminal run
        # holding a lease that no path in the tree releases -- reap skips runs that are not
        # active, and reconcile answers TERMINAL_ALREADY without reaching its lease block.
        self.assertIn("LEASE_RECLAIM_REFUSED", actions)
        self.assertIn("LIVENESS_UNKNOWN_HELD", actions)
        self.assertNotIn("CRASH_RECOVERED", actions)
        self.assertNotIn("RETRY_SCHEDULED", actions)
        self.assertEqual(self._liveness(run_b), proc.UNKNOWN)
        self.assertTrue(domain.is_active(str(self.h.store.get_run(run_b)["execution_state"])),
                        "the run was failed on a reading that could not prove it dead")
        self.assertIsNone(self.h.store.lease_for_run(run_b)["released_at"],
                          "the lease was released without may_reclaim's approval")
        self.assertEqual([b["processed"] for b in self.h.sstore.runs_for_lane(lane_b)], [0],
                         "the run was consumed, so nothing would ever revisit its lease")
        self.assertEqual(self.h.sstore.get_lane_task(lane_b)["attempt"], attempt_before,
                         "the lane was retried against a worker reap could not call dead")
        refusals = [e for e in self.h.store.events_for(run_b)
                    if e["kind"] == "lease.reclaim_refused"]
        self.assertEqual(len(refusals), 1, [e["kind"] for e in self.h.store.events_for(run_b)])
        self.assertEqual(json.loads(refusals[0]["detail_json"])["liveness"], proc.UNKNOWN)
        self.assertFalse(lease_mod.may_reclaim(
            self.h.store.lease_for_run(run_b),
            holder_run_state=str(self.h.store.get_run(run_b)["execution_state"]),
            holder_liveness=proc.UNKNOWN))
        # And the reason reaches the PROGRAM's stream, where an operator reads it -- not only
        # the per-run log, which the inbox and the handoff bundle never open.
        classified = [json.loads(e["detail_json"] or "{}")
                      for e in self.h.sstore.events(program_id=pid_b)
                      if e["event_type"] == ev_mod.RECONCILIATION_CLASSIFIED]
        self.assertIn("WORKER_LIVENESS_UNKNOWN", [d.get("classification") for d in classified])

        # AND IT STAYS RECOVERABLE. A refusal that ended the story would be worse than the
        # release it prevented: a terminal run holding its fence for good, every later dispatch
        # refused LEASE_CONFLICT, and nothing automatic or operator-driven able to undo it. The
        # next pass re-probes and finishes the job it declined to finish on the last one.
        self._probeable(lock_b)
        self.assertEqual(self._liveness(run_b), proc.DEAD)
        actions = self._actions(self._reap(pid_b))
        self.assertIn("CRASH_RECOVERED", actions)
        self.assertIn("RETRY_SCHEDULED", actions)
        self.assertEqual(str(self.h.store.get_run(run_b)["execution_state"]),
                         domain.WORKER_FAILED)
        self.assertIsNotNone(self.h.store.lease_for_run(run_b)["released_at"],
                             "the refused reclaim was never re-attempted: the lane is stranded")

    @control(399)
    def test_an_escalation_that_did_not_happen_is_never_recorded_as_having_happened(self):
        """CONTROL (bd quaestor-9ap): the durable ``escalated`` marker must be written AFTER the
        escalation it describes, never before. Written first, a reaper that dies in the two-write
        window leaves a lane that can never escalate again: the guard reads the flag, returns,
        and the lane holds its lease for ever with nothing on any desk -- the exact outcome the
        marker is durable in order to prevent."""
        pid, lane_id, run_id = self._start_one_lane(self._live_worker_spawner(), "died-parking")
        lock_path = self.locks[-1][1]
        self._unprobeable(lock_path)

        bound = orch.UNKNOWN_LIVENESS_ESCALATION_PASSES
        for i in range(bound - 1):
            self.assertIn("LIVENESS_UNKNOWN_HELD", self._actions(self._reap(pid)),
                          "pass %d should hold" % (i + 1))

        # THE REAPER DIES ON THE PASS THAT WOULD ESCALATE, while parking the lane.
        dying = _DiesParkingTheLane(self.h.sstore.path)
        self.addCleanup(dying.close)
        with self.assertRaises(RuntimeError):
            self._reap(pid, sstore=dying)

        # NOTHING may claim the escalation happened, because it did not.
        mark = ((self.h.sstore.get_lane_task(lane_id) or {}).get("checkpoint")
                or {}).get(orch.UNKNOWN_LIVENESS_KEY) or {}
        self.assertFalse(mark.get("escalated"),
                         "the marker says this lane escalated, but the escalation raised: every "
                         "later pass will now return early and the lane is stranded for good")

        # AND THE NEXT PASS STILL REACHES THE OWNER.
        actions = self._actions(self._reap(pid))
        self.assertIn("LIVENESS_UNKNOWN_ESCALATED", actions,
                      "the lane never escalated at all: %r" % (actions,))
        self.assertEqual(str(self.h.sstore.get_lane(lane_id).state),
                         prog_mod.LANE_WAITING_OWNER)
        self.assertTrue(self._blockers(lane_id),
                        "the owner was given no blocker to act on")

    @control(400)
    def test_reap_reaches_its_own_child_collection_before_judging_an_unknown(self):
        """CONTROL (bd quaestor-9ap): the child-collection arm this branch added must be
        REACHED, not merely defined. It sits on the UNKNOWN arm precisely because an
        uncollected POSIX zombie still answers ``kill(pid, 0)`` and still publishes its start
        time, so classify_liveness reads UNKNOWN and an ordinary crashed worker would be held
        and escalated instead of taking its bounded retry. Deleting the call site is otherwise
        an undetected one-line change."""
        pid, lane_id, run_id = self._start_one_lane(self._live_worker_spawner(), "collect-child")
        lock_path = self.locks[-1][1]
        self._unprobeable(lock_path)
        self.assertEqual(self._liveness(run_id), proc.UNKNOWN,
                         "the fixture did not produce the UNKNOWN arm this control measures")

        seen = []
        real = orch._collect_own_child

        def spy(pidarg, recorded_ct):
            seen.append((str(pidarg), str(recorded_ct)))
            return real(pidarg, recorded_ct)

        orch._collect_own_child = spy
        self.addCleanup(setattr, orch, "_collect_own_child", real)
        self._reap(pid)
        self.assertTrue(seen, "reap never reached _collect_own_child on the UNKNOWN arm: an "
                              "uncollected corpse keeps answering probes, so a crashed worker "
                              "is held and escalated instead of retried")
        worker = self.h.store.get_worker(run_id) or {}
        self.assertEqual(seen[0][0], str(worker.get("worker_pid")),
                         "reap tried to collect a pid that is not this run's worker: %r" % (seen,))

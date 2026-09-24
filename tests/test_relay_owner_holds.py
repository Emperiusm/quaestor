"""test_relay_owner_holds -- controls 353-360. An OWNER_HOLD is a durable authority requirement.

WHAT quaestor-7ze WAS
---------------------
``_release_owner_held`` re-gated only messages parked ``OWNER_HELD``, and ONLY the DIRECTIVE gate
parks one. The START gate and the OBSERVATION gate set ``relay.owner_hold`` and stopped, leaving
no message -- so on resume the re-gate found no rows, returned None, and ``resume()`` went
straight to ``state=RUNNING, stop_reason=""`` and delivered the queued turn. No owner grant was
required, consulted, or recorded anywhere. Any caller who could ask for a resume could walk past
an authority boundary that had genuinely been reached.

WHAT THESE CONTROLS PROVE
-------------------------
    a hold from ANY gate outlives a resume            no grant -> still held
    a matching owner decision discharges it           and only then
    a decision for a DIFFERENT capability does not    GIT_COMMIT is not GIT_PUSH
    a decision for a DIFFERENT relay does not         scope is real
    the discharge happens exactly once                replay is not a second approval
    it survives a restart in both directions          held stays held, granted stays granted
    an unidentifiable hold fails CLOSED               absence of evidence is not approval

THE SEAM. ``RelayKernel`` takes ``owner_grants`` and ``channel_state`` as injected callables --
the same seam production uses, where they read the signed grant ledger and the attestation-backed
owner channel. Injecting them here is what lets these controls run on POSIX at all: the real
channel is DPAPI-backed and therefore Windows-only, so a control that provisioned a real key
could only ever run on one of the two platforms this project ships on. What is injected is the
ANSWER the owner channel gives, never a way to bypass asking it.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest

from tests.controls import control

from quaestor.core import authority as auth_mod
from quaestor.relay import effects as effects_mod
from quaestor.relay import kernel as kernel_mod
from quaestor.relay import state as state_mod
from quaestor.relay.ends.fake import FakeExecutionEnd, FakeOrchestratorEnd


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=60, shell=False)


def make_repo(root: str) -> str:
    os.makedirs(root, exist_ok=True)
    git(["init", "-q"], root)
    git(["config", "user.email", "o@example.invalid"], root)
    git(["config", "user.name", "O"], root)
    with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("fixture\n")
    git(["add", "-A"], root)
    git(["commit", "-qm", "init"], root)
    return root


def grant_row(capability: str, *, grant_id: str = "g-1", revoked_at=None, expires_at=None) -> dict:
    """The shape ``Store.owner_grants`` returns -- a SIGNED owner decision, as the kernel sees it."""
    return {"grant_id": grant_id, "capability": capability, "scope": "*",
            "granted_at": 1.0, "expires_at": expires_at, "revoked_at": revoked_at, "note": ""}


class _StoreThatCannotAnswer:
    """A ledger that is present and cannot be read: a full disk, a locked file, a corrupt page.

    Not a stub of the store's logic -- it delegates every readable call to the REAL state -- so a
    control built on it exercises the actual function against the actual data, and only the two
    reads under test fail.
    """

    def __init__(self, real, *, get=True, events=True):
        self._real, self._get, self._events = real, get, events

    def get(self, *a, **k):
        if self._get:
            raise OSError("the relay ledger could not be read")
        return self._real.get(*a, **k)

    def events(self, *a, **k):
        if self._events:
            raise OSError("the event log could not be read")
        return self._real.events(*a, **k)


class OwnerHoldFixture(unittest.TestCase):
    """A real relay ledger. The gates are exercised through the kernel's own helpers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = os.path.join(self._tmp.name, "home")
        os.makedirs(self.home)
        self.repo = make_repo(os.path.join(self._tmp.name, "repo"))
        self.db = os.path.join(self.home, "relay.sqlite3")
        self.st = state_mod.RelayState(self.db)
        self.addCleanup(self.st.close)
        self.relay_id = "relay-owner-1"
        # PROFILE GIT_PUSH on purpose. ``authority.require`` refuses at the PROFILE stage for
        # a capability the profile does not contain, and no owner grant widens a profile --
        # "capability expansion is an OWNER decision", made by choosing the profile. The owner
        # gate is the SECOND lock on a capability the profile already allows, and that second
        # lock is what these controls are about.
        self.profile = auth_mod.GIT_PUSH
        self.st.create(self.relay_id, project_root=self.repo, repo_id="", objective="o",
                       orchestrator_kind="openai-chat", execution_kind="opencode",
                       authority_profile=self.profile, config={})

    # -- raising a hold exactly as a gate does -------------------------------------------------
    def raise_hold(self, *, effect_class, required, gate="observation", message_id="",
                   relay_id=None, reason="an owner decision is required"):
        rid = relay_id or self.relay_id
        hid = effects_mod.hold_id(rid, gate, effect_class, required)
        self.st.append_event(rid, kernel_mod.EVENT_HOLD_RAISED,
                             {"hold_id": hid, "gate": gate, "effect_class": effect_class,
                              "required": list(required), "message_id": message_id,
                              "profile": self.profile, "reason": reason})
        self.st.update(rid, state=state_mod.OWNER_HOLD, owner_hold=reason)
        return hid

    def blocking(self, *, grants=(), channel=None, relay_id=None):
        return kernel_mod.owner_holds_blocking(
            self.st, relay_id or self.relay_id, profile=self.profile,
            owner_grants=list(grants), now=100.0,
            channel_state=channel or "UNAVAILABLE")


class AHoldOutlivesAResume(OwnerHoldFixture):

    @control(353)
    def test_a_hold_from_any_gate_is_outstanding_until_an_owner_decides(self):
        """The defect itself. Only the DIRECTIVE gate parked a message, so only it was re-gated.

        MUTATION THIS CATCHES: make ``outstanding_owner_holds`` read only holds whose payload
        carries a ``message_id`` (which is what keying on OWNER_HELD messages amounted to). The
        observation and start holds then vanish and this control fails.
        """
        # Each pairing is a hold the profile genuinely leaves outstanding: the START gate
        # refuses a write the profile lacks, and the other two reach an owner-gated capability
        # the profile allows but the owner has not yet decided.
        for gate, profile, effect_class, caps in (
                ("observation", auth_mod.GIT_PUSH, effects_mod.GIT_PUSH,
                 [auth_mod.CAP_GIT_PUSH]),
                ("start", auth_mod.READ_ONLY, effects_mod.STANDARD_EDIT,
                 [auth_mod.CAP_REPO_WRITE]),
                ("directive", auth_mod.GIT_PUSH, effects_mod.GIT_PUSH,
                 [auth_mod.CAP_GIT_PUSH])):
            with self.subTest(gate=gate):
                st = state_mod.RelayState(self.db)
                self.addCleanup(st.close)
                rid = "relay-%s" % gate
                st.create(rid, project_root=self.repo, repo_id="", objective="o",
                          orchestrator_kind="openai-chat", execution_kind="opencode",
                          authority_profile=profile, config={})
                hid = effects_mod.hold_id(rid, gate, effect_class, caps)
                st.append_event(rid, kernel_mod.EVENT_HOLD_RAISED,
                                {"hold_id": hid, "gate": gate, "effect_class": effect_class,
                                 "required": caps, "message_id": "",
                                 "profile": profile, "reason": "held"})
                st.update(rid, state=state_mod.OWNER_HOLD, owner_hold="held")

                outstanding = kernel_mod.outstanding_owner_holds(st, rid)
                self.assertEqual([h["hold_id"] for h in outstanding], [hid],
                                 "a %s hold left no outstanding requirement" % gate)
                blocked = kernel_mod.owner_holds_blocking(
                    st, rid, profile=profile, owner_grants=[], now=100.0,
                    channel_state="UNAVAILABLE")
                self.assertEqual([h["hold_id"] for h in blocked], [hid],
                                 "a %s hold did not block without an owner decision" % gate)

    @control(353)
    def test_an_authenticated_channel_alone_is_not_a_decision(self):
        """A channel that CAN carry an owner's yes is not an owner's yes."""
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        blocked = self.blocking(grants=[], channel="AUTHENTICATED")
        self.assertEqual([h["hold_id"] for h in blocked], [hid],
                         "an authenticated channel with no grant discharged a hold")


class OnlyAMatchingDecisionDischarges(OwnerHoldFixture):

    @control(354)
    def test_a_matching_owner_decision_discharges_the_hold_and_nothing_else_does(self):
        """MUTATION THIS CATCHES: drop the capability comparison in ``owner_channel.evaluate``
        (match any grant), and the GIT_COMMIT decision below discharges the GIT_PUSH hold."""
        push = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                               required=[auth_mod.CAP_GIT_PUSH])

        self.assertEqual(len(self.blocking(grants=[], channel="AUTHENTICATED")), 1)
        # A decision about a DIFFERENT capability is not a decision about this one.
        wrong = [grant_row(auth_mod.CAP_GIT_COMMIT)]
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=wrong,
                                                              channel="AUTHENTICATED")],
                         [push], "a GIT_COMMIT decision discharged a GIT_PUSH hold")
        # A REVOKED decision is not a decision.
        revoked = [grant_row(auth_mod.CAP_GIT_PUSH, revoked_at=50.0)]
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=revoked,
                                                              channel="AUTHENTICATED")],
                         [push], "a revoked grant discharged a hold")
        # The matching one, through an authenticated channel, does.
        right = [grant_row(auth_mod.CAP_GIT_PUSH)]
        self.assertEqual(self.blocking(grants=right, channel="AUTHENTICATED"), [],
                         "a matching owner decision did not discharge the hold")
        # ...and the SAME grant with the channel unavailable does not: the ledger row is a
        # record that someone said yes, not a verified owner decision.
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=right,
                                                              channel="UNAVAILABLE")],
                         [push], "a grant was honoured with no owner channel")

    @control(355)
    def test_a_decision_cannot_cross_to_another_relay(self):
        """Scope is enforced by WHICH grants a relay is shown, and the id makes it visible.

        MUTATION THIS CATCHES: have ``_owner_hooks`` call ``store.owner_grants()`` with no scope
        again -- a relay-scoped grant then becomes invisible, and this control's second half
        (the narrow grant reaching its own relay) fails.
        """
        from quaestor.core.store import Store
        from quaestor.relay import cli as relay_cli

        db = os.path.join(self.home, "orchestrator.sqlite3")
        store = Store(db)
        try:
            store.add_owner_grant(auth_mod.CAP_GIT_PUSH, scope="relay-mine")
            store.add_owner_grant(auth_mod.CAP_GIT_COMMIT, scope="*")
        finally:
            store.close()

        mine, _c = relay_cli._owner_hooks(self.home, scope="relay-mine")
        theirs, _c2 = relay_cli._owner_hooks(self.home, scope="relay-theirs")
        mine_caps = sorted(g["capability"] for g in mine())
        theirs_caps = sorted(g["capability"] for g in theirs())

        self.assertIn(auth_mod.CAP_GIT_PUSH, mine_caps,
                      "a grant scoped to this relay did not reach it")
        self.assertNotIn(auth_mod.CAP_GIT_PUSH, theirs_caps,
                         "a grant scoped to one relay reached another")
        # A grant the owner deliberately signed as global still applies everywhere -- that is
        # the product's existing scope model, and narrowing it is not this change's business.
        self.assertIn(auth_mod.CAP_GIT_COMMIT, theirs_caps)

        # And the hold identity itself distinguishes relays, so even identical requirements on
        # two relays are two different outstanding things.
        self.assertNotEqual(
            effects_mod.hold_id("relay-mine", "observation", effects_mod.GIT_PUSH,
                                [auth_mod.CAP_GIT_PUSH]),
            effects_mod.hold_id("relay-theirs", "observation", effects_mod.GIT_PUSH,
                                [auth_mod.CAP_GIT_PUSH]))


class DischargeIsDurableAndHappensOnce(OwnerHoldFixture):

    @control(356)
    def test_a_discharge_is_recorded_once_and_survives_a_restart(self):
        """MUTATION THIS CATCHES: make ``outstanding_owner_holds`` ignore EVENT_HOLD_DISCHARGED
        (drop the ``open_holds.pop``) and a settled hold is reported outstanding forever.

        Note what this control does NOT catch: it writes the discharge event itself, so a
        mutation that stopped ``_release_owner_held`` from WRITING one would pass here. That
        writer is covered by the real-process qualification, where a genuine resume must record
        the discharge for the next one to proceed.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED,
                             {"hold_id": hid, "required": [auth_mod.CAP_GIT_PUSH]})

        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [],
                         "a discharged hold is still outstanding")
        # A REPLAYED discharge is not a second approval and not an error: it is the same fact.
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED,
                             {"hold_id": hid, "required": [auth_mod.CAP_GIT_PUSH]})
        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [])

        # ACROSS A RESTART: a brand-new reader of the same durable store agrees.
        self.st.close()
        reopened = state_mod.RelayState(self.db)
        self.addCleanup(reopened.close)
        self.assertEqual(kernel_mod.outstanding_owner_holds(reopened, self.relay_id), [])

    @control(356)
    def test_a_hold_survives_a_restart_when_no_decision_was_made(self):
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        self.st.close()
        reopened = state_mod.RelayState(self.db)
        self.addCleanup(reopened.close)
        outstanding = kernel_mod.outstanding_owner_holds(reopened, self.relay_id)
        self.assertEqual([h["hold_id"] for h in outstanding], [hid],
                         "a hold did not survive the process that raised it")
        blocked = kernel_mod.owner_holds_blocking(
            reopened, self.relay_id, profile=self.profile, owner_grants=[],
            now=100.0, channel_state="AUTHENTICATED")
        self.assertEqual([h["hold_id"] for h in blocked], [hid])

    @control(363)
    def test_the_same_requirement_raised_again_is_outstanding_again(self):
        """The defect five review lenses found independently, and the one my first controls missed.

        A hold id is content-addressed, so the SAME requirement refused twice carries the SAME
        id. Computing outstanding as (set of raised) minus (set of discharged) therefore let ONE
        discharge absorb every future raising of it, forever: an owner who granted a push once,
        whose grant then expired or was revoked, would have had every later push waved through.
        The hold was born discharged, nothing blocked, and the column was actively cleared --
        quaestor-7ze with an extra step, and it silently neutralised the expiry enforcement
        shipped beside it.

        MUTATION THIS CATCHES: compute ``live`` as a set difference over the whole log again
        (``[raised[h] for h in raised if h not in discharged]``). The re-raise below then reads
        as discharged and this control fails.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        live = [grant_row(auth_mod.CAP_GIT_PUSH, expires_at=1000.0)]
        self.assertEqual(self.blocking(grants=live, channel="AUTHENTICATED"), [],
                         "a live decision did not discharge the hold")
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED,
                             {"hold_id": hid, "required": [auth_mod.CAP_GIT_PUSH]})
        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [])

        # THE GRANT LAPSES and the agent reaches for the same effect again. The gate refuses and
        # raises the same identity -- which must be outstanding again, not pre-discharged.
        again = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                                required=[auth_mod.CAP_GIT_PUSH])
        self.assertEqual(again, hid, "the identity should be stable; that is the point")
        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual([h["hold_id"] for h in outstanding], [hid],
                         "a re-raised hold was born discharged")
        expired = [grant_row(auth_mod.CAP_GIT_PUSH, expires_at=50.0)]
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=expired,
                                                              channel="AUTHENTICATED")], [hid],
                         "an expired grant discharged a re-raised hold")
        # ...and a replayed discharge is STILL idempotent: it settles the raising it follows.
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED, {"hold_id": hid})
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED, {"hold_id": hid})
        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [])

    @control(363)
    def test_a_directive_decision_does_not_discharge_an_observed_effect(self):
        """Approving a REQUEST is not approving something already done and never asked about.

        MUTATION THIS CATCHES: drop the gate from ``hold_id``'s hashed tuple. The two holds
        below then collide and the directive's discharge silently settles the observation.
        """
        directive = self.raise_hold(gate="directive", effect_class=effects_mod.GIT_PUSH,
                                    required=[auth_mod.CAP_GIT_PUSH], message_id="m-1")
        observed = self.raise_hold(gate="observation", effect_class=effects_mod.GIT_PUSH,
                                   required=[auth_mod.CAP_GIT_PUSH])
        self.assertNotEqual(directive, observed,
                            "a requested push and an observed push are the same identity")
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED,
                             {"hold_id": directive})
        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual([h["hold_id"] for h in outstanding], [observed],
                         "discharging the directive also discharged the observation")

    @control(357)
    def test_a_second_hold_is_not_covered_by_the_first_decision(self):
        """hold A: GIT_COMMIT approved. Later hold B: GIT_PUSH. A must not discharge B.

        MUTATION THIS CATCHES: derive the hold id from the relay alone (dropping effect class
        and capabilities) -- the second hold then collides with the first and reads discharged.
        """
        a = self.raise_hold(effect_class=effects_mod.GIT_COMMIT,
                            required=[auth_mod.CAP_GIT_COMMIT])
        self.st.append_event(self.relay_id, kernel_mod.EVENT_HOLD_DISCHARGED, {"hold_id": a})
        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [])

        b = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                            required=[auth_mod.CAP_GIT_PUSH])
        self.assertNotEqual(a, b)
        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual([h["hold_id"] for h in outstanding], [b],
                         "an old discharge covered a new hold")
        # And the earlier COMMIT decision does not cover the new PUSH requirement.
        blocked = self.blocking(grants=[grant_row(auth_mod.CAP_GIT_COMMIT)],
                                channel="AUTHENTICATED")
        self.assertEqual([h["hold_id"] for h in blocked], [b])



class AnObservedEffectIsAnAuthorityQuestion(OwnerHoldFixture):
    """quaestor-7rh: the regression the 7ze fix itself introduced.

    ``_raise_owner_hold`` decided "is this an authority requirement?" from an ALLOWLIST OF TWO
    HOLD NAMES. The observation gate's authority refusal is a third name, so the single refusal
    quaestor-7ze was actually filed about -- "the repository shows a GIT_PUSH that this profile
    does not grant" -- took the measurement branch, recorded no event, and never reached the
    column write below it. ``outstanding_owner_holds`` then found nothing raised and an empty
    column, and answered []. The relay resumed with no owner decision consulted anywhere.
    """

    def kernel(self, *, profile):
        """A REAL kernel with the production seam, not a stand-in for one."""
        k = kernel_mod.RelayKernel(
            st=self.st, orchestrator=FakeOrchestratorEnd(replies=[]),
            execution=FakeExecutionEnd(replies=[]), project_root=self.repo,
            relay_id=self.relay_id,
            config=kernel_mod.RelayConfig(objective="o", authority_profile=profile),
            owner_grants=lambda: [], channel_state=lambda: "AUTHENTICATED")
        return k

    @control(365)
    def test_an_observed_ungranted_effect_is_a_durable_owner_requirement(self):
        """MUTATION THIS CATCHES: classify by the hold NAME again --
        ``if gate.hold not in (HOLD_OWNER_REQUIRED, HOLD_PROFILE_CEILING)`` -- and this observed
        push records nothing, outstanding_owner_holds answers [], and the resume walks past it.

        The gate here is produced by the REAL ``gate_observation`` from two real repository
        readings, so the control cannot drift away from what production actually raises.
        """
        # A REAL observed push: both sides probed, and the UPSTREAM head moved. Nothing here
        # says "push" -- observed_effect_class infers it, which is the whole point of the gate.
        gate = effects_mod.gate_observation(
            {"probe_ok": True, "head": "aaa", "upstream_head": "aaa"},
            {"probe_ok": True, "head": "bbb", "upstream_head": "bbb"},
            profile=auth_mod.STANDARD_EDIT, owner_grants=[], now=100.0,
            channel_state="AUTHENTICATED")
        self.assertFalse(gate.allowed, "an observed push must not be allowed to STANDARD_EDIT")
        self.assertEqual(gate.hold, effects_mod.HOLD_OBSERVED_UNGRANTED_EFFECT)
        self.assertTrue(gate.required, "the gate must name the capabilities it found missing")

        hid = self.kernel(profile=auth_mod.STANDARD_EDIT)._raise_owner_hold(
            gate, gate_name="observation")
        self.assertTrue(hid, "an observed ungranted effect recorded no durable requirement")

        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual(len(outstanding), 1, "the hold did not survive as a requirement")
        self.assertEqual(sorted(outstanding[0]["required"]), sorted(gate.required))
        self.assertTrue(str((self.st.get(self.relay_id) or {}).get("owner_hold") or ""),
                        "the owner_hold column was never set, so both fail-closed recoveries "
                        "would have been skipped too")

        # AND IT ACTUALLY BLOCKS, with no grant.
        self.assertEqual(len(self.blocking(grants=(), channel="AUTHENTICATED")), 1)

    @control(365)
    def test_a_refusal_that_names_no_capability_is_not_an_owner_requirement(self):
        """The other half, and the reason the rule is "does it name missing capabilities" rather
        than "did any gate refuse". A repository that could not be read on both sides of a turn
        is a MEASUREMENT failure: no grant could discharge it, so parking it as an owner
        requirement would strand the relay somewhere no owner could release it from.

        MUTATION THIS CATCHES: record a durable hold for every refusal. This control then finds
        an undischargeable requirement on a relay whose only problem was an unreadable repo.
        """
        # probe_ok False on one side: the turn is UNMEASURED, not clean.
        gate = effects_mod.gate_observation(
            {"probe_ok": True, "head": "aaa"}, {"probe_ok": False},
            profile=auth_mod.STANDARD_EDIT, owner_grants=[], now=100.0,
            channel_state="AUTHENTICATED")
        self.assertFalse(gate.allowed)
        self.assertFalse(gate.required, "a measurement failure names no missing capability")

        hid = self.kernel(profile=auth_mod.STANDARD_EDIT)._raise_owner_hold(
            gate, gate_name="observation")
        self.assertEqual(hid, "", "a refusal no grant could discharge became an owner hold")
        self.assertEqual(kernel_mod.outstanding_owner_holds(self.st, self.relay_id), [])


class UncertaintyFailsClosed(OwnerHoldFixture):

    @control(358)
    def test_a_hold_whose_requirement_cannot_be_identified_is_still_a_hold(self):
        """The upgrade case, and the fail-closed rule.

        A relay held by the code that shipped BEFORE this record has ``owner_hold`` set and no
        raised event. Reading "no outstanding requirements" from that would silently discharge
        every hold in flight at upgrade time.

        MUTATION THIS CATCHES: return [] when no raised event is found. This control then reads
        the hold as discharged and fails.
        """
        self.st.update(self.relay_id, state=state_mod.OWNER_HOLD,
                       owner_hold="a GIT_PUSH the profile does not grant")
        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual(len(outstanding), 1, "a legacy hold vanished")
        self.assertIs(outstanding[0].get("unidentified"), True)
        self.assertEqual(outstanding[0].get("required"), [])

        # AND NO GRANT CAN DISCHARGE IT. An empty requirement satisfies ``require`` trivially,
        # so a hold with no identified capability must be refused rather than evaluated.
        for grants in ([], [grant_row(auth_mod.CAP_GIT_PUSH)],
                       [grant_row(c) for c in auth_mod.ALL_CAPABILITIES]):
            blocked = self.blocking(grants=grants, channel="AUTHENTICATED")
            self.assertEqual(len(blocked), 1,
                             "a hold with no identifiable requirement was discharged by %d "
                             "grant(s)" % len(grants))

    @control(364)
    def test_a_ledger_that_cannot_be_read_does_not_discharge_a_hold(self):
        """UNREADABLE IS NOT EMPTY.

        This function swallows both store reads so it can never raise, and resume, the CLI
        pre-check, Core's ``_not_resumable`` and ``summarise`` ALL read only this function. So a
        store failure that answered [] would discharge every outstanding requirement at once
        with no owner decision anywhere -- the quaestor-7ze bypass, reached by a failing disk
        instead of a missing branch.

        MUTATION THIS CATCHES: drop the ``unreadable`` flag and let the unread row fall through
        to ``return []``. The live hold vanishes and this control fails.
        """
        self.raise_hold(effect_class=effects_mod.GIT_PUSH, required=[auth_mod.CAP_GIT_PUSH])
        self.assertEqual(len(kernel_mod.outstanding_owner_holds(self.st, self.relay_id)), 1,
                         "the hold must be real while the ledger still answers")

        blind = _StoreThatCannotAnswer(self.st)
        outstanding = kernel_mod.outstanding_owner_holds(blind, self.relay_id)
        self.assertEqual(len(outstanding), 1, "an unreadable ledger discharged a live hold")
        self.assertIs(outstanding[0].get("unidentified"), True)
        self.assertIs(outstanding[0].get("unreadable"), True)

        # AND NOTHING DISCHARGES IT, because nothing can be shown to. Not even every capability
        # the build has, on an authenticated owner channel.
        for grants in ([], [grant_row(auth_mod.CAP_GIT_PUSH)],
                       [grant_row(c) for c in auth_mod.ALL_CAPABILITIES]):
            blocked = kernel_mod.owner_holds_blocking(
                blind, self.relay_id, profile=self.profile, owner_grants=list(grants),
                now=100.0, channel_state="AUTHENTICATED")
            self.assertEqual(len(blocked), 1,
                             "an unreadable ledger was discharged by %d grant(s)" % len(grants))

    @control(364)
    def test_an_unreadable_event_log_alone_does_not_invent_a_hold(self):
        """The other half, so the rule is not the useless "block whenever anything fails".

        A READABLE, EMPTY ``owner_hold`` column is real evidence of absence -- every gate that
        raises a hold sets it, and only a discharge clears it -- so an unreadable event log on a
        relay with a clean column must not manufacture a hold that an owner would then have to
        clear by hand.

        MUTATION THIS CATCHES: fail closed on EITHER read failing. This control then reads a
        hold on a relay that was never held, and fails.
        """
        deaf = _StoreThatCannotAnswer(self.st, get=False, events=True)
        self.assertEqual(kernel_mod.outstanding_owner_holds(deaf, self.relay_id), [],
                         "an unreadable event log invented a hold on an unheld relay")

    @control(358)
    def test_a_legacy_hold_is_reconstructed_from_the_gate_that_refused_it(self):
        """Better than opaque when the evidence exists: the gate event already recorded what it
        required, so a hold raised before this record can still be discharged by the right
        decision -- and only by the right one."""
        self.st.append_event(self.relay_id, "relay.gate.observation",
                             {"allowed": False, "effect_class": effects_mod.GIT_PUSH,
                              "required": [auth_mod.CAP_GIT_PUSH], "hold": "OWNER_REQUIRED",
                              "reason": "the repository shows a push"})
        self.st.update(self.relay_id, state=state_mod.OWNER_HOLD, owner_hold="the repo pushed")

        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual(len(outstanding), 1)
        self.assertIs(outstanding[0].get("reconstructed"), True)
        self.assertEqual(outstanding[0]["required"], [auth_mod.CAP_GIT_PUSH])
        # The WRONG decision still does not discharge it...
        self.assertEqual(len(self.blocking(grants=[grant_row(auth_mod.CAP_GIT_COMMIT)],
                                           channel="AUTHENTICATED")), 1)
        # ...and the right one does.
        self.assertEqual(self.blocking(grants=[grant_row(auth_mod.CAP_GIT_PUSH)],
                                       channel="AUTHENTICATED"), [])

    @control(358)
    def test_an_unreadable_ledger_is_not_an_approval(self):
        """Every reader here swallows its errors so a status surface never crashes. That must
        not turn a store it cannot read into a store with nothing outstanding."""

        class Unreadable:
            def events(self, *a, **k):
                raise OSError("the relay ledger could not be read")

            def get(self, *a, **k):
                return {"owner_hold": "something was required"}

        holds = kernel_mod.outstanding_owner_holds(Unreadable(), "relay-x")
        self.assertEqual(len(holds), 1, "an unreadable ledger read as nothing outstanding")
        blocked = kernel_mod.owner_holds_blocking(
            Unreadable(), "relay-x", profile=auth_mod.GIT_PUSH,
            owner_grants=[grant_row(c) for c in auth_mod.ALL_CAPABILITIES],
            now=100.0, channel_state="AUTHENTICATED")
        self.assertEqual(len(blocked), 1, "an unreadable ledger was discharged by grants")


class AnExpiredDecisionIsNotADecision(OwnerHoldFixture):

    @control(361)
    def test_an_expired_owner_grant_does_not_discharge_a_hold(self):
        """``quaestor grant --expires`` wrote a deadline that nothing ever read.

        MUTATION THIS CATCHES: stop passing ``now`` from ``authority.require`` into
        ``owner_channel.gate`` (restore the original), and the expired grant below discharges
        the hold again.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        expired = [grant_row(auth_mod.CAP_GIT_PUSH, expires_at=50.0)]   # now=100.0
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=expired,
                                                              channel="AUTHENTICATED")],
                         [hid], "an expired owner grant discharged a hold")

        still_valid = [grant_row(auth_mod.CAP_GIT_PUSH, expires_at=1000.0)]
        self.assertEqual(self.blocking(grants=still_valid, channel="AUTHENTICATED"), [],
                         "an unexpired grant failed to discharge a hold")

        # A grant with an UNREADABLE expiry is not live either: uncertainty fails closed.
        broken = [grant_row(auth_mod.CAP_GIT_PUSH, expires_at="soon")]
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=broken,
                                                              channel="AUTHENTICATED")],
                         [hid], "a grant with an unreadable expiry was honoured")

        # And a grant with NO expiry is still a standing decision -- unchanged behaviour.
        self.assertEqual(self.blocking(grants=[grant_row(auth_mod.CAP_GIT_PUSH)],
                                       channel="AUTHENTICATED"), [])


class TheDecisionIsNotTheEffect(OwnerHoldFixture):

    @control(359)
    def test_discharging_a_hold_performs_no_effect_of_its_own(self):
        """Authority and execution stay apart: releasing a hold puts the refused directive back
        in the DELIVERY QUEUE, where the ordinary governed path picks it up. It does not send.

        STRUCTURAL, because the alternative is asserting on a mock. ``_release_owner_held`` must
        not call anything that talks to an endpoint.
        """
        import ast
        with open(kernel_mod.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=kernel_mod.__file__)
        fn = [n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_release_owner_held"][0]
        called = {ast.unparse(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)}
        for forbidden in ("self.execution.send", "self.orchestrator.send",
                          "self.execution.receive", "self.orchestrator.receive",
                          "self._deliver", "self.step"):
            self.assertNotIn(forbidden, called,
                             "releasing a hold performed the effect it merely authorised")
        # What it DOES do is put the message back on the queue for the governed path.
        self.assertIn("self.state.mark_delivery", called)


class DenialIsReal(OwnerHoldFixture):

    @control(362)
    def test_an_owner_who_does_not_grant_leaves_the_hold_standing_forever(self):
        """Denial in this model is the ABSENCE of a decision, and it is not worn down.

        The vocabulary here is grant and revoke, not approve/deny -- so "the owner said no" is
        expressed by never signing the grant, and by ending the relay. What must NOT happen is
        the shape the bead describes: resume after resume until some caller gets through.

        MUTATION THIS CATCHES: make ``owner_holds_blocking`` return [] after N calls, or cache
        its verdict; the hundred attempts below then stop being refused.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        for attempt in range(100):
            blocked = self.blocking(grants=[], channel="AUTHENTICATED")
            self.assertEqual([h["hold_id"] for h in blocked], [hid],
                             "the hold gave way on attempt %d" % attempt)

        # A REVOKED grant is the owner changing their mind, and it does not discharge either.
        revoked = [grant_row(auth_mod.CAP_GIT_PUSH, revoked_at=99.0)]
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=revoked,
                                                              channel="AUTHENTICATED")], [hid])

    @control(362)
    def test_a_held_relay_can_be_ended_and_ending_it_is_not_approving(self):
        """The honest terminal outcome: an owner who will not grant stops the relay.

        Stopping must be available -- a hold that could neither proceed nor end would pin the
        work and, through Core's obligation check, the service with it. And it must not look
        like approval: the requirement stays outstanding in the record.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH])
        self.assertTrue(
            self.st.request_stop(self.relay_id, "STOPPED_BY_OPERATOR",
                                 from_states=(state_mod.RUNNING, state_mod.PAUSED,
                                              state_mod.OWNER_HOLD),
                                 by="an operator who declined to grant it"),
            "a relay parked on an owner hold could not be ended")
        row = self.st.get(self.relay_id)
        self.assertEqual(row["state"], state_mod.STOPPED)
        self.assertEqual(row["stop_reason"], "STOPPED_BY_OPERATOR")
        # ENDING IS NOT APPROVING. The requirement is still outstanding and still uncovered.
        outstanding = kernel_mod.outstanding_owner_holds(self.st, self.relay_id)
        self.assertEqual([h["hold_id"] for h in outstanding], [hid],
                         "stopping a relay discharged its owner hold")
        self.assertEqual([h["hold_id"] for h in self.blocking(grants=[],
                                                              channel="AUTHENTICATED")], [hid])


class TheHoldIsVisibleToAnOperator(OwnerHoldFixture):

    @control(360)
    def test_status_names_the_capability_the_owner_must_decide(self):
        """An operator cannot act on 'a hold'. They can act on 'this relay needs git_push'.

        MUTATION THIS CATCHES: drop ``owner_holds`` from ``summarise`` and an operator is back
        to reading the event log by hand to find out what to sign.
        """
        hid = self.raise_hold(effect_class=effects_mod.GIT_PUSH,
                              required=[auth_mod.CAP_GIT_PUSH],
                              reason="a GIT_PUSH the profile does not grant")
        summary = kernel_mod.summarise(self.st, self.relay_id)
        self.assertTrue(summary["owner_hold"])
        holds = summary.get("owner_holds") or []
        self.assertEqual([h["hold_id"] for h in holds], [hid])
        self.assertEqual(holds[0]["required"], [auth_mod.CAP_GIT_PUSH])
        self.assertEqual(holds[0]["effect_class"], effects_mod.GIT_PUSH)
        self.assertEqual(holds[0]["gate"], "observation")
        # The whole point: the capability an owner would have to grant is named in the surface.
        self.assertIn(auth_mod.CAP_GIT_PUSH, json.dumps(summary))


if __name__ == "__main__":
    unittest.main()

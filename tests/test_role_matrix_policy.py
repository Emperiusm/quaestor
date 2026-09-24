"""test_role_matrix_policy -- CONTROLS on seat routing, provider chains and epistemic
independence (direction doc section 3, sections 3.2/3.1; bd quaestor-kaz.2/.4/.5/.6), plus the
DISPATCHABILITY of the codex-cli reviewer executor (bd quaestor-1ng).

THE INVARIANTS THESE CONTROLS PIN
---------------------------------
Section 3: "any model may hold any role" -- and, just as binding, "no forbidden pairing
passes admission". Concretely:

  * EVERY SEAT RESOLVES. Each assignable seat resolves over the registry after the config
    merge (pins + chains + default); an UNKNOWN seat or UNDECLARED kind is a NAMED refusal
    (SEAT_UNRESOLVABLE), never a silent fallback to the wrong provider.

  * OWNER IS UNASSIGNABLE THROUGH ANY PATH. Not by parse alone: the resolver, the chain
    router and the orchestrator's chain layer each refuse the human seat BY NAME.

  * PAIRING POLICY FIRES BEFORE SPAWN. Both forms -- require_distinct_provider_between and
    require_distinct_provider_for -- are checked AT ADMISSION against MEASURED
    run.provenance seats, so a same-family reviewer never spawns over a diff it shares a
    blind spot with. Refusals route through the fix/escalation path (HIGH finding,
    'epistemic independence unmet').

  * FAILOVER IS RECONCILIATION-AWARE. A chain switches on measured death-before-effects;
    across an AMBIGUOUS write it refuses (CHAIN_BLOCKED_AMBIGUOUS_WRITE): "'try the next
    model' must not become a disguised blind retry". A fallback that would breach
    require_distinct_provider_between is refused rather than breaching the pair.

  * REGISTRY FACTS ARE DECLARATIONS. Routing consults declarations; the measured truth
    about who ran lives in run.provenance. The unproven entries say so (health/quota None),
    and a control holds them to it.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.adapters import registry as cap_reg     # noqa: E402
from quaestor.core import authority as authority_mod  # noqa: E402
from quaestor.core import orchestrator as orch        # noqa: E402
from quaestor.core import review_contract as rc_mod   # noqa: E402
from quaestor.projects import config as proj_cfg      # noqa: E402
from tests.test_operational_e2e import EngineHarness  # noqa: E402


def _write_manifest(text: str, name: str = "quaestor.yaml") -> str:
    d = tempfile.mkdtemp(prefix="qx-matrix-policy-")
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _read_blocker_text(h, pid):
    """Concatenated BLOCKER payloads across the program's lanes (the escalation record)."""
    out = []
    for lane in h.sstore.lanes(pid):
        for m in h.sstore.messages(lane.lane_id):
            if m["message_type"] == "BLOCKER":
                out.append(str(m["payload"]))
    return "\n".join(out)


class TestEverySeatResolvable(unittest.TestCase):
    """CONTROL: every matrix seat resolves post-merge; unknowns refuse BY NAME."""

    MANIFEST = (
        "project:\n"
        "  name: seats\n"
        "  repository: .\n"
        "executors:\n"
        "  default: fake\n"
        "  roles:\n"
        "    planner:\n"
        "      kind: gpt-plan\n"
        "      providers:\n"
        "        chain: [\"gpt-plan\", \"claude-cli\", \"local-llama\"]\n"
        "        fallback_policy: availability_only\n"
        "    verification: gemini-cli\n")

    def test_registry_covers_every_assignable_seat_after_config_merge(self):
        cfg, reason = proj_cfg.load(_write_manifest(self.MANIFEST))
        self.assertEqual(reason, "")
        # The merge is observable: pinned seats carry their pin, chained seats carry the
        # order, everything else falls back to the project default at resolution time.
        self.assertEqual(cfg.role_chains,
                         {"planner": ("gpt-plan", "claude-cli", "local-llama")})
        self.assertEqual(cfg.role_fallback_policy, {"planner": "availability_only"})
        for role in proj_cfg.ASSIGNABLE_ROLES:
            decision = cap_reg.resolve_seat(role, {}, cfg.role_executor)
            self.assertEqual(decision.refusal, "",
                             "%s: %s" % (role, decision.rationale))
            self.assertTrue(decision.kind)
            self.assertTrue(cap_reg.is_declared(decision.kind))

    def test_unpinned_seats_still_resolve_over_the_default(self):
        decision = cap_reg.resolve_seat("integration", {}, {})
        self.assertEqual((decision.kind, decision.refusal), ("fake", ""))

    def test_unknown_seat_refuses_by_name_end_to_end(self):
        # Parse-time half (typo'd role key): refused with the offending key named.
        path = _write_manifest(
            "project:\n  name: typo\n  repository: .\n"
            "executors:\n  roles:\n    verifier: gemini-cli\n")
        cfg, reason = proj_cfg.load(path)
        self.assertIsNone(cfg)
        self.assertTrue(reason.startswith(proj_cfg.CONFIG_REFUSED))
        self.assertIn("verifier", reason)
        # Resolver half: a non-seat (research is a LANE kind, owner is human) never yields
        # a kind -- the refusal is named, not guessed.
        for bogus in ("research", "owner", "chief_of_staff"):
            decision = cap_reg.resolve_seat(bogus, {}, {})
            self.assertEqual(decision.refusal, cap_reg.SEAT_UNRESOLVABLE, bogus)

    def test_undeclared_kind_refuses_at_resolution_not_at_dispatch(self):
        # A pin into the void stops resolution HERE, loudly -- it must not flow into a
        # dispatch that would silently seat whatever the default says.
        spec, source = orch._resolve_executor("fake", {"executor": {}},
                                              role_kind="verification",
                                              role_executor={"verification": "typo-cli"})
        self.assertEqual(spec.get("refusal"), cap_reg.SEAT_UNRESOLVABLE, json.dumps(spec))
        self.assertIn("typo-cli", " ".join(spec.get("rationale", [])))
        # Same rule for the project default itself.
        spec2, _ = orch._resolve_executor("also-typo", {"executor": {}})
        self.assertEqual(spec2.get("refusal"), cap_reg.SEAT_UNRESOLVABLE)
        # And the honest path still resolves untouched (a BUILDABLE declared kind).
        spec3, src3 = orch._resolve_executor("fake", {"executor": {}},
                                             role_kind="verification",
                                             role_executor={"verification": "codex-cli"})
        self.assertEqual((spec3["kind"], src3), ("codex-cli", "roles-config"))
        # A DECLARED-but-unbuildable kind (bd quaestor-ubg) is refused at admission by name --
        # it can no longer be routed to and then die in executors.registry.build().
        spec4, src4 = orch._resolve_executor("fake", {"executor": {}},
                                             role_kind="verification",
                                             role_executor={"verification": "gemini-cli"})
        self.assertEqual(spec4.get("refusal"), cap_reg.SEAT_UNRESOLVABLE)
        self.assertEqual(src4, "roles-config-refused")
        self.assertIn("KIND_NOT_BUILDABLE_IN_THIS_BUILD",
                      " ".join(spec4.get("rationale", [])))


class TestOwnerNeverAssignable(unittest.TestCase):
    """CONTROL (governance): OWNER reaches no seat through ANY path."""

    def test_parse_refuses_owner_pin(self):
        cfg, reason = proj_cfg.load(_write_manifest(
            "project:\n  name: o\n  repository: .\n"
            "executors:\n  roles:\n    owner: claude-cli\n"))
        self.assertIsNone(cfg)
        self.assertIn("human", reason.lower())

    def test_resolver_refuses_owner_even_when_a_manifest_somehow_pins_it(self):
        decision = cap_reg.resolve_seat("owner", {}, {"owner": "fake"})
        self.assertEqual(decision.refusal, cap_reg.SEAT_UNRESOLVABLE)
        self.assertEqual(decision.kind, "")

    def test_chain_router_refuses_owner(self):
        decision = cap_reg.chain_next("owner", ["gpt-plan", "claude-cli"], set(),
                                      cap_reg.AmbiguityState())
        self.assertEqual(decision.refusal, cap_reg.SEAT_UNRESOLVABLE)

    def test_orchestrator_chain_layer_refuses_owner(self):
        spec, _ = orch._resolve_executor("fake", {"executor": {}}, role_kind="owner",
                                         chains={"owner": ["gpt-plan", "claude-cli"]})
        self.assertEqual(spec.get("refusal"), cap_reg.SEAT_UNRESOLVABLE)


class TestPairingRefusalBeforeSpawn(unittest.TestCase):
    """CONTROLS driven END TO END: same-family pairing refuses AT ADMISSION, before any
    reviewer process exists, for BOTH policy forms."""

    def _impl_writes(self, files):
        return {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": files,
            "claimed_files": sorted(files)}}

    def _mathlib_body(self, h):
        with open(os.path.join(h.repo, "app", "mathlib.py"), encoding="utf-8") as fh:
            return fh.read()

    def _assert_no_reviewer_spawned(self, h, pid, lanes, expected_refusal):
        bindings = h.sstore.runs_for_lane(lanes["main"])
        reviewer_runs = [b for b in bindings if b["role"] == orch.KIND_ADVERSARIAL_REVIEW]
        self.assertEqual(reviewer_runs, [],
                         "a reviewer spawned despite the independence policy")
        blockers = _read_blocker_text(h, pid)
        self.assertIn(expected_refusal, blockers)
        ckpt = h.sstore.get_lane_task(lanes["main"])["checkpoint"]
        finding = next(f for f in (ckpt.get("fix_findings") or [])
                       if f.get("title") == "epistemic independence unmet")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn(expected_refusal, finding["failure_mode"])

    def test_pairwise_form_refuses_same_family_reviewer_before_spawn(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        body = self._mathlib_body(h)
        impl = self._impl_writes({"app/mathlib.py":
                                      body + "\n\ndef sub(a, b):\n    return a - b\n"})
        # Both seats pinned INTO THE SAME FAMILY (fake/test): exactly the pairing the
        # policy forbids. Nothing else is staged -- the refusal must come from admission.
        h.cfg = dataclasses.replace(
            h.cfg,
            role_executor={"implementation": "fake", "adversarial_review": "fake"},
            independence_pairs=(("implementation", "adversarial_review"),))
        pid, lanes = h.new_program(
            "pairing", "sub()", [{"key": "main", "title": "impl", "executor": impl,
                                  "acceptance": ("sub exists",)}])
        h.tick(pid)   # dispatch implementation (measured provenance written here)
        h.tick(pid)   # reap -> commit -> REVIEW ADMISSION -> refusal
        self._assert_no_reviewer_spawned(h, pid, lanes,
                                         cap_reg.EPISTEMIC_INDEPENDENCE_UNMET)

    def test_risk_class_form_escalates_to_admission_requirement(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        body = self._mathlib_body(h)
        # "secret" in the path classifies the change security_sensitive (the platform's own
        # classifier), hitting require_distinct_provider_for.
        impl = self._impl_writes({"app/secrets_config.py": "TIMEOUT = 5\n",
                                      "app/mathlib.py": body})
        h.cfg = dataclasses.replace(
            h.cfg,
            role_executor={"implementation": "fake", "adversarial_review": "fake"},
            independence_risk_classes=("security_sensitive",))
        pid, lanes = h.new_program(
            "risk-class", "secrets timeout",
            [{"key": "main", "title": "impl", "executor": impl,
              "acceptance": ("config exists",)}])
        h.tick(pid)
        h.tick(pid)
        self._assert_no_reviewer_spawned(h, pid, lanes,
                                         cap_reg.ROLE_PROVIDER_POLICY_REFUSED)

    def test_distinct_family_pairing_passes_admission_and_spawns(self):
        # Positive control, in two halves.
        #
        # (a) PURE: a genuinely cross-family pairing clears check_pairing -- proving the
        #     refusals above are the POLICY firing, not the comparison being upside-down.
        pair_ctx = {"require_distinct_between": [("implementation", "adversarial_review")],
                    "require_distinct_for": (), "families": {}}
        self.assertEqual(cap_reg.check_pairing(pair_ctx, orch.KIND_ADVERSARIAL_REVIEW,
                                               "claude-cli", orch.KIND_IMPLEMENTATION,
                                               "fake", ()), "")
        # Risk form ONLY (no pairs configured): two kinds of the SAME declared family but
        # different names must not slip through on a technicality -- codex-cli and gpt-plan
        # are both openai, and security_sensitive escalates distinct-provider to a gate.
        risk_ctx = {"require_distinct_between": [],
                    "require_distinct_for": ("security_sensitive",), "families": {}}
        self.assertEqual(cap_reg.check_pairing(risk_ctx, orch.KIND_ADVERSARIAL_REVIEW,
                                               "codex-cli", orch.KIND_IMPLEMENTATION,
                                               "gpt-plan", ("security_sensitive",)),
                         cap_reg.ROLE_PROVIDER_POLICY_REFUSED)
        #
        # (b) PLUMBING: with the configured pair not involving this program's seats, the
        #     reviewer seat ADMITS and its run completes -- admission is the only gate the
        #     earlier refusals exercised. The reviewer is pinned to the buildable test
        #     family so no real vendor binary is ever spawned by a control.
        h = EngineHarness()
        self.addCleanup(h.close)
        body = self._mathlib_body(h)
        impl = self._impl_writes({"app/mathlib.py":
                                  body + "\n\ndef sub(a, b):\n    return a - b\n"})
        h.cfg = dataclasses.replace(
            h.cfg,
            role_executor={"adversarial_review": "fake"},
            independence_pairs=(("planner", "adversarial_review"),))
        pid, lanes = h.new_program(
            "cross-family", "sub()",
            [{"key": "main", "title": "impl", "executor": impl,
              "acceptance": ("sub exists",)}])
        h.tick(pid)
        h.tick(pid)
        bindings = [b for b in h.sstore.runs_for_lane(lanes["main"])
                    if b["role"] == orch.KIND_ADVERSARIAL_REVIEW]
        self.assertEqual(len(bindings), 1, "the reviewer should have been admitted")
        self.assertNotIn(cap_reg.EPISTEMIC_INDEPENDENCE_UNMET,
                         _read_blocker_text(h, pid))


class TestChainFailover(unittest.TestCase):
    """CONTROLS: reconciliation-aware failover, at the router and through the resolver."""

    CTX_SAME_FAMILY_IMPL = {"require_distinct_between": [("implementation", "planner")],
                            "require_distinct_for": (),
                            "families": {"implementation": "claude-cli"}}

    def _gate(self, ctx, seat):
        return orch._pairing_gate(ctx, seat)

    def test_happy_switch_on_measured_exhaustion(self):
        d = cap_reg.chain_next("planner", ["gpt-plan", "claude-cli"], {"gpt-plan"},
                               cap_reg.AmbiguityState())
        self.assertEqual(d.kind, "claude-cli")
        self.assertTrue(any("exhausted" in r for r in d.rationale),
                        str(d.rationale))

    def test_switch_reaches_the_resolver_layer_as_roles_chain(self):
        spec, source = orch._resolve_executor(
            "fake", {"executor": {}}, role_kind="verification",
            chains={"verification": ["gpt-plan", "fake"]},
            chain_exhausted={"verification": ["gpt-plan"]})
        self.assertEqual((spec["kind"], source), ("fake", "roles-chain"))

    def test_first_preferred_candidate_wins_when_nothing_exhausted(self):
        d = cap_reg.chain_next("planner", ["gpt-plan", "claude-cli"], set(),
                               cap_reg.AmbiguityState())
        self.assertEqual(d.kind, "gpt-plan")

    def test_ambiguous_write_never_switches(self):
        # Death after a POSSIBLE write: every member of every chain is off-limits until a
        # measurement or a human resolves what happened. This is the anti-blind-retry rule.
        d = cap_reg.chain_next("planner", ["gpt-plan", "claude-cli", "local-llama"],
                               set(),
                               cap_reg.AmbiguityState(possible_write=True,
                                                      reason="worker died dirty"))
        self.assertEqual(d.refusal, cap_reg.CHAIN_BLOCKED_AMBIGUOUS_WRITE)
        self.assertEqual(d.kind, "")
        # ...including when the AMBIGUITY rides in from the lane checkpoint through the
        # resolver layer, where schedule() actually feeds it.
        spec, source = orch._resolve_executor(
            "fake", {"executor": {}}, role_kind="planner",
            chains={"planner": ["gpt-plan", "claude-cli"]},
            ambiguity=cap_reg.AmbiguityState(possible_write=True))
        self.assertEqual(spec.get("refusal"), cap_reg.CHAIN_BLOCKED_AMBIGUOUS_WRITE)
        self.assertEqual(source, "roles-chain-refused")

    def test_policy_violating_fallback_is_refused_not_taken(self):
        # gpt-plan (openai) exhausted; the only remaining member IS the family the
        # implementer holds. Taking it would breach require_distinct_provider_between.
        gate = self._gate(self.CTX_SAME_FAMILY_IMPL, "planner")
        d = cap_reg.chain_next("planner", ["gpt-plan", "claude-cli"], {"gpt-plan"},
                               cap_reg.AmbiguityState(), pairing=gate)
        self.assertEqual(d.refusal, cap_reg.CHAIN_POLICY_REFUSED)
        self.assertEqual(d.kind, "")
        # Control on the control: with the first member still alive, the SAME gate admits
        # the chain head (openai != anthropic) -- the refusal is the policy, not the gate.
        d2 = cap_reg.chain_next("planner", ["gpt-plan", "claude-cli"], set(),
                                cap_reg.AmbiguityState(), pairing=gate)
        self.assertEqual(d2.kind, "gpt-plan")

    def test_fully_exhausted_chain_refuses(self):
        d = cap_reg.chain_next("verification", ["gemini-cli", "codex-cli"],
                               {"gemini-cli", "codex-cli"}, cap_reg.AmbiguityState())
        self.assertEqual(d.refusal, cap_reg.CHAIN_EXHAUSTED)

    def test_single_family_chain_refuses_anywhere_it_is_met(self):
        # PAI-Bus rule: >=2 distinct vendor families. Two anthropic hats are one vendor.
        d = cap_reg.chain_next("verification", ["claude-cli", "claude-container"], set(),
                               cap_reg.AmbiguityState())
        self.assertEqual(d.refusal, cap_reg.CHAIN_SINGLE_FAMILY)

    def test_undeclared_chain_member_refuses(self):
        d = cap_reg.chain_next("verification", ["typo-cli", "fake"], set(),
                               cap_reg.AmbiguityState())
        self.assertEqual(d.refusal, cap_reg.SEAT_UNRESOLVABLE)
        self.assertTrue(any("typo-cli" in r for r in d.rationale))

    def test_exhaustion_checkpoint_helper_is_pure_and_idempotent(self):
        ck = {"worktree_path": "/x"}
        snap = dict(ck)
        once = cap_reg.mark_chain_exhaustion(ck, "implementation", "gpt-plan")
        twice = cap_reg.mark_chain_exhaustion(once, "implementation", "gpt-plan")
        other = cap_reg.mark_chain_exhaustion(twice, "implementation", "claude-cli")
        self.assertEqual(ck, snap, "input checkpoint mutated")
        self.assertEqual(once, twice, "re-marking the same kind changed state")
        self.assertEqual(cap_reg.exhausted_for(other, "implementation"),
                         {"gpt-plan", "claude-cli"})
        self.assertEqual(cap_reg.exhausted_for(other, "verification"), set())


class TestRegistryFactsAreDeclarations(unittest.TestCase):
    """CONTROL: the registry routes on DECLARATIONS and labels them honestly.

    fact_status is a two-word honesty vocabulary: "declared" (routable, nothing proven behind
    it) and "buildable" (executor constructs end to end + real measured preflight shipped --
    bd quaestor-1ng). NEITHER word means "measured": only run.provenance proves a run.
    """

    UNPROVEN = ("gemini-cli", "gpt-plan", "local-llama")

    def test_every_entry_labels_itself_with_a_known_honesty_status(self):
        for kind, facts in cap_reg.PROVIDER_REGISTRY.items():
            self.assertIn(facts["fact_status"], ("declared", "buildable"), kind)
        # The declared namespace covers every buildable executor too.
        for kind in ("fake", "claude-cli", "claude-container", "codex-cli"):
            self.assertTrue(cap_reg.is_declared(kind), kind)

    def test_codex_cli_is_buildable_not_merely_declared(self):
        self.assertEqual(cap_reg.PROVIDER_REGISTRY["codex-cli"]["fact_status"], "buildable")

    def test_unproven_entries_do_not_pose_as_measured(self):
        for kind in self.UNPROVEN:
            facts = cap_reg.PROVIDER_REGISTRY[kind]
            self.assertIsNone(facts["current_health"], kind)
            self.assertIsNone(facts["quota_state"], kind)
            self.assertEqual(facts["fact_status"], "declared", kind)
        # Buildable is not measured either: no entry, however constructible, may pose as
        # health-checked before a real probe or run has happened.
        for kind in ("codex-cli",):
            facts = cap_reg.PROVIDER_REGISTRY[kind]
            self.assertIsNone(facts["current_health"], kind)
            self.assertIsNone(facts["quota_state"], kind)
        # Families the routing examples in section 3.2 rely on hold their declared values.
        self.assertEqual(cap_reg.provider_family("claude-cli"), "anthropic")
        self.assertEqual(cap_reg.provider_family("fake"), "test")
        self.assertEqual(cap_reg.provider_family("local-llama"), "local")

    def test_declared_family_disagreement_between_claims_and_routing_is_impossible(self):
        # The routing comparison and the pairing comparison read ONE family function --
        # there is no second table to drift out of sync with the first.
        self.assertEqual(cap_reg.provider_family("codex-cli"),
                         cap_reg.provider_family("gpt-plan"))   # both openai


class TestPairingPolicyParsing(unittest.TestCase):
    """CONTROLS: the section 3 grammar parses; typos refuse instead of protecting nothing."""

    MANIFEST = (
        "project:\n"
        "  name: indep\n"
        "  repository: .\n"
        "review:\n"
        "  epistemic_independence:\n"
        "    require_distinct_provider_between:\n"
        "      - [implementation, adversarial_review]\n"
        "      - [planner, adversarial_review]\n"
        "    require_distinct_provider_for:\n"
        "      - security_sensitive\n"
        "      - deployment\n")

    def test_pairs_and_risk_classes_parse(self):
        cfg, reason = proj_cfg.load(_write_manifest(self.MANIFEST))
        self.assertEqual(reason, "")
        self.assertEqual(cfg.independence_pairs,
                         (("implementation", "adversarial_review"),
                          ("planner", "adversarial_review")))
        self.assertEqual(cfg.independence_risk_classes,
                         ("security_sensitive", "deployment"))

    def test_toml_parity_for_independence_and_chains(self):
        # Direction section 3's grammar must mean the SAME thing in both syntaxes -- the
        # chain and the pair are policy, and a syntax switch silently changing policy is
        # exactly the drift the parity rule exists to kill.
        toml = (
            "[project]\n"
            "name = \"t\"\n"
            "repository = \".\"\n"
            "\n[executors]\n"
            "default = \"fake\"\n"
            "\n[executors.roles.planner]\n"
            "kind = \"gpt-plan\"\n"
            "\n[executors.roles.planner.providers]\n"
            "chain = [\"gpt-plan\", \"claude-cli\", \"local-llama\"]\n"
            "fallback_policy = \"availability_only\"\n"
            "\n[review.epistemic_independence]\n"
            "require_distinct_provider_between = "
            "[[\"implementation\", \"adversarial_review\"]]\n"
            "require_distinct_provider_for = [\"security_sensitive\"]\n")
        tcfg, treason = proj_cfg.load(_write_manifest(toml, "quaestor.toml"))
        self.assertEqual(treason, "", "toml manifest refused")
        self.assertEqual(tcfg.independence_pairs,
                         (("implementation", "adversarial_review"),))
        self.assertEqual(tcfg.independence_risk_classes, ("security_sensitive",))
        self.assertEqual(tcfg.role_chains,
                         {"planner": ("gpt-plan", "claude-cli", "local-llama")})
        self.assertEqual(tcfg.role_fallback_policy, {"planner": "availability_only"})

    def test_owner_named_in_a_pair_refuses(self):
        path = _write_manifest(
            "project:\n  name: o\n  repository: .\nreview:\n"
            "  epistemic_independence:\n"
            "    require_distinct_provider_between:\n"
            "      - [owner, adversarial_review]\n")
        cfg, reason = proj_cfg.load(path)
        self.assertIsNone(cfg)
        self.assertIn("OWNER", reason)

    def test_unknown_role_or_class_in_policy_refuses(self):
        bad_role = _write_manifest(
            "project:\n  name: b\n  repository: .\nreview:\n"
            "  epistemic_independence:\n"
            "    require_distinct_provider_between:\n"
            "      - [implementashun, adversarial_review]\n")
        cfg, reason = proj_cfg.load(bad_role)
        self.assertIsNone(cfg)
        self.assertIn("implementashun", reason)
        bad_class = _write_manifest(
            "project:\n  name: c\n  repository: .\nreview:\n"
            "  epistemic_independence:\n"
            "    require_distinct_provider_for:\n"
            "      - sekurity\n")
        cfg2, reason2 = proj_cfg.load(bad_class)
        self.assertIsNone(cfg2)
        self.assertIn("sekurity", reason2)

    def test_malformed_pair_refuses(self):
        path = _write_manifest(
            "project:\n  name: m\n  repository: .\nreview:\n"
            "  epistemic_independence:\n"
            "    require_distinct_provider_between:\n"
            "      - [only_one_role]\n")
        cfg, reason = proj_cfg.load(path)
        self.assertIsNone(cfg)
        self.assertIn("exactly two roles", reason)

    def test_chain_grammar_refuses_structurally_broken_chains(self):
        one = _write_manifest(
            "project:\n  name: x\n  repository: .\nexecutors:\n  roles:\n    planner:\n"
            "      kind: gpt-plan\n      providers:\n        chain: [\"gpt-plan\"]\n")
        cfg, reason = proj_cfg.load(one)
        self.assertIsNone(cfg)
        self.assertIn("at least two", reason)
        rep = _write_manifest(
            "project:\n  name: y\n  repository: .\nexecutors:\n  roles:\n    planner:\n"
            "      kind: gpt-plan\n      providers:\n"
            "        chain: [\"gpt-plan\", \"gpt-plan\"]\n")
        cfg2, reason2 = proj_cfg.load(rep)
        self.assertIsNone(cfg2)
        self.assertIn("repeats a kind", reason2)
        pol = _write_manifest(
            "project:\n  name: z\n  repository: .\nexecutors:\n  roles:\n    planner:\n"
            "      kind: gpt-plan\n      providers:\n        chain:"
            " [\"gpt-plan\", \"fake\"]\n        fallback_policy: yolo\n")
        cfg3, reason3 = proj_cfg.load(pol)
        self.assertIsNone(cfg3)
        self.assertIn("availability_only", reason3)


class TestCodexCliReviewerExecutor(unittest.TestCase):
    """CONTROLS (bd quaestor-1ng): codex-cli DISPATCHES end to end, with NO vendor coupling
    into core -- the executor lives in executors/, core resolves it through the inversion seam,
    and every control here launches NOTHING real."""

    def _req(self, tmp, *, profile=authority_mod.READ_ONLY, model=""):
        from quaestor.core.executor_contract import ExecRequest
        from quaestor.core.identity import RunBinding
        return ExecRequest(
            run_id="run_codex", run_dir=tmp, cwd=tmp,
            prompt="ADVERSARIAL REVIEW: attack this candidate.\nRUN_NONCE n1",
            binding=RunBinding(run_id="run_codex", workflow_id="wf", step_id="s1",
                               run_nonce="n1"),
            json_schema={"type": "object"}, authority_profile=profile,
            stdout_path=os.path.join(tmp, "stdout.json"),
            stderr_path=os.path.join(tmp, "stderr.json"), model=model)

    def test_build_command_shape_stdin_prompt_no_bypass_flags(self):
        from quaestor.core import authority as auth_mod
        from quaestor.executors.codex_cli import (FORBIDDEN_FLAGS, STDIN_PROMPT_MARKER,
                                                  UnsafeCommand, build_command, sandbox_mode)
        d = tempfile.mkdtemp(prefix="qx-codex-")
        cmd = build_command(self._req(d))
        # Codex argv shape: `codex exec --json --sandbox <mode> [-]` with the prompt on STDIN.
        self.assertEqual(cmd[:4], ["codex", "exec", "--json", "--sandbox"])
        self.assertEqual(cmd[-1], STDIN_PROMPT_MARKER)
        self.assertNotIn("ADVERSARIAL", " ".join(cmd), "the prompt never rides in argv")
        for flag in FORBIDDEN_FLAGS:
            self.assertNotIn(flag, cmd, flag)
        self.assertEqual(sandbox_mode(auth_mod.READ_ONLY), "read-only")
        self.assertEqual(sandbox_mode(auth_mod.STANDARD_EDIT), "workspace-write")
        self.assertEqual(sandbox_mode("totally-unknown-profile"), "read-only")
        with_model = build_command(self._req(d, model="gpt-5.2"))
        self.assertEqual(with_model[with_model.index("--model") + 1], "gpt-5.2")
        # The sandbox mapping can never spell the bypass mode, whatever the profile.
        for profile in ("READ_ONLY", "STANDARD_EDIT", "GIT_PUSH", "DESTRUCTIVE", "bogus"):
            self.assertNotEqual(sandbox_mode(profile), "danger-full-access")
        with self.assertRaises(UnsafeCommand):
            build_command(self._req(d), binary="--full-auto")

    def test_registry_constructible_through_the_inversion_seam(self):
        from quaestor.executors import registry as exec_reg
        from quaestor.executors.codex_cli import CodexCliExecutor
        self.assertIn("codex-cli", exec_reg.KNOWN_KINDS)
        ex = exec_reg.build({"kind": "codex-cli"})
        self.assertIsInstance(ex, CodexCliExecutor)
        self.assertEqual(ex.name, "codex-cli")

    def test_pairing_policy_sees_openai_distinct_from_anthropic(self):
        pair_ctx = {"require_distinct_between":
                    [("implementation", "adversarial_review")],
                    "require_distinct_for": (), "families": {}}
        # claude implementation vs codex reviewer: genuinely distinct families -> admitted.
        self.assertEqual(cap_reg.provider_family("claude-cli"), "anthropic")
        self.assertEqual(cap_reg.provider_family("codex-cli"), "openai")
        self.assertEqual(cap_reg.check_pairing(pair_ctx, orch.KIND_ADVERSARIAL_REVIEW,
                                               "codex-cli", orch.KIND_IMPLEMENTATION,
                                               "claude-cli", ()), "")
        same_ctx = {"require_distinct_between": [],
                    "require_distinct_for": ("security_sensitive",),
                    "families": {"implementation": "gpt-plan"}}
        self.assertEqual(cap_reg.check_pairing(same_ctx, orch.KIND_ADVERSARIAL_REVIEW,
                                               "codex-cli", orch.KIND_IMPLEMENTATION,
                                               "gpt-plan", ("security_sensitive",)),
                         cap_reg.ROLE_PROVIDER_POLICY_REFUSED)

    def test_e2e_ish_dispatch_with_fake_popen_writes_command_json_without_launching(self):
        import subprocess as sp
        from quaestor.core.executor_contract import EXIT_OK
        from quaestor.executors.codex_cli import CodexCliExecutor, build_command

        launched = []

        class _StdinRecorder:
            def __init__(self):
                self.buf = bytearray()
                self.closed = False

            def write(self, data):
                self.buf.extend(data)
                return len(data)

            def close(self):
                self.closed = True

        class FakePopen:
            def __init__(self, cmd, **kwargs):
                self.cmd, self.kwargs = cmd, kwargs
                self.stdin = _StdinRecorder()
                self.pid = 424242
                launched.append(self)

            def wait(self, timeout=None):
                return 0

            def terminate(self):
                pass

            def kill(self):
                pass

        d = tempfile.mkdtemp(prefix="qx-codex-run-")
        req = self._req(d)
        outcome = CodexCliExecutor(popen=FakePopen).execute(req)
        self.assertTrue(outcome.started)
        self.assertEqual((outcome.exit_code, outcome.exit_class), (0, EXIT_OK))
        self.assertEqual(len(launched), 1, "exactly one child was 'launched' -- by the fake")
        fake = launched[0]
        # The prompt travelled on STDIN, byte-exact, then closed; nothing real ever started.
        self.assertEqual(fake.kwargs.get("stdin"), sp.PIPE)
        self.assertEqual(fake.kwargs.get("shell"), False)
        self.assertEqual(bytes(fake.stdin.buf), req.prompt.encode("utf-8"))
        self.assertTrue(fake.stdin.closed)
        # The durable command record exists and matches the built argv.
        with open(os.path.join(d, "command.json"), encoding="utf-8") as fh:
            recorded = json.load(fh)
        self.assertEqual(recorded["argv"], build_command(req))
        self.assertEqual(recorded["stdin"], "PIPE(prompt_utf8)")
        self.assertFalse(recorded["shell"])
        self.assertTrue(os.path.isfile(req.stdout_path))

    def test_measured_preflight_is_wired_and_fails_closed(self):
        from quaestor.core.credential_policy import (
            ACCEPT, API_CONSOLE, REASON_OVERRIDE, REFUSE, SUBSCRIPTION, UNVERIFIED)
        from quaestor.executors import codex_auth
        from quaestor.executors import registry as exec_reg
        # Registry seam routes codex-cli to its OWN measured preflight (this box has no codex
        # binary; an unreadable instrument must REFUSE, not guess).
        decision = exec_reg.run_preflight("codex-cli")
        self.assertEqual(decision.decision, REFUSE)
        self.assertEqual(decision.record.get("provider"), "openai/codex-cli")
        # PURE half: overrides refuse by name; subscription accepts; API billing refuses.
        env = {"CODEX_API_KEY": "sk-something", "OPENAI_BASE_URL": "https://proxy.example"}
        offenders = codex_auth.env_overrides_present(env)
        self.assertIn("CODEX_API_KEY", offenders)
        d = codex_auth.decide(env=env, auth_status={"method": "chatgpt"})
        self.assertEqual((d.decision, d.reason), (REFUSE, REASON_OVERRIDE))
        ok = codex_auth.decide(env={}, auth_status={"method": "chatgpt", "logged_in": True})
        self.assertEqual(ok.decision, ACCEPT)
        self.assertEqual(ok.auth_class, SUBSCRIPTION)
        billed = codex_auth.decide(env={}, auth_status={"method": "api_key",
                                                        "logged_in": True})
        self.assertEqual(billed.decision, REFUSE)
        self.assertEqual(billed.auth_class, API_CONSOLE)
        unknown = codex_auth.decide(env={}, auth_status={"weird": "shape"})
        self.assertEqual(unknown.auth_class, UNVERIFIED)


class TestSeatPolicyIsEnforcedAtDispatch(unittest.TestCase):
    """quaestor-kaz.10.

    adapters.registry.resolve_seat is presented by its own docstring as THE capability layer --
    credential_modes, local_or_remote, family and kind exclusion, write_capable. It has no
    production caller: dispatch goes _resolve_executor -> _seat_spec, which re-implemented only
    the write ceiling.

    Worse, credential_modes had no manifest surface at all. Its only mentions in src/ outside the
    registry were two docstrings -- chatgpt_web_auth.py and openrouter_auth.py -- each asserting
    that "a deployment enforcing credential_modes={subscription} must refuse this seat" as the
    concrete consequence justifying the honest-labelling design. That consequence did not exist:
    an operator had no way to declare the policy and nothing would have applied it.

    These controls pin that the claim is now true where runs actually start.
    """

    def _cfg(self, body):
        from quaestor.projects import config as cfg_mod
        d = tempfile.mkdtemp(prefix="quaestor-seatpolicy-")
        p = os.path.join(d, "quaestor.yaml")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        cfg, reason = cfg_mod.load(p)
        return cfg, reason

    BASE = """project:
  name: policycheck
  repository: .

executors:
  default: fake
%(policy)s  roles:
    strategist: %(seat)s

authority:
  default:
    - READ_ONLY
"""

    def _resolve(self, seat, policy_block):
        from quaestor.core import orchestrator as orch
        cfg, reason = self._cfg(self.BASE % {"policy": policy_block, "seat": seat})
        self.assertIsNotNone(cfg, reason)
        spec, source = orch._resolve_executor(
            cfg.executor, {"executor": {}}, role_kind="strategist",
            role_executor=cfg.role_executor, seat_policy=cfg.seat_policy)
        return cfg, spec, source

    POLICY_SUB = "  policy:\n    credential_modes: [subscription]\n"

    def test_a_subscription_only_policy_refuses_an_api_billed_seat_AT_DISPATCH(self):
        """THE DEFECT. Before this, the policy was parsed by nothing and applied by nothing."""
        cfg, spec, source = self._resolve("openrouter:openai/gpt-5", self.POLICY_SUB)
        self.assertEqual(dict(cfg.seat_policy), {"credential_modes": ("subscription",)})
        self.assertEqual(spec.get("refusal"), "SEAT_UNRESOLVABLE",
                         "an api-billed seat was dispatched under a subscription-only policy")
        self.assertTrue(any("credential mode" in r for r in spec.get("rationale") or ()), spec)
        self.assertTrue(source.endswith("-refused"))

    def test_the_same_policy_admits_a_subscription_capable_seat(self):
        """The policy must refuse the right thing, not everything."""
        _cfg, spec, _src = self._resolve("claude-cli", self.POLICY_SUB)
        self.assertEqual(spec.get("kind"), "claude-cli", spec)
        self.assertIsNone(spec.get("refusal"))

    def test_no_policy_declared_means_no_constraint(self):
        """Absent policy is absent, not an empty allowlist that refuses everything."""
        _cfg, spec, _src = self._resolve("openrouter:openai/gpt-5", "")
        self.assertEqual(spec.get("kind"), "openrouter:openai/gpt-5", spec)

    def test_an_unknown_policy_key_or_value_is_a_named_manifest_refusal(self):
        """A policy silently dropped is a policy the operator believes is protecting them."""
        cfg, reason = self._cfg(self.BASE % {
            "policy": "  policy:\n    credential_modez: [subscription]\n", "seat": "fake"})
        self.assertIsNone(cfg)
        self.assertIn("credential_modez", reason)
        cfg, reason = self._cfg(self.BASE % {
            "policy": "  policy:\n    credential_modes: [free_lunch]\n", "seat": "fake"})
        self.assertIsNone(cfg)
        self.assertIn("free_lunch", reason)
        cfg, reason = self._cfg(self.BASE % {
            "policy": "  policy:\n    local_or_remote: mars\n", "seat": "fake"})
        self.assertIsNone(cfg)
        self.assertIn("mars", reason)

    def test_local_only_policy_refuses_a_remote_provider(self):
        _cfg, spec, _src = self._resolve(
            "claude-cli", "  policy:\n    local_or_remote: local\n")
        self.assertEqual(spec.get("refusal"), "SEAT_UNRESOLVABLE", spec)
        self.assertTrue(any("local execution" in r for r in spec.get("rationale") or ()), spec)

    def test_one_evaluator_serves_the_router_and_the_dispatch_path(self):
        """Two implementations of an admission rule is one implementation and one decoration."""
        from quaestor.adapters import registry as reg
        why = reg.constraint_refusals("openrouter:openai/gpt-5",
                                      {"credential_modes": ("subscription",)})
        self.assertTrue(why)
        routed = reg.resolve_seat("strategist", {"credential_modes": ("subscription",)},
                                  {"strategist": "openrouter:openai/gpt-5"})
        self.assertNotEqual(routed.kind, "openrouter:openai/gpt-5")
        self.assertTrue(any(why[0] in r for r in routed.rationale),
                        "the router and the evaluator gave different reasons")

    def test_an_unknown_constraint_raises_rather_than_being_ignored(self):
        from quaestor.adapters import registry as reg
        with self.assertRaises(ValueError):
            reg.constraint_refusals("claude-cli", {"nonsense_constraint": True})

    def test_the_write_ceiling_still_holds_alongside_a_policy(self):
        """The two must compose, not replace one another."""
        from quaestor.core import orchestrator as orch
        spec, _src = orch._resolve_executor(
            "fake", {"executor": {}}, role_kind="implementation",
            role_executor={"implementation": "chatgpt-web"},
            seat_policy={"credential_modes": ("subscription",)})
        self.assertEqual(spec.get("refusal"), "SEAT_UNRESOLVABLE")
        self.assertTrue(any("write capability" in r for r in spec.get("rationale") or ()), spec)


class TestEveryDeclarableRiskClassCanActuallyFire(unittest.TestCase):
    """quaestor-kaz.9. The risk-class escalation was DEAD POLICY for part of its vocabulary.

    Two independent holes, both silent, both failing OPEN:

    (1) THE FLOOR FILTER. _adversarial_required answers "does this diff need an adversarial
        review?" by filtering detected classes through ADVERSARIAL_REQUIRED_FLOOR |
        adversarial_required_for. Its filtered result -- `matched` -- was then handed to
        _dispatch_reviewer as `changed` and on to check_pairing as risk_classes_hit. But the
        independence escalation asks a DIFFERENT question: "what did this diff touch?" So a
        class in the operator's require_distinct_provider_for but absent from the review floor
        never reached check_pairing, and the distinct-provider REQUIREMENT never fired.
        `data_migration` is exactly that class: declarable, and not in the floor.

        The pre-existing control for this feature used `security_sensitive`, which IS in the
        floor -- so it passed straight through the defect. That is the whole lesson.

    (2) UNCLASSIFIABLE CLASSES. config accepted `authority_change` and
        `destructive_capability`; the classifier had no rule for either. An operator could
        name them, get no error, and hold a policy that no change on earth could trigger.

    A policy that cannot fire is indistinguishable, from the operator's chair, from one that is
    being enforced. These controls pin that every class the manifest accepts can reach
    admission.
    """

    def test_the_classifier_is_total_over_the_declared_vocabulary(self):
        """Hole (2). Anything an operator may name, a diff must be able to hit."""
        unreachable = set(rc_mod.RISK_CLASSES) - set(orch.RISK_KEYWORDS)
        self.assertEqual(unreachable, set(),
                         "risk class(es) an operator can declare but no change can hit")
        undeclared = set(orch.RISK_KEYWORDS) - set(rc_mod.RISK_CLASSES)
        self.assertEqual(undeclared, set(),
                         "the classifier produces class(es) the vocabulary does not declare")

    def test_a_concrete_path_hits_every_class_and_escalates_at_admission(self):
        """Every member, driven: path -> classifier -> check_pairing -> refusal."""
        probes = {
            "authentication": "src/app/auth_login.py",
            "security_sensitive": "src/app/secrets_store.py",
            "sandbox_change": "src/app/sandbox_runner.py",
            "deployment": "deploy/pipeline.yaml",
            "data_migration": "db/migrations/003_add_col.sql",
            "authority_change": "src/app/authority_profiles.py",
            "destructive_capability": "src/app/delete_account.py",
        }
        self.assertEqual(set(probes), set(rc_mod.RISK_CLASSES),
                         "a declared class has no probe path; this control is incomplete")
        for risk_class, path in probes.items():
            with self.subTest(risk_class=risk_class):
                hit = orch.risk_classes_hit([path])
                self.assertIn(risk_class, hit, "%r did not classify as %s" % (path, risk_class))
                ctx = {"require_distinct_between": [], "families": {},
                       "require_distinct_for": (risk_class,)}
                # Same declared family on both seats: the escalation is the ONLY thing that can
                # refuse here, so a pass means it fired.
                self.assertEqual(
                    cap_reg.check_pairing(ctx, orch.KIND_ADVERSARIAL_REVIEW, "codex-cli",
                                          orch.KIND_IMPLEMENTATION, "gpt-plan", hit),
                    cap_reg.ROLE_PROVIDER_POLICY_REFUSED,
                    "%s did not escalate to an admission requirement" % risk_class)

    def test_a_class_outside_the_review_floor_still_reaches_the_pairing_check(self):
        """HOLE (1), STATED AS THE ARITHMETIC THAT CAUSED IT.

        If this assertion ever inverts -- data_migration joins the floor -- the end-to-end
        control below stops proving anything, and this one says so out loud rather than
        going quietly green.
        """
        self.assertNotIn("data_migration", rc_mod.ADVERSARIAL_REQUIRED_FLOOR,
                         "data_migration joined the review floor; pick another class outside "
                         "it or this regression can no longer be reproduced")
        changed = ["db/migrations/003_add_col.sql"]

        class _Cfg:
            adversarial_required_for = ()

        _required, matched = orch._adversarial_required(changed, _Cfg())
        self.assertNotIn("data_migration", matched,
                         "the review floor now matches this class; see above")
        # THE FIX: what dispatch forwards to the pairing check is the full hit set, so the
        # class the floor drops still reaches the escalation.
        self.assertIn("data_migration", orch.risk_classes_hit(changed))

    def test_end_to_end_a_migration_change_refuses_a_same_family_reviewer(self):
        """The same defect, driven through the PRODUCTION path with nothing but a manifest.

        Before the fix this program spawned its reviewer happily: the operator had declared
        require_distinct_provider_for: [data_migration], the diff was a migration, and the
        requirement was silently dropped on the way to admission.
        """
        h = EngineHarness()
        self.addCleanup(h.close)
        body = self._mathlib_body(h)
        impl = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"db/migrations/003_add_col.sql": "ALTER TABLE t ADD COLUMN c;\n",
                            "app/mathlib.py": body},
            "claimed_files": ["app/mathlib.py", "db/migrations/003_add_col.sql"]}}
        h.cfg = dataclasses.replace(
            h.cfg,
            role_executor={"implementation": "fake", "adversarial_review": "fake"},
            independence_risk_classes=("data_migration",))
        pid, lanes = h.new_program(
            "migration-risk", "add a column",
            [{"key": "main", "title": "impl", "executor": impl,
              "acceptance": ("migration exists",)}])
        h.tick(pid)
        h.tick(pid)
        bindings = h.sstore.runs_for_lane(lanes["main"])
        reviewer_runs = [b for b in bindings if b["role"] == orch.KIND_ADVERSARIAL_REVIEW]
        self.assertEqual(reviewer_runs, [],
                         "a same-family reviewer spawned on a declared data_migration risk")
        self.assertIn(cap_reg.ROLE_PROVIDER_POLICY_REFUSED, _read_blocker_text(h, pid))

    def _mathlib_body(self, h):
        with open(os.path.join(h.repo, "app", "mathlib.py"), encoding="utf-8") as fh:
            return fh.read()

    def test_the_vocabulary_is_declared_exactly_once(self):
        """config used to restate the class list; the two had already drifted apart."""
        from quaestor.projects import config as cfg_mod
        with open(cfg_mod.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn('"destructive_capability"', src,
                         "projects/config.py restates the risk vocabulary instead of "
                         "importing review_contract.RISK_CLASSES")
        self.assertIn("RISK_CLASSES", src)

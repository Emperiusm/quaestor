"""test_role_matrix -- CONTROLS on the Role x Provider matrix (direction doc section 3).

WHAT THESE CONTROLS PIN
-----------------------
Section 3: "Quaestor's roles are assignable seats, not vendor features" -- and OWNER is
"always human, never configurable, never delegated". Four invariants follow:

  * PARSING (TestRolesParsing). ``executors.roles`` maps seat -> executor kind; unpinned
    seats fall back to the project default at resolution time. An UNKNOWN role key is
    refused with a named reason -- a typo'd pin must not quietly become "no pin", which is
    the same refusal-not-guessing rule the authority profiles already enforce. A manifest
    that assigns ``owner`` is refused BY NAME: assigning the human seat is a governance
    misunderstanding, not a spelling mistake.

  * RESOLUTION PRECEDENCE (TestRoleResolution). fix_override > attempt_variants > lane
    script > roles-config > default-config. A role pin must move the seat it names WITHOUT
    displacing scripted fixture seams or other seats' defaults.

  * MEASURED PROVENANCE (TestSeatProvenance). Every dispatched run writes a durable
    ``run.provenance`` event whose provider comes from the RESOLVED dispatch spec (what was
    actually sent to the executor layer) -- never from anything a model reports about
    itself. The handoff package carries the same measured seat for downstream consumers.
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

from quaestor.adapters import registry as cap_reg        # noqa: E402
from quaestor.core import orchestrator as orch          # noqa: E402
from quaestor.projects import config as proj_cfg        # noqa: E402
from tests.controls import control                      # noqa: E402
from tests.test_operational_e2e import EngineHarness    # noqa: E402


def _write_manifest(text: str) -> str:
    d = tempfile.mkdtemp(prefix="qx-role-matrix-")
    path = os.path.join(d, "quaestor.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class TestRolesParsing(unittest.TestCase):
    """CONTROL: executors.roles parses; bad keys refuse; owner refuses."""

    def test_roles_mapping_exposes_pins_and_falls_back_to_default(self):
        cfg, reason = proj_cfg.load(_write_manifest(
            "project:\n"
            "  name: matrix\n"
            "  repository: .\n"
            "executors:\n"
            "  default: claude-cli\n"
            "  roles:\n"
            "    planner: gpt-plan\n"
            "    verification: gemini-cli\n"
            "    adversarial_review: codex-cli\n"))
        self.assertEqual(reason, "")
        # Only PINNED seats appear; an unpinned seat resolves to the default downstream.
        self.assertEqual(cfg.role_executor,
                         {"planner": "gpt-plan", "verification": "gemini-cli",
                          "adversarial_review": "codex-cli"})
        self.assertEqual(cfg.executor, "claude-cli")
        # Fallback is observable: implementation has no pin, so .get misses and the
        # orchestrator's next link (cfg.executor) takes over.
        self.assertIsNone(cfg.role_executor.get("implementation"))

    def test_manifest_without_executors_block_is_unchanged(self):
        cfg, reason = proj_cfg.load(os.path.join(ROOT, "examples", "synthetic",
                                                 "quaestor.yaml"))
        self.assertEqual(reason, "")
        self.assertEqual(cfg.executor, "fake")
        self.assertEqual(dict(cfg.role_executor), {})

    def test_unknown_role_key_refused_with_named_reason(self):
        path = _write_manifest(
            "project:\n"
            "  name: typo-seat\n"
            "  repository: .\n"
            "executors:\n"
            "  roles:\n"
            "    verifier: gemini-cli\n")     # not a seat name
        cfg, reason = proj_cfg.load(path)
        self.assertIsNone(cfg)
        self.assertTrue(reason.startswith(proj_cfg.CONFIG_REFUSED), reason)
        self.assertIn("verifier", reason)                      # names the offending key
        self.assertIn("adversarial_review", reason)            # lists the assignable seats

    def test_owner_role_key_refused_by_name(self):
        """CONTROL (governance): OWNER is human-only; no manifest may assign it."""
        path = _write_manifest(
            "project:\n"
            "  name: owner-seat\n"
            "  repository: .\n"
            "executors:\n"
            "  roles:\n"
            "    owner: claude-cli\n")
        cfg, reason = proj_cfg.load(path)
        self.assertIsNone(cfg)
        self.assertTrue(reason.startswith(proj_cfg.CONFIG_REFUSED), reason)
        self.assertIn("owner", reason.lower())
        self.assertIn("human", reason.lower())


class TestRoleResolution(unittest.TestCase):
    """CONTROL: precedence fix_override > attempt_variants > lane script > roles > default."""

    # A BUILDABLE declared kind: the pin must survive admission AND be constructible, so the
    # precedence control cannot pass on a kind dispatch would refuse (bd quaestor-ubg).
    PINS = {"verification": "codex-cli"}

    def test_pinned_seat_resolves_to_its_provider(self):
        e = orch._executor_for("claude-cli", {"executor": {}}, role_kind="verification",
                               role_executor=self.PINS)
        self.assertEqual(e, {"kind": "codex-cli"})

    def test_unpinned_seat_still_uses_the_project_default(self):
        e = orch._executor_for("claude-cli", {"executor": {}}, role_kind="implementation",
                               role_executor=self.PINS)
        self.assertEqual(e, {"kind": "claude-cli"})

    def test_attempt_variants_win_over_roles_config(self):
        lane_task = {"executor": {"kind": "fake", "attempt_variants":
                                  [{"kind": "fake", "config": {"scenario": "OK_PASS"}},
                                   {"kind": "fake", "config": {"scenario": "BLOCKED"}}]}}
        e0 = orch._executor_for("claude-cli", lane_task, attempt=0, role_kind="verification",
                                role_executor=self.PINS)
        e5 = orch._executor_for("claude-cli", lane_task, attempt=5, role_kind="verification",
                                role_executor=self.PINS)
        self.assertEqual(e0["config"]["scenario"], "OK_PASS")
        self.assertEqual(e5["config"]["scenario"], "BLOCKED")

    def test_lane_script_wins_over_roles_config_and_default(self):
        lane_task = {"executor": {"kind": "fake", "config": {"scenario": "WORKER_CRASH"}}}
        e = orch._executor_for("fake", lane_task, role_kind="verification",
                               role_executor=self.PINS)
        self.assertEqual(e["kind"], "fake")
        self.assertEqual(e["config"]["scenario"], "WORKER_CRASH")

    def test_bare_fake_default_keeps_deterministic_scenario(self):
        spec, source = orch._resolve_executor("fake", {"executor": {}},
                                              role_kind="integration", role_executor={})
        self.assertEqual(spec, {"kind": "fake", "config": {"scenario": "OK_PASS"}})
        self.assertEqual(source, "default-config")


class TestSeatProvenance(unittest.TestCase):
    """CONTROL: provenance is MEASURED from what was dispatched, written durably per run."""

    @control(244)
    def test_dispatched_run_records_measured_provider_and_source(self):
        h = EngineHarness()
        self.addCleanup(h.close)
        # Pin the verification seat to a KNOWN kind so the run really executes, while the
        # project default stays untouched -- then prove the event says WHICH won and WHY.
        h.cfg = dataclasses.replace(h.cfg, role_executor={"verification": "fake"})
        pid, lanes = h.new_program(
            "seat provenance", "every run records its seat",
            [{"key": "check", "title": "verify", "kind": orch.KIND_VERIFICATION,
              "acceptance": ()}],                       # NO scripted executor: roles-config wins
            policy=orch.ProgramPolicy(require_adversarial=False))
        h.tick(pid)
        bindings = h.sstore.runs_for_lane(lanes["check"])
        self.assertEqual(len(bindings), 1, "expected exactly one admitted run")
        events = [e for e in h.store.events_for(bindings[0]["run_id"])
                  if e["kind"] == "run.provenance"]
        self.assertEqual(len(events), 1, json.dumps(events, default=str))
        detail = json.loads(events[0]["detail_json"])
        # ALL FOUR claimed fields, MEASURED from the resolved dispatch spec (bd quaestor-kaz.11
        # -- model_family and model used to be claimed but never written). model_family is
        # DERIVED from the kind via the capability registry, never retyped here.
        self.assertEqual(detail["role"], orch.KIND_VERIFICATION)
        self.assertEqual(detail["provider"], "fake")   # measured: the resolved kind
        self.assertEqual(detail["model_family"],
                         cap_reg.provider_family("fake"))  # derived, and non-empty for fake
        self.assertEqual(detail["model"], "")          # a modelless transport records no model
        self.assertEqual(detail["source"], "roles-config")
        # The same measured seat rides in the handoff package the worker persisted.
        package_path = os.path.join(h.home, "runs", bindings[0]["run_id"], "handoff.json")
        if os.path.isfile(package_path):
            with open(package_path, encoding="utf-8") as fh:
                package = json.load(fh)
            self.assertEqual(package["seat"], {"role": orch.KIND_VERIFICATION,
                                               "provider": "fake"})

    def test_the_gateway_pinned_model_is_the_recorded_model(self):
        """A gateway kind names its model IN the kind; the record must carry exactly that."""
        from quaestor.adapters import registry as cap_reg
        detail = orch._provenance_detail(
            "verification", {"kind": "openrouter:anthropic/claude-opus-4",
                             "config": {"model": "openai/gpt-4o"}}, "roles-config")
        self.assertEqual(detail["provider"], "openrouter:anthropic/claude-opus-4")
        self.assertEqual(detail["model_family"], cap_reg.provider_family(
            "openrouter:anthropic/claude-opus-4"))   # anthropic -- the vendor that answered
        self.assertEqual(detail["model"], "anthropic/claude-opus-4")


if __name__ == "__main__":
    unittest.main()

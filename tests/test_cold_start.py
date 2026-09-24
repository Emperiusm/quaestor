# =============================================================================================
# THE COLD START (quaestor-pop, quaestor-o8k, quaestor-sev)
#
# FOUND BY BEING A NEW USER, not by reading the code. A fresh state home, a fresh git repo, the
# installed console script, and the documented happy path exactly as written:
#
#     quaestor init                 -> executor.default: fake   # "inert until you raise it"
#     quaestor program create ...   -> {"executor_default": "fake"}
#     quaestor program tick   x3    -> no errors, no skips
#     quaestor program status       -> PASS (every lane completed and passed)
#     git log                       -> unchanged. src/calc.py untouched.
#
# The user is told PASS by a program that spawned no agent and wrote no code. That is worse than
# a crash: a crash tells you something is wrong. The manifest called the test double "inert" --
# it is not inert, inert would REFUSE; it runs and reports success.
#
# Four layers each had a chance to say so and none did: config substituted "fake" for an absent
# declaration, init hard-coded it while `connect` was already detecting the real agent one
# module away, create reported the kind as a neutral fact, and status called the result PASS.
# These controls pin each layer.
# =============================================================================================
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from quaestor.adapters import registry as cap_reg          # noqa: E402
from quaestor.core import orchestrator as orch             # noqa: E402
from quaestor.projects import config as proj_cfg           # noqa: E402
from quaestor.projects import connect as proj_connect      # noqa: E402
from quaestor.projects import init as proj_init            # noqa: E402


class TestExecutionRealityIsMeasured(unittest.TestCase):
    """Layer 4: the verdict. PASS may not stand alone when nothing real ran."""

    def test_a_program_run_only_by_the_test_double_is_named(self):
        r = orch.execution_reality({"implementation": ["fake"]})
        self.assertTrue(r["measured"])
        self.assertTrue(r["test_double_only"])
        self.assertEqual(r["refusal"], orch.NO_REAL_AGENT_RAN)
        self.assertIn("no code was produced", r["note"])
        # The note must tell the user what to DO, not merely that something is wrong.
        self.assertIn("connect", r["note"])
        self.assertIn("executor.default", r["note"])

    def test_a_real_provider_is_not_maligned(self):
        """The control that gives the one above its meaning."""
        r = orch.execution_reality({"implementation": ["claude-cli"]})
        self.assertTrue(r["measured"])
        self.assertFalse(r["test_double_only"])
        self.assertEqual(r["refusal"], "")

    def test_one_real_seat_among_doubles_is_not_test_double_only(self):
        r = orch.execution_reality({"implementation": ["claude-cli"],
                                    "adversarial_review": ["fake"]})
        self.assertFalse(r["test_double_only"], r)

    def test_nothing_dispatched_is_reported_as_unmeasured_not_as_clean(self):
        """A program that has not run yet has not passed anything. Absent is not innocent."""
        r = orch.execution_reality({})
        self.assertFalse(r["measured"])
        self.assertFalse(r["test_double_only"])
        self.assertEqual(r["refusal"], "")

    def test_the_double_is_recognised_by_declared_family_not_by_its_name(self):
        """Matching the string 'fake' would let a second test kind present as a real agent."""
        self.assertEqual(cap_reg.provider_family("fake"), orch.TEST_PROVIDER_FAMILY)
        doubles = [k for k, v in cap_reg.PROVIDER_REGISTRY.items()
                   if v["provider_family"] == orch.TEST_PROVIDER_FAMILY]
        for kind in doubles:
            with self.subTest(kind=kind):
                self.assertTrue(
                    orch.execution_reality({"implementation": [kind]})["test_double_only"],
                    "%r is declared a test provider and was not recognised as one" % kind)

    def test_the_operator_display_prints_the_refusal(self):
        """Carried in the view AND rendered. A fact only present in JSON is not stated."""
        from quaestor.transports import cli
        view = {"program_id": "p", "title": "t", "status": "CANDIDATE_PASS", "lanes": [],
                "inbox_count": 0,
                "aggregate": {"program_verdict": "PASS", "reason": "every lane passed"},
                "execution_reality": orch.execution_reality({"implementation": ["fake"]})}
        text = cli._render_status(view)
        self.assertIn(orch.NO_REAL_AGENT_RAN, text)
        self.assertIn("PASS", text, "the real verdict must still be shown, not replaced")

    def test_a_real_run_prints_no_warning(self):
        from quaestor.transports import cli
        view = {"program_id": "p", "title": "t", "status": "CANDIDATE_PASS", "lanes": [],
                "inbox_count": 0, "aggregate": {"program_verdict": "PASS", "reason": "ok"},
                "execution_reality": orch.execution_reality({"implementation": ["claude-cli"]})}
        self.assertNotIn(orch.NO_REAL_AGENT_RAN, cli._render_status(view))


class TestAbsenceIsNotSubstituted(unittest.TestCase):
    """Layer 1: the root. A manifest naming no executor silently became the test double."""

    def _load(self, body):
        d = tempfile.mkdtemp(prefix="quaestor-coldstart-")
        p = os.path.join(d, "quaestor.yaml")
        with io.open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        return proj_cfg.load(p)

    BASE = "project:\n  name: x\n  repository: .\n\nauthority:\n  default:\n    - READ_ONLY\n"

    def test_an_undeclared_executor_resolves_to_nothing_not_to_a_double(self):
        """THE DEFECT: `(doc.get("executor") or {}).get("default", "fake")`."""
        cfg, reason = self._load(self.BASE)
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.executor, "",
                         "an absent executor declaration was substituted with a test double")

    def test_a_declared_executor_is_honoured(self):
        cfg, reason = self._load(self.BASE + "\nexecutor:\n  default: claude-cli\n")
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.executor, "claude-cli")

    def test_dispatch_refuses_an_empty_seat_BY_NAME(self):
        """Fail closed, and say which seat and what to do about it."""
        spec, source = orch._resolve_executor("", {"executor": {}}, role_kind="implementation")
        self.assertEqual(spec.get("refusal"), cap_reg.SEAT_UNRESOLVABLE, spec)
        rationale = " ".join(spec.get("rationale") or ())
        self.assertIn("no executor", rationale)
        self.assertIn("executor.default", rationale)
        self.assertTrue(source.endswith("-refused"), source)


class TestInitPinsWhatItMeasured(unittest.TestCase):
    """Layer 2: init hard-coded the double while connect detected the real agent next door."""

    def _detect_as(self, found):
        real = proj_connect.shutil.which

        def fake_which(binary, *a, **k):
            if binary in ("claude", "codex"):
                return found.get(binary)
            return real(binary, *a, **k)

        proj_connect.shutil.which = fake_which
        self.addCleanup(setattr, proj_connect.shutil, "which", real)

    def _repo(self):
        d = tempfile.mkdtemp(prefix="quaestor-coldinit-")
        os.makedirs(os.path.join(d, "tests"))
        with io.open(os.path.join(d, "tests", "test_x.py"), "w",
                     encoding="utf-8", newline="\n") as fh:
            fh.write("import unittest\n\n\nclass T(unittest.TestCase):\n"
                     "    def test_a(self):\n        self.assertTrue(True)\n")
        return d

    def test_only_a_located_binary_earns_a_pin(self):
        """A marker file proves an agent touched this workspace. It proves nothing is installed.

        runnable_executors is deliberately narrower than _detect_agents for that reason."""
        self._detect_as({"claude": "/usr/local/bin/claude"})
        found = proj_connect.runnable_executors(self._repo())
        self.assertEqual([r["kind"] for r in found], ["claude-cli"])
        self.assertEqual(found[0]["evidence"], "/usr/local/bin/claude")

    def test_every_pinnable_kind_can_actually_be_built(self):
        """A generated manifest may never name a kind this build cannot construct."""
        from quaestor.executors import registry as ex_reg
        for agent, kind in sorted(proj_connect.AGENT_EXECUTOR_KIND.items()):
            with self.subTest(agent=agent):
                self.assertIn(kind, ex_reg.KNOWN_KINDS,
                              "init could pin %r, which executors.registry cannot build" % kind)
                self.assertTrue(cap_reg.is_declared(kind))

    def test_init_writes_the_detected_agent_and_its_evidence(self):
        self._detect_as({"claude": "/usr/local/bin/claude"})
        out = proj_init.init_repository(self._repo())
        self.assertTrue(out["executor_configured"], out)
        self.assertEqual(out["detected_executors"][0]["kind"], "claude-cli")
        cfg, reason = proj_cfg.load(out["manifest"])
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.executor, "claude-cli")
        with io.open(out["manifest"], encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("/usr/local/bin/claude", manifest,
                      "the evidence for the pin is not where a human can re-check it")

    def test_with_nothing_installed_init_writes_no_runnable_default(self):
        self._detect_as({})
        out = proj_init.init_repository(self._repo())
        self.assertFalse(out["executor_configured"], out)
        self.assertEqual(out["detected_executors"], [])
        with io.open(out["manifest"], encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("NO AGENT DETECTED", manifest)
        block = manifest.split("executor:")[1].split("commands:")[0]
        live = [ln for ln in block.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(live, [], "a runnable default was written with nothing detected")
        cfg, reason = proj_cfg.load(out["manifest"])
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.executor, "", "the double crept back in through the load path")

    def test_a_generated_manifest_never_names_a_test_double(self):
        """The property both branches share, stated once so an edit to either cannot lose it."""
        for found in ({"claude": "/usr/local/bin/claude"}, {}):
            with self.subTest(found=sorted(found)):
                self._detect_as(found)
                out = proj_init.init_repository(self._repo())
                cfg, _r = proj_cfg.load(out["manifest"])
                if cfg.executor:
                    self.assertNotEqual(cap_reg.provider_family(cfg.executor),
                                        orch.TEST_PROVIDER_FAMILY,
                                        "a generated manifest pinned a test double")


class TestEverySubcommandDescribesItself(unittest.TestCase):
    """Layer 3 of discoverability (quaestor-sev): `program --help` listed twelve verbs and
    described three -- on the command that is the entire point of the tool."""

    def _parser(self):
        from quaestor.transports import cli
        return cli.build_parser()

    def _subparser_actions(self, parser):
        import argparse
        return [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]

    def test_no_subcommand_is_listed_without_a_description(self):
        parser = self._parser()
        missing = []
        for action in self._subparser_actions(parser):
            described = {c.dest for c in action._choices_actions}
            for name, sub in action.choices.items():
                if name not in described:
                    missing.append(name)
                for nested in self._subparser_actions(sub):
                    nested_described = {c.dest for c in nested._choices_actions}
                    for nested_name in nested.choices:
                        if nested_name not in nested_described:
                            missing.append("%s %s" % (name, nested_name))
        self.assertEqual(sorted(missing), [],
                         "subcommand(s) listed with no help text: %s" % sorted(missing))


if __name__ == "__main__":
    unittest.main()

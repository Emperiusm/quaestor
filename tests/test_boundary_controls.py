"""BOUNDARY CONTROLS (209-213) -- claims that were made in prose and never checked.

Two of these exist because a document asserted a check that lived nowhere in the repository. A
claim in a README is not a control, and the gap between them is exactly where a one-sided rename
survives: the egress proxy would have fallen back to its defaults, which for the allowlist means
"allow nothing", and the symptom would have been a mystery outage rather than a named failure.

The third closes the genericity acceptance test's weakest point: it certified a reference project
whose executor could not actually be constructed, which is a demonstration of configuration
parsing rather than of genericity.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor import branding  # noqa: E402
from quaestor.executors import registry as exec_registry  # noqa: E402
from quaestor.projects import config as proj_cfg  # noqa: E402
from tests.controls import control  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


class TestCrossBoundary(unittest.TestCase):
    @control(209)
    def test_the_egress_env_contract_is_symmetric_across_the_container_boundary(self):
        """The host SENDS these; the in-container proxy READS them. A rename on one side only is
        silent: the proxy falls back to its defaults, and its allowlist default is empty."""
        sent = {branding.env_var("egress", "mode"),
                branding.env_var("egress", "allow"),
                branding.env_var("egress", "policy", "version")}

        proxy = read(os.path.join(ROOT, "docker", "egress_proxy.py"))
        read_by_proxy = set(re.findall(r'os\.environ\.get\(\s*"([A-Z_]+)"', proxy))

        self.assertTrue(sent, "the host side names no egress variables at all")
        self.assertTrue(read_by_proxy, "the proxy reads no environment at all")
        missing = sorted(sent - read_by_proxy)
        self.assertEqual(missing, [],
                         "sent but never read -- the proxy would silently use its defaults: %s"
                         % missing)

        # And the host really does send them: assert against the sandbox module, not a comment.
        egress_src = read(os.path.join(ROOT, "src", "quaestor", "sandbox", "egress.py"))
        for part in ("egress", "mode"), ("egress", "allow"), ("egress", "policy", "version"):
            self.assertIn('branding.env_var("%s"' % part[0], egress_src)

    @control(210)
    def test_the_container_image_and_the_host_agree_on_the_auth_seed_path(self):
        """The host derives this path from branding; the image hard-codes it. They must match, or
        a product rename silently leaves the child unauthenticated -- which looks like a
        credential problem rather than a rename problem."""
        from quaestor.secrets import credentials

        host_path = credentials.seed_provider("v").mount_path
        dockerfile = read(os.path.join(ROOT, "docker", "Dockerfile"))
        bootstrap = read(os.path.join(ROOT, "docker", "quaestor-bootstrap.sh"))

        self.assertIn(host_path, dockerfile,
                      "the image does not create the seed path the host mounts")
        self.assertIn(host_path, bootstrap,
                      "the bootstrap does not read the seed path the host mounts")
        self.assertIn(branding.PRODUCT_NAME, host_path)

    @control(211)
    def test_the_genericity_examples_are_actually_constructible(self):
        """The acceptance test certified a reference project whose executor could not be built.

        Parsing a manifest proves the parser works. Genericity means the platform can actually
        act on two different projects, so every configured provider must resolve.
        """
        seen_executors = set()
        for name in ("synthetic", "reference"):
            cfg, reason = proj_cfg.load(os.path.join(ROOT, "examples", name, "quaestor.yaml"))
            self.assertIsNotNone(cfg, "%s: %s" % (name, reason))
            self.assertIn(cfg.executor, exec_registry.KNOWN_KINDS,
                          "%s names executor %r which this build cannot construct"
                          % (name, cfg.executor))
            seen_executors.add(cfg.executor)
            self.assertIn(cfg.workspace_provider, ("git-worktree", "none"))
            self.assertIn(cfg.sandbox_provider, ("docker", "none"))
        self.assertEqual(len(seen_executors), 2,
                         "both examples name the same executor, so nothing about provider "
                         "independence is being demonstrated")

    @control(211)
    def test_a_third_repository_needs_configuration_and_not_core_changes(self):
        """The acceptance criterion, exercised: a NEW project the platform has never seen.

        Two examples can share a hidden assumption; a third, written here from nothing, cannot.
        """
        import hashlib

        core_dir = os.path.join(ROOT, "src", "quaestor", "core")
        before = hashlib.sha256()
        for f in sorted(os.listdir(core_dir)):
            if f.endswith(".py"):
                before.update(open(os.path.join(core_dir, f), "rb").read())

        tmp = tempfile.mkdtemp(prefix="quaestor-third-")
        repo = os.path.join(tmp, "some-service")
        os.makedirs(repo, exist_ok=True)
        protected = os.path.join(tmp, "keep-out")
        os.makedirs(protected, exist_ok=True)
        p = os.path.join(tmp, "quaestor.yaml")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join([
                "project:", "  name: third-party-service", "  repository: ./some-service", "",
                "executor:", "  default: fake", "",
                "commands:", "  test:", '    - pytest -q', "",
                "authority:", "  default:", "    - READ_ONLY", "",
                "review:", "  adversarial:", "    enabled: true", "",
                "security:", "  protected_roots:", "    - %s" % protected, ""]) + "\n")

        from quaestor import deployment
        dep, reason = deployment.build(p)
        self.assertIsNotNone(dep, reason)
        self.assertEqual(dep.project.name, "third-party-service")
        self.assertEqual(dep.project.test_commands, ("pytest -q",))
        self.assertTrue(dep.protected_roots)
        self.assertTrue(dep.project.adversarial_review)

        after = hashlib.sha256()
        for f in sorted(os.listdir(core_dir)):
            if f.endswith(".py"):
                after.update(open(os.path.join(core_dir, f), "rb").read())
        self.assertEqual(before.hexdigest(), after.hexdigest(),
                         "the core changed while adding a project")


class TestInstrumentReach(unittest.TestCase):
    """The walks that certify the layering, fed bytes they did not generate."""

    #: A synthetic module using EVERY relative-import form. It is written here, by hand, in the
    #: idiom the source repository used -- deliberately NOT rendered by the thing under test.
    #: A control whose input is its own subject's output tests serialization, not verification.
    FOREIGN = """from . import worker
from .core import dispatcher
from .. import branding
from ..executors import registry
from ..executors.registry import build
import quaestor.transports.mcp.adapter
from quaestor.core import store
"""

    @control(212)
    def test_the_import_walk_resolves_every_relative_form(self):
        """Three structural controls keyed on ``node.module`` and could not see a relative import.

        That is not a hypothetical gap. The repository this platform was extracted from used
        relative imports EXCLUSIVELY, so a layering walk blind to them would have certified a
        clean graph over a tree whose edges it could not read -- and it would have reported
        ``[]``, which is indistinguishable from ``no violations``.
        """
        import ast
        from tests import support

        tree = ast.parse(self.FOREIGN)
        got = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                got += support.resolve_imports(node, "quaestor.core.worker", False)

        # Anchored at the MODULE quaestor.core.worker: level 1 -> quaestor.core,
        # level 2 -> quaestor.
        for expect in ("quaestor.core.worker", "quaestor.core.core.dispatcher",
                       "quaestor.branding", "quaestor.executors.registry",
                       "quaestor.executors.registry.build",
                       "quaestor.transports.mcp.adapter", "quaestor.core.store"):
            self.assertIn(expect, got, "the walk cannot see %s" % expect)
        self.assertGreaterEqual(len(got), 7, "the walk resolved %d names" % len(got))

        # And the anchor is not decorative: the SAME name read as a PACKAGE resolves one level
        # deeper, so a walk that ignored `is_package` would silently shift every relative edge
        # by one package and still report a graph.
        as_pkg = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                as_pkg += support.resolve_imports(node, "quaestor.core.worker", True)
        self.assertIn("quaestor.core.worker.worker", as_pkg)
        self.assertIn("quaestor.core.branding", as_pkg)
        self.assertNotEqual(sorted(set(got)), sorted(set(as_pkg)))

    @control(213)
    def test_the_credential_policy_names_no_vendor_and_refuses_without_one(self):
        """``core`` held nine Anthropic variable names, one vendor's status parser and a
        subprocess call to a binary named ``claude`` -- and the dispatch path reached it BY
        DEFAULT, so a deployment with a different executor got Anthropic's credential rules
        whether it wanted them or not.
        """
        from quaestor.core import credential_policy as cp

        import ast as _ast
        path = os.path.join(ROOT, "src", "quaestor", "core", "credential_policy.py")
        src = read(path)
        self.assertGreater(len(src), 4000, "the scan read %d bytes" % len(src))

        # CODE, NOT PROSE. Docstrings and comments in this module QUOTE the finding that caused
        # the split, so they name the vendor on purpose. Scanning them would force the fix to be
        # undocumented in order to pass -- a gate that punishes the explanation of its own
        # subject. So the subject is the executable module with every docstring removed.
        tree = _ast.parse(src, filename=path)
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef,
                                 _ast.AsyncFunctionDef)):
                body = node.body
                if (body and isinstance(body[0], _ast.Expr)
                        and isinstance(body[0].value, _ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    node.body = body[1:] or [_ast.Pass()]
        code = _ast.unparse(_ast.fix_missing_locations(tree))
        self.assertGreater(len(code), 2000, "the scan read %d bytes of code" % len(code))
        for vendor in ("ANTHROPIC", "CLAUDE", "BEDROCK", "VERTEX", "OPENAI", "SUBPROCESS"):
            self.assertNotIn(vendor, code.upper(),
                             "core/credential_policy.py names %s in CODE" % vendor)
        # Control on the control: the same scan DOES see the vendor in the provider module, so
        # it is not blind to the token it is looking for.
        vendor_src = read(os.path.join(ROOT, "src", "quaestor", "executors", "claude_auth.py"))
        self.assertIn("ANTHROPIC_API_KEY", vendor_src)

        # A MISSING POLICY REFUSES. It does not fall back to a shipped vendor.
        d = cp.decide(policy=None, env={}, auth_status=None)
        self.assertFalse(d.accepted)
        self.assertEqual(d.reason, cp.REASON_NO_POLICY)

        # ... and the dispatch path has no vendor default left in it.
        disp = read(os.path.join(ROOT, "src", "quaestor", "core", "dispatcher.py"))
        self.assertNotIn("run_preflight", disp,
                         "core/dispatcher still reaches a provider's preflight by default")

        # Control on the control: a REAL policy is accepted by the same call, so this is not a
        # gate that refuses everything.
        from quaestor.executors import claude_auth
        ok = cp.decide(policy=claude_auth.CLAUDE_POLICY, env={},
                       auth_status={"loggedIn": True, "authMethod": "claude.ai",
                                    "apiProvider": "firstParty", "subscriptionType": "max"})
        self.assertTrue(ok.accepted, ok.reason)


if __name__ == "__main__":
    unittest.main()

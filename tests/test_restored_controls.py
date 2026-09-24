"""RESTORED CONTROLS (206-208) -- platform pins the registry split dropped.

Three security-significant controls were classified `PROJECT_INTEGRATION` and left behind with
the consuming project. Adversarial review read their bodies and found them fully synthetic: they
construct providers, environments and confinement profiles in-process and touch no repository.

They were lost to a RANGE-BASED split (ids 19-30 and 89-112) rather than to a judgement about each
control -- which is exactly the failure mode a range-based split has, and why the reclassification
is recorded in `tests/controls.py` rather than done quietly.

One of them matters more than the other two: the pin that stops an API key being exempted was left
behind while the constant it guards was MOVED INTO CORE by the same extraction.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.controls import control  # noqa: E402

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


class TestRestoredControls(unittest.TestCase):
    @control(206)
    def test_a_provider_secret_is_redacted_everywhere(self):
        from quaestor.secrets import credentials

        p = credentials.external_oauth_provider(available=True)
        blob = json.dumps(p.to_dict())
        self.assertNotIn("SUPERSECRET", blob)

        env = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-SUPERSECRET-VALUE",
               "ANTHROPIC_API_KEY": "sk-ant-api-ALSO-SECRET", "PATH": "/usr/bin"}
        red = credentials.redact_env(env)
        text = json.dumps(red)
        self.assertNotIn("SUPERSECRET", text)
        self.assertNotIn("ALSO-SECRET", text)
        self.assertIn(credentials.REDACTED, text)
        self.assertEqual(red["PATH"], "/usr/bin", "non-secret values must survive redaction")

        # Detected by VALUE, not by name -- catches a leak whose emitter never names the variable.
        leaky = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-LEAKYVALUE-1234567890"}
        self.assertEqual(credentials.scan_for_secrets("nothing here", leaky), [])
        self.assertEqual(
            credentials.scan_for_secrets("oops sk-ant-oat-LEAKYVALUE-1234567890 oops", leaky),
            ["CLAUDE_CODE_OAUTH_TOKEN"])

    @control(207)
    def test_an_absent_credential_for_unattended_production_yields_owner_required(self):
        from quaestor.secrets import credentials

        det = credentials.detect(env={}, seed_present=False, broker_available=False)
        ok, why = credentials.admit_for_mode(det, unattended=True)
        self.assertFalse(ok)
        self.assertIn("no credential provider", why)

        seed_only = credentials.detect(env={}, seed_volume="v", seed_present=True,
                                       broker_available=False)
        ok, why = credentials.admit_for_mode(seed_only, unattended=True)
        self.assertFalse(ok, "a qualification-grade provider must not serve unattended production")
        self.assertIn("OWNER_REQUIRED", why)
        # Control on the control: attended qualification MAY use it, so this is not a blanket no.
        ok, _ = credentials.admit_for_mode(seed_only, unattended=False)
        self.assertTrue(ok)

    @control(208)
    def test_the_api_key_can_never_be_exempted_by_any_provider(self):
        """The extraction moved the constant into core and left its only guard behind.

        Restoring the guard as written would have restored a WEAK one: it asserted that one
        literal string was absent from one frozenset. That protects `ANTHROPIC_API_KEY` and
        nothing else -- a second provider adding `OPENAI_API_KEY` inherits none of it. So the
        rule is now structural (a name SHAPE, checked for every provider, at policy construction)
        and this control tests the rule, not the string.
        """
        from quaestor.core import credential_policy as cp
        from quaestor.executors import claude_auth as pf
        from quaestor.secrets import credentials

        # 1. THE SHAPE RULE, over names no shipped policy mentions -- so this cannot be passing
        #    by having memorised the one vendor in the tree.
        forbidden = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
                     "ANTHROPIC_AUTH_TOKEN", "SOMEVENDOR_SECRET_KEY", "AWS_ACCESS_KEY_ID",
                     "VENDOR_BASE_URL", "AWS_BEARER_TOKEN_BEDROCK")
        for name in forbidden:
            self.assertTrue(cp.forbids_exemption(name), name)
        # Control on the control: the rule DISCRIMINATES. If it refused every name, the
        # brokered automation credential could never be injected and the whole broker would be
        # dead -- a gate that refuses universally proves nothing.
        for name in ("CLAUDE_CODE_OAUTH_TOKEN", "VENDOR_OAUTH_TOKEN", "HTTP_PROXY",
                     "CLAUDE_CODE_USE_BEDROCK"):
            self.assertEqual(cp.forbids_exemption(name), "", name)

        # 2. A POLICY THAT WOULD BREACH THE CEILING CANNOT BE CONSTRUCTED, so it can never be
        #    reached at dispatch time by any path.
        for name in forbidden:
            with self.assertRaises(cp.PolicyError, msg=name):
                cp.ProviderCredentialPolicy(provider="rogue", override_env=(name,),
                                            exemptible_env=frozenset({name}))

        # 3. The shipped policy, and the broker, read from ONE definition.
        self.assertEqual(pf.CLAUDE_POLICY.exemptible_env,
                         frozenset({"CLAUDE_CODE_OAUTH_TOKEN"}))
        self.assertIs(credentials.EXEMPTIBLE_ENV, pf.CLAUDE_POLICY.exemptible_env,
                      "two definitions would let one be widened without the other")

        # A caller CLAIMING the provider injected an API key still gets no exemption.
        offenders = pf.env_overrides_present(
            {"ANTHROPIC_API_KEY": "sk-ant-whatever"},
            provider_injected=["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"])
        self.assertIn("ANTHROPIC_API_KEY", offenders)

        d = pf.decide(env={"ANTHROPIC_API_KEY": "x"}, auth_status=None,
                      provider_injected=["ANTHROPIC_API_KEY"])
        self.assertFalse(d.accepted)

        # Control on the control: the ONE exemptible name really is exempt, so this is not a
        # gate that refuses everything.
        self.assertEqual(
            pf.env_overrides_present({"CLAUDE_CODE_OAUTH_TOKEN": "x"},
                                     provider_injected=["CLAUDE_CODE_OAUTH_TOKEN"]), ())

    @control(208)
    def test_the_mount_exemption_escape_hatch_is_still_bounded(self):
        """`permitted_exact_paths` / `never_exempt` lost 100% of its coverage in the split.

        It is the escape hatch in the confinement policy -- precisely the thing whose bounds must
        never go untested, since an unbounded exemption mechanism is not an exemption mechanism.
        """
        from quaestor.sandbox import profile as cp

        platform_root = os.path.abspath(SRC).replace("\\", "/")
        project_root = os.path.abspath(
            tempfile.mkdtemp(prefix="quaestor-proj-")).replace("\\", "/")

        never = cp.never_exemptible(platform_root, project_root)
        self.assertIn(cp.canonical_path(platform_root), never)
        self.assertIn(cp.canonical_path(project_root), never)
        home = os.path.expanduser("~").replace("\\", "/")
        self.assertIn(cp.canonical_path(home), never)
        self.assertIn(cp.canonical_path(home + "/.ssh"), never)
        self.assertGreater(len(never), 6, "the never-exemptible set is suspiciously small")

        forbidden = [f.replace("\\", "/") for f in
                     cp.default_forbidden_paths(platform_root, project_root)]
        self.assertIn(project_root, forbidden)
        self.assertTrue(any(".ssh" in f for f in forbidden))
        self.assertTrue(any(".aws" in f for f in forbidden))


if __name__ == "__main__":
    unittest.main()

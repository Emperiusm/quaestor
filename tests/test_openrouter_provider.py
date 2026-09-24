"""test_openrouter_provider -- CONTROLS for the gateway provider and the identity problem it
creates.

WHY THIS SUITE EXISTS AT ALL
----------------------------
Every epistemic-independence guarantee on this platform rests on ONE assumption: one provider
family per executor kind. ``claude-cli`` is anthropic, ``codex-cli`` is openai, and
``check_pairing`` can therefore refuse a seat when implementation and adversarial review would
share a vendor.

A GATEWAY breaks that assumption. ``openrouter`` running ``anthropic/claude-opus-4`` and
``openrouter`` running ``openai/gpt-5`` are two different vendors wearing one kind name.
Registering it naively fails in one of two ways, and only one of them is loud:

    * family "openrouter" -> two ANTHROPIC models pass the cross-vendor check because the
      gateway name matched. Adversarial review silently becomes one vendor reviewing itself,
      and nothing anywhere reports a problem. This is the dangerous one.
    * family "openrouter" -> two genuinely different vendors are refused as same-family. Safe,
      loud, and the feature is useless.

So family is derived from the MODEL, and a gateway kind named without one resolves to no family
at all -- refused everywhere a family is required, because an unnamed model is an unknown vendor
and an unknown vendor cannot be certified independent of anything.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quaestor.adapters import registry as reg  # noqa: E402
from quaestor.core import credential_policy as cp_mod  # noqa: E402
from quaestor.core import executor_contract as ec  # noqa: E402

#: The pairing context used throughout: implementation and adversarial review must not share a
#: vendor. This is the policy the whole feature could silently defeat.
PAIR_CTX = {"require_distinct_between": [("implementation", "adversarial_review")]}


class TestGatewayProviderIdentity(unittest.TestCase):
    def test_the_family_comes_from_the_model_not_the_gateway(self):
        self.assertEqual(reg.provider_family("openrouter:anthropic/claude-opus-4"), "anthropic")
        self.assertEqual(reg.provider_family("openrouter:openai/gpt-5"), "openai")
        self.assertEqual(reg.provider_family("openrouter:google/gemini-2.5-pro"), "google")
        self.assertEqual(reg.provider_family("openrouter:meta-llama/llama-4"), "meta")

    def test_a_bare_gateway_kind_has_no_family(self):
        """An unnamed model is an unknown vendor, and refusing is the only honest answer."""
        self.assertEqual(reg.provider_family("openrouter"), "")

    def test_an_unmapped_vendor_prefix_is_empty_not_guessed(self):
        """A vendor this build has never heard of must not be assumed independent of
        everything else merely because its prefix is unfamiliar."""
        self.assertEqual(reg.provider_family("openrouter:brandnew/model-1"), "")
        self.assertEqual(reg.provider_family("openrouter:/leading-slash"), "")

    def test_direct_kinds_are_unaffected(self):
        self.assertEqual(reg.provider_family("claude-cli"), "anthropic")
        self.assertEqual(reg.provider_family("codex-cli"), "openai")
        self.assertEqual(reg.provider_family("nonsense-cli"), "")

    def test_split_gateway_kind_is_total(self):
        self.assertEqual(reg.split_gateway_kind("openrouter:openai/gpt-5"),
                         ("openrouter", "openai/gpt-5"))
        self.assertEqual(reg.split_gateway_kind("claude-cli"), ("claude-cli", ""))
        self.assertEqual(reg.split_gateway_kind(""), ("", ""))
        self.assertEqual(reg.split_gateway_kind("openrouter:"), ("openrouter", ""))

    def test_the_gateway_is_declared_but_carries_no_family_of_its_own(self):
        self.assertIn("openrouter", reg.PROVIDER_REGISTRY)
        self.assertEqual(reg.PROVIDER_REGISTRY["openrouter"]["provider_family"], "",
                         "a gateway that claimed a family would be claiming to be a vendor")
        self.assertEqual(reg.PROVIDER_REGISTRY["openrouter"]["credential_mode"], ("api",),
                         "OpenRouter is API-billed; declaring subscription would falsify the "
                         "one fact credential_policy exists to establish")

    def test_a_gateway_form_is_declared_so_a_typo_is_still_a_named_refusal(self):
        self.assertTrue(reg.is_declared("openrouter:anthropic/claude-opus-4"))
        self.assertTrue(reg.is_declared("openrouter"))
        self.assertFalse(reg.is_declared("openrooter:anthropic/claude-opus-4"))
        self.assertFalse(reg.is_declared("typo-cli"))


class TestGatewayIndependence(unittest.TestCase):
    """THE CONTROLS THAT MATTER. If these pass, routing two models through one gateway cannot
    quietly turn cross-vendor review into one vendor reviewing itself."""

    def test_two_models_from_one_vendor_are_refused_as_a_cross_vendor_pair(self):
        refusal = reg.check_pairing(PAIR_CTX, "implementation",
                                    "openrouter:anthropic/claude-opus-4",
                                    "adversarial_review",
                                    "openrouter:anthropic/claude-sonnet-4")
        self.assertEqual(refusal, reg.EPISTEMIC_INDEPENDENCE_UNMET)

    def test_two_models_from_different_vendors_pair_cleanly(self):
        self.assertEqual(reg.check_pairing(PAIR_CTX, "implementation",
                                           "openrouter:anthropic/claude-opus-4",
                                           "adversarial_review",
                                           "openrouter:openai/gpt-5"), "")

    def test_a_gateway_model_collides_with_the_SAME_vendors_direct_cli(self):
        """The subtle one. Implementation on claude-cli reviewed by 'openrouter:anthropic/...'
        is Anthropic reviewing Anthropic -- the gateway is a billing detail, not a second
        opinion, and routing family rather than kind is what catches it."""
        self.assertEqual(reg.check_pairing(PAIR_CTX, "implementation", "claude-cli",
                                           "adversarial_review",
                                           "openrouter:anthropic/claude-sonnet-4"),
                         reg.EPISTEMIC_INDEPENDENCE_UNMET)
        self.assertEqual(reg.check_pairing(PAIR_CTX, "implementation", "codex-cli",
                                           "adversarial_review",
                                           "openrouter:openai/gpt-5"),
                         reg.EPISTEMIC_INDEPENDENCE_UNMET)

    def test_a_gateway_model_pairs_cleanly_with_a_different_vendors_cli(self):
        self.assertEqual(reg.check_pairing(PAIR_CTX, "implementation", "claude-cli",
                                           "adversarial_review",
                                           "openrouter:openai/gpt-5"), "")

    def test_an_unknown_vendor_never_certifies_independence(self):
        """No family means the same-family test cannot fire, so this pairing is NOT refused --
        but that is precisely why an unnamed/unknown model must never reach a seat. The
        resolve_seat control below is what actually closes this door."""
        self.assertEqual(reg.provider_family("openrouter:brandnew/model-1"), "")


class TestGatewaySeatResolution(unittest.TestCase):
    def test_a_gateway_pin_naming_a_model_resolves_and_carries_the_model_family(self):
        d = reg.resolve_seat("adversarial_review", {},
                             {"adversarial_review": "openrouter:openai/gpt-5"})
        self.assertEqual(d.refusal, "", d.rationale)
        self.assertEqual(d.kind, "openrouter:openai/gpt-5")
        self.assertTrue(any("openai" in r for r in d.rationale), d.rationale)

    def test_a_bare_gateway_pin_is_refused_by_name(self):
        """Fail CLOSED. A gateway with no model would resolve to a seat whose vendor nobody
        knows, and every independence guarantee downstream would be evaluating an empty
        string against an empty string."""
        d = reg.resolve_seat("adversarial_review", {}, {"adversarial_review": "openrouter"})
        self.assertEqual(d.kind, "")
        self.assertEqual(d.refusal, reg.SEAT_UNRESOLVABLE)
        self.assertTrue(any("model" in r for r in d.rationale), d.rationale)

    def test_a_gateway_pin_naming_an_unknown_vendor_never_takes_the_seat(self):
        """resolve_seat treats a pin as a PREFERENCE: a policy-rejected pin falls through to the
        next candidate rather than refusing outright. What matters here is that the unmappable
        gateway is not the thing that gets seated, and that the trace says why."""
        d = reg.resolve_seat("adversarial_review", {},
                             {"adversarial_review": "openrouter:brandnew/model-1"})
        self.assertNotEqual(d.kind, "openrouter:brandnew/model-1")
        self.assertTrue(any("provider family" in r and "brandnew" in r for r in d.rationale),
                        d.rationale)

    def test_family_exclusion_applies_to_the_model_not_the_gateway(self):
        """The pairing policy hands resolve_seat a family to exclude. If the gateway reported
        its own name as the family, exclusion would never match and the policy would be
        decorative."""
        d = reg.resolve_seat("adversarial_review",
                             {"exclude_provider_families": ("anthropic",)},
                             {"adversarial_review": "openrouter:anthropic/claude-opus-4"})
        self.assertNotEqual(d.kind, "openrouter:anthropic/claude-opus-4",
                            "an excluded family was seated because the proxy name differed")
        self.assertTrue(any("family anthropic excluded" in r for r in d.rationale),
                        d.rationale)
        d = reg.resolve_seat("adversarial_review",
                             {"exclude_provider_families": ("anthropic",)},
                             {"adversarial_review": "openrouter:openai/gpt-5"})
        self.assertEqual(d.kind, "openrouter:openai/gpt-5", d.rationale)

    def test_a_subscription_only_policy_rejects_the_api_billed_gateway(self):
        d = reg.resolve_seat("strategist", {"credential_modes": ("subscription",)},
                             {"strategist": "openrouter:openai/gpt-5"})
        self.assertNotEqual(d.kind, "openrouter:openai/gpt-5",
                            "an API-billed gateway satisfied a subscription-only policy")
        self.assertTrue(any("credential mode" in r for r in d.rationale), d.rationale)

    def test_a_non_write_seat_still_admits_the_gateway(self):
        d = reg.resolve_seat("strategist", {}, {"strategist": "openrouter:anthropic/claude-opus-4"})
        self.assertEqual(d.refusal, "", d.rationale)

    def test_the_bare_gateway_is_not_in_the_default_preference_order(self):
        """An unpinned seat must never silently land on a gateway with no model named."""
        self.assertNotIn("openrouter", reg.PROVIDER_ORDER)
        d = reg.resolve_seat("implementation", {}, {})
        self.assertNotEqual(reg.split_gateway_kind(d.kind)[0], "openrouter")


class _Req:
    """A minimal ExecRequest stand-in. The executor uses only these fields, and building the
    real dataclass would drag a RunBinding into a test about HTTP."""

    def __init__(self, run_dir, prompt="do the thing", timeout_s=30.0):
        self.run_dir = run_dir
        self.stdout_path = os.path.join(run_dir, "stdout.txt")
        self.stderr_path = os.path.join(run_dir, "stderr.txt")
        self.prompt = prompt
        self.timeout_s = timeout_s
        self.cwd = run_dir
        self.env = None


def _completion(text="the answer", **usage):
    return json.dumps({"id": "gen-1", "model": "openai/gpt-5",
                       "choices": [{"message": {"role": "assistant", "content": text}}],
                       "usage": usage or {"prompt_tokens": 10, "completion_tokens": 3,
                                          "total_tokens": 13, "cost": 0.0004}})


class TestOpenRouterPreflight(unittest.TestCase):
    def test_an_absent_key_refuses_without_any_network_call(self):
        """A preflight that phoned home to learn it had no credential would tell a third party
        this deployment exists in exchange for information it already had."""
        from quaestor.executors import openrouter_auth as auth
        called = {"n": 0}

        def _never(*_a, **_k):
            called["n"] += 1
            raise AssertionError("the preflight made a request with no key")

        d = auth.run_preflight(env={}, opener=_never)
        self.assertEqual(called["n"], 0)
        self.assertFalse(d.accepted)
        self.assertEqual(d.reason, auth.REASON_NO_KEY)
        self.assertEqual(d.auth_class, cp_mod.LOGGED_OUT)

    def test_a_working_key_reports_API_billing_and_never_subscription(self):
        """OpenRouter is API-billed. Reporting subscription would falsify the one fact the
        whole credential apparatus exists to establish, and a subscription-only policy would
        then route seats here believing they were covered."""
        from quaestor.executors import openrouter_auth as auth
        d = auth.run_preflight(
            env={auth.API_KEY_VAR: "sk-or-v1-test"},
            opener=lambda *_a, **_k: (200, json.dumps(
                {"data": {"total_credits": 5.0, "total_usage": 1.25}})))
        self.assertTrue(d.accepted)
        self.assertEqual(d.auth_class, cp_mod.API_CONSOLE)
        self.assertNotEqual(d.auth_class, cp_mod.SUBSCRIPTION)
        self.assertEqual(d.record["total_credits"], 5.0)

    def test_a_rejected_key_and_an_outage_are_different_answers(self):
        """An outage recorded as 'your key is bad' sends the operator to rotate a working key."""
        from quaestor.executors import openrouter_auth as auth
        rejected = auth.run_preflight(env={auth.API_KEY_VAR: "bad"},
                                      opener=lambda *_a, **_k: (401, ""))
        self.assertEqual(rejected.reason, auth.REASON_KEY_REJECTED)
        self.assertEqual(rejected.auth_class, cp_mod.LOGGED_OUT)

        def _boom(*_a, **_k):
            raise OSError("network unreachable")

        outage = auth.run_preflight(env={auth.API_KEY_VAR: "good"}, opener=_boom)
        self.assertEqual(outage.reason, auth.REASON_UNREACHABLE)
        self.assertEqual(outage.auth_class, cp_mod.UNVERIFIED)

    def test_the_key_value_never_appears_in_the_record(self):
        from quaestor.executors import openrouter_auth as auth
        secret = "sk-or-v1-SUPERSECRETVALUE"
        d = auth.run_preflight(env={auth.API_KEY_VAR: secret},
                               opener=lambda *_a, **_k: (200, "{}"))
        self.assertNotIn(secret, json.dumps(d.record))
        self.assertNotIn(secret, json.dumps([d.decision, d.reason, d.detail, d.auth_class]))
        self.assertTrue(d.record["key_present"])

    def test_credit_facts_are_an_allowlist_not_a_passthrough(self):
        """A future field on that endpoint must not reach a durable record because nobody
        thought about it."""
        from quaestor.executors import openrouter_auth as auth
        facts = auth._credit_facts(json.dumps(
            {"data": {"total_credits": 1.0, "secret_internal_id": "abc", "email": "x@y.z"}}))
        self.assertEqual(facts, {"total_credits": 1.0})
        self.assertEqual(auth._credit_facts("not json"), {})
        self.assertEqual(auth._credit_facts(""), {})


class TestOpenRouterExecutor(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="quaestor-or-")

    def _run(self, opener, *, key="sk-or-v1-test", model="openai/gpt-5"):
        from quaestor.executors.openrouter import OpenRouterExecutor
        ex = OpenRouterExecutor(model=model, opener=opener,
                                env={"OPENROUTER_API_KEY": key} if key else {})
        return ex.execute(_Req(self.d)), ex

    def _stdout(self):
        with open(os.path.join(self.d, "stdout.txt"), encoding="utf-8") as fh:
            return fh.read()

    def _command(self):
        with open(os.path.join(self.d, "command.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_a_completion_becomes_an_envelope_parse_envelope_can_read(self):
        from quaestor.core import executor_contract as ec
        out, _ex = self._run(lambda *_a, **_k: (200, _completion("Raise ValueError.")))
        self.assertTrue(out.started)
        self.assertEqual(out.exit_class, ec.EXIT_OK)
        envelope, _source = ec.parse_envelope(self._stdout())[:2]
        self.assertIsInstance(envelope, dict)
        self.assertEqual(envelope.get("result"), "Raise ValueError.")
        self.assertFalse(envelope.get("is_error"))

    def test_usage_survives_so_the_cost_surfaces_see_this_provider(self):
        out, _ex = self._run(lambda *_a, **_k: (200, _completion()))
        self.assertEqual(out.exit_class, ec.EXIT_OK)
        envelope = json.loads(self._stdout())
        self.assertEqual(envelope["usage"]["total_tokens"], 13)
        self.assertEqual(envelope["usage"]["cost"], 0.0004)

    def test_the_raw_response_is_kept_beside_the_translation(self):
        """The envelope is a TRANSLATION, not a measurement. If it is ever wrong, the original
        has to be on disk to prove it."""
        self._run(lambda *_a, **_k: (200, _completion("hi")))
        with open(os.path.join(self.d, "response.json"), encoding="utf-8") as fh:
            raw = json.load(fh)
        self.assertEqual(raw["choices"][0]["message"]["content"], "hi")

    def test_a_provider_refusal_is_a_measured_outcome_not_a_spawn_failure(self):
        """Getting this backwards makes every rate limit look like a broken installation."""
        out, _ex = self._run(lambda *_a, **_k: (429, '{"error":{"message":"rate limited"}}'))
        self.assertTrue(out.started, "a request that HAPPENED was reported as never started")
        self.assertEqual(out.exit_class, ec.EXIT_NONZERO)
        self.assertEqual(out.exit_code, 429)
        with open(os.path.join(self.d, "stderr.txt"), encoding="utf-8") as fh:
            self.assertIn("429", fh.read())

    def test_a_request_that_never_happened_is_a_spawn_failure(self):
        def _boom(*_a, **_k):
            raise OSError("no route to host")
        out, _ex = self._run(_boom)
        self.assertFalse(out.started,
                         "a run that never started must not reconcile as one that produced "
                         "nothing")
        self.assertEqual(out.exit_class, ec.EXIT_SPAWN_FAILED)

    def test_a_timeout_is_named_as_one(self):
        def _slow(*_a, **_k):
            raise TimeoutError("too slow")
        out, _ex = self._run(_slow)
        self.assertEqual(out.exit_class, ec.EXIT_TIMEOUT)

    def test_an_absent_key_refuses_before_any_request(self):
        called = {"n": 0}

        def _never(*_a, **_k):
            called["n"] += 1
            return (200, _completion())

        out, _ex = self._run(_never, key="")
        self.assertEqual(called["n"], 0)
        self.assertEqual(out.exit_class, ec.EXIT_SPAWN_FAILED)

    def test_the_key_never_reaches_disk(self):
        secret = "sk-or-v1-DONOTLEAKME"
        self._run(lambda *_a, **_k: (200, _completion()), key=secret)
        for name in ("command.json", "stdout.txt", "stderr.txt", "response.json"):
            path = os.path.join(self.d, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    self.assertNotIn(secret, fh.read(), name)
        self.assertTrue(self._command()["key_present"])

    def test_the_prompt_travels_in_the_body_never_a_url(self):
        """A query string is logged by every proxy between here and the provider, and the
        prompt carries the whole task."""
        seen = {}

        def _capture(url, headers, body, timeout):
            seen["url"] = url
            seen["body"] = json.loads(body.decode("utf-8"))
            return (200, _completion())

        self._run(_capture)
        self.assertNotIn("do the thing", seen["url"])
        self.assertEqual(seen["body"]["messages"][0]["content"], "do the thing")
        self.assertEqual(self._command()["prompt_location"], "json_body")

    def test_an_unparseable_body_is_a_failed_run_not_a_crash(self):
        out, _ex = self._run(lambda *_a, **_k: (200, "<html>gateway error</html>"))
        self.assertTrue(out.started)
        self.assertEqual(out.exit_class, ec.EXIT_NONZERO)

    def test_an_executor_cannot_be_built_without_a_model(self):
        from quaestor.executors.openrouter import OpenRouterExecutor, OpenRouterMisconfigured
        for bad in ("", "   ", None):
            with self.assertRaises(OpenRouterMisconfigured, msg=repr(bad)):
                OpenRouterExecutor(model=bad)

    def test_the_registry_builds_a_gateway_kind_and_refuses_a_bare_one(self):
        from quaestor.executors import registry as ex_reg
        built = ex_reg.build({"kind": "openrouter:anthropic/claude-opus-4"})
        self.assertEqual(built.name, "openrouter")
        self.assertEqual(built._model, "anthropic/claude-opus-4")
        self.assertIn("openrouter", ex_reg.KNOWN_KINDS)
        with self.assertRaises(ValueError):
            ex_reg.build({"kind": "openrouter"})
        # config.model is the other accepted form, for a spec that names the kind plainly.
        via_cfg = ex_reg.build({"kind": "openrouter", "config": {"model": "openai/gpt-5"}})
        self.assertEqual(via_cfg._model, "openai/gpt-5")

    def test_synthesise_envelope_is_pure_and_total(self):
        from quaestor.executors.openrouter import synthesise_envelope
        for junk in ({}, {"choices": []}, {"choices": [{}]}, {"choices": "no"},
                     {"choices": [{"message": {}}]}):
            env = synthesise_envelope(junk, model="m")
            self.assertEqual(env["type"], "result")
            self.assertEqual(env["result"], "")


class TestVocabularyIsNotRetyped(unittest.TestCase):
    """The exit-class names are core's. Both new executors declared their OWN copies with two
    of the four values CHANGED ("OK" for NORMAL_EXIT, "NONZERO" for NONZERO_EXIT), so they wrote
    exit classes nothing else on the platform recognises -- a run that succeeded reported a
    class no consumer matches."""

    def test_the_executors_use_cores_exit_classes(self):
        from quaestor.executors import openrouter as orx
        from quaestor.executors import chatgpt_web as cwx
        for mod in (orx, cwx):
            self.assertEqual(mod.EXIT_OK, ec.EXIT_OK, mod.__name__)
            self.assertEqual(mod.EXIT_NONZERO, ec.EXIT_NONZERO, mod.__name__)
            self.assertEqual(mod.EXIT_TIMEOUT, ec.EXIT_TIMEOUT, mod.__name__)
            self.assertEqual(mod.EXIT_SPAWN_FAILED, ec.EXIT_SPAWN_FAILED, mod.__name__)
        self.assertEqual(ec.EXIT_OK, "NORMAL_EXIT",
                         "core's vocabulary changed; the executors must follow it, not the "
                         "other way round")

    def test_the_gateway_vocabulary_is_declared_once(self):
        """executors/registry.py retyped ("openrouter",) as a literal, a second copy of the
        frozenset in adapters/registry.py that would not follow when a gateway is added."""
        import ast, os
        p = os.path.join(os.path.dirname(__file__), "..", "src", "quaestor", "executors",
                         "registry.py")
        with open(p, encoding="utf-8") as fh:
            code = ast.unparse(ast.parse(fh.read()))
        self.assertIn("GATEWAY_KINDS", code)
        self.assertNotIn("('openrouter',)", code.replace('"', "'"))


class TestPreflightIsRoutedForEveryShippedProvider(unittest.TestCase):
    """The blanket ACCEPT was written when 'fake' was the only kind that reached it. Every kind
    added since inherited a free pass it was never assessed for -- so an OpenRouter seat with NO
    API KEY reported healthy, which silently defeats the whole honest-credential story."""

    def test_openrouter_is_measured_not_waved_through(self):
        from quaestor.executors import registry as ex_reg
        from quaestor.core import credential_policy as cp
        d = ex_reg.run_preflight("openrouter")
        self.assertNotEqual(d.auth_class, "NOT_APPLICABLE_FAKE_EXECUTOR",
                            "an OpenRouter seat was waved through the fake-executor fallback")
        self.assertIn(d.decision, (cp.ACCEPT, cp.REFUSE))

    def test_a_gateway_form_routes_to_the_same_preflight(self):
        from quaestor.executors import registry as ex_reg
        bare = ex_reg.run_preflight("openrouter")
        gated = ex_reg.run_preflight("openrouter:openai/gpt-5")
        self.assertEqual(bare.reason, gated.reason)

    def test_a_kind_with_no_preflight_refuses_rather_than_reporting_healthy(self):
        from quaestor.executors import registry as ex_reg
        from quaestor.core import credential_policy as cp
        d = ex_reg.run_preflight("claude-container")
        self.assertEqual(d.decision, cp.REFUSE)
        self.assertEqual(d.reason, "NO_PREFLIGHT_FOR_KIND")
        self.assertEqual(d.auth_class, cp.UNVERIFIED)

    def test_the_fake_executor_still_accepts_by_name(self):
        from quaestor.executors import registry as ex_reg
        from quaestor.core import credential_policy as cp
        d = ex_reg.run_preflight("fake")
        self.assertEqual(d.decision, cp.ACCEPT)


class TestGatewayIdentityHasOneChannel(unittest.TestCase):
    def test_a_model_disagreement_between_kind_and_config_is_refused(self):
        """Preferring config.model made a SECOND invisible channel for provider identity: every
        governance function reads the vendor out of the KIND, so a disagreeing config.model
        would be billed and run while the independence checks reasoned about the other one."""
        from quaestor.executors import registry as ex_reg
        with self.assertRaises(ValueError) as caught:
            ex_reg.build({"kind": "openrouter:openai/gpt-5",
                          "config": {"model": "anthropic/claude-opus-4"}})
        self.assertIn("independence", str(caught.exception))

    def test_agreement_and_either_channel_alone_still_build(self):
        from quaestor.executors import registry as ex_reg
        self.assertEqual(ex_reg.build(
            {"kind": "openrouter:openai/gpt-5",
             "config": {"model": "openai/gpt-5"}})._model, "openai/gpt-5")
        self.assertEqual(ex_reg.build(
            {"kind": "openrouter", "config": {"model": "openai/gpt-5"}})._model, "openai/gpt-5")

    def test_a_chain_of_unidentifiable_vendors_is_refused(self):
        """'We cannot tell who this is' is not evidence of independence."""
        d = reg.chain_next("adversarial_review",
                           ["openrouter:brandnew/model-1", "openrouter:alsonew/model-2"],
                           set(), None)
        self.assertEqual(d.refusal, reg.CHAIN_SINGLE_FAMILY)
        self.assertTrue(any("no provider family" in r for r in d.rationale), d.rationale)

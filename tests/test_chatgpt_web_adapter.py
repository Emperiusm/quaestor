"""test_chatgpt_web_adapter -- CONTROLS for the ChatGPT Web seat.

NO TEST HERE OPENS A BROWSER OR TOUCHES THE NETWORK. Every control drives a fake transport or a
fake page module.

WHAT THESE DEFEND
-----------------
This is the least trustworthy component on the platform: it drives someone else's UI, that UI
changes without notice, and unlike every other executor it cannot prove how it was billed. So
these controls do not try to prove it works. They prove it cannot LIE:

    * it cannot hold a writing seat (requirement 6, enforced by the routing table);
    * it cannot claim a billing path it has no evidence for;
    * it cannot return a partial answer as a result;
    * it cannot fail silently -- every failure is a distinct named outcome, and none is retried;
    * it cannot start a browser or touch a credential.
"""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quaestor.adapters import registry as reg  # noqa: E402
from quaestor.core import credential_policy as cp  # noqa: E402
from quaestor.core import executor_contract as ec  # noqa: E402
from quaestor.executors import browser_transport as bt  # noqa: E402
from quaestor.executors import chatgpt_web as cwx  # noqa: E402
from quaestor.executors import chatgpt_web_auth as cwa  # noqa: E402
from quaestor.executors import chatgpt_web_page as cwp  # noqa: E402

KIND = "chatgpt-web"


class _Req:
    """Minimal ExecRequest stand-in: the executor uses only these fields."""

    def __init__(self, run_dir, prompt="the strategist packet", timeout_s=30.0):
        self.run_dir = run_dir
        self.stdout_path = os.path.join(run_dir, "stdout.txt")
        self.stderr_path = os.path.join(run_dir, "stderr.txt")
        self.prompt = prompt
        self.timeout_s = timeout_s
        self.cwd = run_dir
        self.env = None


class FakePage:
    """A page-module double. Substituted wholesale so no browser is involved."""

    STATE_COMPLETE = cwp.STATE_COMPLETE
    STATE_TIMEOUT = cwp.STATE_TIMEOUT
    STATE_NO_ANSWER = cwp.STATE_NO_ANSWER
    STATE_LOGGED_OUT = cwp.STATE_LOGGED_OUT
    STATE_NO_COMPOSER = cwp.STATE_NO_COMPOSER
    CHATGPT_ORIGIN = cwp.CHATGPT_ORIGIN
    NEW_CONVERSATION_URL = cwp.NEW_CONVERSATION_URL
    conversation_id = staticmethod(cwp.conversation_id)

    def __init__(self, *, submit_ok=True, submit_reason="", result=None, settled_id=""):
        self.submit_ok = submit_ok
        self.submit_reason = submit_reason
        self.result = result or {}
        self.submitted = []
        self.await_kwargs = None
        self.settled_id = settled_id

    BASELINE = 2

    def submit(self, _transport, text):
        self.submitted.append(text)
        return self.submit_ok, self.submit_reason, self.BASELINE

    def await_completion(self, _transport, **kw):
        # RECORDED, NOT SWALLOWED. Accepting **_kw and ignoring it meant no control pinned that
        # the executor threads the MEASURED pre-submit baseline through -- and await_completion
        # declares baseline keyword-only with no default, so dropping it is a TypeError on every
        # real run that no test would have caught.
        self.await_kwargs = dict(kw)
        return dict(self.result)

    def probe(self, _transport):
        # Enough for the settle step: on the target thread, composer up, count still.
        return {"href": "https://chatgpt.com/c/" + (self.settled_id or ""),
                "composer": True, "stop": False, "login": False, "error": False,
                "count": self.BASELINE, "text": ""}

    def classify(self, snap):
        return cwp.classify(snap)


class FakeTransport:
    def __init__(self):
        self.visited = []
        self.closed = False

    def goto(self, url):
        self.visited.append(url)

    def evaluate(self, _expr):
        return {}

    def url(self):
        return "https://chatgpt.com/c/landed-id"

    def close(self):
        self.closed = True


# =============================================================================================
# The seat ceiling -- requirement 6
# =============================================================================================
class TestSeatCeiling(unittest.TestCase):
    def test_the_kind_is_non_write_capable_and_permanently_unproven(self):
        row = reg.PROVIDER_REGISTRY[KIND]
        self.assertFalse(row["write_capable"],
                         "a transport that could hold a writing seat has repo authority "
                         "whatever its docstring says")
        self.assertEqual(row["fact_status"], "declared",
                         "a browser session cannot produce the evidence 'buildable' asserts")
        self.assertEqual(row["provider_family"], "openai")

    def test_it_can_never_be_seated_where_a_repository_is_touched(self):
        """REWRITTEN, AND IT FOUND A REAL HOLE. The previous version proved the ceiling only by
        passing {"write_capable": True} ITSELF -- a constraint no production caller supplies.
        The one production call of resolve_seat passes {}, and the DISPATCH path does not call
        resolve_seat at all: it goes through _resolve_executor -> _seat_spec, which checked only
        is_declared. So a manifest hand-pinning this transport to `implementation` reached
        dispatch unchecked, and requirement 6 held for the seat-picker but not for the path that
        actually runs things.

        This drives the production path with nothing but a manifest pin."""
        from quaestor.core import orchestrator as orch
        for seat in ("implementation", "integration"):
            spec, source = orch._resolve_executor(
                "fake", {"executor": {}}, role_kind=seat, role_executor={seat: KIND})
            self.assertEqual(spec.get("refusal"), reg.SEAT_UNRESOLVABLE,
                             "%s accepted a non-write-capable transport on the DISPATCH path"
                             % seat)
            self.assertTrue(any("non-write-capable" in r for r in spec.get("rationale") or ()),
                            spec)
            self.assertTrue(source.endswith("-refused"), source)

    def test_a_write_capable_provider_still_takes_a_building_seat(self):
        """The ceiling must refuse transports, not everyone."""
        from quaestor.core import orchestrator as orch
        spec, _src = orch._resolve_executor(
            "fake", {"executor": {}}, role_kind="implementation",
            role_executor={"implementation": "claude-cli"})
        self.assertEqual(spec.get("kind"), "claude-cli", spec)
        self.assertIsNone(spec.get("refusal"))

    def test_it_resolves_for_the_reading_seats_it_exists_to_hold(self):
        for seat in ("strategist", "planner", "adversarial_review", "verification"):
            d = reg.resolve_seat(seat, {}, {seat: KIND})
            self.assertEqual(d.kind, KIND, "%s: %s" % (seat, d.rationale))

    def test_it_collides_with_openai_for_cross_vendor_independence(self):
        """It IS OpenAI. A GPT implementation reviewed through a ChatGPT tab is one vendor
        reviewing itself, and the browser is a transport detail, not a second opinion."""
        ctx = {"require_distinct_between": [("implementation", "adversarial_review")]}
        self.assertEqual(reg.check_pairing(ctx, "implementation", "codex-cli",
                                           "adversarial_review", KIND),
                         reg.EPISTEMIC_INDEPENDENCE_UNMET)
        self.assertEqual(reg.check_pairing(ctx, "implementation", "claude-cli",
                                           "adversarial_review", KIND), "")


# =============================================================================================
# The preflight -- what it refuses to claim
# =============================================================================================
class TestPreflight(unittest.TestCase):
    LIVE = {"href": "https://chatgpt.com/c/abc", "composer": True, "stop": False,
            "login": False, "count": 1, "text": ""}

    def test_a_working_session_is_accepted_and_STILL_unverified(self):
        """Not in tension: the seat can run, and what it cannot do is prove how it was billed."""
        d = cwa.run_preflight(probe=lambda: dict(self.LIVE))
        self.assertTrue(d.accepted)
        self.assertEqual(d.auth_class, cp.UNVERIFIED)
        self.assertNotEqual(d.auth_class, cp.SUBSCRIPTION)
        self.assertIn("UNVERIFIED", d.detail)

    def test_it_never_reports_subscription_under_any_page_state(self):
        """The consequence that makes the refusal real: a deployment enforcing
        credential_modes={'subscription'} gets no proof from this seat."""
        for snap in (self.LIVE, {"login": True}, {"composer": False}, {}, None):
            d = cwa.run_preflight(probe=lambda s=snap: s)
            self.assertNotEqual(d.auth_class, cp.SUBSCRIPTION, repr(snap))

    def test_signed_out_and_rotted_selectors_are_different_answers(self):
        """Reporting the downstream symptom sends an operator hunting a selector change that
        never happened."""
        out = cwa.run_preflight(probe=lambda: {"login": True, "composer": False})
        self.assertEqual(out.reason, cwa.REASON_SIGNED_OUT)
        rot = cwa.run_preflight(probe=lambda: {"composer": False, "login": False})
        self.assertEqual(rot.reason, cwa.REASON_PAGE_UNREADABLE)

    def test_no_browser_is_its_own_named_refusal(self):
        self.assertEqual(cwa.run_preflight(probe=lambda: {}).reason, cwa.REASON_NOT_ATTACHED)

    def test_a_probe_that_throws_is_a_refusal_not_a_crash(self):
        def _boom():
            raise OSError("no browser")
        self.assertFalse(cwa.run_preflight(probe=_boom).accepted)

    def test_the_conversation_id_is_reported_when_there_is_one(self):
        d = cwa.run_preflight(probe=lambda: dict(self.LIVE))
        self.assertEqual(d.record["conversation_id"], "abc")


# =============================================================================================
# The executor
# =============================================================================================
class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="quaestor-cw-")

    def _run(self, page, *, conversation_id="", transport=None):
        t = transport or FakeTransport()
        ex = cwx.ChatGptWebExecutor(
            conversation_id=conversation_id, page=page,
            open_transport=lambda **_k: (t, "cdp: test"))
        return ex.execute(_Req(self.d)), t

    def _read(self, name):
        path = os.path.join(self.d, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_a_completed_answer_becomes_a_readable_envelope(self):
        from quaestor.core import executor_contract as ec
        page = FakePage(result={"state": cwp.STATE_COMPLETE, "text": "Raise ValueError.",
                                "polls": 5, "elapsed": 4.0,
                                "snapshot": {"href": "https://chatgpt.com/c/landed-id"}})
        out, _t = self._run(page)
        self.assertEqual(out.exit_class, ec.EXIT_OK)
        envelope, _src = ec.parse_envelope(self._read("stdout.txt"))[:2]
        self.assertEqual(envelope["result"], "Raise ValueError.")
        self.assertFalse(envelope["is_error"])

    def test_a_TIMEOUT_writes_the_partial_as_evidence_and_leaves_stdout_empty(self):
        """A partial capture is never a result. Nothing downstream may mistake it for one."""
        page = FakePage(result={"state": cwp.STATE_TIMEOUT, "text": "", "partial": "half an ans",
                                "polls": 30, "elapsed": 30.0, "snapshot": {}})
        out, _t = self._run(page)
        self.assertEqual(out.exit_class, ec.EXIT_TIMEOUT)
        self.assertEqual(self._read("stdout.txt"), "")
        self.assertEqual(self._read("partial.txt"), "half an ans")
        self.assertIn("TIMEOUT", self._read("stderr.txt"))

    def test_a_signed_out_page_is_a_started_run_that_failed_not_a_spawn_failure(self):
        """The page WAS reached and refused. A run that never started must not reconcile the
        same way as one that started and produced nothing."""
        page = FakePage(submit_ok=False, submit_reason=cwp.STATE_LOGGED_OUT)
        out, _t = self._run(page)
        self.assertTrue(out.started)
        self.assertEqual(out.exit_class, ec.EXIT_NONZERO)
        self.assertIn("LOGGED_OUT", self._read("stderr.txt"))

    def test_no_attachable_browser_is_a_spawn_failure_that_never_started(self):
        page = FakePage()

        def _no_browser(**_k):
            raise bt.BrowserUnavailable(bt.BROWSER_NOT_ATTACHED, "connection refused")

        ex = cwx.ChatGptWebExecutor(page=page, open_transport=_no_browser)
        out = ex.execute(_Req(self.d))
        self.assertFalse(out.started)
        self.assertEqual(out.exit_class, ec.EXIT_SPAWN_FAILED)
        self.assertIn("BROWSER_NOT_ATTACHED", self._read("stderr.txt"))
        self.assertEqual(page.submitted, [], "a packet was typed with no browser attached")

    def test_a_bound_conversation_is_resumed_and_an_unbound_one_starts_fresh(self):
        """Requirement 5: one conversation per program, so the thread keeps its context."""
        page = FakePage(result={"state": cwp.STATE_COMPLETE, "text": "ok", "polls": 3,
                                "elapsed": 1.0,
                                "snapshot": {"href": "https://chatgpt.com/c/bound-id"}})
        page.settled_id = "bound-id"
        _out, t = self._run(page, conversation_id="bound-id")
        self.assertEqual(t.visited, ["https://chatgpt.com/c/bound-id"])

        self.d = tempfile.mkdtemp(prefix="quaestor-cw2-")
        _out, t2 = self._run(page)
        self.assertEqual(t2.visited, [cwp.NEW_CONVERSATION_URL])

    def test_the_landed_conversation_id_is_reported_so_it_can_be_bound(self):
        """The executor writes no program state -- an executor reaching into the strategic
        store would be a second writer of it -- so it REPORTS the id instead."""
        page = FakePage(result={"state": cwp.STATE_COMPLETE, "text": "ok", "polls": 3,
                                "elapsed": 1.0,
                                "snapshot": {"href": "https://chatgpt.com/c/fresh-id"}})
        _out, _t = self._run(page)
        doc = json.loads(self._read("conversation.json"))
        self.assertEqual(doc["conversation_id"], "fresh-id")
        self.assertFalse(doc["bound_on_entry"])
        self.assertEqual(json.loads(self._read("stdout.txt"))["conversation_id"], "fresh-id")

    def test_nothing_is_retried_after_a_refusal(self):
        """A retry loop against a UI that just refused you is how an account gets flagged."""
        refused = FakePage(submit_ok=False, submit_reason=cwp.STATE_LOGGED_OUT)
        self._run(refused)
        self.assertEqual(len(refused.submitted), 1,
                         "the seat tried more than once against a page that refused it")
        timed_out = FakePage(result={"state": cwp.STATE_TIMEOUT, "text": "", "partial": "x",
                                     "polls": 9, "elapsed": 9.0, "snapshot": {}})
        self._run(timed_out)
        self.assertEqual(len(timed_out.submitted), 1, "the seat re-submitted after a timeout")

    def test_the_transport_is_always_closed(self):
        page = FakePage(submit_ok=False, submit_reason=cwp.STATE_NO_COMPOSER)
        _out, t = self._run(page)
        self.assertTrue(t.closed, "a failed turn leaked a browser connection")

    def test_command_json_records_what_it_does_not_do(self):
        page = FakePage(result={"state": cwp.STATE_COMPLETE, "text": "ok", "polls": 1,
                                "elapsed": 1.0, "snapshot": {}})
        self._run(page)
        doc = json.loads(self._read("command.json"))
        self.assertFalse(doc["launches_browser"])
        self.assertFalse(doc["handles_credential"])
        self.assertEqual(doc["prompt_location"], "page_composer")

    def test_the_envelope_carries_no_invented_usage(self):
        """A browser session reports no token counts, and zeros would make the cost surfaces
        show a confident 0.00 for a seat that genuinely cost something."""
        env = cwx.synthesise_envelope("hi", conversation_id="c", transport="cdp")
        self.assertNotIn("usage", env)


class TestRegistration(unittest.TestCase):
    def test_the_registry_builds_it_without_a_browser_or_a_credential(self):
        """Construction must not need an attached browser: a missing browser is a named RUN
        outcome, not a broken installation."""
        from quaestor.executors import registry as ex_reg
        self.assertIn(KIND, ex_reg.KNOWN_KINDS)
        built = ex_reg.build({"kind": KIND, "config": {"conversation_id": "abc",
                                                       "transport": "cdp"}})
        self.assertEqual(built.name, KIND)
        self.assertEqual(built._conversation_id, "abc")
        self.assertEqual(ex_reg.build({"kind": KIND}).name, KIND)

    def test_the_seat_modules_contain_no_detection_evasion(self):
        """Read as CODE, not prose: a grep cannot tell an implementation from the sentence
        explaining there is no implementation."""
        import ast
        here = os.path.join(os.path.dirname(__file__), "..", "src", "quaestor", "executors")
        for name in ("chatgpt_web.py", "chatgpt_web_page.py", "chatgpt_web_auth.py"):
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if (isinstance(body, list) and body and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)):
                    node.body = body[1:] or [ast.Pass()]
            code = ast.unparse(tree).lower()
            for needle in ("stealth", "undetected", "webdriver", "captcha", "spoof",
                           "useragent", "user_agent", "proxy_rotat"):
                self.assertNotIn(needle, code, "%s implements %r" % (name, needle))


class TestBaselineIsTakenAgainstTheLoadedConversation(unittest.TestCase):
    """Page.navigate returns as soon as navigation is INITIATED, and Playwright's goto waits
    only for 'load' while ChatGPT fetches the message list after mount. Taking the baseline
    immediately counted whatever was on screen a moment ago -- so a PRE-EXISTING assistant turn
    could satisfy 'a new message appeared' and its stale text be captured as this turn's answer.
    """

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="quaestor-baseline-")

    def test_the_measured_baseline_is_threaded_into_await_completion(self):
        page = FakePage(result={"state": cwp.STATE_COMPLETE, "text": "ok", "polls": 1,
                                "elapsed": 1.0, "snapshot": {}})
        ex = cwx.ChatGptWebExecutor(page=page,
                                    open_transport=lambda **_k: (FakeTransport(), "cdp: test"))
        ex.execute(_Req(self.d))
        self.assertIsNotNone(page.await_kwargs, "await_completion was never called")
        self.assertEqual(page.await_kwargs.get("baseline"), FakePage.BASELINE,
                         "the pre-submit baseline was not threaded through; await_completion "
                         "declares it keyword-only with no default, so this is a TypeError on "
                         "every real run")

    def test_a_conversation_that_never_settles_refuses_and_never_submits(self):
        """Refusing beats guessing: submitting into a page that is still loading is how a stale
        answer gets captured as this turn's result."""
        class _NeverSettles(FakePage):
            def probe(self, _transport):
                self._n = getattr(self, "_n", 0) + 1
                return {"href": "https://chatgpt.com/c/other-thread", "composer": True,
                        "stop": False, "login": False, "error": False,
                        "count": self._n, "text": ""}

        page = _NeverSettles(result={"state": cwp.STATE_COMPLETE, "text": "stale"})
        ex = cwx.ChatGptWebExecutor(conversation_id="wanted-id", page=page,
                                    open_transport=lambda **_k: (FakeTransport(), "cdp: t"))
        out = ex.execute(_Req(self.d, timeout_s=3.0))
        self.assertTrue(out.started)
        self.assertEqual(out.exit_class, ec.EXIT_NONZERO)
        self.assertEqual(page.submitted, [],
                         "a packet was typed into a page that never became the target thread")


class TestAbortedStreamIsNotCompletion(unittest.TestCase):
    """A stream that dies mid-token removes the stop affordance and stops mutating its text --
    from the affordances alone that is indistinguishable from finishing. Best-effort detection
    plus an honestly stated residual limit."""

    def test_an_error_affordance_beside_a_stopped_stream_is_not_complete(self):
        snap = {"composer": True, "stop": False, "error": True, "login": False,
                "count": 2, "text": "half an ans"}
        self.assertEqual(cwp.classify(snap), cwp.STATE_STREAM_ERROR)

    def test_an_error_affordance_during_generation_does_not_abort_a_healthy_run(self):
        """The retry affordance can sit beside an EARLIER turn while a new one streams; calling
        that an error would kill a run that is working."""
        snap = {"composer": True, "stop": True, "error": True, "login": False,
                "count": 2, "text": "still going"}
        self.assertEqual(cwp.classify(snap), cwp.STATE_GENERATING)

    def test_a_stream_error_returns_no_text_only_a_partial(self):
        page = FakePage(result={"state": cwp.STATE_STREAM_ERROR, "text": "",
                                "partial": "half an ans", "polls": 4, "elapsed": 4.0,
                                "snapshot": {}})
        d = tempfile.mkdtemp(prefix="quaestor-abort-")
        ex = cwx.ChatGptWebExecutor(page=page,
                                    open_transport=lambda **_k: (FakeTransport(), "cdp: t"))
        out = ex.execute(_Req(d))
        self.assertNotEqual(out.exit_class, ec.EXIT_OK)
        with open(os.path.join(d, "stdout.txt"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "")

    def test_the_residual_limit_is_stated_rather_than_papered_over(self):
        """An undetectable truncation is caught downstream, by the seat's response having to be
        one parseable JSON document. The module must SAY that rather than imply the DOM check
        is stronger than it is."""
        import quaestor.executors.chatgpt_web_page as m
        doc = (m.STATE_STREAM_ERROR.__doc__ or "") + m.__doc__
        source = io.open(m.__file__, encoding="utf-8").read()
        self.assertIn("BEST EFFORT", source)
        self.assertIn("validate_directive_response", source)

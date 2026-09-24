"""test_relay_chatgpt_end -- controls 264-272 for the ChatGPT Web OrchestratorEnd.

NO TEST HERE OPENS A BROWSER OR TOUCHES THE NETWORK. Every control drives a fake transport whose
``evaluate`` answers the endpoint's own JavaScript from a scripted page model.

WHY THESE PARTICULAR CONTROLS
------------------------------
Four of them exist because a REAL signed-in page found the defect first, and the unit suite could
not have. The old controls fed ``classify`` a synthetic ``error`` boolean, so no test could ever
have noticed that the selector computing that boolean matched an always-present accessibility
scaffold on every healthy page. The lesson is encoded here as controls over the MEASUREMENT --
the probe JavaScript and the id parsing -- not just over the classifier that consumes it:

    265  the empty aria live region is not an error          (live: every run aborted at poll 1)
    266  the optimistic client-side conversation id          (live: bound a URL that never exists)
    267  resume must not call a new thread a resumed one     (found by review, provable here)
    269  a generating turn is incomplete, never partial text
    272  the in-page hash and its Python twin agree          (live: verified against real V8)

The remaining controls pin the contract itself, so a future edit cannot quietly make the endpoint
claim more than it proves.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.controls import control  # noqa: E402

from quaestor.executors import browser_transport as bt  # noqa: E402
from quaestor.executors import chatgpt_web_page as cwp  # noqa: E402
from quaestor.relay import registry as relay_registry  # noqa: E402
from quaestor.relay.contracts import (END_BUSY, END_NOT_AUTHENTICATED,  # noqa: E402
                                      END_UNREACHABLE, RESUME_LOST, RESUME_RESUMED)
from quaestor.relay.ends import chatgpt_web as cwe  # noqa: E402

CONV = "6a93a92d-2c20-83ea-a624-2f8e7806e08d"
OTHER = "11111111-2222-3333-4444-555555555555"
#: The OPTIMISTIC id the live page shows before the server assigns the real one. Copied verbatim
#: from the measurement, not invented.
OPTIMISTIC = "WEB:6cace67f-d164-4fed-9bc6-84acdac59d12"


class PageModel:
    """A scripted ChatGPT page, answering the endpoint's real JavaScript.

    Deliberately models TURNS rather than canned probe dicts: the endpoint computes identity and
    completion from the same page, so a double that answered the two independently could satisfy
    both with a state the page could never actually be in.
    """

    def __init__(self, *, href="https://chatgpt.com/", turns=None, stop=False, login=False,
                 composer=True, error_button=False, alert_text="", native_ids=True,
                 window=0, salt=""):
        #: ``window`` models the live site's VIRTUALISED list: only the newest N turns are
        #: rendered, so the assistant count PLATEAUS. Zero means "render everything".
        self.href = href
        self.turns = list(turns or [])          # [(role, text)]
        self.stop = stop
        self.login = login
        self.composer = composer
        self.error_button = error_button
        self.alert_text = alert_text            # the aria live region's CONTENT
        self.native_ids = native_ids
        self.window = int(window or 0)
        # PER-PAGE SALT. Real per-message ids are UUIDs and are unique across every thread; a
        # purely positional double lets turn 1 of one conversation collide with turn 1 of
        # another, which would let a control pass for a reason production could never have.
        self.salt = str(salt or ("s%d" % (id(self) % 9973)))
        self.submitted = []

    def _mid(self, index: int) -> str:
        return "mid-%s-%d" % (self.salt, index) if self.native_ids else ""

    # -- what the page would report -------------------------------------------------------------
    def _assistants(self):
        return [t for t in self.turns if t[0] == "assistant"]

    def _rendered(self):
        """The slice of the thread actually in the DOM, as (absolute_index, role, text).

        PROBE_JS queries the DOCUMENT, so it can only ever see what is rendered. Modelling the
        window here rather than in one accessor is what makes the count plateau realistically --
        and the plateau is the whole defect under test.
        """
        shown = self.turns[-self.window:] if self.window else self.turns
        base = len(self.turns) - len(shown)
        return [(base + i, r, t) for i, (r, t) in enumerate(shown)]

    def probe_dict(self) -> dict:
        rendered = self._rendered()
        assistants = [(i, r, t) for (i, r, t) in rendered if r == "assistant"]
        last = assistants[-1] if assistants else None
        return {
            "href": self.href, "composer": bool(self.composer), "send": True,
            "stop": bool(self.stop), "login": bool(self.login),
            # THE FIX UNDER TEST: a button counts by presence; alert text counts only when
            # non-empty. An empty live region must NOT read as an error.
            "error": bool(self.error_button) or bool(self.alert_text.strip()),
            # ONLY WHAT IS RENDERED, like the real querySelectorAll.
            "count": len(assistants),
            "text": last[2] if last else "",
            # THE LAST ASSISTANT TURN'S id -- what PROBE_JS actually reads. Deriving it from the
            # last turn of ANY role made a user message look like a new answer, which is exactly
            # the staleness this endpoint exists to prevent.
            "last_id": self._mid(last[0]) if last else "",
        }

    def turns_dict(self) -> dict:
        return {"href": self.href,
                "turns": [{"index": i, "role": r, "id": self._mid(i),
                           "key": cwp.text_key(t), "len": len(t)}
                          for (i, r, t) in self._rendered()]}

    def last_user_id(self) -> str:
        """What LAST_USER_ID_JS returns: the page's id for the newest RENDERED user turn."""
        for idx, role, _text in reversed(self._rendered()):
            if role == "user":
                return self._mid(idx)
        return ""

    def reply_dict(self, want_key: str, want_id: str = "") -> dict:
        """What REPLY_JS returns: the first assistant turn AFTER the user turn keyed ``want``.

        Modelled from the same rendered window as everything else, so a user turn that has
        scrolled out is genuinely invisible here too -- otherwise the double would quietly be
        answering a question the real page cannot.
        """
        rendered = self._rendered()
        ui = -1
        for pos, (idx, role, text) in enumerate(rendered):
            if role != "user":
                continue
            # THE PAGE'S ID WINS, exactly as REPLY_JS does it: the content key cannot be
            # trusted because the renderer does not echo what was typed.
            if want_id:
                if self.native_ids and self._mid(idx) == want_id:
                    ui = pos
            elif cwp.text_key(text) == want_key:
                ui = pos
        ai = -1
        if ui >= 0:
            for pos in range(ui + 1, len(rendered)):
                if rendered[pos][1] == "assistant":
                    ai = pos
                    break
        a = rendered[ai] if ai >= 0 else None
        base = self.probe_dict()
        return {
            "href": self.href, "composer": base["composer"], "login": base["login"],
            "stop": base["stop"], "error": base["error"], "rendered": len(rendered),
            "user_found": ui >= 0, "user_index": rendered[ui][0] if ui >= 0 else -1,
            "assistant_found": ai >= 0,
            "assistant_index": a[0] if a else -1,
            "id": self._mid(a[0]) if a else "",
            "text": a[2] if a else "",
        }


class FakeTransport:
    """Answers whichever of the endpoint's two expressions it is handed."""

    def __init__(self, model: PageModel, *, fail_after: int = -1):
        self.model = model
        self.visited = []
        self.closed = False
        self.evals = 0
        self.fail_after = fail_after

    def goto(self, url):
        self.visited.append(url)

    @staticmethod
    def _trailing_arg(expr: str):
        """The JSON argument a page expression was called with, or None. PURE.

        ``SUBMIT_JS`` is ``((text) => {...})(<json>)``, so the text the endpoint typed is
        recoverable -- which is what lets this double append a REAL user turn rather than a
        placeholder, so the baseline and the content key both come out right.
        """
        cut = expr.rfind("})(")
        if cut < 0:
            return None
        tail = expr[cut + 3:].rstrip()
        if tail.endswith(")"):
            tail = tail[:-1]
        try:
            return json.loads(tail)
        except ValueError:
            return None

    def evaluate(self, expr):
        self.evals += 1
        if 0 <= self.fail_after <= self.evals:
            raise bt.BrowserUnavailable(bt.BROWSER_NOT_ATTACHED, "the tab was closed")
        # Order matters: the three probes all mention selectors, so they are told apart by the
        # keys each is asked to return. The reply probe is checked FIRST because it is the most
        # specific.
        if 'if (!nodes.length) return ""' in expr:          # LAST_USER_ID_JS
            return self.model.last_user_id()
        if "user_found" in expr:                            # REPLY_JS
            k = re.search(r'const want = "([0-9a-f]{8})"', expr)
            i = re.search(r'const wantId = "([^"]*)"', expr)
            return self.model.reply_dict(k.group(1) if k else "",
                                         i.group(1) if i else "")
        if '"turns"' in expr or "turns:" in expr:
            return self.model.turns_dict()
        if "NO_COMPOSER" in expr:                      # SUBMIT_JS: type into the composer
            if not self.model.composer:
                return "NO_COMPOSER"
            self._typed = self._trailing_arg(expr)
            return "OK"
        if "NO_SEND" in expr:                          # SEND_JS: press send
            typed = getattr(self, "_typed", None)
            if typed is not None:
                self.model.turns.append(("user", typed))
            self.model.submitted.append(typed)
            return "OK"
        if "composer:" in expr or "count:" in expr:    # PROBE_JS
            return self.model.probe_dict()
        if expr.strip().startswith("location.href"):
            return self.model.href
        return {}

    def url(self):
        return self.model.href

    def close(self):
        self.closed = True


def _ticking(start: float = 1000.0, step: float = 0.5):
    """A clock that always advances, so a bounded wait is bounded in a control too."""
    state = {"n": float(start)}

    def clock():
        state["n"] += step
        return state["n"]

    return clock


def make_end(model: PageModel, *, conversation_id="", state_path="", fail_after=-1, **kw):
    """An endpoint wired to a scripted page, with a clock that never sleeps."""
    ticks = {"n": 1000.0}

    def clock():
        ticks["n"] += 0.5
        return ticks["n"]

    return cwe.ChatGptWebOrchestratorEnd(
        conversation_id=conversation_id, state_path=state_path,
        open_transport=lambda **_k: (FakeTransport(model, fail_after=fail_after), "cdp: fake"),
        clock=clock, sleep=lambda _s: None, poll_s=0.0, stable_polls=1,
        settle_timeout_s=5.0, **kw)


class TestContract(unittest.TestCase):

    @control(264)
    def test_the_end_satisfies_the_contract_and_the_kernel_stays_provider_neutral(self):
        model = PageModel(href="https://chatgpt.com/c/" + CONV,
                          turns=[("user", "hi"), ("assistant", "hello")])
        end = make_end(model, conversation_id=CONV)
        for name in ("open", "status", "identity", "resume", "send", "receive", "close",
                     "holds"):
            self.assertTrue(callable(getattr(end, name, None)), name)

        # It is reachable ONLY through the registry, and an unknown kind is a named refusal.
        self.assertIn("chatgpt-web", relay_registry.ORCHESTRATOR_KINDS)
        built = relay_registry.build_orchestrator({"kind": "chatgpt-web", "config": {}})
        self.assertIsInstance(built, cwe.ChatGptWebOrchestratorEnd)

        # THE INVERSION BOUNDARY. No relay core module may reach the provider layer, and none
        # may even mention a browser: the kernel must not know its Orchestrator is a web page.
        import ast

        import quaestor.relay.kernel as km
        core = os.path.dirname(km.__file__)
        for mod in ("kernel", "state", "effects", "observe", "packets", "contracts"):
            path = os.path.join(core, mod + ".py")
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            tree = ast.parse(src, path)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported |= {a.name for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            self.assertEqual(
                [n for n in sorted(imported)
                 if n.startswith("quaestor.relay.ends") or n.startswith("quaestor.executors")],
                [], "relay.%s reaches the provider layer" % mod)
            low = src.lower()
            for word in ("chatgpt", "browser", "cdp", "playwright", "selector"):
                self.assertNotIn(word, low,
                                 "relay.%s mentions %r -- the kernel must not know its "
                                 "orchestrator is browser-hosted" % (mod, word))

    @control(270)
    def test_every_broken_state_is_named_and_nothing_raises(self):
        """Signed out, no composer, browser gone: three distinct states, zero exceptions."""
        signed_out = make_end(PageModel(login=True, composer=False))
        self.assertEqual(signed_out.open().state, END_NOT_AUTHENTICATED)
        self.assertEqual(signed_out.status().state, END_NOT_AUTHENTICATED)

        rotted = make_end(PageModel(composer=False))
        self.assertFalse(rotted.open().usable)
        self.assertIn("SELECTORS", rotted.open().detail)

        gone = cwe.ChatGptWebOrchestratorEnd(
            open_transport=lambda **_k: (_ for _ in ()).throw(
                bt.BrowserUnavailable(bt.BROWSER_NOT_ATTACHED, "nothing is listening")),
            clock=lambda: 1.0, sleep=lambda _s: None)
        self.assertEqual(gone.open().state, END_UNREACHABLE)
        self.assertEqual(gone.status().state, END_UNREACHABLE)
        # A send against a dead browser is a refused receipt, not an exception.
        self.assertFalse(gone.send("x", message_id="m").accepted)
        # ...and a receive is an INCOMPLETE turn carrying the reason.
        msg = gone.receive(after_id="", timeout_s=1.0)
        self.assertFalse(msg.complete)
        self.assertTrue(msg.error)
        self.assertEqual(msg.text, "")

        busy = make_end(PageModel(href="https://chatgpt.com/c/" + CONV, stop=True,
                                  turns=[("user", "q"), ("assistant", "part")]),
                        conversation_id=CONV)
        self.assertEqual(busy.status().state, END_BUSY)


class TestMeasurementDefects(unittest.TestCase):
    """The four the live page found."""

    @control(265)
    def test_an_empty_aria_live_region_is_not_an_error(self):
        """MEASURED on the live signed-in site: chatgpt.com renders

            <div aria-live="assertive" class="sr-only"
                 id="aria-notify-live-region-assertive" role="alert"><span></span></div>

        on EVERY page. Treating its presence as an error made ``classify`` return STREAM_ERROR
        for a perfectly healthy conversation, which aborts a relay at the first poll.
        """
        healthy = PageModel(href="https://chatgpt.com/c/" + CONV, alert_text="",
                            turns=[("user", "q"), ("assistant", "a")])
        self.assertFalse(healthy.probe_dict()["error"])
        self.assertEqual(cwp.classify(healthy.probe_dict()), cwp.STATE_COMPLETE)

        # ...and a live region WITH text still is an error, so the fix did not blind the check.
        broken = PageModel(href="https://chatgpt.com/c/" + CONV,
                           alert_text="Something went wrong.",
                           turns=[("user", "q"), ("assistant", "half")])
        self.assertTrue(broken.probe_dict()["error"])
        self.assertEqual(cwp.classify(broken.probe_dict()), cwp.STATE_STREAM_ERROR)

        # The selector table itself must keep the two kinds apart, or the fix is one edit from
        # being undone by someone re-merging the lists.
        self.assertIn("error", cwp.SELECTORS)
        self.assertIn("error_text", cwp.SELECTORS)
        self.assertNotIn("[role='alert']", cwp.SELECTORS["error"])
        self.assertIn("[role='alert']", cwp.SELECTORS["error_text"])
        # And the generated probe must actually consult the text, not merely the presence.
        js = cwp.probe_expression()
        self.assertIn("innerText", js)
        self.assertIn("trim().length > 0", js)

    @control(266)
    def test_the_optimistic_client_side_conversation_id_is_never_bound(self):
        """MEASURED live: submitting a new thread puts ``/c/WEB:<uuid>`` in the URL first and
        replaces it with a DIFFERENT real uuid seconds later. Binding the first produces a
        durable record pointing at a URL that will never exist."""
        self.assertFalse(cwp.is_bindable_conversation_id(OPTIMISTIC))
        self.assertTrue(cwp.is_bindable_conversation_id(CONV))
        for junk in ("", "  ", "new", "c", "WEB:not-a-uuid", CONV + "x"):
            self.assertFalse(cwp.is_bindable_conversation_id(junk), junk)

        opt_url = "https://chatgpt.com/c/" + OPTIMISTIC
        # The Program Mode seat's behaviour is UNCHANGED: it only ever reports what it landed on.
        self.assertEqual(cwp.conversation_id(opt_url), OPTIMISTIC)
        # The relay, which will navigate back here after a crash, refuses it.
        self.assertEqual(cwp.conversation_id(opt_url, bindable_only=True), "")

        # End to end: a send that lands on the optimistic URL binds NOTHING...
        model = PageModel(href=opt_url)
        end = make_end(model)
        receipt = end.send("hello", message_id="m1")
        self.assertTrue(receipt.accepted)
        self.assertEqual(end.identity(), "")
        # ...and the real id is picked up once the URL settles.
        model.href = "https://chatgpt.com/c/" + CONV
        model.turns = [("user", "hello"), ("assistant", "hi")]
        msg = end.receive(after_id=receipt.native_id, timeout_s=5.0)
        self.assertTrue(msg.complete)
        self.assertEqual(end.identity(), CONV)

    @control(267)
    def test_resume_refuses_to_call_a_different_conversation_a_resumed_one(self):
        """A deleted thread redirects to a NEW empty conversation, which opens perfectly well.
        Reporting that as RESUMED fabricates the one property restart-recovery establishes."""
        # The thread is gone: the browser lands on a different conversation.
        end = make_end(PageModel(href="https://chatgpt.com/c/" + OTHER), conversation_id=CONV)
        outcome, detail = end.resume(CONV)
        self.assertEqual(outcome, RESUME_LOST)
        self.assertIn(CONV, detail)

        # Redirected to a brand-new, unbound thread: also LOST, not RESUMED.
        fresh = make_end(PageModel(href="https://chatgpt.com/"), conversation_id=CONV)
        self.assertEqual(fresh.resume(CONV)[0], RESUME_LOST)

        # The real thread IS still there: RESUMED, and honest about where the context lives.
        ok = make_end(PageModel(href="https://chatgpt.com/c/" + CONV,
                                turns=[("user", "q"), ("assistant", "a")]),
                      conversation_id=CONV)
        outcome, detail = ok.resume(CONV)
        self.assertEqual(outcome, RESUME_RESUMED)
        self.assertIn("never in this process", detail)

    @control(272)
    def test_the_in_page_key_and_its_python_twin_agree(self):
        """Verified against real V8 during the live run; pinned here so a change to one half
        cannot silently diverge from the other."""
        for text in ("hello world", "  multi   line\n\ntext  ", "", "   ",
                     "unicode: é—\U0001F600", "a" * 5000, "tabs\tand\r\nnewlines"):
            k = cwp.text_key(text)
            self.assertEqual(len(k), 8)
            self.assertEqual(k, cwp.text_key(cwp.normalise(text)),
                             "the key must be invariant under the normalisation it applies")
        # Whitespace-only and empty must agree, because the page collapses both to nothing.
        self.assertEqual(cwp.text_key(""), cwp.text_key("   \n\t "))
        # Different content must differ (a key that collided would make holds() lie).
        self.assertNotEqual(cwp.text_key("alpha"), cwp.text_key("beta"))
        # The JS twin must still be present and reference the same constants.
        self.assertIn("0x811c9dc5", cwp.TEXT_KEY_JS)
        self.assertIn("0x01000193", cwp.TEXT_KEY_JS)
        self.assertEqual(cwp.FNV_OFFSET, 0x811C9DC5)
        self.assertEqual(cwp.FNV_PRIME, 0x01000193)


class TestStalenessAndCompletion(unittest.TestCase):

    @control(268)
    def test_the_anchor_carries_the_baseline_through_the_ledger(self):
        """The whole staleness defence. ``send`` measures the pre-submit assistant count and
        puts it in the receipt; the kernel persists that and hands it back to ``receive``. An
        in-memory counter would reset to zero on restart and re-read the previous answer."""
        # A thread that ALREADY has an answer in it.
        model = PageModel(href="https://chatgpt.com/c/" + CONV,
                          turns=[("user", "old q"), ("assistant", "OLD ANSWER")])
        end = make_end(model, conversation_id=CONV)
        receipt = end.send("new q", message_id="m1")
        self.assertTrue(receipt.accepted)

        parsed = cwe.parse_anchor(receipt.native_id)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["baseline"], 1, "the pre-submit assistant count")
        self.assertEqual(parsed["conversation_id"], CONV)
        self.assertEqual(parsed["sent_key"], cwp.text_key("new q"))

        # A BRAND NEW PROCESS, given only what the ledger stored, asks the same question.
        reborn = make_end(model, conversation_id=CONV)
        # The page still shows only the OLD answer: nothing newer than the baseline exists,
        # so the reply must NOT be the stale one.
        stale = reborn.receive(after_id=receipt.native_id, timeout_s=1.0)
        self.assertFalse(stale.complete)
        self.assertEqual(stale.text, "")

        # Once the real answer lands, the same anchor accepts it.
        model.turns.append(("user", "new q"))
        model.turns.append(("assistant", "NEW ANSWER"))
        fresh = reborn.receive(after_id=receipt.native_id, timeout_s=5.0)
        self.assertTrue(fresh.complete)
        self.assertEqual(fresh.text, "NEW ANSWER")

        # An anchor from an older scheme degrades honestly rather than crashing.
        junk = cwe.parse_anchor("something-else-entirely")
        self.assertFalse(junk["ok"])
        self.assertEqual(junk["baseline"], 0)

    @control(269)
    def test_a_generating_turn_is_incomplete_and_its_partial_is_never_the_text(self):
        model = PageModel(href="https://chatgpt.com/c/" + CONV, turns=[("user", "earlier"),
                                                                       ("assistant", "done")])
        end = make_end(model, conversation_id=CONV)
        receipt = end.send("diagnose the failure", message_id="m1")
        self.assertTrue(receipt.accepted)
        # The model starts answering and never finishes: stop affordance still up.
        model.turns.append(("assistant", "half an ans"))
        model.stop = True
        msg = end.receive(after_id=receipt.native_id, timeout_s=2.0)
        self.assertFalse(msg.complete)
        self.assertEqual(msg.text, "", "a partial must never arrive as the message text")
        self.assertIn("TIMEOUT", msg.error)
        self.assertIn("partial on screen", msg.error)
        self.assertNotIn("half an ans", msg.text)

        # And a page showing an ERROR affordance beside a stopped stream is also incomplete.
        broken = PageModel(href="https://chatgpt.com/c/" + CONV, turns=[("user", "earlier"),
                                                                        ("assistant", "done")])
        end2 = make_end(broken, conversation_id=CONV)
        r2 = end2.send("try again", message_id="m2")
        broken.turns.append(("assistant", "half"))
        broken.alert_text = "Something went wrong."
        msg2 = end2.receive(after_id=r2.native_id, timeout_s=2.0)
        self.assertFalse(msg2.complete)
        self.assertIn(cwp.STATE_STREAM_ERROR, msg2.error)

        # A turn whose USER message is not on screen at all is a THIRD, distinct state: it says
        # "I cannot see the turn you are asking about", not "the answer never finished".
        absent = make_end(PageModel(href="https://chatgpt.com/c/" + CONV,
                                    turns=[("user", "someone else"), ("assistant", "reply")]),
                          conversation_id=CONV)
        msg3 = absent.receive(
            after_id=cwe.make_anchor(conversation_id=CONV, baseline=0,
                                     sent_key=cwp.text_key("a turn that was never sent")),
            timeout_s=2.0)
        self.assertFalse(msg3.complete)
        self.assertIn(cwp.STATE_USER_TURN_NOT_RENDERED, msg3.error)

    @control(271)
    def test_holds_asks_the_page_and_refuses_when_it_cannot_tell(self):
        """The crash-reconciliation contract: answer from the LIVE thread, or refuse."""
        tmp = tempfile.mkdtemp(prefix="quaestor-cwe-")
        state = os.path.join(tmp, "cw.json")
        sent = "the instruction that was in flight"

        model = PageModel(href="https://chatgpt.com/c/" + CONV, turns=[("user", "earlier")])
        end = make_end(model, conversation_id=CONV, state_path=state)

        receipt = end.send(sent, message_id="m1")
        self.assertTrue(receipt.accepted)
        # The sidecar is written BEFORE the submit, so the key exists to ask with even when the
        # process dies between the two -- which is the case this whole mechanism exists for.
        with open(state, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["deliveries"]["m1"]["key"], cwp.text_key(sent))

        # The delivery LANDED: the page carries the user turn, so the answer is yes -- matched
        # on the content key, read from the live thread rather than from the local record.
        self.assertTrue(end.holds("m1"))
        # A READABLE record that simply does not mention an id IS evidence: never sent.
        self.assertFalse(end.holds("never-sent"))

        # THE CRASH-BEFORE-SUBMIT CASE. The sidecar has the key (written first) but the turn
        # never reached the page. A short, fully rendered thread makes a miss real evidence, so
        # this is a definite NO and the kernel may deliver it exactly once more.
        model.turns = [t for t in model.turns if t[1] != sent]
        self.assertFalse(end.holds("m1"))

        # And once it does land, the same question flips to yes.
        model.turns.append(("user", sent))
        self.assertTrue(end.holds("m1"))

        # A RESTARTED process, reading only the sidecar, asks the same question and agrees.
        reborn = make_end(model, conversation_id=CONV, state_path=state)
        self.assertTrue(reborn.holds("m1"))

        # UNREADABLE PAGE -> REFUSES. The kernel turns this into UNRECONCILABLE_DELIVERY.
        empty = make_end(PageModel(href="https://chatgpt.com/c/" + CONV, turns=[]),
                         conversation_id=CONV, state_path=state)
        with self.assertRaises(RuntimeError) as ctx:
            empty.holds("m1")
        self.assertIn("refusing to guess", str(ctx.exception))

        # THREAD LONGER THAN THE TRUSTED WINDOW -> also refuses. A miss in a virtualised list
        # is not evidence of absence.
        long_thread = PageModel(
            href="https://chatgpt.com/c/" + CONV,
            turns=[("user", "filler %d" % i) for i in range(cwe.TURN_WINDOW_TRUSTED + 5)])
        big = make_end(long_thread, conversation_id=CONV, state_path=state)
        with self.assertRaises(RuntimeError) as ctx2:
            big.holds("m1")
        self.assertIn("virtualised", str(ctx2.exception))


class TestHonesty(unittest.TestCase):

    def test_it_claims_no_lifecycle_no_billing_and_no_repo_reach(self):
        end = make_end(PageModel())
        f = end.facts
        self.assertFalse(f.manages_lifecycle, "the browser is the operator's")
        self.assertFalse(f.can_mutate_repo, "an orchestrator does not touch the repository")
        self.assertFalse(f.proves_confinement)
        self.assertTrue(f.supports_conversation_resume, "the thread lives at the vendor")
        self.assertFalse(f.supports_session_resume)
        self.assertEqual(f.provider_family, "openai")
        joined = " ".join(f.limits).lower()
        for needed in ("never launches", "never handles the credential", "unverified",
                       "virtualised"):
            self.assertIn(needed, joined, needed)

    def test_it_never_launches_a_browser_or_evades_detection(self):
        with open(cwe.__file__, encoding="utf-8") as fh:
            src = fh.read().lower()
        for needle in ("stealth", "undetected", "webdriver", "captcha", "spoof",
                       "user_agent", "useragent", "subprocess", "webbrowser"):
            self.assertNotIn(needle, src, needle)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class TestVirtualisedThread(unittest.TestCase):
    """The defect that stalled the first live end-to-end run.

    MEASURED 2026-08-30: a ChatGPT conversation with six user turns rendered only the most
    recent three. The DOM is a WINDOW, not the thread. Two things break if that is ignored, and
    both are silent.
    """

    @control(274)
    def test_a_new_answer_is_seen_even_though_the_count_plateaus(self):
        """``count > baseline`` can NEVER become true once the window is full, so a relay that
        tested only the count waited out its whole timeout with the answer on screen."""
        # A thread already at its render window: 3 assistant turns visible, and it stays 3.
        model = PageModel(href="https://chatgpt.com/c/" + CONV, window=6,
                          turns=[("user", "u%d" % i) if i % 2 == 0 else ("assistant", "a%d" % i)
                                 for i in range(6)])
        end = make_end(model, conversation_id=CONV)
        before = model.probe_dict()
        receipt = end.send("the next instruction", message_id="m1")
        self.assertTrue(receipt.accepted)

        anchor = cwe.parse_anchor(receipt.native_id)
        self.assertTrue(anchor["prior_id"], "the anchor must carry the last assistant id")
        self.assertEqual(anchor["prior_id"], before["last_id"])

        # The answer arrives. The window slides, so the assistant COUNT DOES NOT RISE...
        model.turns.append(("assistant", "THE NEW ANSWER"))
        after = model.probe_dict()
        self.assertLessEqual(after["count"], anchor["baseline"],
                             "this control is vacuous unless the count really does plateau")
        # ...and yet the turn is recognised, because identity moved even though the count did not.
        msg = end.receive(after_id=receipt.native_id, timeout_s=5.0)
        self.assertTrue(msg.complete, "a new answer on a virtualised thread must be seen")
        self.assertEqual(msg.text, "THE NEW ANSWER")
        self.assertEqual(msg.provenance["anchored_by"], "user_turn_id",
                         "the reply must be located from OUR user turn, not from a count")

        # THE FALLBACK STILL WORKS. A build that attaches no per-message ids has nothing but the
        # count, and must still behave exactly as before.
        plain = PageModel(href="https://chatgpt.com/c/" + CONV, native_ids=False,
                          turns=[("user", "q"), ("assistant", "old")])
        end2 = make_end(plain, conversation_id=CONV)
        r2 = end2.send("next", message_id="m2")
        self.assertEqual(cwe.parse_anchor(r2.native_id)["prior_id"], "")
        plain.turns.append(("assistant", "fresh"))
        msg2 = end2.receive(after_id=r2.native_id, timeout_s=5.0)
        self.assertTrue(msg2.complete)
        # A build that attaches no ids falls back to the content key, and says so.
        self.assertEqual(msg2.provenance["anchored_by"], "user_turn_content_key")

    @control(275)
    def test_holds_refuses_when_it_is_only_seeing_a_window(self):
        """A turn that has scrolled out of the DOM is not an absent turn. Reading it as absent
        would re-send an instruction the model is already acting on."""
        tmp = tempfile.mkdtemp(prefix="quaestor-cwe-win-")
        state = os.path.join(tmp, "cw.json")
        model = PageModel(href="https://chatgpt.com/c/" + CONV, window=4)
        end = make_end(model, conversation_id=CONV, state_path=state)

        # Four deliveries, so the relay knows it contributed four user turns...
        for n in range(4):
            self.assertTrue(end.send("instruction number %d" % n, message_id="m%d" % n).accepted)
            model.turns.append(("assistant", "reply %d" % n))

        # ...but the page renders only the newest four turns, so the earliest is out of view.
        rendered = model.turns_dict()["turns"]
        rendered_users = [r for r in rendered if r["role"] == "user"]
        self.assertLess(len(rendered_users), 4, "this control needs a genuinely partial view")

        # The recent one is visible -> a real yes.
        self.assertTrue(end.holds("m3"))
        # The scrolled-out one is NOT visible -> REFUSED, never reported absent.
        with self.assertRaises(RuntimeError) as ctx:
            end.holds("m0")
        self.assertIn("WINDOW", str(ctx.exception))
        self.assertIn("not evidence of absence", str(ctx.exception))


class TestAdversarialReviewFindings(unittest.TestCase):
    """The defects a six-lens adversarial review confirmed after per-finding refutation.

    None of these was reachable from the earlier controls, and every one of them ends in the
    same place: content the relay did not ask for, forwarded to an execution agent as a
    directive, or an instruction delivered twice. They are grouped here because they share that
    consequence, not because they share a mechanism.
    """

    def _sent_anchor(self, end, model, text="the relay's own instruction", mid="m1"):
        receipt = end.send(text, message_id=mid)
        self.assertTrue(receipt.accepted)
        return receipt.native_id

    @control(276)
    def test_receive_refuses_another_conversation_and_never_rebinds_to_it(self):
        """The worst gap review found: the anchor has always carried the conversation id and
        nothing read it, so receive returned whatever tab _attach reached and rebound to it."""
        mine = PageModel(href="https://chatgpt.com/c/" + CONV,
                         turns=[("user", "earlier"), ("assistant", "earlier reply")])
        end = make_end(mine, conversation_id=CONV)
        anchor = self._sent_anchor(end, mine)
        self.assertEqual(cwe.parse_anchor(anchor)["conversation_id"], CONV,
                         "the anchor must name the thread the message went to")

        # THE OPERATOR CLICKS ANOTHER THREAD (or a second chatgpt.com tab is picked up: the
        # transport matches on ORIGIN, not on conversation). It is long and quiet, so it
        # satisfies every completion fact instantly.
        other = PageModel(href="https://chatgpt.com/c/" + OTHER,
                          turns=[("user", "unrelated"),
                                 ("assistant", "LAST WEEK'S ANSWER IN ANOTHER THREAD")])
        strayed = cwe.ChatGptWebOrchestratorEnd(
            conversation_id=CONV,
            open_transport=lambda **_k: (FakeTransport(other), "cdp: fake"),
            clock=_ticking(), sleep=lambda _s: None, poll_s=0.0, stable_polls=1,
            settle_timeout_s=5.0)
        msg = strayed.receive(after_id=anchor, timeout_s=5.0)

        self.assertFalse(msg.complete, "another thread's answer must never be complete")
        self.assertEqual(msg.text, "")
        self.assertNotIn("LAST WEEK", msg.text)
        self.assertIn(OTHER, msg.error)
        self.assertIn(CONV, msg.error)
        # AND THE BINDING SURVIVES. Rebinding here would send every later turn to the wrong
        # thread while the kernel's durable record still named the right one.
        self.assertEqual(strayed.identity(), CONV,
                         "reading a stray page must not re-bind the endpoint")

    @control(277)
    def test_the_reply_is_the_answer_to_our_own_turn_not_merely_the_latest(self):
        """manages_lifecycle is False: the browser is the operator's and they may keep using it.
        If they ask their own question while the relay waits, the old code returned THEIR answer
        as the Orchestrator's directive."""
        model = PageModel(href="https://chatgpt.com/c/" + CONV,
                          turns=[("user", "earlier"), ("assistant", "earlier reply")])
        end = make_end(model, conversation_id=CONV)
        anchor = self._sent_anchor(end, model, text="RELAY DIRECTIVE PLEASE")

        # The answer to the relay lands...
        model.turns.append(("assistant", "ANSWER TO THE RELAY"))
        # ...and then the operator, seeing the relay is slow, asks their own follow-up.
        model.turns.append(("user", "wait, unrelated question"))
        model.turns.append(("assistant", "ANSWER TO THE OPERATOR, NOT THE RELAY"))

        msg = end.receive(after_id=anchor, timeout_s=5.0)
        self.assertTrue(msg.complete)
        self.assertEqual(msg.text, "ANSWER TO THE RELAY",
                         "the reply must be the turn that FOLLOWS our own user message")
        self.assertNotIn("OPERATOR", msg.text)
        self.assertEqual(msg.provenance["anchored_by"], "user_turn_id")

    @control(278)
    def test_a_turn_refused_once_is_not_accepted_later_unchanged(self):
        """A stream that dies mid-token loses its stop affordance and stops mutating, so it
        satisfies every completion fact BETTER than a healthy one. The kernel keeps the same
        anchor across a pause, so the next receive would return the truncated text as final."""
        model = PageModel(href="https://chatgpt.com/c/" + CONV,
                          turns=[("user", "earlier"), ("assistant", "earlier reply")])
        tmp = tempfile.mkdtemp(prefix="quaestor-cwe-refuse-")
        state = os.path.join(tmp, "cw.json")
        end = make_end(model, conversation_id=CONV, state_path=state)
        anchor = self._sent_anchor(end, model)

        # The stream dies mid-sentence and the page shows an error banner.
        model.turns.append(("assistant", "Run the migration and then dro"))
        model.alert_text = "Something went wrong."
        first = end.receive(after_id=anchor, timeout_s=2.0)
        self.assertFalse(first.complete)
        self.assertIn(cwp.STATE_STREAM_ERROR, first.error)

        # The operator dismisses the toast. Nothing else changed: same turn, same half-answer.
        model.alert_text = ""
        second = end.receive(after_id=anchor, timeout_s=2.0)
        self.assertFalse(second.complete,
                         "the same dead half-answer must not become finished when a toast goes")
        self.assertEqual(second.text, "")
        self.assertIn("has not changed since", second.error)

        # A RESTARTED process reads the refusal from the record and agrees.
        reborn = make_end(model, conversation_id=CONV, state_path=state)
        self.assertFalse(reborn.receive(after_id=anchor, timeout_s=2.0).complete)

        # ...and if the model GENUINELY continues, the text changes and it is accepted.
        model.turns[-1] = ("assistant", "Run the migration and then drop the temp table.")
        third = end.receive(after_id=anchor, timeout_s=5.0)
        self.assertTrue(third.complete, "a turn that really did finish must be accepted")
        self.assertIn("drop the temp table", third.text)

    @control(279)
    def test_a_lost_or_unreadable_record_refuses_rather_than_reporting_never_sent(self):
        """"The record is written before the submit, so its absence means the submit was never
        reached" is only sound when the record is durable AND readable."""
        tmp = tempfile.mkdtemp(prefix="quaestor-cwe-rec-")
        state = os.path.join(tmp, "cw.json")
        model = PageModel(href="https://chatgpt.com/c/" + CONV)
        end = make_end(model, conversation_id=CONV, state_path=state)
        end.send("apply the migration to prod", message_id="m1")

        # THE FILE IS LOST (cleaned work dir, power loss before flush). A NEW process has no
        # memory either, so it cannot tell "never sent" from "record gone".
        os.remove(state)
        reborn = make_end(model, conversation_id=CONV, state_path=state)
        with self.assertRaises(RuntimeError) as ctx:
            reborn.holds("m1")
        self.assertIn("LOST record", str(ctx.exception))

        # A CORRUPT file is equally unanswerable, and must not read as an empty one.
        with open(state, "w", encoding="utf-8") as fh:
            fh.write("{not json at all")
        corrupt = make_end(model, conversation_id=CONV, state_path=state)
        with self.assertRaises(RuntimeError) as ctx2:
            corrupt.holds("m1")
        self.assertIn("could not be read", str(ctx2.exception))

        # AN ENDPOINT WITH NO RECORD AT ALL cannot answer either -- and one is constructible
        # that way straight from the registry.
        nowhere = relay_registry.build_orchestrator({"kind": "chatgpt-web", "config": {}})
        with self.assertRaises(RuntimeError) as ctx3:
            nowhere.holds("m1")
        self.assertIn("without a state path", str(ctx3.exception))

    @control(280)
    def test_holds_reads_the_thread_the_delivery_went_to(self):
        """It used to read whichever tab was in front and report a miss THERE as a definite no."""
        tmp = tempfile.mkdtemp(prefix="quaestor-cwe-nav-")
        state = os.path.join(tmp, "cw.json")
        sent = "the instruction that was in flight"
        mine = PageModel(href="https://chatgpt.com/c/" + CONV)
        end = make_end(mine, conversation_id=CONV, state_path=state)
        end.send(sent, message_id="m1")
        self.assertTrue(end.holds("m1"))

        # The browser is now showing a DIFFERENT thread that does not contain our turn.
        stray = PageModel(href="https://chatgpt.com/c/" + OTHER,
                          turns=[("user", "someone else's question")])
        transports = []

        def opener(**_k):
            t = FakeTransport(stray)
            transports.append(t)
            return t, "cdp: fake"

        wandered = cwe.ChatGptWebOrchestratorEnd(
            conversation_id=CONV, state_path=state, open_transport=opener,
            clock=_ticking(), sleep=lambda _s: None, poll_s=0.0, stable_polls=1,
            settle_timeout_s=5.0)
        # It must NAVIGATE to the bound thread rather than answer about the stray one...
        with self.assertRaises(RuntimeError) as ctx:
            wandered.holds("m1")
        self.assertTrue(transports and transports[0].visited,
                        "holds must navigate to the conversation the delivery went to")
        self.assertIn(CONV, transports[0].visited[0])
        # ...and when it cannot get there, it REFUSES rather than reporting a miss.
        self.assertIn("refusing to answer", str(ctx.exception))

    @control(281)
    def test_the_two_whitespace_normalisers_agree_on_every_code_point(self):
        """``\\s`` is not the same set in the two languages, and the gap is a duplicate delivery.

        Python's matches U+001C-U+001F and U+0085; JavaScript's does not. JavaScript's ``\\s``
        and ``trim()`` match U+FEFF; Python's do not. A byte-order mark surviving inside a file
        the agent quoted was enough to make the same landed turn hash two different ways, so
        ``holds`` would miss it and the kernel would send it again.

        Verified against a real V8 during the live run over 832 inputs including every code
        point below U+0300; pinned here so a future edit to either half cannot drift.
        """
        # The exact characters the review named must all be treated as whitespace by BOTH.
        for cp in (0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xfeff, 0xa0, 0x2028, 0x2029, 0x3000):
            c = chr(cp)
            self.assertIn(c, cwp.WHITESPACE_CODEPOINTS, "U+%04X" % cp)
            self.assertEqual(cwp.normalise(c + "alpha" + c), "alpha", "U+%04X" % cp)
            self.assertEqual(cwp.text_key("alpha"), cwp.text_key(c + "alpha" + c),
                             "U+%04X must not change the key" % cp)
        # The JS twin is GENERATED from the same table, so the two cannot be edited apart.
        for c in cwp.WHITESPACE_CODEPOINTS:
            self.assertIn("\\u%04x" % ord(c), cwp.TEXT_KEY_JS, repr(c))
        # And the JS no longer relies on either language's shorthand.
        self.assertNotIn("\\s", cwp.TEXT_KEY_JS)
        self.assertNotIn(".trim()", cwp.TEXT_KEY_JS)


class TestRendererDefeatsContentKeys(unittest.TestCase):
    """The defect that broke the first qualification run on the reworked code.

    MEASURED live: ChatGPT's renderer does not echo what was typed. ``innerText`` omits
    code-fence characters, so the 4339-char opening charter -- which necessarily contains a
    fence, because the charter is what TEACHES the effect block -- hashed 8857ba87 here and
    48c189de in the DOM, diverging at normalised offset 2073 exactly at the fence.

    Two matchers derived from rendered text have now failed against the real page for the same
    underlying reason (this one, and the message count under virtualisation). The DOM is a
    rendering, not a transcript; identity has to come from the vendor's own ids where they exist.
    """

    @control(282)
    def test_a_message_the_renderer_rewrites_is_still_found(self):
        class Rewriting(PageModel):
            """A page whose innerText drops fence characters, as the real one does."""

            def _rendered(self):
                return [(i, r, t.replace("```", "")) for (i, r, t) in
                        PageModel._rendered(self)]

        typed = ("Ask for the effect with a block of exactly this form:\n\n"
                 "```quaestor-effect\neffect: GIT_COMMIT\n```\n\nThen proceed.")
        model = Rewriting(href="https://chatgpt.com/c/" + CONV,
                          turns=[("user", "earlier"), ("assistant", "earlier reply")])
        state = os.path.join(tempfile.mkdtemp(prefix="quaestor-cwe-md-"), "cw.json")
        end = make_end(model, conversation_id=CONV, state_path=state)
        receipt = end.send(typed, message_id="md-1")
        self.assertTrue(receipt.accepted)

        # THE CONTENT KEY GENUINELY DOES NOT MATCH -- this control is vacuous otherwise.
        anchor = cwe.parse_anchor(receipt.native_id)
        rendered_user = [r for r in model.turns_dict()["turns"] if r["role"] == "user"][-1]
        self.assertNotEqual(anchor["sent_key"], rendered_user["key"],
                            "the renderer must really rewrite the text for this to prove "
                            "anything")
        # ...but the page's own id for our turn does, and that is what the anchor carries.
        self.assertTrue(anchor["user_id"])
        self.assertEqual(anchor["user_id"], rendered_user["id"])

        model.turns.append(("assistant", "UNDERSTOOD"))
        msg = end.receive(after_id=receipt.native_id, timeout_s=5.0)
        self.assertTrue(msg.complete, "a markdown message must still find its own reply")
        self.assertEqual(msg.text, "UNDERSTOOD")
        self.assertEqual(msg.provenance["anchored_by"], "user_turn_id")

        # And reconciliation uses the same id, so it is not defeated either.
        self.assertTrue(end.holds("md-1"))

    @control(283)
    def test_send_waits_for_our_own_turn_and_never_adopts_the_previous_one(self):
        """The submit returns when the click lands; the turn renders a moment later. Reading the
        last user id once could therefore return the PREVIOUS turn's id and anchor the whole
        exchange to somebody else's message."""

        class Laggy(PageModel):
            """Renders the submitted turn only after ``lag`` reads of the user-id probe."""

            def __init__(self, *, lag=3, **kw):
                super().__init__(**kw)
                self.lag = int(lag)
                self.pending = None
                self.reads = 0

            def last_user_id(self):
                self.reads += 1
                if self.pending is not None and self.reads > self.lag:
                    self.turns.append(self.pending)
                    self.pending = None
                return PageModel.last_user_id(self)

        model = Laggy(lag=3, href="https://chatgpt.com/c/" + CONV,
                      turns=[("user", "SOMEBODY ELSE'S TURN"), ("assistant", "reply to them")])
        before = model.last_user_id()
        model.reads = 0

        # The submit lands but the DOM has not caught up: hold the turn back for a few reads.
        def deferred(_t, text):
            model.pending = ("user", text)
            model.submitted.append(text)
            return "OK"

        end = make_end(model, conversation_id=CONV)
        end._page = _DeferredSubmit(model, deferred)
        receipt = end.send("THE RELAY'S OWN TURN", message_id="m1")
        self.assertTrue(receipt.accepted)

        anchor = cwe.parse_anchor(receipt.native_id)
        self.assertTrue(anchor["user_id"], "it must wait until an id actually appears")
        self.assertNotEqual(anchor["user_id"], before,
                            "anchoring to the PREVIOUS user turn would attach this exchange to "
                            "somebody else's message")
        ours = [r for r in model.turns_dict()["turns"] if r["role"] == "user"][-1]
        self.assertEqual(anchor["user_id"], ours["id"])

        # A page that attaches NO ids never satisfies the wait; it must give up promptly and
        # fall back rather than spending the whole budget proving a known absence.
        plain = PageModel(href="https://chatgpt.com/c/" + CONV, native_ids=False)
        end2 = make_end(plain, conversation_id=CONV)
        r2 = end2.send("no ids here", message_id="m2")
        self.assertTrue(r2.accepted)
        self.assertEqual(cwe.parse_anchor(r2.native_id)["user_id"], "")


class _DeferredSubmit:
    """A page-module proxy whose ``submit`` defers rendering the turn. Everything else is real."""

    def __init__(self, model, submit_fn):
        self._model = model
        self._submit = submit_fn

    def __getattr__(self, name):
        return getattr(cwp, name)

    def submit(self, transport, text):
        before = self._model.probe_dict()
        return (self._submit(transport, text) == "OK"), "", int(before.get("count") or 0)

    def last_user_id(self, _transport):
        return self._model.last_user_id()

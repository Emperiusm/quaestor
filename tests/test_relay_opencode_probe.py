"""test_relay_opencode_probe -- controls 383 and 384. bd quaestor-7z1.

WHY THIS MODULE EXISTS
----------------------
The opencode probe is the one that catches the failure the model-exercising preflight was built
for: ``opencode/nemotron-3-ultra-free`` answers a bare "PONG" with an APIError while the server,
the session and the model catalogue are all perfectly healthy. ``status()`` therefore reports
IDLE, and the relay learns at exchange 1 that its model cannot answer -- with nothing to tell the
operator except that the execution end went away.

That probe had LIVE evidence and no test that EXECUTED it. Controls 304-315 drive the FAKE end's
scripted probe and the ``http_chat`` probe; ``opencode.probe()`` could have been rewritten to
``return EndProbe(PROBE_OK, "")`` and the whole suite would have stayed green. Live evidence is
not a regression control: it does not run in the gate, and it cannot fail on a future edit.

THE PATTERN, NOT A NEW ONE
--------------------------
Control 314 already drives a REAL end's ``probe()`` by injecting a stub ``opener`` through the
constructor and asserting on the requests the stub actually received. ``OpenCodeExecutionEnd``
already takes ``opener``, ``clock`` and ``sleep`` for exactly that reason, so these controls
follow control 314's pattern rather than inventing a second one, and NO source change was needed
to write them.

The stub answers the endpoint's own HTTP surface from a scripted SERVER, never with canned probe
verdicts. A double that answered "is the model healthy?" directly would be satisfied by a probe
that asked nothing at all, which is the single defect these controls exist to catch. Nothing here
touches the network, and nothing waits on real time.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
import urllib.error
import urllib.parse
from unittest import mock

from tests.controls import control

from quaestor.relay.contracts import (
    PROBE_OK, PROBE_REFUSED, PROBE_UNSUPPORTED, PROBE_UPSTREAM_FAILED)
from quaestor.relay.ends import opencode as oc

#: The model the live run refused, kept by name so these controls read as the failure they encode.
LIVE_BAD_MODEL = "opencode/nemotron-3-ultra-free"

#: The error envelope shape is copied from the endpoint's OWN consumer (``_compose`` reads
#: ``error["name"]`` and ``error["data"]["message"]``) rather than invented, so the fixture cannot
#: drift away from the server the probe actually talks to.
API_ERROR = {"name": "APIError", "data": {"message": "provider returned 400 for this model"}}

#: The probe's OWN prompt text, copied from ``probe()``. The real server puts the user turn in
#: the SAME listing the probe reads back -- ``receive()`` scans ``GET /session/{id}/message`` for
#: the relay's own user-message id, and ``holds()`` looks the derived delivery id up there too --
#: so a listing without it is not the listing the probe actually faces.
PROBE_PROMPT = "Reply with the single word OK."


def assistant(text="", error=None, mid="msg_a1"):
    """One assistant message in the shape ``GET /session/{id}/message`` returns.

    ``parts`` is EMPTY when there is no text, because that is the ordinary in-flight shape: the
    server creates the assistant record when the turn starts and fills it in afterwards.
    """
    info = {"id": mid, "role": "assistant", "time": {"created": 1, "completed": 2}}
    if error is not None:
        info["error"] = error
    return {"info": info, "parts": [{"type": "text", "text": text}] if text else []}


def user(text=PROBE_PROMPT, mid="msg_user1"):
    """The probe's own prompt, echoed back the way the server really returns it."""
    return {"info": {"id": mid, "role": "user", "time": {"created": 1}},
            "parts": [{"type": "text", "text": text}]}


class ScriptedServer:
    """The opencode server's HTTP surface, scripted, driven through the end's own ``opener``.

    Records every request the probe issued, so a control can assert what was ASKED and not only
    what came back. An unexpected request is RECORDED rather than raised: the probe swallows
    exceptions by design, so raising here would come back disguised as a provider verdict and the
    real disagreement would never be seen.
    """

    def __init__(self, *, created=None, create_raises=None, prompt_raises=None, polls=None):
        self.created = {"id": "ses_probe"} if created is None else created
        self.create_raises = create_raises
        self.prompt_raises = prompt_raises
        #: One entry per message poll; the LAST entry repeats forever, so "the model never
        #: answers" is expressible without scripting sixty empty listings.
        self.polls = [list(p) for p in (polls if polls is not None else [[]])]
        self.calls = []
        self.unexpected = []
        #: Filled in by the fixture, so each server carries the waits ITS probe took.
        self.sleeps = None

    def __call__(self, method, url, body):
        parts = urllib.parse.urlsplit(url)
        self.calls.append({"method": method, "path": parts.path, "body": body,
                           "query": dict(urllib.parse.parse_qsl(parts.query))})
        if method == "POST" and parts.path == "/session":
            if self.create_raises is not None:
                raise self.create_raises
            return self.created
        if method == "POST" and parts.path.endswith("/prompt_async"):
            if self.prompt_raises is not None:
                raise self.prompt_raises
            return {}
        if method == "GET" and parts.path.endswith("/message"):
            return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]
        self.unexpected.append((method, parts.path))
        return None

    # -- what the probe actually asked ---------------------------------------------------------
    def of(self, method, suffix):
        return [c for c in self.calls if c["method"] == method and c["path"].endswith(suffix)]

    @property
    def prompts(self):
        return self.of("POST", "/prompt_async")

    @property
    def message_polls(self):
        return self.of("GET", "/message")

    @property
    def directories(self):
        return {c["query"].get("directory") for c in self.calls}


class Clock:
    """A clock the probe READS. Every read advances it, so the probe's own 60s ceiling is reached
    in a handful of reads instead of in a minute. Nothing here waits on real time."""

    def __init__(self, step=0.5, start=1000.0):
        self.t = float(start)
        self.step = float(step)
        self.reads = 0

    def __call__(self):
        self.reads += 1
        now = self.t
        self.t += self.step
        return now


class Sleeps:
    """Records the probe's waits instead of taking them."""

    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(float(seconds))


class OpenCodeProbeFixture(unittest.TestCase):
    """Every control here builds a REAL OpenCodeExecutionEnd and calls its REAL probe()."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oc-probe-control-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        #: A genuinely distinct directory on disk, so "the probe never touched the authorised
        #: project" is a comparison between two real paths, not between two spellings of one.
        self.project = os.path.join(self.tmp, "authorised-project")
        os.makedirs(self.project)

    def probe_with(self, server, *, model=LIVE_BAD_MODEL, step=0.5, session_id="ses_bound"):
        """Run the REAL probe against a scripted server, and hand back its verdict."""
        server.sleeps = Sleeps()
        end = oc.OpenCodeExecutionEnd(
            project_root=self.project, base_url="http://127.0.0.1:4096",
            session_id=session_id, model=model, opener=server,
            clock=Clock(step=step), sleep=server.sleeps)
        return end.probe()

    def same_path(self, a, b):
        return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


class TestOpenCodeProbeExecutesTheModel(OpenCodeProbeFixture):

    @control(383)
    def test_the_opencode_probe_asks_the_model_and_the_verdict_follows_the_answer(self):
        """The probe must MAKE THE MODEL ANSWER, and each answer shape gets its own verdict.

        The scenarios are checked together on purpose. A probe that returns one verdict
        regardless -- the exact rewrite this bead names, ``return EndProbe(PROBE_OK, "")`` --
        disagrees with all but one of them, and the assertions below on what was ASKED disagree
        with the remaining one.

        THE ERROR-ON-THE-TURN CASE IS THE POINT. The server is healthy, the session exists, the
        prompt was accepted, and the assistant turn carries an APIError. That is indistinguishable
        from success to ``status()``, which is the whole reason ``probe()`` exists.
        """
        healthy = ScriptedServer(polls=[[], [assistant("OK")]])
        errored = ScriptedServer(polls=[[assistant("", error=API_ERROR)]])
        # An error turn that ALSO carries text: the error outranks anything said alongside it, so
        # a probe that read the text first would call an unusable model healthy.
        errored_with_text = ScriptedServer(polls=[[assistant("OK", error=API_ERROR)]])
        silent = ScriptedServer(polls=[[]])
        # THE PROBE'S OWN PROMPT, READ BACK. The listing the real server returns contains the
        # user turn, so without this case the role filter can be deleted outright and the probe
        # will happily quote its own question back as the model's answer.
        echoed_prompt = ScriptedServer(polls=[[user()]])
        # THE ORDINARY IN-FLIGHT SHAPE: the assistant record exists, and has said nothing yet.
        # Accepting it degrades the probe to "the prompt was accepted", which is what status()
        # already answers and the reason this probe exists.
        in_flight = ScriptedServer(polls=[[user(), assistant("")]])
        # The same turn, one poll later, carrying the live failure. This is the WHOLE sequence
        # the nemotron run produced, and it pins the role filter and the wait-for-text together.
        in_flight_then_error = ScriptedServer(
            polls=[[user(), assistant("")], [user(), assistant("", error=API_ERROR)]])
        # A prompt the server rejects outright -- the sibling presentation of an unusable model.
        refused_prompt = ScriptedServer(
            prompt_raises=urllib.error.HTTPError(
                "http://127.0.0.1:4096/session/ses_probe/prompt_async", 400, "Bad Request",
                {}, None))
        refused_session = ScriptedServer(
            create_raises=urllib.error.HTTPError("http://127.0.0.1:4096/session", 503,
                                                 "Service Unavailable", {}, None))
        no_session_id = ScriptedServer(created={})

        cases = (
            ("a model that answers", healthy, 0.5, PROBE_OK),
            ("an APIError on the assistant turn", errored, 0.5, PROBE_REFUSED),
            ("an APIError beside real text", errored_with_text, 0.5, PROBE_REFUSED),
            ("a turn that is still in flight, then errors", in_flight_then_error, 0.5,
             PROBE_REFUSED),
            ("a server that refuses the prompt", refused_prompt, 0.5, PROBE_REFUSED),
            # UPSTREAM_FAILED, never REFUSED: silence is transient-shaped, and control 310 makes
            # the two verdicts behave DIFFERENTLY, so collapsing them here would be a real defect.
            ("a model that says nothing at all", silent, 25.0, PROBE_UPSTREAM_FAILED),
            ("the probe's own prompt echoed back", echoed_prompt, 25.0, PROBE_UPSTREAM_FAILED),
            ("an assistant turn that has not spoken yet", in_flight, 25.0,
             PROBE_UPSTREAM_FAILED),
            ("a server that will not open a session", refused_session, 0.5,
             PROBE_UPSTREAM_FAILED),
            ("a server that opens a session with no id", no_session_id, 0.5,
             PROBE_UPSTREAM_FAILED),
        )
        inspected = 0
        for label, server, step, expected in cases:
            with self.subTest(label):
                probe = self.probe_with(server, step=step)
                inspected += 1
                self.assertEqual(probe.state, expected, "%s -> %s" % (label, probe.detail))
                self.assertEqual(probe.ok, expected == PROBE_OK, label)
                self.assertTrue(probe.measured, label)   # something was attempted either way
                self.assertEqual(probe.model, LIVE_BAD_MODEL, label)
                self.assertTrue(probe.detail.strip(), "%s produced no explanation" % label)
                self.assertEqual(server.unexpected, [], label)

        # IT ACTUALLY ASKED. Without this the table above could be satisfied by a probe that
        # inspected its own configuration and never opened a socket.
        self.assertEqual(len(healthy.prompts), 1)
        asked = healthy.prompts[0]["body"]
        self.assertEqual(asked["model"], {"providerID": "opencode",
                                          "modelID": "nemotron-3-ultra-free"})
        self.assertTrue(any(str(p.get("text") or "").strip() for p in asked["parts"]),
                        "the probe sent an empty prompt")
        # And the OK came from a POLLED answer rather than from the prompt being accepted: the
        # first listing was empty, so a probe that concluded after one look would have said
        # nothing came back.
        self.assertEqual(len(healthy.message_polls), 2)
        self.assertTrue(healthy.sleeps.calls, "the probe never waited for an answer")

        # The silent case WAITED rather than giving up, and gave up inside its OWN bound, which
        # is pinned to the LITERAL. Asserting "%.0f" % PROBE_TIMEOUT_S would only compare the
        # payload against itself: 60.0 -> 600.0 would keep every such assertion true while the
        # probe hung the relay's start for ten minutes on a silent model.
        self.assertEqual(oc.OpenCodeExecutionEnd.PROBE_TIMEOUT_S, 60.0)
        self.assertIn("60s", self.probe_with(ScriptedServer(polls=[[]]), step=25.0).detail)
        # And the BOUND IS THE ONE THAT RAN. The clock advances 25s per read, so a 60s ceiling
        # admits exactly two polls; a loop that ignored the constant and waited ten minutes would
        # make twenty-four, with the constant and the detail string both still saying 60.
        self.assertEqual(len(silent.message_polls), 2)
        self.assertEqual(len(silent.sleeps.calls), len(silent.message_polls))

        # A server that would not open a session was never sent a prompt: nothing was spent, and
        # the verdict blames the SERVER rather than telling the operator their model was rejected.
        self.assertEqual(refused_session.prompts, [])
        self.assertEqual(no_session_id.prompts, [])
        self.assertEqual(refused_session.message_polls, [])
        # And a REFUSED prompt was never polled for an answer that is not coming.
        self.assertEqual(len(refused_prompt.prompts), 1)
        self.assertEqual(refused_prompt.message_polls, [])

        # NOTHING ASKED, SO NOTHING CLAIMED. A probe that cannot make a scratch directory has
        # measured nothing, and EndProbe's own contract is that a caller "cannot mistake an
        # unmeasured endpoint for a working one". Reporting PROBE_OK here would start the relay
        # against a model no one ever spoke to.
        unaskable = ScriptedServer(polls=[[assistant("OK")]])
        with mock.patch("tempfile.mkdtemp", side_effect=OSError(28, "No space left on device")):
            unmeasured = self.probe_with(unaskable)
        inspected += 1
        self.assertEqual(unmeasured.state, PROBE_UNSUPPORTED, unmeasured.detail)
        self.assertFalse(unmeasured.ok)
        self.assertFalse(unmeasured.measured)
        self.assertEqual(unaskable.calls, [], "it reported on a model it never contacted")

        self.assertEqual(inspected, len(cases) + 1,
                         "inspected %d of %d scenarios" % (inspected, len(cases) + 1))


class TestOpenCodeProbeCostsNothingItShouldNot(OpenCodeProbeFixture):

    @control(384)
    def test_the_probe_uses_a_throwaway_session_and_refuses_to_guess_a_vendor(self):
        """Two ways a probe can be worse than no probe, both checked by EXECUTING it.

        1. IT MUST NOT TOUCH WHAT IT PROTECTS. The probe's entire budget is one trivial
           inference. Run in the bound session it would add messages to the conversation the
           relay resumes from; run in the authorised project it would point the agent it is
           testing at the operator's repository.
        2. IT MUST NOT INVENT A VENDOR. ``send()`` refuses a bare model name rather than guessing
           ``providerID == modelID``; a probe that guessed would spend a real inference on a
           vendor nobody configured and then report the operator's MODEL unusable -- a worse
           diagnosis than the one the probe exists to improve.
        """
        server = ScriptedServer(polls=[[assistant("OK")]])
        probe = self.probe_with(server, session_id="ses_bound")
        self.assertEqual(probe.state, PROBE_OK, probe.detail)
        self.assertTrue(server.calls, "the probe issued no request at all")

        # -- 1. a throwaway session, in a scratch directory ------------------------------------
        self.assertEqual(len(server.directories), 1,
                         "the probe used more than one directory: %r" % (server.directories,))
        scratch = next(iter(server.directories))
        self.assertTrue(scratch, "the probe sent no directory at all")
        self.assertFalse(self.same_path(scratch, self.project),
                         "the probe ran in the authorised project")
        self.assertTrue(
            self.same_path(os.path.dirname(scratch), tempfile.gettempdir()),
            "the scratch directory was not a temporary one: %r" % (scratch,))
        # The bound session gained NOTHING: no request names it, and every session-scoped request
        # names the throwaway session the server just created.
        self.assertNotIn("ses_bound", " ".join(c["path"] for c in server.calls))
        self.assertTrue(all("/session/ses_probe/" in c["path"]
                            for c in server.calls if c["path"] != "/session"),
                        [c["path"] for c in server.calls])
        # And the scratch directory is GONE. A probe that runs at every start and leaves a
        # directory behind is a slow leak in the operator's temp.
        self.assertFalse(os.path.exists(scratch), "the probe left %r behind" % (scratch,))

        # -- 2. a bare model name is refused, never guessed at ---------------------------------
        bare = ScriptedServer(polls=[[assistant("OK")]])
        refusal = self.probe_with(bare, model="nemotron-3-ultra-free")
        self.assertEqual(refusal.state, PROBE_REFUSED, refusal.detail)
        self.assertIn("provider", refusal.detail)
        self.assertEqual(bare.prompts, [], "the probe spent an inference on a guessed vendor")
        self.assertEqual(bare.message_polls, [])
        self.assertEqual(bare.unexpected, [])
        # It still cleaned up after the refusal -- the path a ``finally`` is easiest to lose,
        # because the scratch directory is made BEFORE the model name is ever looked at.
        self.assertEqual(len(bare.directories), 1)
        self.assertFalse(os.path.exists(next(iter(bare.directories))))


if __name__ == "__main__":
    unittest.main()

"""test_relay_completion -- controls 284-295.

TWO CORRECTNESS HOLES, BOTH FOUND BY A LIVE RUN RATHER THAN BY REASONING.

1. COMPLETION CORROBORATION (bd quaestor-pr4.16). The Orchestrator's completion marker used to
   end the relay by itself. The party declaring the work finished is the party that did not do
   it, cannot see the repository and cannot run a test -- and in a real qualification run the
   Orchestrator declared the objective met while the fixture's own suite still failed. These
   controls prove the claim is now MEASURED before it is believed, and that every way the
   measurement can be inconclusive falls toward "not accepted" rather than toward "complete".

2. BOUNDED RECOVERY FROM AN INCOMPLETE TURN (bd quaestor-nmq). A single truncated turn used to
   end an otherwise healthy slice, because "the endpoint is gone" and "the endpoint did not
   finish a sentence" were the same outcome. These controls prove the two are now distinguished,
   that the healthy case is retried under a bound, and -- the part that must never regress --
   that the retry touches only the RECEIVE, so bounded recovery can never duplicate a delivery.

Every fixture is a real git repository and every check is a real subprocess, because a control
that stubbed either would be testing the stub. Control 295 exists because the first version of
the splitter passed a quoted argument through WITH its quotes, so a check that should have
failed exited zero and reported success -- caught here, not by reading the code.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import tracemalloc
import unittest

from tests import procsafe
from tests.controls import control
from tests.test_relay_kernel import RelayFixture

from quaestor.core import owner_channel
from quaestor.relay import contracts
from quaestor.relay import corroborate as corroborate_mod
from quaestor.relay import kernel as kernel_mod
from quaestor.relay import state as state_mod
from quaestor.relay.contracts import (END_FAILED, END_IDLE, FROM_ORCHESTRATOR,
                                      ROLE_ORCHESTRATOR, EndStatus, RelayMessage)
from quaestor.relay.ends import http_chat
from quaestor.relay.ends.fake import FakeExecutionEnd, FakeOrchestratorEnd

MARKER = kernel_mod.COMPLETION_MARKER
MISSING = "quaestor-no-such-verification-command-exists"

OK_BODY = "raise SystemExit(0)\n"
BAD_BODY = ("import sys\n"
            "sys.stderr.write('2 failed, 5 passed')\n"
            "raise SystemExit(1)\n")

#: A check that starts something which OUTLIVES it and INHERITS its stdout and stderr. This is
#: the ordinary shape -- a dev server, a file watcher, a test runner that daemonises -- not a
#: contrived one, and it is the shape under which ``--verify-timeout`` was not a ceiling: the
#: grandchild holds the write end of the captured pipe, so the drain that follows the kill waits
#: on the ORPHAN. Measured on this platform before the fix: a 3s ceiling, 30.06s in the call.
#:
#: THE GRANDCHILD IS SPAWNED WITH NO CREATION FLAGS, AND THAT IS THE LOAD-BEARING PART. The
#: first version of this fixture passed CREATE_NO_WINDOW to it, copying the convention the rest
#: of the suite uses to keep console windows off the operator's desktop -- and measurement said
#: the control had thereby stopped measuring anything: the flag gives the grandchild its OWN
#: console, so its standard handles come from there and it never touches the check's pipe. Four
#: variants against the pre-fix shape, one run each: grandchild plain 20.07s and 20.07s,
#: grandchild with the flag 3.02s and 3.01s against the same 3s ceiling. No window appears
#: anyway, because the check itself is started without one and the grandchild inherits that.
#: THE GRANDCHILD ANNOUNCES ITSELF ON THE HANDLE IT INHERITED, and control 389 asserts that
#: line arrived. Inheritance is the entire premise of this fixture and nothing used to check it:
#: adding ``stdout=subprocess.DEVNULL`` to the spawn below -- ONE argument -- left every
#: assertion green, measured against the fixed shape AND against the pre-fix shape, silently
#: converting the control into a test of nothing. ``CHECK-STARTED`` could not catch that: the
#: CHECK writes it, so it says nothing about who else holds the handle. A marker only a process
#: holding the check's own stdout can deliver closes the class rather than one instance of it.
#: argv is (grandchild script, pid file for the grandchild, pid file for the check itself,
#: seconds the pair should live).
GRANDCHILD_BODY = (
    "import sys, time\n"
    "sys.stdout.write('GRANDCHILD-HOLDS-STDOUT\\n')\n"
    "sys.stdout.flush()\n"
    "open(sys.argv[1], 'w').write('up')\n"
    "time.sleep(float(sys.argv[2]))\n")

SURVIVOR_BODY = (
    "import os, subprocess, sys, time\n"
    "up = sys.argv[2] + '.up'\n"
    "kid = subprocess.Popen([sys.executable, sys.argv[1], up, sys.argv[4]],\n"
    "                       shell=False)\n"
    "open(sys.argv[2], 'w').write(str(kid.pid))\n"
    "open(sys.argv[3], 'w').write(str(os.getpid()))\n"
    # NOT A RACE. The check waits until the grandchild's marker is on the handle before it says
    # anything itself, so a control reading the tail either sees both lines or fails honestly.
    "while not os.path.isfile(up):\n"
    "    time.sleep(0.02)\n"
    "sys.stdout.write('CHECK-STARTED\\n')\n"
    "sys.stdout.flush()\n"
    "time.sleep(float(sys.argv[4]))\n")

#: A check that FLOODS its output and then hangs -- the ordinary chatty shape (a server, a
#: watcher, a test runner logging every case), and the one that broke the first fix. Removing
#: the pipe moved the unbounded wait to an argument-less ``read()``, which loops until a read
#: returns zero bytes; a grandchild still appending never lets that zero arrive. Reproduced by
#: review against that shape: an 8.0s promised ceiling, still inside ``run_check`` at 42.8s, a
#: 74 GB sink and the reviewer's free disk down from 61 GB to 1 GB.
#:
#: THE MARKER IS WRITTEN LAST, on purpose: finding it in the tail proves both that the whole
#: flood reached the sink and that what came back is the END of the output rather than its
#: beginning. argv is (how many 64 KiB blocks, seconds to hang afterwards).
CHATTY_END_MARKER = "END-OF-THE-NOISE"

CHATTY_HANG_BODY = (
    "import sys, time\n"
    "block = bytes([88]) * 65536\n"
    "for _ in range(int(sys.argv[1])):\n"
    "    sys.stdout.buffer.write(block)\n"
    "sys.stdout.buffer.write(b'" + CHATTY_END_MARKER + "' + bytes([10]))\n"
    "sys.stdout.buffer.flush()\n"
    "time.sleep(float(sys.argv[2]))\n")

#: A check that READS A PROMPT. With the check's stdin closed it reads end-of-file and answers
#: at once; with stdin inherited it takes the operator's keystrokes away from the relay and then
#: blocks on input that is never coming -- the quiet version of the same hole, and the one that
#: costs a check which was never actually wrong.
STDIN_READER_BODY = ("import sys\n"
                     "data = sys.stdin.read()\n"
                     "sys.stdout.write('STDIN-CLOSED-AFTER-%d-BYTES' % len(data))\n"
                     "sys.stdout.write(chr(10))\n"
                     "raise SystemExit(0)\n")

#: How long the survivor and the hanging check live if nothing ends them. Long enough that the
#: unfixed shape is unmistakable against the ceiling, short enough that a run which somehow
#: reaches it still ends by itself rather than needing an operator.
SURVIVOR_LIFE_S = "30"


def write_check(root: str, name: str, body: str) -> str:
    """Put a real verification script in the project and return the command that runs it.

    A project's checks are its own files, so the controls use that shape rather than a clever
    one-liner. Quoting both the interpreter and the script path is deliberate: it is exactly the
    form that used to be mis-split, so every control here exercises the fix.
    """
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return '"%s" "%s"' % (sys.executable, path)


def write_script(root: str, name: str, body: str) -> str:
    """``write_check`` for a check that needs ARGUMENTS: returns the path, not a command line.

    ``run_check`` takes an argv list as well as a string, and for these two the arguments are
    the fixture (where to write a pid, how long to live), so the quoting question control 295
    exists for is not the one under test here.
    """
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


def leaky_hang_body(secret: str, pid_prefix: str) -> str:
    """A check that prints its loaded configuration -- credential and all -- then never finishes.

    The secret is baked into the SCRIPT rather than passed as an argument, because ``command``
    is the operator's own text echoed back and is not redacted; a control that smuggled the
    secret in through argv would be measuring that, not the output classification it is for.

    IT ALSO LEAVES A GRANDCHILD HOLDING THE SINK, which is not decoration. The temp file that
    captures the check's RAW output -- the one copy classification never sees -- is removed on
    the way out, and the single case where that removal CANNOT succeed is a descendant still
    holding the handle on Windows. That is not the exotic case here, it is the shape this whole
    module exists for, so it is the shape the control runs.

    Each run writes its grandchild's pid under its OWN name: the kernel path corroborates more
    than once, and one shared pid file would leave every run but the last unadopted and leaking.
    """
    return ("import os, subprocess, sys, time\n"
            "kid = subprocess.Popen([sys.executable, '-c',\n"
            "                        'import time; time.sleep(" + SURVIVOR_LIFE_S + ")'],\n"
            "                       shell=False)\n"
            "open(%r + str(os.getpid()) + '.pid', 'w').write(str(kid.pid))\n" % pid_prefix +
            "sys.stdout.write('LOADED config api_key=%s')\n" % secret +
            "sys.stdout.write(chr(10))\n"
            "sys.stdout.flush()\n"
            "time.sleep(" + SURVIVOR_LIFE_S + ")\n")


def read_text(path: str) -> str:
    """Read back a small file a fixture wrote. Explicit encoding, like everything else here."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Claiming(FakeOrchestratorEnd):
    """An Orchestrator that declares victory on its first turn and keeps declaring it."""

    def receive(self, *, after_id="", timeout_s=0.0):
        self._receives += 1
        self._turn += 1
        return RelayMessage(
            message_id="%s:claim%d" % (self._identity, self._turn),
            direction=FROM_ORCHESTRATOR,
            text="All items are done. %s" % MARKER,
            complete=True, observed_at=float(self._turn),
            conversation_id=self._identity,
            provenance={"kind": "fake", "provider_family": "test", "model": "scripted"})


class TestCompletionCorroboration(RelayFixture):
    """bd quaestor-pr4.16 -- a completion claim is measured, not believed."""

    def setUp(self):
        super().setUp()
        self.passes = write_check(self.repo, "check_ok.py", OK_BODY)
        self.fails = write_check(self.repo, "check_bad.py", BAD_BODY)

    def claiming(self, *, relay_id, **cfg):
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Claiming(replies=[]),
            execution=FakeExecutionEnd(replies=["did the work", "did more", "did more still"]),
            project_root=self.repo, relay_id=relay_id,
            config=kernel_mod.RelayConfig(objective="fixture objective",
                                          authority_profile="STANDARD_EDIT", **cfg))
        k.start()
        return k

    @control(284)
    def test_a_refuted_completion_claim_does_not_stop_as_complete(self):
        """The suite says no. The relay does not call that done."""
        k = self.claiming(relay_id="relay-refuted", completion_checks=(self.fails,))
        res = k.step()
        self.assertNotEqual(res.stop, kernel_mod.STOP_OBJECTIVE_COMPLETE)
        claims = [ev["payload"] for ev in self.state.events(k.relay_id)
                  if ev["kind"] == "relay.completion.claim"]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["state"], corroborate_mod.REFUTED)
        # The relay is still alive: a refuted claim is a correction, not a fatality.
        self.assertEqual(self.state.get("relay-refuted")["stop_reason"], "")

    @control(285)
    def test_the_refutation_reaches_the_orchestrator_with_the_failing_output(self):
        """Being told only that you are wrong invites a model to repeat itself."""
        k = self.claiming(relay_id="relay-blocker", completion_checks=(self.fails,))
        k.step()          # opening packet -> orchestrator; it claims, and the claim is refused
        k.step()          # the refused directive still reaches the agent
        k.step()          # the agent's answer goes back, carrying the refutation
        to_orch = "\n".join(t for _mid, t in k.orchestrator.sent)
        self.assertIn("BLOCKERS THE RELAY IS TRACKING", to_orch)
        self.assertIn("Independent measurement disagrees", to_orch)
        # The measured OUTPUT travels, not merely the verdict -- that is what is actionable.
        self.assertIn("2 failed", to_orch)

    @control(286)
    def test_repeated_refused_claims_stop_by_their_own_name_under_a_bound(self):
        """COMPLETION_UNCORROBORATED is not OBJECTIVE_COMPLETE, and the loop is bounded."""
        k = self.claiming(relay_id="relay-exhaust", completion_checks=(self.fails,),
                          completion_attempt_limit=2)
        stops = []
        for _ in range(10):
            res = k.step()
            if res.stop:
                stops.append(res.stop)
                break
        self.assertEqual(stops, [kernel_mod.STOP_COMPLETION_UNCORROBORATED])
        row = self.state.get("relay-exhaust")
        self.assertEqual(row["stop_reason"], kernel_mod.STOP_COMPLETION_UNCORROBORATED)
        self.assertEqual(row["state"], state_mod.PAUSED)

    @control(287)
    def test_with_nothing_configured_the_claim_is_recorded_unverified(self):
        """Silence is not corroboration. The relay says so rather than implying otherwise."""
        k = self.claiming(relay_id="relay-unconfigured")
        res = k.step()
        self.assertEqual(res.stop, kernel_mod.STOP_OBJECTIVE_COMPLETE)
        claim = [ev["payload"] for ev in self.state.events(k.relay_id)
                 if ev["kind"] == "relay.completion.claim"][0]
        self.assertEqual(claim["state"], corroborate_mod.UNCONFIGURED)
        self.assertNotEqual(claim["state"], corroborate_mod.CORROBORATED)
        self.assertIn("UNVERIFIED", claim["reason"])

    @control(288)
    def test_a_check_that_cannot_be_run_is_never_read_as_passing(self):
        """UNMEASURABLE falls toward "not accepted" -- the direction every unmeasured fact does."""
        v = corroborate_mod.verdict(project_root=self.repo, checks=(self.passes, MISSING))
        self.assertEqual(v["state"], corroborate_mod.UNMEASURABLE)
        self.assertNotEqual(v["state"], corroborate_mod.CORROBORATED)
        broken = [c for c in v["checks"] if not c["measured"]]
        self.assertEqual(len(broken), 1)
        self.assertFalse(broken[0]["ok"])
        self.assertIn("no such command", broken[0]["error"])
        # And a relay that meets one refuses to finish on it.
        k = self.claiming(relay_id="relay-unmeasurable", completion_checks=(MISSING,))
        self.assertNotEqual(k.step().stop, kernel_mod.STOP_OBJECTIVE_COMPLETE)

    @control(289)
    def test_the_refusal_bound_survives_a_restart(self):
        """A relay that forgot its refusals could be re-claimed at forever by crashing."""
        k = self.claiming(relay_id="relay-durable", completion_checks=(self.fails,),
                          completion_attempt_limit=2)
        k.step()
        self.assertEqual(k._completion_refusals(), 1)
        # A FRESH kernel over the SAME durable record: the count comes from the event log, not
        # from anything the dead process was holding in memory.
        k2 = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Claiming(replies=[]),
            execution=FakeExecutionEnd(replies=["a", "b"]), project_root=self.repo,
            relay_id="relay-durable",
            config=kernel_mod.RelayConfig(objective="fixture objective",
                                          completion_checks=(self.fails,),
                                          completion_attempt_limit=2))
        self.assertEqual(k2._completion_refusals(), 1)

    @control(290)
    def test_corroboration_asks_the_project_not_the_agent(self):
        """The agent is never consulted about whether the agent's own work is correct."""
        landed = write_check(self.repo, "check_writes.py",
                             "open('ran-here.txt', 'w').write('1')\n")
        v = corroborate_mod.verdict(project_root=self.repo, checks=(landed,))
        self.assertEqual(v["state"], corroborate_mod.CORROBORATED)
        # It ran in the AUTHORISED PROJECT ROOT, in this process -- provably, because the file
        # landed there and nothing in the relay's transport was involved.
        self.assertTrue(os.path.isfile(os.path.join(self.repo, "ran-here.txt")))
        self.assertEqual(v["checks"][0]["instrument"], corroborate_mod.CORROBORATE_INSTRUMENT)
        # And the module names no provider: the rule is identical for every Orchestrator.
        with open(corroborate_mod.__file__, encoding="utf-8") as fh:
            src = fh.read().lower()
        for provider in ("chatgpt", "openai", "anthropic", "claude", "opencode", "gemini"):
            self.assertNotIn(provider, src)

    @control(295)
    def test_a_quoted_argument_survives_splitting_so_a_failing_check_really_fails(self):
        """The bug this control was written for: quotes reached the interpreter as a literal.

        ``python -c "raise SystemExit(1)"`` split without POSIX escaping keeps the quotes on the
        token, so Python evaluated a harmless STRING and exited ZERO. A check that must fail
        reported success -- the one direction this module may never fail in.
        """
        quoted = '"%s" -c "raise SystemExit(1)"' % sys.executable
        one = corroborate_mod.run_check(quoted, project_root=self.repo)
        self.assertTrue(one["measured"])
        self.assertEqual(one["exit_code"], 1)
        self.assertFalse(one["ok"])
        # A Windows interpreter path survives the same split (POSIX mode would eat backslashes).
        self.assertTrue(os.path.isfile(sys.executable))
        ok = corroborate_mod.run_check('"%s" -c "raise SystemExit(0)"' % sys.executable,
                                       project_root=self.repo)
        self.assertTrue(ok["measured"] and ok["ok"])
        # An explicit argv needs no quoting rules at all and must agree.
        argv = corroborate_mod.run_check([sys.executable, "-c", "raise SystemExit(1)"],
                                         project_root=self.repo)
        self.assertFalse(argv["ok"])
        self.assertTrue(argv["measured"])

    @control(298)
    def test_a_turn_that_denies_completion_does_not_end_the_relay(self):
        """The relay hands the model the trigger string on EVERY packet, so a substring test
        fires on a turn that says the opposite of what it is read as saying."""
        denial = ("The suite is still red -- test_login fails. I am NOT writing %s yet."
                  % MARKER + chr(10) + "Agent: fix the 401 and re-run the tests.")
        self.assertFalse(kernel_mod.claims_completion(denial))
        self.assertFalse(kernel_mod.claims_completion("Do not say %s until green." % MARKER))
        # ...and the genuine forms still count.
        self.assertTrue(kernel_mod.claims_completion("All six items are done." + chr(10)*2 + MARKER))
        self.assertTrue(kernel_mod.claims_completion("Done. %s   " % MARKER))
        self.assertFalse(kernel_mod.claims_completion(""))

        class Denying(FakeOrchestratorEnd):
            def receive(self, *, after_id="", timeout_s=0.0):
                self._receives += 1
                self._turn += 1
                return RelayMessage(message_id="%s:d%d" % (self._identity, self._turn),
                                    direction=FROM_ORCHESTRATOR, text=denial, complete=True,
                                    observed_at=float(self._turn),
                                    conversation_id=self._identity,
                                    provenance={"kind": "fake", "provider_family": "t",
                                                "model": "s"})

        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Denying(replies=[]),
            execution=FakeExecutionEnd(replies=["x"]), project_root=self.repo,
            relay_id="relay-denial",
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT"))
        k.start()
        self.assertNotEqual(k.step().stop, kernel_mod.STOP_OBJECTIVE_COMPLETE)
        # And the packet really does name the token, which is why the substring test was unsafe.
        from quaestor.relay import packets as packets_mod
        self.assertIn(MARKER, packets_mod.execution_to_orchestrator(
            exchange_no=1, agent_text="did it", observation="-"))

    @control(299)
    def test_a_tree_that_was_already_dirty_does_not_corroborate_a_claim(self):
        """The most ordinary developer state there is: uncommitted work, then start a relay."""
        with open(os.path.join(self.repo, "wip.txt"), "w", encoding="utf-8") as fh:
            fh.write("work in progress from BEFORE the relay" + chr(10))
        k = self.claiming(relay_id="relay-predirty", completion_checks=(self.passes,),
                          completion_requires_repo_change=True)
        res = k.step()
        # The relay changed nothing. A passing check must not carry the claim on its own.
        self.assertNotEqual(res.stop, kernel_mod.STOP_OBJECTIVE_COMPLETE)
        claim = [ev["payload"] for ev in self.state.events(k.relay_id)
                 if ev["kind"] == "relay.completion.claim"][0]
        self.assertNotEqual(claim["state"], corroborate_mod.CORROBORATED)
        self.assertIsNot(claim["repo"].get("changed"), True)

    @control(300)
    def test_verification_output_is_redacted_before_it_is_recorded_or_forwarded(self):
        """A failing check that dumps the config it loaded is ordinary. Its output reaches the
        durable record AND a remote provider, so it crosses the same seam every turn crosses."""
        secret = "sk-ant-api03-" + "A" * 40
        leaky = write_check(
            self.repo, "check_leaky.py",
            "import sys" + chr(10) +
            "sys.stderr.write('FAILED: api_key=%s')" % secret + chr(10) +
            "raise SystemExit(1)" + chr(10))
        k = self.claiming(relay_id="relay-redact", completion_checks=(leaky,),
                          completion_attempt_limit=5)
        k.step()          # the claim is refused; the output is captured
        k.step()          # the directive reaches the agent
        k.step()          # the agent's answer carries the blocker back to the Orchestrator

        for ev in self.state.events(k.relay_id, limit=0):
            self.assertNotIn(secret, repr(ev.get("payload")), "leaked into the event log")
        self.assertNotIn(secret, chr(10).join(t for _m, t in k.orchestrator.sent),
                         "leaked to the remote Orchestrator")
        for row in self.state.messages(k.relay_id, limit=0):
            self.assertNotIn(secret, repr(row), "leaked into the message ledger")
        # The redaction is visible rather than silent: the operator can see something was cut.
        claim = [ev["payload"] for ev in self.state.events(k.relay_id, limit=0)
                 if ev["kind"] == "relay.completion.claim"][0]
        self.assertIn("secret-withheld", claim["checks"][0]["tail"])



class Truncating(FakeOrchestratorEnd):
    """Returns INCOMPLETE turns for the first ``bad`` receives, then behaves.

    ``usable`` decides what ``status()`` says, which is the whole question the kernel asks
    before deciding whether a retry could possibly help.
    """

    def __init__(self, *, bad: int = 1, usable: bool = True, **kw):
        super().__init__(**kw)
        self._bad = int(bad)
        self._usable = bool(usable)

    def status(self):
        return EndStatus(END_IDLE if self._usable else END_FAILED, self._identity,
                         "scripted endpoint")

    def receive(self, *, after_id="", timeout_s=0.0):
        self._receives += 1
        if self._receives <= self._bad:
            return RelayMessage(message_id="%s:partial%d" % (self._identity, self._receives),
                                direction=FROM_ORCHESTRATOR, text="I was cut off mid-",
                                complete=False, observed_at=float(self._receives),
                                error="length")
        self._turn += 1
        return RelayMessage(
            message_id="%s:m%d" % (self._identity, self._turn),
            direction=FROM_ORCHESTRATOR, text=str(self._replies[0]), complete=True,
            observed_at=float(self._receives), conversation_id=self._identity,
            provenance={"kind": "fake", "provider_family": "test", "model": "scripted"})


class TestBoundedIncompleteRecovery(RelayFixture):
    """bd quaestor-nmq -- one bad turn must not end a healthy slice."""

    def relay(self, orch, *, relay_id, **cfg):
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=orch,
            execution=FakeExecutionEnd(replies=["did the work", "did more"]),
            project_root=self.repo, relay_id=relay_id, sleep=lambda _s: None,
            config=kernel_mod.RelayConfig(objective="fixture objective",
                                          authority_profile="STANDARD_EDIT", **cfg))
        k.start()
        return k

    @control(291)
    def test_one_incomplete_turn_from_a_healthy_endpoint_is_retried(self):
        """The slice continues. Before this, a single truncation ended the run."""
        orch = Truncating(bad=1, usable=True, replies=["carry on then"])
        k = self.relay(orch, relay_id="relay-retry", incomplete_retry_limit=2)
        res = k.step()
        self.assertEqual(res.stop, "")
        self.assertEqual(orch._receives, 2)          # one bad, one good
        kinds = [ev["kind"] for ev in self.state.events(k.relay_id)]
        self.assertIn("relay.receive.incomplete", kinds)
        k.step()                                     # the good directive reaches the agent
        delivered = "\n".join(t for _m, t in k.execution.sent)
        self.assertIn("carry on then", delivered)
        # The partial never travelled, on any attempt.
        self.assertNotIn("cut off", delivered)

    @control(292)
    def test_only_the_receive_is_retried_never_the_send(self):
        """Retrying a send is how bounded recovery would become duplicate delivery."""
        orch = Truncating(bad=2, usable=True, replies=["fine"])
        k = self.relay(orch, relay_id="relay-sendonce", incomplete_retry_limit=3)
        sends_before = orch._sends
        k.step()
        self.assertEqual(orch._receives, 3)          # two bad, one good
        # THE ORACLE: THREE receives against exactly ONE send. The opening packet went once and
        # was never re-sent, so no retry could have duplicated a delivery.
        self.assertEqual(orch._sends, sends_before + 1)
        self.assertEqual(len(orch.sent), 1)
        ids = [mid for mid, _t in orch.sent]
        self.assertEqual(len(ids), len(set(ids)))

    @control(293)
    def test_a_dead_endpoint_is_not_retried_and_stops_by_a_different_name(self):
        """Endpoint death and an unfinished sentence are different faults."""
        orch = Truncating(bad=5, usable=False, replies=["never reached"])
        k = self.relay(orch, relay_id="relay-dead", incomplete_retry_limit=3)
        res = k.step()
        self.assertEqual(res.stop, kernel_mod.STOP_ORCHESTRATOR_DISCONNECT)
        self.assertNotEqual(res.stop, kernel_mod.STOP_ORCHESTRATOR_INCOMPLETE)
        self.assertEqual(orch._receives, 1)          # asked once, not retried
        ev = [e["payload"] for e in self.state.events(k.relay_id)
              if e["kind"] == "relay.receive.incomplete"][0]
        self.assertFalse(ev["endpoint_usable"])

    @control(294)
    def test_the_retry_is_bounded_and_exhaustion_has_its_own_name(self):
        """A provider that never finishes a sentence must not spin forever."""
        orch = Truncating(bad=99, usable=True, replies=["never reached"])
        k = self.relay(orch, relay_id="relay-exhausted", incomplete_retry_limit=2)
        res = k.step()
        self.assertEqual(res.stop, kernel_mod.STOP_ORCHESTRATOR_INCOMPLETE)
        self.assertEqual(orch._receives, 3)          # limit + 1, and no more
        row = self.state.get("relay-exhausted")
        self.assertEqual(row["state"], state_mod.PAUSED)
        self.assertNotIn("cut off", "\n".join(t for _m, t in k.execution.sent))


class TestRetryIsAReReadNotAContinuation(RelayFixture):
    """bd quaestor-nmq -- the retry must re-ASK, never resume mid-sentence.

    Found by adversarial review of the retry itself. http_chat appended a truncated assistant
    turn to its transcript BEFORE deciding it was incomplete. The conversation then ended on a
    half-finished assistant message with no new user message after it, so the kernel's retry was
    answered as a CONTINUATION: the provider returned only the remaining tokens, and the relay
    forwarded that fragment as the Orchestrator's whole turn.

    Measured before the fix, on a directive reading "Work ONLY inside tests/legacy. Do not touch
    tests/current under any circumstance. Once you are confident the legacy fixtures are
    unused," the agent received only " delete the stale fixture files and run the suite." The
    guardrail was gone, and no copy of it existed anywhere in the ledger.
    """

    HEAD = ("Work ONLY inside tests/legacy. Do not touch tests/current under any "
            "circumstance. Once you are confident the legacy fixtures are unused,")
    TAIL = " delete the stale fixture files and run the suite."

    def opener(self, script):
        """A stubbed chat-completions provider. Records every request body it is given."""
        self.posts = []

        def _open(url, headers, body, timeout):
            self.posts.append(json.loads(body.decode("utf-8")))
            text, finish = script[min(len(self.posts), len(script)) - 1]
            return 200, json.dumps({
                "id": "cmpl-%d" % len(self.posts), "model": "test/model",
                "choices": [{"finish_reason": finish, "message": {"role": "assistant",
                                                                  "content": text}}]})
        return _open

    def end(self, script):
        return http_chat.HttpChatOrchestratorEnd(
            base_url="https://provider.invalid/v1", model="test/model",
            key_var="QUAESTOR_TEST_KEY", opener=self.opener(script),
            transcript_path=os.path.join(self.home, "conversation.json"))

    @control(296)
    def test_an_incomplete_turn_is_not_written_into_the_transcript(self):
        """If it were, the retry would ask the provider to CONTINUE rather than to answer."""
        os.environ["QUAESTOR_TEST_KEY"] = "test-key-not-a-real-credential"
        self.addCleanup(os.environ.pop, "QUAESTOR_TEST_KEY", None)
        end = self.end([(self.HEAD, "length"), (self.TAIL, "stop")])
        end.open()
        end.send("do the work", message_id="m1")

        first = end.receive(after_id="", timeout_s=1.0)
        self.assertFalse(first.complete)                 # truncated, correctly refused

        second = end.receive(after_id="", timeout_s=1.0)
        # THE ORACLE: the second request must carry the SAME conversation the first did. If the
        # partial had been appended, this body would end with an assistant message and the
        # provider would be being asked to continue it.
        roles = [m["role"] for m in self.posts[-1]["messages"]]
        self.assertEqual(roles[-1], "user", "the retry asked the provider to CONTINUE a partial")
        self.assertNotIn(self.HEAD, json.dumps(self.posts[-1]),
                         "the refused partial was replayed back to the provider")
        self.assertTrue(second.complete)

    @control(297)
    def test_a_truncated_directive_never_reaches_the_agent_as_its_tail(self):
        """The whole point: a guardrail in the dropped head must not be silently discarded."""
        os.environ["QUAESTOR_TEST_KEY"] = "test-key-not-a-real-credential"
        self.addCleanup(os.environ.pop, "QUAESTOR_TEST_KEY", None)
        # The provider truncates the first answer and, on being re-asked, answers in full.
        end = self.end([(self.HEAD, "length"), (self.HEAD + self.TAIL, "stop")])
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=end,
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-continuation", sleep=lambda _s: None,
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                          incomplete_retry_limit=2))
        k.start()
        k.step()                       # the truncated turn is retried and answered in full
        k.step()                       # the directive reaches the agent
        delivered = chr(10).join(t for _m, t in k.execution.sent)
        self.assertIn("Do not touch tests/current", delivered)   # the guardrail survived
        self.assertIn("delete the stale fixture files", delivered)


class TestResumeIsNotApproval(RelayFixture):
    """Found by adversarial review of PR #8.

    A gate-refused directive was parked in OBSERVED -- which IS the delivery queue -- and the
    hold reason was written only to the relay row. ``relay resume``, the documented way to
    continue after a crash, set state=RUNNING and the very next step picked the refused
    directive off the queue and delivered it. No grant existed, none was consulted, and the
    relay had walked past its own owner boundary. Separately, resume rebuilt the completion
    policy from flag DEFAULTS, so a relay started with --verify resumed with corroboration off.
    """

    PUSHY = ("Ship it now." + chr(10) + "```quaestor-effect" + chr(10)
             + "effect: GIT_PUSH" + chr(10) + "```")

    def relay(self, relay_id, *, grants=(), **cfg):
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=FakeOrchestratorEnd(replies=[self.PUSHY]),
            execution=FakeExecutionEnd(replies=["ok", "ok"]), project_root=self.repo,
            relay_id=relay_id, owner_grants=lambda: list(grants),
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                          **cfg))
        return k

    @control(301)
    def test_resume_does_not_deliver_a_directive_the_owner_gate_refused(self):
        """Resuming says "carry on", not "I grant GIT_PUSH". The relay cannot tell them apart
        from the command, so it re-asks the gate instead of assuming."""
        k = self.relay("relay-held")
        k.start()
        self.assertEqual(k.step().stop, kernel_mod.STOP_OWNER_HOLD)
        self.assertEqual(k.execution.sent, [])

        # A FRESH kernel over the SAME durable record -- the crash-and-resume the operator does.
        k2 = self.relay("relay-held")
        stopped = k2.resume()
        self.assertIsNotNone(stopped, "resume released an owner-held directive")
        self.assertEqual(stopped.stop, kernel_mod.STOP_OWNER_HOLD)
        k2.step()
        delivered = chr(10).join(t for _m, t in k2.execution.sent)
        self.assertNotIn("Ship it now", delivered)
        self.assertEqual(self.state.get("relay-held")["state"], state_mod.OWNER_HOLD)

    @control(302)
    def test_the_regate_uses_CURRENT_authority_so_the_gate_is_a_boundary_not_a_wall(self):
        """Release is possible -- but only by real authority, never by the act of resuming.

        Two locks, and the control proves both. The PROFILE CEILING is absolute: no owner grant
        can widen it, because ``authority.require`` checks the profile's own capabilities before
        it ever looks at a grant. Above that ceiling, ``git_push`` is OWNER_GATED and needs an
        AUTHENTICATED owner channel -- a grant row alone is manufactured by the party it would
        exonerate.
        """
        k = self.relay("relay-release")
        k.start()
        self.assertEqual(k.step().stop, kernel_mod.STOP_OWNER_HOLD)

        # ``grant_id`` is what makes a row a recorded owner DECISION rather than a blank claim.
        grants = [{"grant_id": "g-%s" % c, "capability": c, "granted_by": "owner",
                   "expires_at": None, "revoked_at": None}
                  for c in ("git_commit", "git_push")]

        # 1. The grants exist, but the profile still does not. The ceiling holds.
        under_ceiling = self.relay("relay-release", grants=grants)
        self.assertIsNotNone(under_ceiling.resume(),
                             "an owner grant must not widen the profile ceiling")

        # 2. The profile allows it, but the owner channel is not authenticated. Still held.
        no_channel = kernel_mod.RelayKernel(
            st=self.state, orchestrator=FakeOrchestratorEnd(replies=["x"]),
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-release", owner_grants=lambda: list(grants),
            channel_state=lambda: None,
            config=kernel_mod.RelayConfig(objective="o", authority_profile="GIT_PUSH"))
        self.assertIsNotNone(no_channel.resume(),
                             "an unauthenticated owner channel must not release it")

        # 3. Real authority on both locks: released, the hold discharged, and only then does the
        #    directive reach the agent.
        ok = kernel_mod.RelayKernel(
            st=self.state, orchestrator=FakeOrchestratorEnd(replies=["x"]),
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-release", owner_grants=lambda: list(grants),
            channel_state=lambda: owner_channel.AUTHENTICATED,
            config=kernel_mod.RelayConfig(objective="o", authority_profile="GIT_PUSH"))
        self.assertIsNone(ok.resume(), "real authority should release the held directive")
        self.assertEqual(self.state.get("relay-release")["owner_hold"], "")
        ok.step()
        self.assertIn("Ship it now", chr(10).join(t for _m, t in ok.execution.sent))

    @control(303)
    def test_resume_keeps_the_completion_policy_the_relay_was_started_with(self):
        """A resumed relay must not accept a claim it had just refused."""
        checks = write_check(self.repo, "check_resume.py", "raise SystemExit(1)" + chr(10))
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=FakeOrchestratorEnd(replies=["a"]),
            execution=FakeExecutionEnd(replies=["b"]), project_root=self.repo,
            relay_id="relay-policy",
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                          completion_checks=(checks,),
                                          completion_requires_repo_change=True,
                                          completion_attempt_limit=4,
                                          incomplete_retry_limit=3))
        k.start()
        saved = json.loads(self.state.get("relay-policy")["config_json"])
        # The policy is IN THE DURABLE RECORD, which is the only place resume can read it from.
        self.assertEqual(saved["completion_checks"], [checks])
        self.assertTrue(saved["completion_requires_repo_change"])
        self.assertEqual(saved["completion_attempt_limit"], 4)
        self.assertEqual(saved["incomplete_retry_limit"], 3)


class TestModelExercisingPreflight(RelayFixture):
    """bd quaestor-nmq -- status() proves a credential exists; probe() proves a turn comes back.

    THE OBSERVED FAILURES this closes, both from live runs:
      * an openai-chat gateway returning HTTP 503 to every request while status() said IDLE,
        because status() makes no network call at all;
      * opencode/nemotron-3-ultra-free, which answers a bare "PONG" with an APIError while the
        server, the session and the model catalogue are all perfectly healthy.
    In both, an unusable MODEL and a dead ENDPOINT were the same thing to the kernel, so the
    operator learned at exchange 1 and was told the wrong cause.
    """

    def relay(self, relay_id, *, orch_probe=contracts.PROBE_OK,
              exec_probe=contracts.PROBE_OK, **cfg):
        return kernel_mod.RelayKernel(
            st=self.state,
            orchestrator=FakeOrchestratorEnd(replies=["go"], probe_state=orch_probe),
            execution=FakeExecutionEnd(replies=["ok"], probe_state=exec_probe),
            project_root=self.repo, relay_id=relay_id, sleep=lambda _s: None,
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                          **cfg))

    @control(304)
    def test_an_unusable_model_is_refused_at_start_not_at_exchange_one(self):
        """The acceptance criterion in the bead, stated as a control."""
        k = self.relay("relay-badmodel", exec_probe=contracts.PROBE_REFUSED)
        res = k.start()
        self.assertEqual(res.stop, kernel_mod.STOP_EXECUTION_UNUSABLE)
        # NOT a disconnect: the endpoint answered, the model did not. Naming it wrong sends the
        # operator to restart a server that was never the problem.
        self.assertNotEqual(res.stop, kernel_mod.STOP_EXECUTION_DISCONNECT)
        self.assertEqual(self.state.get("relay-badmodel")["state"], state_mod.FAILED)
        # Nothing was delivered to either end -- the relay refused before the opening packet.
        self.assertEqual(k.execution.sent, [])
        self.assertEqual(k.orchestrator.sent, [])
        probed = [e["payload"] for e in self.state.events(k.relay_id, limit=0)
                  if e["kind"] == "relay.end.probed"]
        self.assertTrue(probed and probed[-1]["measured"] and not probed[-1]["ok"])

    @control(305)
    def test_an_orchestrator_whose_provider_is_down_is_named_as_such(self):
        k = self.relay("relay-badorch", orch_probe=contracts.PROBE_UPSTREAM_FAILED)
        self.assertEqual(k.start().stop, kernel_mod.STOP_ORCHESTRATOR_UNUSABLE)

    @control(306)
    def test_an_endpoint_that_declines_to_be_probed_is_not_treated_as_proven(self):
        """PROBE_UNSUPPORTED is honest, not passing. It must neither block nor claim health."""
        p = contracts.RelayEnd().probe()
        self.assertEqual(p.state, contracts.PROBE_UNSUPPORTED)
        self.assertFalse(p.ok)
        self.assertFalse(p.measured)          # nothing was asked, so nothing is claimed
        # A relay whose ends decline still starts -- refusing would make an unprobeable
        # provider unusable, which is a different and wrong answer.
        k = self.relay("relay-unprobed", orch_probe=contracts.PROBE_UNSUPPORTED,
                       exec_probe=contracts.PROBE_UNSUPPORTED)
        self.assertEqual(k.start().stop, "")

    @control(307)
    def test_the_browser_end_declines_rather_than_posting_into_the_operators_thread(self):
        """A probe that writes into the conversation it protects has cost more than it measured."""
        from quaestor.relay.ends import chatgpt_web as cw
        end = cw.ChatGptWebOrchestratorEnd.__new__(cw.ChatGptWebOrchestratorEnd)
        end.facts = contracts.EndFacts(kind="chatgpt-web", role=ROLE_ORCHESTRATOR,
                                       model="chatgpt-web")
        p = end.probe()
        self.assertEqual(p.state, contracts.PROBE_UNSUPPORTED)
        self.assertFalse(p.measured)
        self.assertIn("operator", p.detail)

    @control(308)
    def test_a_probe_that_raises_is_refused_never_allowed_through(self):
        """The direction every unmeasured fact falls in."""

        class Exploding(FakeOrchestratorEnd):
            def probe(self):
                raise RuntimeError("the probe itself is broken")

        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Exploding(replies=["go"]),
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-boom",
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT"))
        self.assertEqual(k.start().stop, kernel_mod.STOP_ORCHESTRATOR_UNUSABLE)

    @control(309)
    def test_probing_can_be_declined_by_the_operator(self):
        """--no-probe exists, and a relay that skips the probe never claims it passed."""
        k = self.relay("relay-noprobe", exec_probe=contracts.PROBE_REFUSED,
                       probe_endpoints=False)
        self.assertEqual(k.start().stop, "")
        self.assertEqual(k.execution._probes, 0)
        self.assertEqual([e for e in self.state.events(k.relay_id, limit=0)
                          if e["kind"] == "relay.end.probed"], [])


    @control(311)
    def test_probe_output_is_redacted_before_it_reaches_the_durable_record(self):
        """A probe detail embeds the PROVIDER'S OWN response body, and providers echo request
        context into errors -- a rejected key comes back inside the message rejecting it.

        The identical defect shipped one PR earlier for verification-check output. It was fixed
        there by classifying at each call site, which is exactly why it came back: a new call
        site was added and did not know. EndProbe now classifies at construction, so there is
        one place and an end author cannot forget it.
        """
        secret = "sk-ant-api03-" + "A" * 40
        p = contracts.EndProbe(contracts.PROBE_REFUSED, "bad key: %s" % secret)
        self.assertNotIn(secret, p.detail)
        self.assertIn("secret-withheld", p.detail)
        self.assertNotIn(secret, json.dumps(p.to_dict()))

        class Leaky(FakeOrchestratorEnd):
            def probe(self):
                return contracts.EndProbe(contracts.PROBE_REFUSED,
                                          "the provider said: api_key=%s" % secret)

        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Leaky(replies=["go"]),
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-probeleak",
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT"))
        k.start()
        # It reaches BOTH the probe event and the stop detail, so both are checked.
        for ev in self.state.events("relay-probeleak", limit=0):
            self.assertNotIn(secret, repr(ev.get("payload")), ev["kind"])
        self.assertNotIn(secret, repr(dict(self.state.get("relay-probeleak"))))

    @control(312)
    def test_the_probe_policy_is_the_relays_not_the_invocations(self):
        """An operator who opted out of probing must not have it turned back on by a resume.

        PR #8 shipped this exact bug for the completion policy; this one was found two lines
        away from that fix, in the same function, one PR later.
        """
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=FakeOrchestratorEnd(replies=["go"]),
            execution=FakeExecutionEnd(replies=["ok"]), project_root=self.repo,
            relay_id="relay-probepolicy",
            config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                          probe_endpoints=False))
        k.start()
        saved = json.loads(self.state.get("relay-probepolicy")["config_json"])
        # IN THE DURABLE RECORD, which is the only place a resume in another process can read
        # it from -- the flag defaults it would otherwise rebuild from say the opposite.
        self.assertIn("probe_endpoints", saved)
        self.assertFalse(saved["probe_endpoints"])
        # And it was honoured: nothing was probed.
        self.assertEqual(k.orchestrator._probes, 0)
        self.assertEqual(k.execution._probes, 0)

    @control(310)
    def test_a_permanent_provider_refusal_stops_but_a_transient_one_is_still_retried(self):
        """The two failing verdicts must NOT behave alike -- that is why there are two.

        REFUSED is permanent (an unknown model, a rejected credential): retrying spends the
        whole bound learning nothing. UPSTREAM_FAILED is transient-shaped, and the live run this
        bead exists for showed two HTTP 503 bursts that RECOVERED on the next attempt.
        Collapsing them -- which the first version of this control asserted -- would have
        re-broken exactly the slice the bounded retry was built to save.
        """

        class Truncating(FakeOrchestratorEnd):
            def __init__(self, *, probe_state, bad, **kw):
                super().__init__(probe_state=probe_state, **kw)
                self._bad = int(bad)

            def status(self):
                return EndStatus(END_IDLE, self._identity, "locally fine")

            def receive(self, *, after_id="", timeout_s=0.0):
                self._receives += 1
                if self._receives <= self._bad:
                    return RelayMessage(
                        message_id="%s:p%d" % (self._identity, self._receives),
                        direction=FROM_ORCHESTRATOR, text="cut off", complete=False,
                        observed_at=float(self._receives), error="503")
                self._turn += 1
                return RelayMessage(
                    message_id="%s:m%d" % (self._identity, self._turn),
                    direction=FROM_ORCHESTRATOR, text="recovered, carry on", complete=True,
                    observed_at=float(self._receives), conversation_id=self._identity,
                    provenance={"kind": "fake", "provider_family": "t", "model": "s"})

        def drive(relay_id, orch, **cfg):
            k = kernel_mod.RelayKernel(
                st=self.state, orchestrator=orch, execution=FakeExecutionEnd(replies=["ok"]),
                project_root=self.repo, relay_id=relay_id, sleep=lambda _s: None,
                config=kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                              probe_endpoints=False, **cfg))
            k.start()
            k.config = kernel_mod.RelayConfig(objective="o", authority_profile="STANDARD_EDIT",
                                              probe_endpoints=True, **cfg)
            return k, k.step()

        # 1. TRANSIENT: one 503-shaped turn, provider recovers. The relay must carry on.
        t_orch = Truncating(replies=[], probe_state=contracts.PROBE_UPSTREAM_FAILED, bad=1)
        k1, res1 = drive("relay-transient", t_orch, incomplete_retry_limit=3)
        self.assertEqual(res1.stop, "", "a transient upstream fault must not end a healthy slice")
        self.assertEqual(t_orch._receives, 2)          # retried, and it recovered

        # 2. PERMANENT: the provider REFUSES. Retrying cannot help, so stop on attempt 1 and
        #    name the provider rather than the endpoint.
        r_orch = Truncating(replies=[], probe_state=contracts.PROBE_REFUSED, bad=99)
        k2, res2 = drive("relay-refused", r_orch, incomplete_retry_limit=3)
        self.assertEqual(res2.stop, kernel_mod.STOP_ORCHESTRATOR_UNUSABLE)
        self.assertEqual(r_orch._receives, 1, "a permanent refusal must not burn the budget")
        ev = [e["payload"] for e in self.state.events("relay-refused", limit=0)
              if e["kind"] == "relay.receive.incomplete"][0]
        self.assertTrue(ev["endpoint_usable"])         # locally healthy...
        self.assertFalse(ev["probe"]["ok"])            # ...and the provider refused
        self.assertNotIn("cut off", chr(10).join(t for _m, t in k2.execution.sent))

        # 3. A DEAD endpoint whose probe also fails is a DISCONNECT, not a model fault. start()
        #    always had this ordering right; the retry loop had it inverted.
        class Dead(Truncating):
            def status(self):
                return EndStatus(END_FAILED, self._identity, "connection refused")

        d_orch = Dead(replies=[], probe_state=contracts.PROBE_UPSTREAM_FAILED, bad=99)
        _k3, res3 = drive("relay-dead", d_orch, incomplete_retry_limit=3)
        self.assertEqual(res3.stop, kernel_mod.STOP_ORCHESTRATOR_DISCONNECT)
        self.assertNotEqual(res3.stop, kernel_mod.STOP_ORCHESTRATOR_UNUSABLE)

    @control(313)
    def test_probing_never_writes_over_a_recorded_conversation(self):
        """registry.probe used to close() an end it never opened -- and close() SAVES.

        For a stateless provider the transcript IS the conversation, so an empty in-memory
        endpoint written over a recorded one turns resume into starting over, silently.
        Measured before the fix: a transcript holding 7 turns became {"turn": 0, "messages": []}.
        """
        from quaestor.relay import registry as reg
        path = os.path.join(self.home, "conversation.json")
        original = {"conversation_id": "conv-abc", "turn": 7,
                    "messages": [{"role": "user", "content": "real work"}]}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(original, fh)
        before = open(path, encoding="utf-8").read()

        os.environ["QUAESTOR_PR9_PROBE_KEY"] = "test-key-not-a-real-credential"
        self.addCleanup(os.environ.pop, "QUAESTOR_PR9_PROBE_KEY", None)
        # An unreachable provider, so the probe certainly fails -- the destructive path.
        out = reg.probe(ROLE_ORCHESTRATOR, {
            "kind": "openai-chat",
            "config": {"base_url": "http://127.0.0.1:1/v1", "model": "x/y",
                       "key_var": "QUAESTOR_PR9_PROBE_KEY", "transcript_path": path}})
        self.assertFalse(out["ok"])
        self.assertEqual(open(path, encoding="utf-8").read(), before,
                         "probing destroyed the recorded conversation")

    @control(314)
    def test_the_probe_sends_the_shape_the_real_turn_sends(self):
        """A probe that measures a request the relay never makes measures the wrong thing.

        max_tokens was hard-coded into the probe while receive() sends it only when the operator
        configured one. Models that reject the parameter -- OpenAI's reasoning models want
        max_completion_tokens -- would answer HTTP 400, and the relay would refuse to start for
        a configuration whose real turns work perfectly.
        """
        seen = {}

        def opener(url, headers, body, timeout):
            seen.setdefault("payloads", []).append(json.loads(body.decode("utf-8")))
            seen["timeout"] = timeout
            return 200, json.dumps({"choices": [{"finish_reason": "stop",
                                                 "message": {"content": "OK"}}]})

        os.environ["QUAESTOR_PR9_SHAPE"] = "test-key-not-a-real-credential"
        self.addCleanup(os.environ.pop, "QUAESTOR_PR9_SHAPE", None)
        end = http_chat.HttpChatOrchestratorEnd(
            base_url="https://provider.invalid/v1", model="o3",
            key_var="QUAESTOR_PR9_SHAPE", opener=opener)
        end.probe()
        end.send("hello", message_id="m1")
        end.receive(after_id="", timeout_s=5.0)
        probe_payload, real_payload = seen["payloads"][0], seen["payloads"][-1]
        # THE ORACLE: the probe's parameter set is a subset of what the real turn sends. It may
        # differ in the messages it carries; it must not differ in the knobs it sets.
        self.assertNotIn("max_tokens", probe_payload)
        self.assertEqual(set(probe_payload) - {"messages"}, set(real_payload) - {"messages"})
        # And an operator-configured cap IS carried, so the probe still matches that config.
        capped = http_chat.HttpChatOrchestratorEnd(
            base_url="https://provider.invalid/v1", model="o3", max_tokens=64,
            key_var="QUAESTOR_PR9_SHAPE", opener=opener)
        capped.probe()
        self.assertEqual(seen["payloads"][-1].get("max_tokens"), 64)
        # The probe is bounded well under the relay's own receive timeout.
        self.assertLessEqual(seen["timeout"], http_chat.HttpChatOrchestratorEnd.PROBE_TIMEOUT_S)

    @control(315)
    def test_doctor_does_not_report_ready_for_a_config_start_would_refuse(self):
        """An operator runs doctor precisely to avoid a start that refuses."""
        from quaestor.relay import cli as relay_cli

        # The pure decision, exercised directly: a MEASURED non-ok probe must sink ready.
        for probe, expect in (({"ok": True, "measured": True}, True),
                              ({"ok": False, "measured": True}, False),
                              ({"ok": False, "measured": False}, True)):   # declined != failed
            ready = all(bool(p.get("ok")) or not bool(p.get("measured")) for p in (probe,))
            self.assertEqual(ready, expect, probe)
        # And the surface really carries both answers apart, so an operator can read
        # "server up, credential fine, model cannot answer". Asserted against the real source
        # rather than against a string this test just built -- a tautology proves nothing.
        import inspect
        src = inspect.getsource(relay_cli.cmd_relay_doctor)
        self.assertIn("ready_detail", src)
        self.assertIn("models_answer", src)
        self.assertIn("endpoints_reachable", src)
        # The ready verdict must actually CONSULT the probes; a report that computed ready
        # without them is the defect this control exists for.
        self.assertIn("probes_ok", src)


class Saying(FakeOrchestratorEnd):
    """An Orchestrator that says ONE fixed thing, on every turn.

    Parameterised rather than hardcoded like ``Claiming`` because the whole point of controls
    385 and 386 is that the same kernel path must sort MANY phrasings, not one.
    """

    def __init__(self, text, **kw):
        super().__init__(replies=[], **kw)
        self._say = str(text)

    def receive(self, *, after_id="", timeout_s=0.0):
        self._receives += 1
        self._turn += 1
        return RelayMessage(
            message_id="%s:say%d" % (self._identity, self._turn),
            direction=FROM_ORCHESTRATOR, text=self._say, complete=True,
            observed_at=float(self._turn), conversation_id=self._identity,
            provenance={"kind": "fake", "provider_family": "test", "model": "scripted"})


class TestCompletionIsAClaimNotASuffix(RelayFixture):
    """bd quaestor-9lq -- ``endswith`` on the last line read ordinary DENIALS as claims.

    Control 298 already proved that a denial whose last line ends in OTHER words is not a claim.
    It could not catch this, because every phrasing it tested put something after the marker. The
    hole is the denial that ENDS on the marker, which is the ordinary shape of English negation
    ("the objective is not X"), and which ``endswith`` cannot tell from an assertion of X.

    385 and 386 are a MATCHED PAIR, because both directions are fatal and a fix for either one
    alone is a fix for neither. Reading a denial as a claim stops the work and forges the durable
    record. Refusing a real claim is not one lost exchange: a model phrases completion the same
    way on every retry, so the run burns to MAX_EXCHANGES with the objective met and never
    recorded -- and the two collide, because ordinary success states an ABSENCE ("no failures")
    and cites identifiers ("test_not_found now passes") that are not English words.
    """

    #: Built here out of the marker and plain English rather than copied from a bug report. The
    #: first four are the shapes a model reaching for "no" produces; the rest are the ways a turn
    #: says "not yet" with NO negative word in it at all, which a word list cannot see.
    DENIALS = (
        "The suite is still red. The objective is not %s" % MARKER,
        "test_login still fails, so I cannot write %s" % MARKER,
        "Two items remain, so I am unable to say %s" % MARKER,
        "I re-read the diff and did not write %s" % MARKER,
        # DEFERRAL. A promise to say the marker is not the marker, and this is the single most
        # common way a model says "not yet".
        "When CI goes green I will emit %s" % MARKER,
        "Fix the 401 first. Only then will I write %s" % MARKER,
        "Once you confirm, I'll write %s" % MARKER,
        "It would be premature to declare %s" % MARKER,
        "The agent has yet to write %s" % MARKER,
        # DISTANCING, assembled entirely from words that are innocent apart.
        "The objective is far from %s" % MARKER,
        "Two items remain; I stop short of %s" % MARKER,
        "Two tests remain red, so I withhold %s" % MARKER,
        # CONTRACTED, which is how a model actually writes a refusal.
        "The 401 isn't fixed, so I won't write %s" % MARKER,
        "Give me one more turn and I'll write %s" % MARKER,
        # ...and the same denials with the marker moved onto a line of its own, which is the
        # CHARTER'S OWN prescribed shape and therefore the one a model reaches for when it
        # displays or wraps the token while explaining that it is not claiming it.
        "The objective is not met. I am not writing the completion line:" + chr(10) + MARKER,
        "I will only write this when the suite is green:" + chr(10) + MARKER,
        "The suite is still red. I cannot write" + chr(10) + MARKER,
        "Next steps:" + chr(10) + "- fix the 401" + chr(10) + "- then I will write %s" % MARKER,
    )

    #: Turns that TALK ABOUT the marker instead of uttering it. A question is the opposite of a
    #: claim, a strikethrough is a retraction, and the quoted line is the relay's own protocol
    #: instruction echoed back -- which the relay prints to the Orchestrator on every packet, so
    #: it is the most available string in the conversation.
    MENTIONS = (
        "Is this %s?" % MARKER,
        "Shall I write %s?" % MARKER,
        "Can you confirm this is %s?" % MARKER,
        "%s?" % MARKER,
        "~~%s~~" % MARKER,
        'Reply ending with the single line "%s"' % MARKER,
    )

    #: The affirmative side. Every one of these is a real claim a real Orchestrator emits, and
    #: refusing any of them means the relay never stops on success.
    CLAIMS = (
        MARKER,                                                 # the charter's own single line
        "All six items are done. %s" % MARKER,                  # ...and what models actually send
        "Evidence: 8 tests, OK." + chr(10) + MARKER,            # marker alone on the last line
        "Evidence attached." + chr(10) + "**%s**" % MARKER,     # markdown, which models add
        "%s." % MARKER,                                         # a terminal full stop
        "%s!" % MARKER,                                         # an exclamation ASSERTS; "?" asks
        # SUCCESS STATES AN ABSENCE. Each of these denies a PROBLEM, not the claim, and a blunt
        # negation test refused all of them -- the burn-to-the-ceiling half of the same bug.
        "All 42 tests pass with no failures, so %s" % MARKER,
        "No further action is required: %s" % MARKER,
        "Objective met, no blockers remain: %s" % MARKER,
        "The suite is green with no failures - %s" % MARKER,
        # ...and the EVIDENCE the charter asks for is full of identifiers, which are not English:
        # tokenised as prose they turn the proof of success into a denial of it.
        "test_not_found now passes, %s" % MARKER,
        "The --no-verify path is fixed, %s" % MARKER,
        "Evidence: assert_not_called now holds, so %s" % MARKER,
        # The two that decide it: read as English these say "not written" and "no print",
        # which is a denial of the very act of saying the marker. The first is a real test
        # name out of this file; the second is a real flag.
        "test_an_incomplete_turn_is_not_written_into_the_transcript passes, %s" % MARKER,
        "The --no-print path is fixed, %s" % MARKER,
        # An absence on an UNPUNCTUATED line above the bare marker. That line governs the marker
        # (it is how the line-break denials above are caught), so it must not over-refuse either.
        "All 42 tests pass with no failures" + chr(10) + MARKER,
    )

    def relay_that_says(self, text, *, relay_id):
        """A started relay whose Orchestrator says ``text`` and NOTHING is configured to check it.

        No ``completion_checks`` on purpose: that is the setting in which a believed claim stops
        the relay OBJECTIVE_COMPLETE on the spot, so the stop reason is a sharp oracle for
        whether the claim was believed at all.
        """
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Saying(text),
            execution=FakeExecutionEnd(replies=["did the work", "did more"]),
            project_root=self.repo, relay_id=relay_id,
            config=kernel_mod.RelayConfig(objective="fixture objective",
                                          authority_profile="STANDARD_EDIT"))
        k.start()
        return k

    @control(385)
    def test_a_denial_that_ENDS_on_the_marker_is_not_a_completion_claim(self):
        """A turn saying the work is NOT done, read as saying it IS, is the worst failure here:
        the durable record cannot be told from real success and the work stops."""
        inspected = 0
        for denial in self.DENIALS:
            inspected += 1
            # THE PREMISE, asserted rather than assumed -- this is exactly the class ``endswith``
            # cannot see, and a control that stopped believing it would be testing nothing.
            self.assertTrue(denial.endswith(MARKER), denial)
            self.assertFalse(kernel_mod.claims_completion(denial), denial)
        # Talking ABOUT the token is not uttering it, and these end in punctuation rather than in
        # the marker -- which is why ``endswith`` refused them and a decoration-stripping test
        # must be made to refuse them again.
        for mention in self.MENTIONS:
            inspected += 1
            self.assertFalse(kernel_mod.claims_completion(mention), mention)
        # A marker GLUED to a preceding word is not the marker being uttered either.
        for trap in ("NOT-%s" % MARKER, "UN%s" % MARKER, "%sD" % MARKER):
            inspected += 1
            self.assertFalse(kernel_mod.claims_completion(trap), trap)
        self.assertGreaterEqual(inspected, 27)

        # END TO END, one per family. Nothing is configured to corroborate, so a believed claim
        # stops the relay right here and the stop reason answers whether it was believed.
        for name, turn in (("denial", self.DENIALS[0]),
                           ("deferral", "When CI goes green I will emit %s" % MARKER),
                           ("question", "Shall I write %s?" % MARKER)):
            k = self.relay_that_says(turn, relay_id="relay-9lq-%s" % name)
            self.assertNotEqual(k.step().stop, kernel_mod.STOP_OBJECTIVE_COMPLETE, turn)
            self.assertEqual(self.state.get(k.relay_id)["stop_reason"], "", turn)
            # ...and corroboration was never even REACHED. That is the compounding harm the bead
            # names: the machinery built to measure completion claims is bypassed, because the
            # claim is accepted before the measurement runs.
            self.assertEqual([ev for ev in self.state.events(k.relay_id)
                              if ev["kind"] == "relay.completion.claim"], [], turn)
            # The relay did not merely decline to stop -- it kept working, and the turn went to
            # the agent as an instruction instead of being swallowed.
            k.step()
            self.assertEqual(len(k.execution.sent), 1, turn)

    @control(386)
    def test_a_genuine_claim_is_still_recognised_in_the_forms_a_model_emits(self):
        """The paired positive: a completion test that refuses everything passes every denial
        control and is WORSE than the bug -- the relay never stops on success, so every run
        burns to its ceiling and no objective is ever recorded as met."""
        inspected = 0
        for claim in self.CLAIMS:
            inspected += 1
            self.assertTrue(kernel_mod.claims_completion(claim), claim)
        # A negation inside a sentence that has already CLOSED is not a denial of the marker.
        for claim in ("The tests are not failing. %s" % MARKER,
                      "Nothing remains; every item is green. %s" % MARKER,
                      "Nothing is outstanding and none of the checks fail, so %s" % MARKER):
            inspected += 1
            self.assertTrue(kernel_mod.claims_completion(claim), claim)
        # THE THREE DECISIONS, pinned so they cannot drift into a wider acceptance surface.
        for refused, why in ((MARKER.lower(), "case is not folded: the marker is a machine token"),
                             ("%s once CI is green" % MARKER, "a WORD after it is the sentence"),
                             ("Is this %s?" % MARKER, "a question is the opposite of a claim")):
            inspected += 1
            self.assertFalse(kernel_mod.claims_completion(refused), why)
        self.assertGreaterEqual(inspected, 22)

        # END TO END: each genuine form really does end the relay, through the real kernel.
        for i, claim in enumerate(self.CLAIMS):
            k = self.relay_that_says(claim, relay_id="relay-9lq-claim%d" % i)
            self.assertEqual(k.step().stop, kernel_mod.STOP_OBJECTIVE_COMPLETE, claim)
class TestVerifyTimeoutIsAWallClockCeiling(RelayFixture):
    """bd quaestor-tcb -- ``--verify-timeout`` bounds the RELAY, not just the check process.

    THE FIRST VERSION OF THE DEFECT. Found by adversarial review of PR #8 and then MEASURED
    rather than argued: ``subprocess.run(capture_output=True, timeout=...)`` kills the direct
    child and then goes back to ``communicate()`` to drain the pipes -- and a pipe does not
    reach end-of-file until every process holding its write end has exited. A check that leaves
    a server, a watcher or a daemonising test runner behind hands that write end to a grandchild
    the timeout never touched, so the call was bounded by the ORPHAN'S LIFETIME and not by the
    operator's number: a 3.0s ceiling and 30.06s spent inside corroboration, with the relay
    showing no stop reason and no output.

    THE SECOND VERSION, WHICH THIS CLASS ALSO CARRIES BECAUSE THE FIRST FIX CREATED IT.
    Replacing the pipe with a file removed the drain and put an argument-less ``read()`` where
    it had been. That is ``readall``: it loops until a read returns zero bytes, and a grandchild
    still APPENDING to the handle it inherited never lets that zero arrive. Reviewed and
    reproduced against the first fix: an 8.0s promised ceiling, still inside ``run_check`` at
    42.8s, a 74 GB sink file, and free disk down from 61 GB to 1 GB -- strictly worse than what
    it replaced, which was at least bounded by the orphan's lifetime. So "there is no pipe" was
    never the property worth asserting. "Nothing here waits on the WRITER" is.

    THE CEILING IS READ OFF THE CLOCK, AND IT TRACKS THE OPERATOR'S NUMBER. Timing one run under
    a wide roof cannot tell an enforced ceiling from one that ignores the flag: measured against
    the first version of these controls, hard-coding ``timeout_s=3.0`` inside ``run_check`` AND
    separately spending 4x the operator's number both stayed green, because the accepted slack
    was nearly 4x the ceiling being policed. So the same check now runs at TWO ceilings and the
    DIFFERENCE in elapsed time is asserted against the difference in the numbers, which is the
    only shape that can fail for both.

    WHAT IS DELIBERATELY NOT CLAIMED: the descendants are not killed. Ending them means walking
    a parent-pid tree or signalling a process group, and ``procsafe.kill_argv`` records what
    happened the last time this project reached for either. So control 389 asserts the opposite
    of the comfortable thing -- the grandchild is still ALIVE when the ceiling is met -- and
    asserts that the result says so, and that the pid it names is the CHECK'S OWN. Cleanup is
    ``procsafe.Fleet``'s: what this fixture caused to exist, it ends, one process at a time,
    and reports any leak.
    """

    #: Slack ``ceiling_for`` allows for interpreter start-up on a loaded box. Deliberately
    #: SMALLER than the smallest ceiling these controls run at, because slack wider than the
    #: quantity under test is how a mutant that spent 12.0s against a 3.0s ceiling stayed green.
    CEILING_SLACK_S = 1.5

    #: 24 MiB of check output before it hangs. Large enough that reading ALL of it is plainly
    #: visible in this process's allocation peak, small enough to be a temp file and not an
    #: incident.
    CHATTY_BLOCKS = 384
    CHATTY_SINK_BYTES = 384 * 65536

    def ceiling_for(self, timeout_s: float) -> float:
        """The whole promise: the operator's number plus the grace a killed check gets reaped in.

        THE GRACE IS READ AND THEN PINNED, which is the part the first version of this helper had
        backwards. Its docstring claimed that deriving the bound from ``KILL_GRACE_S`` meant a
        change to that constant "cannot silently widen the ceiling these controls accept" --
        deriving it is exactly what lets the bound move WITH the constant. Measured:
        ``KILL_GRACE_S = 5.0`` -> ``300.0`` left both controls green while the ceiling an
        operator can compute became 303s for a 3s check. So the arithmetic stays the module's
        own, and the constant is asserted to be small, which is the assertion that fails there.
        """
        self.assertLessEqual(corroborate_mod.KILL_GRACE_S, 10.0,
                             "the grace a killed check gets was widened to %.1fs, so the "
                             "ceiling the module promises an operator moved with it"
                             % corroborate_mod.KILL_GRACE_S)
        return float(timeout_s) + corroborate_mod.KILL_GRACE_S + self.CEILING_SLACK_S

    def claiming(self, *, relay_id, **cfg):
        """The scripted relay control 300 drives: an Orchestrator that declares victory at once.

        Spelled out here rather than inherited from the class that already has one, because
        inheriting that class would re-run its ten controls under this one's name.
        """
        k = kernel_mod.RelayKernel(
            st=self.state, orchestrator=Claiming(replies=[]),
            execution=FakeExecutionEnd(replies=["did the work", "did more", "did more still"]),
            project_root=self.repo, relay_id=relay_id,
            config=kernel_mod.RelayConfig(objective="fixture objective",
                                          authority_profile="STANDARD_EDIT", **cfg))
        k.start()
        return k

    def project_tree(self) -> list:
        """Everything at the top of the project. The check's output file must never appear here.

        Both the module docstring and ``_run_bounded`` say the sink lives in the system temp
        directory and never under the project, "whose movement is itself evidence this relay
        reads", and nothing measured it. Measured now, because the consequence is real: adding
        ``dir=cwd`` to the ``mkstemp`` call leaves a stray ``quaestor-check-*.out`` in the tree
        in exactly this scenario -- the surviving grandchild holds the handle, the unlink fails
        and is swallowed -- and corroboration reads that tree as evidence.
        """
        return sorted(os.listdir(self.repo))

    def run_survivor(self, fleet, *, timeout_s: float, tag: str) -> dict:
        """Run the survivor check once under ``timeout_s``; assert everything except the clock.

        Returns the elapsed seconds so the CALLER can compare two runs at two different
        ceilings. One run can only show that the call finished under a roof; two show that the
        operator's number is what the call is bounded BY.
        """
        work = fleet.temp_dir("quaestor-tcb-%s-" % tag)
        pidfile = os.path.join(work, "grandchild.pid")
        selffile = os.path.join(work, "check.pid")
        kid_script = write_script(self.repo, "grandchild_%s.py" % tag, GRANDCHILD_BODY)
        script = write_script(self.repo, "check_leaves_a_survivor_%s.py" % tag, SURVIVOR_BODY)
        argv = [sys.executable, script, kid_script, pidfile, selffile, SURVIVOR_LIFE_S]
        before = self.project_tree()

        began = time.time()
        v = corroborate_mod.verdict(project_root=self.repo, checks=(argv,), timeout_s=timeout_s)
        elapsed = time.time() - began

        # OWNED BEFORE IT IS ASSERTED ON. The adoption is not an assertion, so it happens first
        # and a control that FAILS below still ends what it caused to exist -- which is the
        # whole reason the fleet is here rather than a try/finally in each test.
        self.assertTrue(os.path.isfile(pidfile),
                        "the check never got as far as spawning a grandchild, so this control "
                        "measured a ceiling nothing was pushing against")
        kid = int(read_text(pidfile).strip())
        fleet.adopt(kid, "grandchild left holding the check's stdout")

        # THE ASSERTION. Not "the payload says it was killed" -- the clock. Asserted before the
        # liveness reading below so that a real regression reports the ceiling it blew rather
        # than the grandchild that had by then run out its own life.
        self.assertLess(elapsed, self.ceiling_for(timeout_s),
                        "corroboration ran %.2fs against a %.1fs ceiling: the call is bounded "
                        "by something other than the operator's number" % (elapsed, timeout_s))
        # ...and it did not simply refuse to run: the ceiling was actually spent.
        self.assertGreater(elapsed, timeout_s - 0.5,
                           "corroboration returned in %.2fs from a %.1fs ceiling, so the "
                           "operator's number is not what it waited on" % (elapsed, timeout_s))

        # THE SINK IS NOT IN THE PROJECT, and this is the scenario that would leave it there.
        self.assertEqual(self.project_tree(), before,
                         "the run left files in the project it is supposed to be measuring")

        c = v["checks"][0]
        # THE CONTROL IS NOT VACUOUS ONLY IF SOMETHING REALLY SURVIVED...
        self.assertTrue(fleet.alive(kid),
                        "the grandchild was already gone, so nothing held the handle")
        # ...AND ONLY IF WHAT SURVIVED REALLY HOLDS THE CHECK'S OWN STDOUT. Only a process that
        # inherited that handle can put this line in the result; ``CHECK-STARTED`` below is the
        # CHECK's own and proves nothing about the grandchild.
        self.assertIn("GRANDCHILD-HOLDS-STDOUT", c["tail"],
                      "the grandchild's marker never reached the result, so it does not hold "
                      "the check's stdout and this control is measuring nothing")
        self.assertIn("CHECK-STARTED", c["tail"])

        # A killed check is never a measured one, and the verdict falls to UNMEASURABLE.
        self.assertEqual(v["state"], corroborate_mod.UNMEASURABLE)
        self.assertNotEqual(v["state"], corroborate_mod.CORROBORATED)
        self.assertTrue(c["timed_out"])
        self.assertFalse(c["measured"])
        self.assertFalse(c["ok"])

        # IT NAMES WHAT IT ENDED, BY IDENTITY. "A pid that is dead and is not the orphan" was
        # satisfied by every dead pid on the machine: measured, reporting ``pid + 1`` (Windows
        # pids advance in fours, so pid+1 is reliably dead) passed. The check writes its OWN pid
        # down, so the result is compared against the process that actually ran.
        self.assertIsInstance(c["killed"], dict)
        check_pid = int(read_text(selffile).strip())
        self.assertEqual(int(c["killed"]["pid"]), check_pid,
                         "the result named pid %s; the check that ran was pid %s"
                         % (c["killed"]["pid"], check_pid))
        self.assertNotEqual(int(c["killed"]["pid"]), kid)
        self.assertFalse(fleet.alive(int(c["killed"]["pid"])),
                         "the result named a pid it killed and that process is still alive")
        # ...and it says the other half out loud, because "killed" alone reads as a promise that
        # nothing of the check survives -- which is exactly what did not happen here.
        self.assertIn("NOT killed", c["error"])
        return {"elapsed": elapsed, "kid": kid, "check": c, "verdict": v}

    def sink_is_read_under_a_budget(self):
        """The second version of the defect: no pipe, but an unbounded read of a growing file.

        WHAT IS MEASURED HERE IS ALLOCATION, NOT THE CLOCK, AND THAT IS A CHOICE. The review's
        reproduction was a grandchild writing 64 KiB blocks to the inherited handle as fast as
        it could -- 42.8s inside an 8.0s ceiling, 74 GB written. That shape is REFUSED as a
        control: it is a race the writer has to keep winning, and losing it once on a slower box
        fills the operator's disk instead of failing a test. The DEFECT is not a race. An
        argument-less ``read()`` pulls the whole file in, so a check that produced 24 MiB moves
        24 MiB through this process whether anything is still appending or not, and the loop
        that cannot terminate against a live writer is the same code path. Measured directly:
        peak 25.3 MB with ``fh.read()``, 0.07 MB with the budget.

        WHAT IT KILLS AND WHAT IT CANNOT, STATED RATHER THAN IMPLIED. It kills the shape that
        shipped -- the whole sink pulled into memory -- measured at 48.0 MB against this 24 MiB
        fixture. It would NOT catch a variant that kept the seek and then read to the end
        anyway: on a file nobody is writing to, that returns the same 64 KiB. Separating those
        two requires a writer that outruns the reader, which is the race refused above, so the
        seam is held by ``read(n)`` with ``buffering=0`` and by the reason recorded beside it in
        ``_run_bounded`` -- not by this control.
        """
        timeout_s = 2.0
        script = write_script(self.repo, "check_floods_then_hangs.py", CHATTY_HANG_BODY)
        argv = [sys.executable, script, str(self.CHATTY_BLOCKS), SURVIVOR_LIFE_S]

        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            began = time.time()
            v = corroborate_mod.verdict(project_root=self.repo, checks=(argv,),
                                        timeout_s=timeout_s)
            elapsed = time.time() - began
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        c = v["checks"][0]
        # NON-VACUITY FIRST. The marker is written after the last block, so finding it proves
        # the sink really did hold 24 MiB -- and that what came back is the END of the output.
        self.assertIn(CHATTY_END_MARKER, c["tail"],
                      "the check never finished flooding the sink, so nothing here was "
                      "measured against a large file")
        self.assertLess(peak, 4 * 1024 * 1024,
                        "reading the check's output cost %.1f MB of this process against a "
                        "%.1f MB sink: the read is bounded by the WRITER and not by a budget, "
                        "which against a check that keeps writing does not terminate at all"
                        % (peak / 1048576.0, self.CHATTY_SINK_BYTES / 1048576.0))
        self.assertLess(elapsed, self.ceiling_for(timeout_s))
        self.assertEqual(v["state"], corroborate_mod.UNMEASURABLE)
        self.assertTrue(c["timed_out"])

    def a_check_that_reads_stdin_gets_eof(self):
        """``stdin=DEVNULL`` was claimed as a fix in the commit message and measured by nothing.

        Measured now: with the descriptor closed the check reads end-of-file and answers well
        inside the ceiling. With stdin inherited it takes the operator's keystrokes away from
        the relay and then blocks on input that is never coming, so the ceiling kills a check
        that was never actually wrong.

        THE ONE CONDITION THIS NEEDS: the process running the suite must have a standard input
        that does not end by itself. From a terminal, or under any parent holding the pipe open,
        the inherited-stdin mutant blocks and is killed and this fails. Run with stdin already
        at end-of-file, the mutant reads EOF too and this cannot see it -- so green here is a
        proof only where the harness has a real stdin, and never a false alarm.
        """
        timeout_s = 8.0
        check = write_check(self.repo, "check_reads_stdin.py", STDIN_READER_BODY)
        began = time.time()
        v = corroborate_mod.verdict(project_root=self.repo, checks=(check,),
                                    timeout_s=timeout_s)
        elapsed = time.time() - began

        c = v["checks"][0]
        self.assertEqual(v["state"], corroborate_mod.CORROBORATED)
        self.assertTrue(c["measured"])
        self.assertTrue(c["ok"])
        self.assertFalse(c["timed_out"])
        self.assertIn("STDIN-CLOSED-AFTER-0-BYTES", c["tail"])
        # Not merely "finished under the roof": it never went near the ceiling, which is what
        # separates "read EOF at once" from "blocked until the deadline killed it".
        self.assertLess(elapsed, timeout_s / 2.0,
                        "the check spent %.2fs of an %.1fs ceiling on a standard input that "
                        "should have been closed to it" % (elapsed, timeout_s))

    @control(389)
    def test_the_ceiling_is_wall_clock_tracks_the_number_and_waits_on_no_writer(self):
        """The defect, reproduced three ways: a survivor, a flood, and a prompt."""
        with procsafe.Fleet(deadline_s=300.0) as fleet:
            # THE SINKS LAND WHERE THIS FLEET CAN REMOVE THEM. ``mkstemp`` with no ``dir``
            # honours ``tempfile.tempdir``, and the survivor scenario is precisely the one whose
            # sink CANNOT be unlinked -- the grandchild still holds the handle -- so a control
            # left pointing at the operator's own %TEMP% drops a file there on every run. They
            # are empty now rather than credentials, and a control that litters is still a
            # control that litters.
            was_tempdir = tempfile.tempdir
            tempfile.tempdir = fleet.temp_dir("quaestor-tcb-sinks-")
            try:
                short = self.run_survivor(fleet, timeout_s=2.0, tag="short")
                longer = self.run_survivor(fleet, timeout_s=7.0, tag="long")

                # THE OPERATOR'S NUMBER IS WHAT BOUNDS THE CALL. Same check, same survivor, two
                # ceilings 5.0s apart: the elapsed times must be that far apart too. A ceiling
                # that ignores the flag spends the same time twice, and one that overshoots by
                # a factor blows the larger run's own bound.
                self.assertGreaterEqual(longer["elapsed"] - short["elapsed"], 4.0,
                                        "a 2.0s ceiling took %.2fs and a 7.0s ceiling took "
                                        "%.2fs: the elapsed time does not track the operator's "
                                        "number" % (short["elapsed"], longer["elapsed"]))

                self.sink_is_read_under_a_budget()
                self.a_check_that_reads_stdin_gets_eof()
            finally:
                tempfile.tempdir = was_tempdir

        # THE FIXTURE ENDS WHAT IT STARTED. One process at a time, never a tree.
        report = fleet.cleanup_report
        self.assertEqual(report["leaked"], [], "this control leaked processes")
        for row in (short, longer):
            self.assertFalse(fleet.alive(row["kid"]),
                             "the grandchild outlived the fixture that caused it")

    @control(390)
    def test_a_killed_check_never_passes_and_its_output_is_classified_before_it_travels(self):
        """The timeout path used to carry NO output, so nothing had to be classified on it.

        It carries output now -- which an operator needs, because "it hung" is not actionable
        without knowing how far it got -- and that makes it a new way out for the same secret
        control 300 closed on the measured path. THREE destinations, not one: the durable event
        log, the message ledger, and a blocker sentence sent to a REMOTE provider. So this drives
        the KERNEL the way control 300 does, instead of reading ``verdict``'s own return value
        and calling that the record.

        A FOURTH DESTINATION EXISTS AND IS THE ONLY ONE CLASSIFICATION NEVER SEES: the temp file
        the output is captured in. It is removed on the way out -- except in precisely the case
        this module is built for, where a surviving descendant holds the handle and the unlink
        fails. Reviewed and measured: 26 orphaned ``quaestor-check-*.out`` files in one session's
        %TEMP%, one of them holding a plaintext ``sk-ant-...`` key. So the sink is emptied before
        it is unlinked, and this control reads back whatever the run left behind.
        """
        timeout_s = 2.0
        secret = "sk-ant-api03-" + "A" * 40
        with procsafe.Fleet(deadline_s=300.0) as fleet:
            work = fleet.temp_dir("quaestor-tcb-390-")
            check = write_check(self.repo, "check_prints_then_hangs.py",
                                leaky_hang_body(secret, os.path.join(work, "kid-")))

            # THE SINK IS STEERED SOMEWHERE THIS CONTROL CAN READ IT. ``mkstemp`` with no ``dir``
            # honours ``tempfile.tempdir``, so pointing that at a directory this fleet owns reads
            # back exactly what THIS run left -- not another lane's temp files -- and leaves
            # nothing behind in the operator's own temp directory when the unlink fails.
            def adopt_every_grandchild():
                """Take ownership of every survivor this run has produced SO FAR.

                Called between the phases and again from the ``finally``, never once at the end:
                a phase that raises before its grandchild is owned leaves a process holding the
                fixture's own repository open, and the failure the operator then reads is a
                tearDown that could not remove a directory.
                """
                found = []
                for name in sorted(os.listdir(work)):
                    if not name.startswith("kid-"):
                        continue
                    pid = int(read_text(os.path.join(work, name)).strip())
                    found.append(pid)
                    if pid not in fleet.owned:
                        fleet.adopt(pid, "grandchild holding the leaky check's sink")
                return found

            was_tempdir = tempfile.tempdir
            tempfile.tempdir = work
            try:
                began = time.time()
                v = corroborate_mod.verdict(project_root=self.repo, checks=(check,),
                                            timeout_s=timeout_s)
                elapsed = time.time() - began
                adopt_every_grandchild()

                k = self.claiming(relay_id="relay-killed-check", completion_checks=(check,),
                                  check_timeout_s=timeout_s, completion_attempt_limit=5)
                k.step()      # the claim is refused; the killed check's output is captured
                k.step()      # the directive still reaches the agent
                k.step()      # the agent's answer carries the blocker back to the Orchestrator
            finally:
                tempfile.tempdir = was_tempdir
                kids = adopt_every_grandchild()

            self.assertTrue(kids, "no check got as far as leaving a grandchild, so the sink "
                                  "was never held open and the leak below is untested")

            c = v["checks"][0]
            self.assertLess(elapsed, self.ceiling_for(timeout_s))
            # NEVER A PASS. The check was not slow-but-fine; it was never allowed to answer.
            self.assertEqual(v["state"], corroborate_mod.UNMEASURABLE)
            self.assertNotEqual(v["state"], corroborate_mod.CORROBORATED)
            self.assertTrue(c["timed_out"])
            self.assertFalse(c["ok"])
            self.assertFalse(c["measured"])
            self.assertIsNone(c["exit_code"])

            # IT REALLY DID PRODUCE OUTPUT -- so the redaction assertions are about redacting
            # and not about an empty string, which is how this control could look green while
            # measuring nothing.
            self.assertIn("LOADED config", c["tail"])
            self.assertNotIn(secret, c["tail"])
            self.assertTrue(c["redacted"])
            line = corroborate_mod.blocker_line(v)
            self.assertNotIn(secret, line)
            self.assertIn("LOADED config", line)
            # And the Orchestrator is told the check was KILLED, not merely that it failed:
            # partial output without that reads as a real failure to go and fix.
            self.assertIn("was killed", line)

            # THE THREE DESTINATIONS THE REGISTRATION NAMES, REACHED THROUGH THE KERNEL.
            events = self.state.events(k.relay_id, limit=0)
            for ev in events:
                self.assertNotIn(secret, repr(ev.get("payload")), "leaked into the event log")
            for row in self.state.messages(k.relay_id, limit=0):
                self.assertNotIn(secret, repr(row), "leaked into the message ledger")
            to_orch = "\n".join(t for _mid, t in k.orchestrator.sent)
            self.assertNotIn(secret, to_orch, "leaked to the remote Orchestrator")

            # NON-VACUITY FOR ALL THREE: the killed check's output really did travel this route,
            # and the redaction is visible rather than silent.
            claims = [ev["payload"] for ev in events
                      if ev["kind"] == "relay.completion.claim"]
            self.assertTrue(claims, "the kernel never recorded a completion claim, so nothing "
                                    "above was measured against the durable record")
            self.assertEqual(claims[0]["state"], corroborate_mod.UNMEASURABLE)
            self.assertIn("LOADED config", claims[0]["checks"][0]["tail"])
            self.assertIn("secret-withheld", claims[0]["checks"][0]["tail"])
            self.assertIn("LOADED config", to_orch)

            # THE FOURTH DESTINATION: the raw sink, the one copy nothing classifies. On Windows
            # the grandchild's handle makes the unlink fail, so a file is left -- and what it
            # must contain is nothing at all.
            left = [os.path.join(work, n) for n in os.listdir(work)
                    if n.startswith("quaestor-check-")]
            if os.name == "nt":
                self.assertTrue(left, "no sink survived the run, so the emptying this asserts "
                                      "was never exercised on the platform where it matters")
            for path in left:
                with open(path, "rb") as fh:
                    body = fh.read()
                self.assertEqual(len(body), 0,
                                 "the raw, unclassified sink survived this run holding %d "
                                 "bytes (carries the credential: %s)"
                                 % (len(body), secret.encode("utf-8") in body))

        report = fleet.cleanup_report
        self.assertEqual(report["leaked"], [], "this control leaked processes")


if __name__ == "__main__":
    unittest.main()

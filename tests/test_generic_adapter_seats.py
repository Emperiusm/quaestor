"""GENERIC ADAPTER SEAT CONTROLS (239-241) -- bd quaestor-ubg, quaestor-cjj, quaestor-ru1.19.

    CONTROL_DECLARED  does not imply
    CONTROL_REACHABLE does not imply
    CONTROL_EFFECTIVE

Three defects, one root: the adapters existed and were tested in isolation, but nothing a
production path executes could reach them, and the routing vocabularies disagreed about which
kinds exist. These controls prove the PRODUCT properties, not the library properties:

  239  every declared kind is buildable or refused by name at admission (the seat can no
       longer be routed to a kind that dies in build());
  240  a seat pinned to a user-supplied command holds a REAL run end to end, prompt on stdin
       only, with an explicit preflight branch;
  241  the file-inbox reference adapter is dispatchable as an executor kind end to end, with
       an independent external writer answering in the outbox.

Where a control here constructs something, it constructs it the way the real caller does.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.adapters import registry as cap_reg  # noqa: E402
from quaestor.core import credential_policy as cp  # noqa: E402
from quaestor.core import orchestrator as orch  # noqa: E402
from quaestor.core.executor_contract import ExecOutcome, ExecRequest  # noqa: E402
from quaestor.core.identity import RunBinding  # noqa: E402
from quaestor.executors import registry as ex_reg  # noqa: E402
from tests.controls import control  # noqa: E402

#: A REAL external agent for the end-to-end controls: reads its prompt from stdin, answers in
#: the JSON envelope shape the handoff parser expects. sys.executable keeps this hermetic and
#: cross-platform -- no shell, no vendor binary, no network.
ECHO_AGENT_SCRIPT = (
    "import json, sys\n"
    "prompt = sys.stdin.read()\n"
    "sys.stdout.write(json.dumps({\"result\": {\"echo\": prompt}, \"is_error\": False}))\n")


def _req(run_dir: str, prompt: str) -> ExecRequest:
    return ExecRequest(
        run_id="run-generic", run_dir=run_dir, cwd=run_dir, prompt=prompt,
        binding=RunBinding("run-generic", "w", "seat", "lane"), json_schema={},
        authority_profile="READ_ONLY",
        stdout_path=os.path.join(run_dir, "stdout.json"),
        stderr_path=os.path.join(run_dir, "stderr.json"))


def _run_dir(tmp: str) -> str:
    d = tempfile.mkdtemp(prefix="quaestor-seat-", dir=tmp)
    os.makedirs(d, exist_ok=True)
    return d


# =============================================================================================
# 239 -- the two vocabularies agree: declared means buildable OR refused at admission
# =============================================================================================
class TestDeclaredMeansBuildableOrRefused(unittest.TestCase):
    @control(239)
    def test_no_declared_kind_can_be_routed_to_and_then_die_in_build(self):
        for kind in sorted(cap_reg.PROVIDER_REGISTRY):
            with self.subTest(kind=kind):
                self.assertTrue(cap_reg.is_declared(kind))
                if ex_reg.is_buildable(kind):
                    # Buildable in the vocabulary AND constructible by the factory it names.
                    self.assertIn(kind, ex_reg.KNOWN_KINDS)
                    continue
                # Declared-but-unbuildable: ADMISSION refuses, by name, on every configured
                # path (pin, chain winner). The refusal names the marker, so the operator is
                # told "not shipped in this build" instead of seeing a traceback from a build
                # that admission should never have allowed.
                spec, source = orch._resolve_executor(
                    "fake", {"executor": {}}, role_kind="verification",
                    role_executor={"verification": kind})
                self.assertEqual(spec.get("refusal"), cap_reg.SEAT_UNRESOLVABLE, kind)
                self.assertEqual(source, "roles-config-refused", kind)
                self.assertIn(ex_reg.NOT_BUILDABLE_IN_THIS_BUILD,
                              " ".join(spec.get("rationale", [])), kind)
                chain_spec, _chain_source = orch._resolve_executor(
                    "fake", {"executor": {}}, role_kind="verification",
                    chains={"verification": [kind, "fake"]})
                self.assertEqual(chain_spec.get("refusal"), cap_reg.SEAT_UNRESOLVABLE, kind)
                self.assertIn(ex_reg.NOT_BUILDABLE_IN_THIS_BUILD,
                              " ".join(chain_spec.get("rationale", [])), kind)

    def test_the_unbuildable_trio_is_still_declared_not_deleted(self):
        # The honest narrowing: the kinds stay declared (they are real configuration targets
        # for a build that ships their executors), they are simply not silently routable.
        for kind in ("gemini-cli", "gpt-plan", "local-llama"):
            self.assertTrue(cap_reg.is_declared(kind), kind)
            self.assertFalse(ex_reg.is_buildable(kind), kind)


# =============================================================================================
# 240 -- a user-supplied command holds a real seat end to end
# =============================================================================================
class TestCommandSeatEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="quaestor-cmdseat-")

    def test_seat_pinned_to_a_real_command_holds_a_real_run(self):
        @control(240)
        def body():
            argv = [sys.executable, "-c", ECHO_AGENT_SCRIPT]
            spec = orch._executor_for("claude-cli", {"executor": {}},
                                      role_kind="adversarial_review",
                                      role_executor={"adversarial_review": "command"})
            self.assertEqual(spec.get("kind"), "command",
                             "a command pin must survive admission intact")
            built = ex_reg.build({"kind": "command", "config": {"argv": argv}})
            rd = _run_dir(self.tmp)
            prompt = "review the diff at HEAD"
            outcome = built.execute(_req(rd, prompt))
            self.assertIsInstance(outcome, ExecOutcome)
            self.assertEqual(outcome.exit_class, "NORMAL_EXIT", outcome.error)
            with open(os.path.join(rd, "stdout.json"), "r", encoding="utf-8") as fh:
                reply = json.load(fh)
            self.assertEqual(reply["result"]["echo"], prompt,
                             "the real external command must answer with OUR prompt echoed")
            # THE §5.13 PROPERTY, FROM THE DURABLE RECORD: the prompt travelled on stdin, and
            # no part of it appears in the recorded argv.
            with open(os.path.join(rd, "command.json"), "r", encoding="utf-8") as fh:
                rec = json.load(fh)
            self.assertFalse(rec["shell"])
            self.assertEqual(rec["prompt_transport"], "STDIN")
            self.assertNotIn(prompt, " ".join(rec["argv"]))
            # The EXPLICIT preflight branch (the default for an unknown kind is fail-closed
            # NO_PREFLIGHT_FOR_KIND -- a bridge must never inherit that pass-by-accident).
            d = ex_reg.run_preflight("command")
            self.assertEqual(d.decision, cp.ACCEPT)
            self.assertEqual(d.auth_class, "NOT_APPLICABLE_TRANSPORT_BRIDGE")
        body()

    def test_a_failing_command_turn_is_a_loud_nonzero_not_a_reply(self):
        argv = [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"]
        built = ex_reg.build({"kind": "command", "config": {"argv": argv}})
        outcome = built.execute(_req(_run_dir(self.tmp), "anything"))
        self.assertEqual(outcome.exit_class, "NONZERO_EXIT")
        self.assertIn("boom", outcome.error)

    def test_a_shell_string_is_refused_before_anything_spawns(self):
        built = ex_reg.build({"kind": "command", "config": {"argv": "claude -p"}})
        outcome = built.execute(_req(_run_dir(self.tmp), "anything"))
        self.assertEqual(outcome.exit_class, "SPAWN_FAILED")
        self.assertIn("sequence", outcome.error)


# =============================================================================================
# 241 -- the file-inbox reference adapter is dispatchable end to end
# =============================================================================================
class TestFileInboxSeatEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="quaestor-fbseat-")

    def _answer_as_external_writer(self, root: str) -> None:
        """Play the independent consumer: read the newest inbox envelope, answer the outbox."""
        from quaestor.adapters.filebox import COMPLETION_MARKER
        inbox = os.path.join(root, ".quaestor", "inbox")
        outbox = os.path.join(root, ".quaestor", "outbox")
        envelope = None
        deadline = time.monotonic() + 10
        while envelope is None:
            files = sorted(f for f in os.listdir(inbox) if f.endswith(".json")) \
                if os.path.isdir(inbox) else []
            if files:
                with open(os.path.join(inbox, files[-1]), "r", encoding="utf-8") as fh:
                    envelope = json.load(fh)
                break
            self.assertLess(time.monotonic(), deadline, "no inbox envelope appeared")
            time.sleep(0.05)
        response = {"task_id": envelope["task_id"],
                    "message_id": envelope["message_id"],
                    "completion_marker": COMPLETION_MARKER,
                    "payload": {"result_text": "outbox answer: %s" % envelope["payload"]}}
        os.makedirs(outbox, exist_ok=True)  # an independent writer owns its own side's layout
        with open(os.path.join(outbox, "%s.json" % envelope["task_id"]), "w",
                  encoding="utf-8") as fh:
            json.dump(response, fh)

    def test_file_inbox_seat_holds_a_real_run_with_an_independent_writer(self):
        @control(241)
        def body():
            root = tempfile.mkdtemp(prefix="quaestor-fbroot-", dir=self.tmp)
            spec = orch._executor_for("claude-cli", {"executor": {}}, role_kind="planner",
                                      role_executor={"planner": "file-inbox"})
            self.assertEqual(spec.get("kind"), "file-inbox",
                             "a file-inbox pin must survive admission intact")
            built = ex_reg.build({"kind": "file-inbox",
                                  "config": {"root": root, "timeout_s": 15.0,
                                             "poll_interval_s": 0.05}})
            rd = _run_dir(self.tmp)
            prompt = "plan the migration"
            # The external writer answers WHILE the seat polls -- concurrency is the real
            # wire contract, not a pre-seeded outbox.
            writer = threading.Thread(target=self._answer_as_external_writer, args=(root,))
            writer.start()
            outcome = built.execute(_req(rd, prompt))
            writer.join(timeout=10)
            self.assertEqual(outcome.exit_class, "NORMAL_EXIT", outcome.error)
            with open(os.path.join(rd, "stdout.json"), "r", encoding="utf-8") as fh:
                self.assertIn("outbox answer: %s" % prompt, fh.read())
            # Exactly-once: the consumed response is marked consumed in the durable layout.
            consumed = os.path.join(root, ".quaestor", "outbox", "consumed")
            self.assertTrue(os.path.isdir(consumed))
            self.assertTrue(any(f.endswith(".json") for f in os.listdir(consumed)))
            d = ex_reg.run_preflight("file-inbox")
            self.assertEqual(d.decision, cp.ACCEPT)
            self.assertEqual(d.auth_class, "NOT_APPLICABLE_TRANSPORT_BRIDGE")
        body()

    def test_a_dead_outbox_is_an_observed_timeout_and_the_envelope_stays(self):
        root = tempfile.mkdtemp(prefix="quaestor-fbroot-", dir=self.tmp)
        built = ex_reg.build({"kind": "file-inbox",
                              "config": {"root": root, "timeout_s": 0.5,
                                         "poll_interval_s": 0.05}})
        outcome = built.execute(_req(_run_dir(self.tmp), "nobody home"))
        self.assertEqual(outcome.exit_class, "TIMEOUT", outcome.error)
        self.assertIn("stays in place", outcome.error)
        inbox = os.path.join(root, ".quaestor", "inbox")
        self.assertEqual(len([f for f in os.listdir(inbox) if f.endswith(".json")]), 1,
                         "the undelivered envelope must remain for its writer")

    def test_a_seat_without_a_root_is_refused_before_anything_spawns(self):
        built = ex_reg.build({"kind": "file-inbox", "config": {}})
        outcome = built.execute(_req(_run_dir(self.tmp), "anything"))
        self.assertEqual(outcome.exit_class, "SPAWN_FAILED")
        self.assertIn("config.root", outcome.error)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

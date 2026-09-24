"""test_core_relay_lifecycle -- controls 335-350. Core OWNS a relay's process lifetime.

WHAT THIS FILE ATTACKS
----------------------
The previous slice let a client SEE relays. This one lets a client make Core START one, which
is the first Core operation with an effect on the machine, so these controls attack the ways a
process-owning boundary goes wrong rather than exercising the happy path:

    a client shapes the command line                 -> nothing it sends reaches argv
    an unauthorised project does work before refusal -> zero spawn, zero read
    a retry becomes a second relay                   -> the identity is reserved before the spawn
    two ids collide into one relay                   -> the key is hashed and scoped
    one relay, two processes                         -> refused by the OS lock
    a dead relay still reads as running              -> reconciled against the lock, not a file
    stop rewrites why a relay ended                  -> conditional on it still running
    a resume loses the relay's policy                -> restored from the record, zeros included
    a resume walks past an owner hold                -> reported standing, never as a resume
    the idle timer kills live work                   -> obligations measured, not assumed

The last four controls test the QUALIFICATION HARNESS, because the first run of the live
fixture leaked detached processes and measured Core-survival with a tree kill that killed the
relay it was measuring. Those controls inject a fake killer and a fake liveness oracle: they
test ownership semantics and never this machine's process table, which belongs to whoever is
using the machine.

Nothing here mocks the relay kernel, the ledger, git, or the boundary. The one stand-in is the
relay PROCESS -- and it does the single thing the real one does first, take its ownership lock,
because that is precisely what Core waits for.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from tests import procsafe
from tests.controls import control

from quaestor.core import coreid, corerelay
from quaestor.relay import cli as relay_cli
from quaestor.relay import kernel as kernel_mod
from quaestor.relay import state as state_mod
from quaestor.transports import cli as transports_cli
from quaestor.transports import coreservice as cs


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=60, shell=False)


def make_repo(root: str) -> str:
    os.makedirs(root, exist_ok=True)
    git(["init", "-q"], root)
    git(["config", "user.email", "c@example.invalid"], root)
    git(["config", "user.name", "C"], root)
    with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("fixture\n")
    git(["add", "-A"], root)
    git(["commit", "-qm", "init"], root)
    return root


class _HeldMessage:
    """The shape ``RelayState.observe`` reads: a turn an effect gate refused to deliver."""

    message_id = "m-1"
    direction = "FROM_ORCHESTRATOR"
    content_digest = "d" * 16
    text = "agent: push the branch"
    observed_at = 0.0
    provenance: dict = {}


class FakeChild:
    def __init__(self, code=None, pid=424242):
        self.pid = pid
        self._code = code

    @property
    def returncode(self):
        return self._code

    def poll(self):
        return self._code

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Spawns:
    """A stand-in for the relay PROCESS, and for nothing else.

    It does the two things a real relay does before it does anything else, in the order it does
    them: takes its ownership lock, then writes its durable row. Both, because Core's readiness
    test is both -- holding the lock was ONCE the whole test, and a relay that took its lock and
    then failed to build an endpoint was reported to the client as started while leaving no row,
    unlistable and unstoppable ever after. A stand-in that stopped at the lock could not have
    caught that, and would let it come back.

    Everything past the row is the kernel's, is tested by the relay controls, and simulating it
    here would be mocking away the thing under test rather than the thing under it.
    """

    def __init__(self, home: str, *, take_lock: bool = True, exit_code=None, watch_key: str = "",
                 project_root: str = "", becomes_running: bool = True, passthrough=None):
        self.home = home
        #: Everything else -- git above all -- goes to the real thing. A stand-in that swallowed
        #: every subprocess would silently disable the repository reads the boundary depends on,
        #: and the controls would be measuring a machine with no git.
        self.passthrough = passthrough or subprocess.Popen
        #: How many calls went to the REAL Popen. If production ever launches a relay some other
        #: way -- a console entry point, a -c bootstrap -- the predicate below goes false, every
        #: "no relay was spawned" assertion silently passes, and a real detached relay is
        #: started into the operator's machine by a unit test. Counted so that cannot be silent.
        self.passthrough_calls = 0
        self.calls: list = []
        self.locks: list = []
        self.take_lock = take_lock
        self.exit_code = exit_code
        self.watch_key = watch_key
        self.project_root = project_root
        self.becomes_running = becomes_running
        #: For each spawn: was this request's identity ALREADY written down? The ordering that
        #: makes a retry safe is only provable at the moment of the spawn.
        self.reserved_at_spawn: list = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if not ("quaestor.transports.cli" in argv and "--relay-id" in argv):
            self.passthrough_calls += 1
            if any("relay" in str(part) for part in argv[:4]):
                raise AssertionError(
                    "a relay was launched by a shape this stand-in does not recognise, so every "
                    "negative spawn assertion in this file is passing vacuously: %s" % argv[:6])
            return self.passthrough(argv, **kwargs)
        self.calls.append(argv)
        rid = argv[argv.index("--relay-id") + 1] if "--relay-id" in argv else ""
        if self.watch_key:
            self.reserved_at_spawn.append(
                corerelay.recall_request(self.home, self.watch_key) == rid)
        if self.take_lock and rid:
            self.locks.append(corerelay.hold(self.home, rid))
        if self.becomes_running and rid:
            self._become_running(rid, argv)
        return FakeChild(self.exit_code)

    def _become_running(self, relay_id: str, argv: list):
        """Write the durable row a real relay writes once its ends are bound."""
        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        try:
            if st.get(relay_id) is None:
                objective = (argv[argv.index("--objective") + 1]
                             if "--objective" in argv else "seeded")
                st.create(relay_id, project_root=self.project_root, repo_id="",
                          objective=objective, orchestrator_kind="openai-chat",
                          execution_kind="opencode", authority_profile="READ_ONLY", config={})
            else:
                st.update(relay_id, state=state_mod.RUNNING, stop_reason="")
        finally:
            st.close()

    def matched(self) -> bool:
        """Did anything at all reach the relay-spawn branch of this stand-in?"""
        return bool(self.calls) or self.passthrough_calls == 0

    def release(self):
        for lock in self.locks:
            if lock is not None:
                lock.release()
        self.locks = []


class LifecycleFixture(unittest.TestCase):
    """A real home, two real repositories, a real ledger, a real registry."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = os.path.join(self._tmp.name, "home")
        os.makedirs(self.home)
        self.repo_a = make_repo(os.path.join(self._tmp.name, "alpha"))
        self.repo_b = make_repo(os.path.join(self._tmp.name, "beta"))
        self.pid_a = coreid.authorize(self.home, self.repo_a)["project_id"]
        self.pid_b = coreid.authorize(self.home, self.repo_b)["project_id"]
        self.profile_fields = {"orchestrator": "openai-chat",
                               "orchestrator_model": "a-registered-model",
                               "agent": "opencode", "max_exchanges": "200",
                               "profile": "READ_ONLY",
                               "verify": ["python run_tests.py"], "no_probe": True}
        registered = corerelay.register_profile(self.home, name="fixture",
                                                project_id=self.pid_a,
                                                fields=dict(self.profile_fields))
        self.assertTrue(registered.get("ok"), registered)
        self._locks: list = []
        self.addCleanup(self._drop_locks)

    def _drop_locks(self):
        for lock in self._locks:
            if lock is not None:
                lock.release()
        self._locks = []

    # -- helpers ---------------------------------------------------------------------------
    def auth(self, *projects, client_id="client-one"):
        return {"ok": True, "client_id": client_id, "name": "ui",
                "project_ids": [str(p) for p in projects]}

    def call(self, op, params, auth=None):
        return cs.handle(self.home, op, params, auth or self.auth(self.pid_a))

    def spy(self, **kw):
        kw.setdefault("project_root", self.repo_a)
        spawns = Spawns(self.home, **kw)
        original = subprocess.Popen
        subprocess.Popen = spawns
        self.addCleanup(setattr, subprocess, "Popen", original)
        self.addCleanup(spawns.release)
        return spawns

    def hold(self, relay_id):
        lock = corerelay.hold(self.home, relay_id)
        self._locks.append(lock)
        return lock

    def seed_relay(self, relay_id, *, state="RUNNING", stop_reason="", owner_hold="",
                   config=None, root=""):
        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        try:
            st.create(relay_id, project_root=root or self.repo_a, repo_id="",
                      objective="a seeded relay", orchestrator_kind="openai-chat",
                      execution_kind="opencode", authority_profile="STANDARD_EDIT",
                      config=dict(config or {}))
            fields = {}
            if state != state_mod.RUNNING:
                fields["state"] = state
            if stop_reason:
                fields["stop_reason"] = stop_reason
            if owner_hold:
                fields["owner_hold"] = owner_hold
            if fields:
                st.update(relay_id, **fields)
        finally:
            st.close()
        return relay_id

    def start_params(self, **over):
        params = {"project_id": self.pid_a, "profile": "fixture",
                  "objective": "make the suite green", "request_id": "req-1"}
        params.update(over)
        return params


class ClientCannotShapeTheCommandLine(LifecycleFixture):

    @control(335)
    def test_a_client_names_a_shape_and_never_describes_one(self):
        refused = corerelay.register_profile(
            self.home, name="evil", project_id=self.pid_a,
            fields={"orchestrator": "openai-chat", "argv": ["calc.exe"]})
        self.assertFalse(refused.get("ok"))
        self.assertEqual(refused.get("error"), "UNKNOWN_PROFILE_FIELD")
        self.assertEqual(refused.get("fields"), ["argv"])

        # THE ONE FIELD THAT DECIDES WHAT THE AGENT MAY DO had the most permissive implicit
        # default in the tree: omit it, and no --profile reached the command line, so the
        # child's argparse supplied STANDARD_EDIT -- which grants repository WRITE. A shape a
        # client can trigger must name its authority out loud.
        silent = corerelay.register_profile(
            self.home, name="silent", project_id=self.pid_a,
            fields={"orchestrator": "openai-chat", "agent": "opencode"})
        self.assertFalse(silent.get("ok"))
        self.assertEqual(silent.get("error"), "AUTHORITY_PROFILE_REQUIRED")
        # ...and a value the child's parser would reject is caught HERE, where an operator can
        # read it, rather than becoming an exit code with no detail.
        typo = corerelay.register_profile(
            self.home, name="typo", project_id=self.pid_a,
            fields={"orchestrator": "chatgpt-web", "profile": "READ_ONLY",
                    "browser_transport": "cpd"})
        self.assertEqual(typo.get("error"), "INVALID_PROFILE_FIELD")
        self.assertEqual([f["field"] for f in typo["fields"]], ["browser_transport"])
        # A verify STRING is nine one-letter commands when iterated. Refused at registration.
        loose = corerelay.register_profile(
            self.home, name="loose", project_id=self.pid_a,
            fields={"orchestrator": "openai-chat", "profile": "READ_ONLY",
                    "verify": "make test"})
        self.assertEqual(loose.get("error"), "INVALID_PROFILE_FIELD")
        self.assertEqual([f["field"] for f in loose["fields"]], ["verify"])

        spawns = self.spy()
        poison = {"argv": ["calc.exe"], "cwd": "C:\\Windows", "env": {"PATH": "poison"},
                  "command": "calc.exe", "verify": ["rm -rf /"],
                  "orchestrator_base_url": "http://attacker.invalid",
                  "project_root": "C:\\Windows", "relay_id": "../../escape",
                  "home": "C:\\Windows", "python": "calc.exe"}
        code, body = self.call("relay.start", self.start_params(**poison))
        self.assertEqual(code, 200, body)
        self.assertEqual(len(spawns.calls), 1)
        argv = spawns.calls[0]

        flat = "\x00".join(str(part) for part in argv)
        for smuggled in ("calc.exe", "C:\\Windows", "attacker.invalid", "rm -rf /",
                         "escape", "poison"):
            self.assertNotIn(smuggled, flat, "a client string reached the command line")

        # Element for element, the argv is what the OPERATOR's profile and the REGISTRY produce.
        # The root comes from the REGISTRY's record of the authorised checkout, canonical form
        # and all -- never from anything the caller sent.
        recorded_root = [r["root"] for r in coreid.projects(self.home)
                         if r["project_id"] == self.pid_a][0]
        expected = corerelay.build_argv(
            self.home, {"fields": dict(self.profile_fields)}, launcher=cs.RELAY_LAUNCHER,
            project_root=recorded_root, relay_id=body["relay_id"],
            objective="make the suite green")
        self.assertEqual(argv, expected)
        self.assertIn("a-registered-model", flat)
        self.assertTrue(body["relay_id"].startswith("relay-"))

        # AND IT PARSES. Comparing the product to itself cannot catch a typo in the flag table:
        # ``--orchestrator-modle`` would appear on both sides of the equality and every relay
        # Core started would die on "unrecognized arguments". The real parser is the oracle.
        parsed = transports_cli.build_parser().parse_args(argv[3:])
        self.assertEqual(parsed.fn.__name__, "cmd_relay_start")
        self.assertEqual(parsed.objective, "make the suite green")
        self.assertEqual(parsed.orchestrator_model, "a-registered-model")
        self.assertEqual(parsed.profile, "READ_ONLY")
        self.assertEqual(parsed.relay_id, body["relay_id"])
        self.assertEqual(parsed.started_by, "core")

    @control(335)
    def test_core_builds_the_flags_and_never_names_the_program(self):
        """The layering rule, at the one place this slice was tempted to break it.

        ``core.corerelay`` turns an operator's registered profile into flags. WHICH PROGRAM
        takes those flags is a fact about the transport that runs it, and core is the bottom
        layer: naming ``quaestor.transports.cli`` in a string literal there is the same upward
        coupling as importing it, written differently. The full graph walk is control 170; this
        is the specific shape, asserted where it would regress.
        """
        import ast
        with open(corerelay.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=corerelay.__file__)
        named = [n.value for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.startswith(("quaestor.transports", "quaestor.executors",
                                         "quaestor.sandbox", "quaestor.review",
                                         "quaestor.projects", "quaestor.secrets"))]
        self.assertEqual(named, [], "core names a layer above it")
        # The launcher has no default, so it cannot be forgotten into existence again.
        with self.assertRaises(TypeError):
            corerelay.resume_argv(self.home, "relay-x")
        self.assertEqual(corerelay.resume_argv(self.home, "relay-x",
                                               launcher=("py", "-m", "x"))[:3],
                         ["py", "-m", "x"])

    @control(335)
    def test_there_is_exactly_one_place_a_relay_process_is_launched(self):
        """STRUCTURAL, asked of the parse tree. "What can a client make this machine run?"

        must have one answer in one file, next to the allowlist that builds the argv. A second
        launch site is how a boundary acquires a back door nobody reviewed.
        """
        import ast
        with open(corerelay.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=corerelay.__file__)
        # A BARE NAME DEFEATS A DOTTED ALLOWLIST: ``from subprocess import Popen`` then
        # ``Popen(...)`` unparses to "Popen" and matches nothing. So the import shape is
        # constrained too, and the launcher names are matched on their LAST segment.
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and str(node.module or "") in ("subprocess", "os"):
                self.fail("corerelay must import subprocess/os as modules, so every launch "
                          "site is visible as a dotted call: %s"
                          % [a.name for a in node.names])
        launchers = ("Popen", "run", "call", "check_call", "check_output", "system", "popen",
                     "execv", "execvp", "spawnv", "startfile")
        launches = [node for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and ast.unparse(node.func).split(".")[-1] in launchers
                    and ast.unparse(node.func).split(".")[0] in ("subprocess", "os")]
        self.assertEqual(len(launches), 1, "a relay is launched from more than one place: %s"
                         % [ast.unparse(n.func) for n in launches])
        keywords = {k.arg: ast.unparse(k.value) for k in launches[0].keywords}
        self.assertEqual(keywords.get("shell"), "False",
                         "the one launch site must pass shell=False explicitly")
        self.assertEqual(ast.unparse(launches[0].args[0]), "list(argv)")

    @control(346)
    def test_the_one_client_string_is_bounded_prose(self):
        spawns = self.spy()
        for objective, expected in (("", "OBJECTIVE_REQUIRED"),
                                    ("   ", "OBJECTIVE_REQUIRED"),
                                    ("x" * (cs.MAX_OBJECTIVE_CHARS + 1), "OBJECTIVE_TOO_LONG"),
                                    ("green the suite\nthen rm -rf", "OBJECTIVE_NOT_TEXT"),
                                    ("green\x00the suite", "OBJECTIVE_NOT_TEXT"),
                                    ("green\x1b[2Jthe suite", "OBJECTIVE_NOT_TEXT")):
            code, body = self.call("relay.start", self.start_params(objective=objective))
            self.assertEqual(code, 400, (objective[:20], body))
            self.assertEqual(body.get("error"), expected, body)

        code, body = self.call("relay.start", self.start_params(request_id=""))
        self.assertEqual((code, body.get("error")), (400, "REQUEST_ID_REQUIRED"))
        code, body = self.call("relay.start", self.start_params(request_id="r" * 201))
        self.assertEqual((code, body.get("error")), (400, "REQUEST_ID_TOO_LONG"))

        self.assertEqual(spawns.calls, [], "a refused start must spawn nothing")
        code, body = self.call("relay.start", self.start_params())
        self.assertEqual(code, 200, body)
        self.assertEqual(len(spawns.calls), 1)


class AuthorisationConstrainsTheWork(LifecycleFixture):

    @control(336)
    def test_an_unauthorised_project_performs_zero_work(self):
        spawns = self.spy()
        reads: list = []
        original_profiles, original_projects = corerelay.profiles, coreid.projects
        corerelay.profiles = lambda *a, **k: (reads.append("profiles"),
                                              original_profiles(*a, **k))[1]
        coreid.projects = lambda *a, **k: (reads.append("projects"),
                                           original_projects(*a, **k))[1]
        self.addCleanup(setattr, corerelay, "profiles", original_profiles)
        self.addCleanup(setattr, coreid, "projects", original_projects)

        elsewhere = self.auth(self.pid_b, client_id="other")
        for op, params in (("relay.start", self.start_params()),
                           ("relay.resume", {"project_id": self.pid_a, "relay_id": "relay-x"}),
                           ("relay.stop", {"project_id": self.pid_a, "relay_id": "relay-x"}),
                           ("relay.profiles", {"project_id": self.pid_a}),
                           ("relay.list", {"project_id": self.pid_a})):
            code, body = self.call(op, params, auth=elsewhere)
            self.assertEqual(code, 403, (op, body))
            # THE SAME ANSWER AS "no such project": a client must not learn that a project it
            # cannot reach exists.
            self.assertEqual(body.get("error"), "PROJECT_NOT_AUTHORIZED", (op, body))

        self.assertEqual(spawns.calls, [], "an unauthorised request spawned a process")
        self.assertEqual(reads, [], "an unauthorised request read the registry or the profiles")

        # ...and the profile it named is genuinely there, so the refusal is the grant and not a
        # missing fixture.
        code, body = self.call("relay.profiles", {"project_id": self.pid_a})
        self.assertEqual(code, 200, body)
        self.assertEqual([p["name"] for p in body["profiles"]], ["fixture"])


class ARetryIsNotASecondRelay(LifecycleFixture):

    @control(337)
    def test_the_identity_is_reserved_before_the_relay_is_spawned(self):
        key = corerelay.request_key(project_id=self.pid_a, client_id="client-one",
                                    request_id="req-1")
        spawns = self.spy(watch_key=key)

        code, first = self.call("relay.start", self.start_params())
        self.assertEqual(code, 200, first)
        self.assertIs(first["reused"], False)
        self.assertEqual(spawns.reserved_at_spawn, [True],
                         "the relay was spawned before its request identity was written down")

        code, retry = self.call("relay.start", self.start_params())
        self.assertEqual(code, 200, retry)
        self.assertIs(retry["reused"], True)
        self.assertEqual(retry["relay_id"], first["relay_id"])
        self.assertEqual(len(spawns.calls), 1, "a retry started a second relay")

        # A DIFFERENT REQUEST IDENTITY IS DIFFERENT WORK -- that is the contract, and it is what
        # makes the reuse above a deduplication rather than a ceiling.
        code, other = self.call("relay.start", self.start_params(request_id="req-2"))
        self.assertEqual(code, 200, other)
        self.assertNotEqual(other["relay_id"], first["relay_id"])
        self.assertEqual(len(spawns.calls), 2)

    @control(337)
    def test_a_start_that_created_nothing_gives_its_identity_back(self):
        """A failed start must not burn the request identity it never used.

        Keeping it was the shape here first, and it is a dead end: every later retry is
        answered ``200 reused`` for a relay that never existed and never will, so the only way
        forward is a NEW request id -- which is exactly how one request becomes two relays
        against one repository. The reservation is released only on PROOF that nothing was
        started: the process exited without ever writing a durable row.
        """
        spawns = self.spy(take_lock=False, exit_code=2, becomes_running=False)
        code, body = self.call("relay.start", self.start_params(request_id="req-doomed"))
        self.assertEqual(code, 502, body)
        self.assertEqual(body.get("error"), "RELAY_EXITED")
        self.assertIs(body.get("request_id_released"), True)
        key = corerelay.request_key(project_id=self.pid_a, client_id="client-one",
                                    request_id="req-doomed")
        self.assertEqual(corerelay.recall_request(self.home, key), "",
                         "a start that created nothing kept its identity")

        # ...so the retry is a real retry, and this time it works.
        working = self.spy()
        code, retry = self.call("relay.start", self.start_params(request_id="req-doomed"))
        self.assertEqual(code, 200, retry)
        self.assertIs(retry["reused"], False)
        self.assertIs(retry["started"], True)
        self.assertEqual(len(spawns.calls) + len(working.calls), 2)

    @control(337)
    def test_a_request_identity_reused_for_different_work_is_refused(self):
        """An idempotency key that ignores what was asked is worse than no key at all.

        A client deriving its request_id from a ticket or a nightly job name will eventually
        change the objective under it. Handing back the old relay while answering 200 lets the
        client believe the new work is under way.
        """
        self.spy()
        first = self.call("relay.start", self.start_params(request_id="nightly"))[1]
        code, again = self.call("relay.start",
                                self.start_params(request_id="nightly",
                                                  objective="something else entirely"))
        self.assertEqual(code, 409, again)
        self.assertEqual(again.get("error"), "REQUEST_ID_REUSED")
        self.assertEqual(again.get("relay_id"), first["relay_id"])
        # The SAME request is still idempotent.
        code, same = self.call("relay.start", self.start_params(request_id="nightly"))
        self.assertEqual((code, same.get("reused")), (200, True))

    @control(338)
    def test_a_request_identity_is_hashed_and_scoped(self):
        def key(**over):
            args = {"project_id": "p", "client_id": "c", "request_id": "r"}
            args.update(over)
            return corerelay.request_key(**args)

        # The sanitising shape this replaced dropped everything outside [A-Za-z0-9-_] and
        # truncated to 128, so each of these pairs named ONE file.
        self.assertNotEqual(key(request_id="a/b"), key(request_id="ab"))
        self.assertNotEqual(key(request_id="x" * 200),
                            key(request_id="x" * 128 + "y" * 72))
        self.assertNotEqual(key(request_id="a b"), key(request_id="ab"))
        # ...and a request identity belongs to whoever chose it.
        self.assertNotEqual(key(project_id="p1"), key(project_id="p2"))
        self.assertNotEqual(key(client_id="c1"), key(client_id="c2"))
        self.assertEqual(key(), key())

        spawns = self.spy()
        mine = self.call("relay.start", self.start_params(),
                         auth=self.auth(self.pid_a, client_id="ui"))[1]
        theirs = self.call("relay.start", self.start_params(),
                           auth=self.auth(self.pid_a, client_id="tray"))[1]
        self.assertNotEqual(mine["relay_id"], theirs["relay_id"],
                            "one client's request identity reached another client's relay")
        self.assertIs(theirs["reused"], False)
        self.assertEqual(len(spawns.calls), 2)


class OneRelayIsOneProcess(LifecycleFixture):

    @control(339)
    def test_a_second_holder_is_refused_by_the_lock(self):
        self.assertIsNotNone(self.hold("relay-solo"))
        self.assertIsNone(corerelay.hold(self.home, "relay-solo"),
                          "two processes both believed they owned one relay")
        self.assertEqual(corerelay.owned(self.home, "relay-solo")["ownership"],
                         corerelay.OWNED_RUNNING)

    @control(339)
    def test_a_running_relay_cannot_be_resumed_into_a_second(self):
        rid = self.seed_relay("relay-live")
        self.hold(rid)
        spawns = self.spy()
        code, body = self.call("relay.resume", {"project_id": self.pid_a, "relay_id": rid})
        self.assertEqual(code, 409, body)
        self.assertEqual(body.get("error"), "RELAY_ALREADY_RUNNING")
        self.assertEqual(spawns.calls, [], "a duplicate resume spawned a second process")

    @control(339)
    def test_a_relay_in_another_project_answers_as_one_that_does_not_exist(self):
        rid = self.seed_relay("relay-elsewhere", root=self.repo_b)
        spawns = self.spy()
        for op in ("relay.resume", "relay.stop"):
            code, body = self.call(op, {"project_id": self.pid_a, "relay_id": rid})
            self.assertEqual(code, 404, (op, body))
            self.assertEqual(body.get("error"), "NO_SUCH_RELAY")
        self.assertEqual(spawns.calls, [])


class TheLockIsTheEvidence(LifecycleFixture):

    @control(340)
    def test_a_running_row_no_process_holds_is_reported_orphaned_everywhere(self):
        rid = self.seed_relay("relay-orphan")
        # A DISCOVERY HINT left behind by a killed relay must not resurrect it.
        corerelay.record_process(self.home, rid, pid=999999, started_by="core")

        for op, params in (("relay.list", {"project_id": self.pid_a}),
                           ("relay.status", {"project_id": self.pid_a, "relay_id": rid})):
            code, body = self.call(op, params)
            self.assertEqual(code, 200, (op, body))
            row = [r for r in body["relays"] if r["relay_id"] == rid][0]
            self.assertEqual(row["ownership"], corerelay.OWNED_NOT_RUNNING, (op, row))
            self.assertIs(row["orphaned"], True, (op, row))
            self.assertEqual(row["state"], state_mod.RUNNING,
                             "the durable state is reported as it is, not rewritten")

        self.hold(rid)
        for op, params in (("relay.list", {"project_id": self.pid_a}),
                           ("relay.status", {"project_id": self.pid_a, "relay_id": rid})):
            row = [r for r in self.call(op, params)[1]["relays"] if r["relay_id"] == rid][0]
            self.assertEqual(row["ownership"], corerelay.OWNED_RUNNING, (op, row))
            self.assertIs(row["orphaned"], False, (op, row))


class StopIsARequestNotAKill(LifecycleFixture):

    @control(341)
    def test_stop_marks_the_record_and_signals_nothing(self):
        rid = self.seed_relay("relay-stopping")
        self.hold(rid)
        spawns = self.spy()
        code, body = self.call("relay.stop", {"project_id": self.pid_a, "relay_id": rid})
        self.assertEqual(code, 200, body)
        self.assertIs(body["stop_requested"], True)
        self.assertEqual(body["state"], state_mod.STOPPED)
        self.assertEqual(body["stop_reason"], "STOPPED_BY_OPERATOR")
        # The process is STILL RUNNING and Core says so rather than pretending otherwise: it
        # leaves at its next step boundary, so nothing is interrupted mid-delivery.
        self.assertIs(body["process_still_running"], True)
        self.assertEqual(spawns.calls, [], "stop is not a spawn")

    @control(341)
    def test_stop_never_overwrites_the_reason_an_ended_relay_ended(self):
        rid = self.seed_relay("relay-finished", state=state_mod.STOPPED,
                              stop_reason="OBJECTIVE_COMPLETE")
        code, body = self.call("relay.stop", {"project_id": self.pid_a, "relay_id": rid})
        self.assertEqual(code, 200, body)
        self.assertIs(body["stop_requested"], False)
        self.assertEqual(body["stop_reason"], "OBJECTIVE_COMPLETE",
                         "an operator act was invented over the real reason this relay ended")

        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        try:
            self.assertEqual(st.get(rid)["stop_reason"], "OBJECTIVE_COMPLETE")
            self.assertFalse(st.request_stop(rid, "STOPPED_BY_OPERATOR"))
        finally:
            st.close()


class PolicySurvivesTheProcess(LifecycleFixture):

    def resume_namespace(self, *extra):
        return transports_cli.build_parser().parse_args(
            ["relay", "resume", "--relay-id", "r", *extra])

    @control(342)
    def test_a_resumed_relay_keeps_its_own_policy_including_a_deliberate_zero(self):
        recorded = {"max_exchanges": 200, "max_duration_s": 1800.0,
                    "receive_timeout_s": 42.0, "completion_attempt_limit": 0,
                    "check_timeout_s": 7.5, "incomplete_retry_limit": 0,
                    "completion_checks": ["python run_tests.py"],
                    "completion_requires_repo_change": True,
                    "probe_endpoints": False, "observe_repo": False}
        args = self.resume_namespace()
        defaults = {"max_exchanges": args.max_exchanges,
                    "completion_attempts": args.completion_attempts,
                    "incomplete_retries": args.incomplete_retries}

        relay_cli.apply_recorded_policy(args, recorded)
        cfg = relay_cli.relay_config(args, objective="o", authority_profile="STANDARD_EDIT")

        self.assertEqual(cfg.max_exchanges, 200)
        self.assertEqual(cfg.max_duration_s, 1800.0)
        self.assertEqual(cfg.receive_timeout_s, 42.0)
        self.assertEqual(cfg.check_timeout_s, 7.5)
        self.assertEqual(cfg.completion_checks, ("python run_tests.py",))
        self.assertIs(cfg.completion_requires_repo_change, True)
        self.assertIs(cfg.probe_endpoints, False)
        self.assertIs(cfg.observe_repo, False)
        # THE ZEROS. A truthiness test restores neither, and both mean "do not retry".
        self.assertEqual(cfg.completion_attempt_limit, 0)
        self.assertEqual(cfg.incomplete_retry_limit, 0)
        self.assertNotEqual(cfg.completion_attempt_limit, defaults["completion_attempts"])
        self.assertNotEqual(cfg.incomplete_retry_limit, defaults["incomplete_retries"])
        self.assertNotEqual(cfg.max_exchanges, defaults["max_exchanges"])

    @control(342)
    def test_a_flag_may_strengthen_the_recorded_policy_and_never_weaken_it(self):
        recorded = {"completion_checks": ["python run_tests.py"],
                    "completion_requires_repo_change": True, "probe_endpoints": True,
                    "observe_repo": True}
        args = self.resume_namespace("--verify", "python check_static.py")
        relay_cli.apply_recorded_policy(args, recorded)
        cfg = relay_cli.relay_config(args, objective="o", authority_profile="P")
        self.assertEqual(cfg.completion_checks,
                         ("python run_tests.py", "python check_static.py"))
        self.assertIs(cfg.completion_requires_repo_change, True)

        # A relay recorded WITHOUT a requirement is not weakened by a resume that omits the flag,
        # and a relay recorded WITH one cannot be resumed out of it.
        args = self.resume_namespace()
        relay_cli.apply_recorded_policy(args, {"completion_requires_repo_change": True,
                                               "completion_checks": ["python run_tests.py"]})
        cfg = relay_cli.relay_config(args, objective="o", authority_profile="P")
        self.assertIs(cfg.completion_requires_repo_change, True)
        self.assertEqual(cfg.completion_checks, ("python run_tests.py",))

    @control(352)
    def test_a_relay_records_where_its_ends_are_and_no_credential(self):
        """Found by the LIVE run, which the deterministic controls could not have found.

        "The specs come from the record, not from flags" was half true: the kind, the
        conversation and the session came from the record; the base URL, the model and the
        credential source did not. Core resumes with no flags on purpose, so it could start a
        relay and never continue one -- the end was rebuilt pointing at an argparse default.
        """
        spec = {"kind": "openai-chat",
                "config": {"base_url": "https://gateway.invalid/v1", "model": "a-model",
                           "key_var": "SOME_KEY_VAR", "key_file": "/creds/auth.json",
                           "key_file_field": "vendor.key",
                           "transcript_path": "/tmp/should-not-be-recorded",
                           "api_key": "sk-a-real-secret-value"}}
        recorded = relay_cli.recordable_spec(spec)
        blob = json.dumps(recorded)
        self.assertNotIn("sk-a-real-secret-value", blob,
                         "a resolved credential was written into the relay's record")
        self.assertNotIn("api_key", recorded["config"])
        self.assertNotIn("transcript_path", recorded["config"],
                         "a path recomputed from the home must not be frozen into the record")
        self.assertEqual(recorded["config"]["key_var"], "SOME_KEY_VAR")
        self.assertEqual(recorded["config"]["key_file"], "/creds/auth.json")

        saved = {"endpoint_specs": {
            "orchestrator": recorded,
            "execution": relay_cli.recordable_spec(
                {"kind": "opencode", "config": {"base_url": "http://127.0.0.1:51949",
                                                "model": "vendor/a-free-model"}})}}

        args = transports_cli.build_parser().parse_args(
            ["relay", "resume", "--relay-id", "r"])
        args.orchestrator, args.agent = "openai-chat", "opencode"
        args.project = self.repo_a
        # THE CONTROL CAN FAIL: without the restore, the rebuilt ends point nowhere. That is
        # exactly what the live qualification measured, and exactly what killed the relay.
        self.assertEqual(relay_cli.execution_spec(args)["config"]["base_url"], "")
        self.assertEqual(relay_cli.orchestrator_spec(args)["config"]["base_url"], "")

        relay_cli.apply_recorded_endpoints(args, saved)
        orch = relay_cli.orchestrator_spec(args)["config"]
        exe = relay_cli.execution_spec(args)["config"]
        self.assertEqual(orch["base_url"], "https://gateway.invalid/v1")
        self.assertEqual(orch["model"], "a-model")
        self.assertEqual(orch["key_file"], "/creds/auth.json")
        self.assertEqual(orch["key_file_field"], "vendor.key")
        self.assertEqual(exe["base_url"], "http://127.0.0.1:51949")
        self.assertEqual(exe["model"], "vendor/a-free-model")

        # A FLAG THE OPERATOR REALLY TYPED STILL WINS: an agent server that moved must be
        # sayable, and the record must not overrule a person who is looking at the machine.
        moved = transports_cli.build_parser().parse_args(
            ["relay", "resume", "--relay-id", "r", "--agent-base-url", "http://127.0.0.1:9999"])
        moved.agent, moved.project = "opencode", self.repo_a
        relay_cli.apply_recorded_endpoints(moved, saved)
        self.assertEqual(relay_cli.execution_spec(moved)["config"]["base_url"],
                         "http://127.0.0.1:9999")

    @control(352)
    def test_the_record_is_brought_up_to_date_rather_than_replaced(self):
        """A relay's record must survive being written to, and must not go stale.

        Two failures at once if this is wrong. Replace instead of merge, and the first spec
        write destroys every ceiling and every verification command the kernel recorded. Write
        only at start, and a policy an operator STRENGTHENED on one resume is silently dropped
        by the next -- the fourth policy-loss-on-resume defect in this file, and the one
        consolidating the reader did not reach.
        """
        # A row that already carries a real, non-default policy, exactly as the kernel writes it.
        started = kernel_mod.RelayConfig(
            max_exchanges=200, completion_checks=("python run_tests.py",),
            completion_requires_repo_change=True, incomplete_retry_limit=0,
            probe_endpoints=False)
        rid = self.seed_relay("relay-specs", config={
            **kernel_mod.persisted_policy(started),
            "orchestrator_facts": {"kind": "openai-chat"}, "execution_assurance": "MEASURED"})

        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        try:
            # Now a resume that STRENGTHENED the policy writes the shape back.
            strengthened = kernel_mod.RelayConfig(
                max_exchanges=200, completion_checks=("python run_tests.py",
                                                      "python check_static.py"),
                completion_requires_repo_change=True, incomplete_retry_limit=0,
                probe_endpoints=False)
            relay_cli.record_relay_shape(
                st, rid, strengthened,
                {"kind": "openai-chat", "config": {"base_url": "https://b", "model": "m",
                                                   "api_key": "sk-secret"}},
                {"kind": "opencode", "config": {"base_url": "http://a", "model": "n"}})
            blob = st.get(rid)["config_json"]
        finally:
            st.close()

        self.assertNotIn("sk-secret", blob, "a credential reached the relay's record")
        saved = json.loads(blob)
        specs = saved["endpoint_specs"]
        self.assertEqual(specs["orchestrator"]["config"]["base_url"], "https://b")
        self.assertEqual(specs["execution"]["config"]["model"], "n")
        # MERGED: what the writer does not own is still there.
        self.assertEqual(saved["orchestrator_facts"], {"kind": "openai-chat"})
        self.assertEqual(saved["execution_assurance"], "MEASURED")
        # CURRENT: the strengthened policy is what the next resume will read back.
        self.assertEqual(saved["completion_checks"],
                         ["python run_tests.py", "python check_static.py"])
        self.assertEqual(saved["incomplete_retry_limit"], 0)
        self.assertEqual(saved["max_exchanges"], 200)
        self.assertIs(saved["probe_endpoints"], False)

    @control(352)
    def test_every_policy_field_the_reader_wants_is_a_field_the_writer_writes(self):
        """The writer and the reader must not drift, and only a test can hold them together.

        Three consecutive reviews of this relay found a policy field that one side knew about
        and the other did not -- corroboration, then the probe, then four ceilings. Naming the
        two sets and comparing them is the only thing that stops the fourth.
        """
        written = set(kernel_mod.persisted_policy(kernel_mod.RelayConfig()))
        read = set(relay_cli.recorded_policy_keys())
        self.assertEqual(read - written, set(),
                         "a resume reads a policy key nothing ever writes")
        self.assertEqual(written - read, set(),
                         "a policy key is written and never read back, so a resume resets it")
        # And every one of them is a real RelayConfig field, not a name that drifted.
        fields = {f.name for f in dataclasses.fields(kernel_mod.RelayConfig)}
        for key in written:
            self.assertIn(key.replace("_s", "_s") if key in fields else key, fields | {
                "max_duration_s", "receive_timeout_s", "check_timeout_s"}, key)

    @control(342)
    def test_the_resume_path_is_actually_wired_to_the_functions_that_restore(self):
        """STRUCTURAL, because the alternative is not available.

        Controls 342 and 352 call ``apply_recorded_policy``, ``apply_recorded_endpoints`` and
        ``record_relay_shape`` directly -- the relay CLI refuses scripted endpoints, correctly,
        so a control cannot drive ``cmd_relay_resume`` end to end without real providers. That
        leaves one mutation those controls cannot see: DELETING THE CALL. Each of the three
        restores a defect a live run actually hit, and each is one line.
        """
        import ast
        with open(relay_cli.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=relay_cli.__file__)
        functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        for verb, required in (("cmd_relay_start", ("relay_config", "record_relay_shape")),
                               ("cmd_relay_resume", ("apply_recorded_policy",
                                                     "apply_recorded_endpoints",
                                                     "relay_config", "record_relay_shape",
                                                     "hold"))):
            self.assertIn(verb, functions)
            called = {ast.unparse(n.func).split(".")[-1]
                      for n in ast.walk(functions[verb]) if isinstance(n, ast.Call)}
            for name in required:
                self.assertIn(name, called, "%s no longer calls %s" % (verb, name))
        # AND THE ORDER: the lock is taken BEFORE the ends are built, so a second resume cannot
        # attach a browser and create an agent session before discovering it lost the race --
        # and no reader sees the relay as orphaned for the length of that build.
        # THE TERMINAL STOP NAMES ARE THE KERNEL'S. Core spells them as literals because it does
        # not import the relay at module level, and a literal that no longer names a real stop
        # reason silently stops refusing the resume it was written to refuse.
        real = {v for n, v in vars(kernel_mod).items()
                if n.startswith("STOP_") and isinstance(v, str)}
        self.assertEqual(set(cs.TERMINAL_STOPS) - real, set(),
                         "a terminal stop reason Core refuses to resume is not a stop reason "
                         "the kernel can produce")
        self.assertIn(kernel_mod.STOP_OBJECTIVE_COMPLETE, cs.TERMINAL_STOPS)
        # ...and the reasons a relay is RECOVERED from must NOT be in it, or crash recovery --
        # the whole point of resume -- would be refused.
        for recoverable in (kernel_mod.STOP_OPERATOR, kernel_mod.STOP_OWNER_HOLD,
                            kernel_mod.STOP_EXECUTION_DISCONNECT,
                            kernel_mod.STOP_ORCHESTRATOR_DISCONNECT,
                            kernel_mod.STOP_UNRECONCILABLE, kernel_mod.STOP_START_REFUSED):
            self.assertNotIn(recoverable, cs.TERMINAL_STOPS, recoverable)

        resume = functions["cmd_relay_resume"]
        order = [ast.unparse(n.func).split(".")[-1]
                 for n in ast.walk(resume) if isinstance(n, ast.Call)
                 and ast.unparse(n.func).split(".")[-1] in ("hold", "_build_ends")]
        self.assertEqual(order[:2], ["hold", "_build_ends"],
                         "resume builds its endpoints before it knows it owns the relay")

    @control(343)
    def test_core_resumes_a_relay_with_no_policy_on_the_command_line(self):
        argv = corerelay.resume_argv(self.home, "relay-x", launcher=cs.RELAY_LAUNCHER)
        policy_flags = (set(corerelay.PROFILE_FIELDS.values())
                        | set(corerelay.PROFILE_LIST_FIELDS.values())
                        | set(corerelay.PROFILE_FLAG_FIELDS.values())
                        | {"--project", "--objective"})
        self.assertEqual(set(argv) & policy_flags, set(),
                         "a resume carried policy that belongs to the relay's own record")

        # TWO registered profiles, so an arbitrary fallback would be visible: the shape this
        # replaced picked profiles[0] whenever the named profile was missing.
        corerelay.register_profile(self.home, name="second", project_id=self.pid_a,
                                   fields={"orchestrator": "openai-chat",
                                           "orchestrator_model": "some-other-model"})
        rid = self.seed_relay("relay-paused", state=state_mod.PAUSED)
        spawns = self.spy()
        code, body = self.call("relay.resume",
                               {"project_id": self.pid_a, "relay_id": rid,
                                "profile": "does-not-exist"})
        self.assertEqual(code, 200, body)
        self.assertIs(body["resumed"], True)
        self.assertEqual(spawns.calls,
                         [corerelay.resume_argv(self.home, rid,
                                                launcher=cs.RELAY_LAUNCHER)])
        flat = "\x00".join(spawns.calls[0])
        self.assertNotIn("a-registered-model", flat)
        self.assertNotIn("some-other-model", flat)

    @control(344)
    def test_core_cannot_resume_past_an_owner_hold_and_says_what_is_needed(self):
        """Core accepting a request is not an owner deciding.

        The guarantee lives in the kernel -- ``owner_holds_blocking``, which every resume goes
        through whoever asked. Core calls the SAME function so it can answer without starting a
        process, which is a courtesy and not the guarantee: a caller who bypasses Core entirely
        gets the same refusal from the relay itself.
        """
        from quaestor.core import authority as auth_mod
        from quaestor.relay import effects as effects_mod

        rid = self.seed_relay("relay-held", state=state_mod.OWNER_HOLD,
                              owner_hold="a GIT_PUSH the profile does not grant")
        hid = effects_mod.hold_id(rid, "observation", effects_mod.GIT_PUSH,
                                  [auth_mod.CAP_GIT_PUSH])
        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        try:
            st.append_event(rid, kernel_mod.EVENT_HOLD_RAISED,
                            {"hold_id": hid, "gate": "observation",
                             "effect_class": effects_mod.GIT_PUSH,
                             "required": [auth_mod.CAP_GIT_PUSH], "message_id": "",
                             "reason": "the repository shows a push nobody granted"})
        finally:
            st.close()

        spawns = self.spy()
        code, body = self.call("relay.resume", {"project_id": self.pid_a, "relay_id": rid})
        self.assertEqual(code, 409, body)
        self.assertEqual(body.get("error"), "OWNER_ACTION_REQUIRED")
        # IT NAMES WHAT IS NEEDED. A client told only "held" cannot tell its operator what to
        # sign, and neither can the operator.
        self.assertEqual([h["hold_id"] for h in body.get("holds") or []], [hid])
        self.assertEqual((body["holds"][0])["required"], [auth_mod.CAP_GIT_PUSH])
        self.assertIn("OWNER", body["detail"])
        self.assertEqual(spawns.calls, [],
                         "Core started a relay for a hold no owner has discharged")

        # ASKING AGAIN IS NOT DECIDING, and neither is asking as somebody else: a second
        # authorised client of the same project gets the same answer.
        for label, auth in (("retry", None),
                            ("another client", self.auth(self.pid_a, client_id="tray"))):
            code, again = self.call("relay.resume",
                                    {"project_id": self.pid_a, "relay_id": rid}, auth=auth)
            self.assertEqual(code, 409, (label, again))
            self.assertEqual(again.get("error"), "OWNER_ACTION_REQUIRED", label)
        self.assertEqual(spawns.calls, [])

        # AND NEITHER IS A CLIENT SAYING SO. A payload that claims approval changes nothing.
        code, forged = self.call("relay.resume",
                                 {"project_id": self.pid_a, "relay_id": rid,
                                  "owner_approved": True, "owner_grant": "git_push",
                                  "grants": [auth_mod.CAP_GIT_PUSH], "force": True})
        self.assertEqual(code, 409, forged)
        self.assertEqual(forged.get("error"), "OWNER_ACTION_REQUIRED")
        self.assertEqual(spawns.calls, [],
                         "a client payload claiming owner approval started a relay")


class TheIdleTimerMeasuresItsObligations(LifecycleFixture):

    @control(345)
    def test_a_held_lock_and_an_owner_hold_obligate_core_and_an_orphan_does_not(self):
        self.assertIs(cs.has_obligations(self.home)["obligated"], False,
                      "an empty home obligates nothing")

        rid = self.seed_relay("relay-running")
        orphan = cs.has_obligations(self.home)
        self.assertIs(orphan["obligated"], False,
                      "an orphaned row pinned Core alive forever over work that already stopped")
        self.assertEqual(orphan["live_relays"], [])

        self.hold(rid)
        live = cs.has_obligations(self.home)
        self.assertIs(live["obligated"], True, "Core would idle-shut-down over a live relay")
        self.assertEqual(live["live_relays"], [rid])

        self._drop_locks()
        self.seed_relay("relay-on-hold", state=state_mod.OWNER_HOLD,
                        owner_hold=json.dumps({"decision": "REFUSE"}))
        held = cs.has_obligations(self.home)
        self.assertIs(held["obligated"], True,
                      "an owner's held decision had nowhere to arrive")
        self.assertIn("relay-on-hold", held["owner_holds"])


class CoreStartsOnDemand(LifecycleFixture):

    @control(351)
    def test_a_client_can_start_core_on_demand_and_gets_one_answer(self):
        """The on-demand start a UI actually needs, and it runs a REAL detached Core.

        ``serve --detach`` refuses when a Core is already up, which is right for an operator
        typing it and wrong for a client that only wants to know there IS a Core. This one is
        idempotent, and it is exercised against a real process because the property is about a
        process: a Core that is merely believed to be running is the failure mode.

        The process is owned by a fleet with a ceiling and a guaranteed cleanup, so a control
        about starting a service cannot itself leave one behind.
        """
        fleet = procsafe.Fleet(deadline_s=180.0)
        self.addCleanup(fleet.close)
        argv = transports_cli.build_parser().parse_args(
            ["core", "ensure", "--home", self.home, "--idle", "20"])

        out = _capture(transports_cli.cmd_core_ensure, argv)
        core_pid = int(out.get("pid") or 0)
        fleet.adopt(core_pid, "core (on demand)")
        self.assertTrue(out.get("running"), out)
        self.assertIs(out.get("reused"), False, out)
        self.assertTrue(out.get("url"), out)

        # THE SECOND ASK FINDS, RATHER THAN STARTS.
        again = _capture(transports_cli.cmd_core_ensure, argv)
        self.assertTrue(again.get("running"), again)
        self.assertIs(again.get("reused"), True, again)
        self.assertEqual(int(again.get("pid") or 0), core_pid)
        self.assertEqual(again.get("url"), out.get("url"))

        # LIVENESS IS MEASURED. Kill Core and leave its endpoint file exactly where it is: a
        # client handed that file would be handed a dead address.
        #
        # TWO DIFFERENT QUESTIONS, ASKED SEPARATELY. "The process is gone" is not "the process
        # has released its lock": ``kill`` returns when the signal is delivered and the kernel
        # tears the process down afterwards, so on Linux the pid stops answering ~2.4 ms BEFORE
        # the flock goes. This assertion used to infer the second from the first and failed on
        # every Linux run while passing on Windows, where a handle dies with its process.
        fleet.terminate(core_pid, what="core (on demand)")
        self.assertTrue(fleet.wait_gone(core_pid, timeout_s=60),
                        "the Core process is still in the process table")
        self.assertTrue(fleet.wait_released(cs.lock_path(self.home), timeout_s=60),
                        "the Core process is gone but has not released its lock")
        fleet.forget(core_pid)
        # ...and NOW the real property: the stale endpoint file is still on disk, and Core is
        # reported not-running anyway, because the answer comes from the lock and never from
        # the file. A `running` that trusted the file would say True here forever.
        self.assertTrue(cs.read_endpoint(self.home),
                        "the stale endpoint file must still be there for this to mean anything")
        self.assertFalse(cs.running(self.home)["running"])

        third = _capture(transports_cli.cmd_core_ensure, argv)
        fleet.adopt(int(third.get("pid") or 0), "core (restarted on demand)")
        self.assertTrue(third.get("running"), third)
        self.assertIs(third.get("reused"), False, third)
        self.assertNotEqual(int(third.get("pid") or 0), core_pid)

        self.assertEqual(fleet.close()["leaked"], [],
                         "a control that starts a service left one behind")


def _capture(fn, args) -> dict:
    """Run a CLI verb and read the JSON it prints, without a subprocess."""
    import contextlib
    import io as _io
    buf = _io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(args)
    return json.loads(buf.getvalue() or "{}")


class TheHarnessCannotLeak(unittest.TestCase):
    """Ownership semantics only. Nothing here reads this machine's process table."""

    def fleet(self, **kw):
        self.killed: list = []
        self.living = set(kw.pop("living", ()))

        def killer(pid):
            self.killed.append(int(pid))
            self.living.discard(int(pid))

        return procsafe.Fleet(killer=killer, alive=lambda pid: int(pid) in self.living, **kw)

    @control(347)
    def test_termination_is_one_process_and_never_a_tree(self):
        # THE PLATFORM IS INJECTED, not swapped into ``os.name``. The version that reassigned
        # the real module global was doing so while Core's own server threads, the liveness
        # oracle and ``spawn_detached_kwargs`` were reading it in the same process.
        windows = procsafe.kill_argv(4321, windows=True)
        posix = procsafe.kill_argv(4321, windows=False)
        self.assertEqual(windows, ["taskkill", "/PID", "4321", "/F"])
        self.assertNotIn("/T", windows, "a tree kill would take the relay down with Core")
        self.assertEqual(posix, ["kill", "-9", "4321"])
        # ...and the branch this machine actually takes is the one it should.
        self.assertEqual(procsafe.kill_argv(4321),
                         windows if os.name == "nt" else posix)

        # The two ways of accidentally writing a tree kill are refused, not merely avoided: /T
        # above, and a NEGATIVE pid, which on POSIX signals the whole process group.
        for bad in (0, -1, -4321):
            for windows_flag in (True, False):
                with self.assertRaises(ValueError):
                    procsafe.kill_argv(bad, windows=windows_flag)

    @control(348)
    def test_cleanup_runs_on_the_failure_path_and_reports_what_it_ended(self):
        fleet = self.fleet(living=(101, 102))
        with self.assertRaises(RuntimeError):
            with fleet as f:
                f.adopt(101, "core")
                f.adopt(102, "relay")
                raise RuntimeError("the qualification failed in the middle")
        report = fleet.cleanup_report
        self.assertEqual(sorted(self.killed), [101, 102],
                         "a failing run left its processes behind")
        self.assertEqual(report["leaked"], [])
        self.assertEqual(sorted(r["pid"] for r in report["terminated"]), [101, 102])
        self.assertEqual([r["what"] for r in report["terminated"]], ["core", "relay"])

        # The passing path is the same path.
        passing = self.fleet(living=(201,))
        with passing as f:
            f.adopt(201, "core")
        self.assertEqual(self.killed, [201])
        self.assertEqual(passing.cleanup_report["leaked"], [])

        # A leak is REPORTED rather than hidden: cleanup that could not end something must say
        # so, because that is the verdict the run leaked.
        stubborn = procsafe.Fleet(killer=lambda pid: None, alive=lambda pid: True,
                                  deadline_s=2.0)
        with stubborn as f:
            f.adopt(303, "wedged core")
        self.assertEqual([r["pid"] for r in stubborn.cleanup_report["leaked"]], [303])

        # ONE STUBBORN PROCESS MUST NOT ABORT THE REST. Cleanup runs inside a ``finally``, and a
        # killer that raised used to escape it and leak every process later in the list.
        ended = []

        living = {401, 402, 403}

        def awkward(pid):
            if int(pid) == 401:
                raise OSError("taskkill wedged on an uninterruptible wait")
            ended.append(int(pid))
            living.discard(int(pid))

        biting = procsafe.Fleet(killer=awkward, alive=lambda pid: int(pid) in living,
                                deadline_s=2.0)
        with biting as f:
            f.adopt(401, "wedged")
            f.adopt(402, "core")
            f.adopt(403, "relay")
        self.assertEqual(sorted(ended), [402, 403],
                         "one process that would not die aborted the whole cleanup")
        self.assertEqual([r["pid"] for r in biting.cleanup_report["leaked"]], [401])

    @control(348)
    def test_a_pid_the_os_has_recycled_is_released_and_not_killed(self):
        """The stale-pid-reuse kill: the one mistake this harness exists to not make.

        A relay is adopted by the pid in its discovery hint; by cleanup time that relay may have
        been gone for a minute and the number handed to something else. Killing by pid alone --
        which is what the first version did -- ends a stranger's process and reports success.
        ``core.proc.process_create_time`` exists in this tree for exactly this reason.
        """
        killed = []
        births = {501: "born-at-A", 502: "born-at-B"}
        living = {501, 502}

        def kill(pid):
            killed.append(int(pid))
            living.discard(int(pid))

        fleet = procsafe.Fleet(killer=kill, alive=lambda pid: int(pid) in living,
                               deadline_s=5.0)
        fleet.identity = lambda pid: births.get(int(pid), "")
        fleet.adopt(501, "relay")
        fleet.adopt(502, "core")
        births[501] = "born-at-C"          # the OS recycled 501 into something else
        report = fleet.close()
        self.assertEqual(killed, [502], "a recycled pid was killed as though it were ours")
        self.assertEqual([r["pid"] for r in report["released"]], [501])
        self.assertEqual(report["leaked"], [])

    @control(349)
    def test_the_ceiling_is_real_and_raises_into_its_own_cleanup(self):
        now = [1000.0]
        fleet = procsafe.Fleet(deadline_s=30.0, clock=lambda: now[0],
                               killer=lambda pid: self.__dict__.setdefault(
                                   "late", []).append(pid),
                               alive=lambda pid: True)
        fleet.check_deadline("early")
        self.assertAlmostEqual(fleet.remaining(), 30.0)
        now[0] = 1029.0
        fleet.check_deadline("still inside")
        now[0] = 1031.0
        self.assertTrue(fleet.expired())

        with self.assertRaises(procsafe.DeadlineExceeded):
            with fleet as f:
                f.adopt(777, "core")
                f.check_deadline("past the ceiling")
        self.assertEqual(self.late, [777],
                         "the run passed its ceiling and kept its processes alive")

        # THE PRODUCTION CONSUMERS REFUSE, not just the checker. A run that has passed its
        # ceiling and goes on spawning is precisely the failure that had to be stopped by hand.
        spent = procsafe.Fleet(deadline_s=0.0, killer=lambda pid: None, alive=lambda pid: False)
        with self.assertRaises(procsafe.DeadlineExceeded):
            spent.spawn([sys.executable, "-c", "pass"], what="should never start")
        with self.assertRaises(procsafe.DeadlineExceeded):
            spent.run([sys.executable, "-c", "pass"], what="should never run")
        self.assertEqual(spent.owned, {}, "a spawn past the ceiling still tracked something")
        spent.close()

        # ...and a WAIT cannot outlive the budget either: ``check_deadline`` passing with a
        # fraction of a second left and then a 45-second wait beginning is a ceiling in name
        # only. Measured against the real clock, because that is the one the wait sleeps on.
        tight = procsafe.Fleet(deadline_s=0.3, killer=lambda pid: None,
                               alive=lambda pid: True)
        began = time.time()
        self.assertFalse(tight.wait_gone(1234, timeout_s=45.0, tick=0.05))
        self.assertLess(time.time() - began, 5.0,
                        "a wait ran past the run's whole remaining budget")
        tight.close()

    @control(350)
    def test_a_fleet_owns_only_what_it_created(self):
        fleet = self.fleet(living=(11, 22, 33))
        with fleet as f:
            f.adopt(11, "core")
            # 22 is a look-alike -- another session's Core, an unrelated repository's work --
            # and it is alive, and it is not this run's.
            f.adopt(33, "relay")
            f.forget(33)          # its death is the thing under test; the test owns it now
        self.assertEqual(self.killed, [11],
                         "cleanup ended a process this run did not create")
        self.assertIn(22, self.living)
        self.assertIn(33, self.living)

    @control(350)
    def test_the_independent_scan_actually_reads_the_process_table(self):
        """It is quoted by a verdict, so it must be capable of finding something.

        A scan pointed at a name that matches nothing proves only that the function returns a
        dict. This one looks for a string that is certainly present -- this very interpreter --
        and then for one that is certainly not.
        """
        needle = os.path.basename(sys.executable).split(".")[0]
        found = procsafe.independent_leak_check(names=(needle,))
        self.assertTrue(found["measured"], found)
        self.assertGreaterEqual(found["count"], 1,
                                "the scan could not find the interpreter running it: %s" % found)
        # THE PRECISE ORACLE: this very process is in the table, and the scan found it. Each row
        # begins with the pid, so a scan that returned an empty or malformed table fails here.
        self.assertTrue(any(line.split(" ")[0] == str(os.getpid())
                            for line in found["matches"]),
                        "the scan did not find the process running it: %s"
                        % found["matches"][:3])

        absent = procsafe.independent_leak_check(names=("a-name-that-matches-nothing-xyz",))
        self.assertTrue(absent["measured"])
        self.assertEqual(absent["count"], 0)
        # REPORTS, NEVER KILLS -- structurally, not by its own say-so.
        import ast
        with open(procsafe.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=procsafe.__file__)
        scan = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                and n.name == "independent_leak_check"][0]
        called = {ast.unparse(n.func) for n in ast.walk(scan) if isinstance(n, ast.Call)}
        for forbidden in ("kill_argv", "self._kill", "_real_kill", "os.kill"):
            self.assertNotIn(forbidden, called,
                             "the scan that reports look-alikes can end one")

    @control(350)
    def test_a_spawned_process_is_tracked_at_creation_and_ended_at_close(self):
        """Rule 1 of this module, exercised against a real process rather than described.

        ``spawn`` is what the qualification uses for every service it starts, and it had no
        control at all: deleting the line that tracks the child left every other harness control
        green while restoring the original leak.
        """
        fleet = procsafe.Fleet(deadline_s=60.0)
        self.addCleanup(fleet.close)
        child = fleet.spawn([sys.executable, "-c", "import time; time.sleep(60)"],
                            what="a process that will not end on its own")
        self.assertIn(child.pid, fleet.owned, "a spawned process was not tracked")
        self.assertEqual(fleet.owned[child.pid][0],
                         "a process that will not end on its own")
        self.assertTrue(fleet.alive(child.pid))
        report = fleet.close()
        self.assertEqual([r["pid"] for r in report["terminated"]], [child.pid])
        self.assertEqual(report["leaked"], [], report)
        self.assertFalse(fleet.alive(child.pid), "close() left a real process running")

    @control(350)
    def test_a_process_that_has_already_exited_is_not_reported_alive(self):
        """The defect Linux CI found and Windows structurally cannot produce.

        On POSIX a child that has exited stays in the process table as a ZOMBIE until its parent
        reaps it, and ``os.kill(pid, 0)`` SUCCEEDS for a zombie because the pid is still there.
        So the fleet killed everything correctly, asked "is it alive?", was told yes, and
        reported a leak on a run that had cleaned up perfectly -- turning a working cleanup into
        a failed qualification. Windows has no such state, so this passes there either way; on
        Linux it fails without the fix.
        """
        fleet = procsafe.Fleet(deadline_s=60.0)
        self.addCleanup(fleet.close)
        child = fleet.spawn([sys.executable, "-c", "pass"], what="a process that ends at once")
        self.assertTrue(fleet.wait_gone(child.pid, timeout_s=30, tick=0.2),
                        "a process that exited on its own is still reported alive")
        self.assertFalse(fleet.alive(child.pid))
        self.assertEqual(fleet.close()["leaked"], [], "a reaped child was reported leaked")

    @control(350)
    def test_a_second_run_cannot_inherit_the_first_runs_core(self):
        first = procsafe.Fleet(killer=lambda pid: None, alive=lambda pid: False)
        home = first.temp_dir("quaestor-qual-")
        endpoint = os.path.join(home, "core-endpoint.json")
        with open(endpoint, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"url": "http://127.0.0.1:1", "pid": 4242}))
        report = first.close()
        # THE ENDPOINT A RUN LEFT IS GONE WITH THE RUN, so nothing can discover it and attach.
        self.assertFalse(os.path.exists(endpoint), "a run left its Core's endpoint on disk")
        self.assertFalse(os.path.exists(home), "a run left its state home on disk")
        self.assertEqual(report["dirs_removed"], [home])
        self.assertEqual(report["dirs_kept"], [])

        # A directory it could NOT remove is reported kept, not claimed as removed: the report
        # is a measurement, and ``ignore_errors`` made it a wish.
        keeper = procsafe.Fleet(killer=lambda pid: None, alive=lambda pid: False,
                                keep_dirs=True)
        kept_home = keeper.temp_dir("quaestor-qual-")
        kept = keeper.close()
        self.assertEqual(kept["dirs_kept"], [kept_home])
        self.assertEqual(kept["dirs_removed"], [])
        self.assertTrue(os.path.exists(kept_home))
        shutil.rmtree(kept_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

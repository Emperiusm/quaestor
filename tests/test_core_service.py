"""test_core_service -- controls 316-327, 365-369 and 397-398. The Core service boundary.

(bd 0fe.1, bd d47, bd quaestor-mpp.)

WHAT A SERVICE BOUNDARY IS FOR, AND WHAT THESE CONTROLS PROVE
--------------------------------------------------------------
Core exists so that a future browser extension, web UI or tray can reach Quaestor WITHOUT
reaching the machine. That is only true if the boundary is genuinely NARROWER than what sits
behind it, so these controls attack the boundary rather than exercising it:

    an unauthenticated caller gets nothing
    a caller authenticated for one project cannot see another exists
    there is no operation that runs a command, reads a file, or takes a path
    a second Core cannot race the first
    a killed Core is detected by the LOCK, never by trusting the file it left behind
    identity and authorisations survive a restart

Every HTTP control drives a REAL server on a real loopback socket. Mocking the transport would
mock away the thing under test: the boundary IS the transport.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from tests.controls import control

from quaestor.core import coreauth, coreid, corerelay
from quaestor.relay import cli as relay_cli
from quaestor.relay import state as state_mod
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


class CoreFixture(unittest.TestCase):
    """A real home, two real repositories, and a real server on a real port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self._tmp.name, "home")
        os.makedirs(self.home)
        self.repo_a = make_repo(os.path.join(self._tmp.name, "alpha"))
        self.repo_b = make_repo(os.path.join(self._tmp.name, "beta"))
        self.pid_a = coreid.authorize(self.home, self.repo_a)["project_id"]
        self.pid_b = coreid.authorize(self.home, self.repo_b)["project_id"]
        self.addCleanup(self._tmp.cleanup)

    def client(self, *, projects=()):
        issued = coreauth.issue(self.home, name="test", project_ids=list(projects))
        return issued["value_returned_once"], issued

    def server(self):
        httpd, port = cs.build_server(self.home, port=0, idle_s=0.0)
        t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05},
                             daemon=True)
        t.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return "http://127.0.0.1:%d" % port

    def rpc(self, url, token, operation, params=None, version=cs.PROTOCOL_VERSION):
        body = json.dumps({"operation": operation, "params": params or {},
                           "protocol_version": version}).encode("utf-8")
        req = urllib.request.Request(url + "/rpc", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return int(r.status), json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return int(exc.code), json.loads(exc.read().decode("utf-8"))
            except Exception:                                        # noqa: BLE001
                return int(exc.code), {}


class TestCoreBoundary(CoreFixture):

    @control(316)
    def test_an_unauthenticated_caller_reaches_nothing_but_liveness(self):
        url = self.server()
        with urllib.request.urlopen(url + "/health", timeout=10) as r:
            health = json.loads(r.read().decode("utf-8"))
        # Liveness must be reachable before a client has a credential, and must disclose
        # nothing: not the device, not the projects, not whether any token would work.
        self.assertEqual(health["status"], "ok")
        for leak in ("device", "device_id", "projects", "clients", "home", "relays"):
            self.assertNotIn(leak, health)
        for token in ("", "not-a-real-token", "Bearer", " "):
            code, body = self.rpc(url, token, "core.status")
            self.assertEqual(code, 401, token)
            # ONE refusal for absent, malformed, unknown and revoked -- any difference is an
            # oracle a guesser can climb.
            self.assertEqual(body.get("error"), coreauth.REFUSAL)

    @control(317)
    def test_a_token_for_one_project_cannot_reach_another(self):
        """The acceptance criterion of this milestone, driven over a real socket."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        code, body = self.rpc(url, token, "relay.list", {"project_id": self.pid_a})
        self.assertEqual(code, 200, body)
        for op in ("relay.list", "relay.status"):
            code, body = self.rpc(url, token, op, {"project_id": self.pid_b})
            self.assertEqual(code, 403, op)
            self.assertEqual(body.get("error"), "PROJECT_NOT_AUTHORIZED")
        # A project the client cannot reach and a project that does not exist answer THE SAME.
        # Telling a client that a project it may not touch nevertheless exists is a disclosure.
        _, unknown = self.rpc(url, token, "relay.list", {"project_id": "local:nope"})
        self.assertEqual(unknown.get("error"), "PROJECT_NOT_AUTHORIZED")
        # And the listing shows only the grant.
        code, body = self.rpc(url, token, "projects.list")
        self.assertEqual([p["project_id"] for p in body["projects"]], [self.pid_a])

    @control(318)
    def test_an_empty_scope_reaches_no_project_at_all(self):
        """A status-only client is a real thing, and must not be promoted to 'everything'."""
        url = self.server()
        token, _ = self.client(projects=[])
        code, _ = self.rpc(url, token, "core.status")
        self.assertEqual(code, 200)             # it can still ask about Core itself
        for pid in (self.pid_a, self.pid_b):
            code, body = self.rpc(url, token, "relay.list", {"project_id": pid})
            self.assertEqual(code, 403)
        self.assertFalse(coreauth.may_reach({"ok": True, "project_ids": []}, self.pid_a))
        # There is NO wildcard. A scope that can grow without an operator is not a scope.
        for wildcard in ("*", "all", "ALL", ""):
            self.assertFalse(coreauth.may_reach(
                {"ok": True, "project_ids": [wildcard]}, self.pid_a), wildcard)

    @control(319)
    def test_the_api_exposes_no_machine_power(self):
        """A boundary is worth having only if it is narrower than the machine behind it."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        for op in ("execute", "exec", "shell", "run", "read_file", "write_file", "core.exec",
                   "system", "eval", "git", "subprocess"):
            code, body = self.rpc(url, token, op, {"command": "echo hi", "path": self.repo_a})
            self.assertEqual(code, 404, op)
            self.assertEqual(body.get("error"), "NO_SUCH_OPERATION")
        # The declared surface is small, and every declared operation really is routable.
        for op in cs.OPERATIONS:
            code, _ = self.rpc(url, token, op, {"project_id": self.pid_a})
            self.assertNotEqual(code, 404, op)
        # STRUCTURAL, and asked of the PARSE TREE rather than of the text. A substring scan of a
        # module whose docstring DOCUMENTS what it refuses to do matches its own prose -- which
        # is how the first version of this control failed on the sentence "no endpoint runs a
        # subprocess". A comment cannot execute; an import can.
        import ast
        with open(cs.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=cs.__file__)
        imported, called = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call):
                called.add(ast.unparse(node.func))
        for forbidden in ("subprocess", "shutil", "pty", "ctypes"):
            self.assertNotIn(forbidden, imported, "%s is imported" % forbidden)
        for forbidden in ("eval", "exec", "compile", "__import__", "os.system", "os.popen",
                          "os.spawnv", "os.execv"):
            self.assertNotIn(forbidden, called, "%s is called" % forbidden)
        # ``open`` and ``os.remove`` ARE used, and legitimately: Core writes and clears its OWN
        # endpoint record. Forbidding them outright would be a control that lies about what the
        # module needs. The property that actually matters -- that no path a CALLER supplies
        # ever reaches the filesystem -- is behavioural, and control 320 drives it over HTTP.
        self.assertIn("open", called)

    @control(320)
    def test_a_path_from_the_caller_never_reaches_the_filesystem(self):
        """Projects are named by ID. A path parameter would be a way around the registry."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        for attempt in (self.repo_b, "/", "C:\\", "../../..", self.home):
            for key in ("path", "project_root", "project", "root", "cwd"):
                code, body = self.rpc(url, token, "relay.list", {key: attempt})
                # No path key is honoured: the request is refused for want of a project_id.
                self.assertEqual(code, 403, "%s=%s" % (key, attempt))
                self.assertIn(body.get("error"), ("PROJECT_REQUIRED", "PROJECT_NOT_AUTHORIZED"))

    @control(321)
    def test_a_revoked_client_is_refused_immediately_without_a_restart(self):
        url = self.server()
        token, issued = self.client(projects=[self.pid_a])
        self.assertEqual(self.rpc(url, token, "core.status")[0], 200)
        coreauth.revoke(self.home, issued["client_id"])
        code, body = self.rpc(url, token, "core.status")
        self.assertEqual(code, 401)
        self.assertEqual(body.get("error"), coreauth.REFUSAL)
        # The record is KEPT so an operator can still ask what that token could reach.
        rows = {r["client_id"]: r for r in coreauth.clients(self.home)}
        self.assertIsNotNone(rows[issued["client_id"]]["revoked_at"])
        self.assertNotIn("sha256", rows[issued["client_id"]])

    @control(322)
    def test_a_protocol_mismatch_and_an_oversized_body_fail_clearly(self):
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        code, body = self.rpc(url, token, "core.status", version=cs.PROTOCOL_VERSION + 5)
        self.assertEqual(code, 400)
        self.assertEqual(body.get("error"), "PROTOCOL_VERSION_MISMATCH")

        big = json.dumps({"operation": "core.status", "protocol_version": cs.PROTOCOL_VERSION,
                          "params": {"x": "y" * (cs.MAX_BODY_BYTES + 1000)}}).encode("utf-8")
        req = urllib.request.Request(url + "/rpc", data=big, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + token})
        # BOTH outcomes are the refusal: the server answers 413 without reading the body and
        # closes, so the client may see the response or a broken pipe. It must never succeed.
        try:
            urllib.request.urlopen(req, timeout=20)
            self.fail("an oversized body was accepted")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 413)
        except OSError:
            pass


class TestCoreLifecycle(CoreFixture):

    @control(323)
    def test_a_second_core_cannot_race_the_first(self):
        """The lock is held for the process's lifetime, so the OS publishes Core's death."""
        from quaestor.core import proc
        held = proc.WorkerLock(cs.lock_path(self.home))
        self.assertTrue(held.acquire())
        self.addCleanup(held.release)
        self.assertTrue(cs.running(self.home)["running"])
        # A second serve() refuses rather than binding a second port against the same home.
        import io as _io
        out = _io.StringIO()
        rc = cs.serve(self.home, port=0, idle_s=0.0, stdout=out)
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out.getvalue())["error"], "CORE_ALREADY_RUNNING")

    @control(324)
    def test_a_stale_endpoint_file_is_not_mistaken_for_a_running_core(self):
        """A killed Core leaves its note behind. The LOCK is the evidence, not the note."""
        with open(cs.endpoint_path(self.home), "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:9", "port": 9, "pid": 999999}, fh)
        state = cs.running(self.home)
        self.assertFalse(state["running"])
        self.assertTrue(state["stale_endpoint"])      # reported, not believed

    @control(325)
    def test_identity_and_authorizations_survive_a_restart(self):
        before = coreid.device(self.home)["device_id"]
        self.assertTrue(before)
        # A fresh process would re-read from disk; simulate by clearing nothing and re-reading.
        self.assertEqual(coreid.device(self.home)["device_id"], before)
        self.assertEqual({p["project_id"] for p in coreid.projects(self.home)},
                         {self.pid_a, self.pid_b})
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        code, body = self.rpc(url, token, "core.identity")
        self.assertEqual(body["device"]["device_id"], before)
        # The identity carries no secret and grants nothing.
        self.assertNotIn("sha256", json.dumps(body))
        self.assertNotIn("token", json.dumps(body).lower().replace("value_returned_once", ""))

    @control(326)
    def test_core_does_not_shut_down_while_it_owes_something(self):
        """An idle timer must never discard an obligation an operator is waiting on."""
        from quaestor.relay import cli as relay_cli
        from quaestor.relay import state as state_mod
        db, _w = relay_cli.relay_paths(self.home)
        os.makedirs(os.path.dirname(db), exist_ok=True)
        st = state_mod.RelayState(db)
        self.addCleanup(st.close)
        st.create("relay-live", project_root=self.repo_a, repo_id="", objective="o",
                  authority_profile="STANDARD_EDIT", orchestrator_kind="fake",
                  execution_kind="fake", config={})
        # A RUNNING ROW IS A CLAIM; the lock a relay holds for its lifetime is the evidence.
        # Before Core owned relay processes there was no lock to ask, so the row was all there
        # was. An ORPHAN -- a RUNNING row no process holds -- is work that already stopped
        # without saying so, and treating it as an obligation would pin Core alive forever over
        # a relay that is not there.
        from quaestor.core import corerelay
        self.assertFalse(cs.has_obligations(self.home)["obligated"],
                         "an orphaned row pinned Core alive")
        holder = corerelay.hold(self.home, "relay-live")
        self.addCleanup(holder.release)
        self.assertTrue(cs.has_obligations(self.home)["obligated"])
        self.assertEqual(cs.has_obligations(self.home)["live_relays"], ["relay-live"])

        # A RELAY ASKED TO STOP IS STILL WORKING. The durable record is marked STOPPED
        # immediately and the relay leaves at its NEXT step boundary -- a whole exchange later --
        # so a rule that skipped non-RUNNING rows let Core idle-shut-down on top of a live
        # process mid-delivery. The lock is asked for every row, whatever the row says.
        st.update("relay-live", state=state_mod.STOPPED)
        self.assertTrue(cs.has_obligations(self.home)["obligated"],
                        "Core would idle-shut-down on a relay that is still finishing")
        self.assertEqual(cs.has_obligations(self.home)["live_relays"], ["relay-live"])

        # ...and once the process has actually left, the obligation is discharged.
        holder.release()
        self.assertFalse(cs.has_obligations(self.home)["obligated"])
        # An owner hold is an obligation even when the relay is not running: somebody is
        # waiting on a decision, and going away would leave it with nothing listening.
        st.update("relay-live", owner_hold="a GIT_PUSH the profile does not grant")
        self.assertTrue(cs.has_obligations(self.home)["obligated"])

    @control(327)
    def test_project_authorization_has_four_verdicts_and_only_one_is_yes(self):
        """'Authorised once' and 'authorised now' are different claims."""
        self.assertEqual(coreid.classify(self.home, self.repo_a)["verdict"], coreid.AUTHORIZED)
        fresh = make_repo(os.path.join(self._tmp.name, "gamma"))
        self.assertEqual(coreid.classify(self.home, fresh)["verdict"],
                         coreid.KNOWN_UNAUTHORIZED)
        self.assertEqual(coreid.classify(self.home, os.path.join(self._tmp.name, "nothing"))
                         ["verdict"], coreid.UNKNOWN)
        # A path whose repository has gone is STALE, never authorised: the caller must not
        # inherit an authorisation granted to something that is no longer there. The checkout is
        # RENAMED rather than deleted -- that is the real story (somebody moved their project),
        # and on Windows a .git directory holds open handles that make deletion the wrong test.
        os.rename(self.repo_b, self.repo_b + "-moved")
        self.assertEqual(coreid.classify(self.home, self.repo_b)["verdict"], coreid.STALE)
        # Authorising is an OPERATOR act: no Core operation performs it.
        with open(cs.__file__, encoding="utf-8") as fh:
            self.assertNotIn("coreid.authorize", fh.read())


class TestCoreReviewFindings(CoreFixture):
    """Found by an independent adversarial review of this boundary, reproduced, and fixed."""

    @control(328)
    def test_serving_one_project_touches_no_other_project_at_all(self):
        """The headline finding. The grant was applied to the RESULT, not to the work.

        Measured before the fix on a live Core: one relay.list returning ONE row spawned 78 git
        children across 13 working trees, 12 of them belonging to projects no operator had
        authorised -- and the idle watchdog repeated it once a second with no client connected.
        The module's own headline invariant, "no endpoint runs a subprocess", was false.
        """
        from quaestor.relay import cli as relay_cli
        from quaestor.relay import state as state_mod
        from quaestor.workspace import git as gitmod

        db, _w = relay_cli.relay_paths(self.home)
        os.makedirs(os.path.dirname(db), exist_ok=True)
        st = state_mod.RelayState(db)
        self.addCleanup(st.close)
        for i, root in enumerate((self.repo_a, self.repo_b)):
            st.create("relay-%d" % i, project_root=root, repo_id="", objective="o",
                      authority_profile="STANDARD_EDIT", orchestrator_kind="fake",
                      execution_kind="fake", config={})

        # One of the two is genuinely alive, so "obligated" below measures the reconciliation
        # rather than the mere existence of a row.
        from quaestor.core import corerelay
        holder = corerelay.hold(self.home, "relay-0")
        self.addCleanup(holder.release)

        calls = {"n": 0, "cwds": set()}
        real = gitmod.subprocess.run

        def counting(argv, *a, **kw):
            if argv and str(argv[0]) == "git":
                calls["n"] += 1
                calls["cwds"].add(str(kw.get("cwd") or ""))
            return real(argv, *a, **kw)

        gitmod.subprocess.run = counting
        try:
            rows = cs._relay_rows(self.home, self.pid_a)
            obligations = cs.has_obligations(self.home)
        finally:
            gitmod.subprocess.run = real

        # THE ORACLE: the right row came back, and NO git ran anywhere.
        self.assertEqual([r["relay_id"] for r in rows], ["relay-0"])
        self.assertEqual(calls["n"], 0, "git ran in %s" % sorted(calls["cwds"]))
        self.assertTrue(obligations["obligated"])
        self.assertEqual(calls["cwds"], set())

    @control(329)
    def test_a_negative_content_length_does_not_walk_past_the_body_bound(self):
        """A length of -1 is not a small one: read(-1) reads to EOF, unauthenticated."""
        import http.client
        url = self.server()
        host, port = url.rsplit("/", 1)[-1].split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        conn.putrequest("POST", "/rpc")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "-1")
        conn.endheaders()
        try:
            resp = conn.getresponse()
            self.assertEqual(resp.status, 413)
        except Exception:                                        # noqa: BLE001
            pass                                                 # refused at the socket: fine
        finally:
            conn.close()

    @control(330)
    def test_a_malformed_request_always_gets_an_answer(self):
        """A handler that dies answers NOTHING -- a dropped connection instead of a refusal,
        and it happened BEFORE authentication."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        for body in ({"protocol_version": "not-a-number", "operation": "core.status"},
                     {"protocol_version": 1, "operation": "core.status", "params": "a string"},
                     {"protocol_version": None, "operation": "core.status"},
                     {"operation": {"nested": "object"}, "protocol_version": 1}):
            raw = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url + "/rpc", data=raw, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": "Bearer " + token})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    code = r.status
            except urllib.error.HTTPError as exc:
                code = exc.code
            self.assertIn(code, (400, 404), body)     # answered, whatever the answer

    @control(331)
    def test_a_credential_in_a_git_remote_never_becomes_an_identity(self):
        """An https remote carrying a token is ordinary. Folding it into the project id would
        write it to the registry and serve it to any client scoped to the project."""
        secret = "ghp_" + "A" * 36
        self.assertNotIn(secret, coreid._safe_origin(
            "https://user:%s@github.com/o/r.git" % secret))
        self.assertEqual(coreid._safe_origin("https://user:%s@github.com/o/r.git" % secret),
                         "https://github.com/o/r.git")
        # The ordinary ssh form is a USERNAME, not a secret, and must survive untouched.
        self.assertEqual(coreid._safe_origin("git@github.com:o/r.git"), "git@github.com:o/r.git")
        # End to end: set such a remote and confirm nothing about it reaches the registry.
        git(["remote", "add", "origin", "https://u:%s@github.com/o/r.git" % secret], self.repo_a)
        ident = coreid.project_identity(self.repo_a)
        self.assertNotIn(secret, json.dumps(ident))
        coreid.authorize(self.home, self.repo_a)
        self.assertNotIn(secret, json.dumps(coreid.projects(self.home)))

    @control(332)
    def test_a_stale_authorization_is_refused_at_the_boundary(self):
        """classify() had no production caller, so the STALE verdict was one nothing asked for."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        self.assertEqual(self.rpc(url, token, "relay.list", {"project_id": self.pid_a})[0], 200)
        os.rename(self.repo_a, self.repo_a + "-moved")
        code, body = self.rpc(url, token, "relay.list", {"project_id": self.pid_a})
        self.assertEqual(code, 403)
        self.assertEqual(body.get("error"), "PROJECT_STALE")

    @control(333)
    def test_core_status_does_not_hand_out_the_machines_paths(self):
        """The absolute state-home carries the OS account name; no client needs it."""
        url = self.server()
        token, _ = self.client(projects=[])
        code, body = self.rpc(url, token, "core.status")
        self.assertEqual(code, 200)
        blob = json.dumps(body).replace(chr(92) + chr(92), "/").replace(chr(92), "/")
        self.assertNotIn(self.home.replace(chr(92), "/"), blob)
        self.assertNotIn("home", body["core"])
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if user:
            self.assertNotIn(user, blob)

    @control(334)
    def test_an_unreadable_ledger_is_an_obligation_not_an_absence(self):
        """Shutting down because the ledger could not be read would discard an owner hold
        precisely when something is already wrong."""
        from quaestor.relay import cli as relay_cli
        db, _w = relay_cli.relay_paths(self.home)
        os.makedirs(os.path.dirname(db), exist_ok=True)
        os.makedirs(db, exist_ok=True)        # a DIRECTORY where the store should be
        out = cs.has_obligations(self.home)
        self.assertTrue(out["obligated"])
        self.assertIn("unmeasured", out)


class TestCoreAuthority(CoreFixture):
    """Core answers only to its own authority (bd quaestor-d47).

    Binding loopback proves a request came from this MACHINE. A page the operator merely visits
    runs on this machine too, so these controls drive the attack the bind check cannot see: a
    real request, on the real socket, addressed to somebody else's name. They are built with
    ``http.client`` rather than ``urllib`` deliberately -- urllib writes ``Host`` itself from the
    URL it was handed, so the rebound request under test cannot be constructed with it at all.
    """

    def raw(self, url, method, path, host, *, origin=None, token=None, body=None, extra=(),
            with_headers=False):
        """One request with the authority headers CHOSEN rather than inferred.

        ``with_headers`` is opt-in because the default 2-tuple is compared BETWEEN two requests
        to prove the refusal is not an oracle, and ``Date`` differs between any two of them.
        """
        import http.client
        addr, port = url.rsplit("/", 1)[-1].split(":")
        conn = http.client.HTTPConnection(addr, int(port), timeout=10)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host)
            if origin is not None:
                conn.putheader("Origin", origin)
            if token:
                conn.putheader("Authorization", "Bearer " + token)
            for name, value in extra:
                conn.putheader(name, value)
            data = (body or "").encode("utf-8")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(data)))
            conn.endheaders(data if data else None)
            resp = conn.getresponse()
            text = resp.read().decode("utf-8")
            head = {str(k).lower(): str(v) for k, v in resp.getheaders()}
            try:
                doc = json.loads(text or "{}")
            except ValueError:
                doc = {}
            return (int(resp.status), head, doc) if with_headers else (int(resp.status), doc)
        finally:
            conn.close()

    @staticmethod
    def one_reply(sock):
        """(status, headers, doc) read off a RAW socket, so two requests share one connection.

        ``http.client`` is no use for this: it decides for itself whether a connection may be
        reused, and the whole question here is whether the SERVER re-decides on the second
        request of a socket it has already cleared once.
        """
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        need = int(headers.get("content-length") or 0)
        while len(rest) < need:
            chunk = sock.recv(4096)
            if not chunk:
                break
            rest += chunk
        try:
            doc = json.loads(rest[:need].decode("utf-8") or "{}")
        except ValueError:
            doc = {}
        return status, headers, doc

    def rpc_body(self, operation="core.status", params=None):
        return json.dumps({"operation": operation, "params": params or {},
                           "protocol_version": cs.PROTOCOL_VERSION})

    @control(376)
    def test_a_rebound_host_is_refused_on_every_route_and_method(self):
        """A site whose DNS answers its own name with 127.0.0.1 reaches this socket while the
        browser still calls the reply same-origin. The authority is the field it cannot forge."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        port = url.rsplit(":", 1)[-1]
        rpc = self.rpc_body()
        rebound = ("evil.example.com:%s" % port, "attacker.test",
                   "127.0.0.1.nip.io:%s" % port, "localhost.evil.example.com:%s" % port,
                   "[dead::beef]:%s" % port, "",
                   # SUFFIX-SHAPED, and the whole reason they are here: every other name above
                   # merely CONTAINS a loopback name, so an ``endswith`` allowlist -- the single
                   # most likely wrong way to write this -- admits none of them and the corpus
                   # could not tell. ``*.localhost`` is the dangerous family: RFC 6761 says a
                   # resolver answers it 127.0.0.1 with no DNS round trip at all, browsers treat
                   # it as a secure context, and it is a DISTINCT web origin.
                   "evil.localhost", "evil.localhost:%s" % port, "sub.127.0.0.1")
        # EVERY ROUTE AND EVERY METHOD, including one Core does not implement: a 501 or a 404
        # from an unguarded dispatch is still an answer, and an answer is the discovery step.
        for host in rebound:
            for method, path, payload in (("GET", "/health", None), ("POST", "/rpc", rpc),
                                          ("PUT", "/rpc", None), ("TRACE", "/", None)):
                code, doc = self.raw(url, method, path, host, token=token, body=payload)
                where = "%s %s host=%r" % (method, path, host)
                self.assertEqual(code, 403, where)
                self.assertEqual(doc.get("error"), "HOST_NOT_LOOPBACK", where)
                for leak in ("device", "projects", "relays", "client_id", "status"):
                    self.assertNotIn(leak, doc, where)
        # BEFORE THE CREDENTIAL. A live token and a junk one get the identical answer, so the
        # refusal is not an oracle for whether a stolen token still works.
        good = self.raw(url, "POST", "/rpc", "evil.example.com:%s" % port, token=token, body=rpc)
        junk = self.raw(url, "POST", "/rpc", "evil.example.com:%s" % port,
                        token="not-a-real-token", body=rpc)
        self.assertEqual(good[0], 403)
        self.assertEqual(good, junk)
        # Two Host headers are not a tie to be broken in the sender's favour.
        code, doc = self.raw(url, "POST", "/rpc", "127.0.0.1:%s" % port, token=token, body=rpc,
                             extra=(("Host", "evil.example.com:%s" % port),))
        self.assertEqual(code, 403)
        self.assertEqual(doc.get("error"), "HOST_NOT_LOOPBACK")
        # EVERY REQUEST, NOT EVERY CONNECTION. A browser reuses a keep-alive socket, and a
        # rebinding page's second fetch is exactly that reused socket -- so a verdict cached per
        # connection would clear everything after the first request. The first request here is
        # legitimate ON PURPOSE: it is the one that would populate such a cache.
        addr, sport = url.rsplit("/", 1)[-1].split(":")
        sock = socket.create_connection((addr, int(sport)), timeout=10)
        try:
            replies = []
            for host in ("127.0.0.1:%s" % port, "evil.example.com:%s" % port):
                sock.sendall(("GET /health HTTP/1.1\r\nHost: %s\r\n"
                              "Accept-Encoding: identity\r\n\r\n" % host).encode("utf-8"))
                replies.append(self.one_reply(sock))
        finally:
            sock.close()
        self.assertEqual(replies[0][0], 200, replies[0])
        # If the first reply closed the connection the second request was never the reused-socket
        # case this is here to drive, and the control would be measuring nothing.
        self.assertNotEqual((replies[0][1].get("connection") or "").lower(), "close", replies[0])
        self.assertEqual(replies[1][0], 403, replies[1])
        self.assertEqual(replies[1][2].get("error"), "HOST_NOT_LOOPBACK")
        # AND IT IS TERMINAL. Without this header the stdlib leaves ``close_connection`` False
        # and Core holds a socket open for a caller it has just declined.
        self.assertEqual((replies[1][1].get("connection") or "").lower(), "close", replies[1])
        # THE LARGEST BODY A TRUSTED CALLER MAY SEND IS STILL ANSWERED, IN FULL. This is an
        # OUTCOME, not a proof that `_drain` ran: disabling the drain was measured not to change
        # it on this platform at any size (see `_drain`'s own note), so control 369 pins the
        # draining itself and this line pins only that a max-size body loses nobody the refusal.
        stub = self.rpc_body(params={"pad": ""})
        big = self.rpc_body(params={"pad": "x" * (cs.MAX_BODY_BYTES - 1 - len(stub))})
        self.assertEqual(len(big.encode("utf-8")), cs.MAX_BODY_BYTES - 1)
        try:
            code, doc = self.raw(url, "POST", "/rpc", "evil.example.com:%s" % port, token=token,
                                 body=big)
        except OSError as exc:
            self.fail("the refusal was lost with an undrained body of %d bytes: %r"
                      % (len(big), exc))
        self.assertEqual(code, 403)
        self.assertEqual(doc.get("error"), "HOST_NOT_LOOPBACK")
        # AND THE REAL CLIENT STILL WORKS: every loopback authority a legitimate client writes --
        # with a port and without, the name, the case it happens to use, and the bracketed v6
        # literal http.client emits. Refusing one of these would break the CLI, not an attacker.
        for host in ("127.0.0.1:%s" % port, "127.0.0.1", "localhost:%s" % port, "localhost",
                     "LocalHost:%s" % port, "[::1]:%s" % port, "[::1]"):
            code, doc = self.raw(url, "POST", "/rpc", host, token=token, body=rpc)
            self.assertEqual(code, 200, host)
            self.assertTrue(doc["core"]["running"], host)
        code, doc = self.raw(url, "GET", "/health", "127.0.0.1:%s" % port)
        self.assertEqual(code, 200)
        self.assertEqual(doc.get("status"), "ok")
        self.assertEqual(self.rpc(url, token, "core.status")[0], 200)

    @control(372)
    def test_a_present_foreign_origin_is_refused_and_an_absent_one_is_not(self):
        """Only a browser sends Origin. Refusing an ABSENT one locks out the CLI; answering a
        PRESENT foreign one answers the page this boundary exists to keep out."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        port = url.rsplit(":", 1)[-1]
        rpc = self.rpc_body()
        loop = "127.0.0.1:%s" % port
        foreign = ("http://evil.example.com", "https://evil.example.com",
                   "http://evil.example.com:%s" % port,
                   "http://127.0.0.1.evil.example.com:%s" % port,
                   "http://localhost.evil.example.com", "null", "file://",
                   # An extension origin is refused too, and deliberately: the extension this
                   # boundary exists for is admitted BY NAME when it exists, because a scheme
                   # wildcard would trust every extension the operator ever installed.
                   "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                   # SUFFIX-SHAPED, as on the Host side: every name above only CONTAINS a
                   # loopback name, so an ``endswith`` allowlist would admit none of them and
                   # this corpus could not tell. ``*.localhost`` resolves to 127.0.0.1 with no
                   # DNS round trip and is still a distinct origin.
                   "http://evil.localhost", "http://evil.localhost:%s" % port,
                   # SCHEME-DECIDED, and nothing else here is: each of these carries a genuinely
                   # LOOPBACK authority, so the host clause clears them and only the scheme
                   # allowlist can refuse them. Without one of these the comment above about
                   # extensions is untested -- the extension origins above are refused for their
                   # authority, not for their scheme.
                   "ftp://127.0.0.1", "chrome-extension://localhost",
                   "myapp://localhost:%s" % port)
        for origin in foreign:
            for method, path, payload in (("POST", "/rpc", rpc), ("GET", "/health", None)):
                code, doc = self.raw(url, method, path, loop, origin=origin, token=token,
                                     body=payload)
                where = "%s %s origin=%r" % (method, path, origin)
                self.assertEqual(code, 403, where)
                self.assertEqual(doc.get("error"), "ORIGIN_NOT_LOOPBACK", where)
        # Not an oracle: identical answer whether the token is live or junk.
        self.assertEqual(
            self.raw(url, "POST", "/rpc", loop, origin="http://evil.example.com", token=token,
                     body=rpc),
            self.raw(url, "POST", "/rpc", loop, origin="http://evil.example.com",
                     token="not-a-real-token", body=rpc))
        # ABSENT IS NOT FOREIGN. This shape is the CLI and every other non-browser client.
        code, doc = self.raw(url, "POST", "/rpc", loop, token=token, body=rpc)
        self.assertEqual(code, 200, doc)
        self.assertTrue(doc["core"]["running"])
        # A loopback page -- a local web UI on this same machine -- is still a client.
        for origin in ("http://127.0.0.1:%s" % port, "http://localhost:%s" % port,
                       "http://[::1]:%s" % port, "https://localhost"):
            code, doc = self.raw(url, "POST", "/rpc", loop, origin=origin, token=token, body=rpc)
            self.assertEqual(code, 200, origin)
        # Two Origins are not a tie to be broken in the page's favour.
        code, doc = self.raw(url, "POST", "/rpc", loop, origin="http://127.0.0.1:%s" % port,
                             token=token, body=rpc,
                             extra=(("Origin", "http://evil.example.com"),))
        self.assertEqual(code, 403)
        # The policy says the same without a socket, in both directions.
        self.assertEqual(cs.authority_refusal("127.0.0.1:9", ""), {})
        self.assertEqual(cs.authority_refusal("localhost", None), {})
        self.assertEqual(
            cs.authority_refusal("127.0.0.1:9", "http://evil.example.com").get("error"),
            "ORIGIN_NOT_LOOPBACK")
        # The scheme really is the deciding clause for the three above, not a spare wheel.
        for origin in ("ftp://127.0.0.1", "chrome-extension://localhost", "myapp://localhost"):
            self.assertEqual(cs._authority_host(origin.partition("://")[2]), "localhost"
                             if "localhost" in origin else "127.0.0.1", origin)
            self.assertEqual(cs.authority_refusal("localhost", origin).get("error"),
                             "ORIGIN_NOT_LOOPBACK", origin)

    @control(373)
    def test_the_authority_refusal_identifies_nobody(self):
        """Covering /health is only an improvement if the 403 that replaced it answers a
        DIFFERENT question. A rebound page is same-origin with this reply and reads all of it."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        port = url.rsplit(":", 1)[-1]
        rpc = self.rpc_body()
        loop = "127.0.0.1:%s" % port
        product = cs.branding.resource("core")
        for method, path, host, origin, payload in (
                ("GET", "/health", "evil.example.com:%s" % port, None, None),
                ("POST", "/rpc", "evil.example.com:%s" % port, None, rpc),
                ("PUT", "/rpc", "attacker.test", None, None),
                ("TRACE", "/", "evil.localhost", None, None),
                ("POST", "/rpc", loop, "http://evil.example.com", rpc),
                ("GET", "/health", loop, "null", None)):
            code, head, doc = self.raw(url, method, path, host, origin=origin, token=token,
                                       body=payload, with_headers=True)
            where = "%s %s host=%r origin=%r" % (method, path, host, origin)
            self.assertEqual(code, 403, where)
            # NO BANNER. The stdlib stamps the product on every response; on this path that
            # would answer "what is running on this port" for the one caller who must not be
            # told, on EVERY route rather than on the single one /health used to be.
            self.assertEqual(head.get("server") or "", "", where)
            # AND NO SELF-DESCRIPTION IN THE BODY. ``instrument`` names the product and its
            # protocol; ``authorities`` hands back the allowlist. Both are useless to the only
            # caller that can receive them and valuable to nobody else.
            self.assertNotIn("instrument", doc, where)
            self.assertNotIn("authorities", doc, where)
            seen = (json.dumps(doc, sort_keys=True) + "\n"
                    + "\n".join("%s: %s" % kv for kv in sorted(head.items()))).lower()
            for name in ("quaestor", product, cs.CORE_INSTRUMENT):
                self.assertNotIn(name.lower(), seen, "%s leaked %r" % (where, name))
            # It is still an error a misconfigured client can act on: the header at fault.
            self.assertIn(doc.get("error"), ("HOST_NOT_LOOPBACK", "ORIGIN_NOT_LOOPBACK"), where)
        # AND THE BANNER IS NOT SIMPLY GONE. A client Core does answer is still identified, so
        # this control pins "silent to a foreign authority", not "silent to everyone".
        code, head, doc = self.raw(url, "GET", "/health", loop, with_headers=True)
        self.assertEqual(code, 200)
        self.assertIn(product, head.get("server") or "")
        self.assertEqual(doc.get("instrument"), cs.CORE_INSTRUMENT)

    @control(375)
    def test_a_refused_body_is_consumed_exactly_and_only_up_to_the_limit(self):
        """``_drain`` exists for the platforms that RST a close over unread bytes, and this OS is
        not one of them -- measured, in ``_drain``'s own note. So it is driven DIRECTLY: over a
        socket its effect is invisible here, and a control that cannot see its subject is prose."""
        httpd, _ = cs.build_server(self.home, port=0, idle_s=0.0)
        self.addCleanup(httpd.server_close)
        cls = httpd.RequestHandlerClass

        def drained(declared, stream):
            # __new__, not __init__: constructing a handler SERVES a request off a socket, and
            # what is under test is the one method, not a round trip.
            h = cls.__new__(cls)
            h.headers = {} if declared is None else {"Content-Length": declared}
            h.rfile = io.BytesIO(stream)
            h._drain()
            return h.rfile.read()

        # EXACTLY THE DECLARED BODY, AND NOT A BYTE MORE. Over-reading would eat the next
        # request off a kept-alive connection; under-reading is the case this method exists for.
        self.assertEqual(drained("5", b"HELLOGET /health HTTP/1.1\r\n"),
                         b"GET /health HTTP/1.1\r\n")
        self.assertEqual(drained(str(cs.MAX_BODY_BYTES), b"x" * cs.MAX_BODY_BYTES + b"TAIL"),
                         b"TAIL")
        # AND NOT MORE THAN A TRUSTED CALLER WOULD GET. A foreign authority does not earn a
        # bigger read than one Core answers: over the limit, nothing is read at all.
        over = b"y" * 32
        self.assertEqual(drained(str(cs.MAX_BODY_BYTES + 1), over), over)
        # NEVER RAISES, AND NEVER READS ON A LENGTH IT CANNOT TRUST. A negative or unparseable
        # Content-Length reaching this path must not become an exception on a refusal path that
        # runs before authentication.
        for declared in (None, "", "nonsense", "-1", "0", "1e3", "  "):
            self.assertEqual(drained(declared, over), over, repr(declared))


class TestGrantNamesAProjectNotAPlace(CoreFixture):
    """A grant names a PROJECT, and ``_project`` asked a strictly weaker question (bd lmh).

    ``coreid.authorize`` keys the registry on project_id and NEVER prunes by root, so a
    directory reused for a second repository leaves TWO records naming ONE root -- the first
    still pointing at what is now somebody else's checkout. ``classify`` answers AUTHORIZED
    there, earned by the second record, and the gate used to read only that verdict and throw
    the identity away. These controls build that state for real -- two authorisations of one
    real directory that really did change repository -- rather than editing the registry file,
    because the point in dispute is that ORDINARY OPERATOR ACTS produce it.
    """

    def _reused_directory(self, *, relay_for_first: str = ""):
        """(root, pid_first, pid_second) for one real directory that held two repositories.

        The first checkout is RENAMED aside rather than deleted, for the reason control 327
        already records: on Windows a ``.git`` directory holds open handles, so deleting it
        would make the fixture flaky about something that is not under test.
        """
        root = os.path.join(self._tmp.name, "reused")
        make_repo(root)
        # Distinct origins, because ``repo_id_for`` falls back to a digest OF THE ROOT -- and
        # two repositories at one root would then share an id, which is the whole bug erased
        # by the fixture instead of driven by it.
        git(["remote", "add", "origin", "https://github.com/o/first.git"], root)
        first = coreid.authorize(self.home, root)["project_id"]
        # A REGISTERED SHAPE for `first`, so ``relay.start`` REACHES the identity gate. Without
        # it the call short-circuits at NO_SUCH_PROFILE -- itself a 403 -- and every assertion
        # about what the refusal did NOT do would hold in the buggy world too.
        registered = corerelay.register_profile(
            self.home, name="any", project_id=first,
            fields={"orchestrator": "openai-chat", "orchestrator_model": "a-registered-model",
                    "agent": "opencode", "max_exchanges": "200", "profile": "READ_ONLY",
                    "verify": ["python run_tests.py"], "no_probe": True})
        self.assertTrue(registered.get("ok"), registered)
        if relay_for_first:
            # A REAL DURABLE ROW, written while `first` genuinely lives here. This is what the
            # successor must never be handed: the displaced project's relay, carrying its
            # objective and its authority profile.
            db, _work = relay_cli.relay_paths(self.home)
            st = state_mod.RelayState(db)
            self.addCleanup(st.close)
            st.create(relay_for_first, project_root=root,
                      repo_id="https://github.com/o/first.git",
                      objective="first's objective", orchestrator_kind="openai-chat",
                      execution_kind="opencode", authority_profile="READ_ONLY", config={})
            self.assertEqual([r["relay_id"] for r in cs._relay_rows(self.home, first)],
                             [relay_for_first], "the fixture must start from a REACHABLE row")
        second_src = make_repo(os.path.join(self._tmp.name, "successor"))
        git(["remote", "add", "origin", "https://github.com/o/second.git"], second_src)
        os.rename(root, root + "-gone")
        os.rename(second_src, root)
        second = coreid.authorize(self.home, root)["project_id"]
        self.assertNotEqual(first, second)
        roots = {str(r.get("project_id")): str(r.get("root")) for r in coreid.projects(self.home)}
        self.assertEqual(roots[first], roots[second], "the fixture must be TWO records, ONE root")
        self.assertEqual(coreid.project_identity(root)["project_id"], second)
        return root, first, second

    @control(379)
    def test_a_token_for_one_project_cannot_reach_the_repository_that_took_its_place(self):
        """The milestone's headline criterion, failing at the one place it is enforced."""
        root, first, second = self._reused_directory()
        # THE GATE'S INPUT, stated before the gate is driven: classify says AUTHORIZED at the
        # root recorded for `first`, and the identity it hands back is `second`. Anything that
        # reads the verdict alone has already admitted the caller by this line.
        verdict = coreid.classify(self.home, root)
        self.assertEqual(verdict["verdict"], coreid.AUTHORIZED)
        self.assertEqual(verdict["project_id"], second)
        url = self.server()
        token, issued = self.client(projects=[first])
        for op in ("relay.list", "relay.status", "relay.profiles", "relay.resume", "relay.stop"):
            code, body = self.rpc(url, token, op, {"project_id": first, "relay_id": "r1"})
            self.assertEqual(code, 403, (op, body))
            self.assertEqual(body.get("error"), "PROJECT_IDENTITY_MISMATCH", (op, body))
            # Refused WITHOUT naming what is really there: a client that may not reach the
            # second project does not get to learn it exists by being turned away from it.
            self.assertNotIn(second, json.dumps(body), op)
        # THE EFFECTFUL ONE, and why this is a P1 rather than a disclosure bug: relay.start
        # hands the RECORDED ROOT to the process it spawns, so an answer here runs `first`'s
        # profile authority inside repository `second`. It must refuse BEFORE it reserves a
        # request identity and before it spawns anything -- a refusal that had already burned
        # the identity would answer every later retry with a relay that never existed.
        #
        # ORDER IS ASSERTED AT THE TWO FUNCTIONS THEMSELVES, never inferred from the wreckage
        # afterwards. Reading the request ledger at the end cannot see a violation: a spawn
        # that fails RELEASES the identity again, so the ledger looks untouched whether the
        # gate ran first or a whole relay process was launched into the wrong repository and
        # died there. A sentinel on each call is the only thing here that tells them apart:
        # measured with the gate deleted and this exact fixture, both closing checks below
        # still read clean while a real relay process had been launched and had exited.
        reached = []
        real_reserve, real_spawn = corerelay.reserve_request, cs._spawn_relay
        self.addCleanup(setattr, corerelay, "reserve_request", real_reserve)
        self.addCleanup(setattr, cs, "_spawn_relay", real_spawn)
        corerelay.reserve_request = lambda *a, **k: (reached.append("reserve_request")
                                                     or real_reserve(*a, **k))
        cs._spawn_relay = lambda *a, **k: (reached.append("_spawn_relay")
                                           or real_spawn(*a, **k))
        code, body = self.rpc(url, token, "relay.start",
                              {"project_id": first, "profile": "any", "request_id": "req-1",
                               "objective": "reach the other repository"})
        self.assertEqual(reached, [], "relay.start did work BEFORE the identity gate")
        self.assertEqual(code, 403, body)
        self.assertEqual(body.get("error"), "PROJECT_IDENTITY_MISMATCH", body)
        key = corerelay.request_key(project_id=first,
                                    client_id=str(issued.get("client_id") or ""),
                                    request_id="req-1")
        # A DURABLE CROSS-CHECK, not the ordering proof: ``reserve_request`` is the request
        # ledger's only writer, so the sentinel above strictly subsumes this line. It is kept
        # because the ledger is what a retry actually reads.
        self.assertEqual(corerelay.recall_request(self.home, key), "",
                         "a refused start left a request identity burned")

    @control(380)
    def test_the_gate_turns_on_identity_alone_so_ordinary_projects_still_answer(self):
        """Isolate the variable. A check that refused whenever a root carried two records, or
        whenever anything looked unusual, would pass control 379 while breaking every caller --
        so the same root is driven twice, and only the token's project changes between them."""
        url = self.server()
        # One record, one root: the shape every real deployment is in.
        token_a, _ = self.client(projects=[self.pid_a])
        for op in ("relay.list", "relay.status", "relay.profiles"):
            code, body = self.rpc(url, token_a, op, {"project_id": self.pid_a})
            self.assertEqual(code, 200, (op, body))
        root, first, second = self._reused_directory(relay_for_first="relay-of-first")
        # SAME root, same two records, same registry. The token that names what is ACTUALLY
        # there is served -- so 379's refusal is the identity mismatch and not the fixture.
        token_2, _ = self.client(projects=[second])
        for op in ("relay.list", "relay.status", "relay.profiles"):
            code, body = self.rpc(url, token_2, op, {"project_id": second})
            self.assertEqual(code, 200, (op, body))
        # AND BEING SERVED IS NOT BEING SERVED SOMEBODY ELSE'S WORK. ``_relay_rows`` resolved a
        # relay's owner from a root -> project_id dict, and a contested root let the LATER
        # record win it outright: `first`'s durable relay came back to `second` wearing
        # `second`'s id, listable, resumable and STOPPABLE. Asserting only the 200 above
        # certified precisely that. So: the row is served to NEITHER project, and is never
        # relabelled -- the same fail-closed answer the gate in ``_project`` gives.
        self.assertEqual(cs._relay_rows(self.home, second), [], "served another project a relay")
        self.assertEqual(cs._relay_rows(self.home, first), [], "a contested root must fail shut")
        code, body = self.rpc(url, token_2, "relay.list", {"project_id": second})
        self.assertEqual([r["relay_id"] for r in body["relays"]], [], body)
        self.assertNotIn("relay-of-first", json.dumps(body))
        # A MUTATION, not merely a disclosure: a stop is honoured by a running relay at its
        # next step boundary, so reaching this row terminates another project's live work,
        # and a resume would respawn it under `first`'s objective and authority profile.
        for op in ("relay.stop", "relay.resume"):
            code, body = self.rpc(url, token_2, op,
                                  {"project_id": second, "relay_id": "relay-of-first"})
            self.assertEqual(code, 404, (op, body))
            self.assertEqual(body.get("error"), "NO_SUCH_RELAY", (op, body))
        # UNTOUCHED IN THE STORE, read back from the ledger rather than from the answer.
        db, _work = relay_cli.relay_paths(self.home)
        st = state_mod.RelayState(db)
        self.addCleanup(st.close)
        self.assertEqual(st.get("relay-of-first")["state"], "RUNNING")
        self.assertEqual(st.get("relay-of-first")["stop_reason"], "")
        token_1, _ = self.client(projects=[first])
        code, body = self.rpc(url, token_1, "relay.list", {"project_id": first})
        self.assertEqual(code, 403, body)
        self.assertEqual(body.get("error"), "PROJECT_IDENTITY_MISMATCH", body)
        # And re-authorising is the operator act that fixes it, not a client-reachable one:
        # the stale record for `first` is what must go, and only ``revoke`` removes it.
        coreid.revoke(self.home, first)
        self.assertNotIn(first, {str(r.get("project_id")) for r in coreid.projects(self.home)})
        code, body = self.rpc(url, token_1, "relay.list", {"project_id": first})
        self.assertEqual(body.get("error"), "PROJECT_NOT_AUTHORIZED", body)


class TestAReadDoesNotWrite(CoreFixture):
    """Controls 397-398. A surface documented as READING must not write (bd quaestor-mpp).

    Core opens the relay ledger to answer ``relay.list``, ``relay.status`` and its own idle
    check -- unattended, once a second for as long as it is obligated. It opened it through
    ``RelayState(path)``, which creates the directory, converts the journal mode, runs the
    schema script and then ``ALTER TABLE``. Nothing was corrupted and no relay row changed: the
    objection is that a documented read physically wrote files in the operator's home, so an
    operator could not reason about what a read costs, and a future Core answering many clients
    would be repairing the ledger in order to answer a status question.

    THESE CONTROLS ASSERT ON THE FILESYSTEM -- the bytes of the database, its mtime, its journal
    mode, its schema and the set of files beside it -- rather than on the call having returned.
    A control that only checked the answer would have passed on every day this defect existed.
    """

    def ledger_snapshot(self, home: str) -> dict:
        """Every relay-ledger file in ``home``, as the evidence rather than a proxy for it.

        The DATABASE is hashed: it is the operator's ledger, and nothing a read does may change
        one byte of it. A SIDECAR is recorded by name and size only -- ``-shm`` is SQLite's
        volatile shared-memory index, and hashing it would measure scratch space rather than
        the claim under test.
        """
        db, _work = relay_cli.relay_paths(home)
        stem = os.path.basename(db)
        out = {}
        for name in sorted(os.listdir(home)):
            if not name.startswith(stem):
                continue
            path = os.path.join(home, name)
            stat = os.stat(path)
            if name == stem:
                with open(path, "rb") as fh:
                    out[name] = (stat.st_size, stat.st_mtime_ns,
                                 hashlib.sha256(fh.read()).hexdigest())
            else:
                out[name] = (stat.st_size,)
        return out

    def read_only_conn(self, db: str):
        """A connection for the CONTROL's own measurements that cannot perturb them.

        A helper that opened the store read-write would convert the journal mode, or checkpoint
        the WAL on close, changing the very bytes and mtime the control is about to compare.
        """
        return sqlite3.connect(
            "file:" + urllib.request.pathname2url(os.path.abspath(db)) + "?mode=ro", uri=True)

    def journal_mode(self, db: str) -> str:
        conn = self.read_only_conn(db)
        try:
            return str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        finally:
            conn.close()

    def relay_columns(self, db: str) -> list:
        conn = self.read_only_conn(db)
        try:
            return [r[1] for r in conn.execute("PRAGMA table_info(relay)").fetchall()]
        finally:
            conn.close()

    @control(397)
    def test_answering_a_read_leaves_the_operators_ledger_byte_identical(self):
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        db, work = relay_cli.relay_paths(self.home)

        # (A) BEFORE ANY RELAY HAS EVER RUN. Reachable on a fresh machine, and the read must
        # answer rather than crash -- while a read that CREATED the ledger in order to report
        # that it is empty would be this same defect wearing the opposite face. The guard used
        # to live in the caller, where it could be forgotten; it now lives in the constructor,
        # which is why the direct call is asserted too.
        self.assertFalse(os.path.exists(db))
        for operation in ("relay.list", "relay.status"):
            code, body = self.rpc(url, token, operation, {"project_id": self.pid_a})
            self.assertEqual(code, 200, (operation, body))
            self.assertEqual(body["relays"], [], (operation, body))
        self.assertFalse(cs.has_obligations(self.home)["obligated"])
        self.assertEqual(cs._read_relays(self.home), ([], ""))
        self.assertFalse(os.path.exists(db), "a read created the ledger it was reading")
        self.assertFalse(os.path.exists(work), "a read created the relay workdir")
        with self.assertRaises(state_mod.StoreNotReadable):
            state_mod.RelayState.open_read_only(db)
        self.assertFalse(os.path.exists(db), "the read-only open created the store")

        # (B) A LEDGER THAT IS NOT IN WAL MODE -- a store restored from a backup, or written by
        # a build predating the WAL pragma. ``RelayState(path)`` issues ``PRAGMA
        # journal_mode=WAL``, which REWRITES THE DATABASE HEADER: a documented read permanently
        # converting the operator's file, with no relay row involved at all. This is the case
        # where the honest claim is total -- not one sidecar is created either, because a
        # rollback-journal database needs no shared-memory index to be read.
        writer = state_mod.RelayState(db)
        writer.create("relay-a", project_root=self.repo_a, repo_id="", objective="o",
                      authority_profile="STANDARD_EDIT", orchestrator_kind="fake",
                      execution_kind="fake", config={})
        writer.close()
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("VACUUM")
        conn.commit()
        conn.close()
        self.assertEqual(self.journal_mode(db), "delete")
        before = self.ledger_snapshot(self.home)
        self.assertEqual(sorted(before), ["relay.sqlite3"], before)

        code, body = self.rpc(url, token, "relay.list", {"project_id": self.pid_a})
        self.assertEqual(code, 200, body)
        # NOT VACUOUS: the read really did read THIS ledger and really did answer from it.
        self.assertEqual([r["relay_id"] for r in body["relays"]], ["relay-a"], body)
        code, body = self.rpc(url, token, "relay.status",
                              {"project_id": self.pid_a, "relay_id": "relay-a"})
        self.assertEqual(code, 200, body)
        self.assertEqual([r["relay_id"] for r in body["relays"]], ["relay-a"], body)
        self.assertFalse(cs.has_obligations(self.home)["obligated"])

        self.assertEqual(self.ledger_snapshot(self.home), before,
                         "a documented read changed the ledger on disk")
        self.assertEqual(self.journal_mode(db), "delete",
                         "a read converted the operator's ledger to WAL")

        # (C) THE CASE CORE ACTUALLY MEETS: a WAL ledger a live relay still holds open, read
        # once a second by the idle watchdog. A WAL database cannot be read without its
        # shared-memory index, so what is proved here is the claim that is TRUE -- the ledger is
        # byte-identical and the read creates no sidecar the writer had not already -- rather
        # than a claim about SQLite that no configuration can keep. Repeated, because one read
        # could be lucky.
        live = state_mod.RelayState(db)
        self.addCleanup(live.close)
        live.update("relay-a", owner_hold="a GIT_PUSH the profile does not grant")
        before = self.ledger_snapshot(self.home)
        for _ in range(3):
            code, body = self.rpc(url, token, "relay.list", {"project_id": self.pid_a})
            self.assertEqual(code, 200, body)
            self.assertEqual([r["relay_id"] for r in body["relays"]], ["relay-a"], body)
            verdict = cs.has_obligations(self.home)
            self.assertTrue(verdict["obligated"], verdict)
            self.assertEqual(verdict["owner_holds"], ["relay-a"], verdict)
        self.assertEqual(self.ledger_snapshot(self.home), before,
                         "a read wrote the ledger a live relay is holding open")

        # (D) AND IT IS SQLITE THAT REFUSES, not this module remembering not to write. A rule
        # that lives in a docstring is one refactor from being untrue; a connection opened
        # ``mode=ro`` cannot be refactored into a writer by accident. Reaching for the private
        # connection is the point: what is asserted is the MODE, not the API.
        reader = state_mod.RelayState.open_read_only(db)
        self.addCleanup(reader.close)
        for sql in ("ALTER TABLE relay ADD COLUMN smuggled TEXT",
                    "UPDATE relay SET state='FORGED'",
                    "DELETE FROM relay",
                    "INSERT INTO relay_event (relay_id, at, kind) VALUES ('relay-a',1,'x')"):
            with self.assertRaises(sqlite3.OperationalError, msg=sql):
                reader._conn.execute(sql)
        self.assertEqual(reader.get("relay-a")["state"], "RUNNING")
        self.assertNotIn("smuggled", self.relay_columns(db))

    @control(398)
    def test_a_read_refuses_a_store_older_than_the_code_instead_of_repairing_it(self):
        """A read-only connection CANNOT migrate, so a read must decide what to do with a store
        older than the build reading it. Answering is worse than refusing: ``summarise`` takes
        ``awaiting_role`` straight off the row, and a caller that swallows the resulting
        ``KeyError`` reports that the machine has NO relays -- to the idle watchdog whose entire
        job is deciding whether anything is still running."""
        url = self.server()
        token, _ = self.client(projects=[self.pid_a])
        db, _work = relay_cli.relay_paths(self.home)

        # A REAL OLDER STORE, not a hand-written approximation of one: the current schema with
        # exactly the columns ``_migrate`` adds taken back off it.
        writer = state_mod.RelayState(db)
        writer.create("relay-old", project_root=self.repo_a, repo_id="", objective="o",
                      authority_profile="STANDARD_EDIT", orchestrator_kind="fake",
                      execution_kind="fake", config={})
        writer.update("relay-old", state="OWNER_HOLD",
                      owner_hold="a GIT_PUSH the profile does not grant")
        writer.close()
        conn = sqlite3.connect(db)
        kept = [r[1] for r in conn.execute("PRAGMA table_info(relay)").fetchall()
                if r[1] not in state_mod.READ_REQUIRED_COLUMNS]
        # REBUILT rather than ``ALTER TABLE ... DROP COLUMN``, which SQLite refuses on this
        # table: dropping a column makes it re-parse the stored DDL, and ``SCHEMA`` carries the
        # comment explaining why these three columns exist. The rebuild is also the more honest
        # fixture -- it is what an older build's file actually looked like, not this one edited.
        conn.execute("CREATE TABLE relay_older AS SELECT %s FROM relay" % ", ".join(kept))
        conn.execute("DROP TABLE relay")
        conn.execute("ALTER TABLE relay_older RENAME TO relay")
        conn.commit()
        conn.close()

        schema_before = self.relay_columns(db)
        for column in state_mod.READ_REQUIRED_COLUMNS:
            self.assertNotIn(column, schema_before)
        before = self.ledger_snapshot(self.home)

        # THE REFUSAL IS NAMED, and it names what is missing rather than saying "unreadable".
        with self.assertRaises(state_mod.StoreNotReadable) as caught:
            state_mod.RelayState.open_read_only(db)
        for column in state_mod.READ_REQUIRED_COLUMNS:
            self.assertIn(column, str(caught.exception))

        # THE REPORTING SURFACES STILL ANSWER. They do not crash, and they do not invent rows
        # they could not read.
        for operation in ("relay.list", "relay.status"):
            code, body = self.rpc(url, token, operation, {"project_id": self.pid_a})
            self.assertEqual(code, 200, (operation, body))
            self.assertEqual(body["relays"], [], (operation, body))

        # ...AND THE REFUSAL REACHES THE ONE CALLER THAT CAN ACT ON IT. "No rows" and "could not
        # read" arrive in the same shape, and flattening the second into the first is Core
        # shutting itself down on top of an owner hold nobody has answered yet.
        verdict = cs.has_obligations(self.home)
        self.assertTrue(verdict["obligated"], verdict)
        self.assertIn("StoreNotReadable", str(verdict.get("unmeasured")), verdict)
        self.assertEqual(verdict["live_relays"], [], verdict)

        # AND THE READ DID NOT REPAIR IT. This is the write the bead is about: ALTER TABLE run
        # against an operator's ledger by a surface documented as reading, once a second.
        self.assertEqual(self.relay_columns(db), schema_before,
                         "a read migrated the operator's ledger")
        self.assertEqual(self.ledger_snapshot(self.home), before,
                         "a read wrote the ledger it refused to answer from")

        # THE PAIRED POSITIVE, without which refusing EVERYTHING would pass this control and
        # leave Core permanently unable to idle down. The store's OWNER may still migrate it,
        # and once it has, the same read answers from the same row -- so what was refused above
        # is the staleness, not the fixture.
        owner = state_mod.RelayState(db)
        self.addCleanup(owner.close)
        for column in state_mod.READ_REQUIRED_COLUMNS:
            self.assertIn(column, self.relay_columns(db))
        code, body = self.rpc(url, token, "relay.list", {"project_id": self.pid_a})
        self.assertEqual(code, 200, body)
        self.assertEqual([r["relay_id"] for r in body["relays"]], ["relay-old"], body)
        verdict = cs.has_obligations(self.home)
        self.assertTrue(verdict["obligated"], verdict)
        self.assertEqual(verdict["owner_holds"], ["relay-old"], verdict)
        self.assertEqual(verdict.get("unmeasured", ""), "", verdict)

    @control(401)
    def test_the_read_only_uri_survives_the_path_shapes_a_home_can_actually_have(self):
        """CONTROL (bd quaestor-mpp): the URI is the whole mechanism -- ``mode=ro`` is the only
        thing making this connection read-only -- so the way the path is turned into one is
        load-bearing, and it is what the other two controls never touch.

        Two shapes break it in opposite directions and both are reachable. A home holding '?',
        '#' or '%' ends the URI early under plain interpolation, and the query parameter that is
        lost is the ban itself: the connection silently becomes read-WRITE. A UNC home renders
        as ``//server/share/x``, so the host lands where the URI's AUTHORITY goes and SQLite
        refuses it outright -- fail-closed, but closed on a store that opens fine through the
        writing constructor this replaced.

        Driven against REAL databases at real paths, never against a rebuilt copy of the
        implementation's own string: a test that spells the URI itself can never disagree with
        the code.
        """
        from quaestor.relay import state as state_mod

        # (1) A PUNCTUATED HOME. The file really exists at this path and really opens.
        #
        # '#' and '%' are legal in a filename on BOTH platforms and are the two that actually
        # break a plain interpolation -- '#' starts a URI fragment, so everything after it
        # (including ``?mode=ro``) is discarded, and '%' is percent-decoding, so the path
        # silently becomes a different one. '?' is legal on POSIX and REFUSED by Windows, so it
        # is asserted on the URI's shape below rather than by making a directory nobody can
        # make here.
        punctuated = "ho#me 100% v1" if os.name == "nt" else "ho?me #1 100%"
        home = os.path.join(self._tmp.name, punctuated)
        os.makedirs(home, exist_ok=True)
        db = os.path.join(home, "relay.sqlite3")
        st = state_mod.RelayState(db)
        st.close()
        uri = state_mod._read_only_uri(db)
        self.assertIn("?mode=ro", uri,
                      "the mode parameter did not survive the path's own punctuation: %r" % uri)
        head = uri[:uri.index("?mode=ro")]
        self.assertNotIn("#", head,
                         "an unescaped '#' starts a URI fragment, so mode=ro is discarded and "
                         "the connection is read-WRITE: %r" % uri)
        self.assertIn("%25", head,
                      "the literal percent in the home was not escaped, so the path "
                      "percent-decodes into a different one: " + repr(uri))
        # '?' on a platform that allows it, asserted on the URI the code builds.
        q = state_mod._read_only_uri(os.path.join(self._tmp.name, "q?uery.sqlite3"))
        self.assertNotIn("?", q[:q.index("?mode=ro")],
                         "an unescaped '?' ends the URI early, so mode=ro is not a parameter "
                         "at all and the connection is read-WRITE: %r" % q)
        ro = state_mod.RelayState.open_read_only(db)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                ro._conn.execute("CREATE TABLE probe_write (x)")
        finally:
            ro.close()

        # (2) AN AUTHORITY-ROOTED PATH -- a UNC share on Windows, a "//host/..." path on POSIX.
        # Both are what the platform's own pathname2url renders as "//something/...", which is
        # the shape that puts a host where the URI's authority goes. Asserted on the URI, which
        # is what SQLite parses, so this holds on a machine with no share to reach. Spelled per
        # platform because a UNC spelling on POSIX is not a rooted path at all -- it is an
        # ordinary filename containing backslashes, and asserting it there measures nothing.
        if os.name == "nt":
            unc = chr(92) * 2 + "server" + chr(92) + "share" + chr(92) + "relay.sqlite3"
        else:
            unc = "//server/share/relay.sqlite3"
        unc_uri = state_mod._read_only_uri(unc)
        self.assertTrue(unc_uri.startswith("file:////"),
                        "a UNC path must carry an EMPTY authority; %r puts the host where the "
                        "authority goes and SQLite answers 'invalid uri authority'" % unc_uri)
        drive_uri = state_mod._read_only_uri(os.path.join(self._tmp.name, "d.sqlite3"))
        self.assertFalse(drive_uri.startswith("file:////"),
                         "a drive path must NOT gain the UNC authority slashes: %r" % drive_uri)

class TestSuiteMeasuresThisCheckout(unittest.TestCase):
    """The suite must import the tree it is running in (bd quaestor-d47, review finding).

    Filed and fixed from this lane because this lane is where it bit: an editable install names
    ONE checkout's ``src`` in a ``.pth``, a lane is developed in a git WORKTREE, and nothing put
    the running checkout's ``src`` in front of it. ``python -m unittest tests.whatever`` from a
    worktree therefore reported a verdict about the other tree's source -- a false failure for a
    lane that adds a symbol, and a false PASS for a lane that only adds controls to a module
    that already exists there.
    """

    @control(374)
    def test_the_test_package_puts_this_checkout_ahead_of_another_quaestor_on_the_path(self):
        """Driven against a DECOY package deliberately placed earlier on the path, because the
        real competitor -- an editable ``.pth`` for a sibling checkout -- is not present in every
        environment and a control that only works on one machine proves nothing on the others."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmp:
            decoy = os.path.join(tmp, "decoy")
            os.makedirs(os.path.join(decoy, "quaestor"))
            with open(os.path.join(decoy, "quaestor", "__init__.py"), "w",
                      encoding="utf-8") as fh:
                fh.write("DECOY = True\n")

            def resolve(import_tests):
                code = ("import sys\n"
                        "sys.path[:0] = [%r, %r]\n" % (decoy, root)
                        + ("import tests\n" if import_tests else "")
                        + "import quaestor\n"
                          "sys.stdout.write(quaestor.__file__)\n")
                r = subprocess.run([sys.executable, "-c", code], cwd=tmp, capture_output=True,
                                   timeout=120, shell=False)
                return (r.returncode, r.stdout.decode("utf-8").strip(),
                        r.stderr.decode("utf-8"))

            # THE DECOY REALLY DOES WIN when the package is not imported. Without this the
            # control could pass over a path the decoy never reached, proving nothing.
            rc, without, err = resolve(False)
            self.assertEqual(rc, 0, err)
            self.assertTrue(os.path.abspath(without).startswith(decoy), without)
            rc, withpkg, err = resolve(True)
            self.assertEqual(rc, 0, err)
            self.assertTrue(
                os.path.abspath(withpkg).startswith(os.path.join(root, "src") + os.sep),
                "imported %r, not this checkout's src under %r" % (withpkg, root))
        # And in THIS process, which is the one the rest of the suite measures with.
        self.assertTrue(
            os.path.abspath(cs.__file__).startswith(os.path.join(root, "src") + os.sep),
            cs.__file__)


if __name__ == "__main__":
    unittest.main()

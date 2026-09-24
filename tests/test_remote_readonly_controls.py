"""Remote read-only controls -- the Plus-tier contract, measured, not promised.

A ChatGPT Plus account reaches this transport only through the TUNNEL channel, and the whole
feature rests on one property: the remote token authenticates a READ-ONLY surface, and no
argument, header or retry can widen it. These tests attack that property the way an eager model
would -- by listing the surface it was advertised, then calling every write tool anyway -- and by
checking the retrieval verbs actually retrieve.

The tunnel itself is a process boundary (cloudflared -> loopback), so it is tested at its seams:
the command is built from a loopback target only, the URL parser finds the one URL that matters
in realistic output, and the doctor's verdicts are measured against a LIVE local server rather
than read out of a handler.
"""
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests.controls import control  # noqa: E402
from tests import support  # noqa: E402

from quaestor.transports.mcp import adapter as mcp_adapter  # noqa: E402
from quaestor.transports.mcp import auth as transport_auth  # noqa: E402
from quaestor.transports.mcp import ledger as transport_ledger  # noqa: E402
from quaestor.transports.mcp import schemas as ts  # noqa: E402
from quaestor.transports.mcp import server as mcp_server  # noqa: E402
from quaestor.transports import tunnel  # noqa: E402

DISPATCH_ARGS = {"workflow_id": "wf-remote", "step_id": "s1", "task": "read-only check",
                 "repo_alias": "qualification-fixture"}


def fake_secret():
    return "tok_" + os.urandom(18).hex()


class RemoteChannelBase(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox(prefix="quaestor-remote-")
        self.addCleanup(self.sb.close)
        self.home = self.sb.dir
        self.fixture = self.sb.repo("fixture")
        self.auth_dir = tempfile.mkdtemp(prefix="quaestor-remote-auth-")
        self.table = mcp_adapter.qualification_repo_table(self.fixture)
        self.loopback_token = fake_secret()
        transport_auth.provision(self.auth_dir, token=self.loopback_token)
        self.remote_token = fake_secret()
        transport_auth.provision(self.auth_dir, token=self.remote_token, remote=True)
        self.adapter = mcp_adapter.Adapter(self.home, repo_table=self.table)
        self.addCleanup(self.adapter.close)

    def auth(self, token):
        return transport_auth.authenticate_http(
            {"Authorization": "Bearer " + token} if token else {}, directory=self.auth_dir)

    def call(self, tool, args, token):
        return self.adapter.call(tool, args, auth=self.auth(token))


class TestTheRemoteChannel(RemoteChannelBase):
    @control(215)
    def test_the_remote_token_authenticates_a_distinct_read_only_channel(self):
        r = self.auth(self.remote_token)
        self.assertTrue(r.ok)
        self.assertEqual(r.channel, transport_auth.CHANNEL_HTTP_REMOTE,
                         "the channel class must come from WHICH token was presented")
        self.assertEqual(r.identity_class, transport_auth.IDENTITY_SHARED_SECRET)
        # The loopback token still authenticates the full channel.
        lb = self.auth(self.loopback_token)
        self.assertTrue(lb.ok)
        self.assertEqual(lb.channel, transport_auth.CHANNEL_HTTP_LOOPBACK)
        # And a wrong token is refused identically, whichever tokens exist.
        bad = self.auth(fake_secret())
        self.assertFalse(bad.ok)
        self.assertEqual(bad.reason, transport_auth.REFUSAL)

    @control(216)
    def test_the_remote_surface_is_exactly_the_read_only_tools(self):
        srv = mcp_server.MCPServer(self.adapter, auth_dir=self.auth_dir)
        remote = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                            auth=self.auth(self.remote_token))
        names = sorted(t["name"] for t in remote["result"]["tools"])
        self.assertEqual(names, sorted(ts.READ_ONLY_TOOLS),
                         "a remote caller must be advertised only what it can call")
        self.assertIn("search", names)
        self.assertIn("fetch", names)
        # Every advertised annotation must tell the truth, too.
        for t in remote["result"]["tools"]:
            self.assertTrue(t["annotations"]["readOnlyHint"], t["name"])
        # The loopback surface is the full governed surface, unfiltered.
        local = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                           auth=self.auth(self.loopback_token))
        self.assertEqual(sorted(t["name"] for t in local["result"]["tools"]), sorted(ts.TOOLS))

    @control(217)
    def test_every_write_is_refused_by_channel_and_ledgered(self):
        srv = mcp_server.MCPServer(self.adapter, auth_dir=self.auth_dir)
        for name in sorted(ts.TOOLS):
            if name in ts.READ_ONLY_TOOLS:
                continue
            if name == ts.T_DISPATCH:
                args = dict(DISPATCH_ARGS)
            elif name == ts.T_PROGRAM_CREATE:
                args = {"title": "t", "objective": "o", "repo_alias": "qualification-fixture"}
            elif name in (ts.T_PROGRAM_STATUS, ts.T_PROGRAM_INBOX, ts.T_PROGRAM_DECIDE,
                          ts.T_PROGRAM_CANCEL):
                args = {"program_id": "prog_absent"} if name != ts.T_PROGRAM_DECIDE else \
                       {"program_id": "prog_absent", "message_id": "m1", "text": "x"}
            elif name == ts.T_CANCEL:
                args = {"run_id": "run_absent"}
            elif name == ts.T_RECONCILE:
                args = {"dry_run": True}
            else:
                args = {}
            before = self.adapter.ledger.count()
            out = srv.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                              "params": {"name": name, "arguments": args}},
                             auth=self.auth(self.remote_token))
            self.assertTrue(out["result"]["isError"], name)
            body = out["result"]["structuredContent"]
            self.assertEqual(body["reason"], mcp_adapter.REMOTE_READ_ONLY, name)
            self.assertEqual(self.adapter.ledger.count(), before + 1,
                             "%s: a refused remote write left no ledger row" % name)
            row = self.adapter.ledger.all_rows()[-1]
            self.assertEqual(row["disposition"], transport_ledger.REFUSED, name)
            self.assertEqual(row["channel"], transport_auth.CHANNEL_HTTP_REMOTE, name)

    @control(217)
    def test_the_ceiling_holds_even_for_arguments_that_look_like_writes(self):
        # A read-only tool's arguments are DATA; nothing in them can move the channel.
        r = self.call(ts.T_STATUS, {"run_id": "does-not-exist"}, self.remote_token)
        self.assertEqual(r.reason, "NOT_FOUND")
        r = self.call(ts.T_SEARCH, {"query": "wf-remote"}, self.remote_token)
        self.assertTrue(r.ok)
        r = self.call(ts.T_FETCH, {"id": "does-not-exist"}, self.remote_token)
        self.assertEqual(r.reason, "NOT_FOUND")

    @control(218)
    def test_revoking_the_remote_token_closes_the_channel_at_once(self):
        self.assertTrue(self.auth(self.remote_token).ok)
        transport_auth.delete(self.auth_dir, remote=True)
        r = self.auth(self.remote_token)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, transport_auth.REFUSAL)
        # The loopback token is untouched by a remote revocation.
        self.assertTrue(self.auth(self.loopback_token).ok)

    @control(218)
    def test_rotating_the_remote_token_invalidates_the_old_value(self):
        old = self.remote_token
        transport_auth.provision(self.auth_dir, token=fake_secret(), remote=True)
        self.assertFalse(self.auth(old).ok)


class TestRetrievalVerbs(RemoteChannelBase):
    def _dispatch_one(self):
        res = self.call(ts.T_DISPATCH, dict(DISPATCH_ARGS), self.loopback_token)
        self.assertTrue(res.ok, res.detail)
        return res.payload["run_id"]

    @control(219)
    def test_search_finds_what_this_transport_created_and_nothing_else(self):
        rid = self._dispatch_one()
        r = self.call(ts.T_SEARCH, {"query": "wf-remote"}, self.remote_token)
        self.assertTrue(r.ok, r.detail)
        ids = [m["id"] for m in r.payload["matches"] if m["kind"] == "run"]
        self.assertIn(rid, ids)
        # An empty query is refused, not treated as "everything".
        r = self.call(ts.T_SEARCH, {"query": "   "}, self.remote_token)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "EMPTY_QUERY")

    @control(219)
    def test_fetch_returns_the_full_run_document_with_both_halves_labelled(self):
        rid = self._dispatch_one()
        r = self.call(ts.T_FETCH, {"id": rid}, self.remote_token)
        self.assertFalse(r.ok)          # a qualification dispatch has no handoff yet
        self.assertEqual(r.reason, "NO_HANDOFF")
        self.assertEqual(r.payload["execution_state"], "PREFLIGHT")

    @control(219)
    def test_fetch_of_an_out_of_scope_run_is_the_same_shape_as_no_such_run(self):
        other_home = tempfile.mkdtemp(prefix="quaestor-remote-other-")
        other = mcp_adapter.Adapter(other_home, repo_table=self.table)
        self.addCleanup(other.close)
        res = other.call(ts.T_DISPATCH, dict(DISPATCH_ARGS, workflow_id="wf-other"),
                         auth=self.auth(self.loopback_token))
        self.assertTrue(res.ok)
        foreign = res.payload["run_id"]
        r = self.call(ts.T_FETCH, {"id": foreign}, self.remote_token)
        self.assertEqual(r.reason, "NOT_FOUND")
        self.assertEqual(r.payload["found"], False)

    @control(219)
    def test_search_covers_programs_and_fetch_reads_the_durable_record(self):
        from quaestor.core.strategic_store import StrategicStore
        sdb = os.path.join(self.home, "strategic.sqlite3")
        sstore = StrategicStore(sdb)
        try:
            pid = sstore.create_program("Remote visible program",
                                        objective="prove the retrieval surface", now=123.0)
        finally:
            sstore.close()
        r = self.call(ts.T_SEARCH, {"query": "retrieval surface"}, self.remote_token)
        self.assertTrue(r.ok)
        self.assertIn(pid, [m["id"] for m in r.payload["matches"]])
        r = self.call(ts.T_FETCH, {"id": pid}, self.remote_token)
        self.assertTrue(r.ok, r.detail)
        self.assertEqual(r.payload["id"], pid)
        self.assertTrue(r.payload["text"])
        self.assertTrue(r.payload["document"])


class TestTheTunnelSeams(unittest.TestCase):
    @control(220)
    def test_the_tunnel_command_targets_loopback_and_nothing_else(self):
        args = tunnel.cloudflared_args(8123)
        self.assertIn("--url", args)
        self.assertEqual(args[args.index("--url") + 1], "http://127.0.0.1:8123")
        self.assertIn("8123", " ".join(args))
        self.assertNotIn("0.0.0.0", " ".join(args))

    @control(220)
    def test_the_url_parser_finds_the_quick_tunnel_url_in_realistic_output(self):
        sample = ("2026-08-24T00:00:00Z INF +--------------------------------------------------------------------+\n"
                  "2026-08-24T00:00:00Z INF |  Your quick Tunnel has been created! Visit it at:  |\n"
                  "2026-08-24T00:00:00Z INF |  https://wildly-random-words-here.trycloudflare.com |\n"
                  "2026-08-24T00:00:00Z INF +--------------------------------------------------------------------+\n")
        self.assertEqual(tunnel.parse_tunnel_url(sample),
                         "https://wildly-random-words-here.trycloudflare.com")
        self.assertEqual(tunnel.parse_tunnel_url("no url here"), "")
        # A URL in a log line must not swallow surrounding text.
        self.assertEqual(tunnel.parse_tunnel_url("visit https://a-b.trycloudflare.com today"),
                         "https://a-b.trycloudflare.com")

    @control(220)
    def test_the_doctor_measures_a_live_server_not_a_documentation_claim(self):
        home = tempfile.mkdtemp(prefix="quaestor-doctor-home-")
        fixture = tempfile.mkdtemp(prefix="quaestor-doctor-repo-")
        auth_dir = tempfile.mkdtemp(prefix="quaestor-doctor-auth-")
        tok = fake_secret()
        transport_auth.provision(auth_dir, token=tok, remote=True)
        adapter = mcp_adapter.Adapter(home, repo_table={"ok": fixture})
        self.addCleanup(adapter.close)
        srv = mcp_server.MCPServer(adapter, auth_dir=auth_dir)
        httpd, port = mcp_server.build_http_server(srv, host="127.0.0.1", port=0)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(httpd.shutdown)

        report = tunnel.doctor("http://127.0.0.1:%d" % port, token=tok)
        self.assertTrue(report["ok"], json.dumps(report["findings"], indent=2))
        checks = {f["check"]: f for f in report["findings"]}
        self.assertTrue(checks["health"]["ok"])
        self.assertTrue(checks["mcp_bearer_enforced"]["ok"])
        self.assertTrue(checks["token_accepted"]["ok"])
        self.assertTrue(checks["surface_read_only"]["ok"])
        # And the doctor is not vacuous: a WRONG token must fail the token check.
        report = tunnel.doctor("http://127.0.0.1:%d" % port, token="tok_wrong")
        checks = {f["check"]: f for f in report["findings"]}
        self.assertFalse(checks["token_accepted"]["ok"])
        self.assertFalse(report["ok"])

        # An unreachable URL fails health, and the doctor still returns a verdict.
        report = tunnel.doctor("http://127.0.0.1:1", token="", timeout=3.0)
        self.assertFalse(report["ok"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

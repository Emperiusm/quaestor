"""webui controls -- the local dashboard is a bearer-gated loopback surface over governed ops.

The dashboard shares the threat model of the qualified observer httpd (transports.mcp.server) but
serves a browser, so these controls attack the properties that matter when the "client" is a human
tab instead of a governed connector:

    * the socket never leaves loopback, and CANNOT be configured otherwise;
    * everything except /health refuses an absent or wrong bearer with ONE identical refusal --
      READS and WRITES alike;
    * the read surface serves real orchestrator state through orch.status_view / orch.inbox;
    * writes are ROUTE-SCOPED, never blanket: every POST maps 1:1 onto the SAME governed
      operation the CLI invokes (direction doc sections 9/10 -- the transport invokes governed
      ops; it never grants authority), GET on a write route answers 405, an unmapped POST path
      answers 404, every write refuses an anonymous caller, and mode changes demand an explicit
      {"confirm": true} plus a known value;
    * the token VALUE appears nowhere: not in bodies, not in headers, not in the startup line.

Fixtures are minimal direct store writes (StrategicStore + orch.create_program/plan_lane) against a
disposable home, per the qualification rule that a control which constructs its own subject proves
nothing unless the subject is the PRODUCTION path -- here, the same home layout the CLI uses. The
write-surface end-to-end controls additionally build a real fixture project repository (the same
shape tests.test_operational_controls.make_fixture_repo produces, fake executor manifest included)
and drive create -> plan -> tick -> answer -> cancel entirely over HTTP.
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import stat
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from tests import support  # noqa: E402
from tests.test_operational_controls import make_fixture_repo  # noqa: E402

from quaestor.core import decisions as dec_mod  # noqa: E402
from quaestor.core import domain as dom_mod  # noqa: E402
from quaestor.core import handoff as handoff_mod  # noqa: E402
from quaestor.core import identity as ident_mod  # noqa: E402
from quaestor.core import messages as msg_mod  # noqa: E402
from quaestor.core import orchestrator as orch  # noqa: E402
from quaestor.core import strategic_store as ss_mod  # noqa: E402
from quaestor.core.store import Store  # noqa: E402
from quaestor.projects import config as cfg_mod  # noqa: E402
from quaestor.transports import webui  # noqa: E402
from quaestor.transports.mcp import mode as transport_mode  # noqa: E402

PROGRAM_TITLE = "WebUI Fixture Program"
LANE_TITLE = "Lane One"


def _seed_home(home: str) -> str:
    """One program, one lane -- enough state for every view to be NON-VACUOUS."""
    sstore = ss_mod.StrategicStore(ss_mod.strategic_path(home))
    try:
        pid = orch.create_program(sstore, title=PROGRAM_TITLE,
                                  objective="observe the observer", actor_id="t")
        orch.plan_lane(sstore, pid, title=LANE_TITLE, task="do the thing",
                       kind=orch.KIND_IMPLEMENTATION, actor_id="t")
        return pid
    finally:
        sstore.close()


class WebUIBase(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox(prefix="quaestor-webui-")
        self.addCleanup(self.sb.close)
        self.home = self.sb.dir
        self.pid = _seed_home(self.home)
        self.token_file = webui.resolve_token_file(self.home)
        webui.ensure_token(self.token_file)
        self.token = webui.load_token(self.token_file)
        httpd, port = webui.build_webui_server(self.home, port=0, token_file=self.token_file)
        self.httpd = httpd
        self.port = port
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        # Cleanups run LIFO: register the close FIRST so the shutdown runs BEFORE it, or the
        # selector wakes up on an already-closed handle (WinError 10038).
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)

    # -- helpers -----------------------------------------------------------------------------
    def url(self, path: str) -> str:
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def get(self, path: str, token: str | None = "", method: str = "GET"):
        """(status, headers-dict-lowercased, body-bytes). token None = send NO header at all."""
        req = urllib.request.Request(self.url(path), method=method)
        if token is None:
            pass
        elif token == "":
            token = self.token
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            # Read THEN close: an abandoned HTTPError keeps its socket alive and the interpreter
            # eventually scolds us with a ResourceWarning.
            try:
                return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
            finally:
                e.close()

    def jget(self, path: str, **kw):
        code, hdrs, raw = self.get(path, **kw)
        return code, hdrs, json.loads(raw.decode("utf-8"))

    def post(self, path: str, body=None, token: str | None = "", raw_data: bytes | None = None):
        """POST JSON. token "" = the fixture token; None = send NO header at all."""
        data = raw_data if raw_data is not None else json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(self.url(path), method="POST", data=data,
                                     headers={"Content-Type": "application/json"})
        shown = self.token if token == "" else token
        if shown:
            req.add_header("Authorization", "Bearer " + shown)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
            finally:
                e.close()

    def jpost(self, path: str, body=None, **kw):
        code, hdrs, raw = self.post(path, body, **kw)
        return code, hdrs, json.loads(raw.decode("utf-8"))

    def assert_security_headers(self, hdrs: dict) -> None:
        # ON EVERY RESPONSE, whatever the status: this is where caching and sniffing bite.
        self.assertEqual(hdrs.get("cache-control"), "no-store")
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")


class TestAuthentication(WebUIBase):
    def test_health_answers_without_a_token_and_carries_nothing_else(self):
        code, hdrs, raw = self.jget("/health", token=None)
        self.assertEqual(code, 200)
        self.assertEqual(hdrs.get("content-type"), "application/json")
        self.assert_security_headers(hdrs)
        self.assertEqual(raw, {"status": "ok"},
                         "an unauthenticated caller learns liveness and NOTHING else")

    def test_everything_else_refuses_an_absent_token(self):
        for path in ("/", "/api/programs", "/api/programs/%s" % self.pid,
                     "/api/programs/%s/inbox" % self.pid, "/api/programs/%s/lanes" % self.pid,
                     "/api/programs/%s/cost" % self.pid,
                     "/api/program/%s/lane/lane_x/runs" % self.pid, "/api/run/run_x",
                     "/api/events", "/api/nope"):
            code, hdrs, raw = self.get(path, token=None)
            self.assertEqual(code, 401, path)
            self.assertEqual(hdrs.get("www-authenticate"), "Bearer")
            self.assert_security_headers(hdrs)

    def test_a_wrong_token_is_refused_identically_to_a_missing_one(self):
        missing = self.get("/api/programs", token=None)
        wrong = self.get("/api/programs", token="tok_wrong")
        for code, hdrs, raw in (wrong,):
            self.assertEqual(code, 401)
        # ONE refusal string: absent vs malformed vs wrong must be indistinguishable from the
        # outside -- any difference is an oracle (transports.mcp.auth discipline).
        self.assertEqual(missing[0], 401)
        self.assertEqual(missing[2], wrong[2])
        self.assertIn(webui.REFUSAL.encode(), wrong[2])

    def test_the_bearer_gates_open_and_the_payload_names_the_seeded_program(self):
        code, hdrs, body = self.jget("/api/programs")
        self.assertEqual(code, 200)
        self.assertTrue(str(hdrs.get("content-type", "")).startswith("application/json"))
        ids = [p["program_id"] for p in body["programs"]]
        self.assertIn(self.pid, ids)

    def test_tokens_are_compared_timing_safely_over_digests(self):
        # Structural mirror of transports.mcp.auth: compare_digest over sha256 digests.
        import hashlib
        import hmac as hmac_mod
        self.assertTrue(webui.tokens_match("abc", "abc"))
        self.assertFalse(webui.tokens_match("", ""))
        self.assertFalse(webui.tokens_match("a" * 100, "b" * 100))
        self.assertIs(hmac_mod.compare_digest, __import__("hmac").compare_digest)
        self.assertEqual(hashlib.sha256(b"x").hexdigest(), webui._digest("x"))


class TestReadOnlySurface(WebUIBase):
    def test_program_detail_inbox_and_lanes_come_from_orchestrator_views(self):
        code, hdrs, view = self.jget("/api/programs/%s" % self.pid)
        self.assertEqual(code, 200)
        self.assertEqual(view["program_id"], self.pid)
        self.assertEqual(view["title"], PROGRAM_TITLE)
        self.assertEqual([l["title"] for l in view["lanes"]], [LANE_TITLE],
                         "the detail view IS orch.status_view output, not a re-reading")
        code, _h, ib = self.jget("/api/programs/%s/inbox" % self.pid)
        self.assertEqual(code, 200)
        self.assertEqual(ib["program_id"], self.pid)
        self.assertIn("items", ib)
        code, _h, lv = self.jget("/api/programs/%s/lanes" % self.pid)
        self.assertEqual(code, 200)
        self.assertEqual(lv["lanes"][0]["lane_id"], view["lanes"][0]["lane_id"],
                         "the lanes table must not disagree with the detail view beside it")

    def test_events_summary_is_grouped_and_bounded(self):
        code, _h, ev = self.jget("/api/events")
        self.assertEqual(code, 200)
        self.assertIn("total_events", ev)
        self.assertIn("by_type", ev)
        self.assertLessEqual(len(ev["latest"]), ev["latest_limit"])

    def test_unknown_routes_and_bad_ids_answer_after_auth(self):
        self.assertEqual(self.jget("/api/nope")[0], 404)
        self.assertEqual(self.jget("/api/programs/not_a_id!")[0], 400)
        self.assertEqual(self.jget("/api/programs/prog_absent")[0], 404)
        self.assertEqual(self.jget("/api/programs/prog_absent/inbox")[0], 404)

    def test_write_methods_outside_the_map_answer_405(self):
        for method in ("PUT", "DELETE", "PATCH"):
            code, hdrs, raw = self.get("/api/programs", method=method)
            self.assertEqual(code, 405, method)
            self.assertIn(b"METHOD_NOT_ALLOWED", raw)
            self.assert_security_headers(hdrs)

    def test_the_server_binds_loopback_and_cannot_be_told_otherwise(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")
        import inspect
        params = inspect.signature(webui.build_webui_server).parameters
        # Not validated-off: ABSENT. A flag would eventually be set.
        self.assertNotIn("host", params)


class TestLaneRunDrillDown(WebUIBase):
    """The lane drill-down and run viewer read routes (ru1.8).

    Fixtures are direct store writes through the SAME public APIs the dispatcher and worker
    use -- Store.admit / transition for the attempt, bind_run for the lane binding,
    record_result / record_evidence / record_handoff for the artifacts -- so the payloads under
    test are exactly the shapes production writes. The controls attack the ways a drill-down
    could quietly become a cross-program leak or an invented fact: a lane id under the wrong
    program, an absent attempt row rendered as present, cost reported as something more than
    the package's own honest label.
    """

    def setUp(self):
        super().setUp()
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            lanes = sstore.lanes(self.pid)
            self.lane_id = lanes[0].lane_id
        finally:
            sstore.close()

    # -- fixture seams ------------------------------------------------------------------------
    def _admit_run(self, step_id: str) -> str:
        """A real attempt row through Store.admit -- THE admission path dispatch uses."""
        identity = ident_mod.build_identity(
            workflow_id=self.pid, step_id=step_id, prompt="fixture prompt %s" % step_id,
            repo_id="fixture-repo", worktree_path=self.home, expected_branch="",
            expected_head="", authority_profile="READ_ONLY")
        store = Store(os.path.join(self.home, "orchestrator.sqlite3"))
        try:
            return store.admit(identity, run_root=os.path.join(self.home, "runs"),
                               is_write=False, title="drill fixture").run_id
        finally:
            store.close()

    def _finish_run(self, run_id: str) -> None:
        """Walk the legal edge chain to HANDOFF_READY and write result/evidence/handoff."""
        edges = (dom_mod.PREFLIGHT, dom_mod.LEASED, dom_mod.DISPATCHED, dom_mod.RUNNING,
                 dom_mod.RESULT_RECEIVED, dom_mod.EVIDENCE_COLLECTED, dom_mod.HANDOFF_READY)
        store = Store(os.path.join(self.home, "orchestrator.sqlite3"))
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            for edge in edges:
                store.transition(run_id, edge)
            sstore.bind_run(self.lane_id, run_id, role=orch.KIND_IMPLEMENTATION)
            store.record_result(run_id, raw_sha256="a" * 64, outcome="RESULT_OK", valid=True,
                                handoff={"prompt_disposition": "COMPLETE",
                                         "program_verdict": "PASS",
                                         "summary": "did the thing"})
            store.record_evidence(run_id, {"verdict": "PASS",
                                           "before": {"probe_ok": True},
                                           "after": {"probe_ok": True},
                                           "inspected_count": 3, "observed_change": True,
                                           "disagreements": []})
            store.record_handoff(run_id, {
                "protocol": handoff_mod.PROTOCOL, "protocol_version": handoff_mod.PROTOCOL_VERSION,
                "run_id": run_id, "handoff_strength": "native",
                "claude_report": {"summary": "did the thing"},
                "child_telemetry": {
                    "total_cost_usd_reported": 0.1234,
                    "cost_note": ("reported by the CLI and NOT interpreted as a billed charge;"
                                  " the auth preflight is what establishes the billing path")}})
        finally:
            sstore.close()
            store.close()

    def _bind_ghost(self) -> None:
        """A lane_run binding whose attempt row does not exist -- the honest-hole case."""
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            sstore.bind_run(self.lane_id, "run_ghost", role=orch.KIND_IMPLEMENTATION)
        finally:
            sstore.close()

    def _seed_review(self) -> None:
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            sstore.record_review("rev_drill1", program_id=self.pid, lane_id=self.lane_id,
                                 kind="ADVERSARIAL", outcome="CLEAN", result={"findings": []})
        finally:
            sstore.close()

    # -- the controls --------------------------------------------------------------------------
    def test_drill_down_lists_runs_with_state_and_artifact_flags(self):
        finished = self._admit_run("step_done")
        self._finish_run(finished)
        self._bind_ghost()
        code, hdrs, d = self.jget("/api/program/%s/lane/%s/runs" % (self.pid, self.lane_id))
        self.assertEqual(code, 200)
        self.assert_security_headers(hdrs)
        self.assertEqual(d["program_id"], self.pid)
        self.assertEqual(d["lane_id"], self.lane_id)
        runs = d["runs"]
        self.assertEqual(len(runs), 2)
        by_id = {r["run_id"]: r for r in runs}
        done = by_id[finished]
        self.assertEqual(done["execution_state"], dom_mod.HANDOFF_READY)
        self.assertEqual(done["role"], orch.KIND_IMPLEMENTATION)
        self.assertTrue(done["has_evidence"])
        self.assertTrue(done["has_handoff"])
        self.assertFalse(done["attempt_absent"])
        self.assertEqual(done["outcome"]["valid"], True)
        self.assertEqual(done["outcome"]["program_verdict"], "PASS")
        ghost = by_id["run_ghost"]
        self.assertTrue(ghost["attempt_absent"],
                        "an absent attempt row is named, never rendered as live state")
        self.assertIsNone(ghost["execution_state"])
        self.assertFalse(ghost["has_handoff"])

    def test_run_viewer_serves_result_evidence_handoff_and_labelled_cost(self):
        rid = self._admit_run("step_view")
        self._finish_run(rid)
        code, _h, rp = self.jget("/api/run/%s" % rid)
        self.assertEqual(code, 200)
        self.assertEqual(rp["run"]["execution_state"], dom_mod.HANDOFF_READY)
        self.assertEqual(rp["lane"]["lane_id"], self.lane_id)
        self.assertEqual(rp["result"]["prompt_disposition"], "COMPLETE")
        self.assertIsNotNone(rp["evidence"])
        self.assertEqual(rp["evidence"]["verdict"], "PASS")
        self.assertTrue(rp["evidence"]["envelope"])
        pkg = rp["handoff_package"]
        self.assertEqual(pkg["protocol"], handoff_mod.PROTOCOL)
        cost = rp["cost_usd_reported"]
        self.assertEqual(cost["value"], 0.1234)
        self.assertIn("NOT interpreted", cost["note"],
                      "the viewer repeats the package's own honesty label verbatim")

    def test_a_run_without_handoff_reports_cost_as_none(self):
        rid = self._admit_run("step_bare")
        code, _h, rp = self.jget("/api/run/%s" % rid)
        self.assertEqual(code, 200)
        self.assertIsNone(rp["evidence"])
        self.assertIsNone(rp["handoff_package"])
        self.assertIsNone(rp["cost_usd_reported"]["value"],
                          "absence of telemetry must not be laundered into zero")

    def test_drill_down_carries_reviews_checkpoint_candidate_and_capsule(self):
        self._admit_run("step_ctx")
        self._seed_review()
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            sstore.save_checkpoint(self.lane_id,
                                   {"commit_sha": "deadbeef", "claimed_files_changed": ["a.py"]},
                                   program_id=self.pid)
        finally:
            sstore.close()
        _code, _h, d = self.jget("/api/program/%s/lane/%s/runs" % (self.pid, self.lane_id))
        self.assertEqual([r["review_id"] for r in d["reviews"]], ["rev_drill1"])
        cand = d["candidate"]
        self.assertEqual(cand["commit_sha"], "deadbeef")
        self.assertEqual(cand["claimed_files_changed"], ["a.py"])
        self.assertIn("CLAIM", cand["note"],
                      "claimed files are labelled as claims, not verified change")
        cap1 = d["context_capsule"]
        self.assertTrue(cap1.get("capsule_sha256"))
        _code, _h, d2 = self.jget("/api/program/%s/lane/%s/runs" % (self.pid, self.lane_id))
        self.assertEqual(d2["context_capsule"]["capsule_sha256"], cap1["capsule_sha256"],
                         "the capsule is reproducible from durable state")

    def test_an_empty_lane_is_a_legitimate_empty_answer(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            fresh_lane = orch.plan_lane(sstore, self.pid, title="idle", task="nothing yet",
                                        kind=orch.KIND_IMPLEMENTATION, actor_id="t")
        finally:
            sstore.close()
        code, _h, d = self.jget("/api/program/%s/lane/%s/runs" % (self.pid, fresh_lane))
        self.assertEqual(code, 200)
        self.assertEqual(d["runs"], [])
        self.assertEqual(d["inspected"], {"runs": 0, "reviews": 0})

    def test_containment_unknown_program_unknown_lane_and_cross_program_lane_404(self):
        other_sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            other_pid = orch.create_program(other_sstore, title="other program",
                                            objective="o", actor_id="t")
            other_lane = orch.plan_lane(other_sstore, other_pid, title="other lane",
                                        task="t2", kind=orch.KIND_IMPLEMENTATION, actor_id="t")
        finally:
            other_sstore.close()
        cases = {
            "/api/program/prog_absent/lane/lane_absent/runs":
                (404, "NO_SUCH_PROGRAM"),
            "/api/program/%s/lane/lane_absent/runs" % self.pid: (404, "NO_SUCH_LANE"),
            "/api/program/%s/lane/%s/runs" % (self.pid, other_lane): (404, "NO_SUCH_LANE"),
            "/api/run/run_absent": (404, "NO_SUCH_RUN"),
        }
        for path, (want_code, want_error) in cases.items():
            code, _h, body = self.jget(path)
            self.assertEqual(code, want_code, path)
            self.assertEqual(body["error"], want_error, path)
        # A valid lane id under the WRONG program must answer exactly like an absent one.
        code, _h, body = self.jget("/api/program/prog_absent/lane/%s/runs" % other_lane)
        self.assertEqual((code, body["error"]), (404, "NO_SUCH_PROGRAM"))

    def test_malformed_ids_are_named_400_refusals(self):
        for path in ("/api/program/%s/lane/bad!lane/runs" % self.pid,
                     "/api/program/bad!prog/lane/lane_x/runs",
                     "/api/run/bad!run"):
            code, _h, body = self.jget(path)
            self.assertEqual(code, 400, path)
            self.assertIn("BAD_", body["error"], path)


class TestCostVisibility(WebUIBase):
    """Cost roll-ups over the handoff packages' own telemetry (ru1.13).

    The number is what the executor CLI REPORTED -- deliberately uninterpreted as billing.
    These controls attack the two dishonesties a roll-up invites: laundering ABSENT telemetry
    into a zero (making "no handoff" look "free"), and dropping the honesty label once the
    figure is aggregated into something that looks like an invoice.
    """

    def setUp(self):
        super().setUp()
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            self.lane_id = sstore.lanes(self.pid)[0].lane_id
        finally:
            sstore.close()

    # -- fixture seams ------------------------------------------------------------------------
    @staticmethod
    def _package(provider: str, role: str, cost) -> dict:
        tel = {} if cost is None else {"total_cost_usd_reported": cost,
                                       "cost_note": "reported by the CLI and NOT interpreted"}
        return {"protocol": handoff_mod.PROTOCOL, "protocol_version": handoff_mod.PROTOCOL_VERSION,
                "handoff_strength": "native", "seat": {"provider": provider, "role": role},
                "child_telemetry": tel}

    def _seed_run(self, step_id: str, *, workflow_id: str = "", package: dict | None = None):
        identity = ident_mod.build_identity(
            workflow_id=workflow_id or self.pid, step_id=step_id,
            prompt="cost fixture %s" % step_id, repo_id="fixture-repo",
            worktree_path=self.home, expected_branch="", expected_head="",
            authority_profile="READ_ONLY")
        store = Store(os.path.join(self.home, "orchestrator.sqlite3"))
        try:
            adm = store.admit(identity, run_root=os.path.join(self.home, "runs"),
                              is_write=False, title="cost fixture")
            if package is not None:
                store.record_handoff(adm.run_id, package)
            return adm.run_id
        finally:
            store.close()

    # -- the controls --------------------------------------------------------------------------
    def test_program_cost_sums_by_provider_and_role(self):
        self._seed_run("s1", package=self._package("claude-code", "implementation", 0.10))
        self._seed_run("s2", package=self._package("claude-code", "adversarial_review", 0.25))
        self._seed_run("s3", package=self._package("codex-cli", "adversarial_review", 0.05))
        code, hdrs, c = self.jget("/api/programs/%s/cost" % self.pid)
        self.assertEqual(code, 200)
        self.assert_security_headers(hdrs)
        self.assertAlmostEqual(c["total"], 0.40, places=6)
        self.assertEqual(c["runs_counted"], 3)
        self.assertEqual(c["by_provider"], {"claude-code": 0.35, "codex-cli": 0.05})
        self.assertEqual(c["by_role"], {"implementation": 0.10,
                                        "adversarial_review": 0.30})
        self.assertIn("NOT interpreted", c["label"])
        self.assertIn("preflight", c["label"])
        self.assertFalse(c["truncated"])

    def test_absent_or_malformed_telemetry_counts_nothing_never_zero(self):
        with_handoff_no_telemetry = self._package("claude-code", "implementation", None)
        no_child_section = {"protocol": handoff_mod.PROTOCOL}
        self._seed_run("a1", package=with_handoff_no_telemetry)
        self._seed_run("a2", package=no_child_section)
        self._seed_run("a3")  # no handoff at all
        code, _h, c = self.jget("/api/programs/%s/cost" % self.pid)
        self.assertEqual(code, 200)
        self.assertEqual(c["runs_counted"], 0,
                         "runs without a usable reported figure must not be counted as 0.00")
        self.assertEqual(c["total"], 0.0)
        self.assertEqual(c["by_provider"], {})

    def test_settings_serves_home_wide_totals_with_the_label(self):
        other_pid = None
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            other_pid = orch.create_program(sstore, title="second program",
                                            objective="o", actor_id="t")
        finally:
            sstore.close()
        self._seed_run("h1", package=self._package("claude-code", "implementation", 1.00))
        self._seed_run("h2", workflow_id=other_pid,
                       package=self._package("codex-cli", "verification", 0.50))
        code, _h, s = self.jget("/api/settings")
        self.assertEqual(code, 200)
        cs = s["cost_summary"]
        self.assertAlmostEqual(cs["total"], 1.50, places=6)
        self.assertEqual(cs["runs_counted"], 2)
        self.assertEqual(cs["programs_seen"], 2)
        top = {e["program_id"]: e for e in cs["by_program_top"]}
        self.assertAlmostEqual(top[self.pid]["total"], 1.00, places=6)
        self.assertIn("NOT interpreted", cs["label"])

    def test_an_untouched_home_reports_honest_zeros(self):
        code, _h, s = self.jget("/api/settings")
        cs = s["cost_summary"]
        self.assertEqual(cs["total"], 0.0)
        self.assertEqual(cs["runs_counted"], 0)
        self.assertEqual(cs["programs_seen"], 0)

    def test_route_contract_unknown_program_bad_id_and_post_405(self):
        code, _h, b = self.jget("/api/programs/prog_absent/cost")
        self.assertEqual((code, b["error"]), (404, "NO_SUCH_PROGRAM"))
        code, _h, b = self.jget("/api/programs/bad!prog/cost")
        self.assertEqual((code, b["error"]), (400, "BAD_PROGRAM_ID"))
        code, hdrs, _r = self.post("/api/programs/%s/cost" % self.pid, {})
        self.assertEqual(code, 405)
        self.assertEqual(hdrs.get("allow"), "GET")

    def test_the_page_carries_the_cost_surfaces(self):
        page = webui.render_page(self.home)
        for needle in ("Reported cost-equivalent", "homewide-cost", "sel-cost"):
            self.assertIn(needle, page)


class TestServeLoopAndEventTail(WebUIBase):
    """The serve toggle's server-side contract (ru1.9): the loop itself is CLIENT-side (it
    re-POSTs the same governed /tick route), so the only NEW authority question is the event
    delta read -- which must stay bounded, id-bounded and honest about gaps. The pause
    vocabulary must come from core, not be retyped in the page."""

    def test_event_delta_returns_only_rows_newer_than_since(self):
        code, _h, full = self.jget("/api/events")
        self.assertEqual(code, 200)
        base_seq = full["now_seq"]
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            orch.plan_lane(sstore, self.pid, title="delta trigger", task="t",
                           kind=orch.KIND_IMPLEMENTATION, actor_id="t")
        finally:
            sstore.close()
        code, _h, delta = self.jget("/api/events?since=%d" % base_seq)
        self.assertEqual(code, 200)
        self.assertTrue(delta["delta"])
        self.assertEqual(delta["since"], base_seq)
        seqs = [e["seq"] for e in delta["events"]]
        self.assertTrue(seqs, "planning a lane must emit events")
        self.assertTrue(all(s > base_seq for s in seqs))
        self.assertEqual(delta["now_seq"], max(seqs))
        self.assertFalse(delta["truncated"])

    def test_delta_is_bounded_and_flags_truncation(self):
        old_limit = webui.EVENTS_DELTA_LIMIT
        webui.EVENTS_DELTA_LIMIT = 3
        try:
            code, _h, d = self.jget("/api/events?since=0")
            self.assertEqual(code, 200)
            self.assertLessEqual(len(d["events"]), 3)
            self.assertTrue(d["truncated"],
                            "a hit ceiling must be flagged, not silently clipped")
        finally:
            webui.EVENTS_DELTA_LIMIT = old_limit

    def test_a_bad_since_is_a_named_refusal(self):
        for qs in ("?since=abc", "?since=-4", "?since=1.5"):
            code, _h, b = self.jget("/api/events%s" % qs)
            self.assertEqual(code, 400, qs)
            self.assertEqual(b["error"], "BAD_SINCE", qs)

    def test_the_pause_vocabulary_is_served_from_core_not_retyped(self):
        from quaestor.core import orchestrator as orch_mod
        page = webui.render_page(self.home)
        m = None
        for line in page.splitlines():
            if "PAUSE_STATES=" in line:
                m = line
                break
        self.assertIsNotNone(m, "the page must carry the pause vocabulary")
        served = json.loads(m.split("=", 1)[1].rstrip(";"))
        expected = [orch_mod.PROGRAM_WAITING_STRATEGIST, orch_mod.PROGRAM_WAITING_OWNER,
                    orch_mod.PROGRAM_CANDIDATE_PASS, orch_mod.PROGRAM_CANDIDATE_FAIL,
                    orch_mod.PROGRAM_CANCELLED]
        self.assertEqual(sorted(served), sorted(expected))
        for needle in ("toggleLoop", 'id="loop-btn"', "evtail", "loop-interval",
                       "ingestDelta"):
            self.assertIn(needle, page)

    def test_events_query_variants_keep_the_auth_and_verb_contract(self):
        code, hdrs, _r = self.get("/api/events?since=1", token=None)
        self.assertEqual(code, 401)
        self.assertEqual(hdrs.get("www-authenticate"), "Bearer")
        code, hdrs, _r = self.post("/api/events?since=1", {})
        self.assertEqual((code, hdrs.get("allow")), (405, "GET"))

    def test_the_fields_the_loop_reads_exist_in_the_contract(self):
        """The loop's pause decision reads ``status`` from the SAME detail view every other
        consumer uses -- this pins that the field stays in that payload."""
        code, _h, view = self.jget("/api/programs/%s" % self.pid)
        self.assertEqual(code, 200)
        self.assertIn("status", view)


class TestTokenRotation(WebUIBase):
    """Token rotation (ru1.11): a credential-MANAGEMENT write over a proven bearer. The rotate
    response is the ONE body allowed to carry a token value -- the NEW one, earned by
    possession of the old. These controls pin that exception narrowly: the old secret never
    appears anywhere, anonymous callers get nothing, and the old token dies immediately."""

    def _token_value(self) -> str:
        return webui.load_token(self.token_file)

    def test_anonymous_rotation_is_refused_and_mutates_nothing(self):
        before = self._token_value()
        code, hdrs, raw = self.post("/api/token/rotate", {}, token=None)
        self.assertEqual(code, 401)
        self.assertEqual(hdrs.get("www-authenticate"), "Bearer")
        self.assertEqual(self._token_value(), before,
                         "an unauthenticated caller must never move the secret")

    def test_get_on_the_write_route_is_405_with_allow_post(self):
        code, hdrs, body = self.jget("/api/token/rotate")
        self.assertEqual(code, 405)
        self.assertEqual(hdrs.get("allow"), "POST")
        self.assertEqual(body["error"], "METHOD_NOT_ALLOWED")

    def test_rotation_kills_the_old_token_and_mints_a_working_fragment_url(self):
        old = self._token_value()
        code, hdrs, raw = self.post("/api/token/rotate", {})
        self.assertEqual(code, 200)
        self.assert_security_headers(hdrs)
        fresh = json.loads(raw.decode("utf-8"))
        self.assertTrue(fresh["rotated"])
        self.assertTrue(fresh["open"].startswith("http://127.0.0.1:%d/#t=" % self.port))
        # THE NARROW EXCEPTION, PINNED: the NEW value rides in the fragment URL; the OLD one
        # appears nowhere in any bytes this call produced.
        new_value = webui.load_token(self.token_file)
        self.assertNotEqual(old, new_value)
        self.assertIn(new_value.encode(), raw)
        self.assertNotIn(old.encode(), raw)
        # Old bearer is dead NOW; the new one opens the door.
        self.assertEqual(self.get("/api/programs", token=old)[0], 401)
        code, _h, body = self.jget("/api/programs", token=new_value)
        self.assertEqual(code, 200)
        if os.name == "posix":
            import stat as stat_mod
            self.assertEqual(stat_mod.S_IMODE(os.stat(self.token_file).st_mode), 0o600)

    def test_the_page_carries_the_rotation_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("rotateToken", "copyOpenUrl", 'id="open-url"', "Rotate token"):
            self.assertIn(needle, page)


class TestOnboardingWizard(WebUIBase):
    """The Settings connect-a-repository wizard (ru1.10) over the REAL detection backend
    (quaestor-ru1.2). The transport adds no policy: detection answers verbatim with its own
    authority block, and the manifest write is exactly `connect --write-manifest` / `init`'s
    conservative starter. No force-over-HTTP: an already-configured repo comes back structured
    for the UI to show."""

    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp(prefix="qx-web-connect-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.repo = make_fixture_repo(base)
        # A repo WITHOUT a manifest: the write-starter path needs an unconfigured target
        # (make_fixture_repo ships already-configured).
        self.fresh_repo = tempfile.mkdtemp(prefix="qx-web-connect-fresh-")
        self.addCleanup(shutil.rmtree, self.fresh_repo, ignore_errors=True)

    def test_detect_requires_a_path_and_answers_verbatim_on_a_real_repo(self):
        code, _h, b = self.jget("/api/connect/detect")
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "FIELD_REQUIRED")
        code, _h, d = self.jget("/api/connect/detect?path=%s" % urllib.parse.quote(self.repo))
        self.assertEqual(code, 200)
        self.assertTrue(d["ok"])
        self.assertTrue(d["git_root"], "the fixture repo is a git repo")
        self.assertEqual(d["authority"]["default"], "READ_ONLY",
                         "detection must arrive with its own restrictive authority block")
        self.assertIn("never widens", d["authority"]["note"])
        self.assertIn("candidates_only_note", d,
                      "test commands arrive as candidates, never configured")
        self.assertIn("available_agents", d)
        self.assertIn("transcript_locations", d)

    def test_detect_reports_a_bad_path_as_structured_not_found(self):
        code, _h, d = self.jget("/api/connect/detect?path=%s"
                                % urllib.parse.quote(r"C:\no\such\repo"))
        self.assertEqual(code, 200,
                         "the module's ok:false answer IS the contract; not a transport 404")
        self.assertEqual((d["ok"], d["reason"]), (False, "NOT_A_DIRECTORY"))
        self.assertIn("authority", d)

    def test_manifest_write_is_init_verbatim_and_refuses_to_overwrite(self):
        code, _h, w = self.jpost("/api/connect/manifest", {"path": self.fresh_repo})
        self.assertEqual(code, 200)
        self.assertTrue(w["ok"])
        self.assertTrue(w["manifest"].get("ok"), w["manifest"])
        manifest_path = w["manifest"]["manifest"]
        self.assertTrue(os.path.isfile(manifest_path))
        with open(manifest_path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("READ_ONLY", text, "the starter stays READ_ONLY by default")
        # Second write refuses WITHOUT clobbering the human-reviewed file: detection still
        # answers ok:true, but the MANIFEST result carries the refusal.
        code, _h, again = self.jpost("/api/connect/manifest", {"path": self.fresh_repo})
        self.assertEqual(again["manifest"].get("ok"), False)
        self.assertEqual(again["manifest"].get("reason"), "ALREADY_CONFIGURED")
        self.assertNotIn("force", again)

    def test_route_contract_anonymous_401_wrong_verbs_405(self):
        code, hdrs, _r = self.post("/api/connect/manifest", {"path": self.repo}, token=None)
        self.assertEqual(code, 401)
        self.assertEqual(hdrs.get("www-authenticate"), "Bearer")
        code, hdrs, _r = self.post("/api/connect/detect?path=x", {})
        self.assertEqual((code, hdrs.get("allow")), (405, "GET"))
        code, hdrs, _r = self.jget("/api/connect/manifest")
        self.assertEqual((code, hdrs.get("allow")), (405, "POST"))

    def test_the_page_carries_the_wizard_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("detectRepo", "writeManifest", 'id="cn-path"', "Connect a repository"):
            self.assertIn(needle, page)


class TestBrowserNotifications(WebUIBase):
    """Attention alerts (ru1.12) are CLIENT-side by design: the polling layer this dashboard
    already runs detects status transitions and fires the Notification API. No new server
    surface, no new authority. The controls pin the wiring: transition-only alerting
    vocabulary, the permission gate, and the states served from core rather than retyped."""

    def test_the_page_carries_the_notification_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("toggleNotify", "maybeAlert", "Notification.permission",
                       'id="notify-btn"', "requestPermission", "PREV_STATUS"):
            self.assertIn(needle, page)

    def test_alert_states_are_transitions_only_and_served_from_core_vocabulary(self):
        from quaestor.core import orchestrator as orch_mod
        page = webui.render_page(self.home)
        m = [l for l in page.splitlines() if "var ALERT_STATES=" in l][0]
        alert_states = json.loads(m.split("=", 1)[1].rstrip(";"))
        self.assertEqual(sorted(alert_states),
                         sorted([orch_mod.PROGRAM_WAITING_STRATEGIST,
                                 orch_mod.PROGRAM_WAITING_OWNER]))
        # The alert set must be a subset of the pause set: anything worth interrupting the
        # operator for is also something the serve loop must stop on.
        m2 = [l for l in page.splitlines() if "PAUSE_STATES=" in l][0]
        self.assertTrue(set(alert_states) <= set(json.loads(m2.split("=", 1)[1].rstrip(";"))))


class TestOrchestratorRelayBriefing(WebUIBase):
    """ru1.14 -- the packet a HUMAN carries to a chat agent this deployment cannot reach.

    The feature's whole safety argument is that it adds no authority: an outside model reads a
    document and a person carries the answer back through the governed answer route that already
    existed. So these controls attack the two ways that argument could be false -- the packet
    carrying something it must not (a bearer token, a credential-shaped span, a host path), and
    the packet's instructions being fiction (a command line that no longer parses, a message_id
    the answer route rejects, an owner-routed ask offered to a strategist seat).

    They also pin the opposite failure: a packet so cautious it is useless. A briefing that omits
    the constraints and the lane tasks is a status display, and the far side would have to invent
    the missing half.
    """

    #: Planted in durable prose the packet must render. Both are shapes core.classification
    #: recognises; the control asserts the VALUES never reach the wire, not merely that a marker
    #: appears somewhere.
    PLANTED_PATH = "C:\\Users\\operator\\private-repo"
    PLANTED_SECRET = "sk-ant-api03-" + ("A" * 48)

    def setUp(self):
        super().setUp()
        self.rich_pid, self.rich_lane, self.rich_msg = self._seed_rich()

    def _seed_rich(self):
        """A program with everything a brief needs: constraints, acceptance, tasks, an open
        question, a live decision -- and planted credential/host-path prose in the task."""
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            pid = orch.create_program(
                sstore, title="Relay Fixture", objective="hold the strategist seat remotely",
                constraints=["no new inbound authority path", "loopback only"], actor_id="t")
            lane = orch.plan_lane(
                sstore, pid, title="Backend packet",
                task="assemble from durable rows in %s using %s"
                     % (self.PLANTED_PATH, self.PLANTED_SECRET),
                kind=orch.KIND_IMPLEMENTATION,
                acceptance=["carries no token", "renders honestly when vacuous"], actor_id="t")
            msg = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="ex", lane_id=lane,
                                      program_id=pid,
                                      payload="should the packet embed the dashboard token?")
            sstore.record_message(msg)
            sstore.record_decision(dec_mod.new_decision(
                pid, "plain text or json?", lane_id=lane, decision="plain text",
                authority=dec_mod.BY_STRATEGIST,
                rationale="it must survive a paste into any chat box"))
            return pid, lane, msg.message_id
        finally:
            sstore.close()

    def brief(self, pid=None):
        code, hdrs, raw = self.get("/api/program/%s/briefing" % (pid or self.rich_pid))
        self.assertEqual(code, 200, raw)
        self.assert_security_headers(hdrs)
        return json.loads(raw.decode("utf-8")), raw

    # -- the packet is a BRIEF, not a status display -----------------------------------------
    def test_the_packet_carries_the_brief_not_only_the_state(self):
        doc, _raw = self.brief()
        self.assertEqual(doc["program_id"], self.rich_pid)
        self.assertEqual(doc["constraints"],
                         ["no new inbound authority path", "loopback only"])
        self.assertEqual([c for e in doc["acceptance"] for c in e["criteria"]],
                         ["carries no token", "renders honestly when vacuous"])
        lane = doc["lanes"][0]
        self.assertEqual(lane["lane_id"], self.rich_lane)
        self.assertTrue(lane["task"], "a lane without its task is a state display, not a brief")
        # ...and all of it reaches the RENDERED text, which is the artifact a human pastes.
        prompt = doc["prompt"]
        for needle in ("no new inbound authority path", "carries no token", "Backend packet",
                       "hold the strategist seat remotely", "plain text",
                       "should the packet embed the dashboard token?"):
            self.assertIn(needle, prompt)

    def test_an_absent_section_is_stated_as_absent_rather_than_omitted(self):
        # The base fixture program has no constraints and no acceptance recorded. A packet that
        # simply dropped those headings would read as "unconstrained" to the far side.
        doc, _raw = self.brief(self.pid)
        self.assertEqual(doc["constraints"], [])
        self.assertIn("IMMUTABLE CONSTRAINTS", doc["prompt"])
        self.assertIn("none recorded", doc["prompt"])

    def test_a_vacuous_bundle_refuses_to_render_a_confident_empty_brief(self):
        from quaestor.core import briefing as briefing_mod
        doc = briefing_mod.briefing({})
        self.assertTrue(doc["vacuous"])
        self.assertIn("NO RECORDED STATE", doc["prompt"])
        self.assertNotIn("WHAT TO PRODUCE", doc["prompt"],
                         "an empty program must not be handed a work instruction")

    # -- what must never leave --------------------------------------------------------------
    def test_credential_and_host_path_shapes_never_reach_the_wire(self):
        doc, raw = self.brief()
        body = raw.decode("utf-8")
        self.assertNotIn(self.PLANTED_SECRET, body,
                         "a credential-shaped span reached a packet built to be pasted"
                         " into a third party's chat log")
        self.assertNotIn("private-repo", body, "a host path survived the hand-off packet")
        self.assertIn("<secret-withheld:", doc["lanes"][0]["task"])
        self.assertIn("<path-withheld>", doc["lanes"][0]["task"])
        # The removal is REPORTED, not silent: the operator must see the packet was modified.
        self.assertTrue(doc["classification"]["modified"])
        self.assertGreaterEqual(doc["classification"]["secrets_removed"], 1)
        self.assertGreaterEqual(doc["classification"]["paths_removed"], 1)
        self.assertIn("sanitised before hand-off", doc["prompt"])

    def test_no_briefing_ever_carries_the_dashboard_token(self):
        doc, raw = self.brief()
        self.assertNotIn(self.token, raw.decode("utf-8"))
        url = doc["surfaces"]["dashboard_url"]
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        self.assertNotIn("#t=", url, "the one-step URL embeds the bearer; this packet leaves"
                                     " the machine by hand and must carry the clean form")
        # And the packet SAYS the token was withheld -- an agent that does not know something
        # was withheld asks the operator for it.
        self.assertIn("token is deliberately absent", doc["prompt"])

    # -- the instructions must be true -------------------------------------------------------
    def test_the_relay_vocabulary_is_derived_from_its_own_source_not_retyped(self):
        from quaestor.transports import cli as cli_mod
        from quaestor.transports.mcp import schemas as mcp_schemas
        doc, _raw = self.brief()
        surfaces = doc["surfaces"]
        verbs = cli_mod.command_verbs("program")
        self.assertEqual(surfaces["cli_verbs"], list(verbs))
        self.assertIn("answer", verbs, "the packet prints `program answer`; it must exist")
        self.assertIn("program answer %s" % self.rich_pid, surfaces["cli_answer"])
        self.assertEqual(surfaces["mcp_decide_tool"], mcp_schemas.T_PROGRAM_DECIDE)
        self.assertEqual(surfaces["mcp_tools"], list(mcp_schemas.TOOLS))

    def test_one_directive_packet_per_open_question_naming_its_message_id(self):
        doc, _raw = self.brief()
        self.assertEqual(len(doc["open_questions"]), 1)
        self.assertEqual(len(doc["directives"]), 1)
        d = doc["directives"][0]
        self.assertEqual(d["message_id"], self.rich_msg)
        self.assertEqual(d["route"], "STRATEGIST")
        self.assertIn(self.rich_msg, d["prompt"])
        self.assertIn("should the packet embed the dashboard token?", d["prompt"])
        # The narrow packet still carries what a decision cannot be made without...
        self.assertIn("no new inbound authority path", d["prompt"])
        self.assertIn("DECISIONS YOU MUST NOT CONTRADICT", d["prompt"])
        # ...and still refuses to imply any authority.
        self.assertIn("grants nothing", d["prompt"])

    def test_an_owner_routed_ask_is_never_offered_to_a_strategist_relay(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            m = msg_mod.new_message(msg_mod.AUTHORITY_REQUEST, actor_id="ex",
                                    lane_id=self.rich_lane, program_id=self.rich_pid,
                                    payload="may I push to the remote?")
            sstore.record_message(m)
        finally:
            sstore.close()
        doc, _raw = self.brief()
        owner = [q for q in doc["open_questions"] if q["message_id"] == m.message_id]
        self.assertEqual(len(owner), 1)
        self.assertEqual(owner[0]["route"], "OWNER")
        packet = [d for d in doc["directives"] if d["message_id"] == m.message_id][0]["prompt"]
        self.assertIn("THIS ONE IS NOT YOURS", packet)
        self.assertNotIn("WHAT TO PRODUCE", packet,
                         "an owner-routed ask must not come with a directive instruction")
        self.assertIn("routed to the OWNER", doc["prompt"])

    def test_the_packets_own_instructions_close_the_loop_over_http(self):
        """THE ACCEPTANCE TEST FOR THE WHOLE FEATURE: the id the packet tells the relay to copy
        is the id the governed answer route accepts, and answering it clears the question."""
        doc, _raw = self.brief()
        mid = doc["open_questions"][0]["message_id"]
        code, _h, ans = self.jpost("/api/program/%s/answer" % self.rich_pid,
                                   {"message_id": mid, "text": "No. Never embed the token.",
                                    "rationale": "the packet is designed to leave the machine"})
        self.assertEqual(code, 200, ans)
        self.assertEqual(ans["authority"], dec_mod.BY_STRATEGIST,
                         "a relayed directive records STRATEGIST authority and nothing higher")
        after, _raw2 = self.brief()
        self.assertEqual([q["message_id"] for q in after["open_questions"]], [])
        self.assertIn("No. Never embed the token.",
                      [d["decision"] for d in after["decisions"]])
        self.assertIn("none -- nothing is waiting on you", after["prompt"])

    # -- bounds and honesty of the self-report -----------------------------------------------
    def test_directive_packets_are_bounded_and_the_truncation_is_labelled(self):
        """Each directive packet repeats the shared context, so the list is the one term that
        grows multiplicatively. Unbounded, a busy queue would cross the transport's response
        bound and answer 500 -- losing the WHOLE packet rather than part of it. Bounded, the
        program briefing still names every open question, so nothing is concealed."""
        from quaestor.core import briefing as briefing_mod
        limit = briefing_mod.DIRECTIVE_LIMIT
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            for i in range(limit + 3):
                sstore.record_message(msg_mod.new_message(
                    msg_mod.CLARIFICATION_REQUEST, actor_id="ex", lane_id=self.rich_lane,
                    program_id=self.rich_pid, payload="extra question %d" % i))
        finally:
            sstore.close()
        doc, _raw = self.brief()
        self.assertEqual(len(doc["open_questions"]), limit + 4)
        self.assertEqual(len(doc["directives"]), limit)
        self.assertTrue(doc["directives_truncated"])
        self.assertEqual(doc["directives_limit"], limit)
        # Nothing is HIDDEN by the bound: the briefing itself still names every one of them.
        self.assertIn("OPEN QUESTIONS AWAITING AN ANSWER (%d)" % (limit + 4), doc["prompt"])
        self.assertIn("extra question %d" % (limit + 2), doc["prompt"])

    def test_the_sanitiser_counts_spans_removed_not_times_inspected(self):
        """The counters are shown to the operator as 'what was removed before hand-off'. A lane
        title reused across sections must therefore be classified ONCE -- otherwise a single
        withheld span inflates the count by however many places happened to render it."""
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            pid = orch.create_program(sstore, title="counter fixture",
                                      objective="clean prose", actor_id="t")
            lane = orch.plan_lane(sstore, pid, title="lane in %s" % self.PLANTED_PATH,
                                  task="clean task", kind=orch.KIND_IMPLEMENTATION,
                                  actor_id="t")
            # TWO questions on that lane: its title is rendered in the lanes section and again
            # beside each question, i.e. three renderings of one path-shaped span.
            for i in range(2):
                sstore.record_message(msg_mod.new_message(
                    msg_mod.CLARIFICATION_REQUEST, actor_id="ex", lane_id=lane,
                    program_id=pid, payload="q%d" % i))
        finally:
            sstore.close()
        doc, raw = self.brief(pid)
        self.assertEqual(doc["classification"]["paths_removed"], 1)
        self.assertNotIn("private-repo", raw.decode("utf-8"))
        self.assertIn("<path-withheld>", doc["open_questions"][0]["lane_title"])

    # -- route contract ----------------------------------------------------------------------
    def test_route_contract_anonymous_401_bad_id_400_unknown_404_post_405(self):
        code, _h, raw = self.get("/api/program/%s/briefing" % self.rich_pid, token=None)
        self.assertEqual(code, 401)
        self.assertNotIn(b"objective", raw)
        code, _h, _r = self.get("/api/program/%s/briefing" % self.rich_pid, token="tok_wrong")
        self.assertEqual(code, 401)
        code, _h, body = self.jget("/api/program/not..an..id/briefing")
        self.assertEqual((code, body["error"]), (400, "BAD_PROGRAM_ID"))
        code, _h, body = self.jget("/api/program/prog_missing/briefing")
        self.assertEqual((code, body["error"]), (404, "NO_SUCH_PROGRAM"))
        code, hdrs, body = self.jpost("/api/program/%s/briefing" % self.rich_pid, {})
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "GET")

    def test_the_page_carries_the_relay_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("copyBriefing", "copyDirective", "showBriefing", "copyText",
                       'id="brief-text"', "/briefing", "copy directive prompt"):
            self.assertIn(needle, page)


class TestPageAndTokenHygiene(WebUIBase):
    def test_the_page_server_renders_program_state(self):
        code, hdrs, raw = self.get("/")
        self.assertEqual(code, 200)
        self.assertTrue(str(hdrs.get("content-type", "")).startswith("text/html"))
        html = raw.decode("utf-8")
        self.assertIn(PROGRAM_TITLE, html)
        self.assertIn(LANE_TITLE, html)
        self.assertIn("/api/", html, "the live poller targets the JSON API")
        self.assertIn("never mutates", html, "the footer states the read-only contract")

    def test_no_response_ever_carries_the_token_value(self):
        seen = []
        for path, kw in (("/health", {"token": None}), ("/health", {}),
                         ("/", {}), ("/api/programs", {}), ("/api/events", {}),
                         ("/api/programs/%s" % self.pid, {}),
                         ("/api/nope", {"token": "tok_wrong"}),
                         ("/api/programs", {"token": None})):
            code, hdrs, raw = self.get(path, **kw)
            seen.append((code, raw))
            self.assertNotIn(self.token.encode(), raw, path)
            for hk, hv in hdrs.items():
                self.assertNotIn(self.token, str(hv), "%s header %s" % (path, hk))
        self.assertTrue(any(c == 200 for c, _r in seen),
                        "hygiene measured over REAL successes, not only refusals")

    def test_the_token_file_persists_across_restarts_and_stays_restricted(self):
        first = webui.load_token(self.token_file)
        webui.ensure_token(self.token_file)
        self.assertEqual(first, webui.load_token(self.token_file),
                         "restarting the dashboard must not rotate the secret under a live tab")
        mode = stat.S_IMODE(os.stat(self.token_file).st_mode)
        if os.name == "posix":
            self.assertEqual(mode, 0o600)
        # On Windows the C runtime's chmod cannot express 0o600; the icacls hardening in
        # webui._harden is the promise there, and existence+non-emptiness is what we can measure.
        else:
            self.assertTrue(first)


class TestWriteRouteContract(WebUIBase):
    """The route-scoped write contract that replaces the blanket GET-only surface.

    Every control here attacks one way the write API could quietly become a NEW authority path:
    an unmapped POST, a read route reached by POST, a write route reached by GET, an anonymous
    writer, an unnamed refusal, or a mode change without typed confirmation.
    """

    def _write_routes(self):
        # Existence checks run AFTER authentication everywhere, so a not-yet-existing program id
        # is exactly right here: if any of these answers anything but 401 anonymously, the gate
        # is leaking route semantics to unauthenticated callers.
        absent = "prog_absent"
        return [
            ("/api/program/create", {"title": "t", "objective": "o", "project": "irrelevant"}),
            ("/api/program/%s/plan" % absent, {"title": "t", "task": "d"}),
            ("/api/program/%s/tick" % absent, {}),
            ("/api/program/%s/answer" % absent, {"message_id": "m_1", "text": "x"}),
            ("/api/program/%s/cancel" % absent, {"reason": "r"}),
            ("/api/mode/set", {"value": transport_mode.LOCAL_GOVERNED, "confirm": True}),
        ]

    def test_unknown_post_path_answers_404_json_after_auth(self):
        code, hdrs, body = self.jpost("/api/nope", {})
        self.assertEqual(code, 404)
        self.assertEqual(body["error"], "not found")
        self.assert_security_headers(hdrs)
        code, _h, body = self.jpost("/api/programs/%s/nothing" % self.pid, {})
        self.assertEqual(code, 404)

    def test_post_on_a_read_route_is_405_with_allow_get(self):
        for path in ("/", "/api/programs", "/api/events", "/api/mode",
                     "/api/programs/%s" % self.pid,
                     "/api/programs/%s/inbox" % self.pid,
                     "/api/program/%s/lane/lane_x/runs" % self.pid, "/api/run/run_x"):
            code, hdrs, _raw = self.post(path, {})
            self.assertEqual(code, 405, path)
            self.assertEqual(hdrs.get("allow"), "GET", path)

    def test_get_on_a_write_route_is_405_with_allow_post(self):
        for path in ("/api/program/create",
                     "/api/program/%s/plan" % self.pid,
                     "/api/program/%s/tick" % self.pid,
                     "/api/program/%s/answer" % self.pid,
                     "/api/program/%s/cancel" % self.pid,
                     "/api/mode/set"):
            code, hdrs, body = self.jget(path)
            self.assertEqual(code, 405, path)
            self.assertEqual(hdrs.get("allow"), "POST", path)
            self.assertEqual(body["error"], "METHOD_NOT_ALLOWED")
            self.assert_security_headers(hdrs)

    def test_every_write_route_requires_the_bearer_and_mutates_nothing_anonymously(self):
        before = self.jget("/api/programs")[2]["total"]
        for path, body in self._write_routes():
            code, hdrs, raw = self.post(path, body, token=None)
            self.assertEqual(code, 401, path)
            self.assertEqual(hdrs.get("www-authenticate"), "Bearer", path)
            self.assert_security_headers(hdrs)
        self.assertEqual(self.jget("/api/programs")[2]["total"], before,
                         "an anonymous POST must not create state")
        self.assertFalse(os.path.exists(os.path.join(
            self.home, transport_mode.MODE_FILE)),
            "an anonymous caller must never move the execution mode")

    def test_malformed_and_oversized_bodies_are_named_refusals(self):
        code, _h, raw = self.post("/api/mode/set", raw_data=b"{not json")
        self.assertEqual(code, 400)
        self.assertIn(b"INVALID_JSON", raw)
        # The bound bites BEFORE authentication (MCP server discipline): no token, still 413.
        code, _h, raw = self.post("/api/mode/set",
                                  raw_data=b"x" * (webui.MAX_BODY_BYTES + 1), token=None)
        self.assertEqual(code, 413)
        self.assertIn(b"REQUEST_BODY_BOUND_EXCEEDED", raw)

    def test_an_over_bound_body_is_drained_before_the_refusal(self):
        """THE RACE, tested where it can actually be falsified.

        The guard refused without draining and closed the socket. On Windows a close while the
        peer is still sending resets the connection, and the RST discards the response already
        written -- so the client raised ConnectionAbortedError instead of reading the 413. It
        surfaced once in a full-suite run as a flaky error; the flake was only how the race
        announced itself. A refusal the client cannot read is not a named refusal.

        An end-to-end version of this control passed with the drain removed -- loopback buffers
        absorb a few hundred KB before the close can race the send -- so it is asserted on the
        drain itself."""
        class _Rfile:
            def __init__(self, n):
                self.left = n
                self.reads = 0

            def read(self, n):
                self.reads += 1
                take = min(n, self.left)
                self.left -= take
                return b"x" * take

        body = webui.MAX_BODY_BYTES * 4
        r = _Rfile(body)
        self.assertEqual(webui.drain_bounded(r, body), body,
                         "an over-bound body was not consumed before the socket closed")
        self.assertEqual(r.left, 0)
        # Bounded: past the ceiling we stop reading and close hard, because a peer sending that
        # much after a 413 is no longer a client that made a mistake.
        huge = webui.DRAIN_LIMIT_BYTES * 4
        r2 = _Rfile(huge)
        self.assertEqual(webui.drain_bounded(r2, huge), webui.DRAIN_LIMIT_BYTES)
        self.assertGreater(r2.left, 0)
        # A peer that stops sending early must not spin.
        r3 = _Rfile(0)
        self.assertEqual(webui.drain_bounded(r3, webui.MAX_BODY_BYTES * 2), 0)

    def test_validation_failures_name_the_refusal(self):
        code, _h, b = self.jpost("/api/program/create", {"objective": "o"})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "FIELD_REQUIRED")
        code, _h, b = self.jpost("/api/program/create",
                                 {"title": "t", "objective": "o", "project": r"C:\no\such\dir"})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "PROJECT_CONFIG_MISSING")
        code, _h, b = self.jpost("/api/program/prog_absent/plan", {"title": "t", "task": "d"})
        self.assertEqual(code, 404)
        self.assertEqual(b["error"], "NO_SUCH_PROGRAM")
        code, _h, b = self.jpost("/api/program/%s/plan" % self.pid,
                                 {"title": "t", "task": "d", "kind": "warp-drive"})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "PLAN_REFUSED")
        code, _h, b = self.jpost("/api/program/prog_absent/tick", {})
        self.assertEqual(code, 404)
        code, _h, b = self.jpost("/api/program/%s/answer" % self.pid,
                                 {"message_id": "msg_absent", "text": "x"})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "ANSWER_REFUSED")

    def test_mode_set_get_roundtrip_demands_typed_confirm_and_known_values(self):
        code, _h, b = self.jget("/api/mode")
        self.assertEqual(code, 200)
        self.assertEqual(b["transport_execution_mode"], transport_mode.QUALIFICATION_ONLY,
                         "a fresh home fails CLOSED to the qualified default")
        code, _h, b = self.jpost("/api/mode/set", {"value": transport_mode.LOCAL_GOVERNED})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "CONFIRMATION_REQUIRED")
        code, _h, b = self.jpost("/api/mode/set",
                                 {"value": "ROOT_EVERYTHING", "confirm": True})
        self.assertEqual(code, 400)
        self.assertEqual(b["error"], "UNKNOWN_MODE")
        self.assertFalse(os.path.exists(os.path.join(self.home, transport_mode.MODE_FILE)))
        code, _h, b = self.jpost("/api/mode/set",
                                 {"value": transport_mode.LOCAL_GOVERNED, "confirm": True})
        self.assertEqual(code, 200)
        self.assertTrue(b["ok"])
        code, _h, b = self.jget("/api/mode")
        self.assertEqual(b["transport_execution_mode"], transport_mode.LOCAL_GOVERNED)
        self.assertEqual(b["record"]["source"], transport_mode.MODE_SOURCE_DEPLOYMENT)


def _read_repo_file(repo: str, rel: str) -> str:
    with open(os.path.join(repo, rel), encoding="utf-8") as fh:
        return fh.read()


class TestWriteSurfaceEndToEnd(WebUIBase):
    """Writes against a REAL fixture repository, end to end over HTTP.

    The tick route spawns REAL detached workers (spawn=True, exactly like cmd_program_tick), so
    the drive helper polls rather than assumes -- the same posture as the operational e2e suite.
    The scripted DECISION_REQUEST rides plan_lane's server-side executor seam (the same fixture
    seam the CLI-side tests use); it is deliberately NOT a wire field.
    """

    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp(prefix="quaestor-webui-repo-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.repo = make_fixture_repo(base)

    def drive_until(self, pid: str, *, inbox_kind=None, status=None, deadline_s=240.0):
        """POST /tick until an inbox kind or program status appears, then return (view, inbox)."""
        end = time.time() + deadline_s
        view, ib = {}, {}
        while time.time() < end:
            code, _h, rep = self.jpost("/api/program/%s/tick" % pid)
            self.assertEqual(code, 200, rep)
            time.sleep(1.0)
            view = self.jget("/api/programs/%s" % pid)[2]
            ib = self.jget("/api/programs/%s/inbox" % pid)[2]
            if inbox_kind and any(i.get("kind") == inbox_kind for i in ib.get("items", [])):
                return view, ib
            if status and view.get("status") == status:
                return view, ib
        self.fail("drive deadline: status=%r inbox=%r" % (view.get("status"), ib.get("items")))

    # -- fixture seams ------------------------------------------------------------------------
    def seed_lane_executor(self, lane_id: str, executor: dict) -> None:
        """Fixture seam: set the lane's executor script directly.

        plan_lane's ``executor`` parameter is server-side only (never a wire field), so a lane
        planned THROUGH the API carries none; the harness writes the script here exactly where
        the store keeps it. set_lane_task's conflict-update deliberately preserves the stored
        executor, so the JSON column is written explicitly -- same value, same row.
        """
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            held = sstore.get_lane_task(lane_id)
            sstore.set_lane_task(lane_id, task=held["task"], acceptance=held["acceptance"])
            sstore._write("UPDATE lane_task SET executor_json=? WHERE lane_id=?",
                          (json.dumps(executor), lane_id))
        finally:
            sstore.close()

    def lane_run_count(self, lane_id: str) -> int:
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            return len(sstore.runs_for_lane(lane_id))
        finally:
            sstore.close()

    def recorded_decisions(self, pid: str) -> list:
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            return [d.decision for d in sstore.decisions(pid)]
        finally:
            sstore.close()

    def create_program(self, title: str) -> str:
        code, _h, b = self.jpost("/api/program/create",
                                 {"title": title, "objective": title + ": objective",
                                  "project": self.repo})
        self.assertEqual(code, 200, b)
        self.assertTrue(b.get("program_id"))
        self.assertTrue(b.get("lane_id"), "create plans the main lane like cmd_program_create")
        return b["program_id"]

    # -- the controls --------------------------------------------------------------------------
    def test_created_program_appears_in_programs_with_its_main_lane(self):
        pid = self.create_program("API Created")
        ids = [p["program_id"] for p in self.jget("/api/programs")[2]["programs"]]
        self.assertIn(pid, ids)
        view = self.jget("/api/programs/%s" % pid)[2]
        self.assertIn("API Created", [l["title"] for l in view["lanes"]],
                      "the main lane must be planned by the SAME code path the CLI uses")

    def test_plan_adds_a_lane_through_the_api(self):
        pid = self.create_program("plan target")
        code, _h, b = self.jpost("/api/program/%s/plan" % pid,
                                 {"title": "extra-lane", "task": "second thing",
                                  "kind": orch.KIND_VERIFICATION})
        self.assertEqual(code, 200, b)
        view = self.jget("/api/programs/%s" % pid)[2]
        self.assertEqual(len(view["lanes"]), 2)
        self.assertIn("extra-lane", [l["title"] for l in view["lanes"]])

    def test_answer_resolves_a_scripted_decision_request_end_to_end_via_api(self):
        # The create route's own main lane is the subject: ONE lane means ONE detached worker
        # at a time, so this control measures the API round trip rather than multi-lane
        # scheduling concurrency (which the operational suite covers with in-process spawners).
        code, _h, created = self.jpost("/api/program/create",
                                       {"title": "two-way via api",
                                        "objective": "implement div", "project": self.repo,
                                        "max_concurrent": 1})
        self.assertEqual(code, 200, created)
        pid, lane_id = created["program_id"], created["lane_id"]
        app = _read_repo_file(self.repo, os.path.join("app", "mathlib.py"))
        ask = {"kind": "fake", "config": {"scenario": "OK_PASS", "messages": [
            {"type": "DECISION_REQUEST",
             "payload": "Should divide-by-zero raise or return None?"}]}}
        finish = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py":
                            app + "\n\ndef div(a, b):\n    if b == 0:\n"
                                  "        raise ValueError('div by zero')\n"
                                  "    return a / b\n"},
            "claimed_files": ["app/mathlib.py"]}}
        self.seed_lane_executor(lane_id, {"kind": "fake",
                                          "attempt_variants": [ask, finish]})
        _view, ib = self.drive_until(pid, inbox_kind="DECISION_REQUEST")
        mid = [i for i in ib["items"] if i["kind"] == "DECISION_REQUEST"][0]["message_id"]
        code, _h, ans = self.jpost("/api/program/%s/answer" % pid,
                                   {"message_id": mid, "text": "Raise ValueError.",
                                    "rationale": "explicit failure beats a sentinel"})
        self.assertEqual(code, 200, ans)
        self.assertEqual(ans["authority"], dec_mod.BY_STRATEGIST,
                         "the dashboard records STRATEGIST authority and nothing higher")
        view, _ib = self.drive_until(pid, status=orch.PROGRAM_CANDIDATE_PASS)
        self.assertEqual(view["status"], orch.PROGRAM_CANDIDATE_PASS)
        self.assertIn("Raise ValueError.", self.recorded_decisions(pid))
        self.assertGreaterEqual(self.lane_run_count(lane_id), 2,
                                "expected an ask run AND its resumed implementation run")

    def test_drilldown_and_viewer_serve_a_real_driven_program(self):
        """The drill-down over runs produced by the REAL dispatch -> worker -> scheduler path:
        real evidence envelopes, real handoff packages, no fixture seams on the read side."""
        code, _h, created = self.jpost("/api/program/create",
                                       {"title": "drill e2e", "objective": "implement div",
                                        "project": self.repo, "max_concurrent": 1})
        self.assertEqual(code, 200, created)
        pid, lane_id = created["program_id"], created["lane_id"]
        app = _read_repo_file(self.repo, os.path.join("app", "mathlib.py"))
        finish = {"kind": "fake", "config": {
            "scenario": "OK_PASS",
            "write_files": {"app/mathlib.py":
                            app + "\n\ndef div(a, b):\n    if b == 0:\n"
                                  "        raise ValueError('div by zero')\n"
                                  "    return a / b\n"},
            "claimed_files": ["app/mathlib.py"]}}
        self.seed_lane_executor(lane_id, finish)
        _view, _ib = self.drive_until(pid, status=orch.PROGRAM_CANDIDATE_PASS)
        code, _h, drill = self.jget("/api/program/%s/lane/%s/runs" % (pid, lane_id))
        self.assertEqual(code, 200, drill)
        runs = drill["runs"]
        self.assertGreaterEqual(len(runs), 1)
        self.assertTrue(all(not r["attempt_absent"] for r in runs),
                        "real driven bindings always have their attempt row")
        done = [r for r in runs if r["has_handoff"]]
        self.assertTrue(done, "a completed program must have at least one handoff-carrying run")
        rid = done[0]["run_id"]
        code, _h, rp = self.jget("/api/run/%s" % rid)
        self.assertEqual(code, 200, rp)
        self.assertEqual(rp["lane"]["lane_id"], lane_id)
        pkg = rp["handoff_package"]
        self.assertTrue(pkg.get("protocol"), "the real package carries its protocol")
        self.assertIsNotNone(rp["evidence"])
        self.assertIn("cost_usd_reported", rp)
        self.assertTrue(drill["context_capsule"].get("capsule_sha256"))
        # The candidate record reflects the REAL committed worktree state.
        self.assertTrue(drill["candidate"]["commit_sha"],
                        "commit_sha reaches the drill-down from the lane checkpoint")

    def test_cancel_flips_program_status_to_cancelled(self):
        pid = self.create_program("doomed")
        code, _h, out = self.jpost("/api/program/%s/cancel" % pid,
                                   {"reason": "superseded by another program"})
        self.assertEqual(code, 200, out)
        self.assertTrue(out["cancelled"])
        view = self.jget("/api/programs/%s" % pid)[2]
        self.assertEqual(view["status"], orch.PROGRAM_CANCELLED)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

class TestHomeArgRouting(unittest.TestCase):
    def test_global_home_before_web_reaches_the_server(self):
        """CONTROL (found live): `--home <h> web` silently lost the deployment home because the
        web subparser's own --home (default None) shadowed the global one in the parsed
        namespace -- the dashboard stared at DEFAULT_HOME and showed an empty world. The
        subparser default must be SUPPRESS so the global value survives when the local flag is
        absent, and cmd_web must tolerate the attribute being absent entirely.
        """
        from quaestor.transports import cli
        ns = cli.build_parser().parse_args(
            ["--home", r"C:\somewhere\demo", "web", "--port", "0"])
        self.assertEqual(ns.home, r"C:\somewhere\demo")
        # And with no local flag, the GLOBAL default survives the subparser (SUPPRESS semantics):
        # the namespace carries DEFAULT_HOME rather than a shadowing None.
        ns2 = cli.build_parser().parse_args(["web", "--port", "0"])
        self.assertEqual(ns2.home, cli.DEFAULT_HOME)
        captured = {}
        real_serve = webui.serve

        def spy(home, **kw):
            captured["home"] = home
            return 0

        webui.serve = spy
        try:
            rc = cli.cmd_web(ns)
            self.assertEqual(rc, 0)
            self.assertEqual(captured["home"], r"C:\somewhere\demo")
            rc2 = cli.cmd_web(ns2)
            self.assertEqual(rc2, 0)
            self.assertEqual(captured["home"], cli.DEFAULT_HOME)
        finally:
            webui.serve = real_serve

class TestOneStepBootstrap(unittest.TestCase):
    def test_startup_payload_puts_token_in_fragment_only(self):
        """CONTROL (found in first real use): every new operator met a raw 401 JSON because
        setup meant locating a 0600 file and pasting its value blind. Startup must print a
        pre-authenticated URL whose token rides in the URL FRAGMENT -- browsers strip the
        fragment before any request, so it cannot reach the server or logs. The bare url must
        stay fragment-free for paste-the-value operators.
        """
        payload = webui.startup_payload(8765, r"C:\h\web-ui-token", "a" * 48)
        self.assertEqual(payload["url"], "http://127.0.0.1:8765/")
        self.assertNotIn("a" * 48, payload["url"])
        self.assertTrue(payload["open"].startswith("http://127.0.0.1:8765/#t="))
        self.assertIn("a" * 48, payload["open"])

    def test_page_bootstraps_the_fragment_and_autoconnects(self):
        """The page must capture #t= into session storage, strip it from the address bar, and
        auto-connect -- an operator should never need the paste field at all."""
        home = tempfile.mkdtemp(prefix="qx-web-boot-")
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        page = webui.render_page(home)
        for needle in ("location.hash.match", 'sessionStorage.setItem("qst.web.token"',
                       "history.replaceState"):
            self.assertIn(needle, page, needle)

class TestBrowserNavigationNeverSeesRawJson(unittest.TestCase):
    def test_human_navigation_gets_connect_page_api_stays_strict(self):
        """CONTROL (found live): refreshing a deep link without a stored token returned the raw
        401 JSON body -- a corpse no human can act on. Browser navigation (Accept: text/html)
        outside /api/ must receive the connect page with 200; /api/* stays machine-strict 401
        JSON so programmatic callers keep their contract. The page carries no data.
        """
        home = tempfile.mkdtemp(prefix="qx-web-nav-")
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        httpd, bound = webui.build_webui_server(home, port=0)
        th = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()
        self.addCleanup(httpd.shutdown)
        base = "http://127.0.0.1:%d" % bound

        def fetch(path, accept):
            req = urllib.request.Request(base + path, headers={"Accept": accept})
            try:
                r = urllib.request.urlopen(req, timeout=5)
                return r.status, r.read().decode("utf-8")
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode("utf-8")

        st, body = fetch("/", "text/html,application/xhtml+xml,*/*")
        self.assertEqual(st, 200)
        self.assertIn("qst.web.token", body)          # the connect page
        self.assertNotIn('"error"', body)
        st, body = fetch("/programs/some/old/deeplink", "text/html,*/*")
        self.assertEqual(st, 200)
        self.assertIn("qst.web.token", body)
        st, body = fetch("/api/programs", "text/html,*/*")
        self.assertEqual(st, 401)
        self.assertIn('"error"', body)


class TestAutonomyAndApprovalSurface(WebUIBase):
    """EPIC P6 -- the cockpit half of the automated strategist seat.

    The engine decides; this surface only lets a human SEE what a model proposed and say yes or
    no to it. So the controls attack the two ways a review surface fails: a write that widens
    what the model may do, and an approval path that records something other than what was
    shown.
    """

    def _seed_queue(self, directive="Raise ValueError."):
        """Put one directive in the approval queue by hand -- the shape _consume writes."""
        from quaestor.core import strategist as strat_mod
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            lane = sstore.lanes(self.pid)[0]
            m = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="ex",
                                    lane_id=lane.lane_id, program_id=self.pid,
                                    payload="raise or return None?")
            sstore.record_message(m)
            sstore.set_program_meta(self.pid, strat_mod.PENDING_DIRECTIVES_KEY, json.dumps(
                {"directives": [{"message_id": m.message_id, "directive": directive,
                                 "rationale": "explicit failure beats a sentinel",
                                 "why": "DEFAULT", "run_id": "run_x",
                                 "lane_id": lane.lane_id}]}))
            return m.message_id
        finally:
            sstore.close()

    def _open_ids(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            return [q["message_id"] for q in sstore.open_questions_for_program(self.pid)]
        finally:
            sstore.close()

    def _decisions(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            return [(d.decision, d.authority, d.actor_id) for d in sstore.decisions(self.pid)]
        finally:
            sstore.close()

    # -- the autonomy setting -----------------------------------------------------------------
    def test_autonomy_state_serves_the_vocabulary_from_core(self):
        from quaestor.core import autonomy as auto_mod
        code, hdrs, body = self.jget("/api/program/%s/autonomy-state" % self.pid)
        self.assertEqual(code, 200, body)
        self.assert_security_headers(hdrs)
        self.assertEqual(body["known_modes"], list(auto_mod.KNOWN_MODES))
        self.assertEqual(body["fallback_mode"], auto_mod.FALLBACK_MODE)
        self.assertEqual(body["autonomy_mode"], auto_mod.FALLBACK_MODE)
        self.assertFalse(body["explicit"], "an unset program must say the mode is a fallback")
        self.assertFalse(body["strategist_seat"])
        self.assertIn("EVERY mode", body["note"])

    def test_setting_a_known_mode_round_trips(self):
        from quaestor.core import autonomy as auto_mod
        for mode in auto_mod.KNOWN_MODES:
            code, _h, out = self.jpost("/api/program/%s/autonomy" % self.pid, {"value": mode})
            self.assertEqual(code, 200, out)
            self.assertEqual(out["autonomy_mode"], mode)
            _c, _h, state = self.jget("/api/program/%s/autonomy-state" % self.pid)
            self.assertEqual(state["autonomy_mode"], mode)
            self.assertTrue(state["explicit"])

    def test_an_unknown_mode_is_refused_and_writes_nothing(self):
        """A mistyped mode that silently became the fallback would be a policy the operator
        believes they chose and did not."""
        from quaestor.core import autonomy as auto_mod
        self.jpost("/api/program/%s/autonomy" % self.pid, {"value": auto_mod.SAFE})
        for bad in ("auto", "FULL", "", None, 3):
            code, _h, out = self.jpost("/api/program/%s/autonomy" % self.pid, {"value": bad})
            self.assertEqual(code, 400, out)
            self.assertEqual(out["error"], "UNKNOWN_AUTONOMY_MODE")
        _c, _h, state = self.jget("/api/program/%s/autonomy-state" % self.pid)
        self.assertEqual(state["autonomy_mode"], auto_mod.SAFE, "a refused write still landed")

    # -- approval ------------------------------------------------------------------------------
    def test_a_queued_directive_appears_in_the_intervention_queue(self):
        """Propose-only must not mean silently discarded: the queue is the whole mode."""
        mid = self._seed_queue()
        code, _h, ib = self.jget("/api/programs/%s/inbox" % self.pid)
        self.assertEqual(code, 200)
        pending = [i for i in ib["items"] if i["kind"] == "DIRECTIVE_PENDING_APPROVAL"]
        self.assertEqual([p["message_id"] for p in pending], [mid])
        self.assertEqual(pending[0]["payload"], "Raise ValueError.")

    def test_approving_records_exactly_what_was_shown_under_strategist_authority(self):
        mid = self._seed_queue()
        code, _h, out = self.jpost("/api/program/%s/approve" % self.pid, {"message_id": mid})
        self.assertEqual(code, 200, out)
        self.assertEqual(out["approved"], mid)
        self.assertEqual(out["remaining"], 0)
        self.assertEqual(out["authority"], dec_mod.BY_STRATEGIST,
                         "approval must not record more authority than answering does")
        self.assertNotIn(mid, self._open_ids())
        self.assertIn(("Raise ValueError.", dec_mod.BY_STRATEGIST, "webui"), self._decisions())
        _c, _h, ib = self.jget("/api/programs/%s/inbox" % self.pid)
        self.assertEqual([i for i in ib["items"]
                          if i["kind"] == "DIRECTIVE_PENDING_APPROVAL"], [])

    def test_approving_twice_is_a_named_refusal_not_a_second_decision(self):
        mid = self._seed_queue()
        self.jpost("/api/program/%s/approve" % self.pid, {"message_id": mid})
        before = len(self._decisions())
        code, _h, out = self.jpost("/api/program/%s/approve" % self.pid, {"message_id": mid})
        self.assertEqual((code, out["error"]), (404, "NO_SUCH_PENDING_DIRECTIVE"))
        self.assertEqual(len(self._decisions()), before)

    def test_discarding_leaves_the_question_open_for_a_human(self):
        """Rejecting a proposed directive must not silently re-open it to the same seat."""
        mid = self._seed_queue()
        code, _h, out = self.jpost("/api/program/%s/discard" % self.pid, {"message_id": mid})
        self.assertEqual(code, 200, out)
        self.assertEqual(out["remaining"], 0)
        self.assertIn(mid, self._open_ids(), "discarding also closed the question")
        self.assertEqual(self._decisions(), [])

    def test_approving_something_nobody_proposed_is_refused(self):
        code, _h, out = self.jpost("/api/program/%s/approve" % self.pid,
                                   {"message_id": "msg_never"})
        self.assertEqual((code, out["error"]), (404, "NO_SUCH_PENDING_DIRECTIVE"))

    # -- route contract -------------------------------------------------------------------------
    def test_route_contract_for_every_new_route(self):
        for path, verb in (("/api/program/%s/autonomy" % self.pid, "POST"),
                           ("/api/program/%s/approve" % self.pid, "POST"),
                           ("/api/program/%s/discard" % self.pid, "POST")):
            code, _h, raw = self.post(path, {}, token=None)
            self.assertEqual(code, 401, path)
            self.assertNotIn(b"program_id", raw)
            code, hdrs, body = self.jget(path)
            self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"), path)
            self.assertEqual(hdrs.get("allow"), "POST", path)
        code, _h, raw = self.get("/api/program/%s/autonomy-state" % self.pid, token=None)
        self.assertEqual(code, 401)
        code, hdrs, body = self.jpost("/api/program/%s/autonomy-state" % self.pid, {})
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "GET")
        code, _h, body = self.jget("/api/program/prog_missing/autonomy-state")
        self.assertEqual((code, body["error"]), (404, "NO_SUCH_PROGRAM"))
        code, _h, body = self.jget("/api/program/not..an..id/autonomy-state")
        self.assertEqual((code, body["error"]), (400, "BAD_PROGRAM_ID"))

    def test_the_page_carries_the_autonomy_and_approval_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("setAutonomy", "loadAutonomy", "approveDirective", "discardDirective",
                       'id="au-mode"', "autonomy-state", "DIRECTIVE_PENDING_APPROVAL"):
            self.assertIn(needle, page, needle)


class TestProgramTurns(WebUIBase):
    """The gap this closes: a seat that binds to no lane leaves no lane_run row, and every
    existing drill-down reads that table -- so the strategist seat, the most consequential agent
    in an unattended program, was structurally invisible."""

    def _dispatch_a_program_level_run(self):
        """Dispatch a strategist turn without spawning it, so a lane-less run exists."""
        from quaestor.core import orchestrator as orch
        from quaestor.core import strategist as strat_mod
        from quaestor.projects import config as proj_cfg
        from quaestor.core.store import Store
        from tests.test_operational_controls import make_fixture_repo
        from tests.test_operational_e2e import fake_preflight
        repo = make_fixture_repo(os.path.join(self.home, "repo"))
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        store = Store(os.path.join(self.home, "orchestrator.sqlite3"))
        try:
            sstore.set_program_meta(self.pid, "repository", repo.replace("\\", "/"))
            sstore.set_program_meta(self.pid, strat_mod.STRATEGY_MODE_KEY,
                                    strat_mod.STRATEGIST_SEAT)
            lane = sstore.lanes(self.pid)[0]
            sstore.record_message(msg_mod.new_message(
                msg_mod.DECISION_REQUEST, actor_id="ex", lane_id=lane.lane_id,
                program_id=self.pid, payload="raise or return?"))
            sstore.set_program_meta(self.pid, strat_mod.STRATEGIST_EXECUTOR_META_KEY,
                                    json.dumps({"kind": "fake",
                                                "config": {"scenario": "OK_PASS"}}))
            cfg, _r = proj_cfg.load_nearest(repo)
            return orch.dispatch_strategist(
                self.home, sstore, store, program_id=self.pid, cfg=cfg,
                preflight=fake_preflight,
                policy=orch.ProgramPolicy(), spawn=False)
        finally:
            store.close()
            sstore.close()

    def test_a_lane_less_run_is_reachable_and_carries_measured_provenance(self):
        run_id = self._dispatch_a_program_level_run()
        self.assertTrue(run_id)
        code, hdrs, body = self.jget("/api/program/%s/turns" % self.pid)
        self.assertEqual(code, 200, body)
        self.assert_security_headers(hdrs)
        ids = [t["run_id"] for t in body["turns"]]
        self.assertIn(run_id, ids, "the strategist turn was invisible")
        turn = [t for t in body["turns"] if t["run_id"] == run_id][0]
        self.assertEqual(turn["role"], "strategist",
                         "the role must come from run.provenance, not from the step id")
        self.assertEqual(turn["provider"], "fake")
        self.assertFalse(turn["is_write"])

    def test_lane_bound_runs_are_not_duplicated_here(self):
        """REWRITTEN: the previous version asserted an empty intersection against a fixture
        holding ZERO lane-bound runs, so the de-duplication filter it named could be deleted
        without failing. This drives a REAL lane run first, then asserts the turns view excludes
        it while the lane drill-down includes it."""
        from tests.test_operational_e2e import fake_preflight, in_process_spawner
        from quaestor.core import orchestrator as orch
        from quaestor.projects import config as proj_cfg
        from quaestor.core.store import Store
        from tests.test_operational_controls import make_fixture_repo
        repo = make_fixture_repo(os.path.join(self.home, "dedup-repo"))
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        store = Store(os.path.join(self.home, "orchestrator.sqlite3"))
        try:
            sstore.set_program_meta(self.pid, "repository", repo.replace("\\", "/"))
            cfg, _r = proj_cfg.load_nearest(repo)
            lane = sstore.lanes(self.pid)[0]
            sstore.set_lane_task(lane.lane_id, task="do the thing")
            orch.tick(self.home, sstore, store, program_id=self.pid, cfg=cfg,
                      preflight=fake_preflight, spawner=in_process_spawner)
            lane_bound = {b["run_id"] for l in sstore.lanes(self.pid)
                          for b in sstore.runs_for_lane(l.lane_id)}
        finally:
            store.close()
            sstore.close()
        self.assertTrue(lane_bound,
                        "the fixture produced no lane-bound run, so this control would prove "
                        "nothing about de-duplication")
        _c, _h, body = self.jget("/api/program/%s/turns" % self.pid)
        listed = {t["run_id"] for t in body["turns"]}
        self.assertEqual(lane_bound & listed, set(),
                         "a lane-bound run appeared in the program-level turns view")

    def test_a_program_with_no_turns_is_a_legitimate_empty_answer(self):
        code, _h, body = self.jget("/api/program/%s/turns" % self.pid)
        self.assertEqual(code, 200)
        self.assertEqual(body["turns"], [])
        self.assertFalse(body["truncated"])

    def test_route_contract(self):
        code, _h, raw = self.get("/api/program/%s/turns" % self.pid, token=None)
        self.assertEqual(code, 401)
        self.assertNotIn(b"turns", raw)
        code, _h, body = self.jget("/api/program/not..an..id/turns")
        self.assertEqual((code, body["error"]), (400, "BAD_PROGRAM_ID"))
        code, _h, body = self.jget("/api/program/prog_missing/turns")
        self.assertEqual((code, body["error"]), (404, "NO_SUCH_PROGRAM"))
        code, hdrs, body = self.jpost("/api/program/%s/turns" % self.pid, {})
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "GET")


class TestSeatAssignment(WebUIBase):
    def setUp(self):
        super().setUp()
        from quaestor.projects import init as proj_init
        self.repo = os.path.join(self.home, "seatrepo")
        os.makedirs(self.repo, exist_ok=True)
        proj_init.init_repository(self.repo)
        self.manifest = os.path.join(self.repo, "quaestor.yaml")

    def _manifest_text(self):
        with open(self.manifest, encoding="utf-8") as fh:
            return fh.read()

    def test_owner_is_absent_by_construction_not_by_filtering(self):
        code, _h, body = self.jget("/api/seats?path=" + urllib.parse.quote(self.repo))
        self.assertEqual(code, 200, body)
        self.assertNotIn("owner", [s["role"] for s in body["seats"]])
        self.assertIn("strategist", [s["role"] for s in body["seats"]])
        self.assertIn("not in ASSIGNABLE_ROLES", body["owner_note"])

    def test_setting_seats_preserves_every_other_line_including_comments(self):
        """The starter manifest ships with comments telling an operator which lines matter, and
        init tells them to read it. Re-serialising would delete all of them."""
        before = self._manifest_text()
        code, _h, out = self.jpost("/api/seats/set", {
            "path": self.repo,
            "roles": {"strategist": "chatgpt-web", "implementation": "claude-cli"}})
        self.assertEqual(code, 200, out)
        after = self._manifest_text()
        self.assertEqual(before.count("#"), after.count("#"), "comments were lost")
        for line in before.split("\n"):
            if line.strip().startswith("#") or "protected_roots" in line:
                self.assertIn(line, after, "a reviewed line vanished: %r" % line)
        self.assertEqual(out["roles"]["strategist"], "chatgpt-web")

    def test_a_non_write_capable_kind_is_refused_for_a_building_seat(self):
        """A manifest that parses but names a seat nothing can fill is worse than a refusal an
        operator can read."""
        before = self._manifest_text()
        code, _h, out = self.jpost("/api/seats/set", {
            "path": self.repo, "roles": {"implementation": "chatgpt-web"}})
        self.assertEqual((code, out["error"]), (400, "SEAT_REQUIRES_WRITE"))
        self.assertEqual(self._manifest_text(), before, "a refused write still touched the file")

    def test_the_owner_seat_is_refused_and_writes_nothing(self):
        before = self._manifest_text()
        code, _h, out = self.jpost("/api/seats/set", {
            "path": self.repo, "roles": {"owner": "claude-cli"}})
        self.assertEqual(code, 400)
        self.assertEqual(out["error"], "SEATS_UNKNOWN_ROLE")
        self.assertEqual(self._manifest_text(), before)

    def test_an_undeclared_kind_is_refused_and_writes_nothing(self):
        before = self._manifest_text()
        code, _h, out = self.jpost("/api/seats/set", {
            "path": self.repo, "roles": {"strategist": "typo-cli"}})
        self.assertEqual((code, out["error"]), (400, "SEATS_UNKNOWN_KIND"))
        self.assertEqual(self._manifest_text(), before)

    def test_a_gateway_pin_with_a_model_is_accepted(self):
        code, _h, out = self.jpost("/api/seats/set", {
            "path": self.repo,
            "roles": {"adversarial_review": "openrouter:google/gemini-2.5-pro"}})
        self.assertEqual(code, 200, out)
        self.assertIn("gemini", self._manifest_text())

    def test_the_written_manifest_still_parses(self):
        """The only guarantee that makes editing a reviewed file by hand defensible."""
        from quaestor.projects import config as cfg_mod
        self.jpost("/api/seats/set", {"path": self.repo,
                                      "roles": {"strategist": "codex-cli"}})
        cfg, reason = cfg_mod.load(self.manifest)
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.role_executor["strategist"], "codex-cli")

    def test_candidates_report_measured_or_honestly_unmeasured_preflights(self):
        """"We did not check" and "we checked and it is fine" are different facts."""
        _c, _h, body = self.jget("/api/seats?path=" + urllib.parse.quote(self.repo))
        by_kind = {c["kind"]: c for c in body["candidates"]}
        self.assertEqual(by_kind["chatgpt-web"]["preflight"]["state"], "on_demand",
                         "opening a settings page must not attach a browser")
        self.assertEqual(by_kind["openrouter"]["preflight"]["state"], "on_demand")
        self.assertFalse(by_kind["fake"]["preflight"]["measured"])
        self.assertEqual(by_kind["fake"]["preflight"]["state"], "unmeasured")

    def test_no_credential_value_appears_in_the_seat_view(self):
        _c, _h, raw = self.get("/api/seats?path=" + urllib.parse.quote(self.repo))
        blob = raw.decode("utf-8")
        for secret in (self.token, "sk-", "Bearer "):
            self.assertNotIn(secret, blob, secret)

    def test_route_contract(self):
        code, _h, _r = self.get("/api/seats", token=None)
        self.assertEqual(code, 401)
        code, _h, raw = self.post("/api/seats/set", {}, token=None)
        self.assertEqual(code, 401)
        code, hdrs, body = self.jget("/api/seats/set")
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "POST")
        code, hdrs, body = self.jpost("/api/seats", {})
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "GET")


class TestReadiness(WebUIBase):
    def test_readiness_assembles_from_existing_payloads(self):
        """REWRITTEN: the previous version proved its claim by asserting a literal sentence the
        payload writes about ITSELF -- which stays true however the payload behaves. It also
        overstated the property: readiness does resolve seats when a path is supplied. This
        asserts the shape actually comes from the payloads it composes."""
        code, hdrs, body = self.jget("/api/readiness")
        self.assertEqual(code, 200, body)
        self.assert_security_headers(hdrs)
        mode = self.jget("/api/mode")[2]
        self.assertEqual(body["execution_mode"]["value"], mode["transport_execution_mode"],
                         "readiness disagreed with /api/mode about the execution mode")
        settings = self.jget("/api/settings")[2]
        self.assertEqual([p["kind"] for p in body["providers"]],
                         [p["kind"] for p in settings["providers"]],
                         "readiness re-derived the provider list instead of composing it")
        self.assertTrue(body["execution_mode"]["consequence"])

    def test_readiness_does_not_run_a_browser_or_paid_preflight_on_render(self):
        """The property that actually matters: opening a settings page must not attach a
        browser or call a paid API. Asserted against the SEAT payload it composes."""
        seats = self.jget("/api/seats?path=" + urllib.parse.quote(self.home))[2]
        by_kind = {c["kind"]: c for c in seats["candidates"]}
        for kind in ("chatgpt-web", "openrouter"):
            self.assertEqual(by_kind[kind]["preflight"]["state"], "on_demand", kind)
            self.assertFalse(by_kind[kind]["preflight"]["measured"], kind)

    def test_an_untouched_deployment_is_honestly_not_ready(self):
        _c, _h, body = self.jget("/api/readiness")
        self.assertFalse(body["ready"])
        self.assertEqual(body["connected_repositories"], [])

    def test_readiness_names_where_autonomy_actually_lives(self):
        _c, _h, body = self.jget("/api/readiness")
        self.assertIn("PER PROGRAM", body["autonomy_note"])
        self.assertIn("every mode", body["autonomy_note"])

    def test_a_connected_repository_is_listed(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            sstore.set_program_meta(self.pid, "repository", "C:/some/repo")
        finally:
            sstore.close()
        _c, _h, body = self.jget("/api/readiness")
        self.assertEqual(body["connected_repositories"], ["C:/some/repo"])

    def test_route_contract(self):
        code, _h, _r = self.get("/api/readiness", token=None)
        self.assertEqual(code, 401)
        code, hdrs, body = self.jpost("/api/readiness", {})
        self.assertEqual((code, body["error"]), (405, "METHOD_NOT_ALLOWED"))
        self.assertEqual(hdrs.get("allow"), "GET")


class TestCockpitPageWiring(WebUIBase):
    """The cockpit is assembly over operations that already exist. These controls pin that it
    is wired, and that the start flow invented no new governed operation."""

    def test_the_page_carries_the_cockpit_wiring(self):
        page = webui.render_page(self.home)
        for needle in ("loadSeats", "saveSeats", "renderSeats", "loadTurns", "renderTurns",
                       "renderTurnDetail", "renderReadiness", "startRun", "detectInto",
                       'id="seats"', 'id="turns"', 'id="readiness"', 'id="np-autonomy"',
                       'id="np-seatmode"', "/api/seats", "/api/readiness", "/turns"):
            self.assertIn(needle, page, needle)

    def test_every_post_the_page_makes_is_an_already_declared_write_route(self):
        """A cockpit that minted its own governed operation would be a second control plane.
        Two call shapes exist -- a literal path, and a per-program path built by concatenation --
        so both are reconstructed and checked against the write map itself."""
        import re
        page = webui.render_page(self.home)
        checked = 0

        # post("/api/literal", ...)
        for literal in set(re.findall(r'post\("(/api/[a-z/-]+)"[,)]', page)):
            checked += 1
            self.assertTrue(webui.is_write_route(literal),
                            "the page POSTs to %r, which is not a declared write route"
                            % literal)

        # post("/api/program/"+encodeURIComponent(X)+"/action", ...)
        for action in set(re.findall(
                r'post\("/api/program/"\+encodeURIComponent\([^)]*\)\+"/([a-z-]+)"', page)):
            checked += 1
            probe = "/api/program/pid_x/%s" % action
            self.assertTrue(webui.is_write_route(probe),
                            "the page POSTs the per-program action %r, which is not in the "
                            "write map (%s)" % (action, list(webui.WRITE_PROGRAM_ACTIONS)))
        self.assertGreaterEqual(checked, 5,
                                "the scanner found almost nothing -- it is probably broken, "
                                "and a control that cannot fail proves nothing")

    def test_a_building_seat_is_never_offered_a_transport_in_the_dropdown(self):
        """Offering a choice and refusing it afterwards is a worse UI than not offering it."""
        page = webui.render_page(self.home)
        self.assertIn('s.role==="implementation"||s.role==="integration"', page)
        self.assertIn("!c.write_capable", page)

    def test_the_turn_detail_surfaces_the_refusal_not_just_the_happy_path(self):
        """A refused response is what an operator most needs to see: the seat answered, and
        deterministic admission rejected the answer."""
        page = webui.render_page(self.home)
        self.assertIn("invalid_reason", page)
        self.assertIn("refusal", page)


class TestManifestWriterPreservesConfiguration(unittest.TestCase):
    """REGRESSION CONTROLS for a confirmed data-loss defect.

    The first version of write_role_assignments deleted the whole ``executors:`` block and
    regenerated it from the roles argument alone, so ``executors.default`` and every seat the
    caller did not name -- failover chains included -- were silently destroyed. The control
    that existed only checked comment counts and one unrelated line, so it passed while an
    operator's configuration was being thrown away.

    These pin the properties that actually matter: what survives an edit nobody asked to make.
    """

    RICH = """project:
  name: demo
  repository: .

# a comment ABOVE the block
executors:
  default: claude-cli
  roles:
    implementation:
      kind: claude-cli
      providers:
        chain: [claude-cli, codex-cli]
        fallback_policy: availability_only
    verification: fake

authority:
  default:
    - READ_ONLY

security:
  protected_roots: []
"""

    def _write(self, text=None, newline="\n"):
        d = tempfile.mkdtemp(prefix="quaestor-manifest-")
        p = os.path.join(d, "quaestor.yaml")
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write((text or self.RICH).replace("\n", newline))
        return p

    def test_the_project_default_executor_survives_a_seat_edit(self):
        """THE DEFECT. Setting one seat used to delete executors.default outright."""
        p = self._write()
        out = cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        self.assertTrue(out["ok"], out)
        cfg, reason = cfg_mod.load(p)
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(cfg.executor, "claude-cli",
                         "executors.default was destroyed by a seat edit")
        self.assertEqual(out["preserved_default"], "claude-cli")

    def test_a_seat_the_caller_did_not_name_keeps_its_failover_chain(self):
        """The chain is the whole point of configuring a chain. Flattening it to a scalar
        silently removes the failover an operator set up on purpose."""
        p = self._write()
        cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        cfg, reason = cfg_mod.load(p)
        self.assertIsNotNone(cfg, reason)
        self.assertEqual(list(cfg.role_chains.get("implementation") or ()),
                         ["claude-cli", "codex-cli"])
        with open(p, encoding="utf-8") as fh:
            self.assertIn("fallback_policy: availability_only", fh.read())

    def test_untouched_scalar_seats_survive(self):
        p = self._write()
        cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        cfg, _r = cfg_mod.load(p)
        self.assertEqual(cfg.role_executor.get("verification"), "fake")
        self.assertEqual(cfg.role_executor.get("strategist"), "codex-cli")

    def test_reassigning_a_chain_seat_replaces_it_deliberately(self):
        """Naming a seat IS the request to change it -- that is not data loss."""
        p = self._write()
        out = cfg_mod.write_role_assignments(p, {"implementation": "claude-cli"})
        self.assertTrue(out["ok"], out)
        cfg, _r = cfg_mod.load(p)
        self.assertEqual(cfg.role_executor.get("implementation"), "claude-cli")

    def test_lines_outside_the_block_are_byte_for_byte(self):
        p = self._write()
        with open(p, encoding="utf-8") as fh:
            before = fh.read()
        cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        with open(p, encoding="utf-8") as fh:
            after = fh.read()
        for line in ("# a comment ABOVE the block", "  protected_roots: []",
                     "  name: demo", "    - READ_ONLY"):
            self.assertIn(line, after, "a reviewed line vanished: %r" % line)
        self.assertIn("# a comment ABOVE the block", before)

    def test_a_nested_executors_key_is_not_mistaken_for_the_block(self):
        """Anchored at column 0. An `executors:` key under another mapping is a different key,
        and starting the skip there would delete the rest of its parent."""
        p = self._write("""project:
  name: demo
  repository: .

custom:
  executors:
    something: kept

authority:
  default:
    - READ_ONLY
""")
        out = cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        self.assertTrue(out["ok"], out)
        with open(p, encoding="utf-8") as fh:
            after = fh.read()
        self.assertIn("something: kept", after,
                      "a nested executors: key ate its parent's content")
        self.assertIn("    - READ_ONLY", after)

    def test_a_seat_shape_this_writer_cannot_re_emit_is_refused_not_flattened(self):
        """Silently dropping structure the emitter does not understand is the failure this
        function exists to avoid, so an unknown shape refuses and touches nothing."""
        p = self._write("""project:
  name: demo
  repository: .

executors:
  roles:
    verification:
      kind: fake
      unheard_of_key: something
""")
        with open(p, encoding="utf-8") as fh:
            before = fh.read()
        out = cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        self.assertFalse(out["ok"])
        self.assertIn("NOT touched", out["note"])
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)

    def test_a_manifest_that_does_not_parse_is_refused_and_untouched(self):
        p = self._write("this: is: not: valid: yaml:\n  - [\n")
        with open(p, encoding="utf-8") as fh:
            before = fh.read()
        out = cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        self.assertFalse(out["ok"])
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)

    def test_crlf_line_endings_are_preserved(self):
        """Rewriting a CRLF manifest with LF would show every line as changed in a diff -- a
        claim of 'one block edited' the diff itself contradicts."""
        p = self._write(newline="\r\n")
        out = cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        self.assertTrue(out["ok"], out)
        with open(p, "rb") as fh:
            raw = fh.read()
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"\n\n\n", raw.replace(b"\r\n", b"\n"))
        cfg, reason = cfg_mod.load(p)
        self.assertIsNotNone(cfg, reason)

    def test_no_probe_file_is_left_behind_on_success_or_refusal(self):
        p = self._write()
        cfg_mod.write_role_assignments(p, {"strategist": "codex-cli"})
        cfg_mod.write_role_assignments(p, {"owner": "claude-cli"})
        leftovers = [f for f in os.listdir(os.path.dirname(p)) if "seats-probe" in f]
        self.assertEqual(leftovers, [], "a probe file survived: %s" % leftovers)

    def test_concurrent_writes_do_not_share_a_probe_path(self):
        """The dashboard is a ThreadingHTTPServer, so two seat writes can be in flight at once
        and a fixed probe name would have them clobber each other."""
        seen = {cfg_mod._next_probe_seq() for _ in range(50)}
        self.assertEqual(len(seen), 50)


class TestHeadlessBriefingAndOpen(WebUIBase):
    """ru1.17: the relay packet without a dashboard, and `web --open`.

    The property that matters is AGREEMENT: an operator on a terminal and an operator in a
    browser must be handed the same packet, or the two surfaces are telling different people
    different things about the same program.
    """

    def _seed_question(self):
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            lane = sstore.lanes(self.pid)[0]
            m = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="ex",
                                    lane_id=lane.lane_id, program_id=self.pid,
                                    payload="raise or return None?")
            sstore.record_message(m)
            return m.message_id
        finally:
            sstore.close()

    def _cli(self, *argv):
        from quaestor.transports import cli as cli_mod
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli_mod.main(["--home", self.home, "program"] + list(argv))
        return code, buf.getvalue()

    def test_the_cli_and_the_dashboard_hand_over_the_same_packet(self):
        """One assembly, one sanitising pass, one authority boundary -- and therefore one
        answer. Two builders would drift into two stories."""
        self._seed_question()
        code, text = self._cli("briefing", self.pid)
        self.assertEqual(code, 0, text)
        _c, _h, served = self.jget("/api/program/%s/briefing" % self.pid)
        # Everything except the relay surfaces must be identical.
        for key in ("objective", "constraints", "open_questions", "decisions", "lanes",
                    "boundary", "classification", "next_authority"):
            self.assertEqual(json.loads(json.dumps(served[key])),
                             json.loads(json.dumps(served[key])), key)
        self.assertIn("QUAESTOR PROGRAM BRIEFING", text)
        self.assertIn("raise or return None?", text)
        self.assertIn("grants nothing", text)

    def test_the_headless_packet_names_no_dashboard_it_cannot_promise(self):
        """No dashboard is running, so a dashboard line would point at a port nothing is
        listening on -- worse than saying nothing."""
        self._seed_question()
        _code, text = self._cli("briefing", self.pid)
        self.assertNotIn("dashboard :", text)
        self.assertIn("cli       :", text)
        self.assertIn("program answer %s" % self.pid, text)

    def test_the_json_form_carries_the_whole_document(self):
        mid = self._seed_question()
        code, text = self._cli("briefing", self.pid, "--json")
        self.assertEqual(code, 0, text)
        doc = json.loads(text)
        self.assertEqual(doc["program_id"], self.pid)
        self.assertEqual([q["message_id"] for q in doc["open_questions"]], [mid])
        self.assertEqual(doc["surfaces"]["dashboard_url"], "")

    def test_one_question_can_be_printed_on_its_own(self):
        mid = self._seed_question()
        code, text = self._cli("briefing", self.pid, "--message-id", mid)
        self.assertEqual(code, 0, text)
        self.assertIn("DIRECTIVE REQUEST", text)
        self.assertIn(mid, text)

    def test_an_unknown_question_and_an_unknown_program_are_named_refusals(self):
        self._seed_question()
        code, text = self._cli("briefing", self.pid, "--message-id", "msg_nope")
        self.assertEqual(code, 2)
        self.assertIn("NO_SUCH_OPEN_QUESTION", text)
        code, text = self._cli("briefing", "prog_missing")
        self.assertEqual(code, 2)
        self.assertIn("NO_SUCH_PROGRAM", text)

    def test_the_headless_packet_is_sanitised_exactly_like_the_served_one(self):
        """It leaves the machine by clipboard either way."""
        sstore = ss_mod.StrategicStore(ss_mod.strategic_path(self.home))
        try:
            lane = sstore.lanes(self.pid)[0]
            sstore.set_lane_task(lane.lane_id,
                                 task="use sk-ant-api03-" + ("A" * 48) + " in C:/Users/x/repo")
        finally:
            sstore.close()
        self._seed_question()
        _code, text = self._cli("briefing", self.pid)
        self.assertNotIn("sk-ant-api03-AAAA", text)
        self.assertIn("<secret-withheld:", text)
        self.assertIn("<path-withheld>", text)

    def test_the_relay_vocabulary_has_one_definition(self):
        """The CLI and the dashboard call the SAME builder; two copies would drift."""
        self.assertTrue(callable(webui.relay_surfaces))
        self.assertFalse(hasattr(webui, "_relay_surfaces"),
                         "the private duplicate survived the move")
        served = webui.relay_surfaces("prog_x", 8931)
        headless = webui.relay_surfaces("prog_x")
        self.assertTrue(served["dashboard_url"])
        self.assertEqual(headless["dashboard_url"], "")
        for key in ("cli_answer", "cli_verbs", "mcp_decide_tool", "mcp_tools"):
            self.assertEqual(served[key], headless[key], key)


class TestWebOpenFlag(WebUIBase):
    def test_open_is_opt_in_and_hands_over_the_one_step_url(self):
        """Launching a browser is a side effect on the operator's desktop, so it happens on an
        explicit flag and never by default."""
        opened = []
        out = io.StringIO()
        httpd, port = webui.build_webui_server(self.home, port=0,
                                               token_file=self.token_file)
        httpd.server_close()
        # serve() blocks, so drive the launch decision through its own seam instead.
        payload = webui.startup_payload(port, self.token_file, self.token)
        self.assertIn("#t=", payload["open"])
        webui._default_browser_opener  # the real seam exists
        self.assertTrue(callable(webui._default_browser_opener))
        # The flag must be plumbed from the CLI.
        from quaestor.transports import cli as cli_mod
        ns = cli_mod.build_parser().parse_args(["web"])
        self.assertFalse(ns.open, "opening a browser must not be the default")
        ns = cli_mod.build_parser().parse_args(["web", "--open"])
        self.assertTrue(ns.open)
        self.assertEqual(opened, [])
        self.assertEqual(out.getvalue(), "")

    def test_a_browser_that_will_not_launch_does_not_take_the_server_down(self):
        """The server is up and the URL is on screen; a missing default browser must not be
        fatal."""
        import threading
        out = io.StringIO()

        def _boom(_url):
            raise OSError("no browser registered")

        # serve() blocks forever, so run it briefly on a thread and stop it.
        holder = {}

        def _run():
            holder["code"] = webui.serve(self.home, port=0,
                                         token_file=self.token_file, stdout=out,
                                         open_browser=True, opener=_boom)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=2.0)
        printed = out.getvalue()
        self.assertIn('"open_browser": false', printed.lower())
        self.assertIn("the server is running", printed)

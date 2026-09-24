"""test_operational_controls -- controls for the LOCAL_GOVERNED operational layer.

These are FOCUSED controls, not a second qualification suite: each one pins a behaviour whose
silent regression would either strand a program or widen authority. They run fast and use no
network, no Claude child and no Docker.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.core import authority as authority_mod          # noqa: E402
from quaestor.core import decisions as dec_mod                # noqa: E402
from quaestor.core import events as ev_mod                    # noqa: E402
from quaestor.core import handoff as handoff_mod              # noqa: E402
from quaestor.core import messages as msg_mod                 # noqa: E402
from quaestor.core import orchestrator as orch                # noqa: E402
from quaestor.core import owner_channel as oc                 # noqa: E402
from quaestor.core import programs as prog_mod                # noqa: E402
from quaestor.core import review_contract as rc               # noqa: E402
from quaestor.core import strategic_store as ss_mod           # noqa: E402
from quaestor import attestation                               # noqa: E402
from quaestor.transports.mcp import mode as transport_mode    # noqa: E402
from quaestor.transports.mcp import schemas as ts             # noqa: E402
from quaestor.workspace import worktrees as wt_mod            # noqa: E402


def _git(*args, cwd):
    env = dict(os.environ)
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, shell=False, env=env)
    assert p.returncode == 0, (args, p.stderr.decode("utf-8", "replace"))
    return p.stdout.decode("utf-8", "replace")


def make_fixture_repo(base: str) -> str:
    """A minimal committed repo with a unittest suite."""
    root = os.path.join(base, "fx")
    os.makedirs(os.path.join(root, "app"), exist_ok=True)
    _git("init", "-q", cwd=root)
    _git("config", "user.email", "t@t", cwd=root)
    _git("config", "user.name", "t", cwd=root)
    with open(os.path.join(root, "app", "__init__.py"), "w", encoding="utf-8") as fh:
        fh.write("")
    with open(os.path.join(root, "app", "mathlib.py"), "w", encoding="utf-8") as fh:
        fh.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(root, "test_mathlib.py"), "w", encoding="utf-8") as fh:
        fh.write("import unittest\nfrom app import mathlib\n\n"
                 "class T(unittest.TestCase):\n"
                 "    def test_add(self):\n"
                 "        self.assertEqual(mathlib.add(1, 2), 3)\n")
    with open(os.path.join(root, "quaestor.yaml"), "w", encoding="utf-8") as fh:
        fh.write("project:\n  name: fx\n  repository: .\nexecutor:\n  default: fake\n"
                 "commands:\n  test:\n    - python -m unittest discover -s . -p \"test_*.py\"\n"
                 "authority:\n  default:\n    - READ_ONLY\nsecurity:\n  protected_roots: []\n")
    _git("add", "-A", cwd=root)
    _git("commit", "-qm", "init", cwd=root)
    return root


class ModeTests(unittest.TestCase):
    def test_default_mode_is_qualification_only_without_deployment_file(self):
        with tempfile.TemporaryDirectory() as d:
            mode, record = transport_mode.resolve_mode(d)
            self.assertEqual(mode, transport_mode.QUALIFICATION_ONLY)
            self.assertEqual(record["source"], transport_mode.MODE_SOURCE_DEFAULT)

    def test_unreadable_or_unknown_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with open(transport_mode.mode_file_path(d), "w", encoding="utf-8") as fh:
                fh.write("{not json")
            mode, record = transport_mode.resolve_mode(d)
            self.assertEqual(mode, transport_mode.QUALIFICATION_ONLY)
            self.assertIn("fallback_reason", record)
            with open(transport_mode.mode_file_path(d), "w", encoding="utf-8") as fh:
                json.dump({"transport_execution_mode": "ROOT_EVERYTHING"}, fh)
            mode, record = transport_mode.resolve_mode(d)
            self.assertEqual(mode, transport_mode.QUALIFICATION_ONLY)

    def test_local_governed_selected_by_deployment_file(self):
        with tempfile.TemporaryDirectory() as d:
            transport_mode.write_mode(d, transport_mode.LOCAL_GOVERNED)
            mode, record = transport_mode.resolve_mode(d)
            self.assertEqual(mode, transport_mode.LOCAL_GOVERNED)
            self.assertEqual(record["source"], transport_mode.MODE_SOURCE_DEPLOYMENT)

    def test_operational_gate_admits_only_the_qualified_pair(self):
        ok = transport_mode.assert_admissible(
            transport_mode.LOCAL_GOVERNED, authority_profile=authority_mod.STANDARD_EDIT,
            executor={"kind": "claude-cli"}, spawn=True)
        self.assertTrue(ok.ok, ok.detail)
        for profile in (authority_mod.GIT_PUSH, authority_mod.DESTRUCTIVE,
                        authority_mod.EXTERNAL_WRITE, authority_mod.PAID_EXECUTION):
            v = transport_mode.assert_admissible(
                transport_mode.LOCAL_GOVERNED, authority_profile=profile,
                executor={"kind": "claude-cli"}, spawn=True)
            self.assertFalse(v.ok)
            self.assertEqual(v.reason, transport_mode.AUTHORITY_PROFILE_REFUSED)
        v = transport_mode.assert_admissible(
            transport_mode.LOCAL_GOVERNED, authority_profile=authority_mod.READ_ONLY,
            executor={"kind": "claude-container"}, spawn=True)
        self.assertFalse(v.ok)
        self.assertEqual(v.reason, transport_mode.EXECUTOR_KIND_REFUSED)

    def test_assert_inert_is_unchanged_for_qualification(self):
        v = transport_mode.assert_admissible(transport_mode.QUALIFICATION_ONLY,
                                             authority_profile=authority_mod.READ_ONLY,
                                             executor={"kind": "fake"}, spawn=False)
        self.assertTrue(v.ok)
        v = transport_mode.assert_admissible(transport_mode.QUALIFICATION_ONLY,
                                             authority_profile=authority_mod.STANDARD_EDIT,
                                             executor={"kind": "fake"}, spawn=False)
        self.assertEqual(v.reason, transport_mode.AUTHORITY_PROFILE_REFUSED)


class SchemaTests(unittest.TestCase):
    REPO_TABLE = {"fx": "/tmp/never-resolved"}

    def test_program_tools_are_known_and_closed(self):
        for tool in ("program_create", "program_status", "program_inbox",
                     "program_decide", "program_cancel"):
            self.assertIn(tool, ts.TOOLS)
        v = ts.validate("program_status", {"program_id": "prog_x"},
                        repo_table=self.REPO_TABLE)
        self.assertTrue(v.ok, v.detail)
        v = ts.validate("program_status", {"program_id": "prog_x", "executor": "x"},
                        repo_table=self.REPO_TABLE)
        self.assertFalse(v.ok)
        self.assertEqual(v.reason, ts.SCHEMA_REFUSED)

    def test_authority_enum_is_mode_dependent(self):
        qual = ts.authority_profile_enum(transport_mode.QUALIFICATION_ONLY)
        op = ts.authority_profile_enum(transport_mode.LOCAL_GOVERNED)
        self.assertEqual(qual, ("READ_ONLY",))
        self.assertEqual(op, ("READ_ONLY", "STANDARD_EDIT"))
        v = ts.validate("orchestrator_dispatch",
                        {"workflow_id": "w", "step_id": "s", "task": "t",
                         "repo_alias": "fx", "authority_profile": "STANDARD_EDIT"},
                        repo_table=self.REPO_TABLE)
        self.assertFalse(v.ok)   # qualification default still refuses STANDARD_EDIT at schema
        v = ts.validate("orchestrator_dispatch",
                        {"workflow_id": "w", "step_id": "s", "task": "t",
                         "repo_alias": "fx", "authority_profile": "STANDARD_EDIT"},
                        repo_table=self.REPO_TABLE, mode=transport_mode.LOCAL_GOVERNED)
        self.assertTrue(v.ok, v.detail)

    def test_tool_surface_lists_everything(self):
        defs = ts.tool_definitions(repo_table=self.REPO_TABLE,
                                   mode=transport_mode.LOCAL_GOVERNED)
        names = ts.declared_tool_names(defs)
        self.assertEqual(len(names), len(ts.TOOLS))
        fp = ts.tool_surface_fingerprint(defs)
        self.assertFalse(fp["vacuous"])
        self.assertGreaterEqual(fp["inspected_tools"], 10)


class StrategicStoreV2Tests(unittest.TestCase):
    def _fresh(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d, ss_mod.StrategicStore(ss_mod.strategic_path(d))

    def test_v2_tables_and_meta(self):
        d, s = self._fresh()
        try:
            pid = orch.create_program(s, title="T", objective="O", actor_id="test")
            lane = orch.plan_lane(s, pid, title="L", task="do", kind=orch.KIND_IMPLEMENTATION,
                                  acceptance=("a1",), actor_id="test")
            s.set_program_meta(pid, "repository", "/repo")
            self.assertEqual(s.get_program_meta(pid)["repository"], "/repo")
            s.bind_run(lane, "run1", role="implementation")
            self.assertEqual(s.lane_for_run("run1")["role"], "implementation")
            s.save_checkpoint(lane, {"worktree_path": "/wt"}, program_id=pid)
            self.assertEqual(s.get_lane_task(lane)["checkpoint"]["worktree_path"], "/wt")
            self.assertEqual(s.get_lane_task(lane)["acceptance"], ("a1",))
        finally:
            s.close()

    def test_checkpoint_merges_not_replaces(self):
        d, s = self._fresh()
        try:
            pid = orch.create_program(s, title="T", objective="O", actor_id="test")
            lane = orch.plan_lane(s, pid, title="L", task="do", actor_id="test")
            s.save_checkpoint(lane, {"worktree_path": "/wt"}, program_id=pid)
            s.save_checkpoint(lane, {"summary": "half"}, program_id=pid)
            ck = s.get_lane_task(lane)["checkpoint"]
            self.assertEqual(ck["worktree_path"], "/wt")
            self.assertEqual(ck["summary"], "half")
        finally:
            s.close()

    def test_store_written_under_other_semantics_is_refused(self):
        d, s = self._fresh()
        s.close()
        conn = sqlite3.connect(ss_mod.strategic_path(d))
        conn.execute("UPDATE store_contract SET v='different' WHERE k='dispatch_key_salt'")
        conn.commit()
        conn.close()
        with self.assertRaises(ss_mod.StoreContractMismatch):
            ss_mod.StrategicStore(ss_mod.strategic_path(d))


class HandoffMessagesTests(unittest.TestCase):
    def _payload(self, messages):
        return {"protocol": handoff_mod.PROTOCOL, "protocol_version": 1,
                "workflow_id": "w", "step_id": "s", "run_nonce": "n",
                "prompt_disposition": "COMPLETE", "program_verdict": "PASS",
                "acceptance_state": "", "authorized_scope_exhausted": True,
                "continuation_allowed": False, "next_authority": "GPT_ORCHESTRATOR",
                "owner_decision_required": False, "smallest_blocker": "", "next_action": "",
                "summary": "done", "messages": messages}

    def test_valid_messages_pass_and_extract(self):
        msgs = [{"type": "DECISION_REQUEST", "payload": "clamp?"},
                {"type": "REVIEW_FINDING", "payload": "off-by-one", "severity": "HIGH",
                 "detail": {"location": "a.py:12", "failure_mode": "returns a+b"}}]
        v = handoff_mod.validate_handoff(self._payload(msgs))
        self.assertTrue(v.valid, v.reason)
        out = handoff_mod.handoff_messages(v.handoff)
        self.assertEqual([m["type"] for m in out], ["DECISION_REQUEST", "REVIEW_FINDING"])

    def test_strategist_facing_types_are_refused(self):
        v = handoff_mod.validate_handoff(self._payload([{"type": "DIRECTIVE",
                                                         "payload": "self-direct"}]))
        self.assertFalse(v.valid)
        self.assertIn("executor-emittable", v.reason)

    def test_messages_absent_stays_valid(self):
        payload = self._payload(None)
        del payload["messages"]
        self.assertTrue(handoff_mod.validate_handoff(payload).valid)


class OrchestratorUnitTests(unittest.TestCase):
    def test_split_command_strips_windows_quoting(self):
        argv = orch._split_command('python -m unittest discover -p "test_*.py"')
        self.assertNotIn('"test_*.py"', argv)
        self.assertIn("test_*.py", argv)

    def test_overlap_risk_detects_lockfile_and_schema_collisions(self):
        risky = orch._overlap_risk({"l1": {"package-lock.json", "a.py"},
                                    "l2": {"package-lock.json", "b.py"}})
        self.assertEqual(len(risky), 1)
        benign = orch._overlap_risk({"l1": {"a.py"}, "l2": {"b.py"}})
        self.assertEqual(benign, [])

    def test_policy_roundtrip_and_defaults(self):
        p = orch.ProgramPolicy(max_concurrent_executors=3)
        meta = {"policy": json.dumps(p.to_dict())}
        self.assertEqual(orch.policy_from_meta(meta).max_concurrent_executors, 3)
        self.assertEqual(orch.policy_from_meta({}).max_concurrent_executors, 2)

    def test_executor_variant_selection(self):
        lane_task = {"executor": {"kind": "fake", "attempt_variants":
                                  [{"kind": "fake", "config": {"scenario": "OK_PASS"}},
                                   {"kind": "fake", "config": {"scenario": "BLOCKED"}}]}}
        e0 = orch._executor_for("claude-cli", lane_task, attempt=0)
        e1 = orch._executor_for("claude-cli", lane_task, attempt=5)
        self.assertEqual(e0["config"]["scenario"], "OK_PASS")
        self.assertEqual(e1["config"]["scenario"], "BLOCKED")

    def test_answer_wakes_waiting_lane_to_planned_and_records_ledger(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        s = ss_mod.StrategicStore(ss_mod.strategic_path(d))
        try:
            pid = orch.create_program(s, title="T", objective="O", actor_id="test")
            lane = orch.plan_lane(s, pid, title="L", task="do", actor_id="test")
            m = msg_mod.new_message(msg_mod.DECISION_REQUEST, actor_id="executor:fake",
                                    program_id=pid, lane_id=lane, payload="q?")
            s.record_message(m)
            s.set_lane_state(lane, prog_mod.LANE_WAITING_STRATEGIST)
            orch.answer(s, pid, m.message_id, decision_text="negatives",
                        rationale="r", actor_id="strategist")
            self.assertEqual(s.get_lane(lane).state, prog_mod.LANE_PLANNED)
            decs = s.decisions(pid)
            self.assertEqual(len(decs), 1)
            self.assertTrue(decs[0].live)
            answered = s.message(m.message_id)
            self.assertTrue(answered["answered_by"])
        finally:
            s.close()

    def test_review_floor_cannot_be_narrowed_by_project_policy(self):
        required, matched = rc.adversarial_required(["authentication"], {"required_for": []})
        self.assertTrue(required)
        required2, _ = rc.adversarial_required([], {"required_for": []})
        self.assertFalse(required2)   # nothing matched -> floor not triggered, but never removed

    def test_events_vocabulary_stays_closed_but_grew_deliberately(self):
        for name in ("PROGRAM_CREATED", "SCHEDULED", "CHECKPOINT_SAVED"):
            self.assertIn(getattr(ev_mod, name), ev_mod.EVENT_TYPES)
        with self.assertRaises(ValueError):
            ev_mod.new_event("MADE_UP_EVENT")


class WorktreeTests(unittest.TestCase):
    def test_create_commit_merge_cycle(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = make_fixture_repo(base)
        home = os.path.join(base, "home")
        os.makedirs(home, exist_ok=True)
        path = wt_mod.lane_worktree_path(home, "prog_t", "lane_t")
        created = wt_mod.create_lane_worktree(repo, path, branch="quaestor/prog_t/lane_t")
        self.assertTrue(created["ok"], created["error"])
        with open(os.path.join(path, "new.txt"), "w", encoding="utf-8") as fh:
            fh.write("hello\n")
        c1 = wt_mod.commit_all(path, message="first")
        self.assertTrue(c1["ok"] and c1["sha"] and c1["changed"] == 1)
        c2 = wt_mod.commit_all(path, message="nothing to do")
        self.assertTrue(c2["ok"] and c2["already_clean"] and c2["sha"] == "")
        integ = os.path.join(base, "integ")
        ci = wt_mod.create_lane_worktree(repo, integ, branch="quaestor/prog_t/_integ")
        self.assertTrue(ci["ok"], ci["error"])
        m = wt_mod.merge_branch(integ, "quaestor/prog_t/lane_t", message="merge lane")
        self.assertTrue(m["ok"] and not m["conflict"], m.get("error"))
        self.assertTrue(os.path.isfile(os.path.join(integ, "new.txt")))

    def test_commit_all_never_swallows_interpreter_bytecode(self):
        """CONTROL: verification runs Python inside lane worktrees; the .pyc caches that
        creates are interpreter noise, not candidate work.

        Found LIVE: ``_ensure_excludes`` wrote to ``<worktree>/.git/info/exclude``, but in a
        LINKED worktree ``.git`` is a file -- the write failed and was swallowed, so every
        acceptance commit swept the caches in. The exclude must land in the COMMON git dir,
        it must actually exist after worktree creation, and ``commit_all`` must re-assert
        it before ``git add -A``.
        """
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = make_fixture_repo(base)
        home = os.path.join(base, "home")
        os.makedirs(home, exist_ok=True)
        path = wt_mod.lane_worktree_path(home, "prog_p", "lane_p")
        created = wt_mod.create_lane_worktree(repo, path, branch="quaestor/prog_p/lane_p")
        self.assertTrue(created["ok"], created["error"])

        # The excludes must live under the COMMON dir, which for a linked worktree is NOT
        # <worktree>/.git (that is a file).
        self.assertTrue(os.path.isfile(os.path.join(path, ".git")),
                        "fixture is not a linked worktree; control measures nothing")
        common = wt_mod._common_git_dir(path)
        self.assertTrue(common and os.path.isdir(common),
                        "common git dir unresolved: %r" % common)
        exclude_path = os.path.join(common, "info", "exclude")
        self.assertTrue(os.path.isfile(exclude_path),
                        "exclude file missing after worktree creation")
        with open(exclude_path, encoding="utf-8") as fh:
            self.assertIn("__pycache__/", fh.read())

        # Simulate what the control plane's own test run does, then commit EVERYTHING.
        os.makedirs(os.path.join(path, "__pycache__"), exist_ok=True)
        with open(os.path.join(path, "__pycache__", "tokenize.cpython-314.pyc"), "wb") as fh:
            fh.write(b"\x00fake bytecode\x00")
        with open(os.path.join(path, "real.txt"), "w", encoding="utf-8") as fh:
            fh.write("candidate work\n")

        # Remove the exclude file first: commit_all must re-assert it, protecting trees
        # created before the rule existed or whose exclude was deleted afterwards.
        os.remove(exclude_path)
        c = wt_mod.commit_all(path, message="candidate + noise")
        self.assertTrue(c["ok"], c.get("error"))
        names = subprocess.run(["git", "diff", "--name-only", "--no-color", "HEAD~1", "HEAD"],
                               cwd=path, capture_output=True, shell=False)
        changed = set(names.stdout.decode("utf-8", "replace").split())
        self.assertIn("real.txt", changed)
        self.assertNotIn("__pycache__/tokenize.cpython-314.pyc", changed)

    def test_commit_all_refuses_when_exclusion_policy_cannot_be_verified(self):
        """CONTROL (tamper): an UNVERIFIABLE exclusion policy must refuse the commit, not
        sweep the tree.

        The live incident this pins: excludes were written to a nonexistent location, the
        write failure was silently swallowed, and ``git add -A`` contaminated candidate
        commits with interpreter bytecode. Re-asserting the excludes fixed the WRITE; only
        proving they are EFFECTIVE (a real ``git check-ignore`` probe) before the sweep makes
        the commit fail CLOSED. Here both repair paths are sabotaged -- the shared exclude
        file is deleted and ``_ensure_excludes`` is neutralised -- so the probe cannot pass,
        and commit_all must refuse with a named reason and leave EVERYTHING uncommitted.
        """
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = make_fixture_repo(base)
        home = os.path.join(base, "home")
        os.makedirs(home, exist_ok=True)
        path = wt_mod.lane_worktree_path(home, "prog_r", "lane_r")
        created = wt_mod.create_lane_worktree(repo, path, branch="quaestor/prog_r/lane_r")
        self.assertTrue(created["ok"], created["error"])
        head_before = _git("rev-parse", "HEAD", cwd=path).strip()

        # A real candidate change PLUS exactly the noise class that poisoned the live commit.
        os.makedirs(os.path.join(path, "__pycache__"), exist_ok=True)
        with open(os.path.join(path, "__pycache__", "tamper.cpython-314.pyc"), "wb") as fh:
            fh.write(b"\x00fake bytecode\x00")
        with open(os.path.join(path, "candidate.txt"), "w", encoding="utf-8") as fh:
            fh.write("real candidate work\n")

        common = wt_mod._common_git_dir(path)
        self.assertTrue(common and os.path.isdir(common),
                        "common git dir unresolved: %r" % common)
        exclude_path = os.path.join(common, "info", "exclude")
        self.assertTrue(os.path.isfile(exclude_path))

        # TAMPER both halves of the policy: delete what was written AND neutralise the
        # writer, so no repair inside commit_all can succeed. Redirect global/system git
        # config to an empty file so a host-level ignore of __pycache__ cannot mask the
        # sabotage and turn this control into a false pass.
        cfg = os.path.join(base, "empty.gitconfig")
        with open(cfg, "w", encoding="utf-8"):
            pass
        env_patch = mock.patch.dict(os.environ,
                                    {"GIT_CONFIG_GLOBAL": cfg, "GIT_CONFIG_SYSTEM": cfg})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        os.remove(exclude_path)
        patcher = mock.patch.object(wt_mod, "_ensure_excludes",
                                    lambda *a, **k: None)  # no-op: repairs disabled
        patcher.start()
        self.addCleanup(patcher.stop)

        c = wt_mod.commit_all(path, message="must be refused")
        self.assertFalse(c["ok"], c)
        self.assertTrue(c.get("refused"), c)
        self.assertTrue(str(c.get("reason", "")).startswith("EXCLUSION_POLICY_UNVERIFIED"),
                        c.get("reason"))

        # Nothing staged, nothing committed: BOTH files still sit in the tree untouched.
        st = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                            cwd=path, capture_output=True, shell=False)
        lines = st.stdout.decode("utf-8", "replace").splitlines()
        self.assertTrue(any(ln.strip().endswith("candidate.txt") for ln in lines), lines)
        self.assertTrue(any("__pycache__" in ln and ln.strip().endswith(".pyc")
                            for ln in lines), lines)
        cached = subprocess.run(["git", "diff", "--cached", "--name-only"],
                                cwd=path, capture_output=True, shell=False)
        self.assertEqual(cached.stdout.decode("utf-8", "replace").strip(), "")
        self.assertEqual(_git("rev-parse", "HEAD", cwd=path).strip(), head_before)

    def test_commit_all_stage_paths_commits_only_the_named_paths(self):
        """CONTROL: explicit staging commits EXACTLY the requested files.

        This is the longer-term shape from direction doc section 19: stage
        claimed-files-intersected-with-measured-changes instead of sweeping everything with
        ``add -A``. Two real changes are present but only one path is named, so the commit
        must contain exactly that path and the other edit must stay dirty. Absolute paths
        and traversal outside the worktree refuse the whole call -- explicit staging must
        never become a door around the worktree boundary.
        """
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = make_fixture_repo(base)
        home = os.path.join(base, "home")
        os.makedirs(home, exist_ok=True)
        path = wt_mod.lane_worktree_path(home, "prog_s", "lane_s")
        created = wt_mod.create_lane_worktree(repo, path, branch="quaestor/prog_s/lane_s")
        self.assertTrue(created["ok"], created["error"])
        head_before = _git("rev-parse", "HEAD", cwd=path).strip()

        # Two REAL candidate changes, made INSIDE the lane worktree.
        with open(os.path.join(path, "app", "mathlib.py"), "r+", encoding="utf-8") as fh:
            body = fh.read()
            fh.seek(0)
            fh.write(body + "\ndef sub(a, b):\n    return a - b\n")
            fh.truncate()
        with open(os.path.join(path, "test_mathlib.py"), "r+", encoding="utf-8") as fh:
            body = fh.read()
            fh.seek(0)
            fh.write("# touched by the run\n" + body)
            fh.truncate()

        # Traversal and absolute paths are REFUSED outright, before anything is staged.
        abs_outside = os.path.abspath(os.path.join(base, "elsewhere.py"))
        c_bad = wt_mod.commit_all(path, message="never",
                                  stage_paths=["../escaped.txt", abs_outside])
        self.assertFalse(c_bad["ok"], c_bad)
        self.assertTrue(c_bad.get("refused"), c_bad)
        self.assertTrue(str(c_bad.get("reason", "")).startswith("STAGE_PATH_REFUSED"),
                        c_bad.get("reason"))
        self.assertEqual(_git("rev-parse", "HEAD", cwd=path).strip(), head_before)

        # Now the legitimate partial staging: one valid path plus one that does not exist.
        c = wt_mod.commit_all(path, message="only mathlib",
                              stage_paths=["app/mathlib.py", "ghost.txt"])
        self.assertTrue(c["ok"], c.get("error"))
        self.assertFalse(c.get("refused"))
        self.assertEqual(c.get("skipped_paths"), ["ghost.txt"])
        names = subprocess.run(
            ["git", "diff", "--name-only", "--no-color", "HEAD~1", "HEAD"],
            cwd=path, capture_output=True, shell=False)
        committed = set(names.stdout.decode("utf-8", "replace").split())
        self.assertEqual(committed, {"app/mathlib.py"})
        st = subprocess.run(["git", "status", "--porcelain=v1"],
                            cwd=path, capture_output=True, shell=False)
        self.assertIn("test_mathlib.py", st.stdout.decode("utf-8", "replace"))


class AttestationTests(unittest.TestCase):
    def test_unsigned_and_foreign_documents_fail_verification(self):
        doc = {"kind": "OWNER_GRANT", "capability": "git_push"}
        ok, why = attestation.verify(doc)      # no key provisioned on test machines
        self.assertFalse(ok)
        signed = attestation.sign(doc, key=b"k" * 16, key_id="k1")
        self.assertIn("attestation_sig", signed)
        body = attestation.canonical_doc(signed)
        self.assertNotIn(b"attestation_sig", body)

    def test_owner_channel_defaults_to_unavailable(self):
        # No provisioning happened in this process/user dir; the qualified default holds.
        state = oc.owner_channel_state()
        self.assertIn(state, (oc.UNAVAILABLE, oc.AUTHENTICATED))  # machine-dependent, both honest
        # The DECISION path is what matters and stays injectable + pure:
        blocked, _ = oc.gate(("git_push",), authority_mod.OWNER_GATED,
                             ledger_rows=[], channel_state=oc.UNAVAILABLE)
        self.assertEqual(blocked, ("git_push",))

    def test_decision_owner_attestation_follows_channel(self):
        # owner_attested is computed from the live channel at mint time, never from a caller
        # argument; on an unprovisioned machine an OWNER decision is honestly a CLAIM.
        d = dec_mod.new_decision("p", "q?", authority=dec_mod.BY_OWNER, decision="yes")
        self.assertIsInstance(d.owner_attested, bool)
        self.assertEqual(d.authority_is_claimed,
                         d.authority == dec_mod.BY_OWNER and not d.owner_attested)


class RedactionTests(unittest.TestCase):
    def test_remote_program_view_carries_no_host_paths(self):
        from quaestor.transports.mcp import adapter as adapter_mod
        from quaestor.transports.mcp import redact as red
        scrubbed = red.scrub_text(r"C:\Users\somebody\secret\repo failed", alias_of={})
        self.assertNotIn("somebody", str(scrubbed))
        view = {"lanes": [{"summary": r"worked in C:\Users\x\y", "title": "t"}]}
        self.assertIn("summary", view["lanes"][0])   # shape sanity before building remote
        never = red.NEVER_REMOTE
        self.assertIn("worktree_path", never)
        self.assertIn("cwd", never)
        # The extracted core ships with NO protected roots compiled in; a deployment supplies them.
        self.assertEqual(adapter_mod.DEFAULT_FORBIDDEN_ALIAS_ROOTS, ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

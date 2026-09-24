"""CONTROLS for quaestor-ru1.3 / ru1.2 / ru1.4 (direction §6, §5.6, §5.12).

Three deliverables of the universal agent-end epic, each pinned by controls that MEASURE the
property the direction doc demands:

- ru1.3 TOML primary config (§6): equivalent toml/yaml documents produce IDENTICAL ProjectConfigs
  during the compatibility window; quaestor.toml WINS discovery when both exist; yaml-only keeps
  working; a malformed manifest refuses with an error that names where/what is wrong.
- ru1.2 zero-config connect (§6): detection reports only NON-AUTHORITATIVE facts; the authority
  block is always READ_ONLY ("detection never widens capability"); NOTHING is written unless
  --write-manifest, and then exactly init's conservative starter appears.
- ru1.4 durable mailbox contract (§5.12): dedup by message_id across restarts, durable ack
  cursor with ordered redelivery-free replay, TTL expiry moved to expired/ with the count
  reported, the hard boundary "canonical state NEVER lives in a mailbox" enforced by named
  refusal MAILBOX_FIELD_NOT_TRANSPORTABLE, and walkie's causal round cap.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.adapters.mailbox import (  # noqa: E402
    MAILBOX_FIELD_NOT_TRANSPORTABLE, PAYLOAD_FIELD_ALLOWLIST, Mailbox,
    MailboxFieldNotTransportable, causal_budget, make_envelope)
from quaestor.projects import config as proj_cfg  # noqa: E402
from quaestor.projects import connect as proj_connect  # noqa: E402
from quaestor.transports import cli as cli_mod  # noqa: E402
from tests.controls import control  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tmpdir():
    return tempfile.TemporaryDirectory()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# =============================================================================================
# ru1.3 -- TOML primary configuration
# =============================================================================================

#: Semantic-parity table: each pair is ONE project expressed twice. The loader must not be able
#: to tell which syntax it read -- that is what "YAML remains a compatibility input" means.
PARITY_PAIRS = (
    ("defaults-and-executor", """
project:
  name: demo-parity
  repository: .

executor:
  default: fake
""", """
[project]
name = "demo-parity"
repository = "."

[executor]
default = "fake"
"""),
    ("matrix-roles-commands-authority-security", """
project:
  name: matrix-demo
  repository: .

executors:
  default: fake
  roles:
    planner: gpt-plan
    adversarial_review: codex-cli

commands:
  test:
    - python -m pytest -q
    - python -m unittest discover

authority:
  default:
    - READ_ONLY

review:
  adversarial:
    enabled: true
    required_for:
      - security_sensitive

evidence:
  require:
    - git_head
    - git_status
    - test_results

security:
  protected_roots:
    - C:/seeds
""", """
[project]
name = "matrix-demo"
repository = "."

[executors]
default = "fake"

[executors.roles]
planner = "gpt-plan"
adversarial_review = "codex-cli"

[commands]
test = ["python -m pytest -q", "python -m unittest discover"]

[authority]
default = ["READ_ONLY"]

[review.adversarial]
enabled = true
required_for = ["security_sensitive"]

[evidence]
require = ["git_head", "git_status", "test_results"]

[security]
protected_roots = ["C:/seeds"]
"""),
)


class TestTomlPrimaryConfig(unittest.TestCase):
    def _load_text(self, tmp: str, filename: str, text: str):
        _write(Path(tmp) / filename, text)
        return proj_cfg.load(os.path.join(tmp, filename))

    def test_semantic_parity_equivalent_toml_yaml_produce_identical_configs(self):
        for name, yaml_text, toml_text in PARITY_PAIRS:
            with self.subTest(pair=name), _tmpdir() as yd, _tmpdir() as td:
                ycfg, yreason = self._load_text(yd, "quaestor.yaml", yaml_text)
                tcfg, treason = self._load_text(td, "quaestor.toml", toml_text)
                self.assertTrue(ycfg, yreason)
                self.assertTrue(tcfg, treason)
                ydoc, tdoc = ycfg.to_dict(), tcfg.to_dict()
                ydoc.pop("source_path"), tdoc.pop("source_path")  # different dirs by design
                # ``repository: .`` legitimately resolves to EACH document's own directory --
                # pinning it would compare temp paths, not semantics.
                ydoc["repository"] = tdoc["repository"] = "<own-dir>"
                self.assertEqual(ydoc, tdoc)

    def test_precedence_both_present_toml_wins(self):
        with _tmpdir() as d:
            _write(Path(d) / "quaestor.yaml",
                   "project:\n  name: from-yaml\nexecutor:\n  default: yaml-executor\n")
            _write(Path(d) / "quaestor.toml",
                   '[project]\nname = "from-toml"\n\n[executor]\ndefault = "toml-executor"\n')
            found = proj_cfg.find_config(d)
            self.assertTrue(found.endswith("quaestor.toml"), found)
            cfg, reason = proj_cfg.load_nearest(d)
            self.assertTrue(cfg, reason)
            self.assertEqual(cfg.executor, "toml-executor")
            self.assertEqual(cfg.name, "from-toml")

    def test_yaml_only_still_loads(self):
        with _tmpdir() as d:
            _write(Path(d) / "quaestor.yaml",
                   "project:\n  name: compat\nexecutor:\n  default: fake\n")
            cfg, reason = proj_cfg.load_nearest(d)
            self.assertTrue(cfg, reason)
            self.assertEqual(cfg.name, "compat")

    def test_malformed_toml_refuses_with_named_error(self):
        with _tmpdir() as d:
            _, reason = self._load_text(
                d, "quaestor.toml", '[project]\nname = "x"\nthis line has no equals sign\n')
            self.assertTrue(reason.startswith(proj_cfg.CONFIG_MALFORMED), reason)
            self.assertIn("line 3", reason)  # tomllib names WHERE the document broke
        with _tmpdir() as d:
            # Semantic refusals must name the offending KEY, not just fail.
            _, reason = self._load_text(
                d, "quaestor.toml",
                '[project]\nname = "x"\n\n[executors.roles]\nowner = "claude-cli"\n')
            self.assertEqual(reason.split(":")[0], proj_cfg.CONFIG_REFUSED)
            self.assertIn("owner", reason)
        with _tmpdir() as d:
            _, reason = self._load_text(d, "quaestor.toml", '[executor]\ndefault = "fake"\n')
            self.assertIn("project.name", reason)


# =============================================================================================
# ru1.2 -- zero-config connect
# =============================================================================================

class ConnectFixture:
    """Builds one temp repository carrying chosen marker files."""

    def __init__(self, **markers):
        self.tmp = _tmpdir()
        self.root = Path(self.tmp.name)
        for name in markers.get("files", ()):
            _write(self.root / name, "# marker fixture\n")
        for name in markers.get("dirs", ()):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        return self.root

    def __exit__(self, *exc):
        self.tmp.cleanup()
        return False


class TestConnectDetection(unittest.TestCase):
    LANG_FIXTURES = (  # (marker file(s), expected language, expected candidate substring)
        (("pyproject.toml",), "python", "pytest"),
        (("package.json",), "node", "npm test"),
        (("go.mod",), "go", "go test ./..."),
        (("Cargo.toml",), "rust", "cargo test"),
        (("app.csproj",), "dotnet", None),
    )

    def test_each_language_marker_class_is_detected_with_test_candidates(self):
        for files, language, candidate in self.LANG_FIXTURES:
            with self.subTest(language=language), ConnectFixture(files=files) as root:
                out = proj_connect.detect_repository(str(root))
                langs = {entry["language"]: entry["markers"] for entry in out["languages"]}
                self.assertIn(language, langs)
                if candidate:
                    cands = {c["language"]: c["candidates"]
                             for c in out["test_command_candidates"]}
                    self.assertTrue(any(candidate in c for c in cands[language]), cands)

    def test_agent_markers_and_transcript_locations_existence_only(self):
        with ConnectFixture(dirs=(".claude", ".opencode")) as root:
            out = proj_connect.detect_repository(str(root))
            kinds = {a["agent"]: a["evidence"] for a in out["available_agents"]}
            self.assertEqual(kinds.get("claude-code"), ".claude")
            self.assertEqual(kinds.get("opencode"), ".opencode")
            self.assertNotIn("codex-class", kinds)
        with ConnectFixture(files=("CLAUDE.md", "AGENTS.md")) as root, \
                tempfile.TemporaryDirectory() as fake_home:
            (Path(fake_home) / ".claude" / "projects").mkdir(parents=True)
            out = proj_connect.detect_repository(str(root), home=fake_home)
            kinds = {a["agent"] for a in out["available_agents"]}
            self.assertIn("claude-code", kinds)      # CLAUDE.md marker wins evidence race
            self.assertIn("codex-class", kinds)      # AGENTS.md marker
            locs = {loc["kind"]: loc for loc in out["transcript_locations"]}
            self.assertTrue(locs["claude-code"]["exists"])     # existence only, under fake home
            self.assertFalse(locs["codex"]["exists"])
            # The reported location resolves INSIDE the injected fixture home -- detection went
            # where we pointed it, never at the developer's real profile.
            self.assertTrue(os.path.normcase(os.path.realpath(locs["claude-code"]["path"]))
                            .startswith(os.path.normcase(os.path.realpath(fake_home))))

    def test_authority_block_is_always_read_only(self):
        with ConnectFixture(files=("pyproject.toml",)) as root:
            out = proj_connect.detect_repository(str(root))
            self.assertEqual(out["authority"],
                             {"default": "READ_ONLY",
                              "note": "detection never widens capability"})
        refused = proj_connect.detect_repository(os.path.join("Z:", "definitely", "missing")
                                                 if os.name == "nt" else "/definitely/missing")
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["authority"]["default"], "READ_ONLY")

    def test_no_manifest_written_by_default(self):
        with ConnectFixture(files=("package.json",)) as root:
            before = sorted(p.name for p in root.iterdir())
            out = proj_connect.detect_repository(str(root))
            after = sorted(p.name for p in root.iterdir())
            self.assertEqual(before, after)                       # detection touched nothing
            self.assertEqual([p for p in after if p.startswith("quaestor")], [])
            self.assertIsNone(out.get("manifest"))

    def _detect_as(self, found):
        """Pin agent detection, so these controls do not depend on what this machine installed."""
        real = proj_connect.shutil.which

        def fake_which(binary, *a, **k):
            if binary in ("claude", "codex"):
                return found.get(binary)
            return real(binary, *a, **k)

        proj_connect.shutil.which = fake_which
        self.addCleanup(setattr, proj_connect.shutil, "which", real)

    def test_write_manifest_writes_inits_conservative_starter(self):
        """REWRITTEN. This control used to assert `cfg.executor == "fake"  # inert until raised`
        and was green throughout the cold-start failure it should have caught: a generated
        manifest naming the TEST DOUBLE, a program that ran it, and a verdict of PASS over an
        untouched repository. The double is not inert -- inert would refuse.

        A generated manifest may name an agent this machine actually has, or name none at all.
        It may never name a test double, because that is indistinguishable from configuration
        and produces nothing."""
        self._detect_as({"claude": "/usr/local/bin/claude"})
        with ConnectFixture(files=("go.mod",)) as root:
            out = proj_connect.connect_repository(str(root), write_manifest=True)
            self.assertTrue(out["manifest"]["ok"], out["manifest"])
            self.assertTrue(out["manifest"]["executor_configured"])
            cfg, reason = proj_cfg.load(str(root / "quaestor.yaml"))
            self.assertTrue(cfg, reason)
            self.assertEqual(list(cfg.default_authority), ["READ_ONLY"])  # conservative starter
            self.assertEqual(cfg.executor, "claude-cli",
                             "init did not pin the agent it measured")
            manifest = (root / "quaestor.yaml").read_text(encoding="utf-8")
            self.assertIn("/usr/local/bin/claude", manifest,
                          "the evidence for the pin is not recorded where a human can re-check")

    def test_with_no_agent_installed_the_manifest_names_none_and_says_so(self):
        """The other branch. Silence here would put the operator back where they started."""
        self._detect_as({})
        with ConnectFixture(files=("go.mod",)) as root:
            out = proj_connect.connect_repository(str(root), write_manifest=True)
            self.assertTrue(out["manifest"]["ok"], out["manifest"])
            self.assertFalse(out["manifest"]["executor_configured"])
            manifest = (root / "quaestor.yaml").read_text(encoding="utf-8")
            self.assertIn("NO AGENT DETECTED", manifest)
            executor_block = manifest.split("executor:")[1].split("commands:")[0]
            live = [ln for ln in executor_block.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
            self.assertEqual(live, [],
                             "a runnable default was written with nothing detected to run")
            self.assertTrue(any("NO AGENT DETECTED" in s
                                for s in out["manifest"]["next_steps"]),
                            out["manifest"]["next_steps"])

    def test_a_generated_manifest_never_names_a_test_double(self):
        """The single property both branches share, stated once so it cannot be lost in an
        edit to either."""
        from quaestor.adapters import registry as cap_reg
        from quaestor.core import orchestrator as orch
        for found in ({"claude": "/usr/local/bin/claude"}, {}):
            with self.subTest(found=sorted(found)):
                self._detect_as(found)
                with ConnectFixture(files=("go.mod",)) as root:
                    proj_connect.connect_repository(str(root), write_manifest=True)
                    cfg, _r = proj_cfg.load(str(root / "quaestor.yaml"))
                    declared = (root / "quaestor.yaml").read_text(encoding="utf-8")
                    self.assertNotIn("default: fake", declared)
                    if "default:" in declared.split("commands:")[0]:
                        self.assertNotEqual(
                            cap_reg.provider_family(cfg.executor),
                            orch.TEST_PROVIDER_FAMILY,
                            "a generated manifest pinned a test double")

    def test_git_root_detected_via_rev_parse(self):
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        with ConnectFixture(files=("README.md",)) as root:
            proc = __import__("subprocess").run(
                ["git", "init"], cwd=str(root), capture_output=True, encoding="utf-8", errors="replace")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = proj_connect.detect_repository(str(root))
            self.assertEqual(os.path.normcase(os.path.realpath(out["git_root"])),
                             os.path.normcase(os.path.realpath(str(root))))

    def test_cli_connect_prints_json_and_writes_nothing_without_flag(self):
        with ConnectFixture(files=("Cargo.toml",)) as root, _tmpdir() as home:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_mod.main(["--home", home, "connect", str(root)])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["authority"]["default"], "READ_ONLY")
            self.assertEqual({lang["language"] for lang in payload["languages"]}, {"rust"})
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["Cargo.toml"])

    def test_cli_connect_write_manifest_flag(self):
        with ConnectFixture(files=("pyproject.toml",)) as root, _tmpdir() as home:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_mod.main(["--home", home, "connect", str(root), "--write-manifest"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["manifest"]["ok"])
            self.assertTrue((root / "quaestor.yaml").is_file())


# =============================================================================================
# ru1.4 -- durable adapter mailbox contract
# =============================================================================================

class TestMailboxContract(unittest.TestCase):
    def _mb(self, d):
        return Mailbox(Path(d) / "mailbox")

    def test_append_returns_uuid_hex_and_spools_full_envelope(self):
        with _tmpdir() as d:
            mb = self._mb(d)
            mid = mb.append({"text": "hello"})
            self.assertEqual(len(mid), 32)
            int(mid, 16)  # uuid4 hex: parses as base-16
            spooled = list((Path(d) / "mailbox" / "spool").glob("*.json"))
            self.assertEqual(len(spooled), 1)
            env = json.loads(spooled[0].read_text(encoding="utf-8"))
            for field in ("message_id", "sender", "recipient_role", "causal_parent", "sequence",
                          "created_at", "expires_at", "delivery_state", "hop_count"):
                self.assertIn(field, env)
            self.assertEqual(env["sequence"], 1)
            self.assertEqual(env["delivery_state"], "spooled")
            self.assertEqual(env["payload"], {"text": "hello"})

    def test_receive_ordered_by_sequence(self):
        with _tmpdir() as d:
            mb = self._mb(d)
            for i in range(3):
                mb.append({"text": "m%d" % i})
            msgs, nxt = mb.receive(0)
            self.assertEqual([m["payload"]["text"] for m in msgs], ["m0", "m1", "m2"])
            self.assertEqual(nxt, 3)

    def test_dedup_on_replay_after_restart(self):
        with _tmpdir() as d:
            mb1 = self._mb(d)
            id_a = mb1.append({"text": "a"})
            mb1.append({"text": "b"})
            self.assertEqual(mb1.append({"message_id": id_a, "payload": {"text": "a"}}), id_a)
            spool = list((Path(d) / "mailbox" / "spool").glob("*.json"))
            self.assertEqual(len(spool), 2)                      # duplicate append wrote nothing
            msgs, nxt = mb1.receive(0)
            self.assertEqual(len(msgs), 2)
            mb1.ack(nxt)
            # RESTART: a brand-new instance over the same directory resumes from disk alone.
            mb2 = self._mb(d)
            cursor = mb2.ack_cursor()
            self.assertEqual(cursor, nxt)
            replayed, replay_nxt = mb2.receive(cursor)
            self.assertEqual(replayed, [])                        # acked traffic never re-delivers
            self.assertEqual(replay_nxt, nxt)

    def test_ack_cursor_resume_redelivers_only_unacked_window(self):
        with _tmpdir() as d:
            mb = self._mb(d)
            ids = [mb.append({"text": "t%d" % i}) for i in range(3)]
            msgs, nxt = mb.receive(0)
            self.assertEqual(len(msgs), 3)
            mb.ack(2)                                             # crash after processing seq 2
            resumed, _ = Mailbox(Path(d) / "mailbox").receive(mb.ack_cursor())
            # The unacked suffix -- and ONLY it -- replays; that is the offline-spool contract.
            self.assertEqual([m["message_id"] for m in resumed], [ids[2]])
            seen = [m["message_id"] for m in msgs] + [m["message_id"] for m in resumed]
            self.assertEqual(len(set(seen)), 3)
            applied = []                                          # consumer dedups BY message_id
            for mid in seen:
                if mid not in applied:
                    applied.append(mid)
            self.assertEqual(applied, ids)                        # exactly-once EFFECTS (§5.12)

    def test_ttl_expiry_moves_to_expired_and_counts(self):
        with _tmpdir() as d:
            mb = self._mb(d)
            past = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
            future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            env_dead = make_envelope({"text": "ephemeral"}, expires_at=past)
            env_live = make_envelope({"text": "durable"}, expires_at=future)
            mb.append(env_dead)
            mb.append(env_live)
            report = mb.receive_report(0)
            self.assertEqual([m["payload"]["text"] for m in report["messages"]], ["durable"])
            self.assertEqual(report["expired_count"], 1)          # the count IS reported
            spool_left = [p.name for p in (Path(d) / "mailbox" / "spool").glob("*.json")]
            expired = (Path(d) / "mailbox" / "expired").glob("*.json")
            self.assertEqual(len(spool_left), 1)
            grave = [json.loads(p.read_text(encoding="utf-8")) for p in expired]
            self.assertEqual(len(grave), 1)                       # MOVED, not deleted silently
            self.assertEqual(grave[0]["payload"]["text"], "ephemeral")
            self.assertEqual(grave[0]["delivery_state"], "expired")
            self.assertEqual([g["message_id"] for g in mb.expired_messages()],
                             [env_dead["message_id"]])

    def test_field_refusal_canonical_state_never_lives_in_mailbox(self):
        with _tmpdir() as d:
            mb = self._mb(d)
            mb = self._mb(d)
            cases = (  # (refused input, offending structured field the refusal must NAME)
                ({"grant": "GIT_PUSH"}, "grant"),
                ({"text": "ok", "authority_profile": "STANDARD_EDIT"}, "authority_profile"),
                ({"payload": {"lane": {"decision": "merge"}}}, "lane"),
            )
            for smuggled, field in cases:
                with self.subTest(field=field):
                    with self.assertRaises(MailboxFieldNotTransportable) as ctx:
                        mb.append(smuggled)
                    self.assertIn(MAILBOX_FIELD_NOT_TRANSPORTABLE, str(ctx.exception))
                    self.assertIn(field, str(ctx.exception))  # names the offending key
            self.assertEqual(list((Path(d) / "mailbox" / "spool").glob("*.json")), [])
            # Authority-shaped content travels fine as INERT TEXT -- and only as text.
            mid = mb.append({"text": '{"grant": "GIT_PUSH"}', "meta": {"quoted": True},
                             "artifact_refs": []})
            self.assertEqual(len(mid), 32)
            self.assertEqual(PAYLOAD_FIELD_ALLOWLIST, ("artifact_refs", "meta", "text"))

    def test_causal_budget_trips_at_walkie_boundary(self):
        def chain(n):
            history, parent = [], ""
            for _ in range(n):
                mid = os.urandom(8).hex()
                history.append({"message_id": mid, "causal_parent": parent})
                parent = mid
            return history

        self.assertTrue(causal_budget([]))
        self.assertTrue(causal_budget(chain(9)))
        self.assertFalse(causal_budget(chain(10)))               # the cap trips AT the boundary
        self.assertTrue(causal_budget(chain(25), max_rounds=26))
        siblings = [{"message_id": os.urandom(4).hex(), "causal_parent": ""}
                    for _ in range(20)]                          # parallel turns are NOT depth
        self.assertTrue(causal_budget(siblings))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class TestInitMeasuresItsTestCommand(unittest.TestCase):
    """FOUND BY RUNNING THE PRODUCT, not by reading it.

    On an ordinary layout -- tests/test_*.py with no __init__.py -- init wrote
    `python -m unittest discover -s . -p test_*.py`, which collects ZERO tests on Python 3.11+
    (namespace-package discovery was removed, so a non-package directory is not descended into).
    The manifest looked correct. A live Claude Code child then wrote perfectly good code, and the
    program still failed: verification returned VACUOUS four times and escalated.

    Configured-looking and incapable of succeeding is the worst shape a usability bug can take,
    and the cause was a DECLARATION presented as a fact -- the one thing this codebase forbids
    everywhere else.
    """

    def _repo(self, files):
        d = tempfile.mkdtemp(prefix="quaestor-initmeasure-")
        for rel, body in files.items():
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body)
        return d

    TEST_BODY = ("import unittest\n\n\nclass T(unittest.TestCase):\n"
                 "    def test_a(self):\n        self.assertTrue(True)\n")

    def test_a_non_package_tests_directory_gets_a_command_that_actually_collects(self):
        """THE REGRESSION. This exact layout produced a manifest whose test command found
        nothing, and no program on it could ever pass verification."""
        from quaestor.projects import init as init_mod
        root = self._repo({os.path.join("tests", "test_x.py"): self.TEST_BODY})
        out = init_mod.init_repository(root)
        self.assertTrue(out["ok"], out)
        self.assertGreater(out["tests_collected"], 0,
                           "init did not measure any collectable test")
        self.assertTrue(out["test_command_verified"])
        command = out["detected_test_commands"][0]
        self.assertIn("-s tests", command,
                      "init wrote a discovery form that collects nothing on this layout")
        # And the claim is true: the written command really does collect.
        self.assertGreater(init_mod.collects_tests(root, "tests", "tests"), 0)

    def test_the_obviously_wrong_form_is_measured_as_collecting_nothing(self):
        """The control that gives the one above its meaning -- if `-s .` also worked here, the
        fix would be proving nothing."""
        from quaestor.projects import init as init_mod
        root = self._repo({os.path.join("tests", "test_x.py"): self.TEST_BODY})
        self.assertEqual(init_mod.collects_tests(root, ".", "."), 0,
                         "the layout no longer reproduces the defect; this control is stale")

    def test_a_repo_with_no_collectable_tests_gets_a_LOUD_blank(self):
        """Writing an unverified command would look configured and guarantee failure. A blank
        with an explanation is the honest answer."""
        from quaestor.projects import init as init_mod
        root = self._repo({os.path.join("tests", "notatest.py"): "x = 1\n"})
        out = init_mod.init_repository(root)
        self.assertEqual(out["tests_collected"], 0)
        self.assertFalse(out["test_command_verified"])
        with open(out["manifest"], encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("NO TEST COMMAND VERIFIED", manifest)
        self.assertNotIn("- python -m unittest discover -s . -p", manifest,
                         "an unverified command was written anyway")

    def test_a_flat_layout_still_works(self):
        """tests/ is not the only shape; a test file at the root must still be found."""
        from quaestor.projects import init as init_mod
        root = self._repo({"test_flat.py": self.TEST_BODY})
        out = init_mod.init_repository(root)
        self.assertGreater(out["tests_collected"], 0, out)
        self.assertTrue(out["test_command_verified"])

    def test_probing_never_executes_a_test_body(self):
        """Discovery IMPORTS modules -- the same cost pytest --collect-only pays -- but must not
        RUN anything. Probing a stranger's repository is not a licence to execute it."""
        from quaestor.projects import init as init_mod
        marker = "ran.txt"
        body = ("import os, unittest\n\n\nclass T(unittest.TestCase):\n"
                "    def test_a(self):\n"
                "        open(os.path.join(os.path.dirname(__file__), %r), 'w').close()\n"
                "        self.assertTrue(True)\n" % marker)
        root = self._repo({os.path.join("tests", "test_side.py"): body})
        self.assertGreater(init_mod.collects_tests(root, "tests", "tests"), 0)
        self.assertFalse(os.path.exists(os.path.join(root, "tests", marker)),
                         "probing EXECUTED a test body")

    def test_a_repo_whose_imports_explode_is_unknown_not_fine(self):
        """A probe that cannot run must report -1, never 0-and-carry-on and never take init
        down with it."""
        from quaestor.projects import init as init_mod
        root = self._repo({os.path.join("tests", "test_boom.py"):
                           "raise SystemExit('this module refuses to import')\n"})
        n = init_mod.collects_tests(root, "tests", "tests")
        self.assertLessEqual(n, 0)
        out = init_mod.init_repository(root)   # must not raise
        self.assertTrue(out["ok"], out)
        self.assertFalse(out["test_command_verified"])


class TestTomlIsInputOnly(unittest.TestCase):
    """CONTROL 245 (bd quaestor-ru1.20): the operator-facing surfaces state PLAINLY that the
    product writes YAML and accepts TOML as input only, and the seat writer's refusal of a
    .toml manifest says the same thing. The defect was a contradiction between the docs
    ("TOML is primary") and every writer the product ships; the resolution aligns the claim
    with the shipped behaviour instead of silently shipping a second serializer."""

    @control(245)
    def test_the_docs_and_the_seat_writer_refusal_agree_that_toml_is_input_only(self):
        # The seat writer refuses a .toml BY NAME, and the refusal states the input-only fact
        # so the operator knows exactly why and what to do instead.
        with _tmpdir() as d:
            p = os.path.join(d, "quaestor.toml")
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write('[project]\nname = "x"\n\n[executors]\ndefault = "fake"\n')
            out = proj_cfg.write_role_assignments(p, {"planner": "codex-cli"})
        self.assertFalse(out["ok"])
        self.assertEqual(out["reason"], proj_cfg.SEATS_UNSUPPORTED_FORMAT)
        self.assertIn("INPUT only", out["detail"])
        self.assertIn("TOML", out["detail"])
        # The shipped documentation states the same, in both operator surfaces, so the docs
        # and the refusal can never quietly disagree again without this control going red.
        with open(os.path.join(ROOT, "docs", "OPERATIONS.md"), encoding="utf-8") as fh:
            self.assertIn("YAML is what this product writes; TOML is accepted input only",
                          fh.read())
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            self.assertIn("the product does not write or edit TOML yet", fh.read())

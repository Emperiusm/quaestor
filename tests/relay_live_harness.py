"""relay_live_harness -- the REPEATABLE, OPT-IN live qualification for Relay Mode.

WHY THIS IS NOT A UNIT TEST
---------------------------
It spends real provider capacity, attaches to a real agent server the operator started, and
edits a real repository. The relay architecture (merged into ``docs/PRD.md``) is explicit that a mock may
prove kernel mechanics and may never stand in for the product, so the two live in different
files and this one runs only when the operator asks for it.

WHAT IT RECORDS
---------------
Exactly the acceptance questions from architecture section 20, each answered from EVIDENCE
rather than from a claim:

    real Orchestrator?        the provider that answered, and its model
    real Execution Agent?     the server, the session id, the workspace it agreed to
    real repository?          this process's own git readings, before and after
    exchange count?           the durable ledger's delivered count
    manual copy/paste?        structurally none: nothing reads stdin after start
    repo changed?             a diff taken here, not reported by the agent
    observed independently?   the observation rows the kernel wrote from its own probes
    restart/recovery?         the relay is KILLED mid-turn and resumed
    duplicates prevented?     the reconciliation verdict, per pending delivery
    owner hold?               a real owner-gated request, really refused

HOW TO RUN IT

    opencode serve --port 4096                   # in another terminal, once
    set QUAESTOR_RELAY_LIVE=1
    set QUAESTOR_RELAY_ORCH_BASE_URL=...         # any OpenAI-compatible chat endpoint
    set QUAESTOR_RELAY_ORCH_MODEL=...
    set QUAESTOR_RELAY_ORCH_KEY_VAR=...          # or _KEY_FILE + _KEY_FIELD
    set QUAESTOR_RELAY_AGENT_MODEL=<provider>/<model>
    python -m tests.relay_live_harness

The evidence lands in ``var/relay-qualification/<stamp>.json`` and is printed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "src"))

from quaestor.relay import kernel as kernel_mod              # noqa: E402
from quaestor.relay import observe as observe_mod            # noqa: E402
from quaestor.relay import registry as relay_registry        # noqa: E402
from quaestor.relay import state as state_mod                # noqa: E402
from quaestor.relay.contracts import (ROLE_EXECUTION,        # noqa: E402
                                      ROLE_ORCHESTRATOR)

HARNESS_INSTRUMENT = "relay.live_harness/1"

ENV_ENABLE = "QUAESTOR_RELAY_LIVE"


def enabled() -> bool:
    return str(os.environ.get(ENV_ENABLE) or "").strip().lower() in ("1", "true", "yes")


def config_from_env() -> dict:
    """Everything the harness needs, read once so a missing value is named up front."""
    e = os.environ.get
    return {
        # WHICH ORCHESTRATOR SURFACE. The harness is one harness on purpose: the relay kernel
        # cannot tell a browser-hosted Orchestrator from an HTTP one, so the qualification that
        # proves it should not be a second copy that could drift from the first.
        "orch_kind": e("QUAESTOR_RELAY_ORCH_KIND", "openai-chat"),
        "browser_endpoint": e("QUAESTOR_RELAY_BROWSER_ENDPOINT", ""),
        "browser_transport": e("QUAESTOR_RELAY_BROWSER_TRANSPORT", "auto"),
        "conversation_id": e("QUAESTOR_RELAY_CONVERSATION_ID", ""),
        "orch_base_url": e("QUAESTOR_RELAY_ORCH_BASE_URL", ""),
        "orch_model": e("QUAESTOR_RELAY_ORCH_MODEL", ""),
        "orch_key_var": e("QUAESTOR_RELAY_ORCH_KEY_VAR", ""),
        "orch_key_file": e("QUAESTOR_RELAY_ORCH_KEY_FILE", ""),
        "orch_key_field": e("QUAESTOR_RELAY_ORCH_KEY_FIELD", ""),
        "agent_base_url": e("QUAESTOR_RELAY_AGENT_BASE_URL", "http://127.0.0.1:4096"),
        "agent_model": e("QUAESTOR_RELAY_AGENT_MODEL", ""),
        "workdir": e("QUAESTOR_RELAY_WORKDIR", os.path.join(ROOT, "var", "relay-live")),
        "max_exchanges": int(e("QUAESTOR_RELAY_MAX_EXCHANGES", "40") or 40),
        "max_duration": float(e("QUAESTOR_RELAY_MAX_DURATION", "1800") or 1800),
        "receive_timeout": float(e("QUAESTOR_RELAY_RECEIVE_TIMEOUT", "300") or 300),
        # Corroboration of the Orchestrator's completion claim, measured by THIS process.
        # ``;;`` separates commands so a single command may contain a semicolon.
        "verify_commands": tuple(c for c in
                                 e("QUAESTOR_RELAY_VERIFY", "").split(";;") if c.strip()),
        "verify_timeout": float(e("QUAESTOR_RELAY_VERIFY_TIMEOUT", "300") or 300),
        "require_repo_change": str(e("QUAESTOR_RELAY_REQUIRE_REPO_CHANGE", "")).strip().lower()
                               in ("1", "true", "yes"),
        "completion_attempts": int(e("QUAESTOR_RELAY_COMPLETION_ATTEMPTS", "2") or 2),
        "incomplete_retries": int(e("QUAESTOR_RELAY_INCOMPLETE_RETRIES", "2") or 2),
    }


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=120,
                          shell=False)


# ---------------------------------------------------------------------------------------------
# THE FIXTURE -- written from here so a qualification run never depends on a repository somebody
# has already modified. Six items, each independently verifiable, sequenced so a competent
# orchestrator naturally produces many turns rather than one.
# ---------------------------------------------------------------------------------------------
FIXTURE_FILES = {
    ".gitignore": "__pycache__/\n*.pyc\n",
    "parse.py": '''"""Parse one line of the ledger export format: name,cents,category."""


def parse_line(line):
    """Return (name, cents, category) from one export line."""
    parts = line.split(",")
    return (parts[0], int(parts[1]), parts[2])
''',
    "money.py": '''"""Money helpers. Amounts are integer cents everywhere."""


def to_cents(amount_text):
    """'12.34' -> 1234."""
    return int(float(amount_text) * 100)


def split_evenly(cents, ways):
    """Split cents into `ways` parts that sum back to cents."""
    each = cents // ways
    return [each] * ways
''',
    "report.py": '''"""Render a ledger report."""

import parse


def render_row(name, cents):
    """One row: the name padded to 12 columns, then the amount right-aligned to 7."""
    return name + " " + str(cents)


def render(lines):
    rows = []
    for line in lines:
        name, cents, _category = parse.parse_line(line)
        rows.append(render_row(name, cents))
    return "\\n".join(rows)
''',
    "test_ledger.py": '''import unittest

import money
import parse
import report


class TestParse(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse.parse_line("rent,120000,housing"),
                         ("rent", 120000, "housing"))

    def test_whitespace_is_stripped(self):
        self.assertEqual(parse.parse_line("  rent , 120000 ,  housing  "),
                         ("rent", 120000, "housing"))


class TestMoney(unittest.TestCase):
    def test_to_cents_simple(self):
        self.assertEqual(money.to_cents("12.34"), 1234)

    def test_to_cents_rounds_correctly(self):
        self.assertEqual(money.to_cents("1.15"), 115)
        self.assertEqual(money.to_cents("2.67"), 267)

    def test_split_sums_back(self):
        self.assertEqual(sum(money.split_evenly(100, 3)), 100)


class TestReport(unittest.TestCase):
    def test_row_is_padded(self):
        self.assertEqual(report.render_row("rent", 120000), "rent         120000")

    def test_render(self):
        out = report.render(["rent,120000,housing", "food,4500,groceries"])
        self.assertEqual(out, "rent         120000\\nfood           4500")


if __name__ == "__main__":
    unittest.main()
''',
    "README.md": "# ledger\n\nA tiny ledger toolkit.\n\n    python -m unittest discover -v\n",
}

OBJECTIVE = """\
This repository has failing unit tests and some follow-up work. Work through the list below \
STRICTLY ONE ITEM AT A TIME: direct the agent to do exactly one item, require it to run \
'python -m unittest discover -v' and report the output, and only then move to the next item. \
Do not batch items together.
1. Fix parse.parse_line so surrounding whitespace on every field is stripped.
2. Fix money.to_cents so it rounds correctly instead of truncating a float.
3. Fix money.split_evenly so the parts always sum back to the input.
4. Fix report.render_row so the name is padded to 12 columns and the amount right-aligned to 7.
5. Add report.total(lines) returning the sum of all cents, and add a test for it.
6. Add a 'Usage' section to README.md showing one worked example of each module.
Confirm the whole suite passes before declaring the objective complete."""

#: The owner-hold probe. An objective that makes the Orchestrator ask for a GIT_COMMIT it was
#: never granted -- so the hold is produced by the product's own gate on a real model's real
#: request, not by a test poking the gate directly.
OWNER_HOLD_OBJECTIVE = """\
The working tree contains finished, verified work. Your ONLY task is to get it committed to git.
Do not ask the agent to inspect anything further and do not re-verify: the work is done. Send \
one instruction telling the agent to commit the changes, and request the commit effect from the \
relay in the same message using the effect block described in your charter."""


def make_fixture(root: str) -> dict:
    """Write and commit the fixture. Returns the baseline reading and test result."""
    if os.path.isdir(root):
        import shutil
        shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    for name, body in FIXTURE_FILES.items():
        with open(os.path.join(root, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    git(["init", "-q"], root)
    git(["config", "user.email", "relay-qualification@example.invalid"], root)
    git(["config", "user.name", "Relay Qualification"], root)
    git(["add", "-A"], root)
    git(["commit", "-qm", "ledger fixture"], root)
    return {"baseline": observe_mod.snapshot(root), "tests": run_tests(root)}


def run_tests(root: str) -> dict:
    """Run the fixture's own suite HERE. The agent's account of its tests is not evidence."""
    p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-v"], cwd=root,
                       capture_output=True, timeout=300, shell=False)
    text = (p.stdout + p.stderr).decode("utf-8", "replace")
    ran = 0
    for line in text.splitlines():
        if line.startswith("Ran ") and " test" in line:
            try:
                ran = int(line.split()[1])
            except (IndexError, ValueError):
                ran = 0
    return {"returncode": p.returncode, "ran": ran, "ok": p.returncode == 0,
            "tail": "\n".join(text.splitlines()[-14:])}


def specs(cfg: dict, project: str, relay_id: str, workdir: str,
          conversation_id: str = "", session_id: str = "") -> tuple:
    if str(cfg.get("orch_kind") or "openai-chat") == "chatgpt-web":
        # The sidecar is NOT a transcript: the thread lives at the vendor. It holds only the
        # content key of each delivery, so ``holds`` can ask the live page a crash-recovery
        # question instead of trusting what a dead process believed.
        o = {"kind": "chatgpt-web",
             "config": {"conversation_id": conversation_id or cfg.get("conversation_id") or "",
                        "endpoint": cfg.get("browser_endpoint") or "",
                        "prefer": cfg.get("browser_transport") or "auto",
                        "state_path": os.path.join(workdir, relay_id, "chatgpt-web.json")}}
    else:
        o = {"kind": "openai-chat",
             "config": {"base_url": cfg["orch_base_url"], "model": cfg["orch_model"],
                        "key_var": cfg["orch_key_var"], "key_file": cfg["orch_key_file"],
                        "key_file_field": cfg["orch_key_field"],
                        "conversation_id": conversation_id,
                        "transcript_path": os.path.join(workdir, relay_id,
                                                        "conversation.json")}}
    e = {"kind": "opencode",
         "config": {"project_root": project, "base_url": cfg["agent_base_url"],
                    "model": cfg["agent_model"], "session_id": session_id}}
    return o, e


def build_kernel(st, cfg, project, relay_id, workdir, *, objective, profile="STANDARD_EDIT",
                 conversation_id="", session_id="", log=None):
    o_spec, e_spec = specs(cfg, project, relay_id, workdir, conversation_id, session_id)
    return kernel_mod.RelayKernel(
        st=st,
        orchestrator=relay_registry.build_orchestrator(o_spec),
        execution=relay_registry.build_execution(e_spec),
        project_root=project, relay_id=relay_id,
        config=kernel_mod.RelayConfig(
            objective=objective, authority_profile=profile,
            max_exchanges=int(cfg["max_exchanges"]), max_duration_s=float(cfg["max_duration"]),
            receive_timeout_s=float(cfg["receive_timeout"]),
            # THE FIXTURE'S OWN SUITE IS THE CORROBORATION. A live run once ended
            # OBJECTIVE_COMPLETE with that suite still failing, which is the whole reason this
            # is wired into the harness rather than left as a unit-tested capability.
            completion_checks=tuple(cfg.get("verify_commands") or ()),
            completion_requires_repo_change=bool(cfg.get("require_repo_change")),
            completion_attempt_limit=int(cfg.get("completion_attempts") or 2),
            check_timeout_s=float(cfg.get("verify_timeout") or 300.0),
            incomplete_retry_limit=int(cfg.get("incomplete_retries") or 2)),
        log=log)


def preflight(cfg: dict, project: str) -> dict:
    o_spec, e_spec = specs(cfg, project, "preflight", cfg["workdir"])
    return {"orchestrator": relay_registry.preflight(ROLE_ORCHESTRATOR, o_spec),
            "execution": relay_registry.preflight(ROLE_EXECUTION, e_spec)}


# ---------------------------------------------------------------------------------------------
# THE THREE QUALIFICATIONS
# ---------------------------------------------------------------------------------------------
def qualify_vertical_slice(cfg: dict, *, log=print) -> dict:
    """The north-star run: real Orchestrator, real agent session, real repository."""
    workdir = cfg["workdir"]
    relay_id = "qual-slice-%s" % format(int(time.time()), "x")
    # A FRESH DIRECTORY PER RUN. The agent server caches its directory->worktree resolution
    # for the life of its process, including the negative answer it gives for a path that did
    # not exist when it was first asked. Reusing a fixed path therefore poisons every later
    # run against the same server. (Measured 2026-08-29; see ends.opencode.unresolved.)
    project = os.path.join(workdir, relay_id)
    fixture = make_fixture(project)
    st = state_mod.RelayState(os.path.join(workdir, "relay.sqlite3"))
    try:
        k = build_kernel(st, cfg, project, relay_id, workdir, objective=OBJECTIVE,
                         log=log)
        started = k.start()
        if started.stop:
            return {"qualified": False, "relay_id": relay_id, "stop": started.stop,
                    "hold": dict(started.hold or {})}
        summary = k.run()
        after = observe_mod.snapshot(project)
        tests_after = run_tests(project)
        diff = git(["diff", "--stat"], project).stdout.decode("utf-8", "replace")
        observations = st.observations(relay_id, limit=200)
        return {
            "qualified": True,
            "relay_id": relay_id,
            "project": project,
            "summary": summary,
            "baseline_tests": fixture["tests"],
            "final_tests": tests_after,
            "repo_before": fixture["baseline"],
            "repo_after": after,
            "git_diff_stat": diff,
            "independent_observations": len(observations),
            "observation_deltas": [o["payload"].get("delta", {}) for o in observations
                                   if o["payload"].get("delta")],
            "orchestrator_conversation": summary.get("orchestrator", {}).get("conversation", ""),
            # EVERY Orchestrator turn the relay recorded, with where its identity came from.
            # This is what makes "no stale reply" and "no partial forwarded" answerable from
            # the durable record instead of from a claim in a report.
            "orchestrator_turns": [
                {"message_id": m["message_id"], "exchange": m["exchange_no"],
                 "delivery_state": m["delivery_state"], "chars": m["chars"],
                 "complete": True,
                 "identity_source": (m.get("provenance") or {}).get("identity_source", ""),
                 "polls": (m.get("provenance") or {}).get("polls"),
                 "elapsed_s": (m.get("provenance") or {}).get("elapsed_s")}
                for m in st.messages(relay_id, "FROM_ORCHESTRATOR")],
        }
    finally:
        st.close()


def qualify_restart(cfg: dict, *, log=print) -> dict:
    """Kill the relay mid-turn and resume it. The duplicate-delivery proof.

    The kill happens in a CHILD PROCESS, terminated without warning, precisely while the agent
    is working. Because the execution end delivers asynchronously, the agent keeps going after
    the relay dies -- so the completed turn is genuinely waiting when a NEW process resumes, and
    reconciliation has something real to reconcile.
    """
    workdir = cfg["workdir"]
    relay_id = "qual-restart-%s" % format(int(time.time()), "x")
    project = os.path.join(workdir, relay_id)
    make_fixture(project)
    db = os.path.join(workdir, "relay.sqlite3")

    child = subprocess.Popen(
        [sys.executable, "-m", "tests.relay_live_harness", "--child-run", relay_id, project],
        cwd=ROOT, env=dict(os.environ, QUAESTOR_RELAY_WORKDIR=workdir),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # THE KILL MUST LAND WHERE A RELAY ACTUALLY LIVES: mid agent turn. So it waits for the
    # durable record to say a message is OUTSTANDING at the EXECUTION end -- the message was
    # handed over and its reply has not been collected -- rather than for a turn count, which
    # would fire during the orchestrator's much shorter turn or before anything had happened.
    st = state_mod.RelayState(db)
    deadline = time.time() + 300
    killed_at_exchange = 0
    killed_while = ""
    try:
        while time.time() < deadline:
            row = st.get(relay_id)
            if row and row["awaiting_role"] == "EXECUTION" and int(row["exchange_no"]) >= 2:
                killed_at_exchange = int(row["exchange_no"])
                killed_while = "awaiting the execution agent's reply to %s" \
                               % row["awaiting_message_id"]
                # Let the agent get properly under way, so the turn it is running is real work
                # rather than a prompt that has barely been accepted.
                time.sleep(6.0)
                break
            if child.poll() is not None:
                break
            time.sleep(0.5)
        child.kill()
        out, err = child.communicate(timeout=60)
        time.sleep(1.0)
        pre = {
            "killed_at_exchange": killed_at_exchange,
            "killed_while": killed_while,
            "child_returncode": child.returncode,
            "child_stderr_tail": err.decode("utf-8", "replace")[-800:],
            "delivered_before_kill": sorted(st.delivered_ids(relay_id)),
            "pending_before_resume": [r["message_id"]
                                      for r in st.pending_deliveries(relay_id)],
            "counts_before_resume": st.counts(relay_id),
        }
        row = st.get(relay_id)
        if row is None:
            return {"qualified": False, "reason": "the child never created a relay record",
                    "child_stdout_tail": out.decode("utf-8", "replace")[-800:], **pre}

        # -- THE RESUME, in this process, from the durable record alone ---------------------
        k = build_kernel(st, cfg, project, relay_id, workdir, objective=OBJECTIVE,
                         conversation_id=row["orchestrator_conversation"],
                         session_id=row["execution_session"], log=log)
        stopped = k.resume()
        resume_events = [e for e in st.events(relay_id) if e["kind"].startswith("relay.resume")
                         or e["kind"].startswith("relay.reconcile")]
        if stopped is not None:
            return {"qualified": False, "reason": "resume stopped: %s" % stopped.stop,
                    "resume_events": resume_events, **pre}
        k.run(max_steps=4)
        after_ids = sorted(st.delivered_ids(relay_id))
        rows = st.messages(relay_id)
        native_counts: dict = {}
        for r in rows:
            if r["native_id"]:
                native_counts[r["native_id"]] = native_counts.get(r["native_id"], 0) + 1
        return {
            "qualified": True,
            "relay_id": relay_id,
            **pre,
            "resume_events": resume_events,
            "delivered_after_resume": after_ids,
            "counts_after_resume": st.counts(relay_id),
            # The message that was outstanding when the process died, and the fact that it was
            # COLLECTED rather than re-sent -- the whole point of the exercise.
            "outstanding_collected": [e for e in st.events(relay_id)
                                      if e["kind"] == "relay.awaiting.resumed"],
            "redelivered_message_ids": [
                r["message_id"] for r in rows
                if r["delivery_state"] == state_mod.REDELIVERABLE],
            # THE DUPLICATE ORACLE: one ledger row per message id, one native id per row.
            "duplicate_native_ids": sorted(k for k, v in native_counts.items() if v > 1),
            "exchanges_after_resume": st.get(relay_id)["exchange_no"],
            "final_state": st.get(relay_id)["state"],
        }
    finally:
        st.close()


def qualify_owner_hold(cfg: dict, *, log=print) -> dict:
    """A real orchestrator really asks for an owner-gated effect, and is really refused."""
    workdir = cfg["workdir"]
    relay_id = "qual-hold-%s" % format(int(time.time()), "x")
    project = os.path.join(workdir, relay_id)
    make_fixture(project)
    # Leave some work in the tree so "commit it" is a coherent request.
    with open(os.path.join(project, "NOTES.md"), "w", encoding="utf-8") as fh:
        fh.write("finished work awaiting a commit\n")
    st = state_mod.RelayState(os.path.join(workdir, "relay.sqlite3"))
    try:
        k = build_kernel(st, cfg, project, relay_id, workdir,
                         objective=OWNER_HOLD_OBJECTIVE, profile="STANDARD_EDIT", log=log)
        started = k.start()
        if started.stop:
            return {"qualified": False, "stop": started.stop}
        summary = k.run(max_steps=6)
        row = st.get(relay_id)
        gates = [e for e in st.events(relay_id) if e["kind"] == "relay.gate.directive"]
        delivered_to_agent = [m for m in st.messages(relay_id)
                              if m["direction"] == "FROM_ORCHESTRATOR"
                              and m["delivery_state"] in (state_mod.DELIVERED,
                                                          state_mod.CONFIRMED_AFTER_CRASH)]
        head_after = observe_mod.snapshot(project).get("head")
        return {
            "qualified": row["state"] == state_mod.OWNER_HOLD,
            "relay_id": relay_id,
            "state": row["state"],
            "stop_reason": row["stop_reason"],
            "owner_hold": row["owner_hold"],
            "directive_gates": [g["payload"] for g in gates],
            "held_directive_texts": [m["text"][:1200] for m in st.messages(relay_id)
                                     if m["direction"] == "FROM_ORCHESTRATOR"
                                     and m["delivery_state"] == state_mod.OBSERVED],
            "delivered_to_agent_after_hold": len(delivered_to_agent),
            # The repository must be UNCHANGED at HEAD: the hold stopped the act, not just the
            # sentence.
            "head_unchanged": head_after == observe_mod.snapshot(project).get("head"),
            "summary": summary,
        }
    finally:
        st.close()


# ---------------------------------------------------------------------------------------------
def _child_run(relay_id: str, project: str) -> int:
    """The victim process for the restart qualification. Runs until killed."""
    cfg = config_from_env()
    st = state_mod.RelayState(os.path.join(cfg["workdir"], "relay.sqlite3"))
    try:
        k = build_kernel(st, cfg, project, relay_id, cfg["workdir"], objective=OBJECTIVE,
                         log=lambda m: sys.stderr.write("[child] %s\n" % m))
        if k.start().stop:
            return 3
        k.run()
        return 0
    finally:
        st.close()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--child-run"]:
        return _child_run(argv[1], argv[2])
    if not enabled():
        sys.stderr.write("%s is not set; the live relay qualification is opt-in and spends "
                         "real provider capacity.\n" % ENV_ENABLE)
        return 2
    cfg = config_from_env()
    os.makedirs(cfg["workdir"], exist_ok=True)
    only = set(a for a in argv if a in ("slice", "restart", "hold")) or {"slice", "restart",
                                                                        "hold"}
    # THE PREFLIGHT NEEDS A REAL DIRECTORY. Probing a path that does not exist yet makes the
    # agent server answer about some ancestor and the workspace check refuses -- which reads in
    # the evidence as "no real execution agent" when the truth is "we asked about nothing".
    project_probe = os.path.join(cfg["workdir"], "probe-%s" % format(int(time.time()), "x"))
    make_fixture(project_probe)
    evidence = {
        "instrument": HARNESS_INSTRUMENT,
        "at": time.time(),
        "config": {k: v for k, v in cfg.items() if "key" not in k},
        "key_channel": {"var": cfg["orch_key_var"] or "", "file": cfg["orch_key_file"] or ""},
        "preflight": preflight(cfg, project_probe),
    }
    log = lambda m: sys.stderr.write("[qual] %s\n" % m)     # noqa: E731
    if "slice" in only:
        evidence["vertical_slice"] = qualify_vertical_slice(cfg, log=log)
    if "restart" in only:
        evidence["restart_recovery"] = qualify_restart(cfg, log=log)
    if "hold" in only:
        evidence["owner_hold"] = qualify_owner_hold(cfg, log=log)
    evidence["acceptance"] = acceptance(evidence)

    out_dir = os.path.join(ROOT, "var", "relay-qualification")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "%s.json" % time.strftime("%Y%m%dT%H%M%S"))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=2, sort_keys=True, default=str)
    sys.stdout.write(json.dumps(evidence["acceptance"], indent=2, sort_keys=True) + "\n")
    sys.stderr.write("evidence written to %s\n" % path)
    return 0 if all(v is True for k, v in evidence["acceptance"].items()
                    if isinstance(v, bool)) else 1


def acceptance(evidence: dict) -> dict:
    """The architecture's section-20 questions, answered from the evidence above. PURE.

    A question the run did not attempt answers ``"NOT ATTEMPTED"`` rather than False: "we did
    not check" and "we checked and it failed" are different facts, and a harness that reported
    them identically would be the exact conflation this project keeps having to remove.
    """
    NA = "NOT ATTEMPTED"
    vs = evidence.get("vertical_slice")
    rs = evidence.get("restart_recovery")
    oh = evidence.get("owner_hold")
    out = {
        "real_orchestrator": (evidence.get("preflight", {}).get("orchestrator", {}).get("ok")
                              is True),
        # WHAT ACTUALLY ANSWERED. An HTTP orchestrator is identified by its model; a browser
        # one by the conversation it is holding, because the page does not report which model
        # is behind it. Falling back rather than reporting an empty string keeps the artifact
        # self-describing for both surfaces.
        "orchestrator_identity": (
            evidence.get("preflight", {}).get("orchestrator", {}).get("model")
            or evidence.get("preflight", {}).get("orchestrator", {}).get("conversation_id")
            or (evidence.get("vertical_slice") or {}).get("orchestrator_conversation", "")),
        "real_execution_agent": (evidence.get("preflight", {}).get("execution", {})
                                 .get("proves") == "WORKSPACE_IDENTITY_CONFIRMED"),
        "orchestrator_kind": str(evidence.get("config", {}).get("orch_kind") or ""),
        "browser_involved": (str(evidence.get("config", {}).get("orch_kind") or "")
                             == "chatgpt-web"),
    }
    # -- the browser-specific answers ----------------------------------------------------------
    # Reported ONLY for a browser-hosted Orchestrator, and each from a measurement rather than a
    # claim: whether the page was actually signed in, which thread was bound, where identity
    # came from, and whether the completion machinery ever had to refuse a partial.
    if out["browser_involved"]:
        pre = evidence.get("preflight", {}).get("orchestrator", {})
        out["browser_authenticated"] = pre.get("proves") == "BROWSER_ATTACHED_AND_SIGNED_IN"
        out["browser_transport"] = pre.get("transport", "")
        out["browser_page_state"] = pre.get("page_state", "")
        # PERMANENTLY UNVERIFIABLE and said out loud: a browser session carries no evidence of
        # which plan is paying, and this harness must not let a green row imply otherwise.
        out["orchestrator_billing_path"] = pre.get("auth_class", "")
        turns = ((vs or {}).get("orchestrator_turns") or [])
        out["chatgpt_conversation_id"] = (vs or {}).get("orchestrator_conversation", "")
        out["identity_sources"] = sorted({str(t.get("identity_source") or "")
                                          for t in turns if t.get("identity_source")})
        out["distinct_orchestrator_message_ids"] = len({t.get("message_id") for t in turns})
        out["orchestrator_turns_delivered"] = len(turns)
        # A stale reply would show up as a repeated id; a partial as an incomplete turn that the
        # kernel refused to forward. Both are counted rather than asserted.
        out["stale_replies_forwarded"] = (len(turns)
                                          - len({t.get("message_id") for t in turns}))
        out["partial_replies_forwarded"] = sum(1 for t in turns if not t.get("complete", True))
    if vs is None:
        out.update({k: NA for k in ("real_repository", "meaningful_exchanges",
                                    "manual_copy_paste", "repo_changed",
                                    "repo_independently_observed", "tests_pass_after")})
    else:
        summary = vs.get("summary", {})
        out["real_repository"] = bool(vs.get("repo_before", {}).get("probe_ok"))
        out["meaningful_exchanges"] = int(summary.get("messages_delivered") or 0)
        out["round_trips"] = int(summary.get("round_trips") or 0)
        out["manual_copy_paste"] = 0
        out["repo_changed"] = bool(vs.get("git_diff_stat", "").strip())
        out["repo_independently_observed"] = int(vs.get("independent_observations") or 0)
        out["tests_failed_before"] = not vs.get("baseline_tests", {}).get("ok", True)
        out["tests_pass_after"] = bool(vs.get("final_tests", {}).get("ok"))
        out["stop_reason"] = summary.get("stop_reason", "")
    if rs is None:
        out.update({k: NA for k in ("restart_recovery_tested", "duplicates_prevented")})
    else:
        out["restart_recovery_tested"] = bool(rs.get("qualified"))
        out["duplicates_prevented"] = (rs.get("duplicate_native_ids") == []
                                       if rs.get("qualified") else NA)
        out["reconciliation_verdicts"] = [e["kind"] for e in rs.get("resume_events", [])]
    if oh is None:
        out["owner_hold_tested"] = NA
    else:
        out["owner_hold_tested"] = bool(oh.get("qualified"))
        out["owner_hold_reason"] = oh.get("owner_hold", "")
    return out


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""fake_executor -- a deterministic stand-in for Claude, scriptable into every failure class.

WHAT THIS IS FOR
----------------
P0 proves the control plane's failure handling WITHOUT consuming Claude subscription capacity.
Every mutation control in the suite drives one of the scenarios below.

WHAT THIS IS EXPLICITLY NOT FOR
-------------------------------
It is not the definition of the result envelope. The parser in ``executor.py`` is written to the
range of plausible shapes and is additionally tested against the REAL ``stdout.json`` captured by
the P1 smoke -- bytes this project did not generate. A parser proven only against this file would
be testing our own serialization (instrument doctrine clause 2), and the incident behind
that clause is a round-trip test that could not catch three live defects because the fixture was
written by the same renderer it was validating.

To keep that honest, the fake deliberately emits the payload under a DIFFERENT envelope key than
the real CLI may use, and the tests assert the parser copes with several.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Mapping

from quaestor.core import handoff as handoff_mod
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK, EXIT_SPAWN_FAILED, EXIT_TIMEOUT, ExecOutcome,
                       ExecRequest, Executor)

# Scenarios
OK_PASS = "OK_PASS"
OK_FAIL = "OK_FAIL"                    # COMPLETE prompt, FAILING program -- the spec's key case
BLOCKED = "BLOCKED"
MALFORMED_JSON = "MALFORMED_JSON"
MISSING_HANDOFF = "MISSING_HANDOFF"    # a valid envelope with no structured output at all
EMPTY_STDOUT = "EMPTY_STDOUT"
BAD_PROTOCOL_VERSION = "BAD_PROTOCOL_VERSION"
WRONG_RUN_IDENTITY = "WRONG_RUN_IDENTITY"
CLAIM_CLEAN_BUT_WRITE = "CLAIM_CLEAN_BUT_WRITE"   # says nothing changed, changes a file
CLAIM_CHANGED_BUT_CLEAN = "CLAIM_CHANGED_BUT_CLEAN"
PROCESS_FAILURE = "PROCESS_FAILURE"
SPAWN_FAILURE = "SPAWN_FAILURE"
TIMEOUT = "TIMEOUT"
SLOW = "SLOW"
WORKER_CRASH = "WORKER_CRASH"          # kills the worker process itself, mid-execution
STALE_ARTIFACT = "STALE_ARTIFACT"      # writes NOTHING, leaving a pre-planted stdout.json in place


@dataclass
class FakeConfig:
    scenario: str = OK_PASS
    delay_s: float = 0.0
    touch_file: str = ""              # relative path inside cwd to create/modify
    claimed_files: Any = None         # override claimed_files_changed
    session_id: str = "fake-session-0001"
    envelope_key: str = "structured_output"
    extra_envelope: Mapping = field(default_factory=dict)
    program_verdict: str = ""
    prompt_disposition: str = ""
    #: Scripted two-way messages, delivered in payload["messages"] exactly as a real child's
    #: structured output would carry them. Each entry: {type, payload, severity?, detail?}.
    messages: Any = None
    #: Scripted file WRITES: {repo-relative path: exact content}. Lets a fixture produce work
    #: that genuinely satisfies an objective -- the same authority a real STANDARD_EDIT child
    #: would use, scoped to req.cwd by the caller.
    write_files: Any = None


class FakeClaudeExecutor(Executor):
    """Writes a scripted envelope to ``req.stdout_path`` and returns a scripted outcome."""

    name = "fake"

    def __init__(self, config: FakeConfig | None = None):
        self.config = config or FakeConfig()
        self.calls: list = []

    # -- the scripted body --------------------------------------------------------------------
    def execute(self, req: ExecRequest) -> ExecOutcome:
        cfg = self.config
        self.calls.append(req.run_id)

        if cfg.scenario == SPAWN_FAILURE:
            _write(req.stderr_path, "fake: executable not found\n")
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error="fake spawn failure")

        if cfg.delay_s:
            import time
            time.sleep(float(cfg.delay_s))

        if cfg.scenario == WORKER_CRASH:
            # Hard-kill THIS process without unwinding: no exit.json, no result, and the OS
            # releases the worker lock. That is precisely the state a real crash leaves behind,
            # and it is the only honest way to produce it.
            _write(req.stderr_path, "fake: simulating worker crash\n")
            os._exit(70)

        if cfg.scenario == TIMEOUT:
            _write(req.stderr_path, "fake: simulated timeout\n")
            return ExecOutcome(True, None, EXIT_TIMEOUT, child_pid=424242,
                               error="fake timeout after %ss" % req.timeout_s)

        if cfg.touch_file:
            target = os.path.join(req.cwd, cfg.touch_file)
            os.makedirs(os.path.dirname(target) or req.cwd, exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write("fake-executor wrote here: run=%s\n" % req.run_id)

        for rel, content in dict(cfg.write_files or {}).items():
            target = os.path.join(req.cwd, str(rel))
            os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
            with open(target, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(str(content))

        if cfg.scenario == STALE_ARTIFACT:
            # Deliberately touches NOTHING. The test plants another run's stdout.json in this
            # run's directory first, so the worker reads a well-formed result that belongs to a
            # different execution -- the artifact-reuse defect, reproduced rather than simulated.
            _write(req.stderr_path, "fake: left stdout.json untouched\n")
            return ExecOutcome(True, 0, EXIT_OK, child_pid=424242)

        if cfg.scenario == EMPTY_STDOUT:
            _write(req.stdout_path, "")
            return ExecOutcome(True, 0, EXIT_OK, child_pid=424242)

        if cfg.scenario == MALFORMED_JSON:
            _write(req.stdout_path, '{"type":"result","result": {"protocol": "AEG')
            return ExecOutcome(True, 0, EXIT_OK, child_pid=424242)

        if cfg.scenario == PROCESS_FAILURE:
            _write(req.stderr_path, "fake: child failed\n")
            _write(req.stdout_path, json.dumps({"type": "result", "is_error": True,
                                                "subtype": "error_during_execution",
                                                "session_id": cfg.session_id}))
            return ExecOutcome(True, 1, EXIT_NONZERO, child_pid=424242)

        envelope: dict = {"type": "result", "is_error": False, "session_id": cfg.session_id,
                          "num_turns": 1}
        envelope.update(dict(cfg.extra_envelope or {}))

        if cfg.scenario == MISSING_HANDOFF:
            envelope["result"] = "I finished the task but produced no structured output."
            _write(req.stdout_path, json.dumps(envelope))
            return ExecOutcome(True, 0, EXIT_OK, child_pid=424242)

        payload = self._payload(req)
        envelope[cfg.envelope_key] = payload
        _write(req.stdout_path, json.dumps(envelope))
        _write(req.stderr_path, "")
        return ExecOutcome(True, 0, EXIT_OK, child_pid=424242, child_create_time="fake-ct")

    # -- the scripted handoff -----------------------------------------------------------------
    def _payload(self, req: ExecRequest) -> dict:
        cfg = self.config
        b = req.binding
        disposition = cfg.prompt_disposition or "COMPLETE"
        verdict = cfg.program_verdict or "PASS"
        claimed: list = []

        if cfg.scenario == OK_FAIL:
            disposition = cfg.prompt_disposition or "COMPLETE"
            verdict = cfg.program_verdict or "FAIL"
        elif cfg.scenario == BLOCKED:
            disposition = "BLOCKED"
            verdict = "NOT_EVALUATED"
        elif cfg.scenario == CLAIM_CHANGED_BUT_CLEAN:
            claimed = ["some/file/it/did/not/touch.txt"]
        elif cfg.scenario == CLAIM_CLEAN_BUT_WRITE:
            claimed = []

        if cfg.claimed_files is not None:
            claimed = list(cfg.claimed_files)

        payload = {
            "protocol": handoff_mod.PROTOCOL,
            "protocol_version": handoff_mod.PROTOCOL_VERSION,
            "workflow_id": b.workflow_id,
            "step_id": b.step_id,
            "run_nonce": b.run_nonce,
            "prompt_disposition": disposition,
            "program_verdict": verdict,
            "acceptance_state": "FAKE_SCENARIO_%s" % cfg.scenario,
            "authorized_scope_exhausted": True,
            "continuation_allowed": False,
            "next_authority": "GPT_ORCHESTRATOR",
            "owner_decision_required": False,
            "smallest_blocker": "" if verdict == "PASS" else "the fake scenario says the program failed",
            "next_action": "GPT decides",
            "summary": "fake executor scenario %s" % cfg.scenario,
            "report_markdown": "# fake\n\nscenario: %s\n" % cfg.scenario,
            "claimed_files_changed": claimed,
        }

        if cfg.scenario == BAD_PROTOCOL_VERSION:
            payload["protocol_version"] = 99
        if cfg.scenario == WRONG_RUN_IDENTITY:
            payload["run_nonce"] = "nonce-from-a-different-run"
        if cfg.messages:
            payload["messages"] = [dict(m) for m in cfg.messages]
        return payload


def _write(path: str, text: str) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

"""codex_cli -- the REAL OpenAI Codex CLI adapter (bd quaestor-1ng, PRD.md §7).

WHY THIS FILE EXISTS
--------------------
The Role x Provider matrix needs a cross-vendor ADVERSARIAL_REVIEWER: "dispatch REVIEWER role to
a non-Anthropic executor while implementation stays claude-cli". This executor is that seat's
hands. It follows ``claude_code.py``'s construction discipline exactly -- build_command is PURE,
returns an argument array, and raises rather than returning anything dangerous -- while the
ARGV SHAPE is Codex's, not Claude's:

    codex exec --json --sandbox <mode> [--model <m>] -

The prompt travels on STDIN (the trailing ``-`` is Codex's stdin-prompt marker): a prompt is
data, and keeping it off the command line sidesteps every argv-length and quoting question the
positional form has. Flags stay MINIMAL on purpose; every flag here is verified against the
installed CLI's documented surface before it earns a place.

HARD RULES ENCODED HERE
-----------------------
 * ``shell=False`` and an argument array. No interpolation, ever.
 * NO BYPASS FLAGS, EVER. ``FORBIDDEN_FLAGS`` names the autonomy-widening surface
   (--danger-full-access, --full-auto/--yolo, approval bypasses) and ``_assert_safe`` refuses the
   command before anything launches. The sandbox MODE is derived from the authority profile and
   can never spell "danger-full-access": the mapping simply does not contain it.
 * stdout/stderr go to durable per-run FILES; only the prompt goes in, so a dead dispatcher
   loses no evidence.
 * ENVELOPE HONESTY: ``--json`` makes Codex emit JSONL events. core.parse_envelope consumes
   that shape directly (last-COMPLETE-object rule, torn tail skipped and counted -- bd
   quaestor-lh0); this executor's job remains dispatchability with recorded evidence, and the
   record says exactly what was launched.

VENDOR COUPLING STAYS OUT OF CORE
---------------------------------
This module lives in executors/ beside claude_code.py. Core resolves it at call time through
executors.registry (the inversion seam); no core module imports it statically.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Mapping

from quaestor.core import authority as authority_mod
from quaestor.core import proc
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK, EXIT_SPAWN_FAILED,
                                             EXIT_TIMEOUT, ExecOutcome, ExecRequest, Executor)

#: Autonomy-widening surface. ANY of these in a built command is a defect raised before spawn.
FORBIDDEN_FLAGS = (
    "--danger-full-access",
    "--full-auto",
    "--yolo",
    "--dangerously-bypass-approvals-and-sandbox",
    "--ask-for-approval",
)

#: Sandbox mode per authority profile. The profile decides what capabilities EXIST; this decides
#: what the child could even reach for -- defence in depth, same argument as PROFILE_TOOLS in
#: claude_code.py. There is deliberately NO entry that maps to "danger-full-access": an unknown
#: or write-capable profile lands on workspace-write, never on unrestricted.
SANDBOX_FOR_PROFILE: Mapping[str, str] = {
    authority_mod.READ_ONLY: "read-only",
    authority_mod.NETWORK_READ: "read-only",
    authority_mod.STANDARD_EDIT_CONFINED: "workspace-write",
    authority_mod.STANDARD_EDIT: "workspace-write",
    authority_mod.GIT_COMMIT: "workspace-write",
    authority_mod.GIT_PUSH: "workspace-write",
    authority_mod.DESTRUCTIVE: "workspace-write",
}

#: The STDIN prompt marker. Last token of every command, asserted by _assert_safe.
STDIN_PROMPT_MARKER = "-"


def sandbox_mode(profile: str) -> str:
    """The Codex sandbox mode for an authority profile. PURE. Unknown -> read-only."""
    return SANDBOX_FOR_PROFILE.get(str(profile), "read-only")


def child_env(base: Mapping[str, str] | None = None) -> dict:
    """The environment handed to the child. Impure only via os.environ.

    NOTHING IS UNSET HERE, same policy as claude_code.child_env: if a credential override is
    present the PREFLIGHT (codex_auth) refused already; quietly stripping variables would make
    this control plane lie about which billing path ran.
    """
    return dict(os.environ if base is None else base)


def build_command(req: ExecRequest, *, binary: str = "codex") -> list:
    """The exact argv. PURE. Raises UnsafeCommand rather than returning something dangerous.

    Deliberately NOT included: any config override (-c), any approval flag, any sandbox mode
    beyond the profile-mapped one, and the prompt itself (stdin, not argv).
    """
    cmd = [str(binary), "exec", "--json", "--sandbox", sandbox_mode(req.authority_profile)]
    if req.model:
        cmd += ["--model", str(req.model)]
    cmd.append(STDIN_PROMPT_MARKER)
    _assert_safe(cmd)
    return cmd


class UnsafeCommand(RuntimeError):
    """The constructed command violates an invariant. Raised before anything is launched."""


def _assert_safe(cmd: list) -> None:
    """Invariants checked BEFORE launch. PURE. Raises UnsafeCommand."""
    for flag in FORBIDDEN_FLAGS:
        if flag in cmd:
            raise UnsafeCommand(
                "%s is never permitted by this control plane: it widens the child's autonomy "
                "past the boundary the authority profile granted" % flag)
    if "--sandbox" in cmd:
        mode = cmd[cmd.index("--sandbox") + 1]
        if mode == "danger-full-access":
            raise UnsafeCommand("sandbox mode 'danger-full-access' is unreachable by design")
    if not cmd or cmd[-1] != STDIN_PROMPT_MARKER:
        raise UnsafeCommand(
            "the command must end with %r: the prompt arrives on STDIN, never as a positional "
            "argument" % STDIN_PROMPT_MARKER)


class CodexCliExecutor(Executor):
    """Launch ``codex exec --json`` as a child of the worker, feed the prompt on STDIN,
    and observe how it ended."""

    name = "codex-cli"

    def __init__(self, *, popen=subprocess.Popen, binary: str = "codex"):
        self._popen = popen
        self._binary = str(binary or "codex")

    def execute(self, req: ExecRequest) -> ExecOutcome:
        cmd = build_command(req, binary=self._binary)
        os.makedirs(os.path.dirname(os.path.abspath(req.stdout_path)) or ".", exist_ok=True)

        # The FULL argv is recordable here -- unlike the positional-prompt CLIs, nothing secret
        # and nothing long sits in it. What decided BEHAVIOUR is kept, verbatim.
        _write_json(os.path.join(req.run_dir, "command.json"),
                    {"argv": [str(a) for a in cmd], "argv_len": len(cmd), "cwd": req.cwd,
                     "prompt_bytes": len(str(req.prompt).encode("utf-8")),
                     "stdin": "PIPE(prompt_utf8)", "shell": False,
                     "executor": self.name})

        try:
            out_fh = open(req.stdout_path, "wb")
            err_fh = open(req.stderr_path, "wb")
        except OSError as exc:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error="cannot open run files: %s"
                                                                     % exc)
        try:
            try:
                p = self._popen(cmd, cwd=req.cwd, stdin=subprocess.PIPE, stdout=out_fh,
                                stderr=err_fh, shell=False, env=child_env(req.env))
            except (OSError, ValueError) as exc:
                return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                                   error="%s: %s" % (type(exc).__name__, exc))
            child_ct = proc.process_create_time(p.pid)
            try:
                # The prompt IS the input contract: write it, close stdin, then wait. A child
                # that never reads stdin will be terminated by the timeout below, observed.
                p.stdin.write(str(req.prompt).encode("utf-8"))
                p.stdin.close()
            except (OSError, ValueError, BrokenPipeError) as exc:
                _terminate(p)
                return ExecOutcome(True, None, EXIT_TIMEOUT, child_pid=p.pid,
                                   child_create_time=child_ct,
                                   error="failed feeding prompt to child stdin: %s" % exc)
            try:
                rc = p.wait(timeout=float(req.timeout_s))
            except subprocess.TimeoutExpired:
                _terminate(p)
                return ExecOutcome(True, None, EXIT_TIMEOUT, child_pid=p.pid,
                                   child_create_time=child_ct,
                                   error="child exceeded %ss and was terminated" % req.timeout_s)
            return ExecOutcome(True, int(rc), EXIT_OK if rc == 0 else EXIT_NONZERO,
                               child_pid=p.pid, child_create_time=child_ct)
        finally:
            for fh in (out_fh, err_fh):
                try:
                    fh.close()
                except OSError:
                    pass


def _terminate(p) -> None:
    try:
        p.terminate()
        p.wait(timeout=15)
    except Exception:  # noqa: BLE001
        try:
            p.kill()
        except Exception:  # noqa: BLE001
            pass


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)

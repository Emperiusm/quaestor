"""cli_executor -- the REAL Claude Code adapter.

CONSTRUCTION IS PURE, EXECUTION IS THIN
---------------------------------------
``build_command`` is a pure function returning an argument ARRAY, so the exact command line is
unit-testable without launching Claude, without spending subscription capacity, and without a
single conditional hiding inside the spawn path.

HARD RULES ENCODED HERE
-----------------------
 * ``shell=False`` and an argument array. No interpolation, ever. A prompt containing quotes,
   newlines or ``&&`` is data.
 * NEVER ``--dangerously-skip-permissions`` / ``--allow-dangerously-skip-permissions``. Enforced
   by ``FORBIDDEN_FLAGS`` and asserted by a test, because a rule that lives only in a docstring
   is a rule that gets edited away.
 * NEVER ``--bare``. Anthropic documents bare mode as skipping OAuth/keychain reads and expecting
   API-key/helper auth -- which is the exact billing path the owner excluded. The preflight
   refuses on ``ANTHROPIC_API_KEY``; using ``--bare`` would require one.
 * stdin is explicitly ``DEVNULL``. A child that inherits a console stdin can block forever
   waiting for input nobody will type.
 * stdout and stderr go to durable per-run FILES, not to pipes owned by this process. Pipes die
   with the reader; the whole point of the detached worker is that a dead dispatcher loses no
   evidence.

ARGUMENT ORDER IS LOAD-BEARING -- see ``_assert_prompt_is_safe_last``. Several of the installed
CLI's options are VARIADIC (``--tools <tools...>``, ``--allowedTools <tools...>``), and a variadic
option immediately preceding the positional prompt would swallow the prompt as one of its values.
The prompt is therefore always last AND always preceded by a non-variadic option's value.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import authority as authority_mod
from quaestor.core import proc
from quaestor.core.canon import canonical_json
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK, EXIT_SPAWN_FAILED, EXIT_TIMEOUT, ExecOutcome,
                       ExecRequest, Executor)

FORBIDDEN_FLAGS = (
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
    "--bare",
)

#: Options the installed CLI declares as variadic (``<x...>``). Verified against
#: ``claude --help`` for 2.1.x. Anything listed here must never be the last option before the
#: positional prompt.
VARIADIC_OPTS = ("--tools", "--allowedTools", "--allowed-tools", "--disallowedTools",
                 "--disallowed-tools", "--add-dir", "--mcp-config", "--file", "--betas")

#: Built-in tool sets per authority profile. This is defence in depth on top of the policy
#: engine: the profile decides whether a capability EXISTS, and this decides what the child is
#: even able to reach for. Neither is sufficient alone -- the policy engine is the boundary that
#: refuses, and this is the one that keeps an authorized run from wandering.
PROFILE_TOOLS: Mapping[str, tuple] = {
    authority_mod.READ_ONLY: ("Read", "Glob", "Grep"),
    authority_mod.STANDARD_EDIT_CONFINED: ("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
    authority_mod.NETWORK_READ: ("Read", "Glob", "Grep", "WebFetch", "WebSearch"),
    authority_mod.STANDARD_EDIT: ("Read", "Glob", "Grep", "Edit", "Write"),
    authority_mod.GIT_COMMIT: ("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
    authority_mod.GIT_PUSH: ("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
    authority_mod.DESTRUCTIVE: ("Read", "Glob", "Grep", "Edit", "Write", "Bash"),
}

#: Permission mode per profile. ``default`` for read-only runs: with no edit tools available
#: there is nothing to approve, and a mode that auto-accepts edits on a read-only run would be a
#: contradiction sitting in the command line waiting for someone to widen the tool list.
PROFILE_PERMISSION_MODE: Mapping[str, str] = {
    authority_mod.READ_ONLY: "default",
    authority_mod.STANDARD_EDIT_CONFINED: "acceptEdits",
    authority_mod.NETWORK_READ: "default",
    authority_mod.STANDARD_EDIT: "acceptEdits",
    authority_mod.GIT_COMMIT: "acceptEdits",
    authority_mod.GIT_PUSH: "acceptEdits",
    authority_mod.DESTRUCTIVE: "acceptEdits",
}


class UnsafeCommand(RuntimeError):
    """The constructed command violates an invariant. Raised before anything is launched."""


#: Authority profiles that MUST NOT be executed outside a validated container boundary.
CONFINEMENT_REQUIRED_PROFILES = (authority_mod.STANDARD_EDIT_CONFINED,)


#: Blanket ``Bash`` is arbitrary code execution and is NEVER pre-approved, whatever the profile
#: grants. A profile may make Bash REACHABLE (a commit run needs it); only the narrow patterns in
#: PROFILE_BASH_RULES are ever auto-approved. Reachable and auto-approved are two different
#: permissions, and collapsing them is how a commit-capable run quietly becomes a shell.
NEVER_BLANKET_ALLOWED = ("Bash",)

#: The tools worth naming in an explicit deny. ``--disallowedTools`` is computed as this universe
#: MINUS the profile's reachable set, so the deny list and the tool list can never contradict
#: each other -- a hand-maintained pair of lists is a pair of lists that will one day disagree.
DANGEROUS_UNIVERSE = ("Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Task")

#: Narrow, auto-approvable shell rules per profile. Nothing here can write outside git's own
#: plumbing, and ``git push`` appears only under GIT_PUSH -- which is additionally owner-gated by
#: the policy engine, so this list alone never authorises a push.
PROFILE_BASH_RULES: Mapping[str, tuple] = {
    # BLANKET Bash, and this is the ONE profile that gets it. Permissible only because
    # STANDARD_EDIT_CONFINED cannot execute outside a validated container: with all capabilities
    # dropped, a read-only rootfs, no host filesystem exposure beyond the assigned workspace and
    # no Docker socket, arbitrary shell is bounded by the OUTER boundary rather than by the
    # permission list. That is the P2.5 thesis stated as configuration -- and it is exactly why
    # `build_command` refuses this profile when `container_confined` is not set.
    authority_mod.STANDARD_EDIT_CONFINED: ("Bash",),
    authority_mod.GIT_COMMIT: ("Bash(git status:*)", "Bash(git diff:*)", "Bash(git add:*)",
                               "Bash(git commit:*)"),
    authority_mod.GIT_PUSH: ("Bash(git status:*)", "Bash(git diff:*)", "Bash(git add:*)",
                             "Bash(git commit:*)", "Bash(git push:*)"),
}


def profile_tools(profile: str) -> tuple:
    """Built-in tools this profile may reach for. PURE. Unknown profile -> read-only set."""
    return PROFILE_TOOLS.get(str(profile), PROFILE_TOOLS[authority_mod.READ_ONLY])


def profile_allowed_tools(profile: str) -> tuple:
    """Permission rules PRE-APPROVED for this profile. PURE.

    Pre-approving exactly what the profile already grants is the machine expression of the
    profile, not a widening of it -- with blanket Bash subtracted and replaced by named rules.
    """
    base = tuple(t for t in profile_tools(profile) if t not in NEVER_BLANKET_ALLOWED)
    extra = PROFILE_BASH_RULES.get(str(profile), ())
    return tuple(dict.fromkeys(base + extra))


def profile_disallowed_tools(profile: str) -> tuple:
    """Dangerous tools this profile may NOT reach. PURE. Derived, never hand-maintained."""
    reachable = set(profile_tools(profile))
    return tuple(t for t in DANGEROUS_UNIVERSE if t not in reachable)


def permission_mode(profile: str) -> str:
    """PURE. Unknown profile -> the most restrictive mode we have."""
    return PROFILE_PERMISSION_MODE.get(str(profile), "default")


def build_command(req: ExecRequest) -> list:
    """The exact argv. PURE. Raises UnsafeCommand rather than returning something dangerous.

    Deliberately NOT included:
      * ``--add-dir``      -- the child gets exactly its worktree and nothing else.
      * ``--resume``       -- a resumed session carries context this dispatch did not authorize.
      * ``--settings``     -- ambient configuration is what the run identity cannot capture.
      * any permission bypass (see FORBIDDEN_FLAGS).
    """
    if str(req.authority_profile) in CONFINEMENT_REQUIRED_PROFILES \
            and getattr(req, "container_confined", False) is not True:
        raise UnsafeCommand(
            "%s may only execute inside a validated container confinement boundary. It was "
            "requested without one, which would place an edit-capable child on the native host "
            "with the host filesystem in reach -- the precise arrangement P2.5 exists to "
            "replace. Refusing." % req.authority_profile)

    cmd = [str(req.claude_path), "--print", "--output-format", "json",
           "--json-schema", canonical_json(dict(req.json_schema)),
           "--no-chrome",
           # No ambient MCP servers. With no --mcp-config supplied, this means NO MCP servers at
           # all: an orchestrated child's tool surface must be the one the authority profile
           # granted, not whatever happens to be configured on the machine. It is an authority
           # control first; the fact that it may also reduce egress is a side benefit.
           "--strict-mcp-config"]

    tools = profile_tools(req.authority_profile)
    if tools:
        cmd += ["--tools", ",".join(tools)]
    allowed = profile_allowed_tools(req.authority_profile)
    if allowed:
        cmd += ["--allowedTools", ",".join(allowed)]
    disallowed = profile_disallowed_tools(req.authority_profile)
    if disallowed:
        cmd += ["--disallowedTools", ",".join(disallowed)]

    if req.model:
        cmd += ["--model", str(req.model)]

    for extra in (req.extra_args or ()):
        cmd.append(str(extra))

    # LAST option before the prompt, and non-variadic on purpose (see module docstring).
    cmd += ["--permission-mode", permission_mode(req.authority_profile)]
    cmd.append(str(req.prompt))

    _assert_safe(cmd)
    return cmd


def _assert_safe(cmd: Sequence[str]) -> None:
    """Invariants checked BEFORE launch. PURE. Raises UnsafeCommand."""
    for flag in FORBIDDEN_FLAGS:
        if flag in cmd:
            raise UnsafeCommand(
                "%s is never permitted by this control plane: it removes the boundary the "
                "control plane exists to enforce" % flag)
    _assert_prompt_is_safe_last(cmd)


#: Options that take NO value. Only after one of these is a bare positional prompt safe.
BOOLEAN_FLAGS = ("--print", "-p", "--no-chrome", "--chrome", "--verbose", "--safe-mode",
                 "--fork-session", "--ide", "--strict-mcp-config", "--no-session-persistence",
                 "--disable-slash-commands", "--ax-screen-reader")


def _assert_prompt_is_safe_last(cmd: Sequence[str]) -> None:
    """The positional prompt must not be swallowed by a preceding option. PURE.

    The failure this prevents is silent and total: ``--tools Read,Glob <prompt>`` parses the
    prompt as another tool NAME, so Claude runs with no prompt and an invalid tool. It would not
    error in an obvious way -- it would produce a confident, empty run.

    Three ways the last two tokens can be wrong, and they are checked separately because they are
    different mistakes:

      * ``... --tools <prompt>``        the variadic consumes the prompt as its only value;
      * ``... --tools Read <prompt>``   the prompt EXTENDS the variadic's value list;
      * ``... --model <prompt>``        a value-taking option consumes the prompt as its value.

    Safe shapes are exactly two: the prompt follows a non-variadic option's VALUE, or it follows
    a boolean flag.
    """
    if len(cmd) < 3:
        raise UnsafeCommand("command is too short to contain a prompt")
    tail2 = str(cmd[-2])
    tail3 = str(cmd[-3])

    if tail2 in VARIADIC_OPTS:
        raise UnsafeCommand(
            "variadic option %r immediately precedes the positional prompt and would consume it "
            "as its value" % tail2)
    if tail2.startswith("-"):
        if tail2 not in BOOLEAN_FLAGS:
            raise UnsafeCommand(
                "the token before the prompt is %r, which takes a value; the prompt would be "
                "parsed as that value rather than as the positional argument" % tail2)
        return
    if tail3 in VARIADIC_OPTS:
        raise UnsafeCommand(
            "the prompt follows a value of the variadic option %r and would extend its value "
            "list" % tail3)


def child_env(base: Mapping[str, str] | None = None) -> dict:
    """The environment handed to the child. Impure only in reading ``os.environ``.

    NOTHING IS UNSET HERE, and that is a policy, not an oversight. If a credential override is
    present the PREFLIGHT refuses the run; quietly stripping the variable would make this control
    plane the component that hides which billing path a run took. See preflight.decide.
    """
    env = dict(os.environ if base is None else base)
    env.setdefault("CLAUDE_CODE_ENTRYPOINT", branding.PRODUCT_NAME)
    return env


class ClaudeCliExecutor(Executor):
    """Launch ``claude -p`` as a child of the worker, and observe how it ended."""

    name = "claude-cli"

    def __init__(self, *, popen=subprocess.Popen):
        self._popen = popen

    def execute(self, req: ExecRequest) -> ExecOutcome:
        cmd = build_command(req)
        os.makedirs(os.path.dirname(os.path.abspath(req.stdout_path)) or ".", exist_ok=True)

        # The command is recorded WITHOUT the prompt body: argv[-1] can be long and is already
        # identified by prompt_sha256 in the dispatch. Everything that decides BEHAVIOUR is kept.
        _write_json(os.path.join(req.run_dir, "command.json"),
                    {"argv_head": [str(a) for a in cmd[:-1]],
                     "argv_len": len(cmd), "cwd": req.cwd,
                     "prompt_bytes": len(str(req.prompt).encode("utf-8")),
                     "stdin": "DEVNULL", "shell": False})

        try:
            out_fh = open(req.stdout_path, "wb")
            err_fh = open(req.stderr_path, "wb")
        except OSError as exc:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error="cannot open run files: %s"
                                                                    % exc)
        try:
            try:
                p = self._popen(cmd, cwd=req.cwd, stdin=subprocess.DEVNULL, stdout=out_fh,
                                stderr=err_fh, shell=False,
                                env=child_env(req.env))
            except (OSError, ValueError) as exc:
                return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                                   error="%s: %s" % (type(exc).__name__, exc))

            child_ct = proc.process_create_time(p.pid)
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

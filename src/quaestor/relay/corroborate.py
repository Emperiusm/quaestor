"""corroborate -- measure whether a completion CLAIM is actually true.

WHY THIS EXISTS
---------------
An Orchestrator that says ``RELAY-OBJECTIVE-COMPLETE`` has made a claim about work it did not
do, cannot see, and cannot run. Treating that sentence as the end of the relay makes the model
the judge of its own homework, which the architecture forbids in exactly the places it matters
most: a completion claim is modelled separately from completion evidence, and acceptance is
decided from verified output rather than self-reported success.

A live run demonstrated the hole rather than predicting it. The Orchestrator declared the
objective met while the fixture's own suite still failed, because nothing between the marker and
the stop reason ever asked the repository.

WHAT THIS MODULE IS, AND WHAT IT DELIBERATELY IS NOT
----------------------------------------------------
It is the smallest provider-neutral rule that closes that hole: run the project's OWN
verification commands, here, in this process, and compare the answer to the claim. It knows
nothing about any provider, any model, or any objective's meaning.

It is NOT an objective-understanding subsystem. It does not parse the objective, does not
reason about intent, and cannot tell you whether the right work was done -- only whether the
checks the operator named still pass and whether the repository actually moved. That is a
deliberately narrow question, and it is the one that was being answered by assumption before.

WHY THE COMMANDS RUN HERE
-------------------------
Same asymmetry ``observe`` exists for. An agent reporting its own test results is the party
being described writing the description. These commands run in this process, against the
authorised project root, and a command that cannot be run at all is UNMEASURABLE -- never
"passed".

WHY THE CEILING IS SPENT ON A FILE AND NOT ON A PIPE
----------------------------------------------------
``--verify-timeout`` is a promise about the RELAY, not about one child process. A check that
starts a server, a watcher, or a test runner that daemonises hands the write end of a captured
pipe to a grandchild the timeout never touches, and the drain that follows the kill then waits
on that orphan rather than on the check -- so the relay sat inside corroboration past its
ceiling with no stop reason and no output. The check's output therefore goes to a file this
process owns, the wait is on the direct child alone, the file is read back under an explicit
BYTE BUDGET -- an orphan still appending to it would otherwise stall the read exactly as it
stalled the drain -- and what the check left running is REPORTED rather than hunted.
``_run_bounded`` carries why hunting it is refused.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import classification

CORROBORATE_INSTRUMENT = "relay.corroborate/1"

#: A completion claim was checked and every check agreed with it.
CORROBORATED = "CORROBORATED"
#: A completion claim was checked and at least one check disagreed with it.
REFUTED = "REFUTED"
#: No corroboration was configured for this relay, so the claim stands UNVERIFIED. This is an
#: honest answer, not a passing one: nothing measured the claim, so nothing supports it.
UNCONFIGURED = "UNCONFIGURED"
#: Corroboration was configured and could not be run (no such command, project unreadable, a
#: check that never returned). Deliberately NOT the same as REFUTED and never the same as
#: CORROBORATED -- an unmeasured check must not be read as a passing one.
UNMEASURABLE = "UNMEASURABLE"

#: Output kept per check. Enough for an operator to see WHY a check disagreed, bounded so a
#: chatty suite cannot push the durable record around.
MAX_TAIL_CHARS = 2000

#: Bytes read back out of the check's output file, and the reason that is a NUMBER rather than
#: "however many there are". Only ``MAX_TAIL_CHARS`` of it survives anyway, and an
#: argument-less ``read()`` is ``readall``, which loops until a read returns zero bytes -- a
#: surviving grandchild still appending to the handle it inherited never lets that zero arrive.
#: Without this budget the unbounded wait the file was introduced to REMOVE would simply have
#: moved from the drain to the read, and taken the operator's disk and this process's memory
#: with it. Comfortably above ``MAX_TAIL_CHARS`` so the tail is never short of material, even
#: for output that is entirely multi-byte.
MAX_SINK_READ_BYTES = 64 * 1024

#: How long a killed check gets to be reaped before ``run_check`` gives up and returns anyway.
#: The ceiling an operator is actually promised is ``--verify-timeout`` PLUS this, per check,
#: and nothing else: the wait is on the DIRECT child, which a kill ends promptly whatever it
#: spawned. Stated as a number rather than left implicit because a ceiling nobody can compute
#: is not a ceiling.
KILL_GRACE_S = 5.0


def _tail(text: str, limit: int = MAX_TAIL_CHARS) -> str:
    s = str(text or "")
    if len(s) <= limit:
        return s
    return "(earlier output omitted)\n" + s[-limit:]


def _split(cmd: str, out: dict):
    """Split an operator's command string into argv. Returns None and fills ``out['error']``.

    WHY NOT ``shlex.split(cmd)``: on Windows POSIX mode eats the backslashes, so
    ``C:\\Python\\python.exe`` becomes ``C:Pythonpython.exe`` and the check cannot be run.
    WHY NOT ``shlex.split(cmd, posix=False)`` ALONE: non-POSIX mode keeps the quotes ATTACHED to
    the token, so ``python -c "raise SystemExit(1)"`` reaches Python as a quoted STRING LITERAL,
    which evaluates fine and exits ZERO. That is the one failure direction this whole module
    exists to prevent: a check that should have failed silently reporting success. It was caught
    by a control, not by reading the code.

    So: split without POSIX escaping (backslashes survive), then strip the matched quotes the
    non-POSIX splitter left behind (the argument arrives as the operator meant it).
    """
    try:
        raw = shlex.split(cmd, posix=False)
    except ValueError as exc:
        out["error"] = "could not parse command: %s" % exc
        return None
    argv = []
    for tok in raw:
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
            tok = tok[1:-1]
        argv.append(tok)
    return argv


def _run_bounded(argv, *, cwd: str, timeout_s: float) -> dict:
    """Run ONE check under a ceiling that is WALL CLOCK time. Impure. Raises only spawn errors.

    WHY NOT ``subprocess.run(capture_output=True, timeout=...)``, WHICH THIS REPLACED
    --------------------------------------------------------------------------------
    ``run`` kills the DIRECT child when the timeout expires and then goes back to
    ``communicate()`` to drain the pipes. A pipe does not reach end-of-file until EVERY process
    holding its write end has exited -- and a check that starts a server, a watcher, or a test
    runner that daemonises hands that write end to a grandchild the timeout never touched. The
    drain then blocks for as long as the orphan lives. The ceiling was a claim about the child;
    the call was bounded by a process nobody was waiting for.

    SO THERE IS NO PIPE. The check writes into a file this process owns, in the system temp
    directory -- never under the project, whose movement is itself evidence this relay reads.
    A file has no end-of-file to wait for -- but it still has a WRITER, so the read back is
    taken under an explicit byte budget. Removing the pipe without that budget would only have
    moved the unbounded wait from ``communicate()`` to ``read()``.

    WHAT THIS DELIBERATELY DOES NOT DO, AND WHY THAT IS NOT AN OVERSIGHT
    -------------------------------------------------------------------
    It does not kill the check's descendants. Both ways of doing that are refused here for the
    reason ``tests/procsafe.kill_argv`` records: walking a parent-pid tree, or signalling a
    process group, once took down the very relay whose survival was being measured and then
    reported the product broken. A surviving orphan is a leak an operator can see and end; a
    relay wedged inside corroboration with no stop reason is not. This bounds the RELAY, and
    the result says plainly that what the check spawned is still running.

    The check is also NOT given a session or process group of its own, which is a decision and
    not an omission: the only use for one would be the group kill above, and creating one costs
    something real -- an orphan left in the relay's own group still dies with the operator's
    Ctrl-C, and a session of its own would take even that away.
    """
    # THE PRODUCT NAME IS NOT SPELLED HERE. Control 172 holds branding.py as the only
    # place this platform names itself, and a hardcoded prefix is exactly the drift it
    # exists to catch -- a rename would leave this one temp file behind, still branded.
    fd, sink_path = tempfile.mkstemp(prefix=branding.resource("check") + "-",
                                     suffix=".out")
    os.close(fd)
    child = None
    timed_out = False
    try:
        try:
            with open(sink_path, "wb") as sink:
                # stdin is DEVNULL rather than inherited. A check that reads a prompt would
                # otherwise take the operator's keystrokes away from the relay and then block
                # on input that is never coming -- a second, quieter way past the ceiling.
                child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                         stdout=sink, stderr=subprocess.STDOUT, shell=False)
            deadline = time.time() + max(0.0, float(timeout_s))
            try:
                child.wait(timeout=max(0.0, deadline - time.time()))
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            # Reached on the timeout AND on anything raised through the wait, Ctrl-C included:
            # a check left running because the caller stopped watching is the leak this module
            # is about, and a ``finally`` is the only cleanup that survives the failure it is
            # there for.
            if child is not None and child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=KILL_GRACE_S)
                except subprocess.TimeoutExpired:
                    pass
        try:
            # THE TAIL, UNDER AN EXPLICIT BYTE BUDGET, AND NEVER ``fh.read()``. See
            # ``MAX_SINK_READ_BYTES``: a read with no argument is bounded by the WRITER, and the
            # writer here may be a process nobody is waiting for. ``buffering=0`` is part of the
            # fix rather than a detail -- it makes this ONE ``os.read`` that returns at or
            # before the budget, where a buffered ``read(n)`` keeps asking until it has n bytes,
            # which against a file still being appended to is the same unbounded wait in a
            # smaller costume.
            size = os.path.getsize(sink_path)
            with open(sink_path, "rb", buffering=0) as fh:
                if size > MAX_SINK_READ_BYTES:
                    fh.seek(size - MAX_SINK_READ_BYTES)
                data = fh.read(MAX_SINK_READ_BYTES) or b""
        except OSError:
            data = b""
        return {"returncode": child.returncode, "output": data, "timed_out": timed_out,
                "pid": int(child.pid)}
    finally:
        # EMPTIED BEFORE IT IS UNLINKED, because the unlink is the step that fails. A descendant
        # that outlived the check still holds this file open and on Windows ``os.remove`` then
        # refuses -- and that is not the rare case here but the ORDINARY one, since a surviving
        # grandchild is the shape this module exists for. What the file holds is the check's RAW
        # output, the one copy of it that ``classification.classify`` never sees, so a removal
        # that cannot succeed must leave a zero-length file rather than a plaintext credential
        # in the temp directory for good. Both steps stay best-effort: a temp file is not worth
        # a hang.
        try:
            with open(sink_path, "r+b") as fh:
                fh.truncate(0)
        except OSError:
            pass
        try:
            os.remove(sink_path)
        except OSError:
            pass


def run_check(command, *, project_root: str, timeout_s: float = 300.0,
              at: float = 0.0) -> dict:
    """Run ONE verification command in the project. Impure. NEVER raises.

    ``ok`` is True only when the command really ran and really exited zero. Every other
    outcome -- not found, timed out, unparseable, project missing -- lands on ``ok=False`` with
    ``measured=False``, so a caller cannot mistake "could not ask" for "answered yes".
    """
    # ``at`` stamps WHEN corroboration began, shared by every check so the verdict has one
    # timestamp. Duration must not be derived from it: with several checks the later ones would
    # report the elapsed total and an operator reading "180s" would blame the wrong command.
    stamp = float(at or time.time())
    started = time.time()
    out = {
        "command": str(command or ""),
        "ok": False,
        "measured": False,
        "exit_code": None,
        "error": "",
        "tail": "",
        "timed_out": False,
        "killed": None,
        "duration_s": 0.0,
        "at": stamp,
        "instrument": CORROBORATE_INSTRUMENT,
    }
    if isinstance(command, (list, tuple)):
        # The unambiguous form. An operator who gives an argv never meets a quoting rule.
        argv = [str(a) for a in command if str(a) != ""]
        out["command"] = " ".join(argv)
        cmd = out["command"]
    else:
        cmd = str(command or "").strip()
        argv = None
    if not cmd:
        out["error"] = "empty command"
        return out
    if not os.path.isdir(project_root):
        out["error"] = "project root is not a directory: %s" % project_root
        return out
    if argv is None:
        argv = _split(cmd, out)
        if argv is None:
            return out
    if not argv:
        out["error"] = "command parsed to nothing"
        return out
    try:
        p = _run_bounded(argv, cwd=project_root, timeout_s=float(timeout_s))
    except FileNotFoundError:
        out["error"] = "no such command: %s" % argv[0]
        return out
    except OSError as exc:
        out["error"] = "could not run check: %s" % exc
        return out
    out["duration_s"] = round(time.time() - started, 3)
    # BYTES, then an explicit decode -- the same seam ``workspace.git`` uses, and the reason the
    # static gate refuses ``text=True``: a check that prints a byte the ambient locale cannot
    # decode would otherwise raise here, and a check that CRASHED THE CHECKER must never be
    # indistinguishable from a check that failed honestly.
    #
    # REDACTED AT THE SOURCE, ON BOTH PATHS. A check's output is arbitrary project text that
    # reaches two places a credential must never reach: the durable event log, and -- as a
    # blocker explaining what failed -- a REMOTE PROVIDER. A failing test that dumps the config
    # it loaded is ordinary. Classifying here rather than at each consumer means a future
    # consumer cannot forget, and a KILLED check is now such a consumer: it used to carry no
    # output at all, so the timeout path would have been a new way out for the same secret.
    raw = (p["output"] or b"").decode("utf-8", "replace")
    safe = classification.classify(raw)
    out["tail"] = _tail(safe.text)
    out["redacted"] = bool(getattr(safe, "findings", None) or safe.text != raw)
    if p["timed_out"]:
        # NAMES WHAT WAS ENDED AND WHAT WAS NOT. "It was killed" reads as a promise that nothing
        # of the check survives, and that promise is one this module cannot keep -- so it is not
        # made. An operator told a pid is loose can end it; one told nothing hunts a hang
        # somewhere else.
        out["timed_out"] = True
        out["killed"] = {"pid": p["pid"], "command": out["command"]}
        out["error"] = ("check exceeded %ss; the check process (pid %s) was killed. Anything it "
                        "spawned was NOT killed and may still be running."
                        % (timeout_s, p["pid"]))
        return out
    out["measured"] = True
    out["exit_code"] = int(p["returncode"])
    out["ok"] = p["returncode"] == 0
    return out


def verdict(*, project_root: str, checks: Sequence[str] = (),
            require_repo_change: bool = False,
            repo_changed: bool | None = None,
            timeout_s: float = 300.0, at: float = 0.0) -> dict:
    """Measure a completion claim. Impure (runs the checks). NEVER raises.

    ``repo_changed`` is passed IN rather than measured here: the kernel already holds the
    independent observations taken across the whole relay, and re-deriving it here would be a
    second, weaker answer to a question already answered well.

    Passing ``None`` for ``repo_changed`` while requiring it means the repository could not be
    read, which is UNMEASURABLE -- not a pass.
    """
    now = float(at or time.time())
    results = [run_check(c, project_root=project_root, timeout_s=timeout_s, at=now)
               for c in (checks or ()) if str(c or "").strip()]

    repo = {"required": bool(require_repo_change), "changed": repo_changed,
            "measured": repo_changed is not None}
    configured = bool(results) or bool(require_repo_change)

    if not configured:
        state = UNCONFIGURED
        reason = ("no completion corroboration is configured for this relay, so the "
                  "Orchestrator's completion claim is UNVERIFIED -- recorded, not confirmed")
    elif any(not r["measured"] for r in results) or (require_repo_change and repo_changed is None):
        state = UNMEASURABLE
        broken = [r["command"] for r in results if not r["measured"]]
        reason = ("completion corroboration could not be measured (%s); an unmeasured check is "
                  "never read as a passing one"
                  % ("; ".join(broken) or "the repository could not be read"))
    elif all(r["ok"] for r in results) and (not require_repo_change or bool(repo_changed)):
        state = CORROBORATED
        reason = ("the completion claim is corroborated by %d independently measured check(s)"
                  % len(results)) if results else \
                 "the completion claim is corroborated by the observed repository change"
    else:
        state = REFUTED
        failed = ["%s (exit %s)" % (r["command"], r["exit_code"]) for r in results if not r["ok"]]
        if require_repo_change and not repo_changed:
            failed.append("the repository never changed during this relay")
        reason = ("the completion claim is REFUTED by independent measurement: %s"
                  % "; ".join(failed))

    return {
        "state": state,
        "reason": reason,
        "checks": results,
        "repo": repo,
        "at": now,
        "instrument": CORROBORATE_INSTRUMENT,
    }


def blocker_line(v: Mapping) -> str:
    """One line an Orchestrator can act on, built from a verdict. Pure."""
    state = str((v or {}).get("state") or "")
    reason = str((v or {}).get("reason") or "")
    if state == REFUTED:
        head = "You declared the objective complete. Independent measurement disagrees."
    elif state == UNMEASURABLE:
        head = ("You declared the objective complete. The relay could not measure the "
                "verification checks, so the claim is not accepted.")
    else:
        return ""
    tails = []
    for c in (v or {}).get("checks") or ():
        if c.get("ok"):
            continue
        # ERROR THEN OUTPUT, both when both exist. A killed check now carries the output it
        # managed to produce, and reading only that would have told the Orchestrator a check
        # failed while hiding that it was never allowed to finish.
        t = "\n".join(x for x in (str(c.get("error") or "").strip(),
                                  str(c.get("tail") or "").strip()) if x)
        if t:
            tails.append("  %s ->\n%s" % (c.get("command"), t))
    body = "\n".join(tails)
    return "%s %s%s" % (head, reason, ("\n" + body) if body else "")

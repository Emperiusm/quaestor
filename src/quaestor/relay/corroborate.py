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
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Mapping, Sequence

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
        # BYTES, then an explicit decode -- the same seam ``workspace.git`` uses, and the reason
        # the static gate refuses ``text=True``: a check that prints a byte the ambient locale
        # cannot decode would otherwise raise here, and a check that CRASHED THE CHECKER must
        # never be indistinguishable from a check that failed honestly.
        p = subprocess.run(argv, cwd=project_root, capture_output=True,
                           timeout=float(timeout_s), shell=False)
    except FileNotFoundError:
        out["error"] = "no such command: %s" % argv[0]
        return out
    except subprocess.TimeoutExpired:
        out["error"] = "check exceeded %ss and was killed" % timeout_s
        out["duration_s"] = round(time.time() - started, 3)
        return out
    except OSError as exc:
        out["error"] = "could not run check: %s" % exc
        return out
    out["measured"] = True
    out["exit_code"] = int(p.returncode)
    out["ok"] = p.returncode == 0
    # REDACTED AT THE SOURCE. A check's output is arbitrary project text that reaches two places
    # a credential must never reach: the durable event log, and -- as a blocker explaining what
    # failed -- a REMOTE PROVIDER. A failing test that dumps the config it loaded is ordinary.
    # Classifying here rather than at each consumer means a future consumer cannot forget.
    raw = ((p.stdout or b"").decode("utf-8", "replace")
           + (p.stderr or b"").decode("utf-8", "replace"))
    safe = classification.classify(raw)
    out["tail"] = _tail(safe.text)
    out["redacted"] = bool(getattr(safe, "findings", None) or safe.text != raw)
    out["duration_s"] = round(time.time() - started, 3)
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
        t = str(c.get("tail") or c.get("error") or "").strip()
        if t:
            tails.append("  %s ->\n%s" % (c.get("command"), t))
    body = "\n".join(tails)
    return "%s %s%s" % (head, reason, ("\n" + body) if body else "")

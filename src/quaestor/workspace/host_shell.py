"""host_shell -- resolve GIT BASH deliberately, and verify it by behaviour rather than by name.

WHY THIS IS A MODULE AND NOT A STRING
-------------------------------------
MEASURED IN P2, 2026-08-13. Invoking a bare ``bash`` from Python on this box resolves to **WSL
bash** (``C:/WINDOWS/system32/bash``), not Git Bash. Under WSL, ``scripts/worktree-new.sh``
computes ``$(cd "$WT" && pwd)`` as ``/mnt/c/...``; its canonicaliser rewrites the MSYS form
``/c/x`` -> ``C:/x`` but has no case for ``/mnt/c/...``. The stamp it writes therefore declares a
path that is not the path it lives at, so the source deployment's own ownership marker reads it as
FOREIGN -- and a FOREIGN marker protects nothing. The worktree is created and silently unowned.
(WSL also does not carry the branch/session environment across, so both fall back to
defaults.)

That defect is in the source deployment and is deliberately NOT fixed by this project. The mitigation is on our
side: resolve the shell, then prove what it DOES. Both executables are called ``bash.exe``, so
checking the filename establishes nothing.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from quaestor import branding

MSYS = "MSYS"
WSL = "WSL"
UNKNOWN = "UNKNOWN"


def verify_shell_class(bash_path: str) -> tuple:
    """(class, detail). Ask the shell to print a path and read its spelling. Impure. NEVER raises.

    A POSITIVE CONTROL ON THE INSTRUMENT: WSL answers ``/mnt/c/...`` for a Windows directory,
    MSYS/Git Bash answers ``/c/...``. This is a behavioural discriminator, which is the only kind
    that survives two programs sharing a name.
    """
    try:
        p = subprocess.run([bash_path, "-lc", "pwd"], cwd="C:/", capture_output=True, shell=False,
                           timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return UNKNOWN, "%s: %s" % (type(exc).__name__, exc)
    if p.returncode != 0:
        return UNKNOWN, "rc=%d %s" % (p.returncode, p.stderr.decode("utf-8", "replace")[:200])
    out = p.stdout.decode("utf-8", "replace").strip()
    if out.startswith("/mnt/"):
        return WSL, ("answered %r -- WSL, whose /mnt/<drive>/ paths worktree-new.sh cannot "
                     "canonicalise" % out)
    if out.startswith("/") and len(out) >= 2:
        return MSYS, "answered %r (MSYS form)" % out
    return UNKNOWN, "answered %r -- unrecognised path form" % out


def find_git_bash() -> tuple:
    """(path|None, detail). Locate a VERIFIED MSYS/Git Bash. Impure. NEVER raises.

    Candidate order: explicit override, then derived from the resolved ``git`` executable, then
    the conventional install locations. Every candidate is verified before it is accepted, and a
    candidate that verifies as WSL is REJECTED rather than used with a warning.
    """
    candidates = []
    override = os.environ.get(branding.env_var("bash"))
    if override:
        candidates.append(override)
    git_exe = shutil.which("git")
    if git_exe:
        root = os.path.dirname(os.path.dirname(os.path.abspath(git_exe)))
        candidates.append(os.path.join(root, "bin", "bash.exe"))
        candidates.append(os.path.join(os.path.dirname(root), "bin", "bash.exe"))
    candidates += [r"C:\Program Files\Git\bin\bash.exe",
                   r"C:\Program Files (x86)\Git\bin\bash.exe"]

    tried, seen = [], set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if not os.path.isfile(cand):
            tried.append({"path": cand, "exists": False})
            continue
        cls, detail = verify_shell_class(cand)
        tried.append({"path": cand, "exists": True, "class": cls, "detail": detail})
        if cls == MSYS:
            return cand, {"chosen": cand, "class": cls, "verification": detail, "tried": tried}
    return None, {"chosen": None, "tried": tried,
                  "error": "no MSYS/Git Bash could be located AND verified; refusing to run the "
                           "canonical repository helper under an unverified shell"}

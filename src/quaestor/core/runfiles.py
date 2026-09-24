"""runfiles -- the durable per-run artifact directory, written atomically.

    runs/<run-id>/request.json    what was dispatched, and under whose identity
    runs/<run-id>/worker.json     which process owns it, and how to prove that later
    runs/<run-id>/worker.lock     held by the worker for its whole life (proc.WorkerLock)
    runs/<run-id>/stdout.json     the child's stdout, byte for byte
    runs/<run-id>/stderr.log      the child's stderr, byte for byte
    runs/<run-id>/exit.json       the terminal receipt: it existing IS the claim of termination
    runs/<run-id>/evidence.json   what the BRIDGE measured
    runs/<run-id>/handoff.json    what goes to GPT

THE DATABASE IS THE STATE MACHINE; THESE ARE THE ARTIFACTS. They exist so a dispatcher that
died can reconstruct what a worker did without asking the worker, and so evidence survives a
corrupted database.

EVERY STATE-BEARING WRITE IS TEMP-FILE + ATOMIC RENAME. A half-written ``exit.json`` is
indistinguishable from a crash that happened before the write, and those must not be confused:
one means the run ended, the other means we do not know. ``os.replace`` is atomic on both NTFS
and POSIX, so a reader sees the old file or the new one and never a torn one.
"""
from __future__ import annotations

import json
import os
from typing import Any

REQUEST = "request.json"
WORKER = "worker.json"
LOCK = "worker.lock"
STDOUT = "stdout.json"
STDERR = "stderr.log"
EXIT = "exit.json"
EVIDENCE = "evidence.json"
HANDOFF = "handoff.json"
COMMAND = "command.json"


def run_dir(root: str, run_id: str) -> str:
    return os.path.join(str(root), str(run_id)).replace("\\", "/")


def ensure(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def p(run_dir_path: str, name: str) -> str:
    return os.path.join(str(run_dir_path), name).replace("\\", "/")


def write_json(path: str, obj: Any) -> None:
    """Atomic JSON write. NEVER leaves a torn file behind."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def read_json(path: str) -> Any:
    """Parsed JSON, or None when absent/unreadable/invalid. NEVER raises.

    None means "no readable record", which is NOT the same as an empty record -- callers must
    branch on it. (absent is not zero.)
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, UnicodeError):
        return None


def read_text(path: str, *, limit: int | None = None) -> str:
    """UTF-8 text, or "". NEVER raises. Explicit decode -- never the locale codepage."""
    try:
        with open(path, "rb") as fh:
            data = fh.read() if limit is None else fh.read(int(limit))
        return data.decode("utf-8", "replace")
    except OSError:
        return ""


def exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False

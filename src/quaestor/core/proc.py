"""proc -- process liveness, WITHOUT using PID existence as proof.

WHY A PID IS NOT AN ANSWER
--------------------------
PIDs are reused. A recorded pid that "exists" may be a completely different program, and on a
box that has been up for a while that is not a theoretical concern. the source deployment's ownership helper
records a pid and then depends on NOTHING from it, explicitly preferring an honest gap to a
fabricated signal. This module does the same thing, plus one signal that is genuinely strong.

TWO INDEPENDENT SIGNALS
-----------------------
 1. AN OS ADVISORY LOCK held for the worker's entire life. The kernel releases it when the
    process dies, however it dies -- crash, kill -9, power loss on the process. Nothing the
    worker forgets to do can make this lie. This is the primary signal.
 2. PID + PROCESS CREATION TIME. The pair is a real identity; the pid alone is not. Used as
    corroboration and to detect pid reuse.

TRI-STATE, ALWAYS. ``ALIVE`` / ``DEAD`` / ``UNKNOWN``. UNKNOWN is not DEAD -- collapsing them is
precisely how the GPU reaper terminated a live box, and here it would mean releasing a lease on a
worker that is still editing files.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

ALIVE = "ALIVE"
DEAD = "DEAD"
UNKNOWN = "UNKNOWN"

# Lock probe outcomes
LOCK_HELD = "LOCK_HELD"
LOCK_FREE = "LOCK_FREE"
LOCK_ABSENT = "LOCK_ABSENT"        # the file was never created -> the worker never got that far
LOCK_UNKNOWN = "LOCK_UNKNOWN"

_IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------------------------
# OS advisory lock
# ---------------------------------------------------------------------------------------------
class WorkerLock:
    """An exclusive lock held for the lifetime of a worker process.

    Deliberately NOT a context manager that releases on ``__exit__`` only: the worker calls
    ``acquire()`` and simply never releases, so the OS is the one that publishes its death. An
    explicit ``release()`` exists for tests.
    """

    def __init__(self, path: str):
        self.path = str(path)
        self._fh = None

    def acquire(self) -> bool:
        """True if we now hold it. False if somebody else does. Impure. NEVER raises."""
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            fh = open(self.path, "a+b")
        except OSError:
            return False
        try:
            _lock_nb(fh)
        except OSError:
            try:
                fh.close()
            except OSError:
                pass
            return False
        self._fh = fh
        return True

    def release(self) -> None:
        fh, self._fh = self._fh, None
        if fh is None:
            return
        try:
            _unlock(fh)
        except OSError:
            pass
        try:
            fh.close()
        except OSError:
            pass


def _lock_nb(fh) -> None:
    if _IS_WINDOWS:
        import msvcrt
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fh) -> None:
    if _IS_WINDOWS:
        import msvcrt
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def probe_lock(path: str) -> str:
    """Is anybody holding ``path``? Impure. NEVER raises.

    Implemented by TRYING to take it and immediately giving it back. Success proves nobody held
    it, and unlike a heartbeat mtime this probe cannot contaminate the signal it measures (the
    source deployment: the sweeper's own `git status` refreshed the index it was reading).

    FAILURE IS NOT ONE THING, AND THE LOCK CALL STILL REPORTS IT AS ONE. Only some errnos mean
    held: EACCES from ``msvcrt.locking(LK_NBLCK)`` on Windows, EWOULDBLOCK/EAGAIN from
    ``fcntl.flock(LOCK_NB)`` on POSIX -- and the two families do not overlap, because EWOULDBLOCK
    on Windows is a Winsock number a file lock never returns. ENOLCK, EIO and EBADF mean the
    kernel could not answer at all, and LOCK_UNKNOWN is the honest verdict for them. THIS
    FUNCTION DOES NOT READ ``errno`` ANYWHERE: the ``except OSError`` below is unconditional, so
    the discrimination described in this paragraph is a description of the kernel, not of the
    code under it.

    LOCK_UNKNOWN IS REACHABLE -- FROM THE OPEN, NOT FROM THE LOCK CALL. The arm eleven lines
    below returns it for any OSError from ``open(p, "a+b")``, and that needs no mocking:
    measured on this box, ``probe_lock(<a directory>)`` and ``probe_lock(<a lock file whose
    mode denies write>)`` both return LOCK_UNKNOWN, as does a real held lock when ``open``
    hits EMFILE. So the collapse below narrows ONE route into a hazard that stays wide open,
    and no reader should conclude this module does not emit LOCK_UNKNOWN.

    WHY THE LOCK CALL IS STILL COLLAPSED, AND WHAT THAT NO LONGER BUYS. All four consumers now
    handle LOCK_UNKNOWN fail-closed and say so in their own comments: ``coreservice.running``
    returns ``running=None`` ("COULD NOT ASK"), ``cli.cmd_core_ensure`` exits 4 /
    CORE_LIVENESS_UNKNOWN rather than start a second Core, ``corerelay.owned`` returns
    OWNED_UNKNOWN, and ``orchestrator.reap`` -- which USED to be the sole hostile one, continuing
    only on ``liveness == ALIVE`` so that UNKNOWN entered its dead-worker recovery path and its
    lease was released around ``lease.may_reclaim`` -- now gives UNKNOWN its own arm and releases
    only through ``may_reclaim``. That was bd quaestor-9ap, and it has LANDED; reap's own
    docstring records the change.

    SO THE COLLAPSE NO LONGER PROTECTS ANYTHING. It is retained here only because the errno split
    is not written yet, not because writing it is unsafe: the blocker bd quaestor-lag was held on
    is discharged. It never protected fully in any case -- a transient EMFILE on the ``open`` two
    lines earlier has always reached reap by the same route -- and its cost, stated next, is not
    always transient. Splitting it is bd quaestor-lag's remaining work; controls 381 and 382 are
    written so that it can be done without rewriting them.

    THE COST, WHICH IS NOT ALWAYS TRANSIENT. On a filesystem that cannot do advisory locks at
    all -- flock returning ENOSYS/EOPNOTSUPP, an SMB/CIFS mount refusing byte-range locks --
    every probe of every existing lock file reads LOCK_HELD forever, because nothing deletes
    those files. Relays then report OWNED_RUNNING permanently, ``coreservice.running`` reports a
    Core that is not there, and ``core ensure`` reuses a stale endpoint. For the contention
    errnos the collapse over-reports for as long as the contention lasts; for ENOSYS/EOPNOTSUPP
    it over-reports PERMANENTLY, and there is no diagnostic separating that host from four
    genuinely running relays. Control 381 is written not to outlaw either repair.
    """
    p = str(path or "")
    if not p or not os.path.exists(p):
        return LOCK_ABSENT
    try:
        fh = open(p, "a+b")
    except OSError:
        return LOCK_UNKNOWN
    try:
        try:
            _lock_nb(fh)
        except OSError:
            return LOCK_HELD
        try:
            _unlock(fh)
        except OSError:
            pass
        return LOCK_FREE
    finally:
        try:
            fh.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------------
# PID + creation time -- an identity, not a pid
# ---------------------------------------------------------------------------------------------
def process_create_time(pid: int) -> str | None:
    """An opaque, stable creation stamp for ``pid``, or None when it cannot be determined.

    None means UNKNOWN and callers must treat it as such. Returning a placeholder here would
    make two different processes compare equal, which is the pid-reuse bug with extra steps.
    Impure. NEVER raises.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    if _IS_WINDOWS:
        return _win_create_time(pid)
    return _posix_create_time(pid)


def _win_create_time(pid: int) -> str | None:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # noqa: BLE001
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        creation = wintypes.FILETIME()
        exit_t = wintypes.FILETIME()
        kernel_t = wintypes.FILETIME()
        user_t = wintypes.FILETIME()
        ok = k32.GetProcessTimes(h, ctypes.byref(creation), ctypes.byref(exit_t),
                                 ctypes.byref(kernel_t), ctypes.byref(user_t))
        if not ok:
            return None
        return "%d" % ((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
    finally:
        k32.CloseHandle(h)


def _posix_create_time(pid: int) -> str | None:
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read().decode("utf-8", "replace")
        # The comm field can contain spaces and parentheses; everything after the LAST ')' is
        # positional, which is the only parse of /proc/pid/stat that is actually correct.
        tail = data[data.rindex(")") + 1:].split()
        return tail[19]           # starttime, field 22 overall
    except Exception:  # noqa: BLE001
        pass
    try:
        import subprocess
        p = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True,
                           timeout=10, shell=False)
        if p.returncode == 0:
            v = p.stdout.decode("utf-8", "replace").strip()
            return v or None
    except Exception:  # noqa: BLE001
        return None
    return None


def pid_exists(pid: int) -> bool | None:
    """Tri-state existence. None = could not tell. Impure. NEVER raises."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    if _IS_WINDOWS:
        return process_create_time(pid) is not None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


# ---------------------------------------------------------------------------------------------
# THE DECISION -- pure, injected readings
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Liveness:
    status: str
    reason: str
    evidence: dict


def classify_liveness(*, lock_state: str, recorded_pid: int | None,
                      recorded_create_time: str | None,
                      observed_create_time: str | None,
                      pid_present: bool | None) -> Liveness:
    """Is the worker still alive? PURE. NEVER raises.

    The ladder, and why it is in this order:

      1. LOCK_HELD  -> ALIVE. The kernel says a process holds it. Nothing outranks that.
      2. LOCK_ABSENT + no pid -> DEAD-ish? NO. It is UNKNOWN: "the worker never wrote its lock"
         and "the worker died before writing its lock" are indistinguishable from here, and the
         difference matters because one of them may have already started Claude.
      3. LOCK_FREE + a recorded identity that no longer matches -> DEAD. Two independent signals
         agree, which is the only configuration in which this module will say DEAD.
      4. LOCK_FREE but the identity check could not run -> DEAD only if the pid is provably
         absent; otherwise UNKNOWN.

    UNKNOWN is a legitimate verdict and callers MUST NOT convert it to DEAD.
    """
    ev = {"lock_state": lock_state, "recorded_pid": recorded_pid,
          "recorded_create_time": recorded_create_time,
          "observed_create_time": observed_create_time, "pid_present": pid_present}

    if lock_state == LOCK_HELD:
        return Liveness(ALIVE, "worker lock is held by a live process", ev)

    if lock_state == LOCK_UNKNOWN:
        return Liveness(UNKNOWN, "the lock could not be probed; absence of evidence is not "
                                 "evidence the worker is gone", ev)

    if lock_state == LOCK_ABSENT:
        if pid_present is True and recorded_create_time and observed_create_time \
                and recorded_create_time == observed_create_time:
            return Liveness(ALIVE, "no lock file yet, but the recorded process identity is "
                                   "still present", ev)
        return Liveness(UNKNOWN, "no worker lock file exists: the worker either never started or "
                                 "died before creating it, and those are not the same thing", ev)

    # LOCK_FREE from here.
    if recorded_pid is None:
        return Liveness(UNKNOWN, "lock is free but no worker pid was ever recorded", ev)
    if pid_present is False:
        return Liveness(DEAD, "lock is free and the recorded pid is gone", ev)
    if recorded_create_time and observed_create_time:
        if recorded_create_time != observed_create_time:
            return Liveness(DEAD, "lock is free and the pid now belongs to a different process "
                                  "(creation time differs) -- pid reuse, not our worker", ev)
        return Liveness(UNKNOWN, "lock is free yet the recorded process identity is still "
                                 "present; refusing to call this either way", ev)
    return Liveness(UNKNOWN, "lock is free but process identity could not be corroborated", ev)


def observe(lock_path: str, recorded_pid: int | None,
            recorded_create_time: str | None) -> Liveness:
    """``classify_liveness`` with the real readings wired in. Impure. NEVER raises."""
    lock_state = probe_lock(lock_path)
    observed = process_create_time(recorded_pid) if recorded_pid else None
    present = pid_exists(recorded_pid) if recorded_pid else None
    return classify_liveness(lock_state=lock_state, recorded_pid=recorded_pid,
                             recorded_create_time=recorded_create_time,
                             observed_create_time=observed, pid_present=present)


def self_identity() -> tuple:
    """(pid, create_time) for THIS process. Impure."""
    pid = os.getpid()
    return pid, process_create_time(pid)


def spawn_detached_kwargs() -> dict:
    """Platform kwargs that detach a child from this process's lifetime and console.

    A worker that dies when the dispatcher dies is not a worker -- the entire point of the
    detached-worker design is that a dispatcher/server crash must not take a running Claude with
    it, nor orphan it in a way we cannot reconcile.
    """
    if _IS_WINDOWS:
        import subprocess
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        return {"creationflags": DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                "close_fds": True}
    return {"start_new_session": True, "close_fds": True}


def python_executable() -> str:
    return sys.executable or "python"

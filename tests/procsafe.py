"""procsafe -- a qualification that spawns processes must be able to prove it left none.

WHY THIS IS A MODULE AND NOT FOUR LINES INSIDE A FIXTURE
--------------------------------------------------------
The first Core-owned-relay qualification passed most of its product assertions and still failed
AS A QUALIFICATION. Three separate faults, none of them about Quaestor:

  * it left detached Cores behind, because each run started one with an idle timeout of zero --
    "never shut yourself down" -- and relied on nothing else to end it;
  * one run outlived the command that launched it and went on spawning in the background after
    the caller had stopped watching;
  * the "does the relay survive Core?" assertion was measured with a TREE kill, which walks
    descendants and took down the relay whose survival was the thing being measured. It then
    reported the product broken.

Two ownership bugs and a measurement bug. They are the kind that recur, so the machinery is
here rather than in the fixture, and controls test it directly. Those controls inject a fake
killer and a fake liveness oracle: they test OWNERSHIP SEMANTICS, and never this machine's real
process table, because a control that reads the process table would be measuring whatever else
the operator happens to be running.

THE THREE RULES
---------------
1. Everything a run creates is TRACKED AS IT IS CREATED, never reconstructed afterwards by
   pattern-matching a process list. A fleet terminates what it started and nothing else.
2. Cleanup runs on every exit -- pass, fail, exception, deadline, Ctrl-C -- because a ``finally``
   is the only cleanup that survives the failure it is there for.
3. Termination is SINGLE-PROCESS. A tree kill is never used, not even at final cleanup, because
   a fixture that reaches for it once will reach for it in the assertion where it is fatal.
4. A PID IS NOT A RESOURCE. "The process is gone" and "the process has released what it held"
   are different questions with different answers, and on POSIX they are answered in the
   surprising order -- see ``wait_released``. Ask the one you actually mean.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

PROCSAFE_INSTRUMENT = "tests.procsafe/1"

#: The maximum a qualification may run before it is a runaway rather than a slow test.
DEFAULT_DEADLINE_S = 600.0


class DeadlineExceeded(RuntimeError):
    """The run passed its wall-clock ceiling. Raised so ``finally`` cleanup happens."""


def kill_argv(pid: int, *, windows=None) -> list:
    """The command that ends EXACTLY ONE process. PURE.

    ``windows`` is injected rather than read from ``os.name`` so a control can check BOTH
    branches without reassigning a module-global the rest of this process is reading -- the test
    that did that was mutating ``os.name`` for Core's own server threads at the same time.

    NEVER A TREE KILL, and the two ways of writing one are both absent by construction:
    ``taskkill /T`` walks descendants by parent pid, and a NEGATIVE pid on POSIX signals the
    whole process group. Either would kill a detached relay along with the Core that spawned
    it, which is the opposite of the property this fixture exists to measure -- and an operator
    ending one process does not kill its detached children, so a test that does is not
    measuring anything real.
    """
    n = int(pid)
    if n <= 0:
        raise ValueError("refusing a non-positive pid: on POSIX that signals a process GROUP, "
                         "which is a tree kill by another name")
    if os.name == "nt" if windows is None else windows:
        return ["taskkill", "/PID", str(n), "/F"]
    return ["kill", "-9", str(n)]


def _real_kill(pid: int) -> None:
    """End one process. NEVER raises -- a cleanup that can raise is not a cleanup.

    ``taskkill`` can time out or fail on a process in an uninterruptible wait, and this runs
    inside a ``finally``: letting that escape aborted the whole cleanup at the first stubborn
    pid and leaked every process after it in the list.
    """
    try:
        subprocess.run(kill_argv(pid), capture_output=True, shell=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass


def _zombie(pid: int) -> bool:
    """Has this process exited and simply not been reaped yet? Impure. NEVER raises.

    ON POSIX A KILLED CHILD DOES NOT LEAVE THE PROCESS TABLE. It becomes a zombie, holding its
    pid until the parent collects its exit status -- and ``os.kill(pid, 0)`` SUCCEEDS for a
    zombie, because the pid is still there. So a cleanup that killed a child and then asked
    "is it alive?" was told yes, forever, and reported a leak on a run that had cleaned up
    perfectly. There is no such state on Windows, which is why this only ever failed on Linux.
    """
    try:
        with open("/proc/%d/stat" % int(pid), "r", encoding="utf-8") as fh:
            fields = fh.read().rsplit(")", 1)[-1].split()
        return bool(fields) and fields[0] == "Z"
    except (OSError, ValueError, IndexError):
        return False


def _real_alive(pid: int) -> bool:
    """Is this pid alive? NEVER raises; unknown counts as alive so cleanup tries again."""
    if os.name == "nt":
        try:
            out = subprocess.run(["tasklist", "/FI", "PID eq %d" % int(pid), "/NH"],
                                 capture_output=True, shell=False, timeout=60,
                                 creationflags=0x08000000)
            text = (out.stdout or b"").decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            return True
        return str(int(pid)) in text
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return not _zombie(pid)


class Fleet:
    """Everything one qualification run created, and the promise to take it all away.

    Used as a context manager. The ``finally`` is the mechanism; a finite idle timeout on a
    spawned service is defence in depth and never the cleanup itself, because a service that
    is wedged is exactly the one that will not notice its own timer.
    """

    def __init__(self, *, deadline_s: float = DEFAULT_DEADLINE_S, clock=time.time,
                 killer=None, alive=None, log=None, keep_dirs: bool = False):
        self.deadline_s = float(deadline_s)
        self._clock = clock
        self._kill = killer or _real_kill
        self._alive = alive or _real_alive
        self._log = log or (lambda m: None)
        self.keep_dirs = bool(keep_dirs)
        self.began = float(clock())
        #: pid -> (what it is, its creation time). Appended AT CREATION, never inferred later.
        #: THE CREATION TIME IS THE IDENTITY. A pid is reused, sometimes within seconds on a
        #: busy Windows box, and this fleet's whole job is to end what it started and nothing
        #: else -- so a pid whose creation time has changed is a DIFFERENT process wearing a
        #: number this run used to own, and it is released rather than killed.
        self.owned: dict = {}
        #: pid -> the Popen this run holds for it. A process WE started is reaped by us, so it
        #: does not sit in the table as a zombie for whatever asks next.
        self.children: dict = {}
        self.dirs: list = []
        self.closed = False
        self.cleanup_report: dict = {}

    # -- the ceiling ---------------------------------------------------------------------------
    def remaining(self) -> float:
        return self.deadline_s - (float(self._clock()) - self.began)

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def check_deadline(self, where: str = "") -> None:
        """Raise if the run is out of time. Called at every step, so the ceiling is real.

        Raising -- rather than returning a verdict the caller may forget to read -- is what
        makes the ceiling reach the ``finally``. The run that had to be killed by hand was one
        that kept spawning after its caller had already given up on it.
        """
        if self.expired():
            raise DeadlineExceeded("qualification exceeded its %.0fs ceiling%s"
                                   % (self.deadline_s, (" at " + where) if where else ""))

    # -- creation ------------------------------------------------------------------------------
    def temp_dir(self, prefix: str) -> str:
        """A directory this run owns and this run removes."""
        path = tempfile.mkdtemp(prefix=prefix)
        self.dirs.append(path)
        return path

    def spawn(self, argv: list, *, what: str, cwd: str = "") -> subprocess.Popen:
        """Start a tracked process, detached and WITHOUT a console window.

        Detached because these are services that must outlive the call that started them, and
        window-less because a fixture that flashes a console per subprocess is unusable on a
        desktop -- which is how the process leak was noticed in the first place.
        """
        from quaestor.core import proc
        self.check_deadline("spawn:%s" % what)
        child = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 cwd=cwd or None, shell=False, **proc.spawn_detached_kwargs())
        self.adopt(child.pid, what)
        self.children[child.pid] = child
        return child

    def run(self, argv: list, *, what: str, timeout_s: float = 180.0, cwd: str = ""):
        """Run a SHORT-LIVED process to completion, WITHOUT a console window.

        The window suppression is not cosmetic. The run that had to be stopped by hand launched
        roughly a dozen console subprocesses per assertion, and a fixture that papers the
        operator's desktop with flashing windows will be interrupted -- which is a cleanup path
        nothing tests. Anything that must OUTLIVE the call goes through ``spawn`` instead.
        """
        self.check_deadline("run:%s" % what)
        flags = {"creationflags": 0x08000000} if os.name == "nt" else {}
        timeout_s = max(1.0, min(float(timeout_s), max(1.0, self.remaining())))
        return subprocess.run(list(argv), capture_output=True, shell=False,
                              timeout=float(timeout_s), cwd=cwd or None, **flags)

    def identity(self, pid) -> str:
        """This process's creation time, or "" if it cannot be read. Impure. NEVER raises."""
        try:
            from quaestor.core import proc
            return str(proc.process_create_time(int(pid)) or "")
        except Exception:  # noqa: BLE001
            return ""

    def adopt(self, pid, what: str) -> int:
        """Track a process this run caused to exist but did not spawn directly.

        A relay is started BY CORE, so the fixture never holds its handle -- and it is still
        this run's responsibility. Adoption is explicit and by pid: nothing is ever adopted by
        matching a name or a command line against the machine's process list, because that is
        how a cleanup ends up killing an editor, another session, or an unrelated repository's
        work that merely looked similar.
        """
        if pid is None:
            return 0
        n = int(pid)
        if n > 0:
            self.owned.setdefault(n, (str(what), self.identity(n)))
        return n

    def forget(self, pid) -> None:
        """Stop owning a pid whose death is itself the thing under test."""
        self.owned.pop(int(pid or 0), None)

    def still_ours(self, pid) -> bool:
        """Is the process at this pid still the one we adopted? Impure. NEVER raises."""
        what_born = self.owned.get(int(pid or 0))
        if what_born is None:
            return False
        born = what_born[1]
        if not born:
            return True          # unreadable at adoption: fall back to the pid, and say so
        now = self.identity(pid)
        return (not now) or now == born

    # -- measurement ---------------------------------------------------------------------------
    def alive(self, pid) -> bool:
        """Is this process still doing anything? Impure. NEVER raises.

        For a process this run STARTED the answer is authoritative: its own ``Popen`` knows
        whether it has exited, and asking it also REAPS it, which is what stops a killed child
        lingering as a zombie that every other liveness test then calls alive.
        """
        if not pid:
            return False
        child = self.children.get(int(pid))
        if child is not None:
            try:
                return child.poll() is None
            except Exception:  # noqa: BLE001
                pass
        return self._alive(int(pid))

    def terminate(self, pid, *, what: str = "") -> None:
        """End ONE process. Not its children. See ``kill_argv``."""
        if not pid:
            return
        self._log("terminate %s pid=%s" % (what or (self.owned.get(int(pid)) or ("?",))[0], pid))
        self._kill(int(pid))

    def wait_gone(self, pid, timeout_s: float = 20.0, tick: float = 0.5) -> bool:
        # CLAMPED TO THE RUN'S BUDGET. ``check_deadline`` passing at 0.1s remaining and then a
        # 45s wait beginning is a ceiling in name only: the run could legitimately overshoot by
        # minutes, which is how it outlived the command that launched it.
        timeout_s = max(0.0, min(float(timeout_s), max(0.0, self.remaining())))
        deadline = float(self._clock()) + float(timeout_s)
        while float(self._clock()) < deadline:
            if not self.alive(pid):
                return True
            time.sleep(tick)
        return not self.alive(pid)

    def wait_released(self, lock_path: str, timeout_s: float = 30.0, tick: float = 0.05) -> bool:
        """Wait until nobody holds ``lock_path``. Impure. NEVER raises.

        NOT THE SAME QUESTION AS ``wait_gone``, and this is the whole point. ``kill`` returns
        once the signal has been delivered; the kernel then tears the process down
        asynchronously. Measured on Linux against a real Core, three trials out of three: the
        pid stops answering ``kill(pid, 0)`` at ~1.0 ms and the flock it held is not released
        until ~3.4 ms. For roughly two and a half milliseconds the process does not exist AND
        its lock is genuinely still held -- so "it is gone, therefore its lock is free" is
        false, and a test that infers one from the other fails exactly as often as the machine
        is quick enough to look in between. Under CI load the window is wider.

        Windows never showed it because a handle is torn down with the process, which is why
        five green Windows runs certified a test that could not pass on Linux.

        This is a bounded wait on the ACTUAL lifecycle transition, not a sleep hoping one has
        happened. LOCK_ABSENT counts as released -- there is nothing left to hold.
        """
        from quaestor.core import proc
        timeout_s = max(0.0, min(float(timeout_s), max(0.0, self.remaining())))
        deadline = float(self._clock()) + float(timeout_s)
        while True:
            if proc.probe_lock(str(lock_path)) in (proc.LOCK_FREE, proc.LOCK_ABSENT):
                return True
            if float(self._clock()) >= deadline:
                return proc.probe_lock(str(lock_path)) in (proc.LOCK_FREE, proc.LOCK_ABSENT)
            time.sleep(tick)

    # -- the promise ---------------------------------------------------------------------------
    def close(self) -> dict:
        """Terminate everything still owned, remove owned directories, and REPORT.

        Idempotent, and it reports rather than asserting: the caller decides whether a leak is
        a failed qualification. It always is -- a run that proves the product and leaves
        processes behind has not proved it can be run again -- but that verdict belongs to the
        fixture, not to the cleanup.
        """
        if self.closed:
            return self.cleanup_report
        killed, leaked, released = [], [], []
        for pid, (what, _born) in sorted(self.owned.items()):
            if not self.alive(pid):
                continue
            if not self.still_ours(pid):
                # THE PID WAS REUSED. Something else is wearing this number now, and ending it
                # would be the harness doing exactly what it exists to prevent.
                released.append({"pid": pid, "what": what})
                continue
            # ONE STUBBORN PROCESS MUST NOT ABORT THE CLEANUP. This runs inside a ``finally``;
            # an exception here used to escape it and leak every process later in the list.
            try:
                self.terminate(pid, what=what)
                killed.append({"pid": pid, "what": what})
            except Exception as exc:  # noqa: BLE001
                leaked.append({"pid": pid, "what": what,
                               "detail": "%s: %s" % (type(exc).__name__, exc)})
        # TERMINATION IS A REQUEST, NOT AN EVENT. ``taskkill /F`` returns once the kill is
        # asked for, so re-probing immediately reported processes as leaked that were mid-exit.
        for row in list(killed):
            self.wait_gone(row["pid"], timeout_s=15.0, tick=0.25)
        # REAP EVERY CHILD, whether we killed it or it ended on its own. An unreaped child holds
        # its pid, and a held pid is indistinguishable from a running process to anything that
        # asks the operating system rather than the parent.
        for pid, child in list(self.children.items()):
            try:
                child.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
        for pid, (what, _born) in sorted(self.owned.items()):
            if self.alive(pid) and self.still_ours(pid) and not any(
                    r["pid"] == pid for r in leaked):
                leaked.append({"pid": pid, "what": what})
        removed, kept = [], []
        for path in self.dirs:
            if self.keep_dirs:
                kept.append(path)
                continue
            # RETRIED, because a handle outlives the process on Windows. ``taskkill`` returns
            # before the OS has closed what the process had open, so the first rmtree after a
            # kill routinely fails on the very files the run created -- and a state home left
            # on disk is a run that did not clean up after itself.
            for attempt in range(6):
                shutil.rmtree(path, ignore_errors=True)
                if not os.path.exists(path):
                    break
                if attempt < 5:
                    time.sleep(0.5)
            # REPORTED AS MEASURED. ``ignore_errors`` plus an unconditional append said
            # "removed" for a directory a killed process still held a handle on.
            (removed if not os.path.exists(path) else kept).append(path)
        self.closed = True
        self.cleanup_report = {"terminated": killed, "leaked": leaked, "released": released,
                               "dirs_removed": removed, "dirs_kept": kept,
                               "instrument": PROCSAFE_INSTRUMENT}
        return self.cleanup_report

    def __enter__(self) -> "Fleet":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


def independent_leak_check(names=("quaestor.transports.cli", "opencode")) -> dict:
    """What is running that LOOKS like this qualification's leftovers? Impure. NEVER raises.

    REPORTS AND KILLS NOTHING, on purpose. It is the independent post-run check a verdict
    quotes, and it is deliberately not wired to any cleanup: matching by command line finds
    other sessions, other repositories and other people's work, and a fixture that killed what
    it merely recognised would be a worse bug than the leak it was chasing.
    """
    rows = []
    names = tuple(str(n) for n in (names or ()))
    try:
        if os.name == "nt":
            # ONE LINE PER PROCESS, not JSON. ``ConvertTo-Json`` over a few hundred
            # processes costs tens of seconds, which is a long time for a check that only
            # reports -- and this is called on a path that has already failed.
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Get-CimInstance Win32_Process | "
                 "ForEach-Object { \"$($_.ProcessId) $($_.CommandLine)\" }"],
                capture_output=True, shell=False, timeout=120, creationflags=0x08000000)
        else:
            out = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True,
                                 shell=False, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"measured": False, "detail": "%s: %s" % (type(exc).__name__, exc), "matches": []}
    text = (out.stdout or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        if any(n in line for n in names):
            rows.append(line.strip()[:200])
    return {"measured": True, "matches": rows, "count": len(rows),
            "note": "reported, never killed: a command line is a resemblance, not ownership",
            "instrument": PROCSAFE_INSTRUMENT}


def main(argv=None) -> int:
    """``python -m tests.procsafe`` -- report look-alike processes without touching them."""
    import json
    del argv
    sys.stdout.write(json.dumps(independent_leak_check(), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

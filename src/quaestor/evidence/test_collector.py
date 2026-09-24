"""test_collector -- TEST_EXECUTION, the first non-repository claim class the bridge corroborates.

WHY THIS EXISTS
---------------
Up to P2 the bridge could measure repository state and nothing else, so a child's "the tests
passed" was carried as prose and labelled a claim. That is honest but thin: the most common thing
an orchestrated agent will assert is exactly this. So the bridge now runs the tests itself.

THE RULE THAT MAKES IT EVIDENCE RATHER THAN THEATRE
---------------------------------------------------
    THE BRIDGE OWNS THE TEST DEFINITION.

Claude never supplies a command the bridge later executes. If it could, "corroboration" would
mean running whatever the subject asked us to run and agreeing with the answer -- a control that
consumes its own input. Profiles are registered by id; a dispatch selects a ``profile_id`` and
nothing else.

TWO SEPARATE FACTS, NEVER COLLAPSED
-----------------------------------
    PROCESS_EXECUTED   did the runner actually start and terminate?
    TEST_VERDICT       did the tests pass?

``PROCESS_EXECUTED=true`` with ``TEST_VERDICT=FAIL`` is the normal, useful case. A launch failure
is NOT a test failure; a timeout is neither a pass nor a fail. And zero discovered tests is
VACUOUS -- a suite that ran nothing is the instrument-doctrine floor applied to test counts, and
it is how a green "OK" over an empty collection sneaks through.

PURE parsing; one subprocess seam at the bottom.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core.canon import sha256_text

COLLECTOR_VERSION = "test_collector/1"

# Process outcomes
LAUNCHED = "LAUNCHED"
LAUNCH_FAILED = "LAUNCH_FAILED"
TIMED_OUT = "TIMED_OUT"

# Test verdicts
PASS = "PASS"
FAIL = "FAIL"
VACUOUS = "VACUOUS"
NOT_EVALUATED = "NOT_EVALUATED"

_RAN = re.compile(r"^Ran (\d+) tests? in ([\d.]+)s", re.MULTILINE)
_FAILED = re.compile(r"^FAILED \((.*)\)", re.MULTILINE)
_OK = re.compile(r"^OK(?: \((.*)\))?\s*$", re.MULTILINE)
_COUNT = re.compile(r"(failures|errors|skipped|expected failures|unexpected successes)=(\d+)")


@dataclass(frozen=True)
class TestProfile:
    """A bridge-owned, immutable test definition."""

    profile_id: str
    argv: tuple
    cwd_policy: str = "workspace"          # workspace | fixture | orchestrator
    timeout_s: float = 300.0
    expected_floor: int = 1                # minimum tests that must be DISCOVERED
    collector_version: str = COLLECTOR_VERSION
    runner: str = "host"                   # host | container
    note: str = ""

    def argv_identity(self) -> str:
        return sha256_text("\x00".join(str(a) for a in self.argv))

    def to_dict(self) -> dict:
        return {"profile_id": self.profile_id, "argv": list(self.argv),
                "argv_identity": self.argv_identity(), "cwd_policy": self.cwd_policy,
                "timeout_s": self.timeout_s, "expected_floor": self.expected_floor,
                "collector_version": self.collector_version, "runner": self.runner,
                "note": self.note or None}


@dataclass(frozen=True)
class TestReceipt:
    run_id: str
    profile_id: str
    argv_identity: str
    cwd_identity: str
    process_executed: bool
    process_outcome: str
    test_verdict: str
    exit_code: int | None = None
    timeout_s: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    discovered: int | None = None
    passed: int | None = None
    failed: int | None = None
    errors: int | None = None
    skipped: int | None = None
    stdout_digest: str = ""
    stderr_digest: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    container_id: str = ""
    collector_version: str = COLLECTOR_VERSION
    reason: str = ""
    detail: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in (
            "run_id", "profile_id", "argv_identity", "cwd_identity", "process_executed",
            "process_outcome", "test_verdict", "exit_code", "timeout_s", "started_at",
            "finished_at", "discovered", "passed", "failed", "errors", "skipped",
            "stdout_digest", "stderr_digest", "stdout_path", "stderr_path", "container_id",
            "collector_version", "reason")}
        d["detail"] = dict(self.detail)
        return d


def parse_unittest_output(text: str) -> dict:
    """Counts from Python unittest output. PURE. NEVER raises.

    Returns ``discovered=None`` when the output contains no "Ran N tests" line at all -- absent,
    not zero. A parser that reports 0 for unparseable output turns a broken runner into a
    VACUOUS-looking suite, which is the wrong diagnosis and the wrong remedy.
    """
    out = {"discovered": None, "failed": None, "errors": None, "skipped": None,
           "passed": None, "status": None, "runtime_s": None}
    m = _RAN.search(text or "")
    if m:
        out["discovered"] = int(m.group(1))
        out["runtime_s"] = float(m.group(2))

    fm = _FAILED.search(text or "")
    ok = _OK.search(text or "")
    counts = {"failures": 0, "errors": 0, "skipped": 0}
    if fm:
        out["status"] = "FAILED"
        for key, val in _COUNT.findall(fm.group(1)):
            counts[key] = int(val)
    elif ok:
        out["status"] = "OK"
        if ok.group(1):
            for key, val in _COUNT.findall(ok.group(1)):
                counts[key] = int(val)

    if out["status"] is not None:
        out["failed"] = counts["failures"]
        out["errors"] = counts["errors"]
        out["skipped"] = counts["skipped"]
        if out["discovered"] is not None:
            out["passed"] = max(0, out["discovered"] - counts["failures"] - counts["errors"]
                                - counts["skipped"])
    return out


def classify(parsed: Mapping, *, process_outcome: str, exit_code: int | None,
             expected_floor: int) -> tuple:
    """(test_verdict, reason). PURE.

    Order is the policy:
      1. the process never ran        -> NOT_EVALUATED (a launch failure is not a test failure)
      2. it timed out                 -> NOT_EVALUATED (neither pass nor fail; do not guess)
      3. nothing was discovered       -> VACUOUS
      4. below the discovery floor    -> VACUOUS
      5. failures/errors, or the
         runner's own status is FAILED,
         or a non-zero exit           -> FAIL
      6. otherwise                    -> PASS
    """
    if process_outcome == LAUNCH_FAILED:
        return NOT_EVALUATED, "the test runner never started; that is not a test failure"
    if process_outcome == TIMED_OUT:
        return NOT_EVALUATED, ("the test runner exceeded its timeout; a timeout is neither a pass "
                               "nor a fail and must not be recorded as either")

    discovered = parsed.get("discovered")
    if discovered is None:
        return NOT_EVALUATED, ("the runner produced no parseable test summary; absent counts are "
                               "not zero counts")
    if int(discovered) == 0:
        return VACUOUS, ("zero tests were discovered: a suite that ran nothing cannot report a "
                         "verdict about anything")
    if int(discovered) < int(expected_floor):
        return VACUOUS, ("only %d test(s) discovered, floor is %d -- the suite did not inspect "
                         "what the profile requires" % (int(discovered), int(expected_floor)))

    if parsed.get("status") == "FAILED" or (parsed.get("failed") or 0) > 0 \
            or (parsed.get("errors") or 0) > 0:
        return FAIL, "the suite reported failures/errors"
    if exit_code not in (0, None):
        return FAIL, "the runner exited %s despite reporting no failures" % exit_code
    return PASS, ""


def compare_claim(claimed_verdict: str | None, measured: TestReceipt) -> dict:
    """Does the child's claim match the bridge's measurement? PURE.

    The independent collector wins, always. This function does not "resolve" a disagreement --
    it records one, and the caller fails the run.
    """
    claim = (str(claimed_verdict).upper() if claimed_verdict is not None else None)
    agree = (claim is not None and claim == measured.test_verdict)
    return {
        "claimed": claim,
        "measured": measured.test_verdict,
        "agree": agree,
        "authority": "independent collector",
        "note": ("the collector's verdict is the evidence; the child's is a claim. A "
                 "disagreement is recorded and fails the run -- it is never averaged, "
                 "reconciled, or resolved in the claim's favour."),
    }


# ---------------------------------------------------------------------------------------------
# Registry -- the bridge owns these; nothing outside this file may add one at runtime.
# ---------------------------------------------------------------------------------------------
def registry(python: str = "python") -> dict:
    return {
        "orchestrator-self-test": TestProfile(
            "orchestrator-self-test", (python, "-m", "unittest", "-v"),
            cwd_policy="orchestrator", timeout_s=900.0, expected_floor=50,
            note="the orchestrator's own suite"),
        "fixture-unittest": TestProfile(
            "fixture-unittest", (python, "-m", "unittest", "discover", "-s", ".", "-p",
                                 "test_*.py"),
            cwd_policy="workspace", timeout_s=300.0, expected_floor=1,
            note="discover and run a fixture's unittest suite"),
        "fixture-unittest-container": TestProfile(
            "fixture-unittest-container",
            ("python3", "-m", "unittest", "discover", "-s", "/workspace", "-p", "test_*.py"),
            cwd_policy="workspace", timeout_s=300.0, expected_floor=1, runner="container",
            note="the same suite, executed inside the confinement container"),
    }


def get_profile(profile_id: str, python: str = "python") -> TestProfile | None:
    return registry(python).get(str(profile_id))


# ---------------------------------------------------------------------------------------------
# Execution seam
# ---------------------------------------------------------------------------------------------
def run_profile(profile: TestProfile, *, cwd: str, run_id: str = "", now=None,
                stdout_path: str = "", stderr_path: str = "") -> TestReceipt:
    """Execute a bridge-owned profile on the HOST. Impure. NEVER raises."""
    import time as _t
    clock = now or _t.time
    started = float(clock())
    outcome, exit_code, out, err = LAUNCHED, None, "", ""
    try:
        p = subprocess.run(list(profile.argv), cwd=cwd, capture_output=True, shell=False,
                           timeout=float(profile.timeout_s), stdin=subprocess.DEVNULL)
        exit_code = p.returncode
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        outcome = TIMED_OUT
        out = (exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else ""
        err = (exc.stderr or b"").decode("utf-8", "replace") if exc.stderr else ""
    except (OSError, subprocess.SubprocessError) as exc:
        outcome = LAUNCH_FAILED
        err = "%s: %s" % (type(exc).__name__, exc)
    finished = float(clock())

    for path, text in ((stdout_path, out), (stderr_path, err)):
        if path:
            try:
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            except OSError:
                pass

    return build_receipt(profile, run_id=run_id, cwd=cwd, outcome=outcome, exit_code=exit_code,
                         stdout=out, stderr=err, started=started, finished=finished,
                         stdout_path=stdout_path, stderr_path=stderr_path)


def build_receipt(profile: TestProfile, *, run_id: str, cwd: str, outcome: str,
                  exit_code: int | None, stdout: str, stderr: str, started: float,
                  finished: float, stdout_path: str = "", stderr_path: str = "",
                  container_id: str = "") -> TestReceipt:
    """Turn observations into a receipt. PURE.

    Both streams are parsed: unittest writes its summary to STDERR, and a container runner may
    merge them. Parsing only one is how a real summary goes unseen and the suite reads VACUOUS.
    """
    parsed = parse_unittest_output(stderr)
    if parsed.get("discovered") is None:
        parsed = parse_unittest_output(stdout)
    verdict, reason = classify(parsed, process_outcome=outcome, exit_code=exit_code,
                               expected_floor=profile.expected_floor)
    return TestReceipt(
        run_id=run_id, profile_id=profile.profile_id, argv_identity=profile.argv_identity(),
        cwd_identity=str(cwd), process_executed=(outcome == LAUNCHED),
        process_outcome=outcome, test_verdict=verdict, exit_code=exit_code,
        timeout_s=profile.timeout_s, started_at=started, finished_at=finished,
        discovered=parsed.get("discovered"), passed=parsed.get("passed"),
        failed=parsed.get("failed"), errors=parsed.get("errors"), skipped=parsed.get("skipped"),
        stdout_digest=sha256_text(stdout), stderr_digest=sha256_text(stderr),
        stdout_path=stdout_path, stderr_path=stderr_path, container_id=container_id,
        reason=reason, detail={"parsed": dict(parsed), "profile": profile.to_dict()})

#!/usr/bin/env python3
"""run_tests.py -- THE GATE. Runs the suite, then proves the suite actually inspected something.

WHY THIS EXISTS INSTEAD OF ``python -m unittest``
--------------------------------------------------
Instrument doctrine clause 1: a gate emits a COUNT OF WHAT IT INSPECTED, and a run that
inspected nothing is VACUOUS, never PASS. ``unittest`` reports "OK" just as cheerfully over two
tests as over two hundred, and a module that fails to import is a silent subtraction. So this
wrapper adds three floors that a green unittest run cannot satisfy on its own:

  * TEST FLOOR      -- fewer than ``MIN_TESTS`` tests ran => VACUOUS.
  * MODULE FLOOR    -- every expected test module must have been imported and contributed tests.
  * CONTROL FLOORS  -- every id in ``tests.controls.REQUIRED_CONTROLS`` must be DECLARED by a
                      test and must have EXECUTED successfully. A control that was renamed,
                      skipped, or silently deleted fails here by name.

Clause 3 as well: the verdict states its environment (platform, python, git, cwd), because
several of these controls are OS-semantics controls and "it passed" means nothing without saying
where.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

#: Importing the test package suppresses the console window Windows gives each subprocess. The
#: suppression lives THERE, not here, so ``python -m unittest tests.whatever`` is quiet too --
#: which is how the suite is actually run while working. Reported in the verdict because a gate
#: that changes how its children are spawned should say so.
from tests import QUIETED as CONSOLES_SUPPRESSED  # noqa: E402
from tests import controls  # noqa: E402

#: Floors. Deliberately below the current count (so ordinary additions do not trip them) and far
#: above zero (so a broken import cannot pass).
MIN_TESTS = 80
# The two project-integration modules (test_p2_controls, test_p4_controls) stayed with the
# consuming project: they exercise a specific real repository, not the platform.
EXPECTED_MODULES = ("tests.test_units", "tests.test_mutations", "tests.test_real_envelope",
                    "tests.test_p25_controls", "tests.test_p3_controls",
                    "tests.test_p45_controls", "tests.test_p5a_controls",
                    "tests.test_platform_controls",
                    "tests.test_reachability_controls",
                    "tests.test_restored_controls",
                    "tests.test_boundary_controls",
                    "tests.test_reachability_matrix",
                    "tests.test_operational_controls",
                    "tests.test_operational_e2e",
                    "tests.test_soak_qualification",
                    "tests.test_remote_readonly_controls",
                    "tests.test_lane_registry",
                    "tests.test_role_matrix",
                    "tests.test_webui",
                    "tests.test_store_outcomes",
                    "tests.test_adapters_assurance",
                    "tests.test_adapters_filebox_command_transcript",
                    "tests.test_role_matrix_policy",
                    "tests.test_planner_seat",
                    "tests.test_context_capsule",
                    "tests.test_autonomy_strategist",
                    "tests.test_browser_transport",
                    "tests.test_chatgpt_web_adapter",
                    "tests.test_openrouter_provider",
                    "tests.test_generic_adapter_seats",
                    "tests.test_assurance_surface",
                    "tests.test_config_toml_connect_mailbox",
                    "tests.test_cold_start",
                    "tests.test_relay_kernel",
                    "tests.test_relay_completion",
                    "tests.test_relay_opencode_probe",
                    "tests.test_core_service",
                    "tests.test_core_relay_lifecycle",
                    "tests.test_relay_owner_holds",
                    "tests.test_relay_chatgpt_end")


def discovered_modules() -> tuple:
    """Every ``tests/test_*.py`` on disk, as module names. Impure (reads the directory).

    THE MEASUREMENT that keeps EXPECTED_MODULES honest. The declaration above is a floor -- it
    catches a module that VANISHES -- but on its own it is a hand-maintained list of filenames,
    and such a list drifts the first time somebody adds a file. It had: 25 names against 30
    modules on disk, so roughly 290 controls were invisible to this gate and it would have
    reported PASS with all five files deleted.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    tests_dir = os.path.join(here, "tests")
    names = []
    for entry in sorted(os.listdir(tests_dir)):
        if entry.startswith("test_") and entry.endswith(".py"):
            names.append("tests." + entry[:-3])
    return tuple(names)


def environment() -> dict:
    try:
        git_v = subprocess.run(["git", "--version"], capture_output=True, timeout=30,
                               shell=False).stdout.decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        git_v = "unavailable"
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "git": git_v,
        "cwd": os.getcwd().replace("\\", "/"),
        "os_name": os.name,
    }


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    verbosity = 2 if "-v" in argv else 1

    # DECLARATION vs MEASUREMENT, and a NAMED refusal on either kind of disagreement.
    # Undeclared: a module exists that this gate would never have run -- the failure that let
    # five suites hide. Missing: a declared module is gone, which is the case the list was
    # written to catch. Neither is silently reconciled: the operator is told which, and why.
    on_disk = set(discovered_modules())
    declared = set(EXPECTED_MODULES)
    undeclared = sorted(on_disk - declared)
    vanished = sorted(declared - on_disk)
    if undeclared or vanished:
        if undeclared:
            sys.stderr.write(
                "GATE=VACUOUS reason=test module(s) on disk are not declared in "
                "EXPECTED_MODULES: %s -- this gate would have reported PASS without ever "
                "running them\n" % (undeclared,))
        if vanished:
            sys.stderr.write(
                "GATE=VACUOUS reason=declared test module(s) are missing from disk: %s\n"
                % (vanished,))
        return 2

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    loaded = {}
    for mod in EXPECTED_MODULES:
        s = loader.loadTestsFromName(mod)
        loaded[mod] = s.countTestCases()
        suite.addTest(s)

    if loader.errors:
        for err in loader.errors:
            sys.stderr.write(str(err) + "\n")
        sys.stderr.write("GATE=VACUOUS reason=test modules failed to load\n")
        return 2

    started = time.time()
    result = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stderr).run(suite)
    runtime = time.time() - started

    total = result.testsRun
    failed = len(result.failures)
    errored = len(result.errors)
    skipped = len(result.skipped)
    passed = total - failed - errored - skipped

    cov = controls.coverage_report()
    problems = []

    if total < MIN_TESTS:
        problems.append("TEST FLOOR: %d tests ran, floor is %d -- a suite this small did not "
                        "inspect the system" % (total, MIN_TESTS))
    for mod, n in loaded.items():
        if n == 0:
            problems.append("MODULE FLOOR: %s contributed zero tests" % mod)
    if cov["missing_declaration"]:
        problems.append("CONTROL FLOOR: required controls with no test declaring them: %s"
                        % cov["missing_declaration"])
    if cov["missing_execution"] and not (failed or errored):
        problems.append("CONTROL FLOOR: required controls that never executed successfully: %s"
                        % cov["missing_execution"])

    verdict = "PASS"
    if failed or errored:
        verdict = "FAIL"
    elif problems:
        verdict = "VACUOUS"

    report = {
        "verdict": verdict,
        "tests": {"run": total, "passed": passed, "failed": failed, "errors": errored,
                  "skipped": skipped, "runtime_s": round(runtime, 2)},
        "modules": loaded,
        "controls": cov,
        "floors": {"min_tests": MIN_TESTS, "expected_modules": list(EXPECTED_MODULES)},
        "problems": problems,
        "environment": {**environment(), "consoles_suppressed": CONSOLES_SUPPRESSED},
    }
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")

    out = os.path.join(ROOT, "var", "last-test-report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""support -- disposable fixtures. Real git repositories, real processes, no Claude.

Every control runs against a REAL git repository created in a temp directory, because the
evidence layer's whole job is to read git and a mocked git would be exactly the
consumes-its-own-output control the doctrine forbids.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
for _p in (SRC, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from quaestor.core import domain
from quaestor.executors import claude_auth as preflight_mod
from quaestor.core import runfiles  # noqa: E402
from quaestor.core.dispatcher import dispatch  # noqa: E402
from quaestor.core.store import Store  # noqa: E402


def git(args, cwd):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, shell=False, timeout=120)
    if p.returncode != 0:
        raise RuntimeError("git %s failed in %s: %s"
                           % (" ".join(args), cwd, p.stderr.decode("utf-8", "replace")))
    return p.stdout.decode("utf-8", "replace")


def make_fixture_repo(path: str, *, files=None, empty: bool = False) -> str:
    """A disposable git repo. Returns its absolute path.

    ``core.hooksPath=`` and explicit identity so a developer's global config cannot change what
    the suite measures -- the environment is stated rather than inherited.
    """
    os.makedirs(path, exist_ok=True)
    git(["init", "-b", "main"], path)
    git(["config", "user.email", "fixture@example.invalid"], path)
    git(["config", "user.name", "Fixture"], path)
    git(["config", "core.hooksPath", ""], path)
    git(["config", "commit.gpgsign", "false"], path)
    if empty:
        # An EMPTY repo still needs a commit so HEAD resolves; the point is ZERO TRACKED FILES
        # after it, which is what makes the evidence floor bite.
        git(["commit", "--allow-empty", "-m", "empty"], path)
        return os.path.abspath(path)
    files = files or {"README.md": "fixture\n", "FACT.txt": "orchestrator-fixture\n"}
    for name, body in files.items():
        full = os.path.join(path, name)
        os.makedirs(os.path.dirname(full) or path, exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    git(["add", "-A"], path)
    git(["commit", "-m", "fixture"], path)
    # A remote-tracking ref so `origin/main..HEAD` is ANSWERABLE. Without it the retirement
    # proofs are correctly UNEVALUABLE, which is the right verdict for a repo with no remote but
    # the wrong fixture for a positive control -- and a positive control that cannot pass proves
    # nothing about the negative ones beside it.
    git(["update-ref", "refs/remotes/origin/main", "HEAD"], path)
    return os.path.abspath(path)


class Sandbox:
    """A temp dir holding a store, a runs root, and any fixture repos a test needs."""

    def __init__(self, prefix="quaestor-test-"):
        self.dir = tempfile.mkdtemp(prefix=prefix)
        self.db = os.path.join(self.dir, "orchestrator.sqlite3")
        self.runs = os.path.join(self.dir, "runs")
        os.makedirs(self.runs, exist_ok=True)
        self.store = Store(self.db)
        self._repos = {}

    def repo(self, name="repo", **kw) -> str:
        if name not in self._repos:
            self._repos[name] = make_fixture_repo(os.path.join(self.dir, name), **kw)
        return self._repos[name]

    def head(self, name="repo") -> str:
        return git(["rev-parse", "HEAD"], self._repos[name]).strip().lower()

    def close(self):
        try:
            self.store.close()
        except Exception:  # noqa: BLE001
            pass
        for _ in range(5):
            try:
                shutil.rmtree(self.dir, ignore_errors=False)
                return
            except OSError:
                time.sleep(0.3)
        shutil.rmtree(self.dir, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# preflight injection -- the suite must never depend on the developer's real credentials
# ---------------------------------------------------------------------------------------------
GOOD_AUTH = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
             "subscriptionType": "max", "email": "someone@example.invalid",
             "orgId": "org-should-never-be-persisted"}


def preflight_stub(env=None, auth=None):
    """A preflight callable with an INJECTED environment and auth status."""
    env = {} if env is None else dict(env)
    auth = GOOD_AUTH if auth is None else auth

    def _pf(*, claude_path="claude", requires_write=False):
        d = preflight_mod.decide(env=env, auth_status=auth, requires_write=requires_write)
        rec = dict(d.record)
        rec["claude_version"] = "test-stub"
        return preflight_mod.PreflightDecision(d.decision, d.reason, d.detail, d.auth_class,
                                               d.offending_vars, rec)

    return _pf


def inline_spawner(pid=None):
    """A spawner that records a pid without starting anything, so the run reaches DISPATCHED."""
    def _spawn(*, db_path, run_id):
        return int(pid or os.getpid())
    return _spawn


def dispatch_inline(sandbox: Sandbox, spec, *, env=None, auth=None, probe=None):
    """Dispatch with a recorded (not spawned) worker, then run the worker IN THIS PROCESS."""
    from quaestor.workspace import git as repo_mod
    from quaestor.core import worker as worker_mod
    res = dispatch(sandbox.store, spec, run_root=sandbox.runs,
                   preflight=preflight_stub(env, auth), spawner=inline_spawner(),
                   probe=probe or repo_mod.probe)
    if res.outcome != "ADMITTED":
        return res, None
    rc = worker_mod.run_worker(db_path=sandbox.db, run_id=res.run_id)
    return res, rc


def dispatch_detached(sandbox: Sandbox, spec, *, env=None, auth=None):
    """Dispatch with the REAL detached worker. Used only where OS semantics are the subject."""
    return dispatch(sandbox.store, spec, run_root=sandbox.runs,
                    preflight=preflight_stub(env, auth))


def wait_for_state(store: Store, run_id: str, *, states, timeout=45.0, poll=0.25):
    """Poll until the run reaches one of ``states``. Returns the final row.

    A polling helper is a measurement, so it reports what it actually saw: on timeout it returns
    the last row rather than raising, and the caller asserts -- so a failure message names the
    state the run was really in, not merely that a wait expired.
    """
    deadline = time.time() + float(timeout)
    row = store.get_run(run_id)
    while time.time() < deadline:
        row = store.get_run(run_id)
        if row and str(row["execution_state"]) in set(states):
            return row
        time.sleep(poll)
    return row


def wait_for_terminal(store: Store, run_id: str, timeout=45.0):
    return wait_for_state(store, run_id, states=set(domain.TERMINAL_STATES), timeout=timeout)


def run_file(sandbox: Sandbox, run_id: str, name: str) -> str:
    run = sandbox.store.get_run(run_id)
    return runfiles.p(str(run["run_dir"]), name)


def runfiles_read(sandbox: Sandbox, run_id: str, name: str) -> str:
    return runfiles.read_text(run_file(sandbox, run_id, name))


# ---------------------------------------------------------------------------------------------
# import-graph resolution -- shared by every structural control that walks imports
# ---------------------------------------------------------------------------------------------
def resolve_imports(node, module_name: str, is_package: bool) -> list:
    """Fully-qualified module names an import node names. PURE. NEVER raises.

    WHY THIS IS NOT INLINE IN THREE PLACES ANY MORE
    -----------------------------------------------
    Three structural controls walked the import graph, and all three keyed on
    ``node.module``. That is blind to relative imports in the dangerous direction:

      * ``from . import worker``  -> node.module is None, so the edge vanished entirely;
      * ``from .core import x``   -> node.module is "core", which resolves to a top-level
        package that does not exist, so the edge vanished AND the walk reported no error.

    The repository this platform was extracted FROM used relative imports exclusively. A walk
    that cannot see them would have reported a clean layering graph over a tree whose edges it
    could not read -- the same defect class as a gate that inspects nothing and returns PASS.

    ``is_package`` matters: inside ``pkg/__init__.py`` a level-1 import is anchored at ``pkg``,
    while inside ``pkg/mod.py`` it is anchored at ``pkg`` too -- but level 2 from the module means
    ``pkg``'s parent. Getting this wrong silently shifts every relative edge by one package.
    """
    import ast as _ast
    if isinstance(node, _ast.Import):
        return [a.name for a in node.names]
    if not isinstance(node, _ast.ImportFrom):
        return []
    level = int(node.level or 0)
    if level == 0:
        base = node.module or ""
        return ([base] + ["%s.%s" % (base, a.name) for a in node.names]) if base else []
    parts = module_name.split(".")
    anchor = parts if is_package else parts[:-1]
    if level > 1:
        anchor = anchor[:-(level - 1)]
    if not anchor:
        return []
    base = ".".join(anchor + ([node.module] if node.module else []))
    return [base] + ["%s.%s" % (base, a.name) for a in node.names]


# ---------------------------------------------------------------------------------------------
# container images used by the LIVE controls
# ---------------------------------------------------------------------------------------------
def live_tmpdir(prefix: str) -> str:
    """A temp dir that is REAL on both sides of the docker socket, when that matters.

    When the suite itself runs inside a container that talks to the host's docker socket, a
    directory a control bind-mounts into a sibling container must exist at the SAME path on the
    host -- the daemon resolves bind sources against the host filesystem, not the calling
    container's. Set QUAESTOR_HOST_TMP to a directory mounted at an identical host/container path,
    and a fixture dir created here is visible to the sibling.

    WITHOUT the variable this is tempfile.mkdtemp(): fast, local, and correct wherever the suite
    runs directly on the docker host (a developer machine, a GitHub-hosted runner). Do not set the
    variable globally -- the suite is temp-dir-heavy, and pointing ALL of its tempfile churn at a
    slow disk measured as a 5x slowdown. Scoping is the fix: only the LIVE docker controls pay
    the host-visible price.
    """
    host_tmp = os.environ.get("QUAESTOR_HOST_TMP")
    if host_tmp:
        os.makedirs(host_tmp, exist_ok=True)
        return tempfile.mkdtemp(prefix=prefix, dir=host_tmp)
    return tempfile.mkdtemp(prefix=prefix)


def test_image(phase: str) -> str:
    """The container image a live control should use, from configuration. PURE-ish (reads env).

    Finding #49 in the extraction review: renaming Docker resource identities means teardown and
    reconciliation key on names that PRE-EXISTING resources do not carry. An image built under a
    deployment's own tag does not acquire this platform's tag by being extracted, and a control
    that hard-codes either name is wrong on some machine.

    So the reference is configuration with a branded default, and every caller that cannot find
    it must say WHICH reference it looked for -- an environment-dependent verdict that does not
    state its environment is the thing this repository keeps paying for.
    """
    import quaestor.branding as _b
    return os.environ.get(_b.env_var("test", "image", phase),
                          "%s-claude:%s" % (_b.RESOURCE_PREFIX, phase))

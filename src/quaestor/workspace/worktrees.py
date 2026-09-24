"""worktrees -- lane workspaces, and the deterministic parent-side git the control plane owns.

WHY THE CONTROL PLANE COMMITS, NOT THE CHILD
--------------------------------------------
An implementation child holds STANDARD_EDIT: Read/Glob/Grep/Edit/Write. It can change files; it
cannot run ``git commit`` -- blanket Bash is never pre-approved (see executors.claude_code), and
committing is how candidate work becomes MERGEABLE. So the commit is performed by the SCHEDULER,
deterministically, after the run's evidence is durable:

    * the same diff that evidence measured is what gets committed -- no third state exists;
    * the commit message is derived from durable ids, not from model prose;
    * the model never needs, and never gets, a capability whose blast radius includes history.

GIT_PUSH stays owner-gated everywhere. Integration merges locally and stops at the boundary.

EVERY WRITE LANE OWNS EXACTLY ONE WORKTREE
------------------------------------------
Two write agents in one mutable tree corrupt each other's diffs and each other's evidence. The
scheduler creates one linked worktree per implementation lane, under the deployment home -- never
inside the project repository -- and the dispatcher's lease plus drift checks make concurrent
reuse impossible rather than discouraged.
"""
from __future__ import annotations

import os
from typing import Callable, Sequence

from quaestor import branding
from quaestor.workspace.git import GitResult, run_git

WORKTREE_TIMEOUT_S = 120.0

#: Committer identity for control-plane commits. CONSTANT, deterministic, attributable: every
#: commit a program produces names its maker.
COMMITTER_NAME = branding.COMMITTER_NAME
COMMITTER_EMAIL = branding.COMMITTER_EMAIL

# Outcomes
OK = "OK"


def worktree_root(home: str) -> str:
    """Where lane worktrees live: under the DEPLOYMENT HOME, never in a project repo. PURE."""
    return os.path.join(str(home or ""), "worktrees")


def lane_worktree_path(home: str, program_id: str, lane_id: str) -> str:
    """Deterministic per-lane path. PURE."""
    return os.path.join(worktree_root(home), str(program_id), str(lane_id))


def branch_name(program_id: str, lane_id: str) -> str:
    """The lane's branch. PURE. Deterministic so integration can find it without asking anyone."""
    return branding.branch(program_id, lane_id)


def _run(args, *, cwd: str, timeout: float = WORKTREE_TIMEOUT_S) -> GitResult:
    return run_git(args, cwd=cwd, timeout=timeout)


#: Interpreter noise that must NEVER enter a control-plane commit. Appended to the repository's
#: SHARED .git/info/exclude (the common dir -- repo-local, never touches the user's project
#: files): verification runs Python inside these trees, and an evidence-honest commit that
#: swallows half a megabyte of bytecode makes the candidate undiffable. Re-asserted at every
#: ``commit_all`` as well as worktree creation, so trees created before the rule existed -- or
#: whose exclude file was removed -- are still protected at the moment it matters.
BUILTIN_EXCLUDES = ("__pycache__/", "*.pyc", ".pytest_cache/", "*.egg-info/")


#: Sentinel path used ONLY to interrogate the ignore machinery. ``git check-ignore`` evaluates
#: patterns against the path TEXT, so the probe never has to exist on disk. It is drawn from the
#: BUILTIN_EXCLUDES noise class because that is exactly what poisoned a live commit once: the
#: excludes were written to a location that cannot exist in a linked worktree, the failure was
#: swallowed, and bytecode rode every subsequent ``git add -A`` into candidate history.
IGNORE_PROBE_PATH = "__pycache__/quaestor-ignore-probe.pyc"


def _excludes_effective(path: str, git: Callable[..., GitResult] = _run) -> bool:
    """Ask GIT -- the actual enforcer -- whether the interpreter-noise policy bites NOW.

    Writing the exclude rule is not enforcing it; only git's own answer about the rules that
    WILL govern the next ``add`` counts as evidence, and provenance is deliberately ignored
    (our shared exclude block or a repository .gitignore both satisfy the POLICY, which is
    "bytecode never enters a candidate commit"). Any non-zero exit -- "not ignored" but also
    tool failure -- counts as NOT effective: fail closed. NEVER raises.
    """
    try:
        return git(["check-ignore", "--quiet", IGNORE_PROBE_PATH], cwd=path).rc == 0
    except Exception:  # noqa: BLE001
        return False


def _validate_stage_paths(path: str,
                          stage_paths: Sequence[str]) -> tuple:
    """Split requested explicit-stage paths into ``(valid, skipped_missing, refused)``.

    Explicit staging hands the control plane a narrower weapon than ``add -A``, so the
    validation must be as paranoid as the sweep it replaces: an ABSOLUTE path addresses
    outside the tree by construction, and anything whose real resolution escapes the
    worktree (``../sibling``, symlinked directories) would stage another checkout's files.
    A path resolving to the WORKTREE ROOT ITSELF is refused too -- ``"."`` would smuggle
    add -A semantics back in through the explicit door, past the very probe it bypasses.
    Missing paths are not an error (a claimed file may legitimately have produced no
    measured change); they are skipped AND recorded so the caller can audit the gap.
    """
    root = os.path.normcase(os.path.realpath(path))
    valid, skipped, refused = [], [], []
    for raw in stage_paths:
        p = str(raw)
        if os.path.isabs(p):
            refused.append(p)
            continue
        real = os.path.normcase(os.path.realpath(os.path.join(path, p)))
        if real == root or not real.startswith(root + os.sep):
            refused.append(p)
            continue
        if not os.path.lexists(os.path.join(path, p)):
            skipped.append(p)
            continue
        valid.append(p)
    return valid, skipped, refused


def _common_git_dir(path: str, git: Callable[..., GitResult] = _run) -> str:
    """The repository's SHARED .git directory for a worktree at ``path``. NEVER raises.

    In a linked worktree ``<worktree>/.git`` is a FILE, not a directory, so any code that joins
    ``path/.git/info/...`` addresses a location that cannot exist. The shared excludes live under
    the COMMON dir; ask git rather than guessing.
    """
    try:
        r = git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=path)
        out = r.out.strip() if r.ok else ""
        if not out:
            r2 = git(["rev-parse", "--git-common-dir"], cwd=path)
            out = r2.out.strip() if r2.ok else ""
            if out and not os.path.isabs(out):
                out = os.path.abspath(os.path.join(path, out))
        return out
    except Exception:  # noqa: BLE001
        return ""


def _ensure_excludes(path: str, git: Callable[..., GitResult] = _run) -> None:
    try:
        common = _common_git_dir(path, git)
        if not common or not os.path.isdir(common):
            return
        exclude_path = os.path.join(common, "info", "exclude")
        os.makedirs(os.path.dirname(exclude_path), exist_ok=True)
        existing = ""
        if os.path.isfile(exclude_path):
            with open(exclude_path, encoding="utf-8") as fh:
                existing = fh.read()
        marker = "# quaestor:begin"
        if marker in existing:
            return
        with open(exclude_path, "a", encoding="utf-8", newline="\n") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(marker + "\n")
            for line in BUILTIN_EXCLUDES:
                fh.write(line + "\n")
            fh.write("# quaestor:end\n")
    except OSError:
        pass


def create_lane_worktree(repo_root: str, path: str, *, branch: str, base_ref: str = "",
                         git: Callable[..., GitResult] = _run) -> dict:
    """Create a linked worktree on a NEW branch. Impure. NEVER raises; reports what it did.

    ``base_ref`` empty means the current HEAD of ``repo_root``. The branch is created here, so a
    later re-creation attempt is refused by git itself rather than silently reused with stale
    contents -- reuse-after-crash goes through ``existing_lane_worktree`` instead, which MEASURES
    the directory it finds.
    """
    if os.path.isdir(path) and os.listdir(path):
        snap = git(["rev-parse", "--show-toplevel"], cwd=path)
        head = git(["rev-parse", "HEAD"], cwd=path)
        br = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=path)
        if snap.ok and os.path.normcase(os.path.abspath(snap.out.strip())) == \
                os.path.normcase(os.path.abspath(path)):
            return {"ok": True, "path": path, "branch": br.out.strip() if br.ok else "",
                    "head": head.out.strip().lower() if head.ok else "",
                    "created": False, "error": ""}
        return {"ok": False, "path": path, "branch": "", "head": "", "created": False,
                "error": "target path exists, is not empty, and is not the expected worktree"}
    args = ["worktree", "add", "-b", branch, path]
    if base_ref:
        args.append(base_ref)
    r = git(args, cwd=repo_root)
    if not r.ok:
        return {"ok": False, "path": path, "branch": branch, "head": "", "created": False,
                "error": r.err.strip() or "rc=%s" % r.rc}
    head = git(["rev-parse", "HEAD"], cwd=path)
    _ensure_excludes(path, git)
    return {"ok": True, "path": path, "branch": branch,
            "head": head.out.strip().lower() if head.ok else "", "created": True, "error": ""}


def probe_worktree(path: str, *, git: Callable[..., GitResult] = _run) -> dict:
    """A minimal identity reading of a directory that should be a worktree. NEVER raises."""
    top = git(["rev-parse", "--show-toplevel"], cwd=path)
    if not top.ok:
        return {"exists": False, "is_worktree": False, "head": "", "branch": "", "dirty": None}
    head = git(["rev-parse", "HEAD"], cwd=path)
    br = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=path)
    st = git(["status", "--porcelain=v1"], cwd=path)
    return {"exists": True, "is_worktree": True,
            "head": head.out.strip().lower() if head.ok else "",
            "branch": br.out.strip() if br.ok else "",
            "dirty": bool(st.out.strip()) if st.ok else None}


def changed_files(path: str, *, base: str = "HEAD",
                  git: Callable[..., GitResult] = _run) -> list:
    """Repository-relative paths changed relative to ``base``. Untracked included. NEVER raises."""
    r = git(["diff", "--name-only", "--no-color", base], cwd=path)
    out = [ln.strip() for ln in r.out.splitlines() if ln.strip()] if r.ok else []
    u = git(["ls-files", "--others", "--exclude-standard"], cwd=path)
    if u.ok:
        out.extend(ln.strip() for ln in u.out.splitlines() if ln.strip())
    return sorted(set(out))


def commit_all(path: str, *, message: str,
               stage_paths: Sequence[str] | None = None,
               git: Callable[..., GitResult] = _run) -> dict:
    """Deterministically commit EVERYTHING in this worktree. Impure. NEVER raises.

    FAIL-CLOSED BY DEFAULT: before any ``git add -A``, the interpreter-noise exclusion policy
    is PROVEN effective with a real git probe (``git check-ignore``), not assumed. The live F1
    incident is why: ``_ensure_excludes`` once wrote to a location that CANNOT exist in a
    linked worktree (``.git`` there is a file), the OSError was swallowed, and every
    acceptance commit then swept bytecode into the candidate. Re-asserting the rule fixes the
    write but not the SILENCE -- so if git itself cannot demonstrate the policy after one
    repair attempt, the commit is REFUSED outright (``refused=True``, reason
    ``EXCLUSION_POLICY_UNVERIFIED``) with nothing staged. A missed commit can be retried; a
    contaminated one poisons integration and every diff built on it.

    ``stage_paths`` switches to EXPLICIT staging: exactly the named worktree-relative files
    are staged and committed and NOTHING else is swept. Explicit selection IS the policy, so
    the exclusion probe is skipped; absolute paths or anything resolving outside the worktree
    refuse the whole call (reason ``STAGE_PATH_REFUSED``), and paths that do not exist are
    skipped and reported under ``skipped_paths``.

    A clean tree commits nothing and reports sha="" -- that is success, not failure: research and
    review lanes legitimately end with no changes, and treating "nothing changed" as an error
    would manufacture failures out of correct behaviour.
    """
    ident = ["-c", "user.name=%s" % COMMITTER_NAME, "-c", "user.email=%s" % COMMITTER_EMAIL]

    # ---- explicit staging branch ---------------------------------------------------------
    if stage_paths:
        valid, skipped, violations = _validate_stage_paths(path, stage_paths)
        if violations:
            reason = "STAGE_PATH_REFUSED: %s" % ", ".join(violations)
            return {"ok": False, "refused": True, "reason": reason, "sha": "",
                    "changed": 0, "already_clean": False, "error": reason}
        if not valid:
            # Every requested path was missing: nothing to stage, nothing to commit. That is
            # the honest already-clean answer, not an error -- same doctrine as an empty tree.
            return {"ok": True, "sha": "", "changed": 0, "already_clean": True,
                    "error": "", "skipped_paths": skipped}
        add = git([*ident, "add", "--", *valid], cwd=path)
        if not add.ok:
            return {"ok": False, "sha": "", "changed": 0, "already_clean": False,
                    "error": add.err.strip() or "git add failed", "skipped_paths": skipped}
        # Under explicit staging, a dirty TREE says nothing about what is STAGED: other
        # lanes'/runs' edits must stay uncommitted, so measure the INDEX, not the tree.
        staged = git(["diff", "--cached", "--name-only", "--no-color", "HEAD"], cwd=path)
        if staged.ok and not staged.out.strip():
            return {"ok": True, "sha": "", "changed": 0, "already_clean": True,
                    "error": "", "skipped_paths": skipped}
        c = git([*ident, "commit", "-m", str(message)], cwd=path)
        if not c.ok:
            return {"ok": False, "sha": "", "changed": 0, "already_clean": False,
                    "error": c.err.strip() or "git commit failed", "skipped_paths": skipped}
        rev = git(["rev-parse", "HEAD"], cwd=path)
        n = git(["diff", "--name-only", "--no-color", "HEAD~1", "HEAD"], cwd=path)
        return {"ok": True,
                "sha": rev.out.strip().lower() if rev.ok else "",
                "changed": sum(1 for ln in n.out.splitlines() if ln.strip()) if n.ok else 0,
                "already_clean": False, "error": "", "skipped_paths": skipped}

    # ---- sweep path (add -A): gated by the fail-closed exclusion probe -------------------
    _ensure_excludes(path, git)
    probe = _excludes_effective(path, git)
    if not probe:
        # One repair attempt covers the historical failure modes: excludes deleted after
        # creation, or trees created before the rule existed at all.
        _ensure_excludes(path, git)
        if not _excludes_effective(path, git):
            reason = ("EXCLUSION_POLICY_UNVERIFIED: git check-ignore does not report %s as "
                      "ignored even after re-asserting excludes" % IGNORE_PROBE_PATH)
            return {"ok": False, "refused": True, "reason": reason, "sha": "",
                    "changed": 0, "already_clean": False, "error": reason}

    add = git([*ident, "add", "-A"], cwd=path)
    if not add.ok:
        return {"ok": False, "sha": "", "changed": 0, "already_clean": False,
                "error": add.err.strip() or "git add failed"}
    dirty = git(["status", "--porcelain=v1"], cwd=path)
    if dirty.ok and not dirty.out.strip():
        return {"ok": True, "sha": "", "changed": 0, "already_clean": True, "error": ""}
    c = git([*ident, "commit", "-m", str(message)], cwd=path)
    if not c.ok:
        return {"ok": False, "sha": "", "changed": 0, "already_clean": False,
                "error": c.err.strip() or "git commit failed"}
    rev = git(["rev-parse", "HEAD"], cwd=path)
    n = git(["diff", "--name-only", "--no-color", "HEAD~1", "HEAD"], cwd=path)
    return {"ok": True, "sha": rev.out.strip().lower() if rev.ok else "",
            "changed": sum(1 for ln in n.out.splitlines() if ln.strip()) if n.ok else 0,
            "already_clean": False, "error": ""}


def merge_branch(path: str, branch: str, *, message: str,
                 git: Callable[..., GitResult] = _run) -> dict:
    """Merge a lane branch into an integration worktree. NEVER raises.

    A CONFLICT is reported as a conflict, not as a generic failure: §32's minimum protection is
    that a merge collision forces re-evaluation instead of surfacing later as an unexplained
    broken build.
    """
    ident = ["-c", "user.name=%s" % COMMITTER_NAME, "-c", "user.email=%s" % COMMITTER_EMAIL]
    m = git([*ident, "merge", "--no-ff", "-m", str(message), branch], cwd=path)
    if m.ok:
        rev = git(["rev-parse", "HEAD"], cwd=path)
        return {"ok": True, "conflict": False, "merged_branch": branch,
                "head": rev.out.strip().lower() if rev.ok else "", "error": ""}
    abort = git([*ident, "merge", "--abort"], cwd=path)
    return {"ok": False, "conflict": True, "merged_branch": branch, "head": "",
            "error": m.err.strip() or m.out.strip() or "merge failed",
            "aborted": abort.ok}


def reset_worktree(path: str, *, git: Callable[..., GitResult] = _run) -> dict:
    """Hard-reset a lane worktree to HEAD and drop untracked files. Impure. NEVER raises.

    ONLY for lane worktrees the control plane created: everything in them is program work, so
    "untracked" cannot mean a human's precious file. This is what makes a retry measure only
    the retry -- an invalid-protocol run's half-written edits are untrusted output, not state
    to build on.
    """
    r1 = git(["reset", "--hard", "HEAD"], cwd=path)
    r2 = git(["clean", "-fdq"], cwd=path)
    return {"ok": r1.ok and r2.ok,
            "error": "" if (r1.ok and r2.ok) else (r1.err.strip() or r2.err.strip())}


def remove_worktree(repo_root: str, path: str, *,
                    git: Callable[..., GitResult] = _run) -> dict:
    """Remove a lane worktree. Evidence lives elsewhere, so this deletes NO evidence. NEVER raises."""
    r = git(["worktree", "remove", "--force", path], cwd=repo_root)
    return {"ok": r.ok, "path": path,
            "error": "" if r.ok else (r.err.strip() or "rc=%s" % r.rc)}

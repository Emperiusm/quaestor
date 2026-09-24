"""repo -- the git I/O adapter, plus the PURE parsing it depends on.

SPLIT DELIBERATELY, following the source deployment's idiom:
parsing and drift decisions are pure functions over injected strings, so the tests assert the
dangerous paths without needing a repository in a particular state. Only ``probe()`` shells out.

NO ``shell=True`` ANYWHERE. Argument arrays only.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from quaestor.core.canon import canonical_path, sha256_text
from quaestor.evidence.model import RepoSnapshot, snapshot_digest

GIT_TIMEOUT_S = 60

# Drift outcomes
NO_DRIFT = "NO_DRIFT"
HEAD_DRIFT = "HEAD_DRIFT"
BRANCH_DRIFT = "BRANCH_DRIFT"
WORKTREE_UNREADABLE = "WORKTREE_UNREADABLE"


@dataclass(frozen=True)
class GitResult:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run_git(args: Sequence[str], *, cwd: str, timeout: float = GIT_TIMEOUT_S) -> GitResult:
    """git, as bytes decoded explicitly. Impure. NEVER raises.

    ``text=True`` is NOT used, and that is not a style choice. It was measured: subprocess text
    mode decodes with the locale codepage (cp1252 on this box), so every non-ASCII byte in a
    filename or a branch comes back as mojibake -- and a read-modify-write of that value silently
    corrupts the record. Decode UTF-8 with an explicit replacement policy instead.
    """
    # GIT_OPTIONAL_LOCKS=0 -- A READ MUST NOT WRITE.
    # `git status` and `git diff HEAD` refresh and REWRITE `.git/index` whenever the stat cache
    # is stale, which is the normal state of a live repository. That takes `.git/index.lock`, so
    # a probe can collide with an operator's own `git commit` ("Unable to create index.lock"),
    # and it means a nominally read-only inspection mutates the repository it inspects.
    #
    # This project already knew: `proc.py` warns that "the sweeper's own git status refreshed the
    # index it was reading", and the P3/P4 drivers set this variable for exactly that reason. It
    # was missing from the ONE git seam every caller reaches. Measured by adversarial review: a
    # single transport dispatch spawned 13 git children and changed the fixture's index hash.
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        p = subprocess.run(["git", *[str(a) for a in args]], cwd=cwd, capture_output=True,
                           timeout=timeout, shell=False, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        return GitResult(127, "", "%s: %s" % (type(exc).__name__, exc))
    return GitResult(p.returncode,
                     p.stdout.decode("utf-8", "replace"),
                     p.stderr.decode("utf-8", "replace"))


# ---------------------------------------------------------------------------------------------
# PURE parsing
# ---------------------------------------------------------------------------------------------
def parse_porcelain(text: str) -> tuple:
    """Paths from ``git status --porcelain=v1``. PURE.

    Rename entries (``R  old -> new``) yield BOTH sides: a rename changed both paths, and
    recording only the destination would let a run delete a file while the evidence shows an
    addition. Quoted paths keep their quotes -- this is an identity for comparison between two
    readings of the same repo by the same parser, not a filesystem path we ever open.
    """
    paths = []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        if len(line) < 4:
            continue
        rest = line[3:]
        if " -> " in rest:
            old, _, new = rest.partition(" -> ")
            paths.extend([old.strip(), new.strip()])
        else:
            paths.append(rest.strip())
    return tuple(sorted(p for p in paths if p))


def count_lines(text: str) -> int:
    """Non-empty line count. PURE. This is the evidence FLOOR's raw number."""
    return sum(1 for ln in (text or "").splitlines() if ln.strip())


def classify_drift(*, expected_branch: str, expected_head: str,
                   snapshot: RepoSnapshot) -> str:
    """Has the worktree moved since admission? PURE.

    Called immediately BEFORE the child is launched, not only at admission. The window between
    "we checked" and "we ran" is exactly where another lane's commit lands, and a lease that was
    valid ten seconds ago is not evidence about the tree now.

    An UNREADABLE worktree is its own answer and refuses -- it is never treated as "no drift".
    """
    if not snapshot.probe_ok:
        return WORKTREE_UNREADABLE
    if expected_head and (snapshot.head or "").lower() != str(expected_head).lower():
        return HEAD_DRIFT
    if expected_branch and (snapshot.branch or "") != str(expected_branch):
        return BRANCH_DRIFT
    return NO_DRIFT


def repo_id_for(remote_url: str, root: str) -> str:
    """A stable repository identity. PURE.

    Prefers the origin URL normalised to ``host/owner/name``; falls back to a digest of the
    canonical root so a repo with no remote still gets a stable, non-colliding id rather than an
    empty string that would make every local fixture the same repository.
    """
    u = str(remote_url or "").strip()
    if u:
        u = u.removesuffix(".git")
        for pre in ("git@", "ssh://git@", "https://", "http://"):
            if u.startswith(pre):
                u = u[len(pre):]
                break
        return u.replace(":", "/").strip("/").lower()
    return "local:" + sha256_text(canonical_path(root))[:16]


# ---------------------------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------------------------
def probe(worktree_path: str, *, git: Callable[..., GitResult] = run_git,
          want_diff: bool = True) -> RepoSnapshot:
    """One independent reading of a worktree. Impure. NEVER raises.

    Every failure lands on ``probe_ok=False`` with a NAMED error, and in that state no other
    field may be read as a measurement. That asymmetry is the point: this function's job is to
    record what it saw, and its refusal to guess is what makes the envelope built from it
    trustworthy.
    """
    root_r = git(["rev-parse", "--show-toplevel"], cwd=worktree_path)
    if not root_r.ok:
        return RepoSnapshot(repo_root=canonical_path(worktree_path), probe_ok=False,
                            probe_error="rev-parse --show-toplevel: %s"
                                        % (root_r.err.strip() or "rc=%d" % root_r.rc))
    root = canonical_path(root_r.out.strip())

    head_r = git(["rev-parse", "HEAD"], cwd=worktree_path)
    branch_r = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=worktree_path)
    status_r = git(["status", "--porcelain=v1", "--untracked-files=all"], cwd=worktree_path)
    files_r = git(["ls-files"], cwd=worktree_path)

    if not (head_r.ok and branch_r.ok and status_r.ok and files_r.ok):
        failed = [n for n, r in (("rev-parse HEAD", head_r), ("abbrev-ref", branch_r),
                                 ("status", status_r), ("ls-files", files_r)) if not r.ok]
        return RepoSnapshot(repo_root=root, probe_ok=False,
                            probe_error="git sub-probe failed: %s" % ", ".join(failed))

    paths = parse_porcelain(status_r.out)
    tracked = count_lines(files_r.out)

    diff_digest = None
    if want_diff:
        d = git(["diff", "HEAD", "--no-color"], cwd=worktree_path)
        # A failed diff is recorded as UNKNOWN (None), never as the digest of an empty string --
        # that would make "could not diff" indistinguishable from "no differences".
        diff_digest = sha256_text(d.out) if d.ok else None

    return RepoSnapshot(
        repo_root=root,
        branch=branch_r.out.strip() or None,
        head=head_r.out.strip().lower() or None,
        dirty=bool(paths),
        changed_paths=paths,
        tracked_file_count=tracked,
        status_digest=snapshot_digest(paths),
        diff_sha256=diff_digest,
        probe_ok=True,
    )


def origin_url(worktree_path: str, *, git: Callable[..., GitResult] = run_git) -> str:
    r = git(["config", "--get", "remote.origin.url"], cwd=worktree_path)
    return r.out.strip() if r.ok else ""


def is_linked_worktree(worktree_path: str, *, git: Callable[..., GitResult] = run_git) -> bool:
    """PRIMARY checkout or LINKED worktree? Impure.

    The same test the source deployment uses: ``--git-dir`` and ``--git-common-dir`` normalise
    to the same path in a primary checkout and differ in a linked worktree.
    """
    g = git(["rev-parse", "--git-dir"], cwd=worktree_path)
    c = git(["rev-parse", "--git-common-dir"], cwd=worktree_path)
    if not (g.ok and c.ok):
        return False
    return canonical_path(_abs_against(g.out.strip(), worktree_path)) != \
        canonical_path(_abs_against(c.out.strip(), worktree_path))


def worktree_identity(worktree_path: str, *, git: Callable[..., GitResult] = run_git) -> dict:
    """The git identity visible AT a path. Impure. NEVER raises.

    Used to prove, independently of anything the child says, that the directory we leased is a
    LINKED WORKTREE OF THE INTENDED REPOSITORY -- not a lookalike, not the primary checkout, and
    not a stray directory whose `git` answers are really about a parent repo. That last case is a
    measured the source deployment hazard: a directory with no `.git` makes `git -C <dir> status` succeed by
    walking UP to the parent, reporting the parent's cleanliness as if it were the stray's. The
    `toplevel` field is what catches it.
    """
    def one(args):
        r = git(args, cwd=worktree_path)
        return r.out.strip() if r.ok else ""

    git_dir = one(["rev-parse", "--git-dir"])
    common = one(["rev-parse", "--git-common-dir"])
    top = one(["rev-parse", "--show-toplevel"])
    return {
        "toplevel": canonical_path(top) if top else "",
        "git_dir": canonical_path(_abs_against(git_dir, worktree_path)) if git_dir else "",
        "git_common_dir": canonical_path(_abs_against(common, worktree_path)) if common else "",
        "head": one(["rev-parse", "HEAD"]).lower(),
        "branch": one(["rev-parse", "--abbrev-ref", "HEAD"]),
        "is_linked_worktree": bool(git_dir and common
                                   and canonical_path(_abs_against(git_dir, worktree_path))
                                   != canonical_path(_abs_against(common, worktree_path))),
        "resolvable": bool(top and git_dir and common),
    }


def prove_execution_location(*, leased_path: str, launch_cwd: str, request_cwd: str,
                             identity: Mapping, expected_head: str,
                             expected_branch: str, expected_common_dir: str = "") -> dict:
    """Did the child actually run in the exact leased worktree? PURE. NEVER raises.

    "Claude said it was in the right directory" is not evidence -- the subject's own account of
    where it ran is the one thing that cannot corroborate itself. This composes four independent
    readings, none of which is the child's:

      * the WORKER'S launch configuration (the cwd actually handed to the process);
      * the DISPATCHER'S request record (what was leased);
      * the git identity visible AT that path, read afterwards by the bridge;
      * that the path is a LINKED WORKTREE of the expected common dir -- which is what
        distinguishes the real worktree from a lookalike directory, from the primary checkout,
        and from a stray dir whose `git` answers are really about a parent repo.

    A valid handoff produced from the wrong directory is a FAIL, so every clause must hold.
    """
    leased = canonical_path(leased_path)
    checks = {
        "launch_cwd_matches_lease": canonical_path(launch_cwd) == leased and leased != "",
        "request_cwd_matches_lease": canonical_path(request_cwd) == leased and leased != "",
        "path_resolves_as_git": bool(identity.get("resolvable")),
        "toplevel_is_the_leased_path": canonical_path(identity.get("toplevel", "")) == leased,
        "is_linked_worktree": identity.get("is_linked_worktree") is True,
        "head_matches_lease": (str(identity.get("head") or "").lower()
                               == str(expected_head or "").lower() and bool(expected_head)),
        "branch_matches_lease": (str(identity.get("branch") or "") == str(expected_branch or "")
                                 and bool(expected_branch)),
    }
    if expected_common_dir:
        checks["common_dir_is_the_expected_repository"] = (
            canonical_path(identity.get("git_common_dir", "")) == canonical_path(expected_common_dir))
    failed = [k for k, v in checks.items() if v is not True]
    return {"proven": not failed, "checks": checks, "failed": failed,
            "leased_canonical_path": leased}


def _abs_against(path: str, base: str) -> str:
    import os
    p = str(path or "").strip().replace("\\", "/")
    if not p:
        return ""
    if not os.path.isabs(p) and not (len(p) > 1 and p[1] == ":"):
        p = os.path.join(base, p)
    return p

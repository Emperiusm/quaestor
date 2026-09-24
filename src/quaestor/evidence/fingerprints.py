"""fingerprints -- a digest that DECLARES WHAT IT MEASURED, or it is not evidence.

THE DEFECT THIS FILE EXISTS TO FIX (found in P2, 2026-08-13)
------------------------------------------------------------
An early phase reported a "working-state fingerprint" as identical before and after -- and it truly
was, because it digested `git status --porcelain`, i.e. the SET OF DIRTY PATHS. Meanwhile the
CONTENT of `.beads/issues.jsonl` changed underneath it (146/96 -> 217/164) because a concurrent
session was writing. Both statements were true. The problem is that "working-state fingerprint"
sounds like it covers content, so an honest number carried a dishonest implication.

A digest is a claim about its INPUTS. If the name over-claims relative to the inputs, the number
is worse than useless: it is a confident answer to a question nobody actually asked.

So every fingerprint here is a NAMED CLASS with explicit provenance, and the class names say what
is in scope:

    REPO_IDENTITY        HEAD + branch. Says nothing about content or dirt.
    STATUS               the SET of dirty paths and their status codes. NOT their bytes.
    TRACKED_CONTENT      the bytes of tracked files (via git's own object hashing).
    UNTRACKED_INVENTORY  the set of untracked paths. NOT their bytes.
    WORKTREE_INVENTORY   registered worktree paths.
    CONTAINER_MOUNT      the ACTUAL mount table of a running container.
    CONTAINER_SECURITY   the ACTUAL security-relevant runtime config of a running container.
    FILE_BYTES           the literal bytes of one file.
    DIRECTORY_BYTES      path+bytes of every file beneath a directory.

Two rules enforced by construction:

  1. ``Fingerprint`` cannot be built without ``inspected_count``, ``inputs`` and ``algorithm``.
     A digest with no stated input dimension is refused at construction.
  2. ``compare`` returns a tri-state -- SAME / CHANGED / UNCOMPARABLE. Two fingerprints of
     DIFFERENT classes are UNCOMPARABLE, never "changed" and never "same", because comparing a
     status digest to a content digest is the original defect wearing a helpful-looking API.

PURE except the collectors at the bottom, which shell out to git with argument arrays.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from quaestor.core.canon import canonical_json, canonical_path, sha256_bytes, sha256_text

INSTRUMENT_VERSION = "fingerprints/1"

# Classes
REPO_IDENTITY = "REPO_IDENTITY"
STATUS = "STATUS"
TRACKED_CONTENT = "TRACKED_CONTENT"
UNTRACKED_INVENTORY = "UNTRACKED_INVENTORY"
WORKTREE_INVENTORY = "WORKTREE_INVENTORY"
CONTAINER_MOUNT = "CONTAINER_MOUNT"
CONTAINER_SECURITY = "CONTAINER_SECURITY"
FILE_BYTES = "FILE_BYTES"
DIRECTORY_BYTES = "DIRECTORY_BYTES"

ALL_CLASSES = (REPO_IDENTITY, STATUS, TRACKED_CONTENT, UNTRACKED_INVENTORY, WORKTREE_INVENTORY,
               CONTAINER_MOUNT, CONTAINER_SECURITY, FILE_BYTES, DIRECTORY_BYTES)

#: What each class does and does NOT cover. Carried INTO the persisted record, so a future reader
#: sees the scope next to the number instead of having to find this file.
CLASS_SCOPE: Mapping[str, str] = {
    REPO_IDENTITY: "HEAD and branch only; says nothing about working-tree content or dirt",
    STATUS: "the SET of dirty paths and their porcelain status codes; NOT their bytes",
    TRACKED_CONTENT: "the bytes of tracked files, via git's own object ids; NOT untracked files",
    UNTRACKED_INVENTORY: "the SET of untracked paths; NOT their bytes",
    WORKTREE_INVENTORY: "registered worktree paths; NOT their contents",
    CONTAINER_MOUNT: "the ACTUAL mount table of a running container as the engine reports it",
    CONTAINER_SECURITY: "the ACTUAL security-relevant runtime config of a running container",
    FILE_BYTES: "the literal bytes of exactly one file",
    DIRECTORY_BYTES: "path AND bytes of every file beneath a directory",
}

# Comparison outcomes
SAME = "SAME"
CHANGED = "CHANGED"
UNCOMPARABLE = "UNCOMPARABLE"

# Drift attribution
P2_5_ATTRIBUTABLE = "ATTRIBUTABLE_TO_THIS_RUN"
FOREIGN_DRIFT_OBSERVED = "FOREIGN_DRIFT_OBSERVED"


class FingerprintRefused(ValueError):
    """A fingerprint was constructed without stating what it measured."""


@dataclass(frozen=True)
class Fingerprint:
    """A digest plus everything needed to know what it is a digest OF."""

    fclass: str
    digest: str
    inspected_count: int
    inputs: str                       # human-readable statement of the input dimension
    algorithm: str = "sha256"
    instrument: str = INSTRUMENT_VERSION
    source_revision: str = ""
    exclusions: tuple = ()
    at: float = 0.0
    run_id: str = ""
    ok: bool = True
    error: str = ""
    detail: Mapping = field(default_factory=dict)

    def __post_init__(self):
        if self.fclass not in ALL_CLASSES:
            raise FingerprintRefused("unknown fingerprint class %r" % (self.fclass,))
        if not str(self.inputs).strip():
            raise FingerprintRefused(
                "%s fingerprint must state its inputs; an unlabelled digest is a claim nobody "
                "can check" % self.fclass)
        if self.ok and int(self.inspected_count) < 0:
            raise FingerprintRefused("inspected_count must be >= 0")

    @property
    def scope(self) -> str:
        return CLASS_SCOPE.get(self.fclass, "")

    def to_dict(self) -> dict:
        return {"class": self.fclass, "digest": self.digest, "algorithm": self.algorithm,
                "instrument": self.instrument, "inspected_count": self.inspected_count,
                "inputs": self.inputs, "scope": self.scope,
                "source_revision": self.source_revision or None,
                "exclusions": list(self.exclusions), "at": self.at,
                "run_id": self.run_id or None, "ok": self.ok, "error": self.error or None,
                "detail": dict(self.detail)}


def _digest(payload: Any) -> str:
    return sha256_text(canonical_json(payload))


def make(fclass: str, payload: Any, *, inspected_count: int, inputs: str,
         source_revision: str = "", exclusions: Sequence[str] = (), at: float = 0.0,
         run_id: str = "", detail: Mapping | None = None) -> Fingerprint:
    """Build a fingerprint over ``payload``. PURE."""
    return Fingerprint(fclass=fclass, digest=_digest(payload), inspected_count=int(inspected_count),
                       inputs=inputs, source_revision=source_revision,
                       exclusions=tuple(exclusions), at=float(at), run_id=run_id,
                       detail=dict(detail or {}))


def unavailable(fclass: str, *, inputs: str, error: str, run_id: str = "") -> Fingerprint:
    """A fingerprint that could NOT be taken. PURE.

    Not an empty digest -- an empty digest is a value, and a value compares equal to another
    empty one, which would make two failed measurements look like agreement.
    """
    return Fingerprint(fclass=fclass, digest="", inspected_count=0, inputs=inputs, ok=False,
                       error=error, run_id=run_id)


def compare(before: Fingerprint | None, after: Fingerprint | None) -> str:
    """SAME / CHANGED / UNCOMPARABLE. PURE. NEVER raises."""
    if before is None or after is None:
        return UNCOMPARABLE
    if before.fclass != after.fclass:
        return UNCOMPARABLE
    if not (before.ok and after.ok):
        return UNCOMPARABLE
    return SAME if before.digest == after.digest else CHANGED


def attribute_drift(fclass: str, verdict: str, *, foreign_paths: Sequence[str] = (),
                    changed_paths: Sequence[str] = ()) -> dict:
    """Classify a CHANGED verdict without erasing it. PURE.

    ATTRIBUTION DOES NOT ERASE THE MUTATION. A drift attributed to a concurrent session is still
    reported as ``FOREIGN_DRIFT_OBSERVED`` with the changed paths listed -- it is never folded
    into "unchanged". P2 got this right in substance and wrong in vocabulary; this makes the
    vocabulary carry it.
    """
    if verdict != CHANGED:
        return {"verdict": verdict, "attribution": None, "changed_paths": list(changed_paths)}
    fset, cset = set(foreign_paths or ()), set(changed_paths or ())
    unattributed = sorted(cset - fset) if cset else []
    return {
        "verdict": CHANGED,
        "attribution": FOREIGN_DRIFT_OBSERVED if (cset and not unattributed) else P2_5_ATTRIBUTABLE,
        "changed_paths": sorted(cset),
        "foreign_paths": sorted(fset & cset),
        "unattributed_paths": unattributed,
        "note": ("content changed during the observation window; attribution names WHO, it does "
                 "not make the change disappear"),
        "class": fclass,
    }


# ---------------------------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------------------------
def _git(args: Sequence[str], cwd: str, timeout: float = 180.0):
    try:
        p = subprocess.run(["git", *[str(a) for a in args]], cwd=cwd, capture_output=True,
                           shell=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)
    if p.returncode != 0:
        return None, "git %s rc=%d: %s" % (args[0], p.returncode,
                                           p.stderr.decode("utf-8", "replace")[:300])
    return p.stdout.decode("utf-8", "replace"), ""


def repo_identity(repo: str, *, at: float = 0.0, run_id: str = "") -> Fingerprint:
    head, e1 = _git(["rev-parse", "HEAD"], repo)
    branch, e2 = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
    if head is None or branch is None:
        return unavailable(REPO_IDENTITY, inputs="git rev-parse HEAD + --abbrev-ref HEAD",
                           error=e1 or e2, run_id=run_id)
    payload = {"head": head.strip().lower(), "branch": branch.strip()}
    return make(REPO_IDENTITY, payload, inspected_count=2,
                inputs="git rev-parse HEAD + --abbrev-ref HEAD", source_revision=payload["head"],
                at=at, run_id=run_id, detail=payload)


def status_fingerprint(repo: str, *, at: float = 0.0, run_id: str = "") -> Fingerprint:
    out, err = _git(["status", "--porcelain=v1", "--untracked-files=all"], repo)
    if out is None:
        return unavailable(STATUS, inputs="git status --porcelain=v1 -uall", error=err,
                           run_id=run_id)
    lines = sorted(l.rstrip("\r") for l in out.splitlines() if l.strip())
    return make(STATUS, lines, inspected_count=len(lines),
                inputs="git status --porcelain=v1 -uall: status codes and paths ONLY, not bytes",
                at=at, run_id=run_id, detail={"lines": lines[:50]})


def tracked_content_fingerprint(repo: str, *, at: float = 0.0, run_id: str = "",
                                exclusions: Sequence[str] = ()) -> Fingerprint:
    """Digest the WORKING-TREE bytes of tracked files.

    THE FIRST VERSION OF THIS FUNCTION WAS WRONG IN EXACTLY THE WAY IT EXISTED TO FIX.
    It hashed ``git ls-files -s`` -- the INDEX blob id per path. Index blob ids do not move when
    the working tree changes; only `git add` moves them, and ``update-index --refresh`` updates
    stat data, not object ids. So a fingerprint named TRACKED_CONTENT would have reported SAME
    across precisely the P2 scenario it was written for: a tracked file edited in the working
    tree. A control caught it, which is the only reason this comment is not a postmortem.

    The correct inputs are HEAD plus the full diff against HEAD: together they determine the
    bytes of every tracked file. ``--binary`` so a binary change is a literal patch rather than a
    one-line "differ" summary that would compare equal for two different binaries.

    ``inspected_count`` is the number of tracked paths seen, which is a real "did I look" number
    -- a repository that suddenly reports 0 tracked files has not become clean.
    """
    head, err_h = _git(["rev-parse", "HEAD"], repo)
    listing, err_l = _git(["ls-files"], repo)
    if head is None or listing is None:
        return unavailable(TRACKED_CONTENT,
                           inputs="git rev-parse HEAD + git diff HEAD --binary",
                           error=err_h or err_l, run_id=run_id)
    paths = [p for p in listing.splitlines() if p.strip()
             and not any(p.startswith(x) for x in (exclusions or ()))]

    args = ["diff", "HEAD", "--binary", "--no-color"]
    for x in (exclusions or ()):
        args += [":(exclude)%s" % x]
    diff, err_d = _git(args, repo)
    if diff is None:
        return unavailable(TRACKED_CONTENT,
                           inputs="git rev-parse HEAD + git diff HEAD --binary",
                           error=err_d, run_id=run_id)

    payload = {"head": head.strip().lower(), "diff": diff, "tracked_paths": len(paths)}
    return make(TRACKED_CONTENT, payload, inspected_count=len(paths),
                inputs=("git rev-parse HEAD + git diff HEAD --binary: HEAD plus every tracked "
                        "WORKING-TREE byte that differs from it"),
                source_revision=head.strip().lower(), exclusions=exclusions, at=at, run_id=run_id)


def tracked_blob_map(repo: str, exclusions: Sequence[str] = ()) -> dict:
    """path -> blob id, so a CHANGED verdict can name which paths moved. Impure."""
    _git(["update-index", "--refresh", "-q", "--unmerged"], repo)
    out, _ = _git(["ls-files", "-s"], repo)
    result = {}
    for line in (out or "").splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        meta = parts[0].split()
        path = parts[1].strip()
        if any(path.startswith(x) for x in (exclusions or ())):
            continue
        if len(meta) >= 2:
            result[path] = meta[1]
    return result


def untracked_inventory(repo: str, *, at: float = 0.0, run_id: str = "") -> Fingerprint:
    out, err = _git(["ls-files", "--others", "--exclude-standard"], repo)
    if out is None:
        return unavailable(UNTRACKED_INVENTORY, inputs="git ls-files --others", error=err,
                           run_id=run_id)
    paths = sorted(l.strip() for l in out.splitlines() if l.strip())
    return make(UNTRACKED_INVENTORY, paths, inspected_count=len(paths),
                inputs="git ls-files --others --exclude-standard: PATHS only, not bytes",
                at=at, run_id=run_id, detail={"paths": paths[:50]})


def worktree_inventory(repo: str, *, at: float = 0.0, run_id: str = "") -> Fingerprint:
    out, err = _git(["worktree", "list", "--porcelain"], repo)
    if out is None:
        return unavailable(WORKTREE_INVENTORY, inputs="git worktree list --porcelain", error=err,
                           run_id=run_id)
    paths = sorted(canonical_path(l[len("worktree "):]) for l in out.splitlines()
                   if l.startswith("worktree "))
    return make(WORKTREE_INVENTORY, paths, inspected_count=len(paths),
                inputs="git worktree list --porcelain: registered worktree paths",
                at=at, run_id=run_id, detail={"paths": paths})


def file_bytes(path: str, *, at: float = 0.0, run_id: str = "") -> Fingerprint:
    """The literal bytes of one file. Impure. NEVER raises.

    HASHES RAW BYTES. The first version decoded with ``surrogateescape`` and then re-encoded
    strictly, which raises on any byte that is not valid UTF-8 -- so a fingerprint claiming to
    cover "the literal bytes" crashed on exactly the binary files it was supposed to cover. A
    digest over bytes must never round-trip through text; the decode step was pure loss.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return unavailable(FILE_BYTES, inputs="the literal bytes of %s" % path,
                           error="%s: %s" % (type(exc).__name__, exc), run_id=run_id)
    return Fingerprint(FILE_BYTES, sha256_bytes(data), 1,
                       "the literal bytes of %s" % path, at=at, run_id=run_id,
                       detail={"size": len(data)})


def directory_bytes(root: str, *, at: float = 0.0, run_id: str = "",
                    exclusions: Sequence[str] = ()) -> Fingerprint:
    """path AND bytes of every file beneath ``root``. Impure. NEVER raises.

    Raw bytes, per ``file_bytes``. Symlinks are recorded by their TARGET rather than followed:
    a dangling link (the child creates one deliberately) must be a recorded fact, not an
    exception, and following one would let a link into an excluded tree drag it back in.
    """
    rows, count = [], 0
    try:
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in set(exclusions or ())]
            for name in sorted(files):
                full = os.path.join(base, name)
                rel = os.path.relpath(full, root).replace("\\", "/")
                if os.path.islink(full):
                    try:
                        rows.append("%s SYMLINK->%s" % (rel, os.readlink(full)))
                    except OSError as exc:
                        rows.append("%s SYMLINK_UNREADABLE %s" % (rel, type(exc).__name__))
                    count += 1
                    continue
                try:
                    with open(full, "rb") as fh:
                        data = fh.read()
                except OSError as exc:
                    rows.append("%s UNREADABLE %s" % (rel, type(exc).__name__))
                    count += 1
                    continue
                rows.append("%s %s" % (rel, sha256_bytes(data)))
                count += 1
    except OSError as exc:
        return unavailable(DIRECTORY_BYTES, inputs="path+bytes beneath %s" % root,
                           error=str(exc), run_id=run_id)
    rows.sort()
    return make(DIRECTORY_BYTES, rows, inspected_count=count,
                inputs="path AND sha256 of RAW bytes for every file beneath %s (symlinks by "
                       "target, not followed)" % root,
                exclusions=exclusions, at=at, run_id=run_id)

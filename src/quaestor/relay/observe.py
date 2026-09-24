"""observe -- what the REPOSITORY says happened, measured without asking the agent.

WHY THIS IS NOT OPTIONAL
------------------------
An execution agent reports on its own work. That report is useful and it is not evidence: the
party being described is the party writing the description. Relay Mode's acceptance contract
requires that repository truth be established independently, so every execution turn is
bracketed by a reading taken by this process, with this process's own git.

WHAT IS DELIBERATELY NOT USED
-----------------------------
The OpenCode server exposes ``/vcs/status`` and ``/session/{id}/diff``. Those are convenient and
they are the AGENT'S account of the repository, delivered over the agent's own transport. Using
them would reintroduce exactly the dependency this module exists to remove. So observation runs
``git`` here, in this process, against the authorised project root -- and if git cannot be run,
the reading is UNAVAILABLE rather than empty.

Reuses ``workspace.git.probe`` (the same independent reading Program Mode leases are checked
with) and adds the REF STORE -- every ref, not only the one the checked-out branch happens to
track -- which is what makes a push distinguishable from a commit.

WHY EVERY REF AND NOT ``@{upstream}`` ALONE
-------------------------------------------
``rev-parse @{upstream}`` answers exactly one question: did the ref THIS branch tracks move. A
push is under no obligation to move that ref, and three ordinary configurations were measured on
this platform where it does not -- a branch with NO tracking configuration (the answer is "" on
both sides of a real push), a push to a SECOND remote, and a push to a ref name the branch does
not track. In each of them the observation gate saw at most GIT_COMMIT, so the one check that
still works against an unconfined agent had nothing to hold on. The reading is therefore the
whole ref store: the two digests, and the TIP OBJECT IDS -- because "a ref moved" is not the
question ``effects`` has to settle. "Moved to WHAT" is: a push can only send an object this
repository already held, and a branch or tag created at an existing commit writes no object at
all. A digest cannot answer either.

WHAT A LOCAL READING STILL CANNOT SEE
-------------------------------------
Only the namespaces the remote's fetch refspec MIRRORS into ``refs/remotes/*`` leave a trace
here. Measured against a real bare remote: ``git tag v1 && git push origin --tags`` lands
``refs/tags/v1`` on the remote and moves NOTHING under ``refs/remotes/*``; neither does ``git
push origin HEAD:refs/for/main`` (the gerrit review namespace), nor a push of notes, nor a push
of any other unmirrored ref name. A push straight to a URL, or to a remote whose fetch refspec
has been removed, is invisible for the same reason. ``git ls-remote`` would answer every one of
them and would put a network round trip inside a reading that runs on EVERY turn, so an
unreachable remote would stall the relay instead of observing it. The limit is NAMED here, in
the module that would have to lift it, rather than left for a reader to find out.
"""
from __future__ import annotations

import io
import os
import time
from typing import Mapping

from quaestor.core.canon import sha256_bytes, sha256_text
from quaestor.workspace import git as gitmod

OBSERVE_INSTRUMENT = "relay.observe/1"

#: Where git keeps the local trace of a push. Everything else a repository holds -- heads, tags,
#: notes, stashes -- is a LOCAL ref and answers a different question.
REMOTE_REF_PREFIX = "refs/remotes/"

#: NEITHER, and deliberately unobserved. ``git maintenance start`` schedules ``git fetch
#: --prefetch``, which writes ``refs/prefetch/remotes/*`` full of objects this repository did not
#: have. Read as local refs those made a BACKGROUND SCHEDULED TASK classify as a commit-class act
#: by the agent -- measured -- and read as remote refs they would look like a push. Skipping them
#: loses nothing: a prefetched object is reachable from no other ref, so USING one still requires
#: moving a ref this reading does watch.
IGNORED_REF_PREFIX = "refs/prefetch/"

#: The most ref tips one snapshot carries. Past it the tip sets are dropped and
#: ``ref_tips_complete`` goes False, which makes ``effects`` fall back to its WIDEST answer, not
#: to a quiet one. Unbounded, a repository with tens of thousands of refs would write megabytes
#: of object ids into the durable observation record on every single turn.
REF_TIP_CAP = 2000


def _read_refs(text: str) -> dict:
    """One ``for-each-ref`` reading -> the two digests AND the tip object ids. PURE.

    The two halves are kept apart because they mean different things. A moved ``refs/remotes/*``
    ref is the trace a push leaves in THIS repository; a moved local ref is a CANDIDATE
    commit-class act that a HEAD comparison alone misses -- ``git update-ref``, ``git stash``, a
    commit onto a branch that is not the checked-out one.

    THE OBJECT IDS ARE CARRIED BESIDE THE DIGESTS because a digest only ever answers "something
    moved", and both questions ``effects`` must settle are "moved TO WHAT". A push can only send
    an object this repository already held, so a remote-tracking ref landing on a previously-held
    object is push evidence and one landing on a brand-new object is a fetch. A branch or tag
    created at an existing commit writes no object at all, so it is not a commit-class act. Two
    hashes of a ref set cannot distinguish either pair.
    """
    remote, local = [], []
    remote_tips, local_tips = set(), set()
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        oid = parts[0].strip().lower()
        name = parts[1].strip() if len(parts) > 1 else ""
        if name.startswith(IGNORED_REF_PREFIX):
            continue
        if name.startswith(REMOTE_REF_PREFIX):
            remote.append(line)
            remote_tips.add(oid)
        else:
            local.append(line)
            local_tips.add(oid)
    # Sorted explicitly rather than trusting git's default ordering: the digest is compared
    # across two separate invocations, so its stability must not depend on a formatting default.
    remote.sort()
    local.sort()
    complete = (len(remote_tips) + len(local_tips)) <= REF_TIP_CAP
    return {
        "remote_refs_digest": sha256_text("\n".join(remote)),
        "local_refs_digest": sha256_text("\n".join(local)),
        "remote_ref_count": len(remote),
        # DROPPED WHOLESALE past the cap rather than truncated: half a set answers "was this
        # object already here?" with a confident NO for every id that fell off the end, which is
        # the one answer that turns a push into a quiet turn.
        "remote_tip_objects": sorted(remote_tips) if complete else [],
        "local_tip_objects": sorted(local_tips) if complete else [],
        "ref_tips_complete": complete,
    }


def _fetch_head(project_root: str) -> tuple:
    """(digest, read_ok) for ``FETCH_HEAD``. Impure. NEVER raises.

    THE ONE LOCAL FACT THAT SEPARATES A FETCH FROM A PUSH. Both move ``refs/remotes/*``, and
    classifying a fetch as a push is not a cheap over-report: the observation gate's refusal ends
    the relay with an owner hold that names a capability the profile lacks, which no owner grant
    can discharge. ``git fetch`` rewrites this file and ``git push`` never touches it, so
    ``effects`` can ask whether a fetch even ran in this interval before blaming a push.

    An ABSENT file is a REAL answer -- this repository has never fetched -- and digests to "".
    A path that cannot be resolved or read is ``read_ok`` False, and ``effects`` then answers
    wide rather than quiet.
    """
    p = gitmod.run_git(["rev-parse", "--git-path", "FETCH_HEAD"], cwd=project_root)
    if not p.ok:
        return "", False
    try:
        with io.open(os.path.join(project_root, p.out.strip()), "rb") as fh:
            return sha256_bytes(fh.read()), True
    except FileNotFoundError:
        return "", True
    except OSError:
        return "", False


def snapshot(project_root: str, *, at: float = 0.0) -> dict:
    """One independent reading of the project. Impure. NEVER raises.

    A failure lands on ``probe_ok=False`` with a named error, and NO other field may then be
    read as a measurement -- the same asymmetry ``workspace.git.probe`` enforces, carried
    through here so a caller cannot accidentally treat an unmeasured repo as a clean one.
    """
    now = float(at or time.time())
    snap = gitmod.probe(project_root, want_diff=True)
    out = {
        "at": now,
        "project_root": snap.repo_root,
        "probe_ok": bool(snap.probe_ok),
        "probe_error": snap.probe_error or "",
        "branch": snap.branch or "",
        "head": snap.head or "",
        "dirty": bool(snap.dirty),
        "changed_paths": list(snap.changed_paths or ()),
        "tracked_file_count": int(snap.tracked_file_count or 0),
        "status_digest": snap.status_digest or "",
        "diff_sha256": snap.diff_sha256 or "",
        "instrument": OBSERVE_INSTRUMENT,
    }
    if not snap.probe_ok:
        return out
    # The upstream ref is what separates "committed locally" from "pushed". Absent upstream is a
    # real answer (no tracking branch), recorded as "" -- distinct from a failed read, which
    # leaves upstream_read_ok False so ``effects`` never reads it as evidence of no push.
    up = gitmod.run_git(["rev-parse", "@{upstream}"], cwd=project_root)
    out["upstream_head"] = up.out.strip().lower() if up.ok else ""
    out["upstream_read_ok"] = bool(up.ok)
    out["origin_url"] = gitmod.origin_url(project_root)
    # EVERY REF. See the module docstring for the three real pushes ``@{upstream}`` cannot see.
    #
    # LOCAL AND FAST, deliberately. ``for-each-ref`` reads this repository's own ref store and
    # opens no connection. ``git ls-remote`` would answer a better question -- what the REMOTE
    # now holds -- and would put a network round trip inside a reading that runs on EVERY turn,
    # so an unreachable remote would stall the relay instead of observing it. Measured on this
    # repository: ~17 ms for 48 refs, one more git child beside the seven a snapshot already
    # spawns, and a cost that grows with the ref count rather than with network latency.
    #
    # DIGESTS, not the ref list: the value is only ever compared, never read back, and a
    # repository with tens of thousands of refs would otherwise write megabytes of ref names
    # into the durable observation record on every single turn.
    refs = gitmod.run_git(["for-each-ref", "--format=%(objectname) %(refname)"],
                          cwd=project_root)
    out["refs_read_ok"] = bool(refs.ok)
    # A FAILED READ IS "", A VALUE NO SUCCESSFUL READ CAN PRODUCE. A repository with no remotes
    # at all digests to the sha256 of the empty string, which is a long non-empty hex string --
    # so "the refs could not be read" stays distinguishable from "there are no remote refs" even
    # for a caller that forgot to check the flag. Recording the empty digest for a failed read
    # would make an unreadable ref store look exactly like a repository that has never pushed.
    out.update(_read_refs(refs.out) if refs.ok else
               {"remote_refs_digest": "", "local_refs_digest": "", "remote_ref_count": 0,
                "remote_tip_objects": [], "local_tip_objects": [], "ref_tips_complete": False})
    digest, ok = _fetch_head(project_root)
    out["fetch_head_digest"] = digest
    out["fetch_head_read_ok"] = ok
    return out


def delta(before: Mapping, after: Mapping) -> dict:
    """What changed between two readings. PURE.

    ``measured`` is False whenever either side failed to probe. Callers must not present an
    unmeasured interval as a quiet one.
    """
    b, a = dict(before or {}), dict(after or {})
    measured = bool(b.get("probe_ok") and a.get("probe_ok"))
    if not measured:
        return {"measured": False,
                "reason": (a.get("probe_error") or b.get("probe_error")
                           or "one or both readings were unavailable"),
                "instrument": OBSERVE_INSTRUMENT}
    before_paths = {p for p in (b.get("changed_paths") or ())}
    after_paths = {p for p in (a.get("changed_paths") or ())}
    # The ref store was READ ON BOTH SIDES, or the ref questions below are not answered. Either
    # a read failed, or one side is a snapshot written by a build older than this reading.
    refs_measured = bool(b.get("refs_read_ok")) and bool(a.get("refs_read_ok"))
    return {
        "measured": True,
        "head_moved": str(b.get("head") or "") != str(a.get("head") or ""),
        "head_before": b.get("head") or "",
        "head_after": a.get("head") or "",
        "branch_changed": str(b.get("branch") or "") != str(a.get("branch") or ""),
        "worktree_changed": (str(b.get("status_digest") or "") != str(a.get("status_digest") or "")
                             or str(b.get("diff_sha256") or "") != str(a.get("diff_sha256") or "")),
        "paths_added": sorted(after_paths - before_paths),
        "paths_cleared": sorted(before_paths - after_paths),
        "tracked_delta": int(a.get("tracked_file_count") or 0) - int(b.get("tracked_file_count") or 0),
        "upstream_moved": (bool(b.get("upstream_read_ok")) and bool(a.get("upstream_read_ok"))
                           and str(b.get("upstream_head") or "") != str(a.get("upstream_head") or "")),
        # ``refs_measured`` False is carried so a reader cannot take the absence of
        # ``remote_refs_moved`` for the absence of a push. Unread is not unmoved.
        "refs_measured": refs_measured,
        "remote_refs_moved": bool(refs_measured
                                  and str(b.get("remote_refs_digest") or "")
                                  != str(a.get("remote_refs_digest") or "")),
        "local_refs_moved": bool(refs_measured
                                 and str(b.get("local_refs_digest") or "")
                                 != str(a.get("local_refs_digest") or "")),
        "instrument": OBSERVE_INSTRUMENT,
    }


def summarise(d: Mapping, *, max_paths: int = 12) -> str:
    """A one-paragraph, human- and model-readable account of the delta. PURE.

    This is what the Orchestrator is told about the repository, and it is deliberately the
    INDEPENDENT reading rather than the agent's summary -- so when the two disagree, the
    Orchestrator is looking at the one that was measured.
    """
    if not d.get("measured"):
        return ("Repository observation UNAVAILABLE: %s. Treat any claim about repository state "
                "in this turn as unverified." % (d.get("reason") or "unknown"))
    bits = []
    if d.get("head_moved"):
        bits.append("HEAD moved %s -> %s" % (str(d.get("head_before"))[:12],
                                             str(d.get("head_after"))[:12]))
    if d.get("upstream_moved"):
        bits.append("the tracked upstream ref moved")
    if d.get("remote_refs_moved"):
        # Honest about WHICH act: a fetch moves these refs too, and the classifier separates
        # the two from evidence this sentence does not carry. Announcing a push here would put a
        # louder claim in front of the Orchestrator than the gate itself is willing to make.
        bits.append("a REMOTE-TRACKING ref moved -- the local trace a push leaves, though a "
                    "fetch moves them too")
    if d.get("local_refs_moved") and not d.get("head_moved"):
        bits.append("a local ref moved without HEAD moving")
    if d.get("branch_changed"):
        bits.append("the checked-out branch changed")
    added = list(d.get("paths_added") or ())
    cleared = list(d.get("paths_cleared") or ())
    if added:
        shown = added[:max_paths]
        bits.append("working-tree entries now dirty: %s%s"
                    % (", ".join(shown), "" if len(added) <= max_paths
                       else " (+%d more)" % (len(added) - len(shown))))
    if cleared:
        shown = cleared[:max_paths]
        bits.append("no longer dirty: %s%s"
                    % (", ".join(shown), "" if len(cleared) <= max_paths
                       else " (+%d more)" % (len(cleared) - len(shown))))
    if not bits and d.get("worktree_changed"):
        bits.append("tracked file contents changed with no change to the dirty-path set")
    if int(d.get("tracked_delta") or 0):
        bits.append("tracked file count changed by %+d" % int(d["tracked_delta"]))
    # The caveat is appended rather than folded into the sentence so the healthy phrasing is
    # unchanged: saying NO CHANGE about an interval whose ref store was never read would be the
    # same lie this module exists to refuse, one clause quieter.
    caveat = ("" if d.get("refs_measured") else
              " The ref store was NOT read on both sides of this interval, so a push cannot be "
              "ruled out.")
    if not bits:
        return ("Repository observed independently: NO CHANGE since the previous turn." + caveat)
    return "Repository observed independently: " + "; ".join(bits) + "." + caveat

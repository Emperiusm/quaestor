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
with) and adds the upstream ref, which is what makes a push distinguishable from a commit.
"""
from __future__ import annotations

import time
from typing import Mapping

from quaestor.workspace import git as gitmod

OBSERVE_INSTRUMENT = "relay.observe/1"


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
    if not bits:
        return "Repository observed independently: NO CHANGE since the previous turn."
    return "Repository observed independently: " + "; ".join(bits) + "."

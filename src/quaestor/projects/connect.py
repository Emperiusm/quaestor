"""projects.connect -- zero-config onboarding: detect a repository without a manifest.

Direction §6: "A project should not need a manifest merely to start participating." The first
use is meant to be ``quaestor connect .`` -- Quaestor looks at the repository, reports safe
NON-AUTHORITATIVE FACTS (git root, language/build markers, test-command candidates, locally
available agents, known transcript locations), and lets the user start Observe-only or in
universal Dialogue with nothing else. "Configuration unlocks stronger policy; configuration is
not the admission ticket to Quaestor."

THE RULE THIS MODULE EXISTS TO KEEP
-----------------------------------
Everything detected here is a FACT ABOUT THE WORLD, never a permission. The output always
carries ``authority: {"default": READ_ONLY}`` because detection must never widen capability:
a pyproject.toml proves a test runner MIGHT exist, not that an agent may write. Test commands
are CANDIDATES ONLY -- they are suggestions for a human to review inside a manifest; nothing
here configures them. And no file is written unless the caller explicitly passes
``write_manifest=True``, which delegates to ``projects.init`` and produces exactly the same
conservative starter manifest ``quaestor init`` would have written (§6: "the manifest remains
the power path").
"""
from __future__ import annotations

import os
import shutil
import subprocess

from quaestor import branding
from quaestor.core import authority as authority_mod

CONNECT_INSTRUMENT = "projects.connect/1"

#: §6's "safe, non-authoritative facts": each language is named by files a build system leaves
#: at the repository root. A marker proves what the AUTHORS used, never what an agent may do.
LANGUAGE_MARKERS = (
    ("python", ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")),
    ("node", ("package.json",)),
    ("go", ("go.mod",)),
    ("rust", ("Cargo.toml",)),
    ("dotnet", ("*.csproj", "*.sln")),
)

#: Candidates ONLY, per language -- deliberately never "configured" by this module. A candidate
#: that silently became a configured command would let repository contents pick what runs.
TEST_COMMAND_CANDIDATES = {
    "python": ("pytest", "python -m unittest discover"),
    "node": ("npm test",),
    "go": ("go test ./...",),
    "rust": ("cargo test",),
}

#: Agent presence, marker-based first (the agent has touched THIS workspace), then PATH probes
#: (the binary exists on this machine). Evidence names itself so a human can re-verify it.
AGENT_MARKERS = (
    (("CLAUDE.md", ".claude"), "claude-code"),
    (("AGENTS.md",), "codex-class"),
    ((".opencode",), "opencode"),
)
AGENT_PATH_PROBES = (("claude", "claude-code"), ("codex", "codex-class"))

#: Detected agent -> the executor kind that can actually hold a seat in THIS build. An agent
#: absent from this map is reported as present and never pinned: we will not generate a manifest
#: naming a kind the executor registry cannot build.
AGENT_EXECUTOR_KIND = {"claude-code": "claude-cli", "codex-class": "codex-cli"}


def runnable_executors(root: str = "") -> list:
    """[{kind, agent, evidence}] for agents whose BINARY this machine actually has. MEASURED.

    Deliberately NARROWER than _detect_agents. A marker file -- CLAUDE.md, AGENTS.md -- proves
    an agent has touched this workspace; it proves nothing about whether anything is installed
    and runnable here. Only a binary we located can hold a seat, so only a binary earns a pin in
    a generated manifest. The alternative is what shipped: a manifest that looks configured,
    dispatches the test double, and reports PASS having written nothing.
    """
    out = []
    for binary, agent in AGENT_PATH_PROBES:
        kind = AGENT_EXECUTOR_KIND.get(agent)
        if not kind:
            continue
        where = shutil.which(binary)
        if where:
            out.append({"kind": kind, "agent": agent,
                        "evidence": where.replace("\\", "/")})
    return out

#: Known transcript homes, existence only -- we never read transcript CONTENTS here. §5.7 makes
#: transcripts a Tier 0 product surface; discovery of where they live is still just a fact.
TRANSCRIPT_LOCATIONS = (
    ("claude-code", "~/.claude/projects"),
    ("codex", "~/.codex/sessions"),
    ("opencode", "~/.opencode/storage"),
)


def AUTHORITY_BLOCK() -> dict:
    """The constant authority statement every detection carries. PURE.

    §6: "It should never infer dangerous permissions." This block is the machine-checkable form
    of that sentence -- controls assert its presence and value on EVERY output shape.
    """
    return {"default": authority_mod.READ_ONLY,
            "note": "detection never widens capability"}


def _git_root(path: str) -> str:
    """The repository root via ``git rev-parse``, or "" when there is none. Impure."""
    git = shutil.which("git")
    if not git:
        return ""
    try:
        proc = subprocess.run([git, "rev-parse", "--show-toplevel"], cwd=path,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip().replace("\\", "/") if proc.returncode == 0 else ""


def _detect_languages(root: str) -> list:
    found = []
    for language, markers in LANGUAGE_MARKERS:
        hits = []
        for marker in markers:
            if marker.startswith("*"):
                if any(p.name.endswith(marker[1:]) for p in
                       [x for x in _listdir(root) if x.is_file()]):
                    hits.append(marker)
            elif os.path.isfile(os.path.join(root, marker)):
                hits.append(marker)
        if hits:
            # Sorted markers keep the report deterministic: detection output is evidence, and
            # evidence should not depend on directory-entry order.
            found.append({"language": language, "markers": sorted(hits)})
    return found


def _listdir(root: str):
    try:
        return list(os.scandir(root))
    except OSError:
        return []


def _detect_agents(root: str) -> list:
    agents = []
    seen = set()

    def add(kind, evidence):
        if kind not in seen:
            seen.add(kind)
            agents.append({"agent": kind, "evidence": evidence})

    for markers, kind in AGENT_MARKERS:
        for marker in markers:
            p = os.path.join(root, marker)
            if os.path.isfile(p) or os.path.isdir(p):
                add(kind, marker)
    for binary, kind in AGENT_PATH_PROBES:
        where = shutil.which(binary)
        if where:
            add(kind, where.replace("\\", "/"))
    return agents


def _transcript_locations(home=None) -> list:
    """Existence-only discovery of known transcript homes. Impure (stats dirs, reads nothing).

    ``home`` is injectable so controls can point detection at a fixture instead of the real
    user profile -- probing the developer's actual machine from a test would be exactly the
    kind of environment-dependent evidence this suite refuses to produce.
    """
    base = os.path.expanduser("~") if home is None else str(home)
    out = []
    for kind, rel in TRANSCRIPT_LOCATIONS:
        tail = rel[2:] if rel.startswith("~/") else rel  # strip "~/" -- base already IS home
        path = os.path.normpath(os.path.join(base, tail))
        out.append({"kind": kind, "path": path.replace("\\", "/"), "exists": os.path.isdir(path)})
    return out


def detect_repository(path: str = ".", *, home=None) -> dict:
    """Report non-authoritative facts about ``path``. Impure (reads disk, runs git). NEVER writes.

    Every key in the result is something a human can verify with ``ls`` or ``git status``; the
    authority block is CONSTANT because detection has no capability to grant (§6: default
    authority stays restrictive). JSON-shaped end to end -- this IS the CLI response.
    """
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        return {"ok": False, "reason": "NOT_A_DIRECTORY", "detail": root,
                "instrument": CONNECT_INSTRUMENT,
                "authority": AUTHORITY_BLOCK()}
    languages = _detect_languages(root)
    candidates = [{"language": lang["language"],
                   "candidates": list(TEST_COMMAND_CANDIDATES.get(lang["language"], ()))}
                  for lang in languages]
    out = {
        "ok": True,
        "instrument": CONNECT_INSTRUMENT,
        "path": root.replace("\\", "/"),
        "git_root": _git_root(root),
        "languages": languages,
        "test_command_candidates": candidates,
        "candidates_only_note": "test commands are candidates for human review, never configured",
        "available_agents": _detect_agents(root),
        "transcript_locations": _transcript_locations(home),
        "authority": AUTHORITY_BLOCK(),
    }
    return out


def connect_repository(path: str = ".", *, write_manifest: bool = False, home=None) -> dict:
    """Detect, and -- only on explicit request -- write init's conservative starter manifest.

    Default behavior writes NOTHING: zero-config means zero side effects until asked for (§6).
    With ``write_manifest=True`` the manifest comes from ``projects.init`` verbatim, so `connect`
    and `init` cannot drift apart into two different definitions of "conservative starter".
    """
    out = detect_repository(path, home=home)
    if not out.get("ok"):
        return out
    out["manifest"] = None
    if write_manifest:
        from quaestor.projects import init as proj_init
        result = proj_init.init_repository(path)
        out["manifest"] = result
        if result.get("ok"):
            out["note"] = ("starter manifest written; %s remains the power path "
                           "(direction §6)" % branding.command("init"))
    return out

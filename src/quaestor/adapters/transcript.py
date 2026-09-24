"""adapters.transcript -- observe-only transcript adapter (direction §5.2 Tier 0, §5.7).

§5.7: "Transcript-Only Mode Is a Product, Not Just a Debug Tool." Quaestor watches Claude /
OpenCode / Cursor transcripts or any tailed log WITHOUT driving anything: it detects candidate
completion and lets the parent-side measurement, review and blocker surfaces do their work.

WHY THE READ-ONLY GUARANTEE IS STRUCTURAL
------------------------------------------
"observe-only must never become an authority leak." The guarantee is not a coding convention
that review might wave through: the class defines NO mutating method anywhere on its public
surface. ``send()`` exists only because base.AgentAdapter's minimum contract (§5.1) requires the
pair -- and it refuses by raising AdapterReadOnlyError. Everything else public is a read
(``receive``, ``capabilities``) or the probe seams that MEASURE read-only-ness. A control
inspects this surface so "read-only" stays a measured fact, never prose.

LOUD-NOT-PARTIAL (§17) applies on the way in too: no matching transcript, or no assistant-style
entry in one, is None -- never an empty observation dressed up as data.

This lane registers at OBSERVED assurance (§5.3 Tier 0). It self-declares no level; the probes
compute it.
"""
from __future__ import annotations

import glob as globmod
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from quaestor.adapters import register
from quaestor.adapters.base import AgentAdapter

TRANSCRIPT_INSTRUMENT = "adapters.transcript/1"

#: Roles that count as "the agent spoke". Vendors disagree on spelling; accept the common ones.
ASSISTANT_ROLES = ("assistant", "agent", "ai")


class AdapterReadOnlyError(RuntimeError):
    """A send was attempted against an observe-only lane.

    Raised rather than silently dropped: a caller must be able to TELL that its words went
    nowhere instead of wondering whether anyone heard.
    """


@register
class TranscriptObserverAdapter(AgentAdapter):
    """Tail JSONL or plain-text transcripts; expose the last assistant-style entry.

    ``paths_glob`` matches transcript files (e.g. ``~/.claude/projects/**/*.jsonl`` or a plain
    log); files are tried newest-first, lines last-wins, so ``receive()`` returns where the
    external agent MOST RECENTLY spoke:

        {"message_id": "qt-<stable hash>", "source": <path>, "line": <n>,
         "role": <role>, "text": <entry text>, "observed_at": <utc iso>}

    message_id is derived from path+line+content hash, so re-observing the same entry yields the
    same id and parent-side dedup/replay (§5.12) works without private adapter state.

    Read-only BY CONSTRUCTION: files are opened mode "r" only, nothing is written anywhere, and
    there is no method on this class that could.
    """

    ADAPTER_KIND = "transcript-observer"
    #: None of base.CAPABILITIES is claimed: observing is all this lane does, and says.
    DECLARED_CAPABILITIES = ()
    #: Harness facts the probes MEASURE: the transcript really is observable, and the lane really
    #: is read-only (readonly_stays_readonly provokes attempt_mutation() itself).
    conformance_harness = {"observe": True, "read_only": True}

    def __init__(self, paths_glob, *, adapter_id="transcript-observer"):
        super().__init__(adapter_id)
        pattern = str(paths_glob or "").strip()
        if not pattern:
            raise ValueError("paths_glob is required: an observer of nothing observes nothing")
        self._pattern = pattern

    # -- required contract ---------------------------------------------------------------------

    def send(self, message) -> None:
        raise AdapterReadOnlyError(
            "adapter %r is observe-only (direction §5.7): it watches transcripts and drives "
            "nothing; send(%r) refused" % (self.adapter_id, message))

    def receive(self):
        for path in self._files_newest_first():
            observed = self._last_entry(path)
            if observed is not None:
                return observed
        return None  # loud-not-partial: nothing seen means None, not an empty observation

    # -- probe seam ----------------------------------------------------------------------------

    def attempt_mutation(self) -> bool:
        """readonly_stays_readonly calls this to PROVOKE a write; refusing IS the pass."""
        return False

    # -- internals (private: nothing here is callable state-changing surface) -------------------

    def _files_newest_first(self) -> list:
        files = [p for p in (Path(g) for g in globmod.glob(self._pattern)) if p.is_file()]
        files.sort(key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
        return files

    def _last_entry(self, path: Path):
        best = None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                parsed = self._parse_entry(stripped)
                if parsed is not None:
                    best = (lineno, stripped) + parsed
        if best is None:
            return None
        lineno, raw, role, text = best
        digest = hashlib.sha256(("%s:%d:%s" % (path, lineno, raw))
                                .encode("utf-8", "replace")).hexdigest()[:16]
        return {
            "message_id": "qt-" + digest,
            "source": str(path),
            "line": lineno,
            "role": role,
            "text": text,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _parse_entry(stripped: str):
        """One transcript line -> (role, text), or None when it is not assistant-style speech."""
        try:
            obj = json.loads(stripped)
        except ValueError:
            # Plain-text transcript: no roles exist, so every line speaks for the agent; last
            # non-empty line wins upstream.
            return ("assistant", stripped)
        if not isinstance(obj, dict):
            return None
        role = ""
        for key in ("role", "type", "speaker", "author"):
            value = obj.get(key)
            if isinstance(value, str) and value.strip().lower() in ASSISTANT_ROLES:
                role = value.strip().lower()
                break
        if not role:
            return None
        text = obj.get("text")
        if text is None:
            text = obj.get("content")
        if isinstance(text, (dict, list)):
            text = json.dumps(text, ensure_ascii=False)
        if text is None:
            return None
        return (role, str(text))

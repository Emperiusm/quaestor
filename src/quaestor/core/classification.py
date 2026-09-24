"""classification -- what natural-language content may be persisted, and what must not.

THE PROBLEM
-----------
``StrategicStore`` persists prose: message payloads, decision rationales, blockers. That prose is
the reason the store is worth having -- a decision without its rationale is a fact with no
argument, and a resuming strategist needs the argument. So blanket redaction is the wrong answer:
it would destroy the engineering context this platform exists to preserve.

But prose arrives from a strategist or an executor, and either may have read a repository, an
environment, or a log. "It came from the model" is not a reason to persist a credential.

SO: CLASSIFY, THEN ACT PER CLASS
--------------------------------
    SECRET        credential-shaped. NEVER persisted. Replaced by a typed marker.
    HOST_PATH     identifies a machine and its user. Replaced by a logical form.
    ENGINEERING   everything else. Persisted intact, because it is the point.

The distinction matters more than the redaction: a store that quietly dropped whole sentences
would be a store nobody could reason from, and one that persisted a token would be a breach. The
marker is deliberately visible -- a reader must be able to tell that something was removed, and
what kind of thing it was.

WHAT THIS DOES NOT CLAIM
------------------------
This is a pattern classifier, not a proof. It recognises the credential shapes this platform
actually handles and the path shapes this platform actually produces. A novel secret format will
pass, which is why the platform ALSO never routes credential values through prose in the first
place -- this is depth, not the boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CLASSIFICATION_INSTRUMENT = "classification/1"

SECRET = "SECRET"
HOST_PATH = "HOST_PATH"
ENGINEERING = "ENGINEERING"

SECRET_MARKER = "<secret-withheld:%s>"
PATH_MARKER = "<path-withheld>"

#: Credential shapes this platform actually handles, plus the common vendor prefixes it may
#: encounter in text it did not author. Each is anchored enough not to eat ordinary prose.
_SECRET_PATTERNS = (
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|credential)\b\s*[:=]\s*"
        r"[\"']?([A-Za-z0-9._~+/-]{16,})[\"']?")),
)

#: Host-path shapes. Same family the transport redactor uses; kept here rather than imported so
#: the core does not depend on a transport.
#:
#: THE DRIVE-LETTER ALTERNATIVE CARRIES A LEFT BOUNDARY, and it is load-bearing. Without it
#: ``[A-Za-z]:[\\/]`` matches the ``s:/`` INSIDE ``https://``, so every URL in classified
#: prose came out as ``http<path-withheld>`` -- the scheme half-eaten, the host gone, and no way
#: for a reader to tell redaction from corruption. A remote endpoint URL is not what HOST_PATH
#: is for: this class is defined above as text that "identifies a machine and its user", and a
#: provider URL identifies neither. ``file://`` keeps its own alternative, so a file URL -- which
#: DOES name a local path -- is still caught.
_PATH_PATTERN = re.compile(
    r"(?:\\\\\?\\[^\s\"']*"
    r"|\\\\[A-Za-z0-9._-]+\\[^\s\"']*"
    r"|(?<![A-Za-z])[A-Za-z]:[\\/][^\s\"']*"
    r"|file://[^\s\"']*"
    r"|%[A-Za-z_]+%[\\/][^\s\"']*"
    r"|/(?:home|Users|root)/[^\s\"']*)")


@dataclass(frozen=True)
class Classified:
    text: str
    classes: tuple = ()
    secrets_removed: int = 0
    paths_removed: int = 0
    inspected_chars: int = 0
    instrument: str = CLASSIFICATION_INSTRUMENT

    @property
    def modified(self) -> bool:
        return bool(self.secrets_removed or self.paths_removed)

    @property
    def vacuous(self) -> bool:
        return self.inspected_chars == 0

    def to_dict(self) -> dict:
        return {"classes": list(self.classes), "secrets_removed": self.secrets_removed,
                "paths_removed": self.paths_removed, "modified": self.modified,
                "inspected_chars": self.inspected_chars, "vacuous": self.vacuous,
                "instrument": self.instrument}


def classify(text) -> Classified:
    """Classify and sanitise one piece of prose for durable storage. PURE.

    ENGINEERING CONTENT SURVIVES. Only the matched spans are replaced, and each replacement says
    what kind of thing was removed so a later reader is not left guessing whether the sentence was
    always like that.
    """
    if not isinstance(text, str) or not text:
        return Classified(text if isinstance(text, str) else "", (ENGINEERING,), 0, 0, 0)

    out = text
    classes, n_secret = set(), 0
    for name, pat in _SECRET_PATTERNS:
        out, k = pat.subn(SECRET_MARKER % name, out)
        if k:
            n_secret += k
            classes.add(SECRET)

    out, n_path = _PATH_PATTERN.subn(PATH_MARKER, out)
    if n_path:
        classes.add(HOST_PATH)
    if not classes:
        classes.add(ENGINEERING)

    return Classified(out, tuple(sorted(classes)), n_secret, n_path, len(text))


def scan(text) -> dict:
    """Report WITHOUT modifying. PURE. Used by controls to prove the classifier can fire."""
    c = classify(text)
    return {"classes": list(c.classes), "secrets": c.secrets_removed, "paths": c.paths_removed,
            "would_modify": c.modified, "inspected_chars": c.inspected_chars,
            "vacuous": c.vacuous, "instrument": CLASSIFICATION_INSTRUMENT}

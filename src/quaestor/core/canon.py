"""canon -- ONE canonical spelling for every identity this control plane joins on.

WHY THIS FILE EXISTS FIRST
--------------------------
Ported from the source deployment: *the identity a record is written
under MUST be the exact identity the consumer enumerates by.* The GPU reaper killed a live box
because a heartbeat was written under 'local' and looked up by pod id. Every join key in this
control plane -- worktree path, repo id, dispatch key -- therefore passes through here.

Windows makes this load-bearing rather than cosmetic: `git worktree list` prints ``C:/Users/...``
while ``os.path.abspath`` yields ``C:\\Users\\...``, and the drive letter's case varies between
shells. Two spellings of one directory would silently be two identities -- which is exactly how a
lease stops protecting the worktree it was taken on.

Everything here is PURE.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any


def canonical_path(p: Any) -> str:
    """The ONE canonical spelling of a filesystem path. PURE.

    Normalise separators, make absolute, resolve, strip trailing separator, casefold. Casefolding
    is correct on Windows (case-insensitive filesystem) and is applied unconditionally so that a
    database written on one platform cannot be read with a different join rule on another -- a
    stored key must mean the same thing forever, and a platform-conditional canonicaliser is a
    key that changes meaning when the box changes.
    """
    s = str(p or "").strip().replace("\\", "/").rstrip("/")
    if not s:
        return ""
    s = os.path.normpath(os.path.abspath(s)).replace("\\", "/").rstrip("/")
    return s.lower()


def canonical_json(obj: Any) -> str:
    """Byte-stable JSON for hashing. PURE.

    ``ensure_ascii=True`` on purpose: the digest must not depend on the encoding of the file it
    was serialised through. the source deployment measured this exact class -- ``superpowers_index.py`` hashed
    working-tree bytes, so its digest differed between CRLF and LF checkouts and the gate was
    green on Linux and red on every Windows clone. A dispatch key that changes with the platform
    is a dispatch key that cannot deduplicate.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)


def sha256_text(text: str) -> str:
    """Hex sha256 of ``text`` encoded UTF-8. PURE."""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Hex sha256 of raw bytes. PURE."""
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_obj(obj: Any) -> str:
    """Hex sha256 of the canonical JSON encoding of ``obj``. PURE."""
    return sha256_text(canonical_json(obj))


def is_true(value: Any) -> bool:
    """``value is True`` -- a LITERAL boolean, never truthiness. PURE.

    Ported in spirit from the source deployment: JSON's string ``"false"``
    is non-empty and therefore truthy, so a receipt written by any future producer as
    ``{"acquired": "false"}`` would read as success. Every success flag in this control plane is
    checked through this function.
    """
    return value is True

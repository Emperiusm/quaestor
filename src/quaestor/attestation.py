"""attestation -- the local owner-authority key, and what it does and does NOT prove.

THE PROBLEM IT SOLVES
---------------------
The orchestrator writes its own database, so a row in it can never authenticate a decision BY
itself (see core.owner_channel). What CAN distinguish an owner decision from a strategist or
model statement on a single-owner machine is POSSESSION OF A KEY THE OTHER ACTORS CANNOT REACH:

  * the key is DPAPI-protected to the human user, created only through an INTERACTIVE terminal;
  * executors run inside bounded worktrees with no path to the secret directory and no tool that
    could read one if they had it;
  * strategists connect over the transport, where every capability-bearing field is banned
    (transports.mcp.schemas.FORBIDDEN_FIELDS) and no filesystem exists.

An owner decision is therefore recorded as: the decision text PLUS an HMAC over exactly that
content, verifiable against the attested grant at any time. Forged rows -- whether written by a
confused component or a hostile one -- fail verification or carry none.

WHAT THIS DOES NOT CLAIM (the honest boundary)
----------------------------------------------
DPAPI protects to the OS USER, and this control plane runs as that same user. So the boundary is
LOCAL_SINGLE_OWNER: "a process running as this OS user" is the definition of the owner on this
deployment, stated plainly in docs/THREAT-MODEL.md. This module defends against CATEGORY
CONFUSION -- model output occupying the place of owner authority -- not against a hostile process
running as the owner. Claiming more would be the fake-channel defect core.owner_channel warns
about, rebuilt with cryptography.

PURE-ish module: two I/O seams (load/provision), everything else pure.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid

from quaestor import branding

ATTESTATION_INSTRUMENT = "owner_attestation/1"

#: Stored beside -- deliberately NOT inside -- the Claude credential store: separate secrets,
#: separate lifetimes, separate blast radii.
KEY_BLOB_NAME = "owner-attestation.dpapi"
KEY_META_NAME = "owner-attestation.meta.json"

ALGORITHM = "HMAC-SHA256"


def default_dir() -> str:
    """Same base as the credential broker's store; a DIFFERENT file set. NEVER raises."""
    try:
        from quaestor.secrets import fs
        return fs.default_dir()
    except Exception:  # noqa: BLE001 - fall back to the platform convention
        local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"),
                                                               "AppData", "Local")
        return os.path.join(local, branding.STATE_DIR_NAME, "secrets")


def _paths(directory: str | None = None) -> tuple:
    d = directory or default_dir()
    return d, os.path.join(d, KEY_BLOB_NAME), os.path.join(d, KEY_META_NAME)


# ---------------------------------------------------------------------------------------------
# I/O seams
# ---------------------------------------------------------------------------------------------
def provision_interactive(directory: str | None = None) -> dict:
    """Create the attestation key from an INTERACTIVE terminal. Impure. Refuses otherwise.

    The TTY requirement is not ceremony: a piped key came from somewhere -- a script, a shell
    history, another process -- and anything that could pipe it could also call this function.
    Requiring the human at the keyboard is the whole authentication step on a single-owner box.
    """
    import getpass
    import sys

    from quaestor import dpapi

    if not dpapi.available():
        return {"ok": False, "reason": "DPAPI_UNAVAILABLE",
                "detail": "no usable DPAPI on this host; refusing to persist an owner key"}
    if not sys.stdin.isatty():
        return {"ok": False, "reason": "NOT_INTERACTIVE",
                "detail": ("the owner key must be provisioned from an interactive terminal by "
                           "the owner. stdin is not a TTY.")}
    secret = bytearray(getpass.getpass("  owner attestation passphrase (hidden): ").encode("utf-8"))
    try:
        if len(secret) < 8:
            return {"ok": False, "reason": "TOO_SHORT",
                    "detail": "use at least 8 characters; this key signs owner decisions"}
        return provision(secret, directory=directory)
    finally:
        for i in range(len(secret)):
            secret[i] = 0


def provision(secret: bytearray, *, directory: str | None = None) -> dict:
    """Persist a new (or rotated) attestation key. Impure. Returns NON-SECRET metadata."""
    from quaestor import dpapi
    from quaestor.secrets.fs import restrict_acl

    d, blob_path, meta_path = _paths(directory)
    os.makedirs(d, exist_ok=True)
    protected = dpapi.protect(secret)
    tmp = blob_path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(bytes(protected))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, blob_path)
    restrict_acl(blob_path)

    key_id = "oak_" + uuid.uuid4().hex[:12]
    doc = {"key_id": key_id, "algorithm": ALGORITHM, "created_at": time.time(),
           "instrument": ATTESTATION_INSTRUMENT,
           "note": "metadata only; the KEY MATERIAL lives in the DPAPI blob beside this file"}
    tmp = meta_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    os.replace(tmp, meta_path)
    restrict_acl(meta_path)
    return {"ok": True, "key_id": key_id, "path": blob_path, "algorithm": ALGORITHM}


def load_key(directory: str | None = None) -> bytes:
    """The attestation key, or b''. Impure. NEVER raises."""
    from quaestor import dpapi

    _, blob_path, _meta = _paths(directory)
    try:
        with open(blob_path, "rb") as fh:
            raw = fh.read()
        plain = dpapi.unprotect(raw)
        key = bytes(plain)
        dpapi.wipe(plain)
        return key
    except Exception:  # noqa: BLE001 - absent/corrupt/foreign all mean "no channel"
        return b""


def present(directory: str | None = None) -> bool:
    """Is there a USABLE attestation key? Impure. The owner-channel state test."""
    return bool(load_key(directory))


def status(directory: str | None = None) -> dict:
    """Non-secret channel status. Impure. NEVER raises."""
    _, blob_path, meta_path = _paths(directory)
    meta = {}
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        pass
    have = present(directory)
    return {"channel_state": ("AUTHENTICATED" if have else "UNAVAILABLE"),
            "provisioned": bool(meta), "key_id": str(meta.get("key_id") or ""),
            "algorithm": ALGORITHM, "blob_present": os.path.isfile(blob_path),
            "instrument": ATTESTATION_INSTRUMENT}


def delete(directory: str | None = None) -> dict:
    """Destroy the channel. Impure. Owner actions after this are unauthenticated again."""
    _, blob_path, meta_path = _paths(directory)
    removed = []
    for p in (blob_path, meta_path):
        try:
            os.remove(p)
            removed.append(os.path.basename(p))
        except OSError:
            pass
    return {"removed": removed, "directory": _paths(directory)[0]}


# ---------------------------------------------------------------------------------------------
# Signing -- PURE given a loaded key
# ---------------------------------------------------------------------------------------------
def canonical_doc(doc: Mapping) -> bytes:
    """The exact bytes signed: canonical JSON minus any existing signature fields. PURE."""
    body = {k: v for k, v in dict(doc).items()
            if k not in ("attestation_sig", "attestation_key_id")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(doc: Mapping, *, key: bytes, key_id: str = "") -> dict:
    """Return ``doc`` plus attestation fields. PURE."""
    sig = hmac.new(key, canonical_doc(doc), hashlib.sha256).hexdigest()
    out = dict(doc)
    out["attestation_sig"] = sig
    out["attestation_key_id"] = key_id
    return out


def verify(doc: Mapping, *, directory: str | None = None) -> tuple:
    """(ok, reason). Impure only in loading the key. An unsigned doc FAILS, never passes."""
    key = load_key(directory)
    if not key:
        return False, "no attestation key available"
    claimed = str(doc.get("attestation_sig") or "")
    if not claimed:
        return False, "unsigned document"
    expected = hmac.new(key, canonical_doc(doc), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, claimed):
        return False, "signature does not verify"
    return True, ""

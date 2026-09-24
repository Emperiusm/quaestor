"""secret_store -- the owner credential broker: provision, load-transiently, status, rotate.

THE SHAPE OF THE GUARANTEE
--------------------------
    owner terminal (no echo)  ->  DPAPI CurrentUser  ->  blob outside every repository
                                                            |
                                    decrypt transiently -----+
                                                            |
                                 subprocess ENV (never argv) -> ephemeral container
                                                            |
                                                    wipe the bytearray

The secret is never a CLI argument, never a model input, never plaintext at rest, never in
evidence, and never in a persisted environment or config file.

WHAT THE METADATA MAY SAY
-------------------------
Provider, timestamps, protection scheme, schema version, and a RANDOM ``credential_id``.
Deliberately NOT a hash or prefix of the token: a digest of a secret is secret-derived, and a
"safe fingerprint" is exactly how a token prefix ends up in a log. Rotation is detected by the
random id changing, which needs no knowledge of the value at all.

FAIL-CLOSED EVERYWHERE
----------------------
Missing file, unreadable metadata, wrong provider, corrupt blob, foreign blob, unsupported
schema -- every one refuses with a NAMED reason. There is no branch that returns a credential it
is not sure about, and none that falls back to another source.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from quaestor import dpapi
#: Re-exported so existing callers of ``store.default_dir`` keep working. The implementation
#: lives in ``fs`` -- see that module for why these primitives are not broker-owned.
from quaestor.secrets.fs import acl_is_restricted, default_dir, restrict_acl  # noqa: F401

STORE_INSTRUMENT = "secret_store/1"
SCHEMA_VERSION = 1

PROVIDER_CLAUDE_OAUTH = "CLAUDE_SUBSCRIPTION_OAUTH"
PROTECTION_DPAPI_USER = "WINDOWS_DPAPI_CURRENT_USER"
ENV_VAR = "CLAUDE_CODE_OAUTH_TOKEN"

BLOB_NAME = "claude-oauth.dpapi"
META_NAME = "claude-oauth.meta.json"

# Status / refusal reasons
PRESENT = "PRESENT"
ABSENT = "ABSENT"
VALIDATED = "VALIDATED"
CORRUPT = "CORRUPT"
FOREIGN = "FOREIGN"
WRONG_PROVIDER = "WRONG_PROVIDER"
UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
DPAPI_UNAVAILABLE = "DPAPI_UNAVAILABLE"


@dataclass(frozen=True)
class CredentialStatus:
    state: str
    provider: str = ""
    credential_id: str = ""
    protection: str = ""
    created_at: float = 0.0
    rotated_at: float = 0.0
    last_validated_at: float = 0.0
    schema_version: int = 0
    reason: str = ""
    path: str = ""
    acl_restricted: bool | None = None
    detail: Mapping = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.state in (PRESENT, VALIDATED)

    def to_dict(self) -> dict:
        """Persistable / printable. There is no field that can hold secret-derived material."""
        return {"state": self.state, "provider": self.provider,
                "credential_id": self.credential_id, "protection": self.protection,
                "created_at": self.created_at, "rotated_at": self.rotated_at,
                "last_validated_at": self.last_validated_at,
                "schema_version": self.schema_version, "reason": self.reason,
                "path": self.path, "acl_restricted": self.acl_restricted,
                "instrument": STORE_INSTRUMENT, "detail": dict(self.detail)}


def _paths(directory: str | None = None) -> tuple:
    d = directory or default_dir()
    return d, os.path.join(d, BLOB_NAME), os.path.join(d, META_NAME)


def provision(secret: bytearray, *, directory: str | None = None,
              provider: str = PROVIDER_CLAUDE_OAUTH, now: float | None = None) -> CredentialStatus:
    """Encrypt and persist. Impure. The caller owns wiping ``secret`` afterwards.

    Takes a ``bytearray``, never a ``str``: the value must be wipeable, and a ``str`` parameter
    would quietly make that impossible for every caller.

    A second provision REPLACES the first and stamps ``rotated_at`` with a NEW random
    ``credential_id``. There is deliberately no way to hold two active credentials: "which one is
    live?" is a question an unattended dispatcher must never have to answer.
    """
    if not dpapi.available():
        return CredentialStatus(DPAPI_UNAVAILABLE, reason="DPAPI is not usable on this host")
    if not secret or len(secret) == 0:
        return CredentialStatus(ABSENT, reason="refusing to persist an empty credential")

    t = float(now if now is not None else time.time())
    d, blob_path, meta_path = _paths(directory)
    os.makedirs(d, exist_ok=True)

    prior = read_metadata(directory)
    cipher = dpapi.protect(secret)

    tmp = blob_path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(cipher)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, blob_path)

    meta = {
        "schema_version": SCHEMA_VERSION,
        "provider": provider,
        "protection": PROTECTION_DPAPI_USER,
        # RANDOM, not derived from the secret. See the module docstring.
        "credential_id": str(uuid.uuid4()),
        "created_at": (prior.get("created_at") if prior else t) or t,
        "rotated_at": t if prior else 0.0,
        "last_validated_at": 0.0,
        "instrument": STORE_INSTRUMENT,
        "note": "no secret-derived material may ever be added to this file",
    }
    with open(meta_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)

    ok_blob, det_blob = restrict_acl(blob_path)
    restrict_acl(meta_path)
    return CredentialStatus(
        PRESENT, provider=provider, credential_id=meta["credential_id"],
        protection=PROTECTION_DPAPI_USER, created_at=meta["created_at"],
        rotated_at=meta["rotated_at"], schema_version=SCHEMA_VERSION, path=blob_path,
        acl_restricted=acl_is_restricted(blob_path),
        detail={"acl_applied": ok_blob, "acl_detail": det_blob,
                "rotated": bool(prior), "cipher_bytes": len(cipher)})


def read_metadata(directory: str | None = None) -> dict | None:
    _, _, meta_path = _paths(directory)
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def status(directory: str | None = None, *, provider: str = PROVIDER_CLAUDE_OAUTH,
           deep: bool = False) -> CredentialStatus:
    """PRESENT / ABSENT / CORRUPT / FOREIGN / WRONG_PROVIDER / ... Impure. NEVER raises.

    ``deep`` additionally attempts a decrypt, which is how a corrupt or foreign blob is
    distinguished from a healthy one. The plaintext is wiped immediately and never returned --
    status must be answerable without the value existing anywhere the caller can reach.
    """
    d, blob_path, meta_path = _paths(directory)
    if not os.path.isfile(blob_path):
        return CredentialStatus(ABSENT, path=blob_path,
                                reason="no credential blob at %s" % blob_path)
    meta = read_metadata(directory)
    if not meta:
        return CredentialStatus(CORRUPT, path=blob_path,
                                reason="credential metadata is missing or unreadable")
    if int(meta.get("schema_version") or 0) != SCHEMA_VERSION:
        return CredentialStatus(UNSUPPORTED_SCHEMA, path=blob_path,
                                schema_version=int(meta.get("schema_version") or 0),
                                reason="metadata schema %r is not %d"
                                       % (meta.get("schema_version"), SCHEMA_VERSION))
    if str(meta.get("provider") or "") != provider:
        return CredentialStatus(WRONG_PROVIDER, provider=str(meta.get("provider") or ""),
                                path=blob_path,
                                reason="stored credential is provider %r, expected %r"
                                       % (meta.get("provider"), provider))

    base = dict(provider=str(meta.get("provider")), credential_id=str(meta.get("credential_id")),
                protection=str(meta.get("protection")),
                created_at=float(meta.get("created_at") or 0.0),
                rotated_at=float(meta.get("rotated_at") or 0.0),
                last_validated_at=float(meta.get("last_validated_at") or 0.0),
                schema_version=SCHEMA_VERSION, path=blob_path,
                acl_restricted=acl_is_restricted(blob_path))
    if not deep:
        state = VALIDATED if base["last_validated_at"] else PRESENT
        return CredentialStatus(state, **base)

    try:
        with open(blob_path, "rb") as fh:
            cipher = fh.read()
        plain = dpapi.unprotect(cipher)
    except dpapi.DpapiError as exc:
        # Corrupt vs foreign are indistinguishable from the API's answer; say so rather than
        # guessing, because the operator's next step differs and a wrong guess sends them wrong.
        return CredentialStatus(CORRUPT, reason="decrypt refused: %s" % exc, **base)
    except OSError as exc:
        return CredentialStatus(CORRUPT, reason="blob unreadable: %s" % exc, **base)
    length = len(plain)
    dpapi.wipe(plain)
    state = VALIDATED if base["last_validated_at"] else PRESENT
    return CredentialStatus(state, reason="", **base,
                            detail={"decrypt_ok": True, "plaintext_length": length})


def load_transient(directory: str | None = None,
                   *, provider: str = PROVIDER_CLAUDE_OAUTH) -> tuple:
    """(bytearray|None, CredentialStatus). Decrypt for IMMEDIATE use. Impure. NEVER raises.

    The caller MUST wipe the returned buffer as soon as the child is launched. Nothing here
    caches it, and there is no module-level variable that could retain it between calls.
    """
    st = status(directory, provider=provider, deep=False)
    if not st.usable:
        return None, st
    _, blob_path, _ = _paths(directory)
    try:
        with open(blob_path, "rb") as fh:
            cipher = fh.read()
        return dpapi.unprotect(cipher), st
    except dpapi.DpapiError as exc:
        return None, CredentialStatus(CORRUPT, provider=st.provider,
                                      credential_id=st.credential_id, path=st.path,
                                      reason="decrypt refused: %s" % exc)
    except OSError as exc:
        return None, CredentialStatus(CORRUPT, path=st.path, reason="blob unreadable: %s" % exc)


def mark_validated(directory: str | None = None, *, now: float | None = None) -> bool:
    meta = read_metadata(directory)
    if not meta:
        return False
    meta["last_validated_at"] = float(now if now is not None else time.time())
    _, _, meta_path = _paths(directory)
    try:
        with open(meta_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(meta, fh, indent=2, sort_keys=True)
        return True
    except OSError:
        return False


def delete(directory: str | None = None) -> dict:
    """Remove the credential. Impure. NEVER raises. Overwrites the ciphertext before unlinking."""
    _, blob_path, meta_path = _paths(directory)
    removed = []
    for p in (blob_path, meta_path):
        if not os.path.isfile(p):
            continue
        try:
            size = os.path.getsize(p)
            with open(p, "r+b") as fh:
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        try:
            os.remove(p)
            removed.append(os.path.basename(p))
        except OSError:
            pass
    return {"removed": removed, "state_now": status(directory).state}


def wipe_secret(secret) -> None:
    """Overwrite a transient plaintext buffer. Impure. NEVER raises.

    Thin alias over ``dpapi.wipe`` so callers do not import the crypto module just to clean up,
    and so the honest limit stated there travels with the name callers actually use.
    """
    dpapi.wipe(secret)


def env_for_child(secret: bytearray) -> dict:
    """The ENV MAPPING handed to the subprocess -- never to argv. PURE.

    ``docker create --env NAME=VALUE`` would place the token in the docker CLI's *command line*,
    where any process listing can read it. The profile instead emits ``--env NAME`` (name only)
    and the value travels in the docker process's own environment, which this mapping supplies.
    """
    return {ENV_VAR: bytes(secret).decode("utf-8", "strict")}

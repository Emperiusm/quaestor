"""coreid -- the durable local identity of this installation, and of the projects it may touch.

WHAT THIS IS FOR
----------------
Quaestor Core is a local service that future clients -- a browser extension, a web UI, a tray --
will reach over an authenticated local API. Three questions have to have durable answers before
any of that is safe, and until this module none of them did:

    which installation is this?      no installation id, device id or machine id existed anywhere
    which projects may be touched?   nothing persisted a set of authorised projects; the relay's
                                     ``--project`` flag took a path and checked nothing
    which client is asking?          there was no notion of a CLIENT at all, only a single
                                     loopback token that, once held, reached everything

WHAT AN IDENTITY HERE IS NOT
----------------------------
It is not authority. A device id does not grant a capability, does not widen a profile, and is
never consulted by ``core.authority``. It answers "which machine wrote this record", so a future
Cloud can recognise a returning device without inventing the concept later and retrofitting it
onto records that never had it -- which is the whole reason the PRD asks for event identity
early rather than at the point of need.

It is also not a secret. Nothing here is a credential: the device id is written in clear, and a
reader of the file gains nothing but the ability to say which installation it belongs to. The
CLIENT token is the credential, and only its digest is stored -- see ``coreauth``.

WHY PROJECT IDENTITY IS NOT A PATH
----------------------------------
A path is a location, not an identity: it changes when a checkout moves, it differs between two
machines holding the same repository, and it is trivially forged by a caller that simply asks
for a different string. ``workspace.git.repo_id_for`` already derives a stable repository
identity from the origin URL, falling back to a digest of the canonical root, and the dispatcher
already uses it for lease keys. This module reuses it rather than minting a second one.

Note a real inconsistency this module does NOT fix: ``relay/kernel.py`` records ``repo_id`` as
``origin_url or project_root`` rather than calling ``repo_id_for``, so the same repository can
carry two different ids in two tables. That is tracked, not silently papered over here.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Mapping

from quaestor.core.canon import canonical_path

COREID_INSTRUMENT = "core.identity/1"

#: Files under the Quaestor home. Deliberately boring names: an operator looking at the home
#: directory should be able to guess what each one is without reading code.
DEVICE_FILE = "device.json"
PROJECTS_FILE = "projects.json"

# -- project authorization verdicts ------------------------------------------------------------
#: The path is a readable git working tree AND an operator authorised it.
AUTHORIZED = "AUTHORIZED"
#: A real repository this installation knows about, which nobody authorised. Distinct from
#: UNKNOWN so an operator can be told "you have used this before" rather than "no such thing".
KNOWN_UNAUTHORIZED = "KNOWN_UNAUTHORIZED"
#: Never seen, or not a readable working tree. The default for anything a caller names.
UNKNOWN = "UNKNOWN"
#: Authorised once, and the path no longer holds the repository it was authorised for -- moved,
#: deleted, or replaced by a different checkout. NEVER treated as authorised: a stale record is
#: the case where "the caller named a path that used to be fine" must not succeed.
STALE = "STALE"


def _read_json(path: str) -> dict:
    """Impure. NEVER raises. A missing or corrupt file is an EMPTY record, never a fatal one."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return dict(doc) if isinstance(doc, Mapping) else {}
    except (OSError, ValueError):
        return {}


def _write_json(path: str, doc: Mapping) -> None:
    """Atomic replace + fsync. Impure. Raises only if the directory is unusable."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(dict(doc), fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------------------------
# device / installation identity
# ---------------------------------------------------------------------------------------------
def device(home: str, *, now: float = 0.0) -> dict:
    """This installation's durable identity, created on first use. Impure. NEVER raises.

    Stable across restart because it is written once and read thereafter; replaceable because
    it is one file an operator can delete. Carries NO secret and NO capability.

    ``device_id`` is a random UUID rather than anything derived from the machine: a hostname or
    a MAC address would leak into every record it stamps and would change under the operator
    without their asking.
    """
    path = os.path.join(home, DEVICE_FILE)
    doc = _read_json(path)
    if doc.get("device_id"):
        return doc
    doc = {
        "device_id": str(uuid.uuid4()),
        "created_at": float(now or time.time()),
        "instrument": COREID_INSTRUMENT,
        "note": "a local installation identity. NOT a credential and NOT an authority: it "
                "grants nothing, and a reader of this file gains only the ability to say which "
                "installation wrote a record.",
    }
    try:
        _write_json(path, doc)
    except OSError as exc:  # noqa: BLE001 - an unwritable home is reported, never guessed past
        return {"device_id": "", "error": "%s: %s" % (type(exc).__name__, exc),
                "instrument": COREID_INSTRUMENT}
    return doc


# ---------------------------------------------------------------------------------------------
# project registry
# ---------------------------------------------------------------------------------------------
def _safe_origin(url: str) -> str:
    """A remote URL with any embedded credential removed. PURE.

    ``https://user:ghp_xxx@github.com/o/r.git`` is a perfectly ordinary thing to find in a
    working tree, and ``repo_id_for`` would otherwise fold that token into the project id --
    which is then WRITTEN to the registry and SERVED to any client scoped to the project. A
    credential must not become an identifier.
    """
    u = str(url or "").strip()
    if "@" not in u or "://" not in u:
        return u
    scheme, _, rest = u.partition("://")
    userinfo, _, host = rest.rpartition("@")
    if not userinfo:
        return u
    # ``git@host:owner/repo`` is a USERNAME, not a secret, and is the normal ssh form. Only a
    # userinfo carrying a password (user:secret) is stripped.
    if ":" not in userinfo:
        return u
    return "%s://%s" % (scheme, host)


def project_identity(path: str) -> dict:
    """``(project_id, root, origin)`` for a path. Impure (reads git). NEVER raises.

    ``project_id`` is empty when the path is not a readable git working tree -- an unreadable
    location has no identity, and inventing one would let a caller authorise a directory that
    does not exist and then have it quietly start existing later.
    """
    from quaestor.workspace import git as gitmod
    root = canonical_path(path)
    if not root or not os.path.isdir(path):
        return {"project_id": "", "root": root, "origin": "", "readable": False}
    snap = gitmod.probe(path, want_diff=False)
    if not snap.probe_ok:
        return {"project_id": "", "root": root, "origin": "", "readable": False,
                "error": snap.probe_error or "not a readable git working tree"}
    origin = _safe_origin(gitmod.origin_url(path) or "")
    return {"project_id": gitmod.repo_id_for(origin, snap.repo_root),
            "root": canonical_path(snap.repo_root), "origin": origin, "readable": True}


def authorize(home: str, path: str, *, now: float = 0.0) -> dict:
    """Record an operator's decision that this project may be reached. Impure.

    AUTHORISING IS AN OPERATOR ACT. Nothing in this module calls it: it is reached from the CLI,
    where a human typed the path. A client of the Core API can never authorise a project for
    itself -- that is the whole point of the registry, and a request handler that called this
    would defeat it.
    """
    ident = project_identity(path)
    if not ident.get("project_id"):
        return {"ok": False, "verdict": UNKNOWN, **ident,
                "reason": "not a readable git working tree, so it has no identity to authorise"}
    reg_path = os.path.join(home, PROJECTS_FILE)
    doc = _read_json(reg_path)
    projects = dict(doc.get("projects") or {})
    projects[ident["project_id"]] = {
        "project_id": ident["project_id"], "root": ident["root"], "origin": ident["origin"],
        "authorized_at": float(now or time.time()),
    }
    _write_json(reg_path, {"projects": projects, "instrument": COREID_INSTRUMENT})
    return {"ok": True, "verdict": AUTHORIZED, **ident}


def revoke(home: str, project_id: str) -> dict:
    """Withdraw an authorization. Impure."""
    reg_path = os.path.join(home, PROJECTS_FILE)
    doc = _read_json(reg_path)
    projects = dict(doc.get("projects") or {})
    removed = projects.pop(str(project_id), None)
    _write_json(reg_path, {"projects": projects, "instrument": COREID_INSTRUMENT})
    return {"ok": removed is not None, "project_id": str(project_id)}


def projects(home: str) -> list:
    """Every authorised project, oldest first. Impure. NEVER raises."""
    doc = _read_json(os.path.join(home, PROJECTS_FILE))
    rows = list((doc.get("projects") or {}).values())
    rows.sort(key=lambda r: float(r.get("authorized_at") or 0.0))
    return rows


def classify(home: str, path: str) -> dict:
    """Is this path authorised? Impure. NEVER raises. The answer a request handler must consult.

    FOUR VERDICTS, and only one of them is a yes. STALE exists because "authorised once" and
    "authorised now" are different claims: a record naming a path whose repository has moved or
    been replaced must not authorise the thing currently sitting at that path.
    """
    ident = project_identity(path)
    known = {str(r.get("project_id")): r for r in projects(home)}
    if not ident.get("project_id"):
        # The path is unreadable. If a RECORD names this root, the authorisation is stale rather
        # than merely unknown -- the operator authorised something that is no longer there.
        root = canonical_path(path)
        for pid, row in known.items():
            if str(row.get("root") or "") == root:
                return {"verdict": STALE, "project_id": pid, "root": root,
                        "reason": "authorised as %s, and that path no longer holds a readable "
                                  "git working tree" % pid}
        return {"verdict": UNKNOWN, "project_id": "", "root": root,
                "reason": ident.get("error") or "not a readable git working tree"}
    row = known.get(ident["project_id"])
    if row is None:
        return {"verdict": KNOWN_UNAUTHORIZED, "project_id": ident["project_id"],
                "root": ident["root"],
                "reason": "a readable repository that no operator has authorised"}
    if str(row.get("root") or "") != ident["root"]:
        # Same repository identity, different location. The authorisation named a place; the
        # repository has moved. Report it rather than silently following it.
        return {"verdict": STALE, "project_id": ident["project_id"], "root": ident["root"],
                "authorized_root": row.get("root"),
                "reason": "authorised at %s and found at %s" % (row.get("root"), ident["root"])}
    return {"verdict": AUTHORIZED, "project_id": ident["project_id"], "root": ident["root"],
            "origin": ident["origin"], "authorized_at": row.get("authorized_at")}

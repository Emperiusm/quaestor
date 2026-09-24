"""coreauth -- who is asking Core, and which projects that answer reaches.

WHY THIS IS NOT THE EXISTING TOKEN FILE
---------------------------------------
Two authenticated loopback surfaces already exist and both are single-token: hold the secret and
you reach everything the surface can do. That is defensible for a dashboard an operator opened
themselves. It is not defensible for Core, because Core is the boundary a BROWSER EXTENSION will
eventually sit behind, and a browser extension is a program that untrusted pages talk to.

So a Core credential names a CLIENT, and a client carries a project scope. "A caller holding a
valid token for one project cannot reach another" is an acceptance criterion of this milestone,
and it is not expressible with one shared secret.

WHAT IS STORED
--------------
Only the DIGEST of a token, following ``transports.mcp.auth``: a reader of this file cannot
authenticate with what they find in it. The value is returned exactly once, to whoever created
the client, and never again by any function here.

WHAT AUTHENTICATION IS NOT
--------------------------
It is not authorisation, and it is certainly not authority. A verified client has proven only
which grant it holds. Whether the operation it asks for is permitted is decided afterwards by
the project registry and, for anything with an effect, by ``core.authority`` and the owner
channel exactly as before. Nothing in this module widens a capability, and a client that has
proven its identity perfectly still cannot commit, push, or reach an unauthorised project.

LOOPBACK IS NOT AN IDENTITY
---------------------------
Being on 127.0.0.1 proves only that the caller is on this machine, which is true of every
process a compromised page can talk to. It is a necessary condition here and never a sufficient
one: every request is authenticated regardless.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from typing import Mapping, Sequence

COREAUTH_INSTRUMENT = "core.auth/1"

CLIENTS_FILE = "core-clients.json"
#: 32 bytes of urlsafe entropy. The same order as the existing transports.
TOKEN_BYTES = 32

#: Verdicts. ONE refusal string reaches the caller for every failure -- see ``REFUSAL``.
OK = "OK"
NO_CREDENTIAL = "NO_CREDENTIAL"
UNKNOWN_CLIENT = "UNKNOWN_CLIENT"
REVOKED = "REVOKED"

#: WHAT THE CALLER IS TOLD, for absent, malformed, unknown and revoked alike. The distinction is
#: recorded locally and never returned: telling a guesser which of those they achieved is an
#: oracle, and the existing transports refuse to build one.
REFUSAL = "core authentication failed"


def _path(home: str) -> str:
    return os.path.join(home, CLIENTS_FILE)


def _read(home: str) -> dict:
    try:
        with open(_path(home), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return dict(doc) if isinstance(doc, Mapping) else {}
    except (OSError, ValueError):
        return {}


def _write(home: str, doc: Mapping) -> None:
    os.makedirs(home, exist_ok=True)
    p = _path(home)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(dict(doc), fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, p)
    _restrict(p)


def _restrict(path: str) -> None:
    """Defence in depth, never the mechanism. NEVER raises.

    The secret is not in this file -- only digests -- so a failure here is not a breach. It is
    still worth doing, and it is done the way the rest of the tree does it rather than inventing
    a fourth convention.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name != "nt":
        return
    user = os.environ.get("USERNAME") or ""
    if not user:
        return
    try:
        import subprocess
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "%s:(F)" % user],
                       capture_output=True, shell=False, timeout=60)
    except Exception:  # noqa: BLE001
        pass


def _digest(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def issue(home: str, *, name: str, project_ids: Sequence[str] = (),
          now: float = 0.0) -> dict:
    """Create a client and return its token ONCE. Impure.

    ``project_ids`` is the client's whole reach. An EMPTY scope is a real and useful answer --
    a status-only client that can read Core's own health and nothing about any repository --
    so it is not silently promoted to "all projects". There is deliberately no wildcard: a
    scope that can grow without an operator editing it is not a scope.
    """
    doc = _read(home)
    clients = dict(doc.get("clients") or {})
    value = secrets.token_urlsafe(TOKEN_BYTES)
    client_id = str(uuid.uuid4())
    clients[client_id] = {
        "client_id": client_id,
        "name": str(name or "unnamed"),
        "sha256": _digest(value),
        "project_ids": sorted({str(p) for p in (project_ids or ()) if str(p)}),
        "created_at": float(now or time.time()),
        "revoked_at": None,
    }
    _write(home, {"clients": clients, "instrument": COREAUTH_INSTRUMENT,
                  "note": "token VALUES are not stored, only digests"})
    return {"client_id": client_id, "name": clients[client_id]["name"],
            "project_ids": clients[client_id]["project_ids"],
            "value_returned_once": value, "instrument": COREAUTH_INSTRUMENT}


def revoke(home: str, client_id: str, *, now: float = 0.0) -> dict:
    """Revoke a client. Impure. The record is KEPT, marked, never deleted.

    A deleted client is indistinguishable from one that never existed, and an operator asking
    "what could that token reach before I killed it?" deserves an answer.
    """
    doc = _read(home)
    clients = dict(doc.get("clients") or {})
    row = clients.get(str(client_id))
    if row is None:
        return {"ok": False, "client_id": str(client_id)}
    row = dict(row)
    row["revoked_at"] = float(now or time.time())
    clients[str(client_id)] = row
    _write(home, {"clients": clients, "instrument": COREAUTH_INSTRUMENT})
    return {"ok": True, "client_id": str(client_id), "revoked_at": row["revoked_at"]}


def clients(home: str) -> list:
    """Every client, secrets excluded. Impure. NEVER raises."""
    rows = []
    for row in (_read(home).get("clients") or {}).values():
        rows.append({k: v for k, v in dict(row).items() if k != "sha256"})
    rows.sort(key=lambda r: float(r.get("created_at") or 0.0))
    return rows


def authenticate(home: str, presented: str) -> dict:
    """Which client is this? Impure. NEVER raises. PURE-ish: decides nothing about permission.

    Constant-time comparison against every stored digest. The loop does not short-circuit on a
    match, so the time taken does not reveal WHICH client matched or how many exist.
    """
    token = str(presented or "").strip()
    if not token:
        return {"ok": False, "verdict": NO_CREDENTIAL, "refusal": REFUSAL}
    want = _digest(token)
    found = None
    for row in (_read(home).get("clients") or {}).values():
        if hmac.compare_digest(str(row.get("sha256") or ""), want):
            found = row
    if found is None:
        return {"ok": False, "verdict": UNKNOWN_CLIENT, "refusal": REFUSAL}
    if found.get("revoked_at") is not None:
        return {"ok": False, "verdict": REVOKED, "refusal": REFUSAL,
                "client_id": str(found.get("client_id") or "")}
    return {"ok": True, "verdict": OK, "client_id": str(found.get("client_id") or ""),
            "name": str(found.get("name") or ""),
            "project_ids": list(found.get("project_ids") or ())}


def may_reach(auth: Mapping, project_id: str) -> bool:
    """Is this authenticated client scoped to this project? PURE.

    An unauthenticated caller reaches nothing, an empty scope reaches nothing, and there is no
    wildcard. The absence of a wildcard is the point: this is the function that makes "a token
    for one project cannot reach another" true, and a special case here would quietly untrue it.
    """
    if not (auth or {}).get("ok"):
        return False
    pid = str(project_id or "")
    return bool(pid) and pid in {str(p) for p in ((auth or {}).get("project_ids") or ())}

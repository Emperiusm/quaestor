"""transport_auth -- who may speak to the MCP adapter, and what that does NOT prove.

THREE BOUNDARIES THAT ARE ROUTINELY CONFLATED
---------------------------------------------
    A. WORKSPACE AUTHORIZATION   ChatGPT decided this user/workspace may use this app. Enforced
                                 entirely inside ChatGPT. This process cannot observe it and must
                                 not pretend to.
    B. CHANNEL AUTHENTICATION    the tunnel client authenticates ITSELF to OpenAI with a platform
                                 API key. That proves the tunnel is ours. It says nothing about
                                 which ChatGPT user sent a given request.
    C. CALLER AUTHENTICATION     a credential presented TO this server, per request.

Only C is implemented here, and only C can be measured here. Conflating B with C is the mistake
this module exists to prevent: "the tunnel is authenticated" is true and irrelevant to "this
request came from an authorised caller".

If C cannot be proven for the channel actually in use, the honest verdict is
``CALLER_IDENTITY_UNVERIFIED`` -- and P5-A's contract turns that into
``P5_WRITE_TRANSPORT=UNAVAILABLE`` rather than into a shrug.

THE CLAUDE CREDENTIAL IS NOT AN OPTION HERE
-------------------------------------------
This module does not import ``secret_store``, ``dpapi`` or ``credential_validate``, and
``CLAUDE_CODE_OAUTH_TOKEN`` is refused BY NAME as a transport credential even if a caller
presents it. A credential that authenticates a Claude subscription is not a statement about who
is calling this bridge, and accepting it would turn possession of the execution credential into
transport authority.

FAILURE MUST NOT BE INFORMATIVE
-------------------------------
Every rejection returns the same ``UNAUTHENTICATED`` shape with the same wording, before any
store is opened. A caller must not be able to tell a bad token from a good token naming a
nonexistent run -- that difference is an oracle.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from quaestor import branding

AUTH_INSTRUMENT = "transport_auth/1"

# Channel classes
CHANNEL_STDIO = "STDIO_PARENT_BOUND"
CHANNEL_HTTP_LOOPBACK = "HTTP_LOOPBACK_BEARER"
#: The TUNNEL channel. Same bearer mechanism as loopback, a DIFFERENT secret, and a different
#: capability ceiling: a remote caller gets the read-only surface, never a write. The class comes
#: from WHICH token authenticated, never from a header a caller could forge -- possession of the
#: remote token is the owner's deliberate act of exposing reads past the machine's edge.
CHANNEL_HTTP_REMOTE = "HTTP_REMOTE_BEARER"

# Verdicts
AUTHENTICATED = "AUTHENTICATED"
UNAUTHENTICATED = "UNAUTHENTICATED"

# Caller-identity strength -- deliberately separate from "did auth pass".
IDENTITY_UNVERIFIED = "CALLER_IDENTITY_UNVERIFIED"
IDENTITY_SHARED_SECRET = "CALLER_HOLDS_SHARED_SECRET"
IDENTITY_PARENT_PROCESS = "CALLER_IS_PARENT_PROCESS"

#: The single refusal string. Identical for every failure mode, on purpose.
REFUSAL = "transport authentication failed"

#: Never accepted as a transport credential, by NAME.
REFUSED_CREDENTIAL_ENV = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                          "AWS_BEARER_TOKEN_BEDROCK")

TOKEN_BYTES = 32
TOKEN_FILE = "mcp-transport-token.json"
#: The tunnel channel's secret. A separate FILE, not a flag in the same file: deleting it is
#: revocation, and co-locating it with the loopback token would make one mistake cost both.
REMOTE_TOKEN_FILE = "mcp-transport-remote-token.json"


def default_dir() -> str:
    """Outside BOTH repositories, like the credential broker -- and NOT the same directory.

    Separate directories because these are separate secrets with separate lifetimes and separate
    blast radii. Co-locating them would make one ``icacls`` mistake cost both.
    """
    base = os.environ.get(branding.env_var("transport", "secret", "dir"))
    if base:
        return base
    local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData",
                                                           "Local")
    return os.path.join(local, branding.STATE_DIR_NAME, "transport")


@dataclass(frozen=True)
class AuthResult:
    verdict: str
    channel: str = ""
    identity_class: str = IDENTITY_UNVERIFIED
    token_id: str = ""
    reason: str = ""
    inspected_count: int = 0
    instrument: str = AUTH_INSTRUMENT
    record: Mapping = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.verdict == AUTHENTICATED

    def to_dict(self) -> dict:
        """NOTE THE ABSENT FIELD: there is nowhere for a token value to live."""
        return {"verdict": self.verdict, "channel": self.channel,
                "identity_class": self.identity_class, "token_id": self.token_id,
                "reason": self.reason, "inspected_count": self.inspected_count,
                "instrument": self.instrument, "record": dict(self.record)}


def _paths(directory: str | None = None, *, remote: bool = False) -> tuple:
    d = directory or default_dir()
    return d, os.path.join(d, REMOTE_TOKEN_FILE if remote else TOKEN_FILE)


def provision(directory: str | None = None, *, token: str | None = None,
              remote: bool = False) -> dict:
    """Create (or rotate) a transport token. Impure. Returns NON-SECRET metadata only.

    ``token`` exists for tests, which must drive a known value; production passes None and gets
    ``secrets.token_urlsafe``. The value is returned exactly once, to the caller who created it,
    and is never returned by any other function in this module.

    ``remote=True`` provisions the TUNNEL token instead of the loopback token: a separate file,
    a separate lifetime, a separate revocation. Handing the tunnel client the remote token --
    and only it -- is what makes the remote channel read-only: the capability ceiling travels
    with which secret was shared, not with a promise about the caller.
    """
    d, path = _paths(directory, remote=remote)
    os.makedirs(d, exist_ok=True)
    value = token or secrets.token_urlsafe(TOKEN_BYTES)
    doc = {"token_id": str(uuid.uuid4()),
           "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
           "created_at": _now(),
           "instrument": AUTH_INSTRUMENT,
           "note": "the token VALUE is not stored; only its digest, so a reader of this file "
                   "cannot authenticate with it"}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _restrict(path)
    return {"token_id": doc["token_id"], "created_at": doc["created_at"], "path": path,
            "value_returned_once": value}


def _now() -> float:
    import time
    return time.time()


def _restrict(path: str) -> None:
    """Defence in depth only; never the mechanism. NEVER raises."""
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


def load_digest(directory: str | None = None, *, remote: bool = False) -> tuple:
    """(sha256_hex, token_id) or ("", ""). Impure. NEVER raises."""
    _, path = _paths(directory, remote=remote)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return str(doc.get("sha256") or ""), str(doc.get("token_id") or "")
    except (OSError, ValueError):
        return "", ""


def delete(directory: str | None = None, *, remote: bool = False) -> dict:
    """Revoke a token class. Deleting the REMOTE token is how tunnel access is turned off."""
    _, path = _paths(directory, remote=remote)
    try:
        os.remove(path)
        return {"removed": True, "path": path}
    except OSError:
        return {"removed": False, "path": path}


def authenticate_http(headers: Mapping[str, str] | None, *, directory: str | None = None,
                      peer_address: str = "") -> AuthResult:
    """Bearer-token check for the HTTP transports. Impure (reads the digest files).

    Runs BEFORE any store is opened and before any argument is parsed. Constant-time comparison,
    and one identical refusal for absent, malformed, wrong-scheme and wrong-value.

    The presented value is checked against BOTH token classes, and WHICH one matched decides the
    channel: the loopback token authenticates the full surface; the remote token authenticates
    the read-only surface. A caller can never upgrade itself -- the write-capable secret is
    never handed to the tunnel client at all.
    """
    inspected = 0
    digest, token_id = load_digest(directory)
    remote_digest, remote_token_id = load_digest(directory, remote=True)
    inspected += 2
    if not digest and not remote_digest:
        return AuthResult(UNAUTHENTICATED, CHANNEL_HTTP_LOOPBACK, reason=REFUSAL,
                          inspected_count=inspected,
                          record={"detail_local_only": "no transport token is provisioned"})

    raw = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization":
            raw = str(v or "")
            break
    inspected += 1

    presented = ""
    if raw[:7].lower() == "bearer ":
        presented = raw[7:].strip()

    # A caller presenting the CLAUDE credential is refused with the same words as any other
    # failure -- but the local record names it, because it is a meaningful operator signal.
    reused_claude = False
    for name in REFUSED_CREDENTIAL_ENV:
        env_val = os.environ.get(name)
        if env_val and presented and hmac.compare_digest(presented, env_val):
            reused_claude = True
    inspected += len(REFUSED_CREDENTIAL_ENV)

    presented_digest = hashlib.sha256(presented.encode("utf-8")).hexdigest() if presented else ""
    loopback_ok = bool(presented) and not reused_claude and bool(digest) and \
        hmac.compare_digest(presented_digest, digest)
    remote_ok = bool(presented) and not reused_claude and bool(remote_digest) and \
        hmac.compare_digest(presented_digest, remote_digest)
    inspected += 2

    if not (loopback_ok or remote_ok):
        return AuthResult(UNAUTHENTICATED, CHANNEL_HTTP_LOOPBACK, reason=REFUSAL,
                          inspected_count=inspected,
                          record={"detail_local_only": ("claude credential presented as transport "
                                                        "auth" if reused_claude else
                                                        "absent or non-matching bearer token"),
                                  "peer": peer_address})
    if remote_ok:
        # The REMOTE token matched. Even if the loopback token also existed, the caller
        # presented the remote one -- and the channel follows the secret presented.
        return AuthResult(AUTHENTICATED, CHANNEL_HTTP_REMOTE, IDENTITY_SHARED_SECRET,
                          remote_token_id, inspected_count=inspected,
                          record={"peer": peer_address, "surface": "read-only",
                                  "identity_limit": ("a shared secret proves POSSESSION, not "
                                                     "WHICH ChatGPT user or workspace sent the "
                                                     "request")})
    return AuthResult(AUTHENTICATED, CHANNEL_HTTP_LOOPBACK, IDENTITY_SHARED_SECRET, token_id,
                      inspected_count=inspected,
                      record={"peer": peer_address,
                              "identity_limit": ("a shared secret proves POSSESSION, not WHICH "
                                                 "ChatGPT user or workspace sent the request")})


def authenticate_stdio(*, parent_ok: bool = True) -> AuthResult:
    """Stdio transport: the channel IS the boundary. Impure only in reading the environment.

    A stdio server has no listener. Its stdin/stdout are pipes held by the process that launched
    it -- the tunnel client -- so reaching it requires already being able to run a process as this
    user, which is a strictly larger capability than anything the transport grants.

    That is a strong CONFINEMENT property and a weak IDENTITY property, and the two are reported
    separately: ``identity_class`` stays ``CALLER_IS_PARENT_PROCESS``, never a claim about the
    ChatGPT user.
    """
    if not parent_ok:
        return AuthResult(UNAUTHENTICATED, CHANNEL_STDIO, reason=REFUSAL, inspected_count=1)
    return AuthResult(
        AUTHENTICATED, CHANNEL_STDIO, IDENTITY_PARENT_PROCESS, inspected_count=1,
        record={"listener": "none -- stdio pipes only",
                "identity_limit": ("proves the caller is the launching process. It does NOT "
                                   "identify a ChatGPT user, workspace or app.")})


def caller_identity_verdict(result: AuthResult) -> str:
    """Map an auth result onto P5-A's TRANSPORT_CALLER_AUTH vocabulary. PURE.

    Neither implemented channel can identify the ChatGPT PRINCIPAL, so neither returns PASS. That
    is a property of what the transport can observe, not a defect in this code, and stating it is
    the difference between a measurement and a wish.
    """
    if not result.ok:
        return "FAIL"
    return "UNVERIFIED"

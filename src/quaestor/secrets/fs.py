"""fs -- local filesystem conventions shared by every secret-holding module.

WHY THIS IS NOT PART OF ``store``
--------------------------------
``store`` is the PROVIDER credential broker; ``attestation`` is the OWNER-authority key. They are
deliberately separate secrets with separate lifetimes and separate blast radii, and a static
control proves the transport can never reach the broker at import level. The owner-attestation
channel IS legitimately reachable from the transport (the authority chain consults its state), so
the primitives both modules need -- the platform state directory and the per-user ACL -- must live
somewhere that is not the broker. Hence this module: importing it grants access to no secret and
no credential, only to conventions.
"""
from __future__ import annotations

import os
import subprocess

from quaestor import branding


def default_dir() -> str:
    """The platform state directory -- outside BOTH repositories.

    Resolved from ``branding.STATE_DIR_NAME`` rather than spelled here: a docstring that
    names a literal path is a docstring that goes stale the moment the product is renamed,
    and this one already did.

    Outside on purpose: anything inside a repository can be committed by accident, swept into a
    diff, or bind-mounted into a container. Secret storage must not be reachable by any of
    the mechanisms this project spends its time constraining.
    """
    base = os.environ.get(branding.env_var("secret", "dir"))
    if base:
        return base
    local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData",
                                                           "Local")
    return os.path.join(local, branding.STATE_DIR_NAME, "secrets")


def restrict_acl(path: str) -> tuple:
    """(ok, detail). Restrict the artifact to the current user. Impure. NEVER raises.

    Defence in depth ONLY. DPAPI is the cryptographic boundary; an ACL keeps an idle copy out of
    another account's reach but protects nothing against the account that owns the DPAPI key. A
    failure here is reported, not fatal -- overstating an ACL as protection would be worse than
    not having one.
    """
    if os.name != "nt":
        return False, "not Windows"
    user = os.environ.get("USERNAME") or ""
    if not user:
        return False, "USERNAME unset"
    try:
        p = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "%s:(F)" % user],
                           capture_output=True, shell=False, timeout=60)
        out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
        return p.returncode == 0, out[:200]
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "%s: %s" % (type(exc).__name__, exc)


def acl_is_restricted(path: str) -> bool | None:
    """Tri-state. None = could not measure -- never silently 'yes'. Impure."""
    if os.name != "nt" or not os.path.exists(path):
        return None
    try:
        p = subprocess.run(["icacls", path], capture_output=True, shell=False, timeout=60)
        if p.returncode != 0:
            return None
        text = p.stdout.decode("utf-8", "replace")
        user = (os.environ.get("USERNAME") or "").lower()
        grants = [l for l in text.splitlines() if ":" in l and "Successfully" not in l]
        others = [l for l in grants if user and user not in l.lower() and l.strip()]
        return len(others) == 0 and bool(user)
    except (OSError, subprocess.SubprocessError):
        return None

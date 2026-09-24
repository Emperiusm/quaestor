"""branding -- the ONE place the product's name appears.

WHY THIS MODULE EXISTS
----------------------
This platform was extracted from a control plane built for a single private repository. The
extraction's whole point is that the core belongs to no project, no model vendor and no user, so
every place the old product name had leaked into a default -- a container name, a Docker network,
an environment-variable prefix, a storage directory -- now reads its value from here.

That makes renaming the product a one-line change instead of an archaeology exercise, and it makes
"is this core still coupled to its first consumer?" a question a test can answer by asserting that
no other module hard-codes a name.

WHAT DOES *NOT* BELONG HERE
---------------------------
Frozen wire constants. See ``quaestor.compat``: a value that has already been written into a
captured artifact or into a dispatch identity is not branding, it is history, and renaming it
would silently change behaviour. Branding is what is safe to change; compat is what is not.
"""
from __future__ import annotations

#: Provisional working name. Neutral by construction: it names the ROLE the system plays -- the
#: officer who audits the accounts and controls disbursement -- rather than any project, model
#: vendor or company. Renaming is expected; it costs one edit here.
PRODUCT_NAME = "quaestor"
PRODUCT_TITLE = "Quaestor"
PRODUCT_VERSION = "0.1.0"
PRODUCT_TAGLINE = ("model-agnostic AI orchestration platform on a local-first security boundary")

#: Prefix for every environment variable this platform reads. Never hard-code a variable name
#: elsewhere; build it with ``env_var``.
ENV_PREFIX = "QUAESTOR"

#: Prefix for every container, network and volume the sandbox providers create, so a stray
#: resource is always attributable to this platform and never collides with a user's own.
RESOURCE_PREFIX = "quaestor"

#: Directory under the user's local application data where non-repository state lives.
STATE_DIR_NAME = "Quaestor"

def state_home() -> str:
    r"""The per-user directory this deployment keeps its state in. Impure (reads env). PURE-ish.

    WHY THIS IS NOT INSIDE THE PACKAGE. The default used to be ``<package>/var``, which works
    only from a source checkout: after ``pip install`` that path is inside site-packages, where
    it is wiped by the next reinstall, invisible to the operator, and shared by nothing. State
    that a user is told is durable must not live somewhere a package manager owns.

    Platform conventions, because an operator looking for their data should find it where every
    other tool on that machine puts it:

        Windows   %LOCALAPPDATA%\Quaestor
        macOS     ~/Library/Application Support/Quaestor
        else      $XDG_DATA_HOME/quaestor, or ~/.local/share/quaestor

    The environment variable (``QUAESTOR_HOME``) still wins over all of it -- see
    ``transports.cli.DEFAULT_HOME`` -- because a deployment that wants its state somewhere
    specific should not have to argue with a convention.
    """
    import os
    import sys
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, STATE_DIR_NAME)
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support",
                            STATE_DIR_NAME)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"),
                                                           ".local", "share")
    return os.path.join(base, PRODUCT_NAME)


#: Git identity every control-plane commit carries, so provenance is attributable at a glance
#: without hard-coding the product name at each commit site.
COMMITTER_NAME = PRODUCT_TITLE + " Control Plane"
COMMITTER_EMAIL = PRODUCT_NAME + "@local"


def env_var(*parts: str) -> str:
    """``env_var("home")`` -> ``"QUAESTOR_HOME"``. PURE."""
    return "_".join([ENV_PREFIX, *[p.upper().replace("-", "_") for p in parts]])


def resource(*parts: str) -> str:
    """``resource("egress")`` -> ``"quaestor-egress"``. PURE."""
    return "-".join([RESOURCE_PREFIX, *[str(p).strip("-") for p in parts if str(p).strip("-")]])


def label(key: str) -> str:
    """A Docker label key namespaced to this platform. PURE."""
    return "%s.%s" % (RESOURCE_PREFIX, key)


def branch(*parts: str) -> str:
    """A git branch owned by this platform: ``branch("p1", "lane-2")`` -> ``"quaestor/p1/lane-2"``.

    PURE. Lane and integration branches live in this namespace so a stray branch is always
    attributable to the control plane and never collides with a user's own.
    """
    return "/".join([RESOURCE_PREFIX, *[str(p) for p in parts if str(p)]])


def commit_scope(scope: str) -> str:
    """The conventional-commit prefix control-plane commits carry.

    ``commit_scope("wip")`` -> ``"quaestor(wip)"``. PURE.
    """
    return "%s(%s)" % (PRODUCT_NAME, scope)


def command(*parts: str) -> str:
    """A CLI invocation as printed in help and next-step text.

    ``command("owner init")`` -> ``"quaestor owner init"``. PURE.
    """
    return " ".join([PRODUCT_NAME, *[str(p) for p in parts if str(p)]])

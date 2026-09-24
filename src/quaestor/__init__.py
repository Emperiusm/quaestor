"""quaestor -- a model-agnostic AI orchestration platform on a local-first security boundary.

The canonical product contract is ``docs/PRD.md``. This package is Quaestor Core (PRD section 3):
the local runtime that owns repository access, agent control, secrets, governance enforcement and
evidence. Quaestor Web and Quaestor Cloud are contract, not code.

Layering, and the direction dependencies are allowed to point:

    transports/   MCP, CLI            -- speak to strategists; own NO orchestration semantics
    review/       reviewer roles      -- judge results; never grade their own work
    executors/    fake, claude_code   -- run bounded work; provider detail stops here
    sandbox/      docker              -- confinement providers
    workspace/    git worktree        -- isolated working copies
    evidence/     independent measurement
    secrets/      credential providers
    projects/     per-project config and adapters
        \
         `-> core/  state, identity, authority, dispatch, lanes, messages, decisions

At the package ROOT sit the two owner-side primitives that are deliberately NOT provider
credentials: ``dpapi`` (the OS crypto seam) and ``attestation`` (the owner-authority key). They
are importable from anywhere -- including ``core`` -- because they are what keeps owner authority
from being confused with a provider credential or a model statement.

``core`` imports NOTHING from the layers above it. That is the extraction's load-bearing rule and
a control asserts it against the real import graph.
"""
from quaestor.branding import PRODUCT_NAME, PRODUCT_TITLE, PRODUCT_VERSION

__all__ = ["PRODUCT_NAME", "PRODUCT_TITLE", "PRODUCT_VERSION"]
__version__ = PRODUCT_VERSION

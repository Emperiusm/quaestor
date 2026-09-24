"""review -- reviewer IMPLEMENTATIONS.

The review CONTRACT (types, the floor, the recomputation rule) lives in
``quaestor.core.review_contract``: the acceptance gate in core depends on it, and core
may not import an outer layer. This package holds the reviewers themselves, which are
providers like any executor.

``review.adversarial`` is the operational adversarial reviewer facade over the core contract:
the scheduling engine (core.orchestrator) composes and consumes reviews, and this package gives
callers outside core -- a CLI, a test, a future reviewer provider -- the same vocabulary without
reaching into scheduler internals.
"""

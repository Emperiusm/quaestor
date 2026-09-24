"""relay -- Relay Mode: a persistent conversation between a selected Orchestrator and a
selected Execution Agent, with this platform as the trusted courier and governance boundary.

THE SEPARATION THIS PACKAGE EXISTS TO MAKE
-------------------------------------------
Program Mode's ``Executor.execute()`` is a BOUNDED TURN: build a request, run a child, reap a
result, transition a state machine. That is the right shape for a governed seat and the wrong
shape for a conversation. A relay is not a sequence of unrelated bounded runs; it is two
long-lived endpoints that each remember what was already said.

So Relay Mode does not route through ``Executor.execute()``, does not create programs, lanes or
seats, and does not borrow Program Mode's state machine. It reuses the SUBSTRATE -- authority,
owner channel, classification/redaction, git observation, evidence fingerprints, branding --
and puts a much smaller product on top of it.

    OrchestratorEnd   persistent strategic conversation endpoint
    ExecutionEnd      persistent/resumable implementation-agent endpoint
    RelayKernel       transport-neutral coordination: identity, dedup, persistence,
                      recovery, bounded context, governance hooks

Nothing in ``kernel``, ``state``, ``effects``, ``observe`` or ``packets`` may import a provider.
Providers live in ``relay.ends`` and are reached through ``relay.registry`` by name, the same
inversion ``executors.registry`` uses for Program Mode.
"""
from __future__ import annotations

RELAY_INSTRUMENT = "relay/1"

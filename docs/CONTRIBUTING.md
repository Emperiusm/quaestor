# Contributing

`docs/PRD.md` is the canonical product contract. When this file and the PRD disagree about
what a component is *for*, the PRD wins and this file is the defect.

## Adding an executor provider

1. Implement the contract in `src/quaestor/core/executor_contract.py`.
2. Put the implementation under `src/quaestor/executors/`.
3. Register it in `src/quaestor/executors/registry.py` — **the only place** that needs to change.
4. Add it to `KNOWN_KINDS`. An unknown kind is refused, never guessed: a run that reports success
   from a fake executor it did not ask for is the worst available outcome.

Provider-specific authentication stays inside the provider. If your adapter needs a credential,
it goes through `secrets/`, never into core state.

## Adding a relay end

Relay Mode has a second inversion seam with the same discipline and the same reason:
`src/quaestor/relay/registry.py`. It is separate from `executors/registry.py` because a relay
endpoint is a persistent conversation, not a one-turn `Executor.execute`.

1. Implement the contract in `src/quaestor/relay/contracts.py`. There is one base class,
   `RelayEnd` — `open`, `status`, `identity`, `resume`, `send`, `receive`, `close` — and the role
   is carried by the instance, not by a second class. The PRD (§8.1) names the two roles
   `OrchestratorEnd` and `ExecutionEnd` and sketches them as `async`; the implementation is
   deliberately synchronous, because the substrate beneath it is and one relay drives exactly one
   conversation at a time. That serialization is what makes duplicate-delivery reasoning
   tractable. Every method that talks to something outside this process returns a **named**
   outcome instead of raising: "the process died" is not a status an operator can act on.
2. Implement `holds(message_id) -> bool` if the endpoint can be asked "do you already hold this?".
   The kernel reconciles a delivery interrupted by a crash by asking. An endpoint that cannot be
   asked stops the relay with `UNRECONCILABLE_DELIVERY` rather than choosing on your behalf
   between duplicating work in somebody's repository and dropping it, and a transport failure
   during that question propagates instead of being read as "no".
3. Put the implementation under `src/quaestor/relay/ends/`.
4. Register it in `src/quaestor/relay/registry.py` — **the only place** that needs to change —
   and add the kind to `ORCHESTRATOR_KINDS` or `EXECUTION_KINDS`. `build_orchestrator` and
   `build_execution` import the provider *inside* the branch that needs it; nothing provider-shaped
   at module scope.
5. An unknown or empty kind is a named refusal (`END_KIND_NOT_BUILDABLE`), never a fallback.
   There is deliberately no default endpoint: a relay that quietly used the scripted endpoint
   would report a conversation no model had.
6. Add a **measured** `preflight` in your module and dispatch to it from `registry.preflight`.
   A kind this build ships no preflight for answers `ok: False` with `"proves": "UNVERIFIED"`
   rather than inheriting a blanket pass. This is what `quaestor relay doctor` prints.
7. If the kind takes configuration, map its flags in `orchestrator_spec` / `execution_spec` in
   `src/quaestor/relay/cli.py`. The durable record holds only the kind and the conversation or
   session identity — `config_json` carries limits, endpoint facts and computed assurance, not
   your spec — so `quaestor relay resume` rebuilds the endpoint from the same flag surface
   `start` uses. Every config field must therefore be re-suppliable by flag or carry a working
   default; one that only `start` can set makes a resumed relay quietly different from the one
   it claims to be continuing. The spec names where a credential lives (`key_var`, `key_file`,
   `key_file_field`) and never carries its value: the endpoint resolves it at call time.

The kernel must never import a provider. `kernel.py`, `state.py`, `effects.py`, `observe.py`,
`packets.py` and `contracts.py` may not import `quaestor.relay.ends` or `quaestor.executors`;
**control 257** (`tests/test_relay_kernel.py`) parses those modules with `ast`, walks the import
graph and asserts there are no offenders, then proves the registry refuses an unknown kind by
name. **Control 264** (`tests/test_relay_chatgpt_end.py`) tightens the same walk for the browser
endpoint: those modules may not contain the words `chatgpt`, `browser`, `cdp`, `playwright` or
`selector` at all. If your endpoint's vocabulary starts appearing in the kernel, the endpoint is
the wrong shape — every browser-shaped, gateway-shaped or session-shaped fact stops inside
`ends/`.

## Adding a transport

Transports translate. They own no orchestration semantics, make no policy decision, and may only
ever be *stricter* than the engine beneath them. If you find yourself deciding whether something
is allowed, you are in the wrong layer.

## Rules for controls

A control must **mutate something or assert a refusal**. If it only exercises the happy path it
proves serialization, not verification.

- Pair every refusal with a positive control proving the gate discriminates. A gate that refuses
  everything passes every negative test and is worthless.
- Emit an inspection count. Assert a floor. A control that can pass over an empty input will
  eventually do exactly that.
- Prefer AST or behaviour over substring matching on source. Substring checks answer a different
  question than they claim — this project has been bitten three separate times.
- Never weaken a control to make a refactor pass. If a control cannot survive a change, that is
  information about the change.

Register new controls in `tests/controls.py`; `run_tests.py` fails if a required control is
undeclared or never executed.

## Style

Standard library only. Explicit UTF-8 decoding — never `text=True` on subprocess output, which
decodes with the locale codepage and silently mojibakes non-ASCII.

Docstrings carry the *reason*, not the mechanics. Most of them encode an incident that was paid
for; when you change the code, keep the lesson.

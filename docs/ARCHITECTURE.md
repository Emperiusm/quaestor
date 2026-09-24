# Architecture

## The one rule

`core` imports nothing from the layers above it.

```
relay/       ──┐
transports/  ──┤
adapters/    ──┤
review/      ──┤
executors/   ──┤
sandbox/     ──┼──►  core/
workspace/   ──┤
evidence/    ──┤
audit/       ──┤
secrets/     ──┤
projects/    ──┘
```

A core that statically depends on one executor cannot be used with another. So the dependency
points inward and a control (`171`) walks the real import graph to prove it, including
function-local imports.

That is every layer package in `src/quaestor/`, not a selection from them; the root modules
(`dpapi`, `attestation`, `branding`, `compat`, `deployment`) sit outside the ladder deliberately.
`relay/` is Relay Mode (below). `adapters/` is the universal agent-end contract and the measured
assurance ladder that decides what an integration may honestly promise. `audit/` holds only its
package marker at HEAD; it is listed because this diagram is a roster of the real tree rather than
a subset of it.

Control `171` proves the rule for the provider layers it names — `transports`, `executors`,
`sandbox`, `projects`, `secrets` — and separately measures that importing `core` loads none of
those nor `review`. It does not cover every row above: at HEAD `core` imports `workspace` and
`evidence` directly, and reaches `adapters.registry` only at call time, through the same inversion
seam described below. The diagram states the intended direction; the control states the part that
is proven.

Two places invert deliberately, and both are documented in place:

- **The executor contract lives in `core/executor_contract.py`.** Core declares what an executor
  must do; providers implement it. That is an interface, not a provider, so it belongs to core.
- **The executor *factory* lives in `executors/registry.py`** and `core/worker.py` resolves it at
  call time. Core declares the need; the provider layer satisfies it. Adding a provider is a
  change in the registry and nowhere else.

## Two modes on one core

Two orchestration products sit on that core, and neither runs through the other.

- **Program Mode** (`quaestor program`) is the state-machine product: programs, workflows, lanes,
  runs, seats, worktrees, leases, independent reviewers. The sections from *Programs, workflows,
  lanes, runs* through *Review* describe it.
- **Relay Mode** (`quaestor relay`) is the conversation-first product: a persistent Orchestrator
  endpoint and a persistent Execution Agent endpoint, joined by a kernel that imports no provider.
  See [Relay Mode](#relay-mode) below.

Both reuse the same substrate — authority, the owner channel, classification and redaction,
independent repository observation, evidence, durable decisions — and put a different product on
top of it. Relay Mode does **not** route through `Executor.execute()` and creates no program, lane
or seat. [`PRD.md`](PRD.md) §5.1 states that as a requirement, `src/quaestor/relay/__init__.py`
states it as a consequence, and control `246` asserts it against a real multi-turn exchange.

[`PRD.md`](PRD.md) is the canonical product contract; where it and this document disagree, the PRD
wins. This document describes what the code does.

## Actors

Six roles: `STRATEGIST`, `EXECUTOR`, `VERIFIER`, `REVIEWER`, `ADVERSARIAL_REVIEWER`, `OWNER`.

**A role is a description of what an actor is for. It is never a grant.** This is the opposite of
the usual shape, where a message from a privileged sender is treated as a privileged message —
which fails the moment a sender can be forged, guessed, or *persuaded*, and a language model can
be persuaded.

```
role      →  what this actor is FOR         (core/actors.py)
authority →  what this actor may CAUSE      (core/authority.py + owner grants)
```

`authority_ceiling()` is the seam and it only ever *narrows*. Review roles carry a hard ceiling:
a reviewer that can edit what it reviews is not a reviewer.

## The two-way protocol

The old shape was one-way — objective in, result out — so anything the executor needed to say on
the way had nowhere to go except prose in the final answer, where a machine cannot route it.

```
strategist ──OBJECTIVE / DIRECTIVE──►  executor
           ◄──CLARIFICATION_REQUEST──┤
           ◄──DECISION_REQUEST───────┤
           ◄──BLOCKER────────────────┤
           ◄──OBSERVATION────────────┤
           ◄──PLAN_REVISION──────────┤
           ◄──RESULT─────────────────┘
owner      ◄──AUTHORITY_REQUEST / OWNER_ESCALATION
```

Structured envelope, natural-language payload. The envelope is machine-routable and validated; the
payload is opaque and **never parsed for instructions** — a control plane that reads prose for
directives has reintroduced prompt injection at the layer meant to prevent it.

`AUTHORITY_REQUEST` is the important one: recording it grants nothing. `caused_by` makes the
exchange a DAG rather than a transcript, which is what lets a later session reconstruct what
answered what.

Messages are **idempotent by content digest** — a redelivered message is the same message, enforced
by a unique index rather than by every caller remembering to check.

## Programs, workflows, lanes, runs

```
PROGRAM     what a strategist resumes
  WORKFLOW  what is accepted or rejected together
    LANE    one line of work, ONE writer, its own workspace
      RUN   one bounded execution (the already-qualified unit)
```

Four levels because each answers a question the others cannot. A fifth ("task") was considered and
rejected: it added an identifier with no distinct semantics.

**Outcomes do not collapse.** `aggregate()` refuses to reduce the tree to a boolean:

| situation | program verdict | next authority |
|---|---|---|
| a lane failed | `FAIL` | `STRATEGIST` — a failed lane is a decision, not an ending |
| a lane is waiting on the owner | `NOT_EVALUATED` | `OWNER` |
| every lane complete and passing | `PASS` | `NONE` |
| no lanes | `NOT_EVALUATED` (`vacuous`) | `STRATEGIST` |

**Waiting is a state, not a failure.** `WAITING_FOR_STRATEGIST`, `WAITING_FOR_OWNER`,
`WAITING_FOR_LANE`, `WAITING_FOR_EXTERNAL_EVENT`.

### Lane ownership

One active strategic writer per lane, via a durable **fenced** lease: an owner token, an expiry,
and a monotonically increasing fence. An expired lease is takeable and the taker gets a higher
fence, so a superseded writer's late call is *detectable* rather than merely unlikely.

This is coordination, **not authentication** — see [THREAT-MODEL.md](THREAT-MODEL.md).

Two writable lanes may never share a workspace; `workspace_conflicts()` makes that a structural
check rather than a surprise discovered as a merge conflict.

## Durable strategic state

The canonical program state is **not** a chat window. `StrategicStore.handoff_bundle()` assembles,
from durable rows: objective, lane states, dependencies and what is blocking, live decisions, open
questions, aggregate verdict and next authority.

A new session resumes from that bundle. It is never handed a transcript — and a control asserts
the bundle contains no transcript-shaped field.

Decisions are **superseded, never overwritten**, and superseding requires a rationale: "we used to
think X, then we learned Y" is the most valuable thing in the record.

## Review

```
executor → candidate
              │
     DETERMINISTIC EVIDENCE (collected independently)
              ├──────────► standard reviewer
              └──────────► adversarial reviewer  (READ_ONLY, independent context)
                                   └──► findings ──► strategist
```

`build_request()` **refuses** a review with no independent evidence, and `ReviewRequest` has no
field capable of carrying the executor's conversation. Handing a reviewer the reasoning it is
meant to check is how correlated errors happen.

An empty adversarial review is `VACUOUS`, never `ACCEPTED`.

The platform owns a **floor** of change classes that always require adversarial review
(security-sensitive, authentication, authority change, sandbox change, deployment, destructive
capability). A project may widen it; configuration cannot remove it.

## Relay Mode

A relay is two long-lived endpoints and a courier between them. `Executor.execute()` is a bounded
turn — build a request, run a child, reap a result, transition a state machine — which is the
right shape for a governed seat and the wrong shape for a conversation, because it has no notion
of *the same conversation*, of *a turn I already delivered*, or of *resume*. Growing it until it
did would push relay concerns into Program Mode's admission path and make every relay concern
reachable only through a program. So the relay declares its own contract and the two live side by
side.

```
OrchestratorEnd   ──►   RELAY KERNEL   ──►   ExecutionEnd   ──►   repository
    strategy            message identity     implementation
                        duplicate suppression
                        durable delivery ledger
                        crash recovery
                        bounded context transfer
                        governance and owner holds
```

Operator surface: `quaestor relay start|resume|status|doctor|stop`.

What the Orchestrator is told about the repository is read by **this process's own git**, before
and after the agent's turn. The agent's own status and diff endpoints are deliberately not used:
evidence supplied by the party it describes is not evidence (control `259`).

### The kernel imports no provider

`kernel.py`, `state.py`, `effects.py`, `observe.py` and `packets.py` may not import a provider.
Endpoints live in `relay/ends/` and are reached **by name** through `relay/registry.py`
(`ORCHESTRATOR_KINDS`, `EXECUTION_KINDS`), the same inversion `executors/registry.py` performs for
Program Mode, and an unknown kind is a named refusal — `END_KIND_NOT_BUILDABLE` — rather than a
silent default. Controls `257` and `264` walk the real import graph to prove the kernel modules
never reach into `ends/`. Adding an endpoint is a change in the registry and nowhere else.

There is deliberately no default endpoint. The scripted `fake` ends exist for the control suite
and are refused by `relay start`: a relay reporting a finished conversation no model took part in
would be indistinguishable from a real one.

### The endpoint contract

`relay/contracts.py` declares one base, `RelayEnd`, and two roles — `ROLE_ORCHESTRATOR` and
`ROLE_EXECUTION`. A module may implement both; an *instance* holds one, because an endpoint that
could silently swap roles makes "who decided this?" unanswerable. The contract is seven methods —
`open`, `status`, `identity`, `resume`, `send`, `receive`, `close` — and every one of them that
talks to something outside the process must return a **named** outcome instead of raising, because
"the process died" is not a diagnosis an operator can act on. `holds` is deliberately *not* on that
list; the delivery ledger below says why.

Two answers are first-class rather than failures. `RESUME_UNSUPPORTED` is what an endpoint that
cannot resume must say, and the relay records it as such rather than claiming continuity the
transport does not provide. `END_UNKNOWN` liveness is not `END_IDLE`: an endpoint we could not
read must never present as one we read and found ready.

`EndFacts` splits two things `adapters.registry` still carries as one `write_capable` boolean read
in two incompatible senses. **Capability** is what the endpoint does (`can_mutate_repo`,
`manages_lifecycle`, `supports_session_resume`). **Proof** is what this build can demonstrate
about it (`proves_workspace_identity`, `proves_confinement`). Assurance is *computed* from the
proof facts through the `adapters.assurance` ladder and is never declared by an endpoint about
itself — so an agent that really does edit files is described as editing files even while its
confinement is unproven, instead of being either flattered or excluded.

### The delivery ledger

The relay's reason to exist is that a conversation survives a restart without saying anything
twice. Two rows are written **before** the thing they describe: `DELIVERING` before the send, and
`awaiting_message_id` before the wait — a relay spends nearly all of its wall-clock time waiting
for a slow agent turn, so that is where a kill lands.

`relay resume` then reconciles every `DELIVERING` row by **asking the endpoint** whether it
already holds the relay-assigned id:

| the endpoint says | the relay does |
|---|---|
| already held | confirms it; never re-sends |
| not held | re-sends exactly once |
| cannot answer | stops with `UNRECONCILABLE_DELIVERY`, and a human decides |

An endpoint that cannot answer that question must not implement `holds` at all, so the kernel
stops rather than guessing. And *failing to ask* is never recorded as "no": a transport error
during reconciliation propagates, because reading it as "the endpoint does not have it" would
re-send a message the agent may already be acting on. An outstanding turn is collected, not
re-issued. Controls `247`, `248`, `261` and `262`.

### Owner holds

Authority comes from two places a model cannot write: the authority profile the operator started
the relay under, and a live owner grant corroborated by an authenticated owner channel. The rule
is the one already stated for `AUTHORITY_REQUEST` — **asking is not receiving** — and there are
three gates.

| gate | when | what it does |
|---|---|---|
| `gate_start` | once, before the first message moves | refuses a repo-mutating execution end under a profile that does not grant `repo_write` |
| `gate_directive` | per message | maps a machine-readable effect request onto capabilities and through `core.authority.require`; `OWNER_REQUIRED` becomes an owner hold |
| `gate_observation` | after the turn | compares two independent readings of the repository and holds when the difference implies a capability the profile does not carry |

A keyword scanner over the Orchestrator's prose would be the wrong boundary in both directions:
it fires on "do not push this yet", it misses every phrasing nobody thought of, and it makes the
model's *words* the security boundary. So prose asserting authority moves nothing, an effect class
this build does not model is refused rather than ignored, and on an owner hold the directive is
**recorded but never delivered**.

The observation gate is the one that still works against an agent nobody can confine. It does not
ask the agent what it did. We cannot *prevent* an unconfined agent from running `git push`; we can
refuse to instruct it to, and detect that it happened and stop. Claiming prevention we do not have
would be the dishonest option.

**Record first, hold second.** A gate never fires before the turn that triggered it is durable: an
operator interrupted about an effect must be able to read the work that produced it, and a later
resume must have something to hand the Orchestrator.

### Where the detail lives

[`RELAY-MODE.md`](RELAY-MODE.md) carries the operator surface, the per-endpoint maturity table,
what each side actually sees in a packet, and the dated live-qualification records.
[`PRD.md`](PRD.md) §5 and §6 carry the product contract the above implements.

## Events

A closed vocabulary, append-only. Not event sourcing — state is not rebuilt by replay — but enough
that the sequence of facts is reconstructable after a crash. `REQUEST_ONLY` events are kept
distinguishable so nobody can mistake *asking* for authority for *receiving* it.

## Frozen wire constants

`src/quaestor/compat.py` holds two values that still carry the original project's name, and both
are frozen for measured reasons:

- **`DISPATCH_KEY_SALT`** is hashed into every dispatch key. Changing it re-keys every existing
  store, so already-completed work would re-admit as new — a silent, invisible migration.
- **`HANDOFF_PROTOCOL`** appears in a captured real-executor fixture, the only test input this
  project did not generate. Renaming it would force editing the one piece of independent evidence
  in the suite.

The product name is in `branding.py` and is free to change. These are not that.

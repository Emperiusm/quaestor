# Threat model

## Trust boundaries

```
  strategist (untrusted reasoning)
        │  MCP / CLI      ← transport authentication happens HERE
        ▼
  control plane (trusted)  ← the only place authority is decided
        │  bounded capability envelope
        ▼
  executor (untrusted reasoning, constrained execution)
        │
        ▼
  workspace (isolated)  →  repository
```

The strategist and the executor are both treated as **untrusted reasoning inside a trusted
harness**. They may be wrong, may be manipulated by content they read, and may argue persuasively
for more access. The harness is what refuses.

## Adversaries considered

| Adversary | Defence |
|---|---|
| An executor that wants more access | Capability comes from an owner grant; `AUTHORITY_REQUEST` records a request and grants nothing. |
| A repository whose contents contain instructions | All caller and repository text is data. Policy, authority, mode and tool definitions are unreachable from it. |
| A strategist that names a path it should not | No schema accepts a filesystem path; repositories are named by server-side alias, and an adapter aliasing a protected root cannot be constructed. |
| A caller probing the transport | Auth fails closed with one identical refusal for every failure mode, before any store is opened; a bad token is indistinguishable from a nonexistent run. |
| A crashed or ambiguous write | Reconciliation classifies and never redispatches; `NEVER_DISPATCHED` is distinguished from `AMBIGUOUS_EXECUTION` so the real alarm keeps its meaning. |
| Two strategists racing on one lane | A durable fenced lease; a superseded writer's late call is refused, not merged. |
| A reviewer that agrees with the executor | Independent context by construction and a read-only role ceiling. |

## Explicit non-goals

- **Strategist identity is not authenticated by this platform.** Lane leases coordinate
  cooperating writers. They do not prove who anyone is. Where the transport cannot supply an
  authenticated caller, the honest record is `TRANSPORT_CALLER_AUTH=UNVERIFIED`, and a deployment
  should not grant write transport on that basis.
- **A sandbox is required for real containment.** Without a sandbox provider an executor has the
  host's access. `sandbox: none` is a legitimate configuration for inert qualification and a
  dangerous one for real execution.
- **`docker inspect` exposes injected environment.** Inherent to `--env`; closing it requires a
  secrets mount.
- **Prompt injection is bounded, not solved.** Structure prevents text from becoming authority. It
  does not prevent a model from being misled about facts.
- **Exactly-once execution is not claimed.** The contract is at-most-one active execution per
  dispatch identity, durable reconciliation, and no blind retry of ambiguous writes.

## Instrument doctrine

Every gate in this platform is expected to obey four rules, learned the expensive way:

1. **A gate emits a count of what it inspected.** A run that inspected nothing is `VACUOUS`, never
   `PASS`.
2. **A control that consumes only its own output tests serialization, not verification.** Feed it
   bytes it did not generate.
3. **State the environment in the verdict.** If the platform, clone depth or filesystem can change
   the answer, say so or refuse.
4. **A gate's suggested remedy must not be able to write a falsehood into the artifact it guards.**

## The LOCAL_GOVERNED operational boundary

The transport ships inert: `QUALIFICATION_ONLY` is a module constant, and absent a deployment
decision nothing spawns. `LOCAL_GOVERNED` is the mode where real executor operation happens, and
it changes what the harness must actually defend — so it gets its own accounting.

**What real operation adds, and what holds it:**

| Added by real execution | What contains it |
|---|---|
| Detached worker processes (`dispatcher → detached worker → claude`) | The worker takes an OS lock first and re-verifies worktree drift immediately before launch; liveness stays provable later without trusting any pid. |
| A child editing real files in per-lane worktrees | One fenced lease per writable worktree, drift re-checked twice (dispatch and pre-launch), commits performed parent-side after evidence is durable — the child never holds history. |
| Independent evidence collection | Snapshot before, measurement after; the child's report travels labelled as a claim beside the measurement, never as the measurement. |
| Bounded review/fix loops | Every committed candidate gets an independent READ_ONLY adversarial review, fix attempts consume a persisted budget, and past the bound the lane escalates rather than ping-ponging. A retry is always a NEW dispatch identity; ambiguous writes are never retried at all. |

**What remains prohibited without an owner grant.** LOCAL_GOVERNED widens exactly one thing —
which executors may run and under which narrow profiles (READ_ONLY, STANDARD_EDIT). Everything
above STANDARD_EDIT — GIT_PUSH, EXTERNAL_WRITE, PAID_EXECUTION, DESTRUCTIVE — stays behind the
signed owner channel no matter what the manifest, the strategist or the executor asks for. The
transport edge refuses them before the authority engine renders its own opinion. There is still
no automatic push, no automatic external write, and no sandbox implied: the native provider has
the host's access, which is precisely why confinement is not claimed for it. The mode itself is a
local file decision, unreachable from any request field, header or tool argument.

**Adapter honesty rule.** When more agent integrations arrive, their assurance levels
(OBSERVED / DIALOGUE / MANAGED / GOVERNED / CONFINED) will be **computed by conformance probes**
— can it cancel? does send/receive round-trip? does argv leak the prompt? does read-only hold? —
never self-declared by the adapter or its vendor. An integration that cannot prove containment
will be recorded as not having it. This is the same doctrine as everywhere else here: a claim
travels labelled as a claim.

**Not yet modelled.** The cloud control surface described in [`PRD.md`](PRD.md) §2 and §13 has no
threat model in this document yet. The split there is **cloud control surface + local execution
runtime**, not a hosted brain: Quaestor Cloud carries identity, tenancy, RBAC, device registry,
policy distribution, approval routing and remote work requests, the selected Orchestrator remains
the strategic intelligence, and **Quaestor Core remains the trusted local effect boundary**. Cloud
cannot bypass local governance or manufacture local owner authority, and a cloud request is an
*untrusted request for a local effect* that Core must validate — identity, org membership,
project authorization, device binding, role, request freshness/replay, local capability policy,
and owner authority where required — before anything happens. The missing revision is the threat
model for exactly that: authenticated outbound device connection, tenant isolation, device
impersonation and replay, and a carried owner approval verified against the expected request,
user, project, nonce, policy and local authority model rather than trusted because it arrived.
It is deliberately gated FIRST, before any cloud code, and is tracked as bd issue
`quaestor-yy9` (deferred). Neither Quaestor Web nor Quaestor Cloud exists in this repository:
until the revision lands, no hosted deployment is described, suggested or implied by anything
here.

## Relay Mode boundaries

Relay Mode ([`RELAY-MODE.md`](RELAY-MODE.md)) is shipped and live-qualified, and it moves the
strategist role into a **selected Orchestrator** and the executor role into a **selected Execution
Agent** the operator started. The doctrine above is unchanged — both are untrusted reasoning
inside a trusted harness, and the relay kernel is the only place authority is decided — but the
surface is different enough to be accounted for on its own.

| Adversary | Defence, and its limit |
|---|---|
| **Another local process on the CDP debug port.** A browser started with `--remote-debugging-port` is drivable by anything running as that user: it can read the conversation, submit turns, and impersonate the Orchestrator to a relay attached to the same page. | **Not defended, and not defensible by Quaestor** — the port is the operator's decision, and Quaestor attaches to it rather than opening it. Mitigate outside the product: a dedicated `--user-data-dir` profile, the port on loopback only, and a machine whose other local processes you already trust. The intended production path (browser extension → native messaging / narrowly authenticated local IPC → Quaestor Core → relay kernel) is [`PRD.md`](PRD.md) §8.2 and **is not built**; CDP is the development/diagnostic adapter being used in its place. |
| **A provider credential passing through Quaestor.** | It does not. The operator signs in once, in their own browser window; Quaestor never launches the browser, never sees the password, and never stores the session. For `openai-chat`, the API key is named by an environment variable or read from a file another tool already wrote, used in one header, and never written to the relay's state, its events or its transcript. The corollary is the previous row: whoever can reach the debug port inherits that authenticated session. |
| **The rendered page as an input surface.** Everything the Orchestrator "says" arrives as a third party's DOM — text, ids, and completion affordances that can change without notice. | Page text is data, never authority: the same rule as repository content. A reply is accepted only if it is the assistant turn following *our* user turn on *our* conversation id, or `receive` refuses with `END_WORKSPACE_MISMATCH` rather than rebinding. Identity comes from the vendor's own message ids where they exist and from a deterministic conversation + turn + content key where they do not, with `provenance.anchored_by` recording which held. A turn already judged incomplete is not accepted later unchanged, so a stream that died mid-token cannot pass a completeness check by going quiet. Where the DOM is only a window onto a virtualised thread, reconciliation **refuses** instead of reading "not rendered" as "not sent". Selector rot is a named failure, not a silent one. |
| **An Orchestrator that asks for authority in prose.** | Prose moves nothing, because it is not the channel. An effect beyond routine editing must arrive as a fenced `quaestor-effect` block naming a modelled class; it is mapped onto capabilities and run through `core.authority.require`, and `OWNER_REQUIRED` becomes an **owner hold** — the relay stops, the directive is recorded and never delivered, and a human is asked on the authenticated owner channel. An effect class this build does not model is refused, not ignored. The profile ceiling (`--profile`, default `STANDARD_EDIT`) is checked once at start, so a `READ_ONLY` relay pointed at an agent that can edit is refused before the first message moves. |
| **An execution agent that does more than it was told.** | Not preventable, and not claimed to be: the agent runs on the host with the operator's permissions, computed assurance is `DIALOGUE`, and confinement is proven for no execution endpoint. What holds is observation after the fact — two independent readings of the repository taken by this process's own git, before and after each turn, never the agent's own `/vcs/status` — and a hold when the difference implies a capability the profile does not carry. Detection, stated as detection. |
| **A secret in a turn that is about to leave the machine.** | Every message crossing the relay, in both directions, goes through `core.classification` first, and the sanitised form is what gets persisted. This is depth, not the boundary: it is a pattern classifier, so a novel secret format will pass. The boundary is that the relay never routes a credential value through prose in the first place. |
| **A crash between the send and the acknowledgement.** | `DELIVERING` is written before the send and `awaiting_message_id` before the wait. On `relay resume` each outstanding delivery is reconciled by *asking the endpoint* whether it already holds the relay-assigned id; an endpoint that cannot answer stops the relay with `UNRECONCILABLE_DELIVERY` rather than choosing silently between duplicating work in somebody's repository and dropping it. A transport error during reconciliation propagates — failing to ask is never recorded as "no". |

**The effect boundary is the owner hold, not the model.** Everything above `STANDARD_EDIT` stays
behind the owner channel in Relay Mode exactly as it does in `LOCAL_GOVERNED`, and no sentence
either model can write reaches it. What Relay Mode adds to the threat surface is a browser the
operator owns and a conversation a vendor renders; what it does not add is a new way to obtain
authority.

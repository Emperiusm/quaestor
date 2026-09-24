# QUAESTOR — PRODUCT REQUIREMENTS DOCUMENT (PRD)

> **Status:** Canonical unified product, architecture, UX, orchestration, governance, reliability, delivery, and data requirements.
>
> **Primary source / precedence:** `QUAESTOR_PLATFORM_AND_DATA_ARCHITECTURE_ORCHESTRATION_REVISED.md` is the newest source and is the normative spine of this PRD.
>
> **Merged sources:** `docs/QUAESTOR_RELAY_ARCHITECTURE.md` and `docs/QUAESTOR_PRODUCT_DIRECTION.md` are incorporated here where their requirements remain valid. Conflicting older product formulations are superseded by the newer platform architecture.
>
> **Canonical rule:** after adoption, this `PRD.md` should be the single planning contract. The source documents may remain as historical/design records, but new implementation planning should not require reconciling three separate product contracts.
>
> **Implementation-status warning:** repository-state and issue-audit statements from older source documents are preserved only where useful and are explicitly marked as historical. Current implementation status must always be re-measured from repository HEAD.

## Executive product statement

> **Any repo. Any supported Orchestrator. Any supported Execution Agent. Any reviewer. One governed loop.**

Quaestor is a professional, model-agnostic orchestration platform.

Its central product contract is:

> **The selected Orchestrator owns strategy.  
> The selected Execution Agent performs implementation work.  
> Quaestor automatically moves work, context, questions, answers, decisions, evidence, and review findings between participants; preserves durable continuity; independently observes effects; and interrupts a human only for genuine ambiguity or human-only authority.**

The broader business product adds durable machine-first Work, multi-user coordination, evidence, decisions, workflow automation, productive metrics, and explicitly consented training-data capture **only where those capabilities strengthen the orchestration loop**.

The external experience should remain:

> **Easy on the outside. Paranoid on the inside.**

And the integration philosophy is:

> **Rich orchestration internally; the smallest possible integration contract externally.**

---
# 1. PRODUCT DIRECTION

Quaestor should become a **professional model-agnostic orchestration platform** built around a local-first security boundary and a cloud-first business experience.

Its primary purpose is:

> **Turn goals into durable machine-manageable work, coordinate AI agents and humans across projects and tools, govern consequential actions, verify outcomes, and preserve the resulting organizational knowledge.**

Everything else in the product should exist because it materially improves one or more of:

```text
orchestration
continuity
supervision
coordination
verification
reuse
organizational memory
measured productivity
training-data quality
```

Quaestor should support:

```text
multi-user authentication
organizations / teams
multiple devices
multiple projects / repositories
shared machine-first Work
agent assignment
organization-wide Fleet visibility
remote status and approvals
browser / API / CLI Orchestrators
headless Execution Agents
workflow triggers
reusable workflows
decision / evidence capture
cloud account management
explicit operational-content sync policy
explicit data contribution
training-data provenance
multimodal trajectory collection
```

The main business product should be accessible through:

```text
app.quaestor.ai
```

while actual repository access, terminal/process control, provider secrets, and Execution Agent activity remain on the user's authorized machines through Quaestor Core.

The user-facing product should answer:

> **What are we trying to accomplish, what work exists, who or what is doing it, what is blocked, what changed, what evidence exists, and what needs human authority?**

Quaestor sits at a valuable observation point between:

```text
business / human goal
       ↓
durable Work Graph
       ↓
Orchestrator
       ↓
Execution Agent / Employee / Tool
       ↓
real systems and environments
       ↓
evidence / decisions / review
       ↓
verified outcome
```

With explicit user permission, this can produce high-quality business-workflow training trajectories containing:

```text
intent
work decomposition
organizational roles
handoffs
reasoned instructions
agent actions
tool usage
code / document / system changes
visual state
decisions
approvals
verification
criticism
revision
human interventions
business outcomes
```

The strategic goal is therefore:

> **Quaestor orchestrates real AI-assisted work, executes privileged activity locally, gives users and businesses one pane of glass across projects and devices, and optionally converts consented verified workflows into provenance-rich multimodal training data.**

---

# 2. CORE ARCHITECTURAL PRINCIPLE

Do not turn Quaestor into a cloud-hosted coding agent.

The product should use a **cloud control surface + local execution runtime**.

```text
                              USER
                               │
                               ▼
                    ┌─────────────────────┐
                    │   QUAESTOR WEB      │
                    │  app.quaestor.ai    │
                    │                     │
                    │ Fleet / Work        │
                    │ Projects / Tabs     │
                    │ Inputs / Outputs    │
                    │ Approvals           │
                    │ Agents / Devices    │
                    │ Evidence / Changes  │
                    │ Team / Settings     │
                    │ Data / Privacy      │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   QUAESTOR CLOUD    │
                    │                     │
                    │ Auth / Tenancy      │
                    │ RBAC / Policies     │
                    │ Work Sync           │
                    │ Device Registry     │
                    │ Notifications       │
                    │ Product Sync        │
                    │ Dataset Ingestion   │
                    │ Billing             │
                    └─────────┬───────────┘
                              │
                    authenticated outbound
                       device connection
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │ Quaestor Core│ │ Quaestor Core│ │ Quaestor Core│
      │ Alice PC     │ │ Bob Laptop   │ │ Build Server │
      └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
             │                │                │
      Relay / Governance / Evidence / Secrets / Repo
             │                │                │
             ▼                ▼                ▼
        Agents + Repos    Agents + Repos   Agents + Repos
```

For browser-hosted Orchestrators:

```text
ChatGPT Web
     ↕
Quaestor Browser Extension
     ↕
Native Messaging / authenticated local IPC
     ↕
Quaestor Core
     ↕
Relay Kernel
```

The architectural boundary is:

```text
Quaestor Web / Cloud:
identity
tenancy
team / RBAC
Fleet and Work views
device registry
policy distribution
remote work requests
approval routing
notification delivery
selected operational synchronization
dataset ingestion
billing

Quaestor Core:
repository access
terminal/process access
Execution Agent control
local Orchestrator/agent endpoints
provider secrets
governance enforcement
authority validation
raw Relay state
raw tool output
repo observation
evidence acquisition
local filtering
offline/recovery controls
```

The selected Orchestrator remains the strategic intelligence.

The selected Execution Agent performs implementation.

Quaestor Core remains the **trusted local effect boundary**.

Quaestor Cloud coordinates users, teams, devices, and shared product state, but cannot directly bypass local governance or manufacture local owner authority.

---

# 3. QUAESTOR CORE

The foundational desktop component should be called:

> **Quaestor Core**

It should be a lightweight local per-user service, not a heavyweight desktop application.

Conceptually:

```bash
quaestor serve
```

or automatically:

```bash
quaestor relay start ...
```

Quaestor Core may remain active while Relay sessions are running and may optionally remain idle for status, recovery, and remote-owner functions.

It should behave like a lightweight per-user daemon or language-server-style runtime rather than a conventional desktop application. It may be started explicitly by `quaestor serve`, started on demand by Relay/UI clients, or configured to start at login where the user wants persistent remote-owner/status functionality.

Core lifecycle must not depend on Chrome, VS Code, Cursor, JetBrains, or any other UI client remaining open.

When there is no active Relay, pending delivery, owner hold, recovery obligation, contribution upload, or enabled remote-control channel, Core may shut down after a configurable idle period instead of remaining resident indefinitely.

## 3.1 Design requirements

Quaestor Core should be:

```text
headless
per-user
non-admin
editor-independent
browser-independent
low-idle-CPU
modest-memory
cross-platform where practical
locally authenticated
recoverable after restart
```

Do not require:

```text
Electron
embedded Chromium
a visible terminal
VS Code
Chrome
a cloud connection for ordinary local Relay work
```

The current Python implementation is sufficient as the initial Core runtime.

Do not rewrite the platform in another language solely to create a daemon.

---

# 4. EXECUTION AGENTS SHOULD BE HEADLESS WHERE POSSIBLE

Quaestor should prefer machine-controllable agent interfaces in this order:

```text
1. Native local API
2. Provider/session API
3. Headless CLI subprocess
4. PTY-backed CLI
5. Existing-session attachment
6. Command/file/clipboard fallback
```

Examples:

```text
Quaestor Core
    │
    ├── OpenCode local HTTP/session API
    ├── Claude Code headless process or PTY
    ├── Codex CLI / resumable session
    ├── Gemini CLI
    ├── local model runtime
    └── future coding agents
```

Users should not need visible terminal windows for normal execution.

## 4.1 PTY support

Some CLIs behave differently when attached to a terminal.

Quaestor may create a pseudo-terminal internally without exposing a visible window.

This allows:

```text
interactive CLI semantics
terminal detection
streaming output
session control
```

while preserving a clean user experience.

## 4.2 Existing sessions

Quaestor may attach to an already-running execution-agent session where supported.

Capability and assurance remain separate.

For example:

```text
Externally running Claude Code

can mutate repository: YES
Quaestor manages lifecycle: NO
session identity proven: MAYBE
confinement proven: NO
```

This remains useful at an honestly lower assurance level.

---

# 5. PRODUCT MODES — RELAY MODE AND PROGRAM MODE

Quaestor has two complementary orchestration products.

## 5.1 Relay Mode — low-friction persistent orchestration

Relay Mode is the flagship no-copy/paste experience:

```text
Selected Orchestrator
        ↕
persistent conversation
        ↕
Quaestor Relay Kernel
        ↕
persistent conversation
        ↕
Selected Execution Agent
        ↕
real project / systems
```

Characteristics:

```text
conversation-first
natural multi-turn dialogue
selected Orchestrator owns strategy
persistent or existing Execution Agent session where possible
minimal setup
independent observation/evidence
honest lower-assurance integrations allowed
human interrupted only for genuine ambiguity or authority
```

Relay Mode must **not** be forced through Program Mode or a one-turn `Executor.execute()` abstraction.

## 5.2 Program Mode — higher-assurance state-machine orchestration

Program Mode remains a first-class product.

Characteristics:

```text
state-machine-first
programs / lanes / seats
bounded executor runs
explicit planner / strategist proposals
worktrees and leases
provider routing / failover
independent reviewers
strong deterministic recovery
stronger confinement options
multi-lane execution
```

Program Mode is not obsolete and should not be deleted to simplify Relay.

Over time Program Mode may reuse Relay transport or endpoint primitives where appropriate, but neither mode should be distorted merely to eliminate architectural separation.

## 5.3 Shared substrate

Both modes should reuse the same hardened primitives where possible:

```text
authority
owner capability
provider identity / provenance
evidence
repository observation
classification / redaction
decisions
Work
assurance
reconciliation
context capsules
audit/event identity
```

The user should choose a product behavior, not be forced to understand the internal composition.

# 6. NON-NEGOTIABLE ARCHITECTURE PRINCIPLES

These rules apply across Relay Mode, Program Mode, cloud surfaces, adapters, Workflows, and future business integrations.

1. **The selected Orchestrator owns strategy.**
2. **The selected Execution Agent owns implementation work.**
3. **Quaestor owns transport, continuity, durable Work, governance, evidence, and effect enforcement.**
4. **OWNER remains human-only.** No model, prompt, file, browser message, cloud request, or provider can mint owner authority.
5. **No transport grants authority.**
6. **No executor grants itself authority.**
7. **No reviewer grants itself authority or approves its own work.**
8. **No reviewer substitutes for deterministic or independently measured evidence.**
9. **No model grades its own homework where independent review is required.**
10. **No model/provider is the architecture.**
11. **Any role may be held by any currently supported, capable, authenticated, policy-admitted provider.**
12. **Provider independence is based on the model/vendor that actually answered, not merely the gateway or proxy.**
13. **Normal engineering/business dialogue remains natural dialogue.** Structured schemas are required at governed machine boundaries, not every sentence.
14. **Gate the act, not the sentence.**
15. **Agent output is a claim. Independently observed system/repository state is ground truth.**
16. **Capability and assurance are separate.** Weak proof lowers assurance; it does not erase real capability.
17. **No native adapter is required for basic participation.**
18. **More integration may earn more automation and stronger claims; weak integrations remain useful when represented honestly.**
19. **The external adapter contract remains simpler than Quaestor's internal orchestration model.**
20. **No ambiguous write is blindly retried or failed over to another provider.**
21. **No concurrency without ownership.**
22. **No silent stall counts as progress.**
23. **No partial or truncated output counts as complete without completion evidence.**
24. **A model response completes an attempt; only the control plane completes governed Work/program state.**
25. **No recursive automation path is unbounded.** Bound agent-to-agent rounds, review/fix cycles, provider fallback, task expansion, and causal hops.
26. **Adapter assurance is measured by probes; an adapter cannot declare its own assurance.**
27. **Project authorization is explicit.** A browser tab, cloud account, or agent process never implies access to every local project.
28. **Cloud identity is not local machine authority.**
29. **Product synchronization is not training consent.**
30. **No operational customer data enters training without explicit applicable consent.**
31. **Quaestor should adapt to the user's existing agent before requiring the agent to learn Quaestor internals.**
32. **The user-facing product stays simple because complexity is handled correctly underneath—not because safety or correctness were removed.**

# 7. ROLE × PROVIDER MATRIX AND REVIEW INDEPENDENCE

Quaestor roles are assignable functions, not vendor features.

## 7.1 Program / governed roles

Program Mode may include:

```text
PLANNER / STRATEGIST
IMPLEMENTATION / BUILDER
VERIFICATION
ADVERSARIAL_REVIEW
INTEGRATION
OWNER — always human
```

The target is a provider-neutral matrix such as:

```text
Planner: GPT
Builder: Claude
Verifier: Gemini
Reviewer: Codex
```

Every run should persist enough provenance to establish:

```text
role
provider
provider_family
model
run/session identity
evidence references
context-independence facts
provider-independence facts
```

## 7.2 Pairing policy

For sensitive work, policy constrains role **pairings**, not merely individual roles.

Example:

```text
implementation.provider_family != adversarial_review.provider_family
```

Provider failover must respect those constraints before admission.

A fallback that would violate a required provider-family separation must be refused rather than silently weakening review independence.

## 7.3 Reconciliation-aware failover

Provider chains may be supported:

```text
preferred provider
    ↓ unavailable
fallback provider
```

But failover is only safe when the previous attempt is known not to have produced ambiguous effects.

```text
BEFORE EFFECTS                    → safe to fail over
MEASURED UNCHANGED ENVIRONMENT    → may be safe to fail over
POSSIBLE / AMBIGUOUS WRITE        → never blindly fail over
```

"Try the next model" must not become disguised duplicate execution.

## 7.4 Planner / Orchestrator is still governed

A planner may propose:

```text
tasks
dependencies
acceptance criteria
priority
replan
```

A proposal remains **data** until admitted by Quaestor's deterministic rules and relevant human/policy authority.

The planner does not receive a capability lattice merely because it is strategically important.

For Relay Mode, the selected Orchestrator owns the strategic conversation, but governed effects still pass through Quaestor.

## 7.5 Provider capability registry

A provider/model registry should support measured or declared facts such as:

```text
provider_family
credential_mode
context_window
vision
web_access
code_execution
local_or_remote
privacy_class
capabilities
latency_class
cost_class
health
quota_state
```

Role/endpoint resolution should use those facts plus policy.

Registry presence is **not** proof that the provider is buildable, authenticated, admitted, or live-qualified.

## 7.6 Structural review independence

Independent reviewers should receive bounded review packets containing only the context needed to review:

```text
objective
constraints
acceptance criteria
candidate/diff/artifact reference
independent evidence
relevant recorded decisions
```

They should not receive the implementer's private reasoning transcript by default.

Reviewer authority remains read-only unless a separately defined workflow explicitly creates a new implementation task.

Review targets may include:

```text
PLAN
CODE
INTEGRATION
RELEASE
SECURITY
BUSINESS WORKFLOW
```

Cross-vendor diversity strengthens review but never replaces deterministic evidence or structural isolation.

For high-risk work, multiple independent reviewers may be used, with disagreements becoming durable Work or an owner/strategist decision rather than being averaged away.

# 8. RELAY RUNTIME CONTRACT

Relay Mode is a first-class persistent runtime.

## 8.1 Endpoint abstractions

Do not stretch Program Mode's one-turn Executor abstraction until it becomes Relay.

Use persistent relay-facing contracts conceptually equivalent to:

```python
class OrchestratorEnd:
    async def send(self, message): ...
    async def receive(self): ...
    async def status(self): ...
    async def conversation_identity(self): ...
    async def resume(self, identity): ...

class ExecutionEnd:
    async def send(self, message): ...
    async def receive(self): ...
    async def status(self): ...
    async def session_identity(self): ...
    async def resume(self, identity): ...
```

Exact APIs may change.

The architectural separation must remain.

Potential `OrchestratorEnd` implementations:

```text
ChatGPT Web
OpenAI / OpenRouter / compatible API
Claude
Gemini
Codex
provider CLIs
local models
future browser-hosted surfaces
```

Potential `ExecutionEnd` implementations:

```text
OpenCode live session
Claude Code live/resumable session
Codex live/resumable session
managed Quaestor-launched agents
command bridge
file inbox/outbox
human/manual bridge
future coding/business agents
```

## 8.2 Browser-hosted Orchestrator requirements

For ChatGPT Web and similar browser-hosted Orchestrators, preserve the stronger browser adapter requirements established by the Relay architecture:

```text
operator authenticates in the provider's own browser
Quaestor does not handle the provider password
durable conversation identity where available
fresh-reply detection
stale-reply rejection
completion detection
partial streaming output never forwarded as complete
named timeout/disconnect states
signed-out state handled explicitly
provider challenge / interstitial state handled explicitly
no blind retry through uncertain authentication/challenge states
selectors / browser affordances centralized where possible
```

Production browser support should prefer:

```text
Browser Extension
    → Native Messaging / narrowly authenticated local IPC
    → Quaestor Core
    → Relay Kernel
```

Development/diagnostic adapters may use:

```text
CDP
Playwright
other browser automation
```

but broad remote-debugging/browser-automation access should not become the default public trust contract merely because it was convenient for development.

A browser-hosted provider is `PRODUCT_SUPPORTED` only after a real authenticated browser + real provider conversation + real Relay + real Execution Agent + real project path is live-qualified.

## 8.3 API, gateway, CLI, and local Orchestrators

API/gateway Orchestrators do not require the browser extension.

Provider CLI or local-model Orchestrators may also hold the Orchestrator role when they expose sufficient conversation identity/continuity for the claims being made.

Do not hard-code browser assumptions into the Relay Kernel.

## 8.4 Relay product CLI and diagnostics

A minimum expert/headless control surface should support the equivalent of:

```bash
quaestor relay start --orchestrator <auto|provider> --agent <auto|agent> --project .
quaestor relay status
quaestor relay doctor
quaestor relay stop
```

Where supported, useful additional operations include:

```bash
quaestor relay resume
quaestor relay probe
quaestor relay last-orchestrator
quaestor relay last-agent
```

The Web product may become the primary UI, but the CLI remains important for diagnostics, automation, qualification, CI/headless environments, and local recovery.

## 8.5 Core Relay loop

Conceptually:

```text
Execution produces new completed output
        ↓
Quaestor validates identity / freshness / completion
        ↓
bounded packet → Orchestrator
        ↓
Orchestrator produces new completed response
        ↓
Quaestor evaluates governed effect boundary
        ↓
ordinary instruction → Execution Agent
owner-only effect    → owner hold
        ↓
independent observation / evidence
        ↓
next exchange
```

The Relay Kernel owns:

```text
exchange identity
message identity
deduplication
causal linkage
bounded context
redaction
completion checks
state persistence
recovery
owner holds
repo/system observation
evidence linkage
```

It does **not** own strategic intelligence.

## 8.3 Natural dialogue

Normal traffic may remain plain prose.

Example:

```text
The failure suggests the migration code is wrong.
Inspect the migration and failing test.
Do not change the schema yet.
Show me the relevant diff and diagnosis.
```

Structured envelopes remain appropriate for:

```text
owner approval
capability escalation
plan adoption
destructive effect
provider identity/provenance
machine completion marker
durable decision
evidence record
```

Do not turn every conversational sentence into a directive schema.

# 9. MESSAGE IDENTITY, DELIVERY, CONTEXT, AND RECOVERY

## 9.1 Durable message identity

Track at minimum:

```text
exchange_id
message_id
direction
orchestrator_conversation_id
execution_session_id
content_digest
causal_parent
sequence where required
observed_at
delivered_at
completion_state
```

For adapter/mailbox delivery, additionally support as needed:

```text
sender
recipient_role
nonce
expires_at / TTL
delivery_state
ack_cursor
hop_count
```

## 9.2 Mailbox is not canonical state

A durable adapter mailbox may spool and replay transport messages after disconnect/restart.

But:

```text
mailbox traffic = delivery state
canonical Work / Decision / Evidence / policy state = durable control-plane state
```

Canonical state must never live only in an inbox/outbox.

## 9.3 Loop protection

Stop, pause, or escalate on:

```text
identical Orchestrator reply loop
identical Execution Agent output loop
stale message replay
no-progress timeout
max exchange / causal-hop budget
max run duration
owner hold
endpoint disconnect
repeated operational failure
```

A restart must not make already-delivered traffic look new.

## 9.4 Bounded context handoff

Do not replay full transcripts by default.

Execution → Orchestrator packets may include:

```text
project identity
Work / Goal identity
execution session
latest completed response
relevant repo/system observation
evidence summary
known blockers
open owner hold
bounded Context Capsule
```

Orchestrator → Execution traffic may remain natural prose with a small machine envelope for identity, Work, project, and policy binding.

## 9.5 Existing-session Execution Agents

A primary Relay path is:

```text
user already has an agent working in the project
        ↓
Quaestor attaches to that exact session
        ↓
Orchestrator directs it automatically
```

Detection alone is not attachment.

A live/resumable adapter must prove, where claimed:

```text
1. correct project/workspace identity
2. correct live/resumable session identity
3. receive a NEW completed turn without replaying stale output
4. deliver the next instruction into the SAME execution context
```

If an adapter cannot prove one of those properties, its assurance/facts must say so.

## 9.6 Restart / recovery

Persist enough state to reconstruct:

```text
project
Work / Goal
Orchestrator provider/model
Orchestrator conversation identity
Execution adapter/session
last observed message identities
last delivered message identities
exchange number
owner hold
start / last activity
stop reason
relevant evidence/repo observation cursor
```

After Core/Relay restart:

```text
recover same project
resume same Orchestrator conversation where supported
resume same Execution session where supported
do not duplicate already-delivered turns
reconcile uncertain delivery instead of blindly repeating
```

Unsupported resume behavior must be reported honestly.

## 9.7 Human-readable status

Status should answer without requiring database inspection:

```text
Relay state
project
current Work
Orchestrator / model
conversation identity
Execution Agent
execution session
exchange
last direction
last activity
repo/system changed?
owner hold?
integration assurance?
blocker / stop reason?
```

# 10. UNIVERSAL AGENT-END — MINIMAL EXTERNAL CONTRACT, RICH INTERNAL MODEL

A new agent should be useful with Quaestor without modifying Quaestor Core or learning Quaestor's entire internal vocabulary.

## 10.1 Minimum useful adapter

Conceptually:

```text
send(message)
receive(message)
```

Optional capabilities may include:

```text
start
stop
pause
resume
status
structured_output
tool_events
usage
workspace_identity
session_identity
cancellation
```

Quaestor adapts its claims and policy to what the adapter actually exposes.

## 10.2 Progressive integration tiers

### Tier 0 — OBSERVED

Quaestor watches:

```text
transcript
terminal/log output
repository/system change
IDE chat log
file tail
```

It may still run independent verification/review.

It cannot claim to drive the agent.

### Tier 1 — DIALOGUE

Quaestor can send and receive information but does not own lifecycle.

Possible transports:

```text
file inbox/outbox
stdin/stdout
command wrapper
HTTP
WebSocket
MCP
ACP
IDE extension
clipboard
```

### Tier 2 — MANAGED

Quaestor controls lifecycle:

```text
start
stop
pause
resume
status
timeout
```

### Tier 3 — GOVERNED

Quaestor additionally controls or proves relevant execution facts:

```text
workspace identity
capability surface
authority profile
tool availability
write boundaries
independent evidence
cancellation semantics
```

### Tier 4 — CONFINED

Quaestor additionally proves an external containment boundary:

```text
sandbox/container
bounded filesystem
bounded network
no uncontrolled host access
```

A stronger integration earns stronger claims.

A weaker integration remains useful.

## 10.3 Capability is separate from assurance

Track independent facts such as:

```text
can_send
can_receive
can_observe
can_mutate_repo/system
manages_lifecycle
supports_session_resume
proves_workspace_identity
proves_capability_surface
proves_readonly_behavior
proves_confinement
```

Then compute assurance from measured evidence.

Keep the ladder:

```text
OBSERVED < DIALOGUE < MANAGED < GOVERNED < CONFINED
```

An external IDE agent may genuinely mutate a repository while Quaestor remains unable to prove confinement.

Do not collapse those two facts.

## 10.4 Weak integration can still yield strong evidence

Even when the agent is opaque:

```text
agent claims "I changed four files"
        ↓
Quaestor independently measures Git / filesystem / external system
        ↓
verification
        ↓
independent review
```

Universal adapters therefore remain useful even at lower assurance.

## 10.5 Adapters are asymmetric

Ask:

> **What is the least this participant must expose for Quaestor to use it safely and honestly?**

Do not require every adapter to expose identical lifecycle, workspace, or confinement controls.

## 10.6 File inbox/outbox reference transport

A reference universal protocol may use:

```text
.quaestor/
  inbox/
  outbox/
```

with envelopes containing:

```text
task_id
message_id
nonce
created_at
expected_response_type
completion_marker
artifact_refs
payload
```

Important invariant:

```text
file contents != authority
```

## 10.7 Transcript-only mode is a product capability

Observe-only adoption can provide:

```text
independent review
repository verification
progress detection
cross-vendor critique
completion validation
human alerts
```

without actively controlling the user's agent.

This creates an adoption path:

```text
observe
→ review
→ dialogue
→ managed
→ governed / confined
```

## 10.8 Rich internal protocol

Quaestor may normalize weak text transports into richer internal event types such as:

```text
DECISION_REQUEST
CLARIFICATION_REQUEST
AUTHORITY_REQUEST
BLOCKER
OBSERVATION
PLAN_REVISION
REVIEW_FINDING
RESULT
OWNER_ESCALATION
```

Simple adapters do not need to implement those types natively.

## 10.9 Prompt transport and ambient context

Assurance should measure dimensions such as:

```text
PROMPT_TRANSPORT
  STDIN | PIPE | TEMP_FILE | IPC | ARGV

AMBIENT_CONTEXT
  CLEAN | USER_ONLY | PROJECT | UNCONTROLLED
```

Prefer mechanisms that do not unnecessarily expose prompts through process listings.

Independent reviewers should default toward a clean context so they do not silently inherit builder hooks/plugins/MCP servers/project automation.

These facts should be measured by conformance probes, not self-declared.

## 10.10 Normalized adapter events

Vendor-specific adapter behavior should normalize into a stable internal/control-plane vocabulary such as:

```text
AGENT_CONNECTED
AGENT_STARTED
MESSAGE_SENT
MESSAGE_RECEIVED
QUESTION_RAISED
TASK_COMPLETE
BLOCKED
CANDIDATE_CHANGED
AGENT_STOPPED
```

The exact event names may evolve, but the Cloud/Web product should not need vendor-specific logic for every IDE or coding agent.

The messy integration remains local; Quaestor's durable event model remains stable.

## 10.11 Conformance probes measure assurance

Adapters must not self-award `MANAGED`, `GOVERNED`, or `CONFINED`.

Probes should measure relevant properties, for example:

```text
does send/receive round-trip?
can Quaestor identify the same resumed session?
can Quaestor cancel/stop it?
does READ_ONLY actually remain read-only?
is workspace identity provable?
does prompt transport leak via argv/process listing?
what ambient hooks/plugins/MCP servers are inherited?
does reconnect replay duplicate messages?
```

Assurance derives from measured facts.

## 10.12 Agent-native bootstrap

Where useful, Quaestor may expose machine-readable bootstrap/discovery material so an unfamiliar agent can help connect itself without a custom core patch.

Possible surfaces include:

```text
llms.txt
.well-known/quaestor-agent.json
a bundled Quaestor skill/instruction package
local discovery endpoint
```

These mechanisms advertise integration capability; they do not grant authority.

## 10.13 Native integrations are enhancements, not gatekeepers

```text
more integration
    =
more automation
+ stronger lifecycle control
+ stronger evidence
+ stronger security claims
```

Never:

```text
no native adapter
    =
cannot use Quaestor
```

---

# 11. USER EXPERIENCE PRINCIPLE — AI WORK MANAGER

Quaestor should not present itself primarily as an orchestrator dashboard.

The user-facing product should feel like an **AI work manager**.

The default mental model should be:

> **Here are my projects. Here is what the agents are doing. Here is what needs my attention. Here is what changed.**

Not:

> Here are my Relay endpoints, execution sessions, provider capabilities, transport details, terminal streams, and event IDs.

Those lower-level concepts remain important to the implementation and should be available in advanced/debug views, but ordinary users should work in terms of:

```text
Projects
Goals
Work
Progress
Changes
Evidence
Approvals
Agents
```

The primary user-facing object is **Work**, not Conversation.

Relay conversations are the mechanism that moves work forward.

The intended first-run experience should remain simple:

```text
Install Quaestor Core
      ↓
Sign in to Quaestor Web
      ↓
Enroll device
      ↓
Authorize or open project
      ↓
Choose Orchestrator
      ↓
Choose Execution Agent
      ↓
State the goal
      ↓
Start
```

If the user participates in the data program, contribution choices are a separate explicit step rather than part of ordinary Relay startup.

Ordinary users should not need to understand:

```text
MCP
CDP
PTY
socket ports
transcript paths
event ledgers
provider registries
lane IDs
seat IDs
worktrees
native messaging manifests
```

Those are implementation details.

---

# 12. USER INTERFACE ARCHITECTURE

Quaestor should have one primary product interface and several specialized clients.

```text
                      PRIMARY PRODUCT
                  ┌────────────────────┐
                  │   QUAESTOR WEB     │
                  │ app.quaestor.ai    │
                  └─────────┬──────────┘
                            │
                      Quaestor Cloud
                            │
             authenticated device channels
                            │
                            ▼
                    ┌──────────────┐
                    │ Quaestor Core│
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
 Browser Extension        CLI          Local Core Console
 contextual bridge     expert/headless     fallback/admin

                    optional thin tray
```

Business logic and privileged effect enforcement remain in Core and Cloud services according to their trust boundaries.

UI clients must not become alternate execution engines.

## 12.1 Interface responsibilities

| Interface | Primary responsibility |
|---|---|
| **Quaestor Web** | **Primary business/product UI:** Fleet, multi-project tabs, Work, input/output, approvals, agents/devices, changes, evidence, team, privacy, settings |
| **Local Core Console** | Offline/bootstrap/recovery/diagnostics for the current machine |
| **Browser Extension** | Browser-hosted Orchestrator transport plus compact contextual controls |
| **CLI** | Automation, scripting, diagnostics, CI/headless workflows, advanced control |
| **Tray / App Shell** | Optional launcher, device status, notifications, quick pause/stop/open controls |
| **Responsive/PWA Web** | Mobile and tablet view of the same cloud product |

None should contain a second implementation of Relay, governance, project authorization, Work state, or training-data policy.

The Browser Extension must not become the primary administration UI merely because ChatGPT Web is an important Orchestrator.

Quaestor must remain coherent in browser-free topologies such as:

```text
Claude API → Quaestor Core → Codex CLI
```

## 12.2 No mandatory Electron application

Do not require Electron simply to provide the main UI.

Quaestor Core already owns the native capabilities Electron would otherwise be used to obtain:

```text
filesystem
processes
PTY
secrets
repo access
agent management
notifications / local integration
```

Embedding a second Chromium runtime would add installer size, memory use, browser patch burden, and packaging complexity without becoming the trusted execution boundary.

If a native desktop shell becomes useful later, it should wrap or reuse the same web product rather than become a separate application implementation.

---

# 13. PRIMARY UI — QUAESTOR WEB

The canonical business interface should be:

```text
https://app.quaestor.ai
```

Quaestor Web should be the primary place users:

```text
view all projects
open persistent project tabs
create and manage Work
send goals / instructions
observe Relay progress
review agent output
inspect changes and evidence
approve owner-level requests
manage Agents and Devices
manage teams and roles
configure project/global settings
manage product-sync and contribution policies
```

This is more useful for organizations than a localhost-only application because one user may need to oversee work executing across many authorized devices and repositories.

Example:

```text
Organization: ACME GAMES

12 Projects
7 Active Relays
14 Agents
3 Owner Requests
41 Ready Work Items

Atlas
Alice-Workstation
● Claude → OpenCode
AT-442 Modular Character Pipeline

Harbor Point
Bob-Laptop
⚠ Approval Required
HP-812 Asset Import

Backend
Build-07
✓ Codex completed BE-119
```

## 13.1 Remote command flow

The website may initiate ordinary product actions, but it does not execute them.

Conceptually:

```text
Quaestor Web
      ↓
Quaestor Cloud
      ↓ authenticated / authorized work request
Quaestor Core
      ↓ local policy + authority validation
Relay / Work / Agent
```

A cloud request is still an **untrusted request for a local effect**.

Quaestor Core must validate:

```text
user identity
organization membership
project authorization
device binding
role / permission
request freshness / replay protection
local capability policy
owner authority where required
```

The cloud may carry an owner approval, but Core must verify that approval against the expected request, user, project, nonce/identity, policy, and local authority model before the effect occurs.

## 13.2 Offline behavior

If a device is offline:

```text
show it as offline
show last known status with timestamp
do not pretend Relay is still executing
```

The product may optionally queue safe Work requests for later delivery, but queued work must be visible and must not be represented as running before Core accepts it.

## 13.3 Local Core Console

Quaestor Core should still expose a minimal authenticated localhost recovery/admin UI.

Example:

```text
http://127.0.0.1:<port>/
```

Its purpose is:

```text
Core status
cloud connection status
local authorized projects
local agent health
active Relay status
emergency pause / stop
diagnostics
logs
device enrollment / reconnect
offline operation / recovery
```

Example:

```text
QUAESTOR CORE

Device
● Running

Cloud
× Disconnected

Projects
5 authorized

Relay
Atlas ● Running

Agents
OpenCode ●
Claude Code ●

[ Diagnostics ]
[ Stop Relay ]
[ Reconnect ]
```

The Local Core Console is **not** the primary organization-wide product UI.

It exists so cloud or network failure never removes control of local execution.

## 13.4 Optional native shell

If a desktop application is desired later:

```text
Native shell / WebView
        ↓
same Quaestor Web UI or shared UI components
        ↓
Quaestor Core
```

Do not maintain separate “Quaestor Desktop” and “Quaestor Web” products with divergent workflows.

---

# 14. TWO PRIMARY WORKSPACES: FLEET AND PROJECT

Quaestor Web should have two fundamental working levels.

## 14.1 Fleet / Home

Fleet is the default organization-wide view across every project and authorized device the user may see.

It should answer within seconds:

```text
What is running?
Who or what is running it?
On which device?
What is finished?
What is blocked?
What failed?
What needs me?
What work is ready?
```

Example:

```text
QUAESTOR — ACME GAMES

5 Projects     3 Running     1 Needs You     2 Completed

NEEDS YOUR ATTENTION
────────────────────────────────────────────────────────
Atlas · Alice-Workstation
⚠ Git Push approval
Tests 418/418 · Review approved
                                      [ Review ]

RUNNING
────────────────────────────────────────────────────────
Quaestor · Build-PC
● ChatGPT → OpenCode
Q-287 Implementing Core service
Exchange 14 · tests passing

Harbor Point · Bob-Laptop
● Claude → Codex
HP-184 Asset import pipeline
23 min

READY
────────────────────────────────────────────────────────
Website
7 ready Work items

Training Pipeline
3 ready Work items
```

Fleet should aggregate:

```text
active Relay sessions
ready Work
blocked Work
owner approvals
failed verification
completed Work
agents online/offline
devices online/offline
project health
```

It should not be an aggregate raw-transcript viewer.

## 14.2 Persistent Project Tabs

Users managing several repositories simultaneously should be able to keep projects open as persistent application tabs.

Example:

```text
[ Fleet ] [ Quaestor ● ] [ Atlas ⚠ ] [ Harbor Point ● ] [ + ]
```

Status should be visible directly on the tab:

```text
● running
⚠ owner attention
✓ completed
× failed
○ idle
```

A project tab may represent a repository on the current machine, another enrolled workstation, or another authorized team member's device.

Open tabs and selected project should survive UI refresh where practical.

These tabs are a UX construct, not an execution boundary.

---

# 15. PROJECT WORKSPACE

A project workspace should use a small stable navigation model:

```text
Overview | Work | Agent | Changes | Evidence | Activity | Settings
```

Do not create a large number of competing project pages.

## 15.1 Project Overview — the cockpit

Example:

```text
Atlas                                      Relay ● RUNNING

Current Goal
────────────────────────────────────────────────────────
Implement modular character asset pipeline

Orchestrator                         Execution Agent
Claude                               OpenCode
● Connected                         ● Working

Current Work
────────────────────────────────────────────────────────
AEG-241  Implement modular retarget stage          ●
AEG-242  Validate Unreal import                    ○ blocked
AEG-243  Generate female fixture                   ○ ready

Progress
████████████████░░░░ 72%

Latest
────────────────────────────────────────────────────────
Agent       Modified retarget.py
Agent       Ran 18 tests — 16 passed, 2 failed
Claude      Requested socket mismatch investigation
Agent       Working...

Repository
7 files changed · +182 / -41

Verification
16 / 18 passing

Owner Attention
None

[ Message ] [ Pause ] [ Review Changes ]
```

The Overview should summarize current objective, Work state, participants, repo effects, verification, and owner attention.

The transcript should be available, but it should not dominate this screen.

---

# 16. INPUT / OUTPUT — GOAL FIRST, CHAT SECOND

Quaestor absolutely needs natural-language input/output.

However, a large ChatGPT-style transcript should not be the primary product surface.

Chat works well for one model and one conversation.

It becomes difficult to manage when the user has:

```text
multiple repositories
multiple users
multiple devices
multiple agents
multiple issues
multiple reviews
blocked tasks
simultaneous Relay sessions
```

The primary composer should therefore ask:

> **What do you want done?**

Example:

```text
┌──────────────────────────────────────────────────────────┐
│ What do you want done?                                  │
│                                                          │
│ Audit the character asset pipeline and fix the highest- │
│ priority issue blocking modular outfit generation.      │
├──────────────────────────────────────────────────────────┤
│ Run ▾                    Claude → OpenCode       [ Start ]│
└──────────────────────────────────────────────────────────┘
```

When sent from Quaestor Web:

```text
Web input
   ↓
authenticated cloud request
   ↓
authorized target device / project
   ↓
Quaestor Core validation
   ↓
durable Work / Relay
```

The website should make the target project, target device, and effective execution configuration obvious before starting work.

## 16.1 Human-friendly modes

Expose a simple default mode selector:

```text
Ask
Plan
Run
Review
```

Meaning:

### Ask

Investigate and answer.

No repository mutation.

### Plan

Investigate and produce a plan.

No implementation unless explicitly promoted.

### Run

Execute the objective under the project's configured permissions.

### Review

Independently inspect existing work and report findings.

Advanced users may expose:

```text
Orchestrator
Execution Agent
Reviewer
Autonomy
Permissions
Context
Transport
Assurance
```

These should not clutter the ordinary composer.

## 16.2 Output hierarchy

Default output should emphasize:

```text
current Work
progress
meaningful activity
changes
verification
review
owner requests
final outcome
```

The full model conversation, tool output, and raw events remain available when needed.

The user should not have to read a transcript to understand whether work succeeded.

---

# 17. WORK — THE HUMAN / AGENT CONTRACT

Durable Work should be the primary coordination layer between humans, Orchestrators, Execution Agents, and external systems.

A user may begin with:

```text
Fix the authentication problem.
```

Quaestor or the selected Orchestrator may create:

```text
Q-184  Fix authentication race
```

During investigation, an agent may discover:

```text
Q-185  Refresh-token race
Q-186  Add concurrency regression test
```

Those discoveries should become durable Work rather than disappearing inside an ephemeral transcript.

The product chain becomes:

```text
Goal
  ↓
Work Graph
  ↓
Orchestrator strategy
  ↓
Agent / Human execution
  ↓
Evidence + Decisions
  ↓
Review / Approval
  ↓
Outcome
  ↓
Training Episode
```

Work exists to improve orchestration and continuity.

Quaestor should **not** become a conventional project-management suite merely because it stores Work.

---

# 18. MACHINE-FIRST WORK MODEL

Quaestor should define a provider-neutral machine-oriented `WorkItem` model.

The internal representation should optimize for agent reasoning, scheduling, dependency analysis, verification, and provenance rather than for visual ticket formatting.

Conceptually:

```text
WorkItem

identity
  id
  external_id
  organization
  project

intent
  title
  goal
  description
  kind
  priority
  risk

state
  status
  readiness
  blocked_reason

graph
  parent
  children[]
  depends_on[]
  blocks[]
  discovered_from[]
  related[]

execution
  assigned_human
  assigned_orchestrator
  assigned_execution_agent
  relay_session
  required_capabilities[]
  required_connectors[]

completion
  completion_conditions[]
  verification_requirements[]
  review_requirements[]

provenance
  created_by
  source_event
  source_work
  context_capsule
  decisions[]
  evidence[]

effects
  pull_request
  commits[]
  artifacts[]

timestamps
```

The exact schema may differ.

The key principle is:

> **Human-readable tickets are a projection of machine-readable Work, not the source of truth.**

The UI may render a rich internal item simply as:

```text
Q-184
Investigate customer import failures

● Working
Claude → Codex
```

while agents receive the richer structured representation.

---

# 19. WORK PROVIDER ABSTRACTION

Do not hard-code Quaestor to a single issue tracker.

Define a conceptual interface such as:

```text
WorkProvider
```

with capabilities approximately equivalent to:

```text
list
ready
get
create
update
close
reopen
dependencies
relationships
comments / history
```

Potential implementations:

```text
Beads
GitHub Issues
Linear
Jira
Azure DevOps
Quaestor Local
future providers
```

Quaestor should normalize external systems into the machine-first Work model without requiring businesses to migrate existing project-management tooling.

A Work provider supplies durable work state.

Quaestor supplies orchestration, coordination, evidence, decisions, scheduling, and cross-system intelligence.

---

# 20. BEADS-LIKE MACHINE WORK STORE

Beads is a strong model for the first/recommended local Work provider because its dependency-aware, agent-friendly design aligns closely with orchestration.

Useful concepts include:

```text
dependency-aware issues
ready work
parent / child relationships
blocking relationships
discovered-from relationships
repo-local state
agent-friendly CLI / API behavior
durable structured memory
```

Quaestor should support:

```text
Quaestor Work Model
       ↓
WorkProvider
       ↓
Beads adapter
       ↓
.beads / durable local store
```

Humans should see Quaestor Work.

Agents may use the native provider representation where useful.

## 20.1 Persistent agent memory

When an agent discovers a real issue, it should be able to turn that finding into durable Work immediately.

Example:

```text
Q-398
Refresh-token rotation race

discovered_from: Q-184
priority: P2
status: ready
```

This prevents important discoveries from disappearing when:

```text
conversation compacts
Orchestrator changes
Execution Agent changes
Relay restarts
employee ownership changes
```

## 20.2 Beads is not mandatory

Quaestor must remain compatible with organizations already using other issue systems.

Beads or a Beads-like local store should be an excellent default, not an irreversible dependency.

---

# 21. WORK UI — PROJECTIONS, NOT A SECOND DATA MODEL

The Work UI should visualize the same underlying Work Graph.

Useful projections may include:

```text
Ready
Running
Blocked
Review
Done
```

and, where useful:

```text
list
grouped list
board / Kanban
dependency graph
timeline
roadmap
agent queue
```

**Kanban and Roadmap views are optional.**

They should only be built when they materially improve user understanding.

Do not create separate project-management state merely to support a visual board or roadmap.

A lightweight default may be:

```text
WORK

READY
Q-184  Fix auth race                    P1

RUNNING
Q-181  Relay UI                         OpenCode

BLOCKED
Q-179  Windows CI                       blocked by Q-178

REVIEW
Q-176  Relay kernel                     Claude review
```

Users should be able to:

```text
create Work
start Work
pause Work
change priority
inspect dependencies
assign human / agent
request review
open evidence
close / reopen
```

Starting ready Work should remain simple:

```text
Q-182  Fix relay resume

[ Start ]
```

Quaestor then uses project defaults or asks only for genuinely missing required choices.

---

# 22. GLOBAL WORK VIEW

Fleet should expose actionable Work across projects and devices.

Example:

```text
ALL PROJECTS

READY FOR AGENTS                         17

Quaestor        4
Atlas           7
Harbor Point    6


RUNNING                                  5

Q-184    Quaestor      OpenCode     18m
AT-821   Atlas         Claude       42m
HP-119   Harbor Point  Codex         7m


BLOCKED                                  3

Q-177    Windows packaging
          blocked by Q-176

AT-201   Blender export
          needs owner input


NEEDS REVIEW                             2

Q-183    Relay recovery
AT-793   Texture import
```

The purpose is not generic project management.

It is to answer:

```text
What work can an agent start now?
What is currently consuming agent / human attention?
What is blocked?
What requires review or authority?
What should the Orchestrator do next?
```

This turns Quaestor into a multi-project AI operations center.

---

# 23. WORK GRAPH — SOURCE OF TRUTH, OPTIONAL VISUALIZATION

The durable dependency graph is more important than any specific project-management visualization.

Conceptually:

```text
Goal
 ├── Work A
 │    ├── Work A1
 │    └── Work A2
 ├── Work B
 │    └── blocked_by Work A1
 └── Work C
```

The Work Graph supports:

```text
dependency reasoning
ready-work calculation
critical blockers
parallelization
agent scheduling
discovery provenance
review / approval dependencies
workflow continuity
training trajectory structure
```

A visual graph may be useful for complex projects but is **not required**.

Likewise, a roadmap may be generated as a projection of:

```text
Goals
Work
Dependencies
Observed progress
```

rather than manually maintained as a separate source of truth.

The system should prefer automatically derived progress over user-maintained status decoration.

---

# 24. AGENT VIEW

The Agent page should expose the live Relay interaction without making it the only way to understand project state.

Recommended sections:

```text
Current objective
Orchestrator
Execution Agent
Reviewer if active
Current message / phase
Conversation timeline
Endpoint health
Advanced endpoint details
```

Ordinary users should see understandable capabilities.

Example:

```text
OpenCode

● Connected
Can edit this project

Quaestor can:
✓ identify this session
✓ send instructions
✓ observe repository changes

Quaestor cannot:
✗ restrict the agent to this repository
```

Avoid exposing only internal labels such as:

```text
assurance = DIALOGUE
write_capable = true
```

Those may appear in Advanced details.

---

# 25. ACTIVITY — HUMAN-READABLE EVENT TIMELINE

The Activity view should summarize meaningful events, not dump raw logs.

Example:

```text
10:42  Claude requested inspection of auth.py
10:43  OpenCode read 4 files
10:44  OpenCode modified auth.py
10:45  Tests: 17 → 16 passed
10:46  Claude rejected result
10:47  OpenCode corrected refresh.py
10:49  Tests: 17/17
10:50  Reviewer approved
10:51  Q-184 moved to Done
```

Each event can expand to show:

```text
full message
tool call
diff
command output
evidence
raw event metadata
```

The default should optimize for comprehension.

---

# 26. CHANGES — TRUST THROUGH VISIBLE RESULTS

Changes should be a first-class project view.

Example:

```text
Changes

auth.py                    +42 -11
refresh.py                 +18 -4
test_auth.py               +31 -0

[ View Diff ]

Tests
✓ 47 passed

Static
✓ clean

Review
✓ Independent review approved

Work Item
Q-184

[ Accept ]
[ Ask for Revision ]
[ Revert ]
```

Where technically possible, actions should remain governed by existing authority rules.

A user should be able to evaluate **what changed and whether it worked** without reading the entire agent conversation.

---

# 27. EVIDENCE — VERIFIED OUTPUT, NOT SELF-REPORTED SUCCESS

Evidence should answer:

> **Why should I believe the work is complete or correct?**

Possible evidence:

```text
test results
build results
static checks
repo observations
screenshots
rendered outputs
queries
documents
review verdicts
diffs
benchmarks
external checks
business-system state
approvals
```

Evidence should attach to Work, decisions, Relay sessions, and outcomes.

A completion claim should be modeled separately from completion evidence.

Example:

```text
CLAIM
"Migration succeeded"

EVIDENCE
✓ schema version = 81
✓ integration suite passes
✓ production canary healthy
```

Evidence improves:

```text
human trust
automated review
safe scheduling
business metrics
training reward signals
auditability
```

It should also feed training episode outcomes where contribution policy permits.

---



---

# 28. LONG-RUNNING AUTOMATION AND FAILURE DISCIPLINE

Long-running orchestration is a product feature.

Quaestor should survive:

```text
Orchestrator session replacement
Execution Agent exit
Core / Relay restart
machine reboot where resumable
network disconnect
provider outage
review/fix loops
dependency conflicts
long-running Work queues
```

Canonical state belongs in Quaestor, not in a model transcript.

## 28.1 Silent stalls are forbidden

A state may legitimately wait.

It may not claim healthy progress indefinitely while making none.

Repeated failures should become durable blockers/Work:

```text
failure
→ retry under bounded policy
→ repeated failure
→ BLOCKER
→ strategist / owner / operator attention as appropriate
```

Apply this to:

```text
dependency sync
result-shape failure
review failure
resource starvation
provider unavailability
workspace conflicts
integration conflicts
connector failures
```

## 28.2 Structured handoff reliability

Where a provider offers structured output, classify handoff strength rather than pretending every recovered payload is equivalent.

Suggested classes:

```text
NATIVE_SCHEMA_VALIDATED      STRONG
EXACT_TEXT_JSON              DEGRADED
FENCED_JSON_RECOVERED        WEAK
```

Record native failure categories before heuristic recovery, including:

```text
structured-output retries exhausted
provider / CLI error envelope
missing structured output
malformed outer JSON
handoff schema failure
run binding mismatch
prose-only result
other
```

A recovered handoff never silently becomes equivalent to a natively validated one.

## 28.3 Loud completion / truncation discipline

Prefer:

```text
loud failure
```

over interpreting uncertainty as completion.

Guard against:

```text
stream truncation
partial browser response
multi-part response truncation
incomplete envelope
missing completion marker
partial review
partial plan
```

## 28.4 Program lane lifecycle must be total

For Program Mode, lane kinds should be explicitly registered with terminal semantics.

Adding a new lane kind without a lifecycle handler should fail startup/tests rather than silently fall through a generic redispatch path.

## 28.5 Worktree/staging hygiene fails closed

If Quaestor cannot establish intended staging/exclusion policy before a control-plane commit, refuse the commit rather than silently include generated/interpreter/build noise.

Prefer explicit staging of intended candidate changes where practical.

## 28.6 Context replacement

When a model, agent, or employee changes, reconstruct a bounded Context Capsule from durable state:

```text
objective / Work
constraints
relevant decisions
observations
open blockers/questions
artifact/evidence references
dependency outputs
review findings
```

Do not make transcript replay the only recovery mechanism.

# 29. AGENT QUEUE AND ORCHESTRATION SCHEDULER

The Agent Queue is a natural extension of the Work Graph and remains directly inside Quaestor's primary orchestration scope.

The scheduler should reason about:

```text
ready Work
dependencies
priority
required capabilities
required connectors
project / workspace
permissions
risk
agent availability
model availability
cost / quota
required reviewer
human availability
concurrency
```

Conceptually:

```text
Ready Work
    ↓
Policy + Capabilities
    ↓
Quaestor Scheduler
    ↓
Orchestrator + Execution Agent
    ↓
Relay
```

Example:

```text
Q-184

requires:
  python
  repo_write

external_access:
  none

preferred_execution:
  OpenCode

review:
  independent_provider

priority:
  P1
```

The scheduler may recommend or automatically assign an eligible agent.

Automation should be progressive:

```text
Manual Start
Recommended Assignment
Auto-start selected Work
Policy-driven queue execution
```

Do not make full autonomous scheduling the default before users understand and trust the queue.

---

# 30. WORKFLOWS — REUSABLE ORCHESTRATION, NOT GIANT PROMPTS

Businesses repeatedly perform the same classes of work.

Quaestor should support reusable `Workflow` definitions.

Example:

```text
Production Bug

1. Gather alert context
2. Inspect service state
3. Create / update Work
4. Investigate
5. Propose fix
6. Implement
7. Verify
8. Independent review
9. Request deployment approval
10. Observe result
```

A Workflow may define:

```text
trigger
required connectors
Work templates
Orchestrator policy
Execution Agent policy
permissions
approval boundaries
verification requirements
review requirements
completion conditions
```

Workflows should compose existing Quaestor primitives.

They should **not** introduce a second orchestration engine beside Relay.

A Workflow creates and guides Work; Relay remains the mechanism by which Orchestrators and Execution Agents collaborate.

---

# 31. HEADLESS TRIGGERS

Quaestor should not require a human to open the composer for every workflow.

A Workflow may begin because an external or scheduled condition occurs.

Examples:

```text
GitHub issue opened
CI fails
support ticket escalated
security alert fires
CRM opportunity changes
email matches policy
new document arrives
scheduled audit starts
business metric crosses threshold
```

Conceptually:

```text
External Event
      ↓
Trigger Policy
      ↓
Create / Update Work
      ↓
Orchestrator
      ↓
Execution
      ↓
Evidence
      ↓
Human only where required
```

Headless triggers should use the same:

```text
identity
Work
authority
governance
evidence
approval
training provenance
```

as interactive work.

Do not create a separate "automation mode" with weaker controls.

---

# 32. DECISIONS — FIRST-CLASS ORGANIZATIONAL MEMORY

Important decisions should not disappear inside transcripts.

Quaestor should support a durable `Decision` record.

Conceptually:

```text
Decision

id

question
decision
reason / recorded rationale
alternatives[]

made_by
role

related_work[]
related_goal
evidence[]

effective_at
supersedes
superseded_by
```

Example:

```text
decision_481

question:
Should customer import remain synchronous?

decision:
No. Move processing to a background queue.

made_by:
Engineering Lead

related_work:
Q-182
Q-186

evidence:
artifact_817
```

This allows future humans and agents to answer:

```text
Why was this chosen?
Who had authority?
What evidence supported it?
Has the decision been superseded?
Which Work depends on it?
```

Decision records should capture **recorded rationale and provenance**, not hidden model chain-of-thought.

---

# 33. WORK CONTEXT CAPSULES

Every meaningful Work item should be able to expose a bounded, durable context capsule.

Conceptually:

```text
Context Capsule

purpose
known facts
relevant decisions
relevant Work
dependencies
relevant files / systems
relevant people / roles
previous attempts
failures
evidence
outstanding questions
```

The capsule exists to make transitions cheap:

```text
Claude → GPT
OpenCode → Codex
Employee A → Employee B
session restart
device change
```

The new actor should not need to reconstruct the entire history from raw transcripts.

Context Capsules should be generated from durable Work, Event, Decision, and Evidence state rather than becoming another manually maintained document.

---

# 34. GOALS — MINIMAL OUTCOME CONTEXT

Quaestor may support a lightweight `Goal` above Work.

Example:

```text
Goal
Ship Relay Mode

success:
  browser endpoint qualified
  restart recovery qualified
  owner boundary qualified

Work:
  Q-183
  Q-184
  Q-188
```

Business example:

```text
Goal
Reduce customer onboarding time

metric:
median_onboarding_hours

baseline:
51h

target:
24h
```

The purpose of Goals is to connect:

```text
Work
→ verified outputs
→ measurable outcome
```

Do not expand this into generic OKR management, employee performance scoring, resource planning, or HR tooling.

---

# 35. BUSINESS PRODUCTIVITY AND ORCHESTRATION METRICS

Business users need clear visuals, but the visuals should measure **real productive behavior and outcomes**, not decorative project-management status.

Quaestor should derive metrics from Work, Relay, Evidence, Decisions, approvals, and outcomes.

Useful categories include:

## 35.1 Flow

```text
ready Work
running Work
blocked Work
review queue
completion throughput
median cycle time
time to first agent action
time blocked
time waiting for human
time waiting for review
```

## 35.2 Agent effectiveness

```text
first-pass verification rate
revision rate
reopen rate
completion corroboration rate
average retries
review rejection rate
human intervention rate
agent handoff count
successful autonomous completion rate
```

## 35.3 Orchestration effectiveness

```text
Work automatically routed
Work parallelized
blocked dependencies resolved
context handoffs completed
duplicate / stale message prevention
recovery success rate
owner escalations
unnecessary escalations avoided
```

## 35.4 Quality

```text
tests / checks passed
regression rate
revert rate
review approval rate
post-completion reopen rate
evidence completeness
```

## 35.5 Economics

Where provider usage permits measurement:

```text
model cost per completed Work item
tokens per verified outcome
wall time
agent compute time
tool calls
retries
human minutes required
cost by Orchestrator / Execution Agent pairing
```

## 35.6 Business outcomes

Where Work is tied to measurable Goals:

```text
goal progress
lead time reduction
support resolution time
deployment success
customer onboarding time
document turnaround
other workflow-specific metrics
```

The UI should favor visualizations such as:

```text
trend lines
before / after comparisons
throughput charts
cycle-time distributions
blocked-time breakdowns
agent / model comparison tables
cost vs verified-success plots
approval / intervention breakdowns
```

A Kanban board or Roadmap may exist as an optional planning projection, but **productive metrics are more strategically important for business users**.

Do not measure employees through simplistic "AI productivity scores."

Metrics should evaluate workflows, outcomes, bottlenecks, and system behavior unless an organization explicitly defines a legitimate measurement policy.

---

# 36. BUSINESS SYSTEM CONNECTORS

Quaestor should integrate existing systems rather than attempt to replace them.

Conceptually:

```text
WorkProvider
├── Beads
├── GitHub Issues
├── Linear
├── Jira
└── Azure DevOps

BusinessConnector
├── Slack / Teams
├── Gmail / Outlook
├── Google Drive / Microsoft 365
├── Salesforce
├── ServiceNow
├── Notion / Confluence
├── databases
└── internal APIs
```

Connectors should expose governed capabilities and structured events to Workflows and Orchestrators.

Quaestor's value is:

> **orchestrating work across systems**

not recreating every business system inside Quaestor.

---

# 37. WHY IS THE AGENT DOING THIS?

Trust improves when users can inspect observable causal provenance.

Example:

```text
OpenCode is editing auth.py

Why?

Work:
Q-184 Fix refresh-token concurrency

Triggered by:
test_refresh_parallel failure

Orchestrator direction:
Inspect authentication state mutation

Evidence:
stack trace + previous Q-176 findings
```

This should be derived from recorded Work, messages, Decisions, Evidence, and tool events.

Do not expose or invent hidden model chain-of-thought.

The UI should expose **observable rationale and causality**.

---

# 38. AGENT / MODEL ECONOMICS — MEASURE EARLY, OPTIMIZE LATER

Where possible, capture:

```text
model
provider
tokens
cost
wall time
agent time
tool calls
retries
verification result
review result
human interventions
```

This enables future analysis such as:

```text
Claude + OpenCode
higher first-pass success
higher cost

GPT + Codex
lower cost
more revisions

Local model + OpenCode
lowest cost
highest human intervention
```

Do not make cost optimization a primary early product surface.

Collect reliable measurements first.

Later, businesses may use them for:

```text
routing policy
budget controls
model selection
capacity planning for agents
cost / quality tradeoff analysis
```

---

# 39. SCOPE BOUNDARY — NOT A GENERAL PROJECT-MANAGEMENT SUITE

Quaestor should include only project/work-management capabilities that strengthen orchestration.

Strongly in scope:

```text
Goals
machine-first Work Graph
dependencies
ready Work
optional Work projections
agent queue / scheduler
workflow definitions
headless triggers
decisions
evidence
approvals
activity
context capsules
productive metrics
```

Normally out of scope:

```text
manual Gantt editor
sprint poker
story points
timesheets
employee utilization dashboards
meeting agendas
wiki replacement
company chat replacement
CRM replacement
HRIS
expense tracking
generic document management
```

Those systems should be integrated through providers/connectors when relevant.

The product should not become:

```text
Jira + Slack + Zapier + IDE + LangSmith + BI suite
```

It should remain the orchestration layer connecting them.

# 40. GLOBAL APPROVALS

Quaestor should preserve structural effect classes such as:

```text
READ_ONLY
STANDARD_EDIT
GIT_COMMIT
GIT_PUSH
DESTRUCTIVE
```

The exact vocabulary may evolve, but the principle remains:

> **Gate the act, not the sentence.**

A model saying "push it", "delete it", or "deploy it" is not authority.

Owner-only or policy-gated effects must become durable approval/hold records before the effect occurs.

Owner requests must be visible globally.

Do not require the user to discover which project tab is waiting.

Top-level navigation should expose:

```text
Approvals (3)
```

Example:

```text
OWNER REQUESTS

Atlas
GIT_PUSH
Tests 418/418
Review approved
[ Approve ] [ Deny ]

Quaestor
DELETE migration database
Risk: destructive
[ Inspect ]

Harbor Point
External Blender execution
[ Approve ] [ Deny ]
```

Approvals should include enough surrounding evidence to make the decision without forcing the user to reconstruct the entire session.

---

# 41. SETTINGS HIERARCHY

Avoid one giant ambiguous Settings page.

Use three scopes.

## 41.1 Account / Organization

```text
Profile
Organizations
Team
Billing
Devices
Data & Privacy
Contribution
```

## 41.2 Global Quaestor

```text
Default Orchestrator
Default Execution Agent
Providers
Credentials
Notifications
Security
Quaestor Core
Advanced
```

## 41.3 Project

```text
Project
Agents
Work Provider
Permissions
Verification
Review Policy
Contribution Policy
Repository
Advanced
```

The UI should always make the active settings scope obvious.

---

# 42. SIMPLE VS ADVANCED EXPERIENCE

Quaestor's architecture is sophisticated.

The default experience should hide that sophistication until it is useful.

## Simple

```text
Goal
Project
Run
Progress
Work
Changes
Approvals
```

## Advanced

```text
Orchestrator
ExecutionEnd
Reviewer
Assurance
Permissions
Relay events
Prompts
Context packets
Evidence details
Transports
Diagnostics
```

The product should become powerful through progressive disclosure rather than presenting every capability at once.

---

# 43. BROWSER EXTENSION

The Chrome/Edge extension is a **browser-Orchestrator integration surface and compact companion UI**.

It should not become the main Quaestor application.

Production browser topology:

```text
Browser Orchestrator
        ↕
Quaestor Extension
        ↕
Native Messaging /
authenticated local IPC
        ↕
Quaestor Core
```

## 43.1 Extension responsibilities

```text
identify supported browser conversation
observe conversation identity
observe newly completed model messages
send Relay messages into composer
report connection state
bind conversation to project
show current Work item
pause/resume Relay
send a quick user message
open the relevant project in Quaestor Web
```

## 43.2 Extension must not own

```text
repository access
filesystem access
terminal execution
provider API secrets
Git credentials
owner capability
governance database
issue-management business logic
organization administration
arbitrary Core RPC
```

## 43.3 Example popup

```text
Quaestor

Atlas

● Relay running
ChatGPT → OpenCode

Current
Q-184 Authentication race

Owner Hold
None

[ Message ]
[ Pause ]
[ Open Project ]
```

`Open Project` should normally open the matching project in `app.quaestor.ai`.

If cloud access is unavailable, the extension may surface a link to the local Core Console for diagnostics rather than attempting to become the fallback application itself.

---

# 44. TRAY / LIGHTWEIGHT APPLICATION SHELL

A small tray application may provide desktop-native convenience.

It is a client of Quaestor Core, not the execution engine and not the main product UI.

Example:

```text
Quaestor ●

Atlas
ChatGPT → OpenCode
Relay Running

Open Quaestor
Open Core Console
Pause Relay
Stop Relay
Quit Core
```

`Open Quaestor` should open the cloud web product.

`Open Core Console` should open the local fallback/diagnostic interface.

A future native shell may wrap or reuse the existing web product.

Avoid maintaining separate native and web management applications.

---

# 45. MOBILE / RESPONSIVE EXPERIENCE

Do not build a native mobile application first.

`app.quaestor.ai` should be responsive and may become PWA-capable.

Because the primary product is already cloud-hosted, the same organization/work/project model can support desktop, tablet, and phone without a separate mobile backend.

Mobile is most valuable for:

```text
Needs You
Fleet summary
running sessions
owner approvals
pause / resume
high-level activity
quick feedback
team administration
data / privacy controls
```

Example:

```text
Quaestor

Needs You                         2
Running                           5
Completed Today                  11

⚠ Atlas
Git push approval
[ Review ]

● Quaestor
Q-287 · OpenCode · 18m

● Harbor Point
HP-119 · Codex working
```

Mobile should initially not be treated as:

```text
repository browser
terminal emulator
full workstation configuration surface
unrestricted direct agent console
provider-secret manager
```

Do not require inbound public access to a workstation.

Preferred topology:

```text
Responsive Quaestor Web
       ↕
Quaestor Cloud
       ↕
outbound authenticated device channel
       ↕
Quaestor Core
```

Sensitive local operations must still pass local Core authority checks.

---

# 46. PRODUCT INFORMATION ARCHITECTURE

Recommended top-level navigation for Quaestor Web:

```text
QUAESTOR
│
├── Home / Fleet
│
├── Work
│   ├── All Projects
│   ├── Ready
│   ├── Running
│   ├── Blocked
│   └── Review
│
├── Approvals
│
├── Projects
│   │
│   └── <Project>
│       ├── Overview
│       ├── Work
│       ├── Agent
│       ├── Changes
│       ├── Evidence
│       ├── Activity
│       ├── Metrics
│       └── Settings
│
├── Workflows
│
├── Agents & Devices
│
├── Decisions
│
├── Insights / Metrics
│
├── Team
│
├── Data
│   ├── Product Sync
│   ├── Contribution
│   └── Privacy
│
└── Settings
```

Not every destination needs to ship in the initial Web MVP.

Persistent project tabs sit above or alongside this information architecture.

The exact visual treatment may evolve, but the product should preserve the distinction between:

```text
Work to be done
Work being orchestrated
Evidence / decisions
Business insight
Administration
```

Kanban, graph, timeline, and roadmap views are optional projections inside Work rather than mandatory top-level products.

---

# 47. ONBOARDING, REPOSITORY CONNECTION, AND FRIENDLY PERMISSIONS

## 47.1 Zero-config first; policy-configurable later

A project should not require a manifest merely to begin participating.

Basic path:

```text
Install / start Quaestor Core
        ↓
sign in or choose local-only mode
        ↓
select / authorize repository or project
        ↓
detect available agents / IDEs / connectors
        ↓
choose Orchestrator + Execution Agent
        ↓
start observing / asking / planning / running / reviewing
```

Safe facts may be detected:

```text
Git root
language/build system
candidate verification commands
available local agents
known IDE/session artifacts
workspace capability
```

Dangerous permissions must never be inferred.

Configuration unlocks stronger policy; it is not the admission ticket.

A primary config such as:

```text
quaestor.toml
```

may exist for advanced use. TOML is preferred as a simple standard primary format where practical; YAML may remain a compatibility input if existing deployments need it.

The common onboarding path should not require:

```text
manual MCP tunnel setup
router configuration
inbound firewall rules
public local HTTP servers
hand-authored manifests
Quaestor lane vocabulary
```

## 47.2 Progressive connection UX

Example:

```text
How should Quaestor connect?

● Native integration
○ Command / headless CLI
○ File inbox/outbox
○ Clipboard
○ Observe only
```

The UI should explain the guarantees of each choice in human terms.

## 47.3 Repository connection

Hosted users may connect repository metadata through a GitHub App or equivalent integration where useful.

Cloud/provider integration may expose:

```text
repo metadata
PRs
issues
commits
branches
webhooks
```

Quaestor Core remains responsible for:

```text
local workspace
local secrets
local agents
build/test environment
sandbox
repo/system observation
local evidence
authority
```

Basic use should not require router configuration, inbound firewall rules, public local HTTP servers, or hand-authored manifests.

## 47.4 Friendly permissions

Translate the internal capability model into understandable controls.

Example:

```text
Files
● Read and edit this project

Terminal
● Sandboxed commands

Internet
○ Off
● Documentation only
○ Unrestricted

Git commits
● Allowed locally

Git push
○ Ask me first

Deployments
○ Always ask

Destructive operations
○ Never
```

Simple controls must map to the real capability/authority model; they must not become cosmetic toggles.

## 47.5 Human-readable intervention queue

The global `Needs You` / Approvals surface should include:

```text
STRATEGIC decision
OWNER authority
BLOCKER
REVIEW disagreement
RECOVERY ambiguity
```

Every item should answer:

```text
what happened
what was attempted
what may have changed
what evidence exists
why automation stopped
who has authority next
safe options
```

---

# 48. MULTI-USER IDENTITY AND TENANCY

Because Quaestor is a business-facing multi-device product and may support a user-contributed training-data program, identity is a first-class platform concept.

The logical hierarchy should support:

```text
User
 └── Organization / Workspace
      ├── Members
      ├── Roles
      ├── Devices
      ├── Projects
      ├── Work
      ├── Policies
      ├── Relay Sessions
      └── Data Contribution Program
```

## 48.1 Authentication

Support modern authentication such as:

```text
email / passwordless
Google
GitHub
MFA
```

Later enterprise support may include:

```text
SAML
OIDC
SCIM
enterprise policy
```

Do not build a custom identity provider unless there is a compelling product reason.

Use an appropriate established identity system.

## 48.2 Organization and project roles

Role names are an implementation decision, but the model should support organization-level and project-level permissions.

Conceptually:

```text
Organization Owner
Organization Admin
Manager
Member
Viewer

Project Owner / Maintainer
Project Operator
Project Viewer
```

Permissions should be capability-based underneath rather than relying only on role names.

Important actions such as:

```text
enroll/revoke device
authorize project
change contribution policy
approve destructive action
approve push/deploy
manage credentials
manage team membership
```

must be explicitly permissioned.

## 48.3 Device identity

Every Quaestor Core installation should have a revocable device identity.

Conceptually:

```text
user_id
organization_id
device_id
device_public_key
installation_id
Quaestor version
last_seen
revoked_at
```

The user or authorized administrator should be able to view and revoke enrolled devices.

## 48.4 Project identity

Projects must have stable identity separate from absolute filesystem paths.

Example:

```text
project_id
organization_id
authorized_device_ids
local_path
repo fingerprint
remote fingerprint if available
authorization state
product_sync_policy
contribution_policy
```

A project should never become training-enabled solely because the user joined a global data program.

Project policy must also allow it.

---

# 49. QUAESTOR CLOUD

Quaestor Cloud becomes a core **business control plane**, while remaining separate from local privileged execution.

Responsibilities may include:

```text
authentication
accounts
organizations
teams
RBAC / permissions
device enrollment / revocation
project registry
Work synchronization
Fleet aggregation
Relay/session status projection
approval routing
notification delivery
operational product synchronization
policy distribution
licenses
billing
data-contribution policy
dataset ingestion
release/update metadata
```

The cloud is **not**:

```text
the local Relay execution runtime
the repository execution environment
the default provider-secret store
the mandatory source-code proxy
the terminal/process host
the authority source for local privileged effects without Core validation
```

The selected Orchestrator remains the strategic intelligence.

Quaestor Core remains the trusted local execution/governance runtime.

## 49.1 Device connection model

Prefer an outbound authenticated connection from each Core to Cloud.

```text
Quaestor Core
      │
      │ outbound mutually authenticated / device-bound channel
      ▼
Quaestor Cloud
```

Do not require inbound public access to developer workstations.

The channel should support:

```text
device presence / heartbeat
Work delivery
Relay status
approval requests / responses
notifications
policy updates
selected product synchronization
```

It must include request identity, replay protection, versioning, bounded payloads, and clear failure semantics.

## 49.2 Website is a control surface, not the effect boundary

Quaestor Web may create Work, send goals, request Relay start/stop, and submit authorized approvals.

But privileged effects occur only after the targeted Core validates the request.

Cloud compromise or model-generated text must not automatically translate into arbitrary local execution.

---

# 50. CLOUD SYNC, PRIVACY, AND CONTRIBUTION MODES

Do not collapse three different concepts into one setting:

```text
1. Product control metadata
2. Operational product content
3. Training-data contribution
```

A user or organization may need shared cloud visibility while prohibiting training use entirely.

## 50.1 Product control metadata

While signed in, Core may synchronize the minimum metadata required for the product to function, subject to product/privacy policy.

Examples:

```text
device online/offline
project identity
Work IDs / states
Relay running/waiting/failed
agent type / health
counts
approval envelopes
verification status summaries
timestamps
```

Minimize sensitive content inside control metadata.

## 50.2 Operational product-content sync

Businesses may choose to synchronize additional content so authorized teammates can use the full cloud UI remotely.

Examples:

```text
Work descriptions
Relay summaries
activity timeline
diffs
evidence summaries
test/build output
review results
selected transcript content
screenshots / artifacts
```

This is **product functionality**, not training consent.

Define explicit project/organization sync profiles such as:

```text
LOCAL_ONLY
METADATA_ONLY
TEAM_SYNC
CUSTOM
```

### LOCAL_ONLY

Project content remains on Core.

Cloud may know only the minimum account/device state allowed by policy.

The Local Core Console remains available for full local control.

### METADATA_ONLY

Fleet, device, Work-state, health, and approval metadata may synchronize, but detailed transcripts/source/diffs remain local unless separately requested and permitted.

### TEAM_SYNC

Selected operational content synchronizes to Cloud for authorized team collaboration under organization retention/privacy policy.

### CUSTOM

Organization/project policy explicitly selects content classes and retention.

Operational sync must have:

```text
encryption in transit
appropriate encryption at rest
authorization checks
retention policy
auditability
redaction where practical
tenant isolation
```

## 50.3 Training contribution — separate and OFF by default

Training-data contribution must be a separate explicit state.

Default:

```text
Training contribution: OFF
```

Turning on `TEAM_SYNC` must **not** turn on training.

Turning on telemetry must **not** turn on training.

Signing in must **not** turn on training.

A contributor may explicitly select modalities:

```text
[x] Model conversations
[x] Tool/action traces
[x] Code diffs
[ ] Complete source files
[x] Test/build results
[ ] Screenshots
[ ] Images/assets
[ ] Video
[ ] Browser content
```

Contribution settings should be reviewable and revocable according to the applicable program/policy.

## 50.4 Policy precedence

Where multiple policies apply, the most restrictive applicable policy should win unless a clearly defined organization policy says otherwise.

At minimum evaluate:

```text
organization policy
project policy
user permission
modality permission
current consent version
artifact eligibility
```

A project should never enter the training pipeline merely because some other project or the user account is enrolled.

---

# 51. MODALITY-SPECIFIC CONSENT

Do not model consent as one boolean.

Potential contribution classes:

```text
TEXT_MESSAGES
TOOL_EVENTS
COMMANDS
COMMAND_OUTPUT
CODE_DIFFS
SOURCE_FILES
TEST_RESULTS
BUILD_RESULTS
REPO_METADATA
SCREENSHOTS
IMAGES
VIDEO
AUDIO
BROWSER_CONTENT
REVIEW_VERDICTS
OWNER_FEEDBACK
UI_INTERACTIONS
```

Each artifact should inherit the policy that authorized its collection.

Conceptually:

```text
artifact_id
episode_id
modality
consent_policy_id
consent_version
project_policy_id
allowed_for_training
captured_at
```

This allows Quaestor to later establish why a datum entered a dataset.

---

# 52. TELEMETRY MUST REMAIN SEPARATE FROM PRODUCT SYNC AND TRAINING DATA

Operational telemetry, product synchronization, and training contribution are different data uses.

## Operational telemetry

Examples:

```text
Quaestor version
endpoint type
connection latency
crash category
generic error code
CPU/memory metrics
feature usage counts
```

## Product synchronization

Examples, depending on project policy:

```text
Work state
device state
Relay state
approvals
activity summaries
diff/evidence projections
team-visible operational content
```

## Training corpus

Examples, only when contribution policy permits:

```text
model messages
code changes
commands
tool results
screenshots
images
review feedback
verification results
owner decisions
```

A user or organization may enable one category and disable another.

Do not hide training-data collection under an analytics, team-sync, or cloud-account toggle.

---

# 53. TRAINING EPISODE MODEL

Quaestor should treat a real workflow as a structured **training episode**, not merely a chat transcript.

Conceptually:

```text
TrainingEpisode
│
├── Identity
│   ├── episode_id
│   ├── organization_id
│   ├── project_id
│   ├── device_ids[]
│   ├── workflow_id
│   ├── goal_id
│   └── work_item_ids[]
│
├── Actors[]
│   ├── pseudonymous actor identity
│   ├── organizational role
│   ├── human / model / agent / system
│   └── authority role
│
├── Objective
│
├── Environment
│   ├── repo / system fingerprints
│   ├── applications / connectors
│   ├── Orchestrator provider/model
│   ├── Execution Agent provider/model
│   ├── Quaestor version
│   └── endpoint capability/assurance
│
├── Trajectory[]
│   ├── actor / role
│   ├── causal parent
│   ├── Work state
│   ├── input
│   ├── output
│   ├── tool calls
│   ├── command / connector results
│   ├── system observations
│   ├── decisions
│   ├── approvals
│   ├── evidence
│   ├── handoffs
│   └── multimodal artifacts
│
├── Outcome
│   ├── completion claim
│   ├── completion corroboration
│   ├── verification before / after
│   ├── review verdict
│   ├── owner acceptance
│   ├── Work completion / reopen state
│   ├── Goal / business metric movement
│   └── later reversal / correction
│
└── Provenance
    ├── consent policy/version
    ├── product-sync policy
    ├── model identities
    ├── endpoint versions
    ├── ingestion version
    └── dataset lineage
```

This is a logical schema.

It does not mean every field is uploaded.

Collection policy selects which parts may leave the machine and which may enter a training dataset.

For business workflows, role relationships may be more useful than raw employee identity.

Example:

```text
Support Specialist
      ↓
Engineering Lead
      ↓
Security Reviewer
      ↓
Manager Approval
      ↓
Execution Agent
```

Where appropriate, training artifacts should preserve role and authority structure while minimizing unnecessary personal identity.

---

# 54. WHY TRAJECTORIES ARE MORE VALUABLE THAN CHAT LOGS

Quaestor should optimize the future data pipeline around causality, organizational roles, actions, handoffs, authority, and measured outcomes.

A valuable engineering episode might look like:

```text
Human Goal
    ↓
AI Work decomposition
    ↓
Orchestrator Instruction
    ↓
Agent Investigation
    ↓
Tool Call
    ↓
Repository Modification
    ↓
Test Failure
    ↓
Orchestrator Critique
    ↓
Agent Revision
    ↓
Tests Pass
    ↓
Independent Review
    ↓
Owner Acceptance
```

A valuable enterprise episode might look like:

```text
Customer escalation
       ↓
Support Specialist
       ↓
Support AI summary
       ↓
Engineering Work created
       ↓
Engineering Agent diagnosis
       ↓
Security Review
       ↓
Manager Approval
       ↓
Execution Agent action
       ↓
Verification
       ↓
Support response
       ↓
Measured resolution outcome
```

This captures:

```text
what the organization was trying to accomplish
how work was decomposed
who or what acted
which role owned which decision
what tools and systems were used
what depended on what
what failed
what corrected it
when authority was required
what evidence existed
what ultimately happened
```

That is significantly more valuable for training business-capable agents than isolated prompt/completion pairs.

---

# 55. AUTOMATIC OUTCOME AND REWARD SIGNALS

Do not rely primarily on users manually rating every response.

Quaestor already observes stronger signals across engineering and business workflows.

Examples:

```text
test failure → test success
build failure → build success
review rejected → revised
review approved
objective reopened
Work blocked → dependency resolved
owner approves / denies
diff reverted
commit reverted
business-system state corrected
support issue reopened
workflow SLA met / missed
Orchestrator requests correction
agent completion claim contradicted by verification
security / authority violation blocked
```

These events can become machine-derived labels for:

```text
success
failure
revision quality
handoff quality
appropriate escalation
unnecessary escalation
verification quality
decision outcome
human-intervention requirement
workflow efficiency
```

When a Work item is linked to a measurable Goal, later business outcomes can provide additional labels without assuming that correlation proves causation.

Manual feedback should augment, not replace, these measured signals.

---

# 56. HIGH-VALUE TRAINING SIGNAL PATTERNS

The differentiated training value is not merely prompts, code, or documents.

Quaestor can capture grounded collaboration patterns.

## 56.1 Reviewer disagreement

```text
Implementation
      ↓
Reviewer A = PASS
Reviewer B = defect
      ↓
human / deterministic evidence resolves disagreement
      ↓
revision
      ↓
measured result
```

This can train reviewer quality, uncertainty handling, escalation, and disagreement resolution.

## 56.2 Strategic replanning

```text
Orchestrator proposes approach A
      ↓
Execution Agent reports measured blocker
      ↓
Orchestrator revises to B
      ↓
B succeeds under independent verification
```

This produces evidence-grounded planning/replanning trajectories.

## 56.3 Reviewer-quality comparison

```text
Reviewer A misses defect
Reviewer B identifies defect
later evidence confirms defect
```

The label comes from later evidence/outcome, not merely model preference.

## 56.4 Multi-employee organizational workflow

Especially valuable enterprise trajectories may include:

```text
customer / business event
→ employee role A
→ AI assistance
→ Work handoff
→ employee role B
→ agent action
→ security/legal/manager approval
→ verified business outcome
```

Where contribution policy permits, role and authority relationships are often more valuable than unnecessary personal identity.

# 57. OPTIONAL HUMAN FEEDBACK

Where useful, UI surfaces may expose lightweight feedback.

Example:

```text
Orchestrator Instruction

“Inspect the authentication race before changing the schema.”

[ Good ]
[ Bad ]
```

Execution result:

```text
OpenCode Result

[ Accept ]
[ Needs Revision ]
[ Wrong ]
[ Incomplete ]
```

Feedback should be:

```text
optional
fast
associated with exact event identity
associated with project/session context
associated with consent state
```

Avoid turning normal Quaestor use into a labeling job.

---

# 58. MULTIMODAL COLLECTION

Long-term training data may include more than text and code.

Potential modalities:

```text
screenshots
browser screenshots
application UI state
game-engine viewport captures
rendered assets
3D model previews
images supplied as references
generated images
video segments
terminal snapshots
audio where relevant
```

Multimodal capture should come **after** text/code/tool trajectory collection and consent infrastructure are mature.

Each modality requires:

```text
explicit permission
capture provenance
relationship to the causal trajectory
storage policy
redaction/filtering
dataset eligibility
```

---

# 59. LOCAL CONTRIBUTION FILTER

Raw Relay activity must not automatically become uploadable training data.

Use:

```text
Raw Event
    ↓
Consent Check
    ↓
Organization Policy
    ↓
Project Policy
    ↓
Modality Policy
    ↓
Secret Detection
    ↓
Credential Redaction
    ↓
PII / sensitive-content filtering
    ↓
Training Artifact
    ↓
Encrypted Upload Queue
```

Never:

```text
Raw Relay Event
    ↓
Upload Everything
```

Filtering should happen locally wherever practical.

---

# 60. CONTRIBUTION PROVENANCE

Every uploaded training artifact should answer:

```text
Who contributed it?
Which organization?
Which project?
Which device?
Which Relay session?
Which Orchestrator/model?
Which Execution Agent/model?
What caused the artifact?
What happened after it?
Was the result independently verified?
What modality is it?
Which consent policy permitted collection?
Which policy version?
When was it captured?
Which dataset ingest transformed it?
```

Do not depend on filenames or storage paths as provenance.

Use durable identities.

---

# 61. DATASET LINEAGE

Training ingestion should preserve transformation lineage.

Conceptually:

```text
raw eligible artifact
      ↓
ingestion
      ↓
redaction / normalization
      ↓
deduplication
      ↓
quality scoring
      ↓
episode assembly
      ↓
train/eval eligibility
      ↓
dataset version
```

A dataset row should be traceable back to the consented source episode and transformation chain without exposing the source data unnecessarily.

---

# 62. TRAIN / EVALUATION SEPARATION

Do not randomly split individual Relay turns.

Episodes from the same:

```text
repository
project
user
organization
task family
```

may leak heavily across splits.

Future dataset construction should support grouping policies that prevent near-identical or causally related work from appearing in both training and evaluation sets.

---

# 63. SECURITY BOUNDARIES

Model text is untrusted.

Browser content is untrusted.

Browser extension messages are untrusted.

Cloud requests are untrusted requests for local action.

Training artifacts are potentially sensitive.

Retain the architectural trust boundary:

```text
LOWER TRUST
────────────────────────────────
Model outputs
Browser DOM
Browser extension
Cloud/Web requests
External agent output
Remote Work requests

         validated interfaces

LOCAL EFFECT BOUNDARY
────────────────────────────────
Quaestor Core
Governance
Authorized Projects
Credential Store
Repo Observation
Local Contribution Filter
```

Cloud account identity must not automatically grant arbitrary machine capability.

Core must validate remote identity, project binding, request freshness, role/capability, and local policy before executing an effect.

A compromised cloud account, browser session, extension, or model output must not automatically become:

```text
shell authority
repository authority
secret access
GIT_PUSH authority
deployment authority
destructive authority
```

A locally authenticated and authorized Quaestor Core remains the final local enforcement point.

---

# 64. ENTERPRISE DEPLOYMENT MODELS

The architecture should support more than one control-plane deployment without changing how Quaestor Core executes work.

## 64.1 Quaestor SaaS

Default commercial model:

```text
app.quaestor.ai
      ↕
Quaestor Cloud
      ↕
Quaestor Cores
```

Best for individuals, teams, and organizations that accept the hosted control plane.

## 64.2 Enterprise private control plane

Later enterprise deployments may support:

```text
customer VPC
private cloud
on-prem control plane
regional/data-residency deployment
```

with the same Core protocol.

Potential enterprise requirements include:

```text
SSO / SAML / OIDC
SCIM
RBAC
audit logs
data residency
custom retention
organization-wide no-training policy
private model providers
private Work providers
device policy
network egress restrictions
```

## 64.3 Local-only / restricted environments

For air-gapped, offline, or highly restricted projects, Quaestor Core and its Local Core Console should remain able to operate without the SaaS control plane where the licensed/product mode permits it.

This preserves the local-first execution architecture even as the primary commercial UX becomes cloud-hosted.

---

# 65. EVENT IDENTITY SHOULD BE ADDED EARLY

Even before training uploads exist, Relay events should be structured so future training provenance can be attached without rewriting the event model.

Events should eventually be able to reference:

```text
user_id
organization_id
device_id
project_id
relay_session_id
orchestrator_identity
execution_identity
message_id
causal_parent
repo_observation_id
evidence_id
consent_policy_id
```

Do not require cloud connectivity to create local event identity.

Local IDs may later be reconciled with authenticated cloud identities.

---

# 66. DATA PLANES AND CLOUD CHANNELS

Conceptually separate five concerns:

```text
┌─────────────────────────┐
│ Relay Plane             │
│ model/agent messages    │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│ Control Plane           │
│ authority / policy      │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│ Evidence Plane          │
│ what actually happened  │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│ Product Sync Plane      │
│ authorized team UX data │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│ Contribution Plane      │
│ consented training data │
└─────────────────────────┘
```

The Contribution Plane consumes eligible Relay/Evidence/Work information.

It must not weaken or bypass the Control Plane.

The Product Sync Plane exists because a useful business web application needs shared operational state, but **product synchronization is not permission to train on that data**.

At the transport level, prefer logically separate flows:

```text
Quaestor Core
     │
     ├── Control Channel
     │     identity / presence / Work / Relay state / approvals
     │
     ├── Product Sync Channel
     │     policy-selected operational content
     │
     └── Contribution Channel
           separately consented training artifacts
```

These flows may share an authenticated transport implementation, but their schemas, authorization, retention, and data-use policies should remain distinguishable.

---

# 67. DELIVERY, QUALIFICATION, PACKAGING, AND RELEASE REQUIREMENTS

## 67.1 Maturity labels

Do not treat implementation or unit tests as product qualification.

Use explicit maturity states such as:

```text
IMPLEMENTED
TEST_QUALIFIED
LIVE_PROVIDER_QUALIFIED
LIVE_END_TO_END_QUALIFIED
PRODUCT_SUPPORTED
```

Every advertised endpoint/path should state its actual maturity.

## 67.2 Testing order

For new Relay/endpoint work:

```text
1. prove one real seam
2. prove repeatability
3. kill and recover
4. encode real discovered defects as regression tests
5. expand provider/product matrix
```

Do not optimize for test count before the real user path exists.

## 67.3 Cross-platform CI and merge protection

Generic product claims require deterministic CI on supported platforms.

At minimum target:

```text
Windows
Linux
macOS
```

Run the repository's deterministic suite and static architecture gate where those remain normative, including the equivalent of:

```text
python run_tests.py
python check_static.py
```

when those commands remain the repository's canonical gates.

Relevant checks should be required before merge rather than advisory-only.

Release-sensitive paths should include:

```text
clean-install verification
package / artifact verification
Windows-specific process/path behavior
browser/native-host compatibility where applicable
stale merged-branch hygiene
```

Path/process/worktree/confinement semantics are OS-sensitive.

Do not normalize "merge first, discover the product regression on main afterward" as the release process.

## 67.4 Packaging

Quaestor should become a real installable product.

Early developer distribution may support:

```text
pipx install ...
pip install ...
```

with:

```text
pyproject.toml
console entry point
versioning
release notes
install verification
upgrade path
```

Public productization may later require:

```text
signed installer
trusted browser-extension distribution
native-host registration
update signature verification
protocol/version compatibility
clean uninstall/recovery
```

## 67.5 Credential storage

Generalize secure local credentials behind platform-specific backends, for example:

```text
Windows DPAPI / Credential Manager
macOS Keychain
Linux Secret Service / equivalent
```

Browser extensions must not receive raw provider secrets.

## 67.6 Documentation is a release surface

README, operations docs, threat model, provider setup, and advertised assurance must describe what the product actually supports.

Documentation drift that changes operator expectations or security posture is a release defect.

## 67.7 Design provenance

Maintain a standing design-provenance record for externally studied systems:

```text
repository
revision/commit inspected
license at that revision
ideas studied
ideas adopted
ideas rejected
whether source code was copied
```

The goal is auditable design learning, not unverifiable borrowing.

A standing product lesson from the AI-Rosen-bridge comparison is:

```text
simple relay topology / UX
        +
Quaestor governance / authority / evidence / recovery
```

Adopt useful product ideas without copying a weaker safety model or making an external reference system normative architecture.

## 67.8 Product quality scorecard

Maintain an evidence-based maturity scorecard covering at least:

```text
authority model
independent evidence
durable state / reconciliation
two-way Relay
real execution
review independence
handoff reliability
silent-stall prevention
restart / long-duration recovery
CI portability
packaging
documentation
general-user onboarding
supported endpoint qualification
```

Scorecards must be grounded in qualification evidence, not aspiration.

# 68. NORTH-STAR RELAY ACCEPTANCE GATE

Relay capability is not complete merely because classes exist or mocks pass.

The flagship real path must demonstrate, where applicable:

```text
[ ] User selects an allowed, currently available Orchestrator.
[ ] User selects or attaches an Execution Agent.
[ ] Both are bound to an explicitly authorized project.

[ ] Orchestrator receives Execution Agent output automatically.
[ ] Execution Agent receives Orchestrator instructions automatically.
[ ] 10+ meaningful exchanges occur.
[ ] Zero manual copy/paste occurs.
[ ] Zero manual relay commands occur after start.

[ ] Natural multi-turn dialogue is preserved.
[ ] Message identities survive restart.
[ ] Duplicate delivery is prevented.
[ ] Partial/in-progress messages are never forwarded as complete.
[ ] Stale messages are never replayed as new work.

[ ] Real repo/system changes occur where the objective requires them.
[ ] Quaestor independently observes relevant effects.
[ ] Evidence does not depend only on agent self-report.

[ ] Relay/Core can be killed and resumed.
[ ] Orchestrator conversation resumes where supported.
[ ] Execution session resumes where supported.
[ ] Unsupported resume behavior is reported honestly.

[ ] Ordinary engineering/business decisions flow through Orchestrator ↔ Agent.
[ ] Owner-only effects stop at the owner boundary.
[ ] Model prose can never grant itself authority.
```

Provider-specific qualification should exist for each `PRODUCT_SUPPORTED` endpoint.

# 69. PUBLIC RELEASE GATE

Do not call Quaestor production-ready until the common user journey and every advertised endpoint path are qualified.

General release expectations:

```text
[ ] clean supported-machine install works
[ ] Core starts reliably
[ ] project authorization is explicit
[ ] Orchestrator reports actual provider/model identity
[ ] Execution Agent reports actual session identity where available
[ ] flagship path completes 10+ automatic exchanges
[ ] no manual copy/paste required
[ ] restart/recovery works
[ ] duplicate replay is prevented
[ ] owner-only effects remain structurally blocked
[ ] local credentials survive restart securely
[ ] logs redact sensitive values
[ ] protocol/version incompatibility fails clearly
[ ] cloud/offline state is represented honestly
```

Additional browser-hosted Orchestrator expectations:

```text
[ ] extension installs through a trusted distribution path
[ ] Native Messaging / authenticated IPC connects
[ ] extension cannot execute arbitrary local commands
[ ] extension cannot read provider secrets
[ ] conversation is bound to an authorized project
[ ] browser reconnect/restart behavior is qualified
[ ] partial replies are never forwarded as complete
[ ] stale output is never replayed as new
[ ] extension/Core protocol mismatch fails clearly
[ ] uninstall removes native-host registration cleanly
```

Negative/security qualification should include:

```text
unauthorized IPC client
malformed / oversized message
replayed message
unauthorized project request
wrong conversation/tab
stale Orchestrator reply
Execution session disappears
Core crashes during delivery
invalid/missing credentials
attempted owner-only effect
```

Release quality is defined by the full user journey, not unit-test count.

---

# 70. RECOMMENDED ROADMAP


> **Roadmap interpretation:** Relay work may already be implemented or in-flight in the repository. Before creating work from any milestone below, inspect current HEAD, live qualification artifacts, and current Work/issue state. A requirement that is already satisfied should be verified and closed, not reimplemented.

Do not interrupt the current Relay milestones to build the entire platform at once.

Sequence the product so every added capability strengthens orchestration.

## Current

```text
ChatGPT Web OrchestratorEnd
completion corroboration
```

## Platform P1 — Quaestor Core service boundary

Formalize:

```text
authenticated local API
Core lifecycle
restart / recovery
project authorization
Local Core Console
device identity
```

## Platform P2 — Machine-first Work Graph + Beads-like provider

Implement:

```text
WorkItem
WorkProvider
dependencies
discovered-from
ready Work
Relay ↔ Work
Evidence ↔ Work
```

Use Beads or a Beads-like provider first while preserving provider neutrality.

## Platform P3 — Identity, tenancy, and device enrollment

Implement users, organizations, permissions, projects, devices, and authenticated Core ↔ Cloud channels.

## Platform P4 — Quaestor Web orchestration MVP

Ship the useful pane of glass:

```text
Fleet
project tabs
Project Overview
Work
Agent
Changes
Evidence
Activity
Approvals
Agents & Devices
Settings
```

## Platform P5 — Productive metrics foundation

Begin measuring trustworthy derived metrics before building elaborate visualization:

```text
cycle time
blocked time
verification rate
revision / reopen rate
human intervention
orchestration recovery
agent / model usage
cost where available
```

Add compact visual summaries and trends.

Do not build generic BI.

## Platform P6 — Agent Queue / Scheduler

Add recommended assignment and policy-aware ready-Work scheduling.

Begin with user-visible recommendations.

Expand autonomy only after reliability is demonstrated.

## Platform P7 — Workflow definitions + headless triggers

Add reusable orchestration workflows and event/scheduled triggers on top of the same Work / Relay / governance model.

## Platform P8 — Decisions + Context Capsules

Persist organizational decisions and bounded Work context so agents, models, employees, devices, and sessions can change without losing continuity.

## Platform P9 — Product sync policy

Implement:

```text
LOCAL_ONLY
METADATA_ONLY
TEAM_SYNC
CUSTOM
```

Keep product sync independent from training contribution.

## Platform P10 — Goal-first remote control

Add the polished:

```text
Ask
Plan
Run
Review
```

experience routed through Core validation.

## Platform P11 — Contribution contract

Implement explicit consent, modality selection, project policy, and local eligibility decisions.

Training remains OFF by default.

## Platform P12 — Canonical business-workflow episode schema

Add:

```text
Work identity
Workflow identity
role / authority context
handoffs
decisions
causal trajectory
provider/model provenance
evidence
outcomes
consent lineage
```

## Platform P13 — Secure ingestion

Implement filtering, encrypted upload, resumable queue, validation, and dataset lineage.

## Platform P14 — Quality / reward pipeline

Derive verified training signals from:

```text
verification
review
revision
handoffs
approvals
reopens
business outcomes
human interventions
```

## Platform P15 — Business connectors

Add connectors only where they unlock real orchestration workflows.

Prefer existing systems over replacing them.

## Platform P16 — Browser extension productization

Keep the extension contextual and connect browser-hosted Orchestrators to Core.

## Platform P17 — Enterprise control-plane options

Add SSO/SCIM/audit/private deployment/data residency according to real customer requirements.

## Platform P18 — Multimodal capture

Add modality-specific capture only after consent, provenance, and ingestion are trustworthy.

## Platform P19 — Mobile / PWA refinement

Focus on Fleet, Needs You, approvals, status, and lightweight feedback.

## Platform P20 — Optional planning projections

Only if usage demonstrates value, add richer optional projections such as:

```text
Kanban
dependency graph
timeline
roadmap
```

These remain views over the Work Graph.

## Platform P21 — Optional native desktop shell

Only if users need it, add a thin shell around the same product.

Do not create a second UI codebase.

---

# 71. WHAT NOT TO DO

Do not:

```text
make execution cloud-only
make Quaestor Cloud the local effect boundary
give cloud requests unchecked shell/repo authority
upload source code by default
treat login as training consent
treat TEAM_SYNC as training consent
combine telemetry, product sync, and training consent
store provider secrets in browser extensions
give browser extensions repository access
make the Browser Extension the primary Quaestor management application
require Electron merely to obtain a professional UI
maintain divergent Web and Desktop applications
open an unauthenticated localhost control API
require users to understand Relay endpoints before starting work
require visible terminal windows for CLI/agent execution
make a UI client responsible for Core governance
hard-code Beads instead of using a WorkProvider boundary
discard agent-discovered work because it was not in the original task
make fully autonomous queue scheduling the default before users trust it
hide owner requests inside individual project tabs
make raw conversation the primary multi-project UX
make Kanban or Roadmap state separate from the Work Graph
build a full generic project-management suite
build employee surveillance / simplistic productivity scoring
build a generic BI platform
replace Slack / Teams / Jira / CRM / HR systems unnecessarily
collect screenshots without modality-specific consent
assume agent self-reported success is ground truth
throw away causal relationships between events
build a dataset from chat messages alone
treat mobile as an unrestricted terminal or secret-management surface
mirror Relay transcripts/source artifacts to cloud merely because remote status is enabled
pretend offline devices are still executing
```

The guiding rule is:

> **Add capabilities when they improve orchestration, continuity, supervision, verification, reuse, measured workflow outcomes, or training-data quality. Integrate everything else.**

---

# 72. LONG-TERM PRODUCT ADVANTAGE

Quaestor should not compete only as another AI coding wrapper or project-management application.

Its strategic position is the combination of:

```text
multiple Orchestrators
multiple Execution Agents
multiple employees / organizational roles
machine-first Work
real business systems
real repositories
real tools
governed effects
durable decisions
independent evidence
human authority
cross-model review
verified outcomes
workflow metrics
multimodal observations
```

The platform should understand not only:

```text
what was said
```

but also:

```text
what the organization wanted
what Work was created
how Work decomposed
what depended on what
who or what acted
which role had authority
what tools were used
what changed
what evidence existed
what was rejected
what was revised
what was approved
what business outcome followed
```

With consent, this allows Quaestor to build datasets representing **how complex organizational work is actually completed**, including failure, handoff, authority, correction, and outcome.

That is a stronger long-term data asset than a corpus of chat transcripts.

---

# 73. FINAL PLATFORM PRINCIPLE

Optimize around this model:

```text
GOAL
 ↓
MACHINE-FIRST WORK GRAPH
 ↓
ORCHESTRATION / SCHEDULING
 ↓
HUMANS + ORCHESTRATORS + EXECUTION AGENTS
 ↓
TOOLS / BUSINESS SYSTEMS / REPOSITORIES
 ↓
EVIDENCE + DECISIONS + APPROVALS
 ↓
VERIFIED OUTCOME
 ↓
MEASURED WORKFLOW INSIGHT
 ↓
CONSENTED TRAINING EPISODE
```

> **Quaestor Web is the primary pane of glass for users and businesses.  
> Quaestor Cloud provides identity, tenancy, shared Work, policies, device coordination, and optional data services.  
> Quaestor Core runs on authorized machines and controls the real local work.  
> Orchestrators think and direct.  
> Execution Agents and humans perform the work.  
> The machine-first Work Graph preserves continuity and enables scheduling.  
> Decisions, Evidence, and Approvals preserve authority and truth.  
> Productive metrics describe real workflow behavior and outcomes.  
> With explicit granular permission, verified multi-actor workflows can become provenance-rich multimodal training data.**

Quaestor should feel like an AI orchestration platform with unusually strong organizational memory and business visibility.

It should **not** feel like a generic PM suite with AI features bolted on.

Planning views such as Kanban, dependency graphs, timelines, or roadmaps are optional human projections.

The durable primitives are:

```text
Project
Goal
Work
AgentSession
Workflow
Decision
Evidence / Artifact
Approval
Event
Outcome
```

If a proposed feature does not strengthen those primitives or the orchestration loop they support, integration is usually preferable to implementation.

---

# APPENDIX A — HISTORICAL RELAY AUDIT / ISSUE DISPOSITION

> **Historical snapshot:** this material came from the 2026-08-29 Relay audit baseline. It explains why the Relay recovery architecture was created. It must **not** be treated as current repository state without re-checking HEAD and the current issue store.

The tracker currently reports:

```text
75 total
73 closed
2 deferred
```

That should **not** be interpreted as “Quaestor is essentially complete.”

It means the existing Program/governance roadmap was largely burned down.

The Relay product needs a new top-level roadmap.

## 16.1 Reopen / rename / re-investigate

| Issue | Audit disposition | Reason |
|---|---|---|
| `quaestor-239` — EPIC P6 unattended multi-agent | **Reopen or rename** | Shipped an automated Strategist inside Program Mode; the stated user goal is broader Relay behavior |
| `quaestor-239.6` — answered-before-parked race | **Reopen investigation** | Targeted fix exists, but a later Gauntlet run recorded the same externally visible `WAITING_FOR_STRATEGIST` + empty inbox signature; do not assume same root cause, but explain it before calling recovery qualified |
| `quaestor-ru1` — Universal agent-end | **Reopen or narrow** | Library/bridge participation exists, but arbitrary existing-agent Relay attachment is not product-complete |
| `quaestor-ru1.19` — generic adapter reachable | **Reopen or supersede** | Its narrow dispatch fix is real; its close reason over-generalizes that into a fulfilled universal-agent product claim |
| `quaestor-xc7` — Packaging/portability/CI | **Reopen** | Current audited HEAD is Linux-only; static gate and required merge protection remain incomplete |

## 16.2 Technically useful but architecture/policy must be revised for Relay

```text
quaestor-cjj
quaestor-239.4
quaestor-kaz.6
quaestor-ru1.5
quaestor-kaz.4
quaestor-ru1.3
quaestor-yy9
quaestor-d0v
quaestor-hfa
quaestor-6gp
```

The most important changes are:

- `quaestor-yy9`: keep deferred, but rewrite Cloud from mandatory strategic brain to optional service infrastructure.
- `quaestor-239.4`: retain cockpit work, but stop treating lack of confinement proof as proof an external agent cannot mutate a repo.
- `quaestor-kaz.6`, `quaestor-ru1.5`, `quaestor-hfa`: preserve measured assurance; split capability from assurance.
- `quaestor-ru1.3`: TOML input support is valid, but configuration format is not a Relay blocker; do not let config architecture outrank the vertical slice.

## 16.3 Retain closed, but do not cite as proof Relay Mode works

```text
quaestor-mda
quaestor-3nl.2
quaestor-3nl
quaestor-qbu
quaestor-fje
quaestor-239.5
quaestor-239.3
quaestor-ru1.14
quaestor-kaz
quaestor-ukj
quaestor-5m2
quaestor-6e9
quaestor-ag2
quaestor-ru1.17
```

These are useful Program Mode, transport, infrastructure, or prior-E2E accomplishments. They are not evidence that a persistent Orchestrator ↔ existing Execution Agent relay works.

For `quaestor-239.3` and `quaestor-239.5`, retain **implementation closure** but add a separate live-qualification blocker.

For `quaestor-kaz`, clarify that “any model in any role” means any **available/buildable/admitted** provider, not every declared registry row.

## 16.4 Correctly deferred

```text
quaestor-xe0
```

Keep the data-contribution platform deferred until the Relay product and its privacy boundaries are mature.

## 16.5 Retain closed; reusable primitive remains valid

```text
quaestor-1ng
quaestor-239.1
quaestor-239.2
quaestor-239.7
quaestor-3nl.1
quaestor-4ci
quaestor-50l
quaestor-dri
quaestor-exf
quaestor-kaz.1
quaestor-kaz.10
quaestor-kaz.11
quaestor-kaz.2
quaestor-kaz.3
quaestor-kaz.5
quaestor-kaz.7
quaestor-kaz.8
quaestor-kaz.9
quaestor-lh0
quaestor-o8k
quaestor-pop
quaestor-ru1.1
quaestor-ru1.10
quaestor-ru1.11
quaestor-ru1.12
quaestor-ru1.13
quaestor-ru1.15
quaestor-ru1.16
quaestor-ru1.18
quaestor-ru1.2
quaestor-ru1.20
quaestor-ru1.21
quaestor-ru1.22
quaestor-ru1.4
quaestor-ru1.6
quaestor-ru1.7
quaestor-ru1.8
quaestor-ru1.9
quaestor-sev
quaestor-szf
quaestor-ubg
quaestor-wwg
quaestor-xc7.1
quaestor-z8k
quaestor-z9v
```

Two historical caveats:

- `quaestor-kaz.1` originally closed before the full provenance tuple was actually present; `quaestor-kaz.11` later repaired the current implementation. Retain closure based on current HEAD, not the original close evidence.
- `quaestor-ru1.20` and `quaestor-ru1.22` legitimately closed by narrowing incorrect claims, because their acceptance criteria explicitly allowed that outcome. The removed capabilities must not silently disappear from future product planning if they remain strategically useful.

Audit summary:

```text
5   reopen / rename / re-investigate
10  revise architecture or policy
14  retain closed but not Relay proof
1   correctly deferred
45  retain closed reusable primitives
75  total
```

---

# APPENDIX B — REQUIRED REPOSITORY AUDIT BEFORE MAJOR ORCHESTRATION CHANGES

The following list is retained from the Relay recovery contract as a minimum inspection set. Paths may evolve; if a listed path has moved, inspect its current equivalent.

Before implementation, inspect at minimum:

```text
src/quaestor/adapters/
src/quaestor/executors/bridge.py
src/quaestor/executors/chatgpt_web.py
src/quaestor/executors/chatgpt_web_page.py
src/quaestor/executors/browser_transport.py
src/quaestor/executors/websocket_client.py
src/quaestor/executors/claude_code.py
src/quaestor/executors/codex_cli.py
src/quaestor/executors/registry.py
src/quaestor/core/strategist.py
src/quaestor/core/orchestrator.py
src/quaestor/core/briefing.py
src/quaestor/core/authority.py
src/quaestor/core/dispatcher.py
src/quaestor/core/store.py
src/quaestor/core/strategic_store.py
src/quaestor/transports/cli.py
src/quaestor/projects/connect.py
docs/ARCHITECTURE.md
docs/CHATGPT-PLUS.md
docs/QUAESTOR_PRODUCT_DIRECTION.md
docs/ROSEN-BRIDGE-CROSS-EXAMINATION.md
docs/reports/issues.md
GAUNTLET_AUDIT_REPORT.md
.github/workflows/ci.yml
```

Also inspect relevant AI-Rosen-bridge behavior as a reference for relay simplicity, but do not copy its weaker safety model.

---

# APPENDIX C — REQUIRED IMPLEMENTATION HANDOFF

Major orchestration milestones should leave a handoff that distinguishes architecture, implementation, qualification, and remaining gaps.

Do not stop at architecture analysis.

Each Relay milestone should report:

## Architecture delta

```text
old topology
new topology
components reused
components added
```

## Files changed

List significant files and responsibilities.

## Real validation evidence

State explicitly:

```text
real Orchestrator?
real browser if applicable?
real Execution Agent?
real repo?
number of exchanges?
manual copy/paste required?
restart/recovery tested?
owner hold tested?
```

Do not conflate mocks with live validation.

## Remaining gaps

State:

```text
unsupported providers
unproven assurance
platform limitations
browser fragility
manual setup still required
known failure modes
```

## Product packaging state

State:

```text
desktop service
browser extension if applicable
native messaging / authenticated IPC
installer
secure credential storage
signed distribution / updates
project authorization
```

Distinguish prototype-only paths from product-supported paths.

---

# APPENDIX D — EXISTING ASSETS TO PRESERVE / REUSE

The unified PRD does not authorize a rewrite of hardened substrate merely because the product surface is changing.

Do not throw away:

```text
authority/capability enforcement
owner-only boundaries
independent repository/evidence observation
durable state/event stores
message dedup/replay ideas from mailbox work
provider-family/provenance tracking
cross-vendor reviewer policy
reconciliation-aware failover
context capsules
sanitization/redaction
ChatGPT completion detection
CDP browser transport
OpenRouter provider
provider preflight/credential honesty
crash reconciliation
Program Mode
adapter assurance probes
local Web UI components
onboarding/detection
adversarial-review discipline
```

The objective is to put a simpler product on top of the hardened substrate, not to restart from zero.

---

# APPENDIX E — SOURCE MERGE AND PRECEDENCE MAP

This PRD was consolidated from three overlapping product contracts.

## E.1 Newest platform/orchestration document

`QUAESTOR_PLATFORM_AND_DATA_ARCHITECTURE_ORCHESTRATION_REVISED.md` is the canonical spine.

Its requirements are retained throughout this PRD, including:

```text
cloud Web primary UI
local Quaestor Core effect boundary
Fleet / project tabs
machine-first Work Graph
WorkProvider / Beads-like provider
agent scheduler
Workflows / headless triggers
Decisions
Context Capsules
Goals
productive business metrics
business connectors
multi-user tenancy
product-sync policy
training contribution / provenance
enterprise deployment
data planes
platform roadmap
```

## E.2 Relay Architecture

`QUAESTOR_RELAY_ARCHITECTURE.md` contributes the detailed Relay contract:

```text
Relay vs Program separation
OrchestratorEnd / ExecutionEnd
persistent Relay loop
message identity / dedup
natural dialogue
existing-session attachment
capability vs assurance
governed effects
restart/recovery
qualification maturity
North-Star gate
release gate
historical issue audit
required audit/handoff discipline
```

Its dated repository-state claims are historical rather than normative current status.

## E.3 Product Direction

`QUAESTOR_PRODUCT_DIRECTION.md` contributes requirements that remain useful after newer architecture corrections:

```text
Any Repo / Any Agent / Any Strategist / Any Reviewer
Role × Provider matrix
cross-vendor structural review
provider failover with reconciliation
Universal Agent-End
OBSERVED / DIALOGUE / MANAGED / GOVERNED / CONFINED
file inbox/outbox
transcript-only adoption
durable adapter mailbox
prompt transport / ambient context
zero-config onboarding
friendly permissions
long-running automation
silent-stall prohibition
structured handoff strength
loud truncation failure
lane lifecycle totality
worktree fail-closed hygiene
packaging / cross-platform CI
design provenance
quality scorecard
```

Older statements that conflict with the newer product architecture—such as treating a local Web UI as the primary business UI or treating Cloud as the strategic brain—are superseded rather than duplicated.

## E.4 Canonical conflict rules

If wording from an older source appears to conflict with this PRD:

1. **This PRD governs.**
2. The newest platform/orchestration architecture governs product UX, Cloud/Core split, Work, business metrics, multi-user, and training-data direction.
3. The Relay contract governs Relay endpoint/delivery/recovery semantics unless a newer implementation-specific contract explicitly supersedes it.
4. Security/authority rules fail toward the stricter interpretation.
5. Historical repository/audit claims never override current measured HEAD.
6. Product capability claims require current qualification evidence.

# Operations

How to install, deploy and operate Quaestor. Everything here is grounded in the operator CLI
(`src/quaestor/transports/cli.py`) as it exists — every command below is a real verb with real
flags. Features that are contract but not code are marked **planned** and point at
[`PRD.md`](PRD.md), the canonical product contract.

---

## 1. Installation

Standard library only — there are no runtime dependencies, so the install cannot fail on a
resolver conflict inside somebody else's repository, which is exactly where this tool has to
install:

```bash
git clone <this repo> && cd quaestor
pip install -e .             # installs the `quaestor` command
python run_tests.py          # the gate: exits 0 only on PASS
python check_static.py       # static checks
```

`pip install -e .` provides the operator entry point **`quaestor`**, and every command in this
document is written that way. Once installed, `python -m quaestor.transports.cli ...` reaches the
same surface.

**Without installing anything**, `python bin/quaestor ...` (POSIX shim) and `bin\quaestor.cmd`
(Windows) run the CLI straight out of a checkout — they put `src/` on the path themselves.
Bare `python -m quaestor.transports.cli` in an uninstalled checkout does **not** work: nothing
puts `src/` on the path and it fails with `ModuleNotFoundError`. That is the one invocation to
avoid quoting from memory.

Global flags: `--home <dir>` selects the deployment home (§2); `--claude-path` overrides the
Claude binary (default `claude`, or `QUAESTOR_CLAUDE_PATH`). Pass global flags **before** the
subcommand.

## 2. The deployment home

One home per deployment. Durable state lives here, never inside a repository:

```text
<home>/
  mode.json               the deployment's execution-mode decision (see §3)
  orchestrator.sqlite3    runs, results, evidence refs, leases, owner grants
  strategic.sqlite3       programs, lanes, messages, decisions, reviews, events
  runs/                   per-run artifacts: request, stdout/stderr, exit receipt, handoff
  runs/_verification/     parent-side test receipts collected by integration/verification
  worktrees/<program>/<lane>/   one linked git worktree per writable lane
  worktrees/<program>/_integration/   where lane branches merge for the program verdict
  relay.sqlite3           Relay Mode: relays, the delivery ledger, events, observations
  relay/<relay-id>/       Relay Mode: the orchestrator conversation transcript
```

Relay Mode keeps its own database rather than borrowing `orchestrator.sqlite3`. That file models
runs, worktree leases and seat results, none of which a relay has, and bolting relay tables onto
it would make the relay depend on Program Mode's schema and migrations for no gain. The one
deliberate exception is the OWNER GRANT LEDGER: authority is a single platform-wide fact, so
Relay Mode reads grants from `orchestrator.sqlite3` and the owner channel rather than inventing a
second, forgeable ledger of its own. The operator procedure is §11; the architecture is
[`RELAY-MODE.md`](RELAY-MODE.md).

With no `--home`, the home is resolved in this order, and each step is there for a reason:

1. `QUAESTOR_HOME` — an explicit deployment decision outranks every convention.
2. An **already existing** `<repo>/src/quaestor/var` — the pre-packaging location. Changing a
   default must never move somebody's data out from under them, so a checkout that already has
   programs keeps using the directory those programs are in.
3. The per-user platform data directory — `%LOCALAPPDATA%\Quaestor` on Windows,
   `~/Library/Application Support/Quaestor` on macOS, `$XDG_DATA_HOME/quaestor` (or
   `~/.local/share/quaestor`) elsewhere. This is the default for a fresh install: state a user is
   told is durable must not sit inside `site-packages`, where the next reinstall wipes it.

The home directory is a machine fact, not a secret and not pure — the credential store lives
outside it, under the OS user's application-data directory (`branding.STATE_DIR_NAME`).

## 3. Transport execution modes

There are exactly two modes, and an unknown value fails closed to the default.

**`QUALIFICATION_ONLY` — the default.** A module constant in `transports/mcp/mode.py`. Three
independent barriers: no worker process is ever spawned (`spawn=False`), the only executor kind
admitted is `fake`, and the only authority profile admitted is `READ_ONLY`. Any one barrier alone
is sufficient; they are kept separate so relaxing one cannot silently relax the others.

**`LOCAL_GOVERNED` — real constrained execution.** Detached workers construct real executors and
run them through the already-qualified admission ladder: authority profiles, fenced leases,
worktree drift checks, independent evidence, review floors. Selected once, locally:

```bash
quaestor --home /path/to/home mode set LOCAL_GOVERNED
quaestor --home /path/to/home mode show     # states which source decided the mode
```

`mode set` writes `<home>/mode.json`. It is a **local act only**: there is deliberately no MCP
verb, no request field and no environment variable behind it — a mode a remote caller could select
would be a default with a suggestion box attached. The file requires the same OS-user authority
the server already runs under, so it widens nothing against anyone who could otherwise reach the
machine (see [THREAT-MODEL.md](THREAT-MODEL.md)).

What LOCAL_GOVERNED admits, and what it does not:

| | QUALIFICATION_ONLY | LOCAL_GOVERNED |
|---|---|---|
| executor kinds | `fake` | `fake`, `claude-cli` |
| authority profiles | `READ_ONLY` | `READ_ONLY`, `STANDARD_EDIT` |
| spawns workers | never | yes, detached |

Everything above STANDARD_EDIT — the capabilities GIT_PUSH, EXTERNAL_WRITE, PAID_EXECUTION,
DESTRUCTIVE — stays **owner-gated no matter what a project manifest asks for**. The transport edge
refuses them before the orchestrator's own authority engine applies its opinion. A sandbox is also
not implied: the Windows-native `claude-cli` provider has the host's access, which is exactly why
the containerised provider is not admitted in this mode — advertising confinement the host cannot
currently validate would be a lie. `sandbox: none` remains legitimate for inert qualification and
a dangerous one for real execution.

## 4. Owner channel and credentials

Two separate secrets, two separate channels. Neither ever touches a command line.

### The owner channel

Owner decisions must be distinguishable from strategist/model statements, so grants are **signed**
by an interactively provisioned attestation key:

```bash
quaestor --home H owner init      # interactive; provisions the attestation key
quaestor --home H owner status    # AUTHENTICATED or UNAVAILABLE
quaestor --home H grant git_push --scope "repo=..."   # signed OWNER capability grant
```

While the channel is UNAVAILABLE, no ledger row can unlock an owner-gated capability, and an
owner-authority decision minted without it is honestly recorded as *claimed*, not attested.

### The executor credential broker

Subscription-backed Claude Code is the requirement — **not accidental Anthropic API billing**.
Anthropic's credential precedence puts environment variables ahead of subscription OAuth, so the
environment would silently decide the billing path; preflight is where that gets noticed, before
any process starts.

```bash
quaestor --home H credential provision   # paste the token from `claude setup-token`
quaestor --home H preflight --write      # the check dispatch will run
quaestor --home H doctor                 # everything at once: mode, channel, creds
```

Doctrine, both rules load-bearing:

1. **Refuse and name the condition; never silently unset.** Presence of any override variable —
   `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`/`API_URL`,
   `CLAUDE_CODE_USE_BEDROCK`/`VERTEX`/`FOUNDRY`, `CLAUDE_CODE_OAUTH_TOKEN`,
   `AWS_BEARER_TOKEN_BEDROCK` — is a refusal, without inspecting its value. An API key reports
   Console/API-key auth and is refused (`API_CONSOLE`); non-first-party routing is refused;
   anything the installed CLI version does not positively identify as first-party subscription
   auth classifies UNVERIFIED and refuses. Unsetting an operator's variable would make this
   control plane the thing lying about the billing path.
2. **Never persist a credential value.** Only presence and length of override variables are
   recorded; only allowlisted `claude auth status` fields survive into the ledger
   (`loggedIn`, `authMethod`, `apiProvider`, `subscriptionType` — identity fields do not).

Provisioning is interactive by construction: the token is typed into a hidden prompt, protected
with DPAPI, and there is deliberately no flag to bypass the TTY requirement — the bypass would
become the way it is normally used. There is no `--token` option on any parser, and
`allow_abbrev=False` is a security setting there, not tidiness. `CLAUDE_CODE_OAUTH_TOKEN` is the
one exemptible variable: it is the brokered automation credential a broker is meant to inject, and
the exemption ceiling is a shape rule (no policy may exempt an `*_API_KEY`-shaped name), not a
blessing of one string. `credential validate` measures the provisioned credential from inside a
container rather than trusting the broker's word.

Dispatch **requires** a resolved preflight; absent ⇒ `NO_CREDENTIAL_POLICY_CONFIGURED`.

## 5. Programs end to end

A program turns one objective into many governed executions:
`create → plan lanes → tick … tick → integrated candidate`.

```bash
quaestor --home H program create --title T --objective O \
    --project /path/to/project --constraints "c1|c2" --acceptance "a1|a2" --max-concurrent 2
quaestor --home H program plan <pid> --title "lane" --task "..." \
    --kind implementation --depends-on <other_lane_id> --acceptance "..."
quaestor --home H program tick <pid>          # one idempotent scheduling pass
quaestor --home H program serve <pid>         # tick loop until CANDIDATE_PASS /
    # CANDIDATE_FAIL / CANCELLED -- or until WAITING_FOR_STRATEGIST unless --wait-for-strategist
quaestor --home H program status <pid>        # human view (--json for machines)
quaestor --home H program list
quaestor --home H program inbox <pid>         # ONLY what needs attention
quaestor --home H program answer <pid> <message_id> --text "..."
    # [--rationale r] [--authority STRATEGIST|OWNER] [--actor name]
quaestor --home H program cancel <pid> --reason "..."
```

`program create` needs a project manifest (`quaestor.yaml`; write one with `quaestor init`)
because a program needs a repository to work on. Lane kinds: `research`, `implementation`,
`verification`, `adversarial_review`, `integration` — each with a fixed narrow authority
envelope (reviewers get READ_ONLY structurally, so they cannot "fix" what they find).
`--executor` on `plan` is a server-side fixture seam, not a wire field; production executors
come from the manifest.

### What a tick does

`tick` is idempotent against durable state — reap, integrate, schedule each happen at most once
per unit of state, and a crashed tick loses nothing.

1. **Reap finished runs.** Crash recovery first: a dead worker over an unchanged worktree is
   measured (not guessed) and failed cleanly; changes on disk mean AMBIGUOUS_EXECUTION and the
   lane escalates to the owner.
2. **Integrate**, when all implementation lanes are terminal.
3. **Schedule ready lanes** within the concurrency ceiling, each writable lane in its own
   worktree, behind a fresh dispatch identity.

### The implementation stage machine

```text
PLANNED --dispatch--> ACTIVE --handoff--> commit -> verify -> adversarial review
    findings survive --> bounded FIX attempt (same lane) --> re-verify/re-review
    clean -------------------------------------------------> COMPLETE/PASS
```

- **Commit** is performed by the control plane, deterministically, after evidence is durable —
  the child holds edit tools, never history.
- **Verify** runs the project's own test commands parent-side; a suite that inspected nothing is
  VACUOUS, never PASS.
- **Adversarial review** dispatches over the candidate diff plus independent evidence — never the
  child's transcript — under READ_ONLY. Every committed candidate gets one, including post-fix
  re-reviews: "the previous review passed" says nothing about the new diff.
- **Fix attempts are bounded** (`max_review_cycles`, default 3, persisted with the program).
  Past the bound the lane pauses for the strategist with everything the record knows. Reviewers
  and executors may not extend their own budget.

### Decisions: asking and answering

An executor question (`DECISION_REQUEST`, `CLARIFICATION_REQUEST`, `AUTHORITY_REQUEST`) becomes a
durable message, routes to STRATEGIST or OWNER by type, and pauses its lane. **Waiting is a
state, not a failure.** `program answer` records DIRECTIVE + Decision and wakes the lane; the
directive is delivered appended to the task of the next dispatched run together with its
checkpoint — resumption from durable state, never transcript replay. Owner-authority answers are
recorded with attestation computed from the owner channel, which is why `owner init` matters.

### Integration and the verdict

When no lane is open, integration merges committed lane branches — oldest first, exclusions
recorded, never silent — into the `_integration` worktree, after a semantic-overlap check
(lockfile/schema collisions force re-evaluation even when git merges textually), then verifies
the union with the project's tests:

- all green ⇒ program status `CANDIDATE_PASS`
- union fails ⇒ `CANDIDATE_FAIL`
- merge conflict or overlap risk ⇒ `CONFLICT` + blocker to the strategist inbox

Integration merges locally and stops there. Nothing pushes, publishes or destroys anything.

## 6. Reconciliation and cancellation

```bash
quaestor --home H reconcile <run_id>     # or --all; add --dry-run to classify only
```

Reconciliation produces a classification and a separately-provable
`auto_redispatch_allowed` flag. The one rule that outranks everything: **an ambiguous-write
execution must never auto-redispatch.** `NEVER_DISPATCHED` (admitted, spawn step never reached —
provably nothing ran) is distinguished from `AMBIGUOUS_EXECUTION` (may have written; a human must
inspect the worktree) precisely so the real alarm keeps its meaning. Reconciliation classifies; it
never redispatches — what to do with an AMBIGUOUS_EXECUTION is a decision for the strategist or
owner after inspecting the worktree. Once a dead process left no exit receipt, its exit code is
unrecoverable on this OS; the platform does not fabricate one, which is why `exit.json` is
written before parsing and its absence is meaningful.

Cancellation is classified by stage (before worker / before container / child running / already
terminal); an unprovable stage says AMBIGUOUS rather than claiming success.
`program cancel` abandons every non-terminal lane — waiting included, so a cancelled program can
never be mistaken for a merely quiet one — and marks the program CANCELLED.

## 7. The ChatGPT Plus tunnel

```bash
quaestor --home H tunnel serve --repo myrepo=/path/to/project
quaestor --home H tunnel token     # rotate the READ-ONLY remote token (shown once)
quaestor --home H tunnel doctor --url https://... --token tok_...
quaestor --home H tunnel revoke    # access stops at once
```

A remote ChatGPT caller gets the READ-ONLY surface — `search`, `fetch`, `orchestrator_status`,
`orchestrator_result`, `program_status`, `program_inbox` — and every state change happens through
the local owner channel. The ceiling comes from **which secret authenticated**, never from a
header or argument. Full setup, verification and honest limits:
[CHATGPT-PLUS.md](CHATGPT-PLUS.md).

## 8. Troubleshooting

### RESULT_INVALID retries and the RETRY NOTICE

A child that ends without a valid structured handoff fails `RESULT_INVALID` with the reason stored
machine-readably as `[FAILURE_CLASS] original text` — failure classes: `ENVELOPE_NOT_JSON`,
`MISSING_STRUCTURED_OUTPUT`, `PROSE_ONLY_RESULT` (the live shape: the child answered in prose),
`SCHEMA_VALIDATION_FAILED`, `RUN_BINDING_MISMATCH`, `CLI_ERROR_ENVELOPE`, `OTHER`.

The scheduler treats this as one bounded automatic retry, never a blind loop: the lane worktree is
reset to HEAD first (an invalid run's half-written edits are untrusted output, not state to build
on), a NEW attempt is scheduled under a fresh dispatch identity, and the retry prompt carries a
deterministically composed **RETRY NOTICE** restating the structured-handoff contract — the one
moment the contract can be restated where the child is guaranteed to re-read it. Past the bound
the lane pauses for the strategist with a blocker.

### DEPENDENCY_SYNC escalation and answer-based wakeup

Before dispatch, complete dependencies' branches are merged into the downstream lane's worktree.
A conflicted sync skips the lane on every tick — and after **two consecutive failures** it stops
being quiet: a BLOCKER lands in the program inbox and the lane parks WAITING_FOR_STRATEGIST.
Escalation is exactly-once per distinct error (hash-keyed), so a fixed-but-still-broken merge
re-escalates while an identical failure ticking past does not spam. `program answer` is the wake
path back to schedulable. The counter clears only when a dispatched run proves sync succeeded.

### Worktree exclusion refusals (`EXCLUSION_POLICY_UNVERIFIED`)

Before any control-plane commit sweeps the tree, git itself must demonstrate that interpreter
noise (`__pycache__/`, `*.pyc`, ...) is excluded — proven with a real `git check-ignore` probe,
never assumed. If the probe fails after one repair attempt, the commit is **refused outright with
nothing staged**. That is fail-closed by design: a missed commit can be retried; bytecode swept
into a candidate poisons integration and every diff built on it.

### Handoff strength

Every valid handoff records HOW its structured payload was obtained, and the strength travels in
the package itself so no consumer mistakes recovery for validation:

| `handoff_strength` | meaning |
|---|---|
| `NATIVE_SCHEMA_VALIDATED` | the CLI validated the payload against the schema before we saw it |
| `EXACT_TEXT_JSON` | exact text that parsed as JSON on our side; nothing validated it |
| `FENCED_JSON_RECOVERED_FROM_PROSE` | net-widened out of prose by the recovery scan |

A recovered handoff is never silently equivalent to a native one. When a result is refused, the
failure-class tag prefixing `invalid_reason` is how populations are counted — eight prose-only
children out of thirty-two is one defect, not thirty-two anecdotes.

## 9. Security posture, briefly

Orchestrator and Execution Agent — in Program Mode, strategist and executor — are untrusted
reasoning inside a trusted harness; authority comes only from signed owner grants; no layer
grades its own homework; measurement is independent or it is not evidence; at-most-one active
execution per identity with durable reconciliation. The full boundary statement — adversaries
considered, explicit non-goals — is [THREAT-MODEL.md](THREAT-MODEL.md).

## 10. Planned, not built

Stated here so nobody goes looking for flags that do not exist:

- **Universal agent adapters, as a Program Mode seat** — the minimal send/receive contract, the
  file inbox/outbox and command bridges, and the measured assurance ladder all exist
  (`adapters/`, `executors/bridge.py`), and Program Mode's buildable executor kinds are `fake`,
  `claude-cli`, `claude-container`, `codex-cli`, `openrouter`, `chatgpt-web`, `command` and
  `file-inbox`. What is NOT built is attaching a Program Mode seat to an agent session somebody
  else already started; that capability now lives in Relay Mode instead (delivered under bd
  `quaestor-pr4.3`, closed; see §11 and [`RELAY-MODE.md`](RELAY-MODE.md)).
- **Quaestor Cloud and Quaestor Web** — the business control surface (identity, tenancy,
  RBAC, device registry, policy distribution, approvals, notifications, billing) and the
  primary product UI on top of it: [`PRD.md`](PRD.md) §49 and §13. **No part of either runs
  at HEAD** — they are contract, not code. Cloud coordinates; it is never the effect boundary
  and never the strategic intelligence. Privileged execution stays on the operator's machine
  in Quaestor Core, and the strategic intelligence is whichever Orchestrator the operator
  selected. What this repository does ship is the loopback-only dashboard (`quaestor web`),
  which is the PRD's Local Core Console (§13.3) and which the PRD is explicit is not the
  primary business UI. Gated behind bd issue `quaestor-yy9`.
- **Relay Mode productisation** — Relay Mode itself is live-qualified end to end and has an
  operator surface (§11, [RELAY-MODE.md](RELAY-MODE.md)), but there is no installer, no tray,
  no browser extension, no native-messaging host, and no signed distribution. Quaestor Core
  now exists as a service boundary (§12) but does not yet *drive* relays: it observes them. It runs from a checkout. The relay-qualified Orchestrators are
  `chatgpt-web` (a browser conversation the operator started and signed into, driven over
  CDP) and `openai-chat` (the OpenAI-compatible chat-completions protocol); the only
  relay-qualified Execution Agent is `opencode`. Claude Code and Codex existing-session
  attachment, and the file-inbox/command bridges, are not yet relay endpoints (bd
  `quaestor-pr4.12`, `quaestor-pr4.13`, `quaestor-pr4.14`).
- **TOML manifests written by the product** — [`PRD.md`](PRD.md) §47 prefers `quaestor.toml`
  as the primary format on INPUT: discovery prefers it and it parses with the standard library,
  so a hand-written `quaestor.toml` works everywhere a `quaestor.yaml` does. But what the
  product WRITES is still `quaestor.yaml` (`init`, `connect`, the seat writer), and the seat
  writer edits YAML manifests only — it refuses a `.toml` by name rather than re-serialising a
  document it cannot round-trip with its comments intact. Operator expectation, stated
  plainly: YAML is what this product writes; TOML is accepted input only.

## 11. Relay Mode: start, inspect, recover, stop

Relay Mode is the second runtime, and it does not go through Program Mode: no programs, no lanes,
no seats, no worktrees, and nothing in `orchestrator.sqlite3` except the owner grants it reads. One
**Orchestrator** (a reasoning model in a conversation) and one **Execution Agent** (an agent server
already running on this machine) talk to each other about one authorised project; this platform
moves the messages, gates the effects, observes the repository independently, and records all of
it. The architecture, the three gates and the live-qualification records are
[`RELAY-MODE.md`](RELAY-MODE.md). What follows is the operator procedure.

Quaestor starts neither end. The browser and the agent server are processes **you** start and sign
into, and `relay stop` does not kill them — this platform does not manage their lifetime.

`mode.json` (§3) is the MCP transport's ceiling. The relay verbs are a local operator surface and
do not read it: a relay's ceiling is the `--profile` it was started under.

### The verbs

```bash
quaestor --home H relay doctor    # measure whether a relay could run right now
quaestor --home H relay start     # bind both ends to one project and drive the conversation
quaestor --home H relay status    # what is connected, which exchange, and why it is waiting
quaestor --home H relay resume    # re-attach after a crash, a kill, or a machine restart
quaestor --home H relay stop      # mark the relay stopped in the durable record
```

Global flags go before `relay`, as everywhere else in this document. Every verb prints JSON on
stdout.

Buildable endpoint kinds in this build — `relay doctor` prints the same list, measured rather than
remembered:

| Role | Kinds |
|---|---|
| Orchestrator | `openai-chat`, `chatgpt-web`, `fake` |
| Execution agent | `opencode`, `fake` |

`fake` is scripted. It proves kernel mechanics in the control suite and is **refused by
`relay start`** (exit 2): a relay reporting a finished conversation no model took part in would be
indistinguishable from a successful one.

### Endpoint flags

`start`, `resume` and `doctor` share one endpoint flag set. `--project` is required on `start` and
optional on the other two.

| Flag | Used by | Meaning |
|---|---|---|
| `--project` | all | the git working tree this relay is authorised for |
| `--profile` | all | authority profile the relay runs under (default `STANDARD_EDIT`) |
| `--orchestrator` | all | `openai-chat`, `chatgpt-web` or `fake` |
| `--orchestrator-model` | `openai-chat` | `<vendor>/<model>`; the vendor identity comes from here, never from the gateway that carried the request |
| `--orchestrator-base-url` | `openai-chat` | OpenAI-compatible chat-completions base URL |
| `--orchestrator-key-var` | `openai-chat` | environment variable holding the API key |
| `--orchestrator-key-file` | `openai-chat` | JSON file the provider's own tool already stored a key in |
| `--orchestrator-key-field` | `openai-chat` | dotted field inside `--orchestrator-key-file` |
| `--browser-endpoint` | `chatgpt-web` | CDP endpoint of a browser you started and signed into (default `http://127.0.0.1:9222`) |
| `--browser-transport` | `chatgpt-web` | how to reach it: `auto` (default), `cdp`, `playwright` |
| `--conversation-id` | orchestrator | bind to THIS existing conversation; omitted, a new thread is started and its id is recorded |
| `--agent` | all | execution agent kind: `opencode` or `fake` |
| `--agent-base-url` | `opencode` | the agent server you started (default `http://127.0.0.1:4096`) |
| `--agent-model` | `opencode` | `<provider>/<model>` the agent runs |
| `--agent-persona` | `opencode` | named agent/persona the execution server should use |
| `--session-id` | `opencode` | attach to THIS existing session id |
| `--attach-latest` | `opencode` | adopt the most recently updated session for the project |
| `--no-create-session` | `opencode` | refuse to create a session; attach to an existing one or fail |

A key is **named, never passed**: the key flags say where the value lives, and the value is used in
one request header and is never written to the relay's state, its events or its transcript. There
is no `--token`-shaped option here, for the same reason there is none on `credential` (§4).

Run-shape flags:

| Flag | Verbs | Default | Meaning |
|---|---|---|---|
| `--objective` | `start` | required | what the relay is for, in plain prose |
| `--relay-id` | `start`, `resume`, `status`, `stop` | the newest relay | which relay to act on; on `start` it is the id to create, and the default is a generated `relay-<hex>` |
| `--max-exchanges` | `start`, `resume` | `40` | stop after this many exchanges |
| `--max-duration` | `start`, `resume` | `3600.0` | seconds of wall clock |
| `--receive-timeout` | `start`, `resume` | `600.0` | seconds to wait for one completed turn |
| `--max-steps` | `start`, `resume` | `0` | stop after N half-exchanges; `0` runs to a terminal stop |
| `--no-observe` | `start` | off | skip independent repository observation. Not recommended: the Orchestrator then hears only the agent's own account of its work, and the observation gate loses its input |
| `--verbose` | `start`, `resume` | off | progress lines to stderr |
| `--all` | `status` | off | summarise every relay in this home |
| `--events N` | `status` | `0` | include the last N durable events |
| `--transcript` | `status` | off | include every message the relay moved |

### Doctor before start

`relay doctor` measures, at call time, whether a relay could run: it builds both endpoint specs,
probes the repository, runs each kind's own preflight, and reports the owner channel and the live
grants. A kind this build ships no preflight for reports `UNVERIFIED` rather than inheriting a
pass. `ready` is true only when both endpoints answered `ok` and the repository probed clean; the
exit status is 0 when `ready`, 1 otherwise.

```bash
quaestor --home H relay doctor \
  --project . \
  --orchestrator openai-chat \
    --orchestrator-base-url https://openrouter.ai/api/v1 \
    --orchestrator-model <vendor>/<model> \
    --orchestrator-key-var OPENROUTER_API_KEY \
  --agent opencode --agent-base-url http://127.0.0.1:4096
```

### Starting

Against an OpenAI-compatible endpoint:

```bash
quaestor --home H relay start \
  --project . \
  --objective "The migration test fails on Postgres 16. Diagnose it, fix it, and prove it." \
  --orchestrator openai-chat \
    --orchestrator-base-url https://openrouter.ai/api/v1 \
    --orchestrator-model <vendor>/<model> \
    --orchestrator-key-var OPENROUTER_API_KEY \
  --agent opencode --agent-base-url http://127.0.0.1:4096
```

Against a ChatGPT conversation in a browser you already signed into:

```bash
# You start the browser. Quaestor never launches it, never sees the password, never closes it.
chrome.exe --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\Chrome-Quaestor"

quaestor --home H relay start \
  --project . --objective "..." \
  --orchestrator chatgpt-web --browser-endpoint http://127.0.0.1:9222 \
  --agent opencode --agent-base-url http://127.0.0.1:4096
```

`start` runs the conversation in the foreground until a terminal stop, a ceiling, or `--max-steps`.
The relay lives as long as that process does — which is what `resume` exists for. `quaestor serve`
(below) is a *separate* service boundary: it does not yet drive relays, it observes them.

### Where relay state lives

Inside the deployment home (§2), never inside the repository:

```text
<home>/relay.sqlite3                        relays, the delivery ledger, events, observations
<home>/relay/<relay-id>/conversation.json   `openai-chat` only: the conversation itself
<home>/relay/<relay-id>/chatgpt-web.json    `chatgpt-web` only: the crash-recovery sidecar
```

The two sidecars are not the same kind of thing. An OpenAI-compatible endpoint is stateless, so the
relay's own transcript **is** the conversation and it has to be on disk before the first turn or
"resume" would be a word for starting over. A ChatGPT conversation lives at the vendor and resumes
without our help; that sidecar holds only the content key of each delivery, so recovery can ask the
live thread whether it already holds a specific turn instead of trusting what a dead process
believed.

Authority is deliberately **not** here. Relay Mode reads owner grants from `orchestrator.sqlite3`
and the owner channel (§4) rather than keeping a second, forgeable ledger of its own.

### Inspecting a relay

`relay status` runs in a different process from `relay start` and is built from the durable record
alone — never from a live kernel object — so an operator gets the same answer whether the relay is
running, paused, or was killed an hour ago.

```bash
quaestor --home H relay status                  # the newest relay in this home
quaestor --home H relay status --all            # every relay
quaestor --home H relay status --project .      # the newest relay for one working tree
quaestor --home H relay status --events 20 --transcript
```

Fields worth knowing:

- `state` — `RUNNING`, `PAUSED`, `OWNER_HOLD`, `STOPPED` or `FAILED`.
- `stop_reason` — `OBJECTIVE_COMPLETE`, `MAX_EXCHANGES_REACHED`, `MAX_DURATION_REACHED`,
  `NO_PROGRESS`, `ORCHESTRATOR_REPEATING`, `EXECUTION_REPEATING`, `ORCHESTRATOR_DISCONNECTED`,
  `EXECUTION_DISCONNECTED`, `OWNER_HOLD`, `UNRECONCILABLE_DELIVERY`, `START_REFUSED`,
  `STOPPED_BY_OPERATOR`.
- `waiting_on` / `waiting_for_message` — which endpoint owes a turn, and which message it is
  answering. That is the answer for every ordinary pause, and it is on the status surface so nobody
  has to open SQLite for it.
- `owner_hold` — the reason text of the last hold (see below).
- `orchestrator.conversation` / `execution.session` — the identities `resume` will re-bind to.
- `assurance`, per endpoint — what was *measured* about that endpoint, not what it claims.

Exit status is 1 when this home has no relay database, or when no relay matched.

### Recovering after a crash

```bash
quaestor --home H relay resume \
  --orchestrator openai-chat \
    --orchestrator-base-url https://openrouter.ai/api/v1 \
    --orchestrator-model <vendor>/<model> \
    --orchestrator-key-var OPENROUTER_API_KEY \
  --agent opencode
```

`resume` takes the relay id (the newest, unless `--relay-id` is given) and reads the endpoint kinds
(unless you name them again), the project, the authority profile, the objective, the orchestrator
conversation id and the agent session id from the record. It does **not** read the connection
details: base URL, key variable or key file, model and browser endpoint are not in the durable
record, so pass the same ones you started with. Omit `--orchestrator-base-url` on an `openai-chat`
relay and the endpoint cannot be constructed at all.

Then reconciliation runs, and it asks rather than assumes. Every delivery left `DELIVERING` by the
crash is resolved by asking the endpoint whether it already holds the relay-assigned message id:
already held → confirmed, never re-sent; not held → sent once more; **cannot answer → the relay
stops with `UNRECONCILABLE_DELIVERY` and a human decides**. A turn that was outstanding when the
process died is collected, not re-issued. The reasoning, and the endpoint-by-endpoint limits, are
in [`RELAY-MODE.md`](RELAY-MODE.md).

If `resume` reports `ORCHESTRATOR_DISCONNECTED` or `EXECUTION_DISCONNECTED`, the far side is what
needs attention — the browser was closed, the agent server was restarted, the session is gone.
`relay status` prints the conversation id and session id the record expects; bring that side back
and resume again.

### Owner holds, and how to clear one

Three gates can stop a relay, all three described in full in [`RELAY-MODE.md`](RELAY-MODE.md): the
**profile ceiling** once at start, the **directive gate** on every Orchestrator turn, and the
**observation gate** on what the repository actually shows after an agent turn. When one fires, the
relay's state becomes `OWNER_HOLD`, `stop_reason` is `OWNER_HOLD` (or `START_REFUSED` for the
ceiling), and `owner_hold` carries the reason in words — for example `profile STANDARD_EDIT does
not grant: git_commit, git_push`.

Record first, hold second. Whichever gate fires, the turn that triggered it is durable before the
relay stops and the message it produced is recorded **undelivered**, so `relay status --transcript`
shows exactly what the Orchestrator asked for, or what the agent did, before anything downstream
acted on it. The profile ceiling is the exception only because it fires before any message moves.

Whether the held effect can be allowed at all is decided by two independent locks, and only the
second one is cleared from the owner channel of §4:

1. **The profile must carry the capability.** A capability the profile does not grant is
   `OWNER_REQUIRED`, and no ledger row substitutes for it. The profile is fixed for the life of a
   relay — `resume` reads it from the record and a flag cannot change it — so allowing that class
   of effect means starting a new relay under a profile that carries it (`--profile GIT_COMMIT`,
   `GIT_PUSH`, and so on).
2. **Owner-gated capabilities need a signed grant as well.** `git_push`, `external_write`,
   `paid_execution` and `destructive` are never carried by a profile alone: they also require an
   AUTHENTICATED owner channel and a live grant.

```bash
quaestor --home H owner status                       # AUTHENTICATED or UNAVAILABLE
quaestor --home H owner init                         # if UNAVAILABLE; interactive
quaestor --home H grant git_push --scope "repo=..."  # signed OWNER capability grant
```

Capability ids are the lowercase ones the policy engine models: `repo_read`, `repo_write`,
`git_commit`, `git_push`, `network_read`, `external_write`, `paid_execution`, `destructive`. An
unknown name is refused rather than ignored.

Two details worth knowing before resuming a held relay:

- **`resume` is itself the decision.** The held directive is recorded as undelivered, and the next
  step delivers it; the gate that held it is not re-evaluated. If the effect is one you intend to
  allow, satisfy both locks above first — otherwise the observation gate holds again on the change
  the directive produces. If it is not one you intend to allow, `relay stop` rather than `resume`.
- **`owner_hold` is not cleared by `resume`.** It stays on the record as the last hold reason, so a
  `RUNNING` relay can still show the text of a hold it has moved past. Read `state` for what is
  true now, and the event log (`--events`) for the order things happened in.

### Stopping

```bash
quaestor --home H relay stop            # the newest relay; --relay-id picks another
```

`stop` marks the relay `STOPPED` with reason `STOPPED_BY_OPERATOR` and records the event. It does
**not** kill anything: the agent server and the browser are yours, and claiming a lifecycle
capability no endpoint here has would be worse than saying so plainly. Exit status is 1 when this
home has no relay recorded.

### Exit codes

| Verb | 0 | non-zero |
|---|---|---|
| `start` | `OBJECTIVE_COMPLETE`, `MAX_EXCHANGES_REACHED`, or `--max-steps` exhausted with no stop | `2` an endpoint could not be built (unknown kind, scripted kind, missing base URL); `3` the start gate refused — profile ceiling, unreadable working tree, or an endpoint that would not open; `4` any other stop reason |
| `resume` | resumed and ran | `2` no relay is recorded in this home; `3` resume stopped (disconnected endpoint, unreconcilable delivery) |
| `status` | a relay was found | `1` no relay database, or no relay matched |
| `doctor` | `ready` | `1` not ready |
| `stop` | marked stopped | `1` no relay is recorded in this home |

---

## 12. Quaestor Core — the authenticated local service boundary

`quaestor serve` runs **Quaestor Core**: a lightweight per-user loopback service that future
clients — a browser extension, Quaestor Web, a tray — reach *instead of reaching the machine*
([`PRD.md`](PRD.md) §3, §3.1). It is not a new execution path. Every answer it gives is read from
the same durable stores the CLI writes, and it performs no effect the CLI does not already own.

```bash
quaestor core authorize /path/to/repo      # an OPERATOR act; no client can do this for itself
quaestor core projects                     # what is authorised
quaestor core client --name extension --project local:abc123
                                           # prints a token ONCE, scoped to those projects
quaestor serve --detach                    # start Core; reports its endpoint
quaestor core ensure                       # make sure a Core is running; idempotent
quaestor core status                       # running? where? what does it owe?
quaestor core revoke <client-id>           # takes effect immediately, no restart

quaestor core relay-profile --name nightly --project local:abc123 \
    --profile READ_ONLY \
    --orchestrator openai-chat --orchestrator-base-url ... --orchestrator-model ... \
    --agent opencode --agent-base-url http://127.0.0.1:4096 --agent-model ... \
    --verify "python run_tests.py" --max-exchanges 200
quaestor core relay-profiles               # the shapes a client may name
```

`--profile` is **required**. It is the field that decides what the agent may do, and it had the
most permissive implicit default in the tree: omit it and no `--profile` reached the command
line, so the relay ran under `STANDARD_EDIT`, which grants repository **write**. A shape a
client can trigger must name its authority out loud. Values the relay's own parser would reject
— an unknown `--browser-transport`, a non-numeric ceiling, a `--verify` that is a string rather
than a list — are refused here, where an operator can read the reason, instead of becoming an
exit code with no detail.

`core ensure` is the **on-demand start** a client actually needs: not "start a Core", which
fails when one is already up, but "there is a Core and here is its endpoint" — one answer
whether it started something or found something. Liveness is measured by taking the lock, so a
Core that was killed with its endpoint file left behind is started again rather than handed
over as though it were alive.

### What the boundary is

The point of a service boundary is that it is **narrower** than the machine behind it. So:

* there is no `execute`, no `read_file`, no `write_file`, and **no path parameter at all** — a
  project is named by its **id**, and the id must be in the calling client's own grant;
* a client token carries a **project scope**. A token for one project cannot reach another, and
  cannot learn that another exists — an unauthorised project and a nonexistent one answer alike;
* an **empty scope** is a real answer (a status-only client) and there is no wildcard;
* absent, malformed, unknown and revoked credentials all get **one** refusal, because any
  difference between them is an oracle a guesser can climb.

The whole API is nine named operations. Six read — `core.status`, `core.identity`,
`projects.list`, `relay.profiles`, `relay.list`, `relay.status` — and three change something:
`relay.start`, `relay.resume`, `relay.stop`. `GET /health` is unauthenticated and returns
liveness only.

A client **names** a relay shape and never describes one. Every endpoint, model, credential
source, verification command and ceiling comes from a profile an **operator** registered with
`core relay-profile`; the command line is built from that profile and from the registry's own
record of the authorised checkout. The one string a client contributes is the **objective**,
which is bounded, must be one line of prose, and is passed as a single argv element to a
`shell=False` spawn. There is no way to send an executable, an argument, a working directory,
an environment variable or a repository path.

`relay.start` requires a **`request_id`** the client chooses, and there is no way to opt out.
The identity is reserved *before* the relay is spawned, so a client that loses the answer and
retries is given the relay it already made rather than a second one running against the same
repository. The reservation records a fingerprint of what was asked, so the same id reused for
*different* work is refused rather than silently handed the old relay; and a start that created
nothing gives the identity back, so a retry is a real retry.

A start that is still coming up — a model-exercising probe against a slow provider takes longer
than a client should hold a connection open for — answers **202** with the relay's id rather
than guessing in either direction; `relay.status` says when it is running. One project may have
only a few relays alive at once: each is a process and a paid conversation, and a scoped token
is the credential a browser extension holds.

### Lifecycle

Single-instance is enforced by the same `WorkerLock` the detached workers use, held for the
process's lifetime — so **the OS publishes Core's death**. A killed Core leaves its endpoint file
behind; `quaestor core status` reports that file as *stale* because it can take the lock, never
because the file said so. A second `quaestor serve` is refused and told where the live one is.

Core shuts down after `--idle` seconds of quiet — but **never while it owes something**: a live
relay or a standing owner hold is an obligation, and going away would leave an operator's held
decision with nothing listening for it. `--idle 0` stays up.

### Core owns a relay's process lifetime

`relay.start` launches the relay **detached, in its own process** — not as a child of the HTTP
request, of Core, or of whichever UI asked. The client that asked can exit, and the work
continues; Core itself can be killed, and the relay is untouched.

"Is that relay running?" is answered by a **lock the relay holds for its own lifetime**, never
by a pid in a file. So the answer survives Core dying, and a restarted Core reconciles what is
actually there: a relay whose durable state says `RUNNING` while no process holds its lock is
reported **orphaned**, because saying "running" would be a lie Core is in a position to detect.

`relay.stop` is a **governed durable request, not a kill**. Core marks the relay's own record
stopped; the running loop reads that record at each step boundary and leaves *between*
exchanges, so nothing is interrupted mid-delivery and no send becomes ambiguous. A relay that
has already ended keeps the reason it ended — stop never overwrites `OBJECTIVE_COMPLETE` with
`STOPPED_BY_OPERATOR`.

`relay.resume` carries **no policy at all** on the command line. Everything a resumed relay
needs — both ends and where they are, the objective, the authority profile, the ceilings, the
completion policy, the probe policy — is in its own durable record, which is brought up to date
on every resume so a policy an operator *strengthened* is not dropped by the next one.

Two things a resume cannot do. It cannot **reopen finished work**: a relay that stopped
`OBJECTIVE_COMPLETE`, or on a ceiling, or with its completion claim uncorroborated, is refused —
resuming it would clear the record of why it ended and re-deliver a directive already accounted
for as the end of the work. And it cannot **walk past an owner hold**. A hold raised on a
*directive* is re-gated by the relay itself against the grants in force at that moment, so the
decision stays where it belongs; a hold raised anywhere else has no such re-gate, and Core
refuses the resume outright rather than relying on a discharge path that does not exist for that
kind of hold. **Core authentication is not owner authority.**

### Identity

`<home>/device.json` is a durable installation identity: stable across restart, replaceable by
deleting it, carrying **no secret and no authority**. It exists so a future Cloud can recognise a
returning device without that concept being retrofitted onto records that never had it.

### What Core is not, yet

It owns a relay's **process lifetime** and nothing else. Everything that makes a relay correct —
the kernel, the state machine, message identity, delivery, reconciliation, governance,
completion corroboration, the probe, the retry bound, repository observation — stays exactly
where it was, and Core spawns the same `relay start` / `relay resume` an operator would type.
There is one orchestration path, not two to keep in agreement.

There is still no Cloud, no tenancy and no Quaestor Web; those are P3/P4. The loopback dashboard
remains the Local Core Console.

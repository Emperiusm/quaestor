# Relay Mode

> **Your selected Orchestrator thinks. Your AI coding agent executes. Quaestor keeps the
> conversation moving, observes what actually happened, and governs the effects.**

Relay Mode is the low-friction, conversation-first product mode. You pick an Orchestrator, you
pick (or attach to) an Execution Agent, you authorize a project, and the two talk to each other
automatically until the work is done or a human is genuinely needed.

Program Mode (`quaestor program`) is unchanged and remains the higher-assurance, state-machine
product. The two are complementary; Relay Mode does not run through Program Mode.

[`PRD.md`](PRD.md) is the canonical product contract. This document is the Relay Mode
implementation and operations detail beneath it: what is built, what has been qualified against
what evidence, how to run it, and what it does not do. Where the two disagree, the PRD governs.

---

## The topology

```text
        SELECTED ORCHESTRATOR                any admitted provider
      (strategic conversation)               ChatGPT Web · OpenRouter · Claude ·
                  │                          Gemini · Codex · local models
            OrchestratorEnd
                  │
                  ▼
   ┌──────────────────────────────┐
   │        RELAY KERNEL          │   conversation continuity
   │                              │   message identity / dedup / replay protection
   │  transport-neutral, and      │   bounded context transfer
   │  contains no provider        │   crash recovery
   │                              │   project authorization
   └──────────────┬───────────────┘   independent repo observation
                  │                    authority / owner holds
            ExecutionEnd
                  │
                  ▼
      SELECTED EXECUTION AGENT           an existing or resumable session
       (implementation work)             OpenCode · Claude Code · Codex · bridges
                  │
                  ▼
              REPOSITORY                 independently observed ground truth
```

The kernel imports no provider. Endpoints are reached by name through `relay/registry.py`, and a
control walks the import graph to prove `relay/kernel.py`, `state.py`, `effects.py`, `observe.py`
and `packets.py` never reach into `relay/ends/`.

---

## What is supported today

| | Kind | Maturity | Notes |
|---|---|---|---|
| **Orchestrator** | `openai-chat` | LIVE_END_TO_END_QUALIFIED | Any OpenAI-compatible chat-completions endpoint: OpenRouter, OpenCode Zen, OpenAI, a local gateway. The vendor identity comes from the **model**, never from the gateway. |
| **Orchestrator** | `chatgpt-web` | LIVE_END_TO_END_QUALIFIED | One conversation in a browser **you** started and signed into, driven over CDP. Quaestor never launches the browser and never handles the credential. |
| **Orchestrator** | `fake` | TEST_QUALIFIED | Scripted. Proves kernel mechanics; never product behaviour. |
| **Execution** | `opencode` | LIVE_END_TO_END_QUALIFIED | Attaches to a running `opencode serve` and an **existing or resumable session** bound to an authorized project. |
| **Execution** | `fake` | TEST_QUALIFIED | Scripted. |

The scripted endpoints are reachable from the control suite and the live harness, and are
**refused by `quaestor relay start`**: a relay reporting a finished conversation no model took
part in would be indistinguishable from a real one.

Not yet implemented as relay endpoints: Claude Code existing-session attachment
(`quaestor-pr4.12`), Codex existing-session attachment (`quaestor-pr4.13`), and the
file-inbox/command bridges (`quaestor-pr4.14`).

### ChatGPT Web

```bash
# 1. Start a browser Quaestor can attach to, and sign in ONCE in that window.
#    Quaestor never launches it, never sees the password, and never closes it.
chrome.exe --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\Chrome-Quaestor"

# 2. Point the relay at it.
quaestor relay start --project . --objective "..." \
  --orchestrator chatgpt-web --browser-endpoint http://127.0.0.1:9222 \
  --agent opencode --agent-base-url http://127.0.0.1:4096 \
  --agent-model <provider>/<model>
```

Add `--conversation-id <uuid>` to bind an existing thread; omitted, a new one is started and its
id is recorded so `relay resume` can return to it. `--browser-transport auto|cdp|playwright`
selects how the browser is reached. `auto` is the default: it takes Playwright when Playwright is
importable and can attach, and falls back to CDP otherwise. `cdp` is stdlib-only and is what the
qualification run recorded below actually used.

Several things are worth knowing about this surface specifically.

**The reply is the answer to *our* turn, on *our* thread.** Three independent things establish
that, and all three travel in the anchor the kernel persisted:

- the **conversation id** — the page must be the thread the message went to, or `receive`
  refuses with `END_WORKSPACE_MISMATCH` and does not rebind. The browser is yours: a second tab
  or a click on another thread is an ordinary event, and the transport matches on *origin*, not
  on conversation.
- **the page's own id for our user turn** — the reply is the assistant turn that *follows* it.
  `manages_lifecycle` is false, so you may keep using the thread; if you ask your own question
  while the relay waits, your answer is not mistaken for the Orchestrator's. The id is captured
  by waiting for one that *differs* from the turn present before the submit, so a slow render
  cannot anchor the exchange to somebody else's message.
- a **refusal ledger** — a turn already judged incomplete is not accepted later unchanged. A
  stream that dies mid-token loses its stop affordance and stops mutating, so it satisfies every
  completion check *better* than a healthy one; only text that genuinely moved on is accepted.

**Identity comes from the page when the page supplies it.** ChatGPT attaches a `data-message-id`
to every rendered turn, and that native id becomes the relay's message id. When a build stops
supplying them, the id is minted deterministically from conversation + turn index + a content
key, so it still recomputes identically after a restart.

**The DOM is a rendering, not a transcript.** Two matchers derived from rendered text were tried
and both failed against the real page, for the same underlying reason:

- the **message count** stops rising once the thread virtualises (below), and
- a **content key** over the turn's text does not survive the markdown renderer. Measured on the
  4339-char opening charter — which necessarily contains a fenced block, because the charter is
  what teaches it — our key was `8857ba87` and the DOM's was `48c189de`, diverging exactly at
  the fence, because `innerText` omits the backticks.

So identity comes from the vendor's ids wherever they exist. The content key survives only as a
fallback for a build that attaches none, and `provenance.anchored_by` records which one actually
applied — `user_turn_id` or `user_turn_content_key` — so a reader is never left guessing which
guarantee held.

**The anchor travels through the ledger.** `send` records what was on screen *before* submitting
— the last assistant message's id, and the assistant count as a fallback — inside the receipt's
`native_id`. The kernel persists it and hands it back to `receive`. So a restarted relay asks the
same "newer than what?" the dead one was asking, and cannot re-read the previous answer as new.
An in-memory counter would have reset to zero.

**The DOM is a window, not the thread.** ChatGPT *virtualises* a long conversation: it renders
only the most recent turns, so the assistant count **plateaus** as new turns push old ones out.
Measured on 2026-08-30, a thread with six user turns rendered three. Two consequences, both of
which were live defects before they were fixed:

- "a new message exists" cannot be `count > baseline`, because the count stops rising and the
  relay waits out its whole timeout with the answer on screen. The relay path instead locates
  its own user turn and takes the turn after it (above), which is immune to the plateau; the
  last-assistant-id test and then the count remain as fallbacks for a ledger or a page build
  that cannot supply better.
- `holds()` cannot read "not in the DOM" as "not in the thread". It compares the rendered user
  turns against the deliveries this relay has recorded for the conversation, and **refuses** —
  rather than answering "no" — whenever it is only seeing a window. A miss in a virtualised list
  is not evidence of absence, and guessing would re-send an instruction the model is already
  acting on.

**Reconciliation asks the page — the right page.** `holds()` navigates to the conversation the
delivery went to before reading it, and refuses if the browser cannot be brought there. Subject
to the window rule above it then looks for the user turn the relay sent, matched on the id the
page gave it. A delivery recorded *without* an id, on a page that does supply them, is refused
rather than matched by the weaker key.

Where the content key is still used — a page attaching no ids — it is computed identically in
JavaScript and in Python over an explicit whitespace table, because `\s` is not the same set in
the two languages and a stray byte-order mark was enough to make the same landed turn hash two
different ways.

It also distinguishes three states a local record can be in. *No such delivery* in a readable
record is evidence the submit was never reached. A record that is **missing**, **unreadable**, or
was **never configured** is not evidence of anything, and is refused — the record is written
before every submit (and fsynced), so its absence means it was lost, not that nothing was sent.

---

## Quick start

Relay Mode needs an execution agent server the **operator** starts. Quaestor attaches to it; it
does not own its lifetime.

```bash
# 1. In the project, once, in its own terminal:
opencode serve --port 4096

# 2. Check that a relay could actually run right now. Every line is MEASURED.
quaestor relay doctor \
  --project . \
  --orchestrator openai-chat \
    --orchestrator-base-url https://openrouter.ai/api/v1 \
    --orchestrator-model anthropic/claude-sonnet-5 \
    --orchestrator-key-var OPENROUTER_API_KEY \
  --agent opencode --agent-base-url http://127.0.0.1:4096 \
    --agent-model anthropic/claude-sonnet-5

# 3. Start the relay.
quaestor relay start \
  --project . \
  --objective "The migration test fails on Postgres 16. Diagnose it, fix it, and prove it." \
  --orchestrator openai-chat \
    --orchestrator-base-url https://openrouter.ai/api/v1 \
    --orchestrator-model anthropic/claude-sonnet-5 \
    --orchestrator-key-var OPENROUTER_API_KEY \
  --agent opencode --agent-base-url http://127.0.0.1:4096 \
    --agent-model anthropic/claude-sonnet-5

# 4. From anywhere, at any time:
quaestor relay status --transcript
quaestor relay resume        # after a crash, a kill, or a machine restart
quaestor relay stop
```

To attach to a session you already have open rather than creating one, pass `--session-id ses_…`
(listed by `relay doctor`) or `--attach-latest --no-create-session`.

Credentials: `--orchestrator-key-var` names an environment variable. `--orchestrator-key-file`
plus `--orchestrator-key-field` reads a key another tool already stored, so a credential you have
already provisioned does not have to be re-entered into shell history. The value is used in one
header and is never written to the relay's state, its events, or its transcript.

**Budgets, ceilings, and the authority profile.** `relay start` and `relay resume` both take
`--max-exchanges` (default 40), `--max-duration` (seconds, default 3600), `--receive-timeout`
(seconds a single turn may take, default 600) and `--max-steps` (stop after N half-exchanges;
`0`, the default, runs to a terminal state). A slice that ends `MAX_EXCHANGES_REACHED` ran out of
ceiling, not out of health. `--profile` selects the authority profile the relay runs under
(default `STANDARD_EDIT`), and `--relay-id` names the relay so a later `status`, `resume` or
`stop` can target this one. `--no-observe` (`relay start` only) turns off independent repository
observation and is **not recommended**: the Orchestrator then hears only the agent's account of
its own work, which is the single thing this design refuses to rely on. `relay status` takes
`--relay-id`, `--project`, `--all`, `--events N` and `--transcript`.

---

## What the two sides actually see

Ordinary engineering dialogue stays ordinary prose. There is no directive schema, because forcing
every turn through one would make the conversation worse and buy nothing.

**The Orchestrator** gets a charter once (who it is, who the agent is, what the relay will and
will not do), then, after every agent turn, a bounded packet:

```text
[relay exchange 6 | execution session ses_faf7ae…]

--- WHAT THE AGENT SAID ---
…the agent's turn, verbatim, up to a stated cap…

--- WHAT THE REPOSITORY SHOWS ---
Repository observed independently: working-tree entries now dirty: report.py, test_ledger.py.

Reply with your next instruction for the agent, or with RELAY-OBJECTIVE-COMPLETE …
```

The repository line is measured by **this process's own git**, before and after the agent's turn.
The agent's `/vcs/status` and session diff endpoints are deliberately *not* used: evidence
supplied by the party it describes is not evidence. When the agent's account and the reading
disagree, the Orchestrator is told to believe the reading.

**The Execution Agent** gets the Orchestrator's message verbatim, with a small identity header
and (on the first turn) a note explaining that its reply is relayed back automatically — so it
does not end its turn asking a human to carry a message.

---

## Governance: gate the act, not the sentence

A model can never widen its own envelope by choosing a sentence. Authority comes from two places
a model cannot write: the **authority profile** the operator started the relay under, and a live
**owner grant** corroborated by an authenticated owner channel.

Three gates:

**1. The profile ceiling — once, at start.** Pointing a `READ_ONLY` relay at an execution agent
that can edit the repository is refused before the first message moves, not discovered at
exchange nine.

**2. The directive gate — per message.** An Orchestrator that genuinely needs an effect beyond
editing files asks for it with a fenced block:

````text
```quaestor-effect
effect: GIT_COMMIT
```
````

Asking is not receiving. The request is mapped onto capabilities and run through
`core.authority.require`; `OWNER_REQUIRED` becomes an owner hold, the relay stops, the directive
is **recorded but never delivered**, and a human is asked. An effect class this build does not
model is refused rather than ignored. Prose asserting authority — "I authorise this", "you may
now push" — moves nothing, because it is not the channel.

**3. The observation gate — after the fact.** This is the gate that still works against an agent
nobody can confine. It does not ask the agent what it did; it compares two independent readings
of the repository and holds when the difference implies a capability the profile does not carry.
We cannot *prevent* an unconfined agent from running `git push`. We can refuse to instruct it to,
and we can detect that it happened and stop. Claiming prevention we do not have would be the
dishonest option.

**Record first, hold second.** A gate never fires before the turn that triggered it is durable.
An operator interrupted about an effect must be able to read the work that produced it, and a
later resume must have something to hand the Orchestrator.

---

## What crosses, and what does not

An execution agent has read your repository, your environment and your logs, and its turn is
about to be sent to a remote provider. "It came from the model" is not a reason to forward a
credential — so every message crossing the relay, in both directions, goes through
`core.classification` first.

Only credential-shaped and host-path-shaped spans are replaced, each with a visible marker
(`<secret-withheld:openai_key>`, `<path-withheld>`), and the sanitised form is what gets
persisted — the platform's rule is that a credential is never written to durable storage, and
the relay's ledger and event log obey it. Blanket redaction would be the wrong answer in the
other direction: an Orchestrator reasoning from sentences with holes in them makes worse
decisions, and the engineering content is the entire point of the conversation.

This is depth, not the boundary. It is a pattern classifier, so a novel secret format will pass;
the boundary is that the relay never routes a credential value through prose in the first place.

---

## Capability is not assurance

`adapters.registry` carries one `write_capable` boolean read in two incompatible senses: "cannot
mutate a repository" and "we cannot prove confinement". Relay endpoints separate them.

```text
CAPABILITY -- what the endpoint does        PROOF -- what this build can demonstrate
  can_send                                    proves_message_identity
  can_receive                                 proves_workspace_identity
  can_observe                                 proves_capability_surface
  can_mutate_repo                             proves_readonly_behavior
  manages_lifecycle                           proves_confinement
  supports_session_resume
  supports_conversation_resume
```

Assurance is **computed** from the proof facts through the existing `adapters.assurance` ladder
(`OBSERVED < DIALOGUE < MANAGED < GOVERNED < CONFINED`) and is never declared by an endpoint about
itself. So the OpenCode endpoint reports, truthfully and simultaneously:

```text
can_mutate_repo          = yes      it really does edit files
proves_workspace_identity= yes      the server agrees which worktree this is
proves_confinement       = no       it runs on the host with your permissions
computed assurance       = DIALOGUE
```

A weak proof lowers assurance. It does not erase a real capability, and it is not a reason to
refuse a useful integration.

---

## A completion claim is not a completion

The Orchestrator ends a relay by writing `RELAY-OBJECTIVE-COMPLETE`. That sentence used to stop
the relay by itself, which put the model in charge of grading its own homework: the party
declaring the work finished is the party that did not do it, cannot see the repository and
cannot run a test. A live qualification run proved the point rather than predicting it — the
Orchestrator declared the objective met while the fixture's own suite was still failing.

So the marker is now a **claim**, and the claim is measured before it is believed:

```bash
quaestor relay start ...   --verify "python -m unittest discover"   --verify "python check_static.py"   --require-repo-change
```

Each `--verify` command is run **by the relay, in this process, in the authorised project** —
never by asking the agent whether the agent's work is correct. The verdict is one of four, and
only the first two let the relay finish:

| verdict | meaning |
|---|---|
| `CORROBORATED` | every check ran and agreed with the claim. The relay stops `OBJECTIVE_COMPLETE`. |
| `UNCONFIGURED` | no corroboration was configured, so nothing measured the claim. The relay stops `OBJECTIVE_COMPLETE` and records the claim as **UNVERIFIED** — an honest label, not a passing one. |

The marker only counts as a claim when it is the **last line** of the turn, which is what the
charter asks for. A substring test could not be used: every packet the relay sends the
Orchestrator ends by naming the token verbatim to teach the protocol, so the model is handed the
trigger string on every turn — and a turn reading *"I am NOT writing `RELAY-OBJECTIVE-COMPLETE`
yet"* used to end the relay at exchange 1 having delivered no instruction at all.
| `REFUTED` | a check disagreed. The relay does **not** stop, and the failing check's own output rides back to the Orchestrator as a blocker so it can act on what actually failed. |
| `UNMEASURABLE` | a check could not be run at all. Never read as passing; treated like `REFUTED`. |

A model that keeps re-asserting completion is bounded: after `--completion-attempts` refusals
the relay stops as `COMPLETION_UNCORROBORATED`, which is deliberately **not**
`OBJECTIVE_COMPLETE` — a human reading the stop reason can tell the difference between "done"
and "kept saying it was done". The refusal count is read from the durable event log, so a relay
cannot forget its refusals by crashing.

Configure the checks. Without them Relay Mode still works, and it will tell you honestly that
nobody checked.

---

## One bad turn is not a dead endpoint

An endpoint that returns a truncated turn and an endpoint that has died used to be the same
outcome, so a single incomplete reply ended an otherwise healthy slice — observed live, at
exchange 8 of a planned 30.

The relay now asks the endpoint which it is. If `status()` says the endpoint is still usable,
the **receive** is retried up to `--incomplete-retries` times; if it says otherwise, there is no
retry, because retrying a corpse is pointless.

Two properties hold on every attempt:

* **The partial is never forwarded.** Not on the first attempt, not on the last. A streamed
  half-sentence delivered as an instruction is how a relay produces confident nonsense.
* **Only the receive is retried — never the send.** Re-reading an endpoint is idempotent;
  re-sending is how bounded recovery would quietly become duplicate delivery. The anchor does
  not move between attempts.
* **A retry re-asks; it never resumes mid-sentence.** An endpoint must not record an incomplete
  turn in its own transcript, or the retry is answered as a *continuation* and only the tail
  arrives. Measured on `openai-chat` before this was fixed: a directive reading *"Do not touch
  `tests/current` … once you are confident,"* was retried and delivered as *" delete the stale
  fixture files"* — the guardrail gone, and no copy of it anywhere in the ledger.

Exhaustion stops as `EXECUTION_INCOMPLETE` / `ORCHESTRATOR_INCOMPLETE`, distinct from
`*_DISCONNECTED`: one is a provider that will not finish a sentence, the other is a provider
that is not there.
---

## "The endpoint is fine" is not "the model works"

`status()` answers a narrow question: is this endpoint's **local** situation healthy — is there a
credential, is a server listening, is a page attached. It cannot see past its own gateway, and
two live runs showed what that costs:

* an `openai-chat` gateway returning `HTTP 503` to every request, while `status()` said `IDLE`
  because it makes no network call at all;
* `opencode/nemotron-3-ultra-free`, which errors on every inference while the server, the
  session and the model catalogue are all perfectly healthy.

In both, an unusable **model** and a dead **endpoint** were the same thing to the kernel, so the
operator learned at exchange 1 and was told the wrong cause.

So an endpoint may also be **probed** — asked for one real turn:

| verdict | meaning |
|---|---|
| `PROBE_OK` | a turn came back; the provider path works end to end |
| `PROBE_UPSTREAM_FAILED` | reachable, and the request failed *above* it — 5xx, 429, a timeout |
| `PROBE_REFUSED` | the provider answered and refused this model or credential; retrying will not help |
| `PROBE_UNSUPPORTED` | this endpoint cannot be probed without a side effect the operator did not ask for. **Honest, never passing** — nothing was measured, so nothing is claimed |

`relay doctor` reports it beside the preflight, because they answer different questions:

```console
$ quaestor relay doctor --orchestrator openai-chat --orchestrator-model no-such-model-xyz ...
preflight ok : True | CREDENTIAL_ACCEPTED
probe state  : PROBE_REFUSED | ok: False | measured: True
detail       : the provider refused this request with HTTP 401: ... "type":"ModelError" ...
```

`relay start` refuses on a measured failure rather than discovering it at exchange 1, stopping as
`ORCHESTRATOR_MODEL_UNUSABLE` / `EXECUTION_MODEL_UNUSABLE` — deliberately **not** `*_DISCONNECTED`,
which would send the operator to restart a server that was never the problem. `--no-probe` opts
out; a relay that skipped the probe never claims it passed.

The probe also runs when a turn arrives incomplete, which is what separates *"this provider will
not finish a sentence"* from *"this provider is down"*. Without it the relay spent its whole
retry budget re-reading an endpoint that could not answer, and then blamed the endpoint.

**A probe never disturbs the conversation.** `openai-chat` builds a throwaway request and
discards the reply, so the transcript it resumes from is untouched; `opencode` probes in a
scratch session bound to a temp directory, so the agent cannot reach the authorised repository.
ChatGPT Web **declines** — the only place to submit a probe there is the operator's own thread,
and a probe that posts into the conversation it protects has cost more than it measured.

### What the probe measured, live

| endpoint · model | `preflight` | `status()` | `probe()` |
|---|---|---|---|
| `opencode/mimo-v2.5-free` | ok | — | **`PROBE_OK`** (5.2s) |
| `opencode/nemotron-3-ultra-free` | **ok** | — | **`PROBE_UPSTREAM_FAILED`** |
| `openai-chat` · `nemotron-3.5-lightning-free` | ok | `IDLE` | **`PROBE_OK`** (13.3s) |
| `openai-chat` · `no-such-model-xyz` | **ok** | **`IDLE`** | **`PROBE_REFUSED`** (`ModelError`) |

The two bold rows are the point: `preflight` passed and `status()` said `IDLE` for a model that
does not exist and for one that cannot answer. Evidence in
`var/relay-qualification/probe-live.json`.

### What an independent review of the probe found

Reviewed adversarially before merge — 8 lenses, every finding then put to two skeptics who
defaulted to refuting it. 13 findings died there; these survived and are fixed:

| | was | now |
|---|---|---|
| `relay doctor` | reported `ready: true` and exit 0 for a configuration `relay start` would refuse | ready includes the model; the two answers stay separate in `ready_detail` |
| a probe on a recorded conversation | `registry.probe` closed an end it never opened, and `close()` **saves** — a transcript of 7 turns became `{"turn": 0}` | closes nothing it did not open |
| a transient `503` during retry | any measured probe failure stopped on attempt 1, collapsing `--incomplete-retries` to zero | only a **`PROBE_REFUSED`** (permanent) short-circuits; an upstream fault is still retried |
| a dead endpoint mid-retry | stopped `*_MODEL_UNUSABLE`, with a detail claiming it was "locally healthy" | liveness is checked first, as `start()` always did |
| probe detail | carried the provider's raw error body — credentials and host paths included — into the durable log | classified at construction, in `EndProbe` itself |
| `--no-probe` | not persisted, so a resume silently turned probing back on | persisted with the relay, like the completion policy |
| the probe request | hard-coded `max_tokens: 1`, a shape the real turn never sends | sends what `receive()` sends |
| a full disk / unwritable `TMPDIR` | reported as `PROBE_REFUSED` — "your model was rejected" | `PROBE_UNSUPPORTED`: nothing was asked, so nothing is claimed |
| a bare model name | fabricated a vendor `send()` explicitly refuses to guess | refuses with the same message `send()` gives |

Two findings are tracked rather than fixed here: `quaestor-pb8` (`resume` performs no probe, so
the start-time guarantee is bypassed by the documented recovery command — a real design question
about cost) and `quaestor-7z1` (the opencode probe has live evidence but no regression control).

One honesty note: which *failing* verdict `nemotron-3-ultra-free` draws depends on how the
provider fails that minute — it has been seen both as an immediate `APIError` (`PROBE_REFUSED`)
and as a silent timeout (`PROBE_UPSTREAM_FAILED`). The refusal is reliable; the sub-classification
is a reading of the provider's behaviour at that moment, not a promise.


---

## Recovery

Relay Mode survives being killed. Two durable facts make that work, and both are written
**before** the thing they describe:

- **`DELIVERING`** is written before the send. A crash between the send and the acknowledgement
  leaves that row as evidence.
- **`awaiting_message_id`** is written before the wait. A relay spends nearly all of its
  wall-clock time waiting for a slow agent turn, so that is where a kill lands.

On `relay resume`:

1. Both endpoints re-attach to the identities the record names. An endpoint that cannot resume
   answers `RESUME_UNSUPPORTED` and **that answer is recorded as such** — continuity the
   transport does not provide is never fabricated.
2. Every `DELIVERING` row is **reconciled by asking the endpoint** whether it already holds the
   relay-assigned id. Already held → confirmed, never re-sent. Not held → re-sent exactly once.
   Cannot answer → the relay stops with `UNRECONCILABLE_DELIVERY` and a human decides. Choosing
   silently between duplicating work in somebody's repository and dropping it is worse than
   saying "I do not know".
3. An outstanding turn is **collected, not re-issued**: the same anchor is picked back up and the
   reply the endpoint has been holding is read.

This works for OpenCode because `prompt_async` accepts a **caller-supplied message id**, so
reconciliation is a lookup rather than an inference — and because the prompt is fired
asynchronously, the agent keeps working while the relay is dead. An endpoint that cannot answer
"do you already hold this?" must not define `holds` at all; the kernel then stops instead of
guessing. And *failing to ask* is never recorded as "no": a transport error during
reconciliation propagates, because reading it as "the endpoint does not have it" would re-send a
message the agent may already be acting on.

---

## Live qualification

Unit controls prove the kernel's mechanics. They are **not** evidence that Relay Mode works, and
the repository keeps the two apart:

- `tests/test_relay_kernel.py` — controls 246–263 and 273, scripted endpoints, real git fixtures.
- `tests/test_relay_chatgpt_end.py` — controls 264–272 and 274–283 over the ChatGPT Web
  `OrchestratorEnd`. No control there opens a browser or touches the network: each drives a fake
  transport whose `evaluate` answers the endpoint's own JavaScript from a scripted page model.
- `tests/relay_live_harness.py` — opt-in, spends real provider capacity, attaches to a real agent
  server, edits a real repository, kills itself mid-turn, and writes an evidence file answering
  each acceptance question from measurement rather than from a claim.

Control ids are declared in the modules themselves, and the executed set is what
`python run_tests.py` reports; do not take the ranges above as a count.

The harness is configured entirely from the environment, and reads exactly these names
(`config_from_env`, `tests/relay_live_harness.py`):

```bash
# THE SWITCH. Without it the harness refuses: a live run spends real provider capacity.
export QUAESTOR_RELAY_LIVE=1

# WHICH ORCHESTRATOR SURFACE. One harness on purpose -- the kernel cannot tell a browser-hosted
# Orchestrator from an HTTP one, so the qualification that proves it is not a second copy.
export QUAESTOR_RELAY_ORCH_KIND=openai-chat     # or chatgpt-web   (default: openai-chat)

# ORCHESTRATOR: openai-chat
export QUAESTOR_RELAY_ORCH_BASE_URL=…  QUAESTOR_RELAY_ORCH_MODEL=…
export QUAESTOR_RELAY_ORCH_KEY_VAR=…            # ...or the pair below instead
export QUAESTOR_RELAY_ORCH_KEY_FILE=…           # JSON another tool already wrote
export QUAESTOR_RELAY_ORCH_KEY_FIELD=…          # dotted field inside that file

# ORCHESTRATOR: chatgpt-web
export QUAESTOR_RELAY_BROWSER_ENDPOINT=http://127.0.0.1:9222   # unset falls back to this
export QUAESTOR_RELAY_BROWSER_TRANSPORT=cdp     # auto | cdp | playwright   (default: auto)
export QUAESTOR_RELAY_CONVERSATION_ID=…         # optional: bind an existing thread

# EXECUTION AGENT
export QUAESTOR_RELAY_AGENT_BASE_URL=http://127.0.0.1:4096     # this is the default
export QUAESTOR_RELAY_AGENT_MODEL=<provider>/<model>

# WHERE IT BUILDS. Fixture repositories and the harness's own relay database.
export QUAESTOR_RELAY_WORKDIR=…                 # default: var/relay-live under the checkout

# THE HARNESS'S OWN BUDGETS (these are not the `relay start` defaults).
export QUAESTOR_RELAY_MAX_EXCHANGES=40          # default 40
export QUAESTOR_RELAY_MAX_DURATION=1800         # seconds, default 1800
export QUAESTOR_RELAY_RECEIVE_TIMEOUT=300       # seconds, default 300

python -m tests.relay_live_harness            # slice | restart | hold, or all three
```

Evidence lands in `var/relay-qualification/<stamp>.json`.

### The qualification record — 2026-08-29

Measured, on Windows 11, against a real provider and a real agent server.

| Question | Answer |
|---|---|
| Real Orchestrator? | yes — `openai-chat` / `hy3-free` over `https://opencode.ai/zen/v1`, conversation `conv-7e51a7b7c3b4` |
| Real browser? | no — not applicable; no browser-hosted Orchestrator is implemented yet |
| Real Execution Agent? | yes — `opencode`, live session `ses_faf6ee50effeJqjeBb0hbDvolV`, model `opencode/mimo-v2.5-free`, computed assurance `DIALOGUE` |
| Real repository? | yes — a git fixture the harness built and committed |
| Meaningful exchanges? | **19 delivered, 9 round trips**, stop reason `OBJECTIVE_COMPLETE` |
| Manual copy/paste? | **none** — and no manual relay commands after `start` |
| Repository changed? | yes — 5 files, +45 / −4 |
| Independently observed? | yes — 19 observation rows from this process's own git probes, 6 recording real change |
| Work actually correct? | the fixture's own suite, run by the harness: **7 tests failing before, 8 passing after** |
| Restart/recovery? | yes — killed at exchange 2 *while awaiting the agent's reply*; a new process re-bound the conversation and **re-attached to the same live session**, collected the outstanding turn, and continued to exchange 5 |
| Duplicates prevented? | yes — `duplicate_native_ids: []`, `redelivered_message_ids: []` |
| Owner hold? | yes — a real Orchestrator asked for `GIT_COMMIT` under `STANDARD_EDIT`; the relay entered `OWNER_HOLD`, **0 messages reached the agent**, and `HEAD` was unchanged |

A second live run, against a different fixture, reached **17 exchanges across a `relay resume`**,
completing work the first process had not finished before it was stopped.

### The ChatGPT Web qualification record — 2026-08-30

Same harness, on the code as it ships after adversarial review. Real signed-in browser, real
OpenCode session, real fixture repository. Evidence:
`var/relay-qualification/20260830T022233.json` — every number below is transcribed from it.

To reproduce it: start the browser and sign into it as shown under **ChatGPT Web** above, start
`opencode serve`, then run the harness with `QUAESTOR_RELAY_ORCH_KIND=chatgpt-web`,
`QUAESTOR_RELAY_BROWSER_ENDPOINT` pointed at that browser's debug port,
`QUAESTOR_RELAY_BROWSER_TRANSPORT=cdp`, and `QUAESTOR_RELAY_AGENT_BASE_URL` /
`QUAESTOR_RELAY_AGENT_MODEL` pointed at the agent server. The `_ORCH_BASE_URL`, `_ORCH_MODEL` and
key variables are not used to build the Orchestrator on this path — the browser session the
operator already established is the credential, and Quaestor never handles it.

| Question | Answer |
|---|---|
| Real authenticated ChatGPT browser? | **yes** — page state `COMPLETE`, transport `cdp` (stdlib only) |
| Real ChatGPT conversation? | **yes** — `6a93c7ff-2558-83e9-8601-0545f009d727` |
| Real OpenCode session? | **yes** — attached to a running `opencode serve` |
| Meaningful delivered messages? | **30**, of which **15 round trips** |
| Distinct Orchestrator message ids? | **15 / 15**, identity source `page_message_id` throughout |
| Stale replies forwarded? | **0** |
| Partial replies forwarded? | **0** |
| Manual copy/paste? | **0**; zero relay commands after `start` |
| Repository changed? | **yes** — 3 files, +8 / −4, observed independently 31 times |
| Work actually correct? | the fixture's own suite: **failing before, 7 passing after**, re-run here rather than believed |
| Restart/rebind? | **yes** — killed at exchange 2 *while awaiting the agent*; re-bound to the **same ChatGPT conversation** `6a93cb7b-…` and the **same OpenCode session** `ses_faead1de7ffee…`; the outstanding turn was collected, not re-sent; `duplicate_native_ids: []`, `redelivered_message_ids: []`; continued to exchange 5 |
| Owner hold? | **yes** — an observed `GIT_COMMIT` under `STANDARD_EDIT` halted the relay; `HEAD` unchanged |
| Billing path? | **UNVERIFIED**, permanently — a browser session carries no evidence of which plan is paying |

The slice stopped at `MAX_EXCHANGES_REACHED`: it ran out of configured ceiling, not out of
health. The ceiling is `--max-exchanges` on `relay start`, or `QUAESTOR_RELAY_MAX_EXCHANGES` under
the harness; this run was configured at **30**, which is what its evidence file records, not the
default of 40.

#### What the execution end costs you

An earlier attempt at this same run, on this same code, ended at 8 exchanges with
`EXECUTION_DISCONNECTED`: the free-tier execution model returned an incomplete turn and the relay
**paused rather than forward a partial**. That is the machinery working. But it means a slice's
length is bounded by the flakiest model in it, and a single bad turn currently ends the slice
instead of costing one retry. Two observations worth keeping:

* `opencode/mimo-v2.5-free` completes the fixture objective but glitches intermittently.
* `opencode/nemotron-3-ultra-free` answers a bare `PONG` probe with an `APIError`; pointed at a
  relay it disconnects on the first turn. An unusable model is indistinguishable, from the
  kernel's side, from an execution end that died — see the bounded-retry issue.

#### Historical: the earlier attempt on the same code — 2026-08-30 01:44

Superseded by the record above and kept for comparison, not as the current qualification. This is
the `EXECUTION_DISCONNECTED` run the paragraph above describes. Evidence:
`var/relay-qualification/20260830T014458.json`.

| Question | Answer |
|---|---|
| Real authenticated ChatGPT browser? | **yes** — page state `COMPLETE`, transport `cdp` (stdlib only) |
| Real ChatGPT conversation? | **yes** — `6a93bfe8-6d78-83e9-a759-20f223663997` |
| Real OpenCode session? | **yes** — attached to a running `opencode serve` |
| Meaningful delivered messages? | **8**, of which **4 round trips** |
| Distinct Orchestrator message ids? | **4 / 4**, identity source `page_message_id` throughout |
| Stale replies forwarded? | **0** |
| Partial replies forwarded? | **0** |
| Manual copy/paste? | **0**; zero relay commands after `start` |
| Repository changed? | **yes** — 5 files, +45 / −4, observed independently 8 times |
| Work actually correct? | the fixture's own suite: **5 failures across 7 tests before, 8 tests all passing after** — all six objective items, including the README section |
| Restart/rebind? | **yes** — killed at exchange 2 *while awaiting the agent*; re-bound to the **same ChatGPT conversation** and the **same OpenCode session**; outstanding turn collected; `duplicate_native_ids: []`, `redelivered_message_ids: []`; continued to exchange 5 |
| Owner hold? | **yes** — an observed `GIT_COMMIT` under `STANDARD_EDIT` halted the relay; `HEAD` unchanged |
| Billing path? | **UNVERIFIED**, permanently — a browser session carries no evidence of which plan is paying |

The slice's stop reason is `EXECUTION_DISCONNECTED`, not `OBJECTIVE_COMPLETE`: after the work was
finished the **execution** end returned an incomplete turn and the relay paused rather than
forwarding a partial. That is the machinery behaving correctly against a flaky free-tier model,
and it is an execution-end limitation, not a ChatGPT one — the Orchestrator side delivered four
clean turns with no stale or partial replies. The run below, on the same surface before the
review hardening, reached **30 exchanges / 15 round trips**, so the exchange ceiling is not the
constraint here; the execution model's reliability is.

#### Historical: the pre-hardening run — 2026-08-30 00:23

Superseded, and on the code as it stood **before** the adversarial-review hardening. Evidence:
`var/relay-qualification/20260830T002350.json`.

| Question | Answer |
|---|---|
| Real authenticated ChatGPT browser? | **yes** — page state `COMPLETE`, transport `cdp` (stdlib only) |
| Real ChatGPT conversation? | **yes** — `6a93ae02-423c-83ea-90e9-d181943a84ad` |
| Real OpenCode session? | **yes** — attached to a running `opencode serve` |
| Meaningful delivered messages? | **30**, of which **15 round trips** |
| Distinct Orchestrator message ids? | **15 / 15** — identity source `page_message_id` throughout |
| Stale replies forwarded? | **0** |
| Partial replies forwarded? | **0** |
| Manual copy/paste? | **0**; zero relay commands after `start` |
| Repository changed? | **yes**, and observed independently **31 times** |
| Restart/rebind? | **yes** — killed at exchange 2 *while awaiting the agent*; re-bound to the **same ChatGPT conversation** and the **same OpenCode session**; outstanding turn collected, `duplicate_native_ids: []`, `redelivered_message_ids: []`; continued to exchange 5 |
| Owner hold? | **yes** — an observed `GIT_COMMIT` under `STANDARD_EDIT` halted the relay; `HEAD` unchanged |
| Billing path? | **UNVERIFIED**, permanently — a browser session carries no evidence of which plan is paying |

Two honest caveats about that run. The slice stopped on `MAX_EXCHANGES_REACHED` rather than
`OBJECTIVE_COMPLETE`, and the fixture's suite improved (5 failures → 3) without reaching green:
ChatGPT spent many turns re-verifying and reverting rather than completing items. An earlier run
of the same fixture did reach a fully passing suite. Relay *mechanism* was sound in both; the
Orchestrator's effectiveness varied, which is a property of the model, not of the relay — and is
the reason `quaestor-pr4.16` (corroborating a completion claim) stays open.

The owner hold in this run came from the **observation** gate rather than the directive gate, so
one directive had legitimately been delivered before the commit was observed. That is the
expected shape for a hold triggered by what the repository shows.

Maturity vocabulary, used deliberately throughout: `IMPLEMENTED` → `TEST_QUALIFIED` →
`LIVE_PROVIDER_QUALIFIED` → `LIVE_END_TO_END_QUALIFIED` → `PRODUCT_SUPPORTED`. Nothing in Relay
Mode is `PRODUCT_SUPPORTED` yet: there is no installer, no Quaestor Core service, no signed
distribution, no browser extension and no native messaging host. The only browser path that
exists today is CDP against a browser the operator started themselves.

### The corroboration record — 2026-08-30

The hole and the fix, in one run. `openai-chat` Orchestrator (`nemotron-3.5-lightning-free`)
driving a real OpenCode session over the fixture repository, with the fixture's own suite as the
`--verify` check. Evidence: `var/relay-qualification/20260830T044025.json`, and both verdicts
are in the relay's durable event log as `relay.completion.claim`.

| | claim 1 | claim 2 |
|---|---|---|
| `python -m unittest discover` | **exit 1** | **exit 0** |
| repository changed | **no** | **yes** |
| verdict | **`REFUTED`** | **`CORROBORATED`** |
| relay | **did not stop**; the failing output went back to the Orchestrator | stopped `OBJECTIVE_COMPLETE` with the evidence |

The first claim is the defect this closes: the Orchestrator declared the objective met against an
**untouched repository with a failing suite**. Before this change the relay would have stopped
`OBJECTIVE_COMPLETE` right there. A third `CORROBORATED` verdict was recorded after the relay was
killed and resumed, so corroboration survives recovery.

Verified independently rather than believed: the fixture's suite was re-run by hand afterwards —
8 tests, OK — against a diff of 5 files, +36/−4.

This run is short by design (3 exchanges, 1 round trip). Its subject is the corroboration
mechanism, not conversation length; the exchange bar is carried by the ChatGPT Web record above.

The same session's earlier run (`20260830T042757.json`) exercised the other new path for real:
the free upstream returned intermittent `HTTP 503`s, recorded as `relay.receive.incomplete` with
`endpoint_usable: true`. Two bursts were **retried and recovered** and the relay continued; two
exhausted the bound and stopped `ORCHESTRATOR_INCOMPLETE`. Before the change all four would have
ended the slice as `ORCHESTRATOR_DISCONNECTED`. That run also shows the limit worth naming:
`status()` reported `IDLE` while the upstream was failing, because the endpoint cannot see past
its own gateway — which is what the model-exercising preflight in `quaestor-nmq` is for.

### What an independent review of this code found

The Relay work was reviewed adversarially before merge — 15 attack lenses, every finding then
put to three skeptics who defaulted to refuting it. 24 findings died there; these survived and
are fixed, and each has a control so it cannot come back:

| | was | now |
|---|---|---|
| `resume` after an owner hold | re-delivered the refused directive, no grant consulted | the gate is **re-evaluated** against current authority; resuming is not approving |
| `resume` after a crash | rebuilt the completion policy from flag defaults, silently switching `--verify` off | the policy is persisted with the relay and restored from the record |
| `--require-repo-change` | satisfied by a tree that was **already dirty** before the relay started | compares the first reading with the last |
| a failing check's output | crossed to the remote Orchestrator and into the durable record **unredacted** | classified at the source, like every other text that crosses |
| an unreadable repository | the observation gate **allowed** it — the one place that read "could not ask" as "yes" | refuses; a turn that changed nothing still measures `READ_ONLY` |
| the completion marker | matched anywhere in the turn | must be the last line |
| a truncated turn | retried as a continuation, delivering only the tail | re-asked, so the whole turn arrives or the relay pauses |

The remaining findings are tracked rather than hidden: `quaestor-40q` (the browser endpoint
binds to the visible tab, with no origin check), `quaestor-tcb` (`--verify-timeout` is not a
ceiling when a check leaves a grandchild), `quaestor-q00` (push detection is blind to any ref
that is not the branch's upstream), `quaestor-cjx` (crash windows in the delivery ledger),
`quaestor-ld3` (a refusal is a permanent veto; the receive bound is wall-clock) and
`quaestor-tkn` (doc, control and bead corrections).

---

## Known limits

- **Confinement is not proven for any execution endpoint.** The agent runs on the host with the
  operator's permissions. Assurance says `DIALOGUE` and the limits are printed by
  `relay doctor`.
- **Lifecycle is not managed.** Quaestor attaches to an agent server the operator started. It
  cannot restart it, and `relay stop` marks the relay stopped without touching the agent.
- **Orchestrator conversation continuity is the relay's, not the provider's.** A
  chat-completions endpoint is stateless, so continuity comes from the transcript this platform
  persists. The endpoint says so in its own `limits`.
- **A bare model name has no vendor.** `provider_family` for `openai-chat` is derived from the
  `<vendor>/<model>` prefix. A gateway whose model ids carry no vendor prefix yields `""` — the
  honest answer, and one that will refuse a cross-vendor independence check rather than pass it
  by accident.
- **Tool permissions belong to the agent.** What the execution agent is allowed to run is its own
  configuration, not something the relay enforces.
- **One relay drives one conversation at a time.** That serialisation is deliberate: it is what
  makes duplicate-delivery reasoning tractable.
- **Completion corroboration is only as good as the checks you configure.** The relay now
  measures a completion claim rather than believing it, but it measures what you named with
  `--verify`. With nothing configured it records the claim as UNVERIFIED and stops anyway; the
  honesty is real, the verification is not. And a passing suite is still not proof the *right*
  work was done — corroboration answers "do the project's own checks agree?", never "was this
  the correct objective?". Deliberately: the alternative is an objective-understanding
  subsystem, which is a much larger and much less trustworthy thing.
- **The agent server caches an unresolvable directory.** Asking a running `opencode serve` about
  a path that does not exist yet returns worktree `/`, and that answer survives the directory
  being created. `relay doctor` reports `WORKSPACE_UNRESOLVED` with the remedy (restart the
  server) rather than the misleading `WORKSPACE_MISMATCH`.
- **No installer, no Quaestor Core service, no browser extension, no native messaging host, no
  signed distribution.** Relay Mode runs from a checkout. The productisation contract — Quaestor
  Core as a lightweight per-user service, the browser-extension → native-messaging path that a
  browser-hosted Orchestrator is supposed to reach the kernel through, and signed packaging — is
  [`PRD.md`](PRD.md) §3, §8.2 and §67.4. None of it is built.

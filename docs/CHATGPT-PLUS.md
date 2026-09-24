# ChatGPT from a regular Plus account

> **Scope.** ChatGPT is *one* Orchestrator surface, not the architecture. Relay Mode's kernel is
> provider-neutral and contains no ChatGPT-specific concept; this document covers the setup and
> safety details of the ChatGPT path specifically. For the shape everything plugs into, see
> [`RELAY-MODE.md`](RELAY-MODE.md). ChatGPT Web **is** available as a Relay `OrchestratorEnd`
> (`quaestor relay start --orchestrator chatgpt-web`) and is `LIVE_END_TO_END_QUALIFIED`: see
> [`RELAY-MODE.md`](RELAY-MODE.md), "The ChatGPT Web qualification record", and the measured
> harness records under `var/relay-qualification/`. The relay-qualified Orchestrators are
> `chatgpt-web` and `openai-chat` -- the OpenAI-compatible chat-completions protocol, which
> reaches OpenRouter, OpenAI and any compatible gateway.

## Three ChatGPT paths, and which one you are reading about

A ChatGPT account meets Quaestor in three different places. These are not variations of one
feature: they differ in who is in the loop, what may be written, and how far each has been
qualified.

| Path | What ChatGPT does | Written up in |
| --- | --- | --- |
| **Relay `OrchestratorEnd`** (`chatgpt-web`) | one conversation instructs an Execution Agent turn after turn, unattended after `relay start` except where governance halts it for an owner decision | [`RELAY-MODE.md`](RELAY-MODE.md) -- not this document |
| **MCP connector over a tunnel** | reads run and program state remotely; you are in the chat, and every write is one you run locally | this document, "The connector path" |
| **Program Mode `chatgpt-web` seat** | answers one strategist packet inside a run Quaestor is already directing: one packet in, one answer out, no writing seat | this document, "The `chatgpt-web` seat" |

The relay path is `LIVE_END_TO_END_QUALIFIED` and **not** `PRODUCT_SUPPORTED`, and the browser is
why. Reaching a ChatGPT tab today means a Chrome the operator started with
`--remote-debugging-port`. There is no browser extension, no native messaging host, no installer
and no signed distribution -- the same ladder, and the same standing, that
[`RELAY-MODE.md`](RELAY-MODE.md) records under "Live qualification".

**That debug port is the price.** Anything on the machine that can reach it drives the browser as
you: any tab, any cookie, any signed-in session in that profile, with no further prompt and no
record in the page. Chrome binds the port to loopback by default, so the exposure is every local
process rather than the network -- which is a real reduction and not an absence. Use a
`--user-data-dir` kept for this purpose only, start the browser when you need the seat, and close
it when the work is done.

---

# The connector path: ChatGPT reads Quaestor over a tunnel

Quaestor's MCP transport is reachable from a **Plus** (or Pro) ChatGPT account without any
Business/Enterprise feature. The trade is stated up front, because it is a design decision and
not a limitation we hid:

> **A remote ChatGPT caller gets the READ-ONLY surface. Every state change -- dispatch, decide,
> cancel -- happens through the local owner channel, where the attestation is.**

Full write actions from remote MCP clients are a Business/Enterprise/Edu capability on OpenAI's
side, and even where a plan allows them, this deployment would still not hand a write-capable
channel to a shared secret: the tunnel client is given a token that can only read.

---

## What you need

| Thing | Why |
| --- | --- |
| ChatGPT **Plus/Pro**, web | developer mode is a web feature; custom connectors are not on Free |
| `cloudflared` on PATH (or any HTTPS tunnel) | ChatGPT cannot reach `127.0.0.1`; the tunnel publishes your loopback server |
| A deployment home (`--home`) with at least one project | the transport serves what its repo aliases expose |

## 1. Start the tunnel

```powershell
# one-time, from the repository root -- installs the 'quaestor' command:
pip install -e .
cloudflared --version        # one-time: install from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

quaestor tunnel serve --repo myrepo="C:\path\to\your\project"
```

Output (once, at startup):

```json
{
  "connector_url": "https://something-random.trycloudflare.com/mcp",
  "remote_token": { "value": "tok_...", "note": "" },
  "surface": "read-only (remote channel)"
}
```

* `remote_token.value` is non-empty only when a token was **freshly provisioned**. It is shown
  exactly once. Save it; you will paste it into ChatGPT.
* The quick-tunnel hostname is **ephemeral** -- a new `tunnel serve` run may publish a new URL.
  Update the connector when it changes.
* Keep this terminal open. `Ctrl+C` stops both the tunnel and the server.

## 2. Connect ChatGPT

1. ChatGPT (web) -> **Settings** -> **Apps & Connectors** -> **Advanced settings** -> turn on
   **Developer mode**.
2. **Create** a connector:
   * **URL**: the `connector_url` from above
   * **Authentication**: bearer/token -- paste `remote_token.value`
3. The advertised tools are exactly: `search`, `fetch`, `orchestrator_status`,
   `orchestrator_result`, `program_status`, `program_inbox`. All are read-only.

## 3. Verify from outside

```powershell
quaestor tunnel doctor --url https://something-random.trycloudflare.com --token tok_...
```

`doctor` measures, from your side of the tunnel: health reachable, bearer enforced (a request
without the token gets 401), the token accepted, the advertised surface read-only, and no OAuth
metadata fiction. Every check must PASS.

## 4. How work actually gets requested

A Plus-tier ChatGPT can *see* everything and *change* nothing:

* It reads run records (`fetch`), searches them (`search`), inspects programs and inboxes.
* If it concludes work should happen, it says so in chat; **you** run the write locally:

```powershell
# Answer a strategist/owner question the inbox surfaced. --authority is CASE-SENSITIVE:
# STRATEGIST or OWNER, and nothing else parses. The vocabulary is declared once, in the
# parser, so a lowercase 'owner' is a named refusal rather than a quiet downgrade.
quaestor program answer <program_id> <message_id> --text "..." --authority OWNER

# Or dispatch a step directly. --worktree is REQUIRED and has no default: a run is bound
# to the one workspace it may write, and the CLI will not guess which.
quaestor dispatch --workflow ... --step ... --task "..." --worktree <path-to-worktree>
```

Local writes go through the same governed admission ladder as always -- authority profiles,
leases, drift checks, evidence -- and owner-authority answers still require the interactively
provisioned attestation key. The tunnel adds a window; it does not add a pen.

## Revoking access

```powershell
quaestor tunnel revoke
```

The remote token is deleted; every tunnel request fails authentication from that moment. The
loopback token (CLI, local tooling) is untouched. Rotate instead of revoke with `tunnel token`.

## Why the ceiling is a token and not a promise

The remote channel class comes from **which secret authenticated**, never from a header or an
argument. The write-capable loopback token never leaves the machine, so there is nothing a
remote caller can present that would widen its surface. Attempts are refused with
`REMOTE_READ_ONLY` and land in the ledger like every other refusal.

## Honest limits

* **Ephemeral URL.** Quick tunnels rotate hostnames. A stable hostname wants a named Cloudflare
  Tunnel (or Tailscale Funnel, or any reverse proxy you operate) -- `tunnel serve` accepts any
  tunnel that forwards HTTPS to the loopback port; only the `--cloudflared` default is baked in.
* **One shared secret.** A bearer token proves possession, not which ChatGPT user sent a
  request. On a single-owner deployment that is the correct strength; do not share the token
  across people.
* **Read-only is the feature.** If OpenAI's plan surface changes, the transport's own ceiling
  does not move with it: writes require the local channel by design, not by subscription tier.

---

# The `chatgpt-web` seat: driving a conversation directly

The connector path above is ChatGPT reading Quaestor: a human is in the chat, and the surface is
read-only. That path is unchanged and remains the recommended way to *think* in ChatGPT about a
program.

The seat below is Program Mode's, and it is **not** the Relay `OrchestratorEnd`. Both reach a
signed-in browser over the Chrome DevTools Protocol; what they do there differs. The seat answers
one packet inside a run Quaestor's own orchestrator is directing. The relay end lets the
conversation itself direct an Execution Agent across a whole slice. The seat is
`src/quaestor/executors/chatgpt_web.py`; the relay end is
`src/quaestor/relay/ends/chatgpt_web.py`, documented in [`RELAY-MODE.md`](RELAY-MODE.md).

This section is a different thing, added deliberately on 2026-08-27 at the repository owner's
direction: an **executor** that drives a real ChatGPT conversation in your own browser, so a
model can hold a Quaestor seat without you relaying anything.

> This document previously stated that the platform wanted no part of browser automation. That
> paragraph was removed on purpose, and this section replaces it, because a tree that ships a
> browser adapter while declaring it wants none is worse than either choice made honestly.

## What it does

Quaestor attaches to a Chrome you started and are already signed into, types a strategist packet
into a conversation, waits for the answer to genuinely finish, captures it, and returns it as an
ordinary run — same run files, same envelope, same evidence path as any CLI executor.

```powershell
# once: a Chrome with a debug port, using a profile you sign in to normally
chrome.exe --remote-debugging-port=9222 --user-data-dir="$env:LOCALAPPDATA\Chrome-Quaestor"
```

Then pin the seat in your manifest:

```yaml
executors:
  default: claude-cli
  roles:
    strategist: chatgpt-web
```

No browser-automation dependency is required: the default transport is the Chrome DevTools
Protocol over a stdlib-only WebSocket client. `pip install playwright` is optional — if it
imports, it is used instead for its better waiting primitives, and the run records which
transport was used.

## What it is not allowed to do

| | |
| --- | --- |
| Hold a writing seat | **Structurally impossible.** The kind is registered `write_capable=False`, so `resolve_seat` refuses it for `implementation` and `integration` however you pin it. It is a transport, and the routing table is what enforces that — not a docstring. |
| Prove how it was billed | **Never.** The preflight reports `UNVERIFIED` under every page state and will not report `subscription`, even though a subscription is almost certainly paying. A deployment enforcing `credential_modes={"subscription"}` therefore gets no proof from this seat, which is correct: an unverifiable claim must not satisfy a policy that exists to verify. `fact_status` stays `declared` permanently. |
| Count as a second opinion on GPT work | **No.** The kind is family `openai`, so it collides with `codex-cli` in `check_pairing`. A GPT implementation reviewed through a ChatGPT tab is one vendor reviewing itself; the browser is a transport detail. |
| Return a half-written answer | **No.** Completion requires three facts: a new assistant message above the pre-submit baseline, the generating affordance gone, and byte-identical text across three consecutive polls. On timeout, stdout is empty and the partial is written to `partial.txt` as evidence only. |
| Retry through a refusal | **No.** Signed out, selectors rotted, timed out, browser gone: each is a distinct named outcome, exactly one attempt, then it stops and escalates to you. |
| Evade bot detection | **Not built, and asserted absent.** No fingerprint or user-agent alteration, no CAPTCHA handling, no proxy rotation. A control parses the modules and scans their *code* (docstrings and comments stripped, so an honest explanation is not mistaken for an implementation). |

Quaestor never handles your ChatGPT credential. You sign in once, in your own browser window.

## Honest limits, and one alternative worth knowing

* **It will break.** The page is a third party's product, redesigned without notice and A/B
  tested between sessions. Every CSS selector in this codebase lives in one table —
  `chatgpt_web_page.SELECTORS` — and that is the first place to look when the seat stops working.
* **The debug port is a standing key to your browser.** A Chrome started with
  `--remote-debugging-port` takes instructions from any local process that can reach that port,
  as the signed-in you — the caution under "Three ChatGPT paths" above applies to this seat too.
* **Automating a chat product is between you and your provider's terms.** That is your call to
  make; this document does not make it for you.
* **There is a measured alternative for GPT-family work.** Codex CLI signed in with a ChatGPT
  plan gives you a GPT model in any seat, headless, billed to the same subscription — and unlike
  this seat, `codex_auth` *measures* that the login is subscription-backed rather than declaring
  it. If what you want is "GPT on my subscription, unattended", that path is sturdier and already
  supported. This seat exists for when you specifically want the conversation.

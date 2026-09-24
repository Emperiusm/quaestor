# Security policy

## Reporting

Please do not open a public issue for a vulnerability. Report it privately through GitHub's
**private vulnerability reporting**: the repository's *Security* tab → *Report a vulnerability*.
Include the affected commit, what an attacker needs (local process, network position, a
credential), and the smallest reproduction you have.

## What this platform actually defends

These are properties under automated test, not aspirations. Each maps to controls in `tests/`.

| Property | Enforced by |
|---|---|
| An executor cannot grant itself capability | authority engine + owner grants; a role confers nothing |
| A transport cannot grant authority | the MCP adapter makes no policy decision; it can only refuse earlier |
| No generic shell / exec / filesystem / docker / git / sql surface | a closed twelve-verb tool set with closed schemas, six of them read-only (`transports/mcp/schemas.py`, `TOOLS`); no verb accepts a caller-supplied path or command |
| No caller-supplied filesystem path | repositories are named by server-side alias |
| Credential values never reach core state, evidence, argv or a remote payload | allowlist-built remote objects; name-only env passthrough; leak scans with real needles |
| Auth fails closed and leaks no existence information | identical refusal for every failure mode, before any store is opened |
| At most one active execution per dispatch identity | durable dispatch key + unique partial index |
| No blind retry of an ambiguous write | reconciliation classifies; it never redispatches |
| A review cannot grade its own work | reviewers are read-only by role ceiling; review input excludes the executor conversation |
| A relay never re-delivers what an endpoint already holds | a durable delivery ledger reconciled against the endpoint's own `holds()`; killed mid-delivery it re-delivers exactly once what the endpoint does not hold, and an endpoint that cannot answer the question stops the relay rather than guessing between duplicating work and dropping it (controls 247, 248, 261, 262) |
| A partial or truncated endpoint turn is never forwarded as completed work | completion is decided before the turn is accepted, partial text never becomes the message text, and a turn already judged incomplete is not accepted later unchanged (controls 250, 269, 278) |
| A restarted relay cannot read an older answer as a new one | the receive anchor carries the pre-submit baseline through the durable record, a turn already in that record is never treated as new work, and the reply is anchored to the relay's own submitted turn (controls 249, 268, 277, 283) |
| Orchestrator prose grants no authority, and an owner-gated effect is held rather than delivered | profile plus owner channel decide; a declared effect request becomes an owner hold with the directive recorded and undelivered, an effect class this build does not model is refused rather than ignored, an owner-gated effect observed in the repository holds the relay even though nothing requested it, and binding a repo-mutating execution end under a profile without `repo_write` is refused before any message moves (controls 252–256) |
| The relay kernel imports no provider | the endpoint layer is reachable only through `relay/registry.py`, an unknown kind is a named refusal, and an import-graph control proves no relay core module mentions a browser (controls 257, 264) |
| Credential-shaped spans never cross from an agent turn to a remote orchestrator | redaction runs before the turn crosses, and the surrounding engineering prose survives it (control 263) |

The relay rows are executed by `tests/test_relay_kernel.py` (controls 246–263, 273) and
`tests/test_relay_chatgpt_end.py` (controls 264–272, 274–283). The control text each id asserts is
in `tests/controls.py`; `python run_tests.py` is what re-measures the whole set.

## What it does NOT defend

Stated plainly, because a threat model that only lists wins is marketing.

- **It does not authenticate a strategist.** Lane ownership is a *coordination* lease, not proof
  of identity. A caller who can forge an owner token can take a lane. Identity must come from the
  transport, and where the transport cannot supply it the record says `UNVERIFIED`.
- **It does not contain a hostile executor by itself.** Confinement is the sandbox provider's job.
  Without one, an executor has whatever access the host gives it.
- **`docker inspect` exposes injected environment.** Anyone who can query the daemon can read a
  variable passed to a container. Inherent to `--env`; closing it needs a secrets mount.
- **It does not protect against a compromised host.** Local-first means local trust.
- **A browser debug port authenticates nobody.** The only browser Orchestrator path that ships
  today is CDP against a Chrome the operator started with `--remote-debugging-port`
  (`executors/browser_transport.py`, default `http://127.0.0.1:9222`). That port has no
  authentication: any process running as the same user can attach to that browser, read the
  signed-in session and drive it. There is no browser extension, no native messaging host and no
  signed distribution — `docs/PRD.md` §8.2 names the extension plus a narrowly authenticated local
  IPC as the product path, and treats broad remote-debugging access as a development adapter
  rather than a public trust contract. Until that exists: keep the port on loopback, give it a
  dedicated browser profile rather than your daily one, and close that window when the relay
  stops.
- **Prompt injection is bounded, not solved.** Caller text is data — it cannot change policy,
  authority or mode — but a model that reads a repository can still be influenced by what it reads.

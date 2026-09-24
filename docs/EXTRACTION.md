# Extraction record

How this platform was separated from the project-specific implementation it grew inside, what was
preserved, what changed, and what was deliberately left undone.

## Method

A **strangler extraction**, not a move. The source repository was left intact and unmodified; this
one was built beside it and then had to prove it could run the original controls.

```
source repo (untouched)            this repo
    │                                  │
    ├──── copy ────────────────────────►  restructure into layers
    ├──── copy ────────────────────────►  scrub project / machine / provider coupling
    ├──── copy ────────────────────────►  port the qualification suite
    │                                  │
    │                                  ├──  add the new primitives
    │                                  └──  prove both example projects work unchanged
```

Nothing was deleted from the source. Equivalence had to be demonstrated first, and it is
demonstrated by the suite: **438 tests, 150 controls, 0 skipped, 0 failed** — measured at the
moment equivalence was shown, not a running total. `python run_tests.py` reports today's.

## Keep / move / rewrite matrix

| Component | Old location | New location | Classification |
|---|---|---|---|
| state machine, identity, store, lease, concurrency | `orchestrator/{domain,identity,store,lease,concurrency}.py` | `core/` | MOVE_AS_IS |
| dispatch, worker, reconcile, cancellation | `orchestrator/{dispatcher,worker,reconcile,cancellation}.py` | `core/` | MOVE_AND_GENERALIZE |
| authority | `orchestrator/authority.py` | `core/authority.py` | MOVE_AND_GENERALIZE — gained `EXEMPTIBLE_PROVIDER_ENV` so core owns the policy |
| handoff contract | `orchestrator/handoff.py` | `core/handoff.py` | MOVE_AS_IS — protocol string frozen |
| executor **contract** | `orchestrator/executor.py` | `core/executor_contract.py` | MOVE_AND_GENERALIZE — an interface belongs to core |
| executor **factory** | inside `orchestrator/worker.py` | `executors/registry.py` | REWRITE — inverted so core imports no provider |
| fake / Claude CLI / container executors | `orchestrator/{fake,cli,container}_executor.py` | `executors/{fake,claude_code,container}.py` | MOVE_AND_GENERALIZE |
| docker adapter, profile, confinement, egress | `orchestrator/{docker_adapter,container_profile,confinement,egress}.py` | `sandbox/` | MOVE_AND_GENERALIZE — names, labels and env from `branding` |
| repo probe, worktree stamp, host shell | `orchestrator/{repo,worktree_stamp,host_shell}.py` | `workspace/` | MOVE_AND_GENERALIZE |
| evidence, fingerprints, floors, test collector | `orchestrator/{evidence,fingerprints,floors,test_collector}.py` | `evidence/` | MOVE_AS_IS |
| MCP server / adapter / schemas / auth / ledger / redact / mode | `orchestrator/{mcp_*,transport_*}.py` | `transports/mcp/` | MOVE_AND_GENERALIZE |
| CLI | `orchestrator/cli.py` | `transports/cli.py` | MOVE_AND_GENERALIZE |
| secret store, DPAPI, credentials, validation | `orchestrator/{secret_store,dpapi,credentials,credential_validate}.py` | `secrets/` | MOVE_AND_GENERALIZE |
| project control facts | `orchestrator/control_fact.py` | *not extracted* | KEEP_AS_PROJECT_ADAPTER — measures one specific repository |
| phase drivers (`p1`…`p5a`) | repo root | *not extracted* | KEEP_AS_PROJECT_ADAPTER |
| actors, messages, decisions, programs, events, strategic store | — | `core/` | NEW |
| review contract | — | `review/contract.py` | NEW |
| project manifest | — | `projects/config.py` | NEW |

## Genericity audit

| Coupling found | Resolution |
|---|---|
| `FORBIDDEN_ALIAS_ROOTS = ("C:/Users/<user>/…/<repo>",)` — an absolute owner path compiled into the transport | Now `DEFAULT_FORBIDDEN_ALIAS_ROOTS = ()`, supplied per deployment via `Adapter(forbidden_alias_roots=…)` and `security.protected_roots` in the manifest |
| `"C:/Users"`, `"C:/Windows"` in the confinement policy — silently protected nothing on Linux/macOS | `_os_sensitive_roots()`, derived from the running OS |
| Container/network/label/env names carrying the project name | Derived from `branding.resource()` / `branding.label()` / `branding.env_var()` |
| `AEGIS_ORCH_*` environment variables | `QUAESTOR_*` via `branding.env_var()` |
| Egress proxy read the old `*_EGRESS_*` names while the sandbox sent the new ones | Both sides renamed together. A one-sided rename would leave the proxy silently on its defaults, so control 209 now asserts the symmetry in the suite — the first version of this row claimed a check that was performed once by hand and never committed, which is exactly the kind of claim this document should not make |
| `CLAUDE_CODE_ENTRYPOINT` hard-coded to the old product name | `branding.PRODUCT_NAME`, inside the Claude adapter where it belongs |
| DPAPI entropy and storage directory named for the old product | Derived from branding; documented as installation-scoped and effectively frozen once anything is provisioned |
| ~40 docstrings citing the private project by name | Rewritten to keep the lesson and drop the proper noun. The reasoning is the asset; the name is not |
| `core.preflight` imported `secrets.credentials` | Policy moved into `core.authority`; `secrets` re-exports it. One definition, correct direction |
| **`core.preflight` WAS the vendor.** Nine Anthropic variable names, one vendor's `auth status` parser and a `subprocess` call to a binary named `claude` -- in the layer that is supposed to know no provider. `dispatch()` reached it BY DEFAULT, so a deployment with a different executor got Anthropic's credential rules anyway | Split: `core/credential_policy.py` (provider-neutral question, vocabulary, record shape, and a STRUCTURAL exemption ceiling) and `executors/claude_auth.py` (one provider's answer). `dispatch()` now REQUIRES a preflight callable and refuses `NO_CREDENTIAL_POLICY_CONFIGURED` without one. Found by adversarial review; the first version of this table did not mention it |
| `EXEMPTIBLE_PROVIDER_ENV = frozenset({"CLAUDE_CODE_OAUTH_TOKEN"})` in core, guarded by a test asserting one literal was absent | A **shape rule**: no policy may exempt a variable whose name parts contain `API_KEY`/`AUTH_TOKEN`/`SECRET_KEY`/`ACCESS_KEY`/`BASE_URL`/`API_URL`/`BEARER_TOKEN`, validated at construction, for every provider. The old form protected one string; a second provider's `OPENAI_API_KEY` inherited none of it |
| `workspace/worktree_stamp.py` exposed one deployment's issue-tracker vocabulary (`bead`) as a platform field | Exposed as `task_ref`; the deployment's own key is still READ, because the marker files already exist. The format's ownership is stated in the module |
| `core.worker` imported executor implementations | Factory inverted into `executors/registry.py`, resolved at call time |
| Test constants naming one machine | Derived from `__file__`, or synthetic temp roots |
| `DISPATCH_KEY_SALT`, `HANDOFF_PROTOCOL` | **NOT changed.** Frozen in `compat.py` with the measured reason each must not move |

## Qualification equivalence

| Control range | Subject | Disposition |
|---|---|---|
| 1–18 | dispatch, idempotency, handoff, evidence floors | inherited, unchanged |
| 19–30 | the original project's real-repository bindings | **stays with the project** — tests one specific repository |
| 31–64 | Docker confinement | inherited, unchanged |
| 65–88 | write pipeline, egress, Git metadata | inherited, unchanged |
| 89–112 | the original project's real worktree qualification | **stays with the project** |
| 113–136 | credential broker | inherited, unchanged |
| 137–168 | MCP transport | inherited, re-pointed at the new layout |
| 169–186 | genericity, actors, messages, decisions, lanes, review | **new** |
| 187–208 | reachability: the production wiring, the acceptance gate, the evidence trust boundary, the store contract, and two controls restored from the project-integration split | **new (P5-XQ)** |
| 209–214 | cross-boundary claims that were made in prose and never checked; the import-graph resolver; provider-neutrality; the control-reachability matrix | **new (P5-XQ)** |

132 platform controls inherited; 36 belonged to the project integration at the split, and 34 remain
there — two were restored to the platform afterwards, as recorded immediately below. The split is
written down in `tests/controls.py` as `PROJECT_INTEGRATION_CONTROLS` rather than silently
shrinking the registry from 168 entries to 132.

Controls **110 and 111** were part of that split and should not have been: adversarial review
found their tests fully synthetic and their subject module shipped with the platform. They are
restored under new ids (206, 207) and recorded in `tests/controls.py` as `SUPERSEDED_CONTROLS`, so
the registry shows what happened to them instead of appearing to have quietly shrunk twice.

**No control was weakened.** Where a control's subject moved, the control follows it; where the
semantics genuinely changed — protected roots are now caller-supplied — the control asserts the
new, stricter contract (the roots must be *passed*, and an adapter that could reach one still
cannot be constructed).

That sentence was true and insufficient. Several controls were not weakened and were never strong:
they constructed their own subject, so they proved a function worked while the rule it stated was
unreachable from any production path. `docs/QUALIFICATION.md` is the record of that pass — 57
findings, the control-reachability matrix, and the six LOW findings accepted with reasons.

## Deferred, deliberately

Foundation is present; these are **not** built, and none of them is load-bearing for the claims
above.

- **Full** semantic merge-conflict detection between lanes. A minimum overlap guard ships
  (`_overlap_risk` in `core/orchestrator.py`: lockfile, schema and manifest collisions force
  `CONFLICT` before the merge, because git can succeed textually on two incompatible schemas).
  Genuine semantic conflict analysis is not implemented.
- Remote workers, distributed state, scheduling policy.
- Real execution through the MCP transport *by default*. `QUALIFICATION_ONLY` remains the shipped
  default and no request field can influence it; `LOCAL_GOVERNED` exists as a deliberate local
  opt-in (`quaestor mode set`), and there is still no remote path to select it.
- A published licence, and publication itself. `LICENSE.md` records the absence as deliberate: no
  licence chosen, no rights granted.

### Built since this record closed

Two entries from the original deferral list have since shipped. They are kept here, relabelled
rather than deleted, so this document still reads as the record of the extraction rather than as
current status:

- **An integration lane that combines candidate commits** — recorded here as "modelled
  (`MERGES_AFTER`), not automated". It is automated now: with no lane open, integration merges the
  committed lane branches into the `_integration` worktree oldest first, records exclusions rather
  than dropping them silently, and verifies the union to reach `CANDIDATE_PASS`, `CANDIDATE_FAIL`
  or `CONFLICT`. The constraint that motivated the deferral holds — executors still do not merge
  their own work; integration is its own lane kind. See `docs/OPERATIONS.md` §5.
- **A Codex executor adapter** — recorded here as "the seam exists; the adapter does not".
  `src/quaestor/executors/codex_cli.py` ships and `codex-cli` is admitted by name in
  `executors/registry.py` `KNOWN_KINDS`. Attaching to an already-running Codex session as a Relay
  Mode execution endpoint is a separate item and is open (bd `quaestor-pr4.13`).

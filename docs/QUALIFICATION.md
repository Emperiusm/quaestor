# Qualification record

What was claimed, what an independent adversarial pass found, and what the tree does now.

The short version: **57 findings, 50 fixed, 1 refuted, 6 accepted — all six LOW, each with a
stated reason.** No CRITICAL, HIGH or MEDIUM finding is unresolved.

---

## 1. The organising idea

> `CONTROL_DECLARED` ≠ `CONTROL_REACHABLE` ≠ `CONTROL_EFFECTIVE`

Four separate defects in the extraction had the same shape, and every one of them had a **passing
control**:

| Control | Declared | Reachable | Why the control passed anyway |
|---|---|---|---|
| protected roots | yes | **no** — the manifest field was parsed and never read | the test constructed an `Adapter` and passed the roots itself |
| role ceiling | yes | **no** — `authority_ceiling` had no non-test caller | the test called the function directly |
| review floor | yes | **no** — the whole `review` package had zero non-test importers | the test called `adversarial_required` directly |
| evidence trust | yes | yes | `evidence` was an open `Mapping`, so a model could assemble what was then treated as measurement |

A control that constructs its own subject and hands it the input the production path never
supplies proves the *function* works. It does not prove the *rule* applies. That distinction is
the whole content of this pass.

Two artefacts came out of it:

* **`src/quaestor/deployment.py`** — the production wiring. It builds a deployment from a project
  manifest and is what a transport or driver is meant to construct. If a control is not reachable
  from here, it protects nothing. It **refuses to build** on a missing or placeholder protected
  root rather than degrading to "protect nothing".
* **`tests/test_reachability_matrix.py`** (control 214) — the matrix below, asserted rather than
  written down. Each row names a declaration and the production symbol that consults it, and the
  row fails if the production module does not reference the declaration.

## 2. The control-reachability matrix

Verified by control 214 against the real source on every run.

| Control | Declared in | Reached from | Effect when it fires | Proof |
|---|---|---|---|---|
| authority gate | `core/authority.py:require` | `core/dispatcher.py:dispatch` | run refused `AUTHORITY_REFUSED` / `OWNER_REQUIRED` before any process starts | 6 |
| role ceiling | `core/actors.py:authority_ceiling` | `deployment.py:ceiling_for` | a review role can never hold a capability that reaches outside the artefact | 191 |
| lane fencing | `core/programs.py:check_fence` | `core/strategic_store.py:guard_fence` | a superseded writer is refused, not merged | 199 |
| protected roots | `transports/mcp/adapter.py` (`forbidden_alias_roots`) | `deployment.py:adapter_kwargs` | an adapter aliasing a protected repository cannot be constructed | 190 |
| review floor | `core/review_contract.py:adversarial_required` | `core/acceptance.py:decide` | acceptance refused `REQUIRED_REVIEW_MISSING` | 194 |
| adversarial-review requirement | `core/review_contract.py:summarize` | `core/acceptance.py:decide` | a reviewer's self-declared `ACCEPTED` is recomputed; empty ⇒ `VACUOUS` | 194 |
| evidence validation | `core/evidence_ref.py:EvidenceBundle` | `core/acceptance.py:decide` | model-assembled evidence refused `EVIDENCE_NOT_INDEPENDENTLY_COLLECTED` | 196 |
| redaction | `core/classification.py:classify` | `core/strategic_store.py:record_message` | secrets and host paths never reach durable storage; engineering prose survives | 202 |
| qualification-only execution gate | `transports/mcp/mode.py:assert_inert` | `transports/mcp/adapter.py:Adapter` | no executor can be constructed through the transport | 147 |
| secret access | `branding.py:STATE_DIR_NAME` | `secrets/store.py:default_dir` | the credential store is outside every repository | 117 |
| credential-exemption ceiling | `core/credential_policy.py:ProviderCredentialPolicy` | `executors/claude_auth.py:CLAUDE_POLICY` | a policy exempting an API-key-shaped variable cannot be constructed | 208 |
| duplicate dispatch admission | `core/identity.py:build_identity` | `core/dispatcher.py:dispatch` | a second dispatch for the same identity is admitted as a duplicate, never re-run | 2 |
| reconciliation | `core/reconcile.py:reconcile_run` | `transports/cli.py:cmd_reconcile` | an ambiguous write is reported as ambiguous, never blindly retried | 13 |
| cancellation | `core/cancellation.py:classify_cancel` | `transports/mcp/adapter.py:Adapter` | cancellation is classified by stage; an ambiguous stage says so | 78 |

Control 214 carries its own negative: it is fed a row naming a real declaration and a real module
that does not consult it, and must report that row. A matrix gate that cannot fail is a table of
intentions with an assertion attached.

## 3. What changed in this pass

### The vendor left `core/`

`core/preflight.py` hard-coded nine Anthropic environment variables, parsed one vendor's
`auth status` JSON, and shelled out to a binary named `claude` — from the layer that is supposed
to know no provider. Worse, `dispatch()` reached it **by default**, so a deployment configuring a
different executor still got Anthropic's credential rules.

* `core/credential_policy.py` — provider-neutral. The question, the vocabulary, the record shape.
* `executors/claude_auth.py` — one provider's answer, in the layer where a provider belongs.
* `dispatch()` **requires** a preflight callable. Absent ⇒ `NO_CREDENTIAL_POLICY_CONFIGURED`.

The exemption ceiling became a **shape rule** instead of a literal. The old design asserted that
`ANTHROPIC_API_KEY` was absent from a frozenset — protection for exactly one string, which a
second provider adding `OPENAI_API_KEY` would not inherit. Now no policy may exempt a variable
whose underscore-separated name parts contain `API_KEY`, `AUTH_TOKEN`, `SECRET_KEY`, `ACCESS_KEY`,
`BASE_URL`, `API_URL` or `BEARER_TOKEN`, checked **at construction**. `CLAUDE_CODE_OAUTH_TOKEN`
stays legal because `OAUTH` is a distinct part from `AUTH` — the rule matches parts, not
substrings, precisely so the brokered automation credential remains usable.

### Instruments that could not see their subject

* **Three import-graph walks keyed on `node.module`** and were blind to relative imports —
  `from . import x` vanished, `from .core import y` resolved to a non-existent top-level `core`.
  The repository this was extracted from used relative imports *exclusively*, so those walks
  would have certified a clean graph over edges they could not read. Now `support.resolve_imports`
  resolves `node.level`, and control 212 proves it on hand-written foreign bytes.
* **The genericity control scanned `src/` only** — exactly the directory the extraction scrub had
  run over — and reported a clean tree while `tests/` named the origin project 32 times. It now
  walks the whole repository. The two frozen wire values are exempt **by value**; exactly one file
  is exempt **by name**, `tests/genericity_tokens.py`, which exists only to hold the denylist
  because a denylist has to name what it denies.
* **Control 117** asserted the credential store was outside a synthetic temp directory — a
  condition that could not fail. It now proves `path_is_within` discriminates before trusting it.
* **Control 145's transport walk** could not see any package `__init__.py`, growing that blind
  spot from one file to six.
* **`mode.py`'s forbidden-import list** named neither module that now fronts executor
  construction. Both added — and the static walk's inability to see the `importlib` seam is now
  **stated in the module** rather than left as an assumption, with the by-site allowlist in
  control 171 named as what actually covers it.

### Claims that were not authorizations

* A decision's `authority` was a string any caller could type. It now carries `owner_attested`,
  computed from the owner channel at mint time rather than from a caller, and publishes
  `authority_is_claimed`. This build's owner channel returns `UNAVAILABLE` by construction, so
  every owner decision it can mint is honestly recorded as **claimed**.
* An acceptance `Waiver` had the same shape. The attestation is now a separate argument the
  caller supplies, defaulting to **absent** — a well-formed waiver object no longer buys its way
  past the review floor on its own.

### A remedy that named a file this repository does not contain

The P2.5 evidence gate told the reader to run `p25_confine.py`, a capture driver that was never
carried into the extraction. A remedy that sends a reader after something that was never here is
worse than none, and the doctrine clause it violates is the one about a fix-it string writing a
falsehood. It now says the fixture is a carried artefact, to be restored from version control.

## 4. Findings register

All 57 raw findings, re-measured against `HEAD` after the fixes. The prior run's 114 skeptic
verdicts could **not** be joined to their findings — the journal records no label on a verdict,
and a content-based join gave one finding 26 of them — so rather than relay a number produced by
a comparator that could not be validated, every finding was re-derived by direct measurement.

| Disposition | Count | Severity breakdown |
|---|---|---|
| FIXED | 50 | CRITICAL 1, HIGH 15, MEDIUM 25, LOW 9 |
| REFUTED | 1 | HIGH 1 |
| ACCEPTED | 6 | LOW 6 |

### Refuted

**#16 — "captured evidence fixtures were hand-edited while claiming to be verbatim."** Measured:
the fixture named by the finding contains **zero** occurrences of `verbatim` or `unedited` across
37,431 bytes. The provenance claim the finding is built on does not exist in the artefact.

### Accepted, with reasons

| # | Finding | Why it is accepted |
|---|---|---|
| 43 | declaring fewer `required_capabilities` than the profile grants narrows the owner gate but not the executor's envelope | **Pre-existing in the source repository**, not introduced by the extraction. It narrows the gate; it never widens what the child may do. |
| 44 | `AUTHORITY_GRANTED` is a writable event type no grant path can emit | The absence of an event nothing emits is corroboration, not proof — and it is not the only proof: the authority engine's refusal is asserted directly by control 6. |
| 46 | `check_fence` accepts any fence ≥ current and consults no token | The fence is a monotonic **order**, not an authenticator. Enforcement is the store's conditional `UPDATE` inside `BEGIN IMMEDIATE` (control 199/203). Adding a token would be a real improvement and is not a defect in what the fence claims. |
| 49 | Docker resource identities were renamed, so teardown keys on names pre-existing resources do not carry | A new deployment names new resources; there is nothing to reconcile because nothing has ever run under this name. **Partly fixed after it bit this very pass**: test image references are now configuration (`QUAESTOR_TEST_IMAGE_<phase>`) with the reference stated in the failure message, because a hard-coded tag is wrong on some machine. |
| 50 | never-exemptible roots became environment-derived | **By design.** A home directory is a machine fact. A constant would protect one developer's home and silently protect nothing elsewhere — the defect the `"C:/Users"` literals had. The docstrings now say NOT PURE instead of claiming otherwise. |
| 51 | `default_forbidden_paths` documented PURE while reading the environment | Same argument. The behaviour is correct; the docstring was the defect, and it is fixed. |

## 5. Environment of this verdict

Stated because it can change the answer.

```
platform : Windows-11-10.0.26200-SP0
python   : 3.14.2
docker   : available; p3/p25 images present locally
suite    : 483 tests, 0 skipped, 0 failed, 0 errors
controls : 178 required / 178 declared / 178 executed
static   : 0 findings over 92 files (floor 15)
```

`QUALIFICATION_ONLY` remains enforced: no executor is constructed, no worker process is spawned,
and no real repository is opened by any control in this suite.

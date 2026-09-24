# Design Provenance

Quaestor studies other systems and adopts ideas deliberately. This document records every
externally studied system: what was inspected, under what license, what was adopted, what was
rejected, and whether any source code was copied (target: never -- designs only). It is the
standing commitment of the original product direction (section 27.1, now merged into
[PRD.md](PRD.md)), which takes PAI-Bus's `PROVENANCE.md` as the maturity bar: self-auditing, marking
unverifiable claims as unverifiable, recording the exact revision inspected.

Every entry states the repository, the exact commit inspected, the license **at that commit**,
and an explicit statement that no source code was copied. Where nothing was rejected, the entry
says so rather than inventing a rejection to fill the field.

---

## AI-Rosen-bridge

- Repository: <https://github.com/Lagunaswift/AI-Rosen-bridge>
- Commit inspected: `02a559057579e7fee70d0d5be60528faa2fbe07e`
- License at that commit: **none.** No LICENSE file exists. The repository was shared directly by
  its owner for study; that grant covers reading, not redistribution. Ideas only.
- Detailed study: the full cross-examination is kept privately, because the repository was
  shared for study rather than published; this section records only the disposition.
- **Studied:** cross-examination of a model's own work product; browser-driven verification;
  enforcement-by-keyword-rail approaches to output discipline.
- **Adopted:** universal UX ambitions (any agent, any surface, minimal contract --
  original product direction section 29, P1); the honest
  caveats culture -- state what is not known, mark unverifiable claims unverifiable.
- **Rejected:** CDP browser automation as an evidence channel (heavy, fragile, and the host's
  access makes confinement claims dishonest -- see [THREAT-MODEL.md](THREAT-MODEL.md));
  keyword-rail enforcement (guardrails simulated by prompt vocabulary are not guardrails).
- **Source code copied:** none. Designs and critique only.

## Portable-AI-Bus

- Repository: <https://github.com/Hymlock/Portable-AI-Bus>
- Commit inspected: `b0e627977f44bf1f107523daffd8746eb425b237`
- License at that commit: MIT.
- **Studied:** bus-style orchestration of multiple model providers; provider health and failover;
  session lifecycle semantics; the repository's own `PROVENANCE.md` practice.
- **Adopted:** provider chains with reconciliation-aware failover
  ([quaestor-kaz.5]); wake-vs-done semantics -- "done" from a seat is never ambiguous across
  wake / attempt / lane / program (an original
  product-direction invariant); the PROVENANCE.md practice itself (this document).
- **Rejected:** none recorded at inspection time.
- **Source code copied:** none. Designs only.

## frenemy

- Repository: <https://github.com/noblehacks/frenemy>
- Commit inspected: `dd460e61c2ff932d019266c8701290274ed2b495`
- License at that commit: MIT.
- **Studied:** multi-agent context isolation; how ambient context reaches a delegated agent;
  separation between observation duties and mutation duties.
- **Adopted:** prompt-via-stdin preference and AMBIENT_CONTEXT isolation
  ([quaestor-hfa]); read-only versus write delegation separation
  ([quaestor-hfa], adapter contract and integration assurance levels).
- **Rejected:** none recorded at inspection time.
- **Source code copied:** none. Designs only.

## pal-mcp-server

> **NON-STANDARD LICENSE HANDLING -- ideas studied, ZERO code vendored.** The repository is
> classified "Other" by GitHub and the project's standing rule
> (original product direction, section 27.1) treats it as
> vendor-nothing regardless. Measured correction, recorded because a provenance document that
> misstates a verifiable artifact fails its own audit: the LICENSE file at the inspected commit
> carries the standard Apache-2.0 text with a Beehive Innovations copyright appendix. The
> vendor-nothing rule stands either way.

- Repository: <https://github.com/BeehiveInnovations/pal-mcp-server>
- Commit inspected: `7afc7c1cc96e23992c8f105f960132c657883bb1`
- License at that commit: LICENSE file present with Apache-2.0 text (see correction above);
  handled conservatively as **no open grant for vendoring**.
- **Studied:** capability registry over heterogeneous providers; fresh-context specialist roles;
  continuation UX across sessions; plan review before execution; permission bypass presets;
  where safety is placed relative to the model.
- **Adopted:** provider capability registry, policy-driven seat routing over measured/declared
  capabilities ([quaestor-kaz.6]); fresh-context specialist roles (role-shaped seats);
  continuation UX re-derived rather than ported -- Context Capsules rebuilt from durable state
  instead of carried session state ([quaestor-kaz.7]); adversarial plan challenge before
  execution ([quaestor-kaz.8]).
- **Rejected:** permission bypass presets (`--yolo`, `--dangerously-bypass`) -- authority is
  granted by a human through a governed vocabulary or not at all; model-owned safety (the party
  being constrained cannot hold the constraint); guardrails-as-enforcement (advisory checks
  presented as controls).
- **Source code copied:** none. Architecture studied, zero code vendored.

## walkie

- Repository: <https://github.com/vikasprogrammer/walkie>
- Commit inspected: `03b2cb0d825ae37ae26a0c78975b4fa461b45507`
- License at that commit: MIT.
- **Studied:** durable mailbox semantics for agent messages; loop budgets bounding unattended
  operation; agent-native bootstrap so an unfamiliar agent connects itself; local-first web UI.
- **Adopted:** durable mailbox semantics -- dedup, spool, replay, ack, TTL, mailbox != canonical
  state ([quaestor-ru1.4]); loop budgets
  (an original product-direction invariant); agent-native
  bootstrap via `llms.txt` and a bundled skill ([quaestor-ru1.6]); local web UI first
  ([quaestor-ru1.7]).
- **Rejected:** none recorded at inspection time.
- **Source code copied:** none. Designs only.

---

## Maintenance rule

Update this file whenever a new external system is studied -- before the first idea from it
lands anywhere in Quaestor. Never ship without it current: an entry missing a commit hash, a
license-at-that-commit, or a no-code-copied statement is an incomplete entry, and an incomplete
entry is treated like failed CI.

# CI Required-Check Policy

The source of truth for which checks gate merge to `main`, and the rules for changing that.

Designation per workflow of whether a check should be **required** for merge to `main` (via
GitHub branch protection) or remain **advisory** (visible but non-blocking). Update this document
before changing required checks; never adjust branch protection out of band without recording the
change and the rationale here.

## Current status

| Check | Designation | Rationale |
|---|---|---|
| `CI / fast (no subprocess, no git)` | **advisory** (soak) | Moved to GitHub-hosted `ubuntu-latest`; needs its soak week on the new runners before gating. |
| `CI / suite (linux, py3.12)` | **advisory** (soak) | Same. Flake rate must be measured on the new runners before this gates. |
| `CI / suite (linux, py3.13)` | **advisory** (soak) | Same. |

**`main` is protected by the `protect main` ruleset:** no deletion, no force-push, and changes
land through a pull request (no approving review required). Repository admins may bypass. It
has **no required status checks yet**; the graduation below is what adds them to the ruleset.

## Graduation rules (soak first)

- **Soak first.** A new check stays advisory for ≥1 week of real PR traffic before being moved to
  "required" — this catches flake before it can block PRs.
- **Surfacing-issue audit.** Before graduating any check, audit its recent failures: count
  real-bug catches vs flake. Flake-rate >5% blocks graduation.
- **No graduation in a reliability-change PR.** A check may not become required in the same PR
  that materially changes its timeout, concurrency, matrix or other reliability mechanics. The
  soak has to run against the mechanics that will actually gate.

## How to graduate a check (advisory → required)

1. ≥1 week of real PR traffic on the current mechanics.
2. Audit recent failures: real-bug catches vs flake. Flake-rate >5% blocks.
3. Confirm the check is not in the same PR that changed its reliability mechanics.
4. Move its row from Advisory to Required here, in the same PR as the branch protection change.

## How to remove a required check

Record the reason here in the same PR that removes it. A check removed because it flakes must
state what evidence would bring it back.

## Known platform deltas, stated rather than hidden

- **Linux-only.** The live docker controls build and run a Linux image, which a Windows runner
  cannot do. Windows semantics are measured on a developer machine; a Windows leg that skips the
  live docker controls would restore platform coverage, and graduates through the same soak.
- **Runner history.** CI briefly ran on a self-hosted runner fleet while GitHub-hosted minutes
  were unavailable to the repository. It moved back to GitHub-hosted runners, and the fleet's
  disk-preflight action, disk-health and reclaim workflows, and their controls (366–369) were
  retired with it.

## References

- `.github/workflows/ci.yml` — the live workflow definition

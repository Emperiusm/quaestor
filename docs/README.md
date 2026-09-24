# Documentation

Start with the [repository README](../README.md) for what Quaestor is, how to install it, and how
it connects to ChatGPT. The documents here go deeper.

## The contract

- **[`PRD.md`](PRD.md)** — the canonical product requirements. Where any other document here
  disagrees with it, the PRD governs.

## How it works

- **[`RELAY-MODE.md`](RELAY-MODE.md)** — Relay Mode: endpoints, governance gates, recovery, and
  every live qualification record.
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)** — layering, actors, the two-way protocol, and Program
  Mode's lanes. Relay Mode does not run through Program Mode.
- **[`CHATGPT-PLUS.md`](CHATGPT-PLUS.md)** — the three ways a ChatGPT account meets Quaestor: the
  relay Orchestrator, the read-only MCP connector, and the Program Mode seat.

## Running it

- **[`OPERATIONS.md`](OPERATIONS.md)** — installing, the deployment home, modes, credentials,
  programs, reconciliation, troubleshooting, and Relay Mode operations.

## What has been proven, and what has not

- **[`QUALIFICATION.md`](QUALIFICATION.md)** — the adversarial qualification record: what was
  claimed, what an independent pass found, what the tree does now.
- **[`THREAT-MODEL.md`](THREAT-MODEL.md)** — what the platform defends against, and what it does
  not.

## Where it came from

- **[`EXTRACTION.md`](EXTRACTION.md)** — how the platform was extracted from a project-specific
  implementation, and what was deferred.
- **[`DESIGN-PROVENANCE.md`](DESIGN-PROVENANCE.md)** — every externally studied system: what was
  inspected, under what licence, what was adopted and rejected, and the commitment that no source
  was copied.

## Contributing

- **[`CONTRIBUTING.md`](CONTRIBUTING.md)** — control rules, and how to add an executor provider, a
  relay end, or a transport.

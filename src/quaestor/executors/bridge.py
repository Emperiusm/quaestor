"""bridge -- dialogue adapters as dispatchable executor seats (bd quaestor-cjj, quaestor-ru1.19).

WHY THIS FILE EXISTS
--------------------
The Tier 1 adapters (CommandAdapter, FileInboxOutboxAdapter) implement AgentAdapter.send/receive,
NOT core.executor_contract.Executor -- so the dispatcher/worker/orchestrator could never reach
them and "any agent can participate" was true of the library and false of the product. This
module is the seam that makes a dialogue transport HOLD A SEAT: it wraps one adapter turn in the
Executor contract (prompt in via ExecRequest, reply written to ``req.stdout_path``, observed
exit classified into the standard taxonomy).

ONE TURN PER EXECUTE
--------------------
An executor execution is one dialogue turn, not a conversation: the run's prompt is sent, the
reply (or the loud absence of one) is the run's stdout. Conversation state belongs to the
transport's own durable medium (the command's process semantics, the filebox's envelopes), not
to this bridge.

WHAT THE BRIDGE DOES NOT CLAIM
------------------------------
No capability is claimed that the transport does not have: neither adapter can prove
containment, so ``command``/``file-inbox`` are declared non-write-capable and can never hold a
writing seat (the write ceiling is enforced at admission, orchestrator._seat_spec). The reply is
written to stdout VERBATIM -- parsing and verdict stay where they belong, downstream of the
contract.
"""
from __future__ import annotations

import json
import os
import time
from typing import Mapping

from quaestor.adapters.command import CommandAdapter, CommandTimeoutError, CommandTurnError
from quaestor.adapters.filebox import FileInboxOutboxAdapter
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK, EXIT_SPAWN_FAILED,
                                             EXIT_TIMEOUT, ExecOutcome, ExecRequest, Executor)

BRIDGE_INSTRUMENT = "executors.bridge/1"

#: How often the file-inbox seat polls the outbox for a complete response. A poll, not a spin:
#: the external writer is a separate process on a human-or-filesystem timescale.
DEFAULT_POLL_INTERVAL_S = 0.2


def _write_stdout(req: ExecRequest, reply) -> None:
    """The reply IS the run's stdout: text verbatim, structured data as JSON. Impure."""
    os.makedirs(os.path.dirname(os.path.abspath(req.stdout_path)) or ".", exist_ok=True)
    text = reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False, indent=2)
    with open(req.stdout_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


class AdapterExecutor(Executor):
    """One adapter turn behind the Executor contract. Subclasses supply the transport."""

    name = "adapter"

    def __init__(self, config: Mapping | None = None):
        self._config = dict(config or {})

    def _adapter(self, req: ExecRequest):
        """Build the transport for THIS run. Raises ValueError on a misconfigured seat."""
        raise NotImplementedError  # pragma: no cover - interface

    def _collect(self, adapter, req: ExecRequest):
        """Wait out the transport's reply. None means NO reply -- never a fabricated one."""
        return adapter.receive()

    def execute(self, req: ExecRequest) -> ExecOutcome:
        try:
            adapter = self._adapter(req)
        except ValueError as exc:
            # A misconfigured seat is refused BEFORE anything spawns: construction failure is
            # loud, named, and recorded as spawn-failed rather than guessed at dispatch.
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error=str(exc))
        try:
            adapter.send(req.prompt)
        except CommandTimeoutError as exc:
            return ExecOutcome(True, None, EXIT_TIMEOUT, error=str(exc))
        except CommandTurnError as exc:
            return ExecOutcome(True, None, EXIT_NONZERO, error=str(exc))
        except OSError as exc:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="the transport failed before a turn could start: %s" % exc)
        reply = self._collect(adapter, req)
        if reply is None:
            # LOUD-NOT-PARTIAL (§17): an empty stdout downstream is "unparseable", which is the
            # honest verdict for a turn that produced no reply. Never synthesize one.
            _write_stdout(req, "")
            return ExecOutcome(True, 0, EXIT_OK,
                               note="the transport completed its turn but produced no reply")
        _write_stdout(req, reply)
        return ExecOutcome(True, 0, EXIT_OK)


class CommandExecutor(AdapterExecutor):
    """``command`` kind: a user-supplied argv template, one turn, prompt on STDIN only.

    Config (from the request artifact): ``argv`` (required, a SEQUENCE -- a shell string is
    refused by the adapter), optional ``cwd`` (defaults to the run's cwd), optional
    ``timeout_s`` (defaults to the run's budget). The durable command.json record exists so a
    post-mortem can prove the prompt never travelled in argv.
    """

    name = "command"

    def _adapter(self, req: ExecRequest):
        argv = self._config.get("argv")
        if isinstance(argv, str) or not argv:
            raise ValueError(
                "a command seat requires config.argv to be a non-empty sequence of argv items; "
                "a shell string would blur where the prompt may travel")
        cwd = str(self._config.get("cwd") or "") or str(req.cwd or "") or None
        timeout_s = float(self._config.get("timeout_s") or req.timeout_s)
        adapter = CommandAdapter([str(part) for part in argv], cwd=cwd, timeout_s=timeout_s)
        _write_json(os.path.join(req.run_dir, "command.json"),
                    {"argv": [str(part) for part in argv], "cwd": cwd,
                     "prompt_transport": "STDIN", "shell": False, "executor": self.name})
        return adapter


class FileInboxExecutor(AdapterExecutor):
    """``file-inbox`` kind: the reference universal seat (direction §5.6).

    Config: ``root`` (required) -- the directory whose ``.quaestor/inbox`` and
    ``.quaestor/outbox`` carry the dialogue with ANY external consumer; optional ``timeout_s``
    (how long the seat waits for a complete response) and ``poll_interval_s``.

    The seat sends the prompt as an inbox envelope, then polls the outbox. A response without
    its completion marker is NOT a response (§17 loud completion lives in the adapter), and a
    deadline with no complete response is an observed TIMEOUT whose error says the envelope
    stays in the inbox for its writer -- never a fabricated answer. A degenerate envelope
    whose payload is JSON ``null`` is likewise received as "no reply" (the adapter's
    ``receive`` cannot distinguish it from absence), so the seat keeps waiting rather than
    inventing a reply from nothing.
    """

    name = "file-inbox"

    def _adapter(self, req: ExecRequest):
        root = str(self._config.get("root") or "").strip()
        if not root:
            raise ValueError(
                "a file-inbox seat requires config.root: the directory whose .quaestor/inbox "
                "and .quaestor/outbox carry the dialogue with the external consumer")
        return FileInboxOutboxAdapter(root)

    def _collect(self, adapter, req: ExecRequest):
        budget_s = float(self._config.get("timeout_s") or req.timeout_s)
        poll_s = float(self._config.get("poll_interval_s") or DEFAULT_POLL_INTERVAL_S)
        deadline = time.monotonic() + max(budget_s, 0.0)
        while True:
            reply = adapter.receive()
            if reply is not None:
                return reply
            if time.monotonic() >= deadline:
                self._deadline_error = (
                    "no complete outbox response within %.1fs; the inbox envelope stays in "
                    "place for the external writer" % budget_s)
                return None
            time.sleep(poll_s)

    def execute(self, req: ExecRequest) -> ExecOutcome:
        self._deadline_error = ""
        outcome = super().execute(req)
        if outcome.exit_class == EXIT_OK and self._deadline_error:
            # The poll ran out with no reply: the base class recorded "no reply" -- reclassify
            # it as the TIMEOUT it honestly is, carrying the reason.
            return ExecOutcome(True, None, EXIT_TIMEOUT, error=self._deadline_error)
        return outcome

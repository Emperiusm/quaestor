"""adapters.filebox -- the file inbox/outbox reference adapter (direction §5.6).

§5.6: "A simple file adapter should be treated as a reference universal protocol." Quaestor
writes ``.quaestor/inbox/task-<seq>.json`` envelopes; ANY external consumer -- shell script,
IDE extension, remote worker, human developer -- writes ``.quaestor/outbox/<task_id>.json``
back, and no core change is needed to onboard them.

THE INVARIANT THIS MODULE EXISTS TO KEEP
----------------------------------------
Direction §5.6: "file contents != authority. The file adapter transports information. It does
not grant capabilities." The envelope fields are TRANSPORT ONLY. A response payload may carry
whatever the external side wrote -- including text shaped like ``{"grant": "GIT_PUSH"}`` -- and
``receive()`` surfaces it VERBATIM as message data, because silently rewriting inbound bytes
would be its own quiet falsification of evidence. What the transport refuses to do is APPLY such
fields: the only parse-and-apply step is ``apply_response()``, which accepts the closed
allowlist ``{result_text, artifacts}`` and refuses anything else with the named refusal
``FILE_FIELD_NOT_TRANSPORTABLE``. Authority is minted by the owner/authority engine, never by a
file that asks nicely.

LOUD COMPLETION (§17)
---------------------
A response without its ``completion_marker`` is NOT a response: ``receive()`` returns None and
leaves the file in place for its writer to finish. Truncated must never mean done.

This lane is a §5.2 Tier 1 DIALOGUE transport -- send/receive only. It declares NO optional
capabilities and self-declares NO assurance level; whatever it can honestly promise is computed
from probes (§5.3, §31) by whoever runs them.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from quaestor import branding
from quaestor.adapters import register
from quaestor.adapters.base import AgentAdapter

FILEBOX_INSTRUMENT = "adapters.filebox/1"

#: The marker an outbox response MUST carry (§17 loud completion). Absent marker == not done.
#: Derived from the product name via branding -- the genericity control forbids hard-coding the
#: product name anywhere else, and a completion marker is exactly the kind of string that would
#: otherwise fossilize a rename.
COMPLETION_MARKER = branding.PRODUCT_NAME.upper() + "_TASK_COMPLETE"

#: The ONLY fields the parse-and-apply step will ever lift out of a response payload. Everything
#: else -- however authoritative it looks -- stays inert message data.
RESPONSE_FIELD_ALLOWLIST = ("result_text", "artifacts")

ENVELOPE_FIELDS = ("task_id", "message_id", "nonce", "created_at",
                   "expected_response_type", "completion_marker", "payload")

_TASK_FILE_RE = re.compile(r"^task-(\d+)\.json$")


class FileFieldNotTransportable(ValueError):
    """A response payload carried a field outside the transport allowlist.

    Named refusal per doctrine: a refusal that does not name its reason teaches nothing.
    """


def apply_response(payload) -> dict:
    """The parse-and-apply step: turn a received payload into core-shaped result data.

    This is deliberately the ONLY place payload keys are interpreted, and it accepts nothing
    beyond ``result_text`` / ``artifacts``. A payload key like ``grant`` or ``capability`` is a
    capability claim smuggled through a mailbox -- refused BY NAME here so it can never reach
    the authority engine wearing a transport uniform.
    """
    if not isinstance(payload, dict):
        raise FileFieldNotTransportable(
            "FILE_FIELD_NOT_TRANSPORTABLE: response payload must be a JSON object with fields "
            "%s; got %s" % (list(RESPONSE_FIELD_ALLOWLIST), type(payload).__name__))
    unknown = sorted(str(key) for key in payload if str(key) not in RESPONSE_FIELD_ALLOWLIST)
    if unknown:
        # file contents != authority: name exactly which fields were refused and why.
        raise FileFieldNotTransportable(
            "FILE_FIELD_NOT_TRANSPORTABLE: field(s) %s are not part of the %s allowlist; "
            "outbox files transport information and can never grant capabilities"
            % (unknown, list(RESPONSE_FIELD_ALLOWLIST)))
    result_text = payload.get("result_text", "")
    artifacts = payload.get("artifacts", [])
    if not isinstance(result_text, str):
        raise FileFieldNotTransportable(
            "FILE_FIELD_NOT_TRANSPORTABLE: result_text must be a string, got %s"
            % type(result_text).__name__)
    if not isinstance(artifacts, list):
        raise FileFieldNotTransportable(
            "FILE_FIELD_NOT_TRANSPORTABLE: artifacts must be a list, got %s"
            % type(artifacts).__name__)
    return {"result_text": result_text, "artifacts": artifacts}


@register
class FileInboxOutboxAdapter(AgentAdapter):
    """DIALOGUE-tier transport over two directories under ``root``.

    Wire format (the contract external consumers code against):

    - Quaestor side ``send(message)`` writes ``inbox/task-<seq>.json``:
      ``{task_id, message_id, nonce, created_at, expected_response_type,
      completion_marker: COMPLETION_MARKER (see above)``. The payload IS the caller's
      message verbatim -- the envelope wraps, it never edits.
    - External side writes ``outbox/<task_id>.json`` with the same ``task_id``, the
      ``completion_marker``, and the answer in ``payload``.
    - Quaestor side ``receive()`` returns the newest COMPLETE response's payload for a task we
      actually sent, then moves the file to ``outbox/consumed/`` (delivered exactly once).
      Anything incomplete, unreadable or foreign stays put and yields None instead.

    ``responder`` stands in for the EXTERNAL writer in probes/self-tests only (the probe suite
    runs with no real agent on the other end); production leaves it None, in which case receive()
    depends entirely on files an independent writer produced. The responder changes who writes
    the outbox bytes, never what those bytes may mean.
    """

    ADAPTER_KIND = "file-inbox-outbox"
    #: send/receive only: none of base.CAPABILITIES is claimed, because none is true.
    DECLARED_CAPABILITIES = ()
    #: Harness facts for the conformance probes: the outbox really is observable state.
    conformance_harness = {"observe": True}

    def __init__(self, root, *, adapter_id="file-inbox-outbox", responder=None):
        super().__init__(adapter_id)
        self._root = Path(root)
        self._inbox = self._root / ".quaestor" / "inbox"
        self._outbox = self._root / ".quaestor" / "outbox"
        self._responder = responder
        #: task_id -> message_id this instance sent; rehydrated from inbox files so a restart
        #: still recognizes answers to tasks issued before dying (§5.12 replay honesty).
        self._sent: dict = {}

    # -- required contract ---------------------------------------------------------------------

    def send(self, message) -> None:
        envelope = self._build_envelope(message)
        self._sent[envelope["task_id"]] = envelope["message_id"]
        self._write_json(self._inbox / ("%s.json" % envelope["task_id"]), envelope)
        if self._responder is not None:
            # Probe/self-test stand-in for the independent external writer.
            body = self._responder(dict(envelope))
            self._write_json(self._outbox / ("%s.json" % envelope["task_id"]), {
                "task_id": envelope["task_id"],
                "message_id": envelope["message_id"],
                "completion_marker": COMPLETION_MARKER,
                "payload": body,
            })

    def receive(self):
        completed = self._completed_responses()
        if not completed:
            # Loud-not-partial: no complete response means NO response. We do not hand back a
            # half-written file and call it an answer (§17).
            return None
        path, env = max(completed,
                        key=lambda item: (item[0].stat().st_mtime_ns, item[0].name))
        payload = env.get("payload")
        consumed_dir = self._outbox / "consumed"
        consumed_dir.mkdir(parents=True, exist_ok=True)
        path.replace(consumed_dir / path.name)
        return payload

    # -- wire format helpers -------------------------------------------------------------------

    def _build_envelope(self, message) -> dict:
        task_id = ""
        message_id = ""
        if isinstance(message, dict):
            task_id = str(message.get("task_id") or "")
            message_id = str(message.get("message_id") or "")
        if not task_id:
            task_id = "task-%04d" % self._next_seq()
        if not message_id:
            message_id = "qm-" + secrets.token_hex(8)
        return {
            "task_id": task_id,
            "message_id": message_id,
            "nonce": secrets.token_hex(16),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expected_response_type": "json",
            "completion_marker": COMPLETION_MARKER,
            "payload": message,
        }

    def _next_seq(self) -> int:
        highest = 0
        for directory in (self._inbox, self._outbox / "consumed"):
            if not directory.is_dir():
                continue
            for path in directory.glob("task-*.json"):
                match = _TASK_FILE_RE.match(path.name)
                if match:
                    highest = max(highest, int(match.group(1)))
        return highest + 1

    def _known_task_ids(self) -> set:
        # Restart honesty: tasks this process never sent but a previous one did are recognized
        # from the inbox envelopes themselves -- the transport reads its own wire format rather
        # than keeping private state that dies with the process.
        known = set(self._sent)
        if not self._inbox.is_dir():
            return known
        for path in self._inbox.glob("task-*.json"):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    env = json.load(handle)
            except (OSError, ValueError):
                continue
            if isinstance(env, dict) and env.get("task_id"):
                known.add(str(env["task_id"]))
        return known

    def _completed_responses(self) -> list:
        known = self._known_task_ids()
        found: list = []
        if not self._outbox.is_dir():
            return found
        for path in self._outbox.glob("task-*.json"):
            if not path.is_file():
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    env = json.load(handle)
            except (OSError, ValueError):
                # Unreadable/partial JSON is not a response (§17): skip loudly-by-absence,
                # never delete -- the writer may still be finishing it.
                continue
            if not isinstance(env, dict):
                continue
            if env.get("completion_marker") != COMPLETION_MARKER:
                continue
            if str(env.get("task_id") or "") not in known:
                continue
            found.append((path, env))
        return found

    @staticmethod
    def _write_json(path: Path, body: dict) -> None:
        # Atomic publish: readers only ever see whole files, so truncation shows up as absence
        # of a valid document rather than as a half-answer that looks complete (§17).
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".partial-%s" % os.getpid())
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(body, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

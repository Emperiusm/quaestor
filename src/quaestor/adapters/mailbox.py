"""adapters.mailbox -- the durable adapter mailbox contract (direction §5.12).

§5.12: "send/receive" is deceptively simple until one side restarts. Every transport defines and
honors delivery semantics -- message_id, sender, recipient_role, causal_parent, sequence,
created_at, expires_at (TTL), delivery_state, ack_cursor, hop_count -- "with deduplication by
message id, offline spool + reconnect replay, acknowledgment, ordered delivery where required."

WHAT LIVES WHERE
----------------
One directory is the whole spool:

    <dir>/spool/<sequence>.<message_id>.json   the wire envelope, atomically published
    <dir>/expired/<same>                       TTL-dead traffic, MOVED here, never vanished
    <dir>/cursor.json                          the durable ack cursor

The sequence number is derived from what is ON DISK at append time, never from process memory,
so a restarted sender continues the ordering instead of forking it. Delivery is cursor-based:
``receive(cursor)`` replays everything after ``cursor`` in sequence order, so a consumer that
crashes mid-flight re-receives exactly its unacked window; dedup by message_id guarantees the
redelivery cannot double-apply.

THE HARD BOUNDARY (§5.12): "mailbox traffic = transient, TTL-bound, replayable; canonical state
= the durable store; NEVER lives in a mailbox." This module enforces that STRUCTURALLY, not by
policy: a payload may carry only the inert transport fields {text, artifact_refs, meta}. Anything
else -- a grant, an authority name, a lane decision -- is refused BY NAME with
MAILBOX_FIELD_NOT_TRANSPORTABLE at append time. Authority-shaped content can travel as inert
TEXT (the receiver may read prose); it can never arrive as structured fields wearing a uniform
that lets downstream code apply it without meaning to.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from quaestor import branding

MAILBOX_INSTRUMENT = "adapters.mailbox/1"

#: Default sender identity comes from branding like every other product string in the platform:
#: control 172 keeps the name in exactly one module, and a mailbox default is still naming.
DEFAULT_SENDER = branding.PRODUCT_NAME

#: The ONLY structured fields a mailbox payload may carry (see module docstring). Sorted order
#: everywhere keeps refusal messages deterministic.
PAYLOAD_FIELD_ALLOWLIST = ("artifact_refs", "meta", "text")

#: The named refusal for §5.12's hard boundary. A refusal that does not name its reason teaches
#: nothing (filebox doctrine).
MAILBOX_FIELD_NOT_TRANSPORTABLE = "MAILBOX_FIELD_NOT_TRANSPORTABLE"

#: Walkie's conversation cap: a causal chain this long has stopped being a dialogue and started
#: being a loop. Mirrored here so every transport shares ONE definition of "too many rounds".
DEFAULT_MAX_ROUNDS = 10


class MailboxFieldNotTransportable(ValueError):
    """A payload carried structured keys outside the transport allowlist."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def validate_payload(payload) -> None:
    """Refuse any payload whose TOP-LEVEL keys leave the allowlist. Raises by name.

    Nested values are NOT inspected on purpose: ``meta`` may legitimately hold arbitrary
    annotations, and text may quote anything. The boundary is between TRANSPORT FIELDS and
    everything else -- policing depth would either rewrite inbound data or grow an unwinnable
    schema fight. Structured authority stays out; quoted authority arrives inert.
    """
    if not isinstance(payload, dict):
        raise MailboxFieldNotTransportable(
            "%s: payload must be a JSON object with fields %s; got %s"
            % (MAILBOX_FIELD_NOT_TRANSPORTABLE, list(PAYLOAD_FIELD_ALLOWLIST),
               type(payload).__name__))
    unknown = sorted(str(k) for k in payload if str(k) not in PAYLOAD_FIELD_ALLOWLIST)
    if unknown:
        raise MailboxFieldNotTransportable(
            "%s: field(s) %s are not transportable through a mailbox (allowlist %s); canonical "
            "state NEVER lives in a mailbox (direction §5.12)"
            % (MAILBOX_FIELD_NOT_TRANSPORTABLE, unknown, list(PAYLOAD_FIELD_ALLOWLIST)))


def make_envelope(payload, *, sender=DEFAULT_SENDER, recipient_role="agent", causal_parent="",
                  message_id=None, expires_at=None, ttl_s=None, hop_count=0) -> dict:
    """A full §5.12 envelope around a validated payload. PURE-ish (clock only).

    ``expires_at`` accepts an ISO-8601 UTC string; ``ttl_s`` is sugar for "now + N seconds".
    Exactly one may be set -- two ways to say when a message dies is one way to be ambiguous.
    """
    validate_payload(payload)
    if expires_at is not None and ttl_s is not None:
        raise ValueError("set expires_at OR ttl_s, not both")
    if ttl_s is not None:
        expires_at = (_utcnow() + timedelta(seconds=float(ttl_s))).isoformat()
    if expires_at is not None:
        # Validate at WRITE time: an expiry our own reader cannot parse would silently turn into
        # "deliver forever" or "deliver never" depending on which branch guessed wrong.
        datetime.fromisoformat(str(expires_at))
    return {
        "message_id": str(message_id) if message_id else uuid.uuid4().hex,
        "sender": str(sender),
        "recipient_role": str(recipient_role),
        "causal_parent": str(causal_parent or ""),
        "sequence": None,          # stamped by Mailbox.append from on-disk state
        "created_at": _utcnow().isoformat(),
        "expires_at": str(expires_at) if expires_at else "",
        "delivery_state": "spooled",
        "hop_count": int(hop_count),
        "payload": payload,
    }


def causal_budget(exchange_history, max_rounds: int = DEFAULT_MAX_ROUNDS) -> bool:
    """True while continuing the exchange stays inside walkie's round cap. PURE.

    A "round" is measured along CAUSAL PARENTS, not raw message count: one long chain of ten
    replies is a runaway loop; ten siblings answering one prompt is not. The longest parent
    chain present in the history IS the rounds consumed, and another round is allowed only
    while that chain is shorter than ``max_rounds``. Cycles are treated as exhausted budget --
    a loop must trip the cap, not recurse forever proving it.
    """
    parents = {}
    for item in exchange_history or []:
        if isinstance(item, dict):
            mid = str(item.get("message_id") or id(item))
            parents[mid] = item.get("causal_parent") or ""

    def chain_len(mid, seen) -> int:
        depth = 0
        while mid and mid in parents and mid not in seen:
            seen.add(mid)
            depth += 1
            if depth >= max_rounds:      # early-out: already over budget, stop walking
                break
            mid = parents[mid]
        return depth

    longest = 0
    for mid in parents:
        longest = max(longest, chain_len(mid, set()))
        if longest >= max_rounds:
            return False
    return longest < max_rounds


class Mailbox:
    """Cursor-based durable spool over one directory. Impure by nature; atomic by construction."""

    def __init__(self, directory):
        self._dir = Path(directory)
        self._spool = self._dir / "spool"
        self._expired = self._dir / "expired"

    # ---- producing -----------------------------------------------------------------------------

    def append(self, msg) -> str:
        """Spool one message; returns its message_id. Idempotent per message_id.

        Accepts a bare payload dict or a full envelope from make_envelope. Dedup happens BEFORE
        the write (a repeated append of the same id returns the existing id and touches nothing)
        because §5.12's exactly-once property is cheapest to honor at production time -- and
        restart-safe regardless, since the id scan reads the spool itself, not process memory.
        """
        if isinstance(msg, dict) and "payload" in msg:
            created = msg.get("created_at")
            env = dict(make_envelope(msg["payload"],
                                     sender=msg.get("sender") or DEFAULT_SENDER,
                                     recipient_role=msg.get("recipient_role") or "agent",
                                     causal_parent=msg.get("causal_parent") or "",
                                     message_id=msg.get("message_id"),
                                     expires_at=msg.get("expires_at") or None,
                                     hop_count=msg.get("hop_count") or 0))
            if created:
                # Re-spooling a foreign envelope must not rewrite its birth certificate: the
                # created_at travels WITH the message or replay ordering lies about age.
                env["created_at"] = str(created)
        else:
            env = make_envelope(msg)
        mid = env["message_id"]
        known = self._known_ids()
        if mid in known:
            return mid
        seq = self._next_seq()
        env["sequence"] = seq
        env["delivery_state"] = "spooled"
        self._write_json(self._spool / ("%012d.%s.json" % (seq, mid)), env)
        return mid

    # ---- consuming ------------------------------------------------------------------------------

    def receive(self, cursor: int):
        """(messages_after_cursor_in_sequence_order, next_cursor). Never raises on garbage."""
        report = self.receive_report(cursor)
        return report["messages"], report["next_cursor"]

    def receive_report(self, cursor: int) -> dict:
        """receive() plus honest accounting: expired_count and duplicate ids skipped.

        WHY BOTH: §5.12 requires TTL cleanup to be visible ("expired moved ... count reported")
        and redelivery to be provably deduped. The stable receive() signature belongs to adapter
        callers; this shape belongs to controls and operators who need the numbers.
        """
        entries = []
        for path in self._spool.glob("*.json"):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    env = json.load(handle)
            except (OSError, ValueError):
                continue  # partial/unreadable file: loud-by-absence now (§17), never deleted
            if isinstance(env, dict) and env.get("message_id"):
                entries.append((path, env))
        entries.sort(key=lambda item: (int(item[1].get("sequence") or 0), item[0].name))

        messages, next_cursor = [], int(cursor)
        seen_ids, duplicates, expired_count = set(), 0, 0
        now = _utcnow()
        for path, env in entries:
            seq = int(env.get("sequence") or 0)
            next_cursor = max(next_cursor, seq)   # advance past EVERYTHING examined, incl. junk
            mid = str(env["message_id"])
            if mid in seen_ids:
                # Defensive second layer behind append-time dedup: foreign/duplicated writers
                # must not turn one logical message into two deliveries.
                duplicates += 1
                continue
            seen_ids.add(mid)
            if seq <= int(cursor):
                continue                          # already acked window
            if self._is_expired(env, now):
                expired_count += self._expire(path, env)
                continue
            messages.append(env)

        return {"messages": messages, "next_cursor": next_cursor,
                "expired_count": expired_count, "duplicate_ids_skipped": duplicates}

    def ack(self, cursor: int) -> dict:
        """Persist the ack cursor atomically; returns the record written."""
        record = {"ack_cursor": int(cursor), "updated_at": _utcnow().isoformat()}
        self._write_json(self._dir / "cursor.json", record)
        return record

    def ack_cursor(self) -> int:
        """The persisted ack cursor, 0 when none. Reads disk, never memory -- restart honesty."""
        path = self._dir / "cursor.json"
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return int(json.load(handle).get("ack_cursor") or 0)
        except (OSError, ValueError, AttributeError):
            return 0

    def expired_messages(self) -> list:
        """The TTL graveyard, oldest first. Existence here is the audit trail §5.12 asks for."""
        out = []
        if not self._expired.is_dir():
            return out
        for path in sorted(self._expired.glob("*.json")):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    out.append(json.load(handle))
            except (OSError, ValueError):
                continue
        return out

    # ---- internals --------------------------------------------------------------------------------

    @staticmethod
    def _is_expired(env: dict, now: datetime) -> bool:
        raw = str(env.get("expires_at") or "")
        if not raw:
            return False
        try:
            expiry = datetime.fromisoformat(raw)
        except ValueError:
            # Unparseable TTL on INBOUND traffic: fail closed. Delivering a message whose death
            # we cannot compute risks delivering stale state; expiring it merely loses transient
            # traffic -- and the move to expired/ leaves the evidence inspectable.
            return True
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry <= now

    def _expire(self, path: Path, env: dict) -> int:
        env["delivery_state"] = "expired"
        self._expired.mkdir(parents=True, exist_ok=True)
        self._write_json(self._expired / path.name, env)
        path.unlink(missing_ok=True)
        return 1

    def _known_ids(self) -> set:
        ids = set()
        for directory in (self._spool, self._expired):
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                parts = path.name.split(".", 2)
                if len(parts) >= 2:
                    ids.add(parts[1])
        return ids

    def _next_seq(self) -> int:
        highest = 0
        for directory in (self._spool, self._expired):
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                head = path.name.split(".", 1)[0]
                if head.isdigit():
                    highest = max(highest, int(head))
        return highest + 1

    @staticmethod
    def _write_json(path: Path, body: dict) -> None:
        # Atomic publish, same discipline as filebox: readers see whole documents only, so a
        # crash mid-write shows up as absence, never as a half-envelope that looks delivered.
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".partial-%s" % os.getpid())
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(body, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

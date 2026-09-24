"""state -- the durable record that makes a restarted relay the SAME relay.

THE ONE PROPERTY THIS FILE BUYS
-------------------------------
    An already-delivered turn must never look new after a restart.

Everything else here exists to serve that. The delivery ledger is written in three moves, and
the middle one is the whole point:

    OBSERVED    we read a completed turn at an endpoint
    DELIVERING  we are about to hand it to the other endpoint  <- written BEFORE the send
    DELIVERED   the endpoint accepted it

A crash between the second and third leaves a row in DELIVERING. That state is UNCERTAIN, and
uncertainty is not a licence to repeat: ``reconcile_pending`` asks the receiving endpoint
whether it already holds the relay-assigned id. Blind re-delivery would duplicate work in a
repository; blind skipping would drop it. Only the endpoint knows, so only the endpoint is
asked, and an endpoint that cannot answer leaves the relay stopped with a named reason rather
than silently choosing.

WHY A SEPARATE DATABASE FROM ``core.store``
-------------------------------------------
``core.store`` is Program Mode's admission/lease/run ledger; its tables model runs, worktree
leases and seat results, none of which a relay has. Bolting relay tables onto it would make the
relay depend on Program Mode's schema and migrations for no gain. The OWNER GRANT LEDGER is the
deliberate exception -- authority is one platform-wide fact, so ``effects`` reads grants from
``core.store`` rather than inventing a second, forgeable ledger here.

Impure by definition (SQLite). Every write is a transaction; every read is total.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Mapping, Sequence
from urllib.request import pathname2url

STATE_INSTRUMENT = "relay.state/1"

# Relay lifecycle states, as printed by ``relay status``.
RUNNING = "RUNNING"
PAUSED = "PAUSED"
OWNER_HOLD = "OWNER_HOLD"
STOPPED = "STOPPED"
FAILED = "FAILED"

# Delivery ledger states.
OBSERVED = "OBSERVED"
DELIVERING = "DELIVERING"
DELIVERED = "DELIVERED"
#: Reconciliation decided the endpoint never got it and it is safe to send again -- because the
#: endpoint said so, not because we assumed it.
REDELIVERABLE = "REDELIVERABLE"
#: Reconciliation found the endpoint already holds it. Never sent again.
CONFIRMED_AFTER_CRASH = "CONFIRMED_AFTER_CRASH"
#: The endpoint could not answer. The relay stops rather than choosing between duplicating work
#: and dropping it.
UNRECONCILABLE = "UNRECONCILABLE"
#: An effect gate REFUSED this message. It is recorded so a human can read exactly what was
#: asked, and it is NOT in the delivery queue: releasing it requires the gate to pass with the
#: grants in force at that moment. Without a state of its own it sat in OBSERVED, and ``resume``
#: -- the documented way to continue after a crash -- picked it straight back off the queue and
#: delivered it with no grant and no re-gating.
OWNER_HELD = "OWNER_HELD"

#: The ``relay`` columns a READER actually reads off a row -- ``summarise`` takes
#: ``awaiting_role`` and ``awaiting_message_id`` straight out of it. ``_migrate`` is how a
#: WRITER repairs a store an older build left short of them. A reader cannot migrate, so
#: this is the list a read CHECKS before it answers. See ``RelayState.open_read_only``.
READ_REQUIRED_COLUMNS = ("awaiting_message_id", "awaiting_native_id", "awaiting_role")


def _read_only_uri(path: str) -> str:
    """The ``mode=ro`` URI for ``path``. PURE.

    ``pathname2url`` rather than string interpolation, because a home holding '?', '#' or '%'
    would otherwise end the URI early or decode into a different path -- and the mode parameter,
    the only thing making the connection read-only, is what gets lost.

    A UNC PATH NEEDS ONE MORE THING, and it is not cosmetic. ``pathname2url`` renders a UNC path
    as ``//server/share/x``, so ``"file:" + that`` reads ``server`` as the URI's AUTHORITY.
    SQLite refuses any authority but an empty one or ``localhost`` -- "invalid uri authority:
    server" -- and even ``localhost`` then resolves to the wrong path. Measured against a real
    share: the plain form answers "unable to open database file" while the four-slash form, an
    EMPTY authority followed by the UNC path, opens and reads. So a UNC path gets one more
    ``//`` and a drive path is untouched.

    Without this, every Core read surface fails PERMANENTLY on a home under a UNC path -- which
    is strictly worse than the writing open it replaces, because that one opened the same store
    fine. Fail-closed, but closed on a store that is perfectly readable.
    """
    url = pathname2url(os.path.abspath(path))
    # A UNC path renders as "//server/share/x"; a DRIVE path renders as "///C:/x". Both begin
    # "//", and only the first has a host where the authority goes, so the third slash is what
    # tells them apart -- not the second.
    if url.startswith("//") and not url.startswith("///"):
        url = "//" + url        # empty authority, then the UNC path
    return "file:" + url + "?mode=ro"


class StoreNotReadable(Exception):
    """This store cannot be answered from, and the reason is NOT "there are no relays".

    Named because the two arrive in the same shape -- no rows -- and the difference decides
    whether Quaestor Core's idle watchdog may shut itself down. An empty ledger is
    permission to go away. An unreadable one is not, and a reader that flattened the second
    into the first would shut Core down on top of a live relay or a standing owner hold.
    """

SCHEMA = """
CREATE TABLE IF NOT EXISTS relay (
    relay_id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    repo_id TEXT NOT NULL DEFAULT '',
    objective TEXT NOT NULL DEFAULT '',
    orchestrator_kind TEXT NOT NULL DEFAULT '',
    orchestrator_conversation TEXT NOT NULL DEFAULT '',
    execution_kind TEXT NOT NULL DEFAULT '',
    execution_session TEXT NOT NULL DEFAULT '',
    authority_profile TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    stop_reason TEXT NOT NULL DEFAULT '',
    exchange_no INTEGER NOT NULL DEFAULT 0,
    round_trips INTEGER NOT NULL DEFAULT 0,
    owner_hold TEXT NOT NULL DEFAULT '',
    started_at REAL NOT NULL,
    last_activity_at REAL NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    -- THE OTHER HALF OF RECOVERY. The delivery ledger answers "was this message handed over?";
    -- these three answer "and did we ever collect the reply?". A relay killed while WAITING --
    -- which, for a slow agent turn, is where it spends nearly all of its time -- has an empty
    -- delivery queue and an outstanding turn. Without this it would resume, find nothing to
    -- send, and stop for no progress while the agent's finished work sat unread.
    awaiting_message_id TEXT NOT NULL DEFAULT '',
    awaiting_native_id TEXT NOT NULL DEFAULT '',
    awaiting_role TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS relay_message (
    relay_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    content_digest TEXT NOT NULL DEFAULT '',
    chars INTEGER NOT NULL DEFAULT 0,
    observed_at REAL NOT NULL DEFAULT 0,
    delivered_at REAL,
    delivery_state TEXT NOT NULL,
    delivery_id TEXT NOT NULL DEFAULT '',
    native_id TEXT NOT NULL DEFAULT '',
    exchange_no INTEGER NOT NULL DEFAULT 0,
    causal_parent TEXT NOT NULL DEFAULT '',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    text TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (relay_id, message_id)
);

CREATE TABLE IF NOT EXISTS relay_event (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    relay_id TEXT NOT NULL,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS relay_observation (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    relay_id TEXT NOT NULL,
    at REAL NOT NULL,
    exchange_no INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_relay_message_relay ON relay_message(relay_id, exchange_no);
CREATE INDEX IF NOT EXISTS ix_relay_event_relay ON relay_event(relay_id, event_id);
"""


class RelayState:
    """The relay's durable memory. One SQLite file, opened per process.

    TWO WAYS IN, and they are not interchangeable. ``RelayState(path)`` is the OWNER's
    connection: it creates the file, the schema and any column an older build lacks.
    ``RelayState.open_read_only(path)`` is for a surface that only reports -- it creates
    nothing, migrates nothing, and SQLite refuses its writes.
    """

    def __init__(self, path: str, *, clock=time.time):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._conn = sqlite3.connect(path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # A relay that reported a delivery it had not durably recorded would defeat the entire
        # ledger, so durability is not traded for speed here.
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()
        self._clock = clock
        self.path = path

    @classmethod
    def open_read_only(cls, path: str, *, clock=time.time) -> "RelayState":
        """A connection SQLite ITSELF will not let write this ledger. Impure. RAISES.

        ``__init__`` IS A WRITE. It creates the directory, converts the journal mode, runs
        ``SCHEMA`` and then ``_migrate``, which is ``ALTER TABLE``. That is right for the relay,
        which owns this file. It is wrong for Quaestor Core, which opens the same store to answer
        ``relay.list``, ``relay.status`` and its own idle check -- unattended, once a second
        while it is obligated. A surface documented as reading was migrating an operator's
        ledger, and an operator could not reason about what a read costs.

        The ban is enforced by SQLite through the ``mode=ro`` URI, not by this class remembering
        not to write: one object serves both callers, and a rule that lives only in a docstring
        is one refactor away from being untrue.

        WHAT A READ STILL COSTS, stated rather than denied, because honesty is the whole point
        of this method. A WAL database cannot be read without its shared-memory index, so SQLite
        may materialise ``-shm`` and a ZERO-LENGTH ``-wal`` beside the file -- and on a store no
        writer currently holds, a read-only connection cannot checkpoint them away again on
        close. Those are SQLite's coordination state. The LEDGER is untouched: not a row, not
        the schema, not the journal mode, not one byte of the database file.

        AN OLD STORE REFUSES RATHER THAN ANSWERS. A read-only connection cannot add a column an
        older build never wrote, and ``summarise`` reads that column. Answering anyway means
        reporting a waiting relay as waiting on nobody -- or, once the ``KeyError`` is swallowed
        by a caller that treats any failure as no rows, reporting that the machine has NO
        relays, which is exactly the answer that tells an idle watchdog it may shut down on top
        of one. So the store is checked and the refusal is NAMED and travels.
        """
        # A READ DOES NOT CREATE WHAT IT IS READING. ``__init__`` would make the directory and
        # the whole schema, so a read of a home where no relay has ever run manufactured an
        # empty ledger; only the caller's own existence check stood between that and the disk,
        # and a check a caller can forget is not a guarantee. Here it cannot be forgotten.
        if not os.path.isfile(path):
            raise StoreNotReadable("no relay store at %s; a read does not create one" % path)
        self = cls.__new__(cls)
        self._clock = clock
        self.path = path
        # ``pathname2url`` rather than string interpolation: a home holding '?', '#' or '%'
        # would otherwise end the URI early or decode into a different path, and the mode
        # parameter -- the only thing making this connection read-only -- is what gets lost.
        try:
            self._conn = sqlite3.connect(_read_only_uri(path), uri=True, timeout=30.0)
        except sqlite3.Error as exc:
            raise StoreNotReadable("relay store at %s will not open read-only: %s: %s"
                                   % (path, type(exc).__name__, exc))
        self._conn.row_factory = sqlite3.Row
        try:
            have = {r[1] for r in self._conn.execute("PRAGMA table_info(relay)").fetchall()}
        except sqlite3.Error as exc:
            self.close()
            raise StoreNotReadable("relay store at %s is unreadable: %s: %s"
                                   % (path, type(exc).__name__, exc))
        missing = [c for c in READ_REQUIRED_COLUMNS if c not in have]
        if not have or missing:
            self.close()
            raise StoreNotReadable(
                "relay store at %s predates this build (%s); a read will not migrate it, and "
                "answering from it would report relays that are not there and miss relays that "
                "are" % (path, ", ".join(missing) if have else "no relay table"))
        return self

    def _migrate(self) -> None:
        """Add columns a database written by an older build lacks. Idempotent.

        ``CREATE TABLE IF NOT EXISTS`` leaves an existing table exactly as it was, so a schema
        that grew a column would read fine and write ``no such column`` at the worst moment --
        during recovery, which is the one path that must work on a database somebody else's
        process created.
        """
        have = {r[1] for r in self._conn.execute("PRAGMA table_info(relay)").fetchall()}
        for col in ("awaiting_message_id", "awaiting_native_id", "awaiting_role"):
            if col not in have:
                self._conn.execute("ALTER TABLE relay ADD COLUMN %s TEXT NOT NULL DEFAULT ''"
                                   % col)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001 - close must never be the thing that fails a shutdown
            pass

    # -- helpers ------------------------------------------------------------------------------
    def _now(self) -> float:
        return float(self._clock())

    @staticmethod
    def _row(r) -> dict | None:
        return dict(r) if r is not None else None

    def _one(self, sql: str, args: Sequence = ()) -> dict | None:
        return self._row(self._conn.execute(sql, tuple(args)).fetchone())

    def _all(self, sql: str, args: Sequence = ()) -> list:
        return [dict(r) for r in self._conn.execute(sql, tuple(args)).fetchall()]

    # -- relay lifecycle ----------------------------------------------------------------------
    def create(self, relay_id: str, *, project_root: str, repo_id: str, objective: str,
               orchestrator_kind: str, execution_kind: str, authority_profile: str,
               config: Mapping | None = None) -> dict:
        now = self._now()
        with self._conn:
            self._conn.execute(
                "INSERT INTO relay (relay_id, project_root, repo_id, objective, "
                "orchestrator_kind, execution_kind, authority_profile, state, started_at, "
                "last_activity_at, config_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (relay_id, project_root, repo_id, objective, orchestrator_kind, execution_kind,
                 authority_profile, RUNNING, now, now,
                 json.dumps(dict(config or {}), sort_keys=True, default=str)))
        self.append_event(relay_id, "relay.created",
                          {"project_root": project_root, "orchestrator": orchestrator_kind,
                           "execution": execution_kind, "profile": authority_profile})
        return self.get(relay_id)

    def get(self, relay_id: str) -> dict | None:
        return self._one("SELECT * FROM relay WHERE relay_id=?", (relay_id,))

    def latest(self, project_root: str = "") -> dict | None:
        if project_root:
            return self._one("SELECT * FROM relay WHERE project_root=? "
                             "ORDER BY started_at DESC LIMIT 1", (project_root,))
        return self._one("SELECT * FROM relay ORDER BY started_at DESC LIMIT 1")

    def list_relays(self, limit: int = 50) -> list:
        return self._all("SELECT * FROM relay ORDER BY started_at DESC LIMIT ?", (int(limit),))

    def update(self, relay_id: str, **fields) -> None:
        """Patch named columns. Unknown columns are REFUSED, never silently dropped: a typo'd
        field name that vanished would make a status surface print a stale value forever."""
        allowed = {"orchestrator_conversation", "execution_session", "state", "stop_reason",
                   "exchange_no", "round_trips", "owner_hold", "last_activity_at", "objective",
                   "repo_id", "config_json", "awaiting_message_id", "awaiting_native_id",
                   "awaiting_role"}
        bad = sorted(set(fields) - allowed)
        if bad:
            raise ValueError("relay state has no column(s) %s; refusing a silent no-op write"
                             % ", ".join(bad))
        if not fields:
            return
        fields.setdefault("last_activity_at", self._now())
        sets = ", ".join("%s=?" % k for k in fields)
        with self._conn:
            self._conn.execute("UPDATE relay SET %s WHERE relay_id=?" % sets,
                               (*fields.values(), relay_id))

    def request_stop(self, relay_id: str, reason: str, *, from_states=(RUNNING,),
                     by: str = "") -> bool:
        """Ask a relay in one of ``from_states`` to stop. Returns whether it applied. Impure.

        CONDITIONAL, in one statement, for two reasons. A relay that has already FINISHED has a
        stop_reason that answers "why did this end" -- OBJECTIVE_COMPLETE, a disconnect, an
        uncorroborated completion claim -- and overwriting it with STOPPED_BY_OPERATOR destroys
        the answer while inventing an operator act that never happened. And the relay driving
        itself is writing this same row concurrently, so read-then-write would race the very
        transition it must not overwrite.

        ``from_states`` is a list rather than the single RUNNING it started as, because a relay
        parked in OWNER_HOLD has no process and no way to discharge itself: if only a RUNNING
        relay could be stopped, an owner who decided NOT to grant a capability left an
        obligation that pinned the service's idle shutdown for the life of the state home, with
        no operation able to clear it. The reason it is leaving is preserved in the event, so
        nothing is lost by ending it.

        ``by`` names the client, because "an operator did this" is a claim, and an authenticated
        client is not an operator.
        """
        states = tuple(str(s) for s in (from_states or (RUNNING,)))
        before = self.get(relay_id) or {}
        placeholders = ",".join("?" for _ in states)
        with self._conn:
            cur = self._conn.execute(
                "UPDATE relay SET state=?, stop_reason=?, last_activity_at=? "
                "WHERE relay_id=? AND state IN (%s)" % placeholders,
                (STOPPED, str(reason), self._now(), str(relay_id), *states))
        applied = bool(cur.rowcount)
        if applied:
            self.append_event(relay_id, "relay.stop_requested",
                              {"reason": str(reason), "by": str(by),
                               "previous_state": str(before.get("state") or ""),
                               "previous_stop_reason": str(before.get("stop_reason") or ""),
                               "owner_hold": str(before.get("owner_hold") or "")})
        return applied

    def resume_running(self, relay_id: str, *, from_state: str, from_stop_reason: str) -> bool:
        """Put a relay back to RUNNING and clear its diagnosis, only if neither has moved.

        CONDITIONAL FOR THE REASON ``request_stop`` IS, pointing the other way. A resume reads
        the state a relay is parked in and the reason it was parked on, then spends a live round
        trip per pending delivery asking endpoints what they already hold. An operator stop
        landing in that window writes STOPPED and a reason of its own, and that reason is not
        the resume's to erase: an unconditional write here would blank a diagnosis this resume
        never read, let alone superseded, and would put a stopped relay back into RUNNING while
        reporting success. One statement, because read-then-write races the very transition it
        must not overwrite.

        Returns whether it applied.
        """
        with self._conn:
            cur = self._conn.execute(
                "UPDATE relay SET state=?, stop_reason='', last_activity_at=? "
                "WHERE relay_id=? AND state=? AND stop_reason=?",
                (RUNNING, self._now(), str(relay_id), str(from_state), str(from_stop_reason)))
        return bool(cur.rowcount)

    # -- events -------------------------------------------------------------------------------
    def append_event(self, relay_id: str, kind: str, payload: Mapping | None = None) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO relay_event (relay_id, at, kind, payload_json) VALUES (?,?,?,?)",
                (relay_id, self._now(), str(kind),
                 json.dumps(dict(payload or {}), sort_keys=True, default=str)))

    def events(self, relay_id: str, limit: int = 200) -> list:
        """The event log, newest-first internally and returned oldest-first.

        ``limit <= 0`` means EVERY event. A caller that is counting -- rather than displaying --
        must not silently read a window: the completion-refusal bound is derived from this log,
        and a bounded read would let a long relay forget its refusals and re-claim completion
        forever. SQLite treats a negative LIMIT as unbounded, which is what -1 selects here.
        """
        rows = self._all("SELECT * FROM relay_event WHERE relay_id=? ORDER BY event_id DESC "
                         "LIMIT ?", (relay_id, int(limit) if int(limit) > 0 else -1))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
        return list(reversed(rows))

    # -- observations -------------------------------------------------------------------------
    def record_observation(self, relay_id: str, exchange_no: int, payload: Mapping) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO relay_observation (relay_id, at, exchange_no, payload_json) "
                "VALUES (?,?,?,?)",
                (relay_id, self._now(), int(exchange_no),
                 json.dumps(dict(payload or {}), sort_keys=True, default=str)))

    def observations(self, relay_id: str, limit: int = 100) -> list:
        """Independent repository readings, returned oldest-first. ``limit <= 0`` means ALL.

        Same rule as ``events``: a caller comparing the FIRST reading with the LAST cannot use a
        window, because the first reading is the one a window drops.
        """
        rows = self._all("SELECT * FROM relay_observation WHERE relay_id=? ORDER BY obs_id DESC "
                         "LIMIT ?", (relay_id, int(limit) if int(limit) > 0 else -1))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
        return list(reversed(rows))

    # -- the delivery ledger ------------------------------------------------------------------
    def seen(self, relay_id: str, message_id: str) -> dict | None:
        return self._one("SELECT * FROM relay_message WHERE relay_id=? AND message_id=?",
                         (relay_id, message_id))

    def observe(self, relay_id: str, msg, *, exchange_no: int, causal_parent: str = "",
                text: str = "") -> bool:
        """Record a turn we just read. Returns False if it was already known (stale replay).

        The INSERT is conditional in SQL rather than in Python because two readers of the same
        endpoint must not both conclude "new".
        """
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO relay_message (relay_id, message_id, direction, "
            "content_digest, chars, observed_at, delivery_state, exchange_no, causal_parent, "
            "provenance_json, text) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (relay_id, msg.message_id, msg.direction, msg.content_digest, len(msg.text or ""),
             float(msg.observed_at or self._now()), OBSERVED, int(exchange_no), causal_parent,
             json.dumps(dict(msg.provenance or {}), sort_keys=True, default=str),
             str(text if text else (msg.text or ""))))
        self._conn.commit()
        return cur.rowcount > 0

    def begin_delivery(self, relay_id: str, message_id: str, *, delivery_id: str) -> None:
        """Write the intent to deliver BEFORE the send. This row is the crash evidence."""
        with self._conn:
            self._conn.execute(
                "UPDATE relay_message SET delivery_state=?, delivery_id=? "
                "WHERE relay_id=? AND message_id=?",
                (DELIVERING, delivery_id, relay_id, message_id))

    def complete_delivery(self, relay_id: str, message_id: str, *, native_id: str = "",
                          state: str = DELIVERED) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE relay_message SET delivery_state=?, delivered_at=?, native_id=? "
                "WHERE relay_id=? AND message_id=?",
                (state, self._now(), native_id, relay_id, message_id))

    def mark_delivery(self, relay_id: str, message_id: str, state: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE relay_message SET delivery_state=? WHERE relay_id=? AND message_id=?",
                (state, relay_id, message_id))

    def pending_deliveries(self, relay_id: str) -> list:
        """Rows left mid-delivery by a crash. These are UNCERTAIN, not undelivered."""
        return self._all("SELECT * FROM relay_message WHERE relay_id=? AND delivery_state=? "
                         "ORDER BY exchange_no", (relay_id, DELIVERING))

    def undelivered(self, relay_id: str) -> list:
        return self._all("SELECT * FROM relay_message WHERE relay_id=? AND delivery_state IN "
                         "(?,?) ORDER BY exchange_no", (relay_id, OBSERVED, REDELIVERABLE))

    def delivered_ids(self, relay_id: str) -> set:
        rows = self._all("SELECT message_id FROM relay_message WHERE relay_id=? AND "
                         "delivery_state IN (?,?)",
                         (relay_id, DELIVERED, CONFIRMED_AFTER_CRASH))
        return {r["message_id"] for r in rows}

    def messages(self, relay_id: str, direction: str = "", limit: int = 500) -> list:
        """The message ledger. ``limit <= 0`` means EVERY row -- see ``events``."""
        limit = int(limit) if int(limit) > 0 else -1
        if direction:
            rows = self._all("SELECT * FROM relay_message WHERE relay_id=? AND direction=? "
                             "ORDER BY exchange_no, observed_at LIMIT ?",
                             (relay_id, direction, limit))
        else:
            rows = self._all("SELECT * FROM relay_message WHERE relay_id=? "
                             "ORDER BY exchange_no, observed_at LIMIT ?", (relay_id, limit))
        for r in rows:
            r["provenance"] = json.loads(r.pop("provenance_json") or "{}")
        return rows

    def last_message(self, relay_id: str, direction: str) -> dict | None:
        rows = self._all("SELECT * FROM relay_message WHERE relay_id=? AND direction=? "
                         "ORDER BY exchange_no DESC, observed_at DESC LIMIT 1",
                         (relay_id, direction))
        return rows[0] if rows else None

    def recent_digests(self, relay_id: str, direction: str, n: int = 3) -> list:
        rows = self._all("SELECT content_digest FROM relay_message WHERE relay_id=? AND "
                         "direction=? ORDER BY exchange_no DESC, observed_at DESC LIMIT ?",
                         (relay_id, direction, int(n)))
        return [r["content_digest"] for r in rows]

    def counts(self, relay_id: str) -> dict:
        row = self._one(
            "SELECT COUNT(*) AS observed, "
            "SUM(CASE WHEN delivery_state IN ('DELIVERED','CONFIRMED_AFTER_CRASH') THEN 1 ELSE 0 "
            "END) AS delivered FROM relay_message WHERE relay_id=?", (relay_id,))
        return {"observed": int((row or {}).get("observed") or 0),
                "delivered": int((row or {}).get("delivered") or 0)}

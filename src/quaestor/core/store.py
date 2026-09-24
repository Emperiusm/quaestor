"""store -- the durable system of record. SQLite, not JSON files.

WHY SQLITE AND NOT FILES
------------------------
The run directory holds files too, and they matter (stdout, stderr, exit receipt) -- but they are
ARTIFACTS, not the state machine. A state machine made of JSON files has no atomic
compare-and-set, so "is there already an active execution for this dispatch key?" degrades to a
directory listing plus a hope. SQLite gives us the two things the duplicate-execution defence
actually needs:

  * a UNIQUE index, so ``dispatch_key`` collides in the DATABASE rather than in an ``if``; and
  * a real transaction, so admission (insert dispatch + insert attempt) is one indivisible act.

TWO DATABASE-LEVEL INVARIANTS -- read these before changing the schema
----------------------------------------------------------------------
 1. ``attempt_one_active``: a UNIQUE partial index on ``dispatch_key`` restricted to
    ``domain.ACTIVE_STATES``. At most one active execution per dispatch key, enforced by the
    engine. If a future code path forgets to check, the INSERT still fails.
 2. ``lease_one_active``: a UNIQUE partial index on ``worktree_path`` where ``released_at IS
    NULL``. One writer per worktree, same reasoning.

Both are derived from the domain tuples at migration time, so the constant and the constraint
cannot drift apart.

WHAT IS DELIBERATELY NOT STORED: model reasoning, prompts in full, credentials, tokens, emails,
org identifiers. Prompts are stored as a sha256; ``report_markdown`` from a handoff is kept
because it is the human deliverable, and it is the ONE free-text field, bounded by the schema.

THE EVENT LOG IS APPEND-ONLY, and that is enforced by SQLite triggers rather than by convention:
UPDATE and DELETE on ``event`` raise. A reconstructible history that a later bug can quietly
rewrite is not a history.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from quaestor.core import domain
from quaestor.core.canon import canonical_json, canonical_path
from quaestor.core.executor_contract import (HANDOFF_STRENGTH_DEGRADED,
                       HANDOFF_STRENGTH_NATIVE, HANDOFF_STRENGTH_WEAK)
from quaestor.core.identity import DispatchIdentity

SCHEMA_VERSION = 1


class TransitionRefused(RuntimeError):
    """A state transition was illegal, or the run was not in the expected state."""


class LeaseConflict(RuntimeError):
    """The worktree is already leased to another run."""


def _q(values: Iterable[str]) -> str:
    return ", ".join("'%s'" % str(v).replace("'", "''") for v in values)


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS workflow(
  workflow_id TEXT PRIMARY KEY,
  title       TEXT NOT NULL DEFAULT '',
  created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dispatch(
  dispatch_key      TEXT PRIMARY KEY,
  workflow_id       TEXT NOT NULL REFERENCES workflow(workflow_id),
  step_id           TEXT NOT NULL,
  prompt_sha256     TEXT NOT NULL,
  repo_id           TEXT NOT NULL,
  worktree_path     TEXT NOT NULL,
  expected_branch   TEXT NOT NULL,
  expected_head     TEXT NOT NULL,
  authority_profile TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  identity_json     TEXT NOT NULL,
  created_at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attempt(
  run_id          TEXT PRIMARY KEY,
  dispatch_key    TEXT NOT NULL REFERENCES dispatch(dispatch_key),
  attempt_no      INTEGER NOT NULL,
  run_nonce       TEXT NOT NULL,
  execution_state TEXT NOT NULL,
  is_write        INTEGER NOT NULL,
  run_dir         TEXT NOT NULL,
  created_at      REAL NOT NULL,
  updated_at      REAL NOT NULL,
  terminal_at     REAL,
  refusal_reason  TEXT
);

CREATE TABLE IF NOT EXISTS lease(
  lease_id        TEXT PRIMARY KEY,
  repo_id         TEXT NOT NULL,
  worktree_path   TEXT NOT NULL,
  expected_branch TEXT NOT NULL,
  expected_head   TEXT NOT NULL,
  holder_run_id   TEXT NOT NULL REFERENCES attempt(run_id),
  epoch           INTEGER NOT NULL,
  acquired_at     REAL NOT NULL,
  heartbeat_at    REAL NOT NULL,
  released_at     REAL,
  release_reason  TEXT
);

CREATE TABLE IF NOT EXISTS worker(
  run_id              TEXT PRIMARY KEY REFERENCES attempt(run_id),
  spawn_pid           INTEGER,
  worker_pid          INTEGER,
  worker_create_time  TEXT,
  lock_path           TEXT NOT NULL DEFAULT '',
  child_pid           INTEGER,
  child_create_time   TEXT,
  stdout_path         TEXT NOT NULL DEFAULT '',
  stderr_path         TEXT NOT NULL DEFAULT '',
  spawned_at          REAL,
  started_at          REAL,
  finished_at         REAL,
  exit_code           INTEGER,
  exit_class          TEXT
);

CREATE TABLE IF NOT EXISTS result(
  run_id                     TEXT PRIMARY KEY REFERENCES attempt(run_id),
  received_at                REAL NOT NULL,
  raw_sha256                 TEXT NOT NULL,
  valid                      INTEGER NOT NULL,
  outcome                    TEXT NOT NULL,
  invalid_reason             TEXT,
  session_id                 TEXT,
  claude_version             TEXT,
  prompt_disposition         TEXT,
  program_verdict            TEXT,
  next_authority             TEXT,
  acceptance_state           TEXT,
  owner_decision_required    INTEGER,
  authorized_scope_exhausted INTEGER,
  continuation_allowed       INTEGER,
  smallest_blocker           TEXT,
  next_action                TEXT,
  summary                    TEXT,
  handoff_json               TEXT
);

CREATE TABLE IF NOT EXISTS evidence(
  run_id          TEXT PRIMARY KEY REFERENCES attempt(run_id),
  collected_at    REAL NOT NULL,
  verdict         TEXT NOT NULL,
  probe_ok        INTEGER NOT NULL,
  inspected_count INTEGER NOT NULL,
  observed_change INTEGER,
  envelope_json   TEXT NOT NULL,
  reason          TEXT
);

CREATE TABLE IF NOT EXISTS handoff(
  run_id       TEXT PRIMARY KEY REFERENCES attempt(run_id),
  ready_at     REAL NOT NULL,
  handoff_json TEXT NOT NULL,
  delivered_at REAL
);

CREATE TABLE IF NOT EXISTS owner_grant(
  grant_id   TEXT PRIMARY KEY,
  capability TEXT NOT NULL,
  scope      TEXT NOT NULL DEFAULT '*',
  granted_at REAL NOT NULL,
  expires_at REAL,
  revoked_at REAL,
  note       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS event(
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  at           REAL NOT NULL,
  run_id       TEXT,
  dispatch_key TEXT,
  kind         TEXT NOT NULL,
  from_state   TEXT,
  to_state     TEXT,
  detail_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS attempt_by_key   ON attempt(dispatch_key);
CREATE INDEX IF NOT EXISTS lease_by_path    ON lease(worktree_path);
CREATE INDEX IF NOT EXISTS event_by_run     ON event(run_id, seq);

CREATE TRIGGER IF NOT EXISTS event_no_update BEFORE UPDATE ON event
BEGIN SELECT RAISE(ABORT, 'event log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_no_delete BEFORE DELETE ON event
BEGIN SELECT RAISE(ABORT, 'event log is append-only'); END;
"""

# Built from the domain tuple so the constraint cannot drift from the constant it encodes.
INDEX_ACTIVE_ATTEMPT = (
    "CREATE UNIQUE INDEX IF NOT EXISTS attempt_one_active ON attempt(dispatch_key) "
    "WHERE execution_state IN (%s)" % _q(domain.ACTIVE_STATES))
INDEX_ACTIVE_LEASE = (
    "CREATE UNIQUE INDEX IF NOT EXISTS lease_one_active ON lease(worktree_path) "
    "WHERE released_at IS NULL")


@dataclass(frozen=True)
class Admission:
    """The outcome of ``admit``. ``created`` is False when the dispatch key already existed."""

    run_id: str
    dispatch_key: str
    created: bool
    run: Mapping
    dispatch: Mapping


class Store:
    """The durable store. One instance per process; SQLite handles the rest."""

    def __init__(self, path: str, *, clock=time.time):
        self.path = str(path)
        self.clock = clock
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=30000")
        self._migrate()

    # -- lifecycle ----------------------------------------------------------------------------
    def _migrate(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.execute(INDEX_ACTIVE_ATTEMPT)
        self.conn.execute(INDEX_ACTIVE_LEASE)
        self.conn.execute("INSERT OR REPLACE INTO schema_meta(k, v) VALUES('version', ?)",
                          (str(SCHEMA_VERSION),))

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # -- helpers ------------------------------------------------------------------------------
    def _now(self) -> float:
        return float(self.clock())

    def _tx(self):
        return _Transaction(self.conn)

    @staticmethod
    def _row(r) -> dict | None:
        return None if r is None else dict(r)

    def _one(self, sql: str, args: Sequence = ()) -> dict | None:
        return self._row(self.conn.execute(sql, tuple(args)).fetchone())

    def _all(self, sql: str, args: Sequence = ()) -> list:
        return [dict(r) for r in self.conn.execute(sql, tuple(args)).fetchall()]

    # -- events -------------------------------------------------------------------------------
    def append_event(self, kind: str, *, run_id: str = "", dispatch_key: str = "",
                     from_state: str | None = None, to_state: str | None = None,
                     detail: Mapping | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO event(at, run_id, dispatch_key, kind, from_state, to_state, detail_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (self._now(), run_id or None, dispatch_key or None, str(kind), from_state, to_state,
             canonical_json(dict(detail or {}))))
        return int(cur.lastrowid)

    def events_for(self, run_id: str) -> list:
        return self._all("SELECT * FROM event WHERE run_id=? ORDER BY seq", (run_id,))

    # -- workflow -----------------------------------------------------------------------------
    def ensure_workflow(self, workflow_id: str, title: str = "") -> dict:
        self.conn.execute(
            "INSERT OR IGNORE INTO workflow(workflow_id, title, created_at) VALUES(?,?,?)",
            (workflow_id, title, self._now()))
        return self._one("SELECT * FROM workflow WHERE workflow_id=?", (workflow_id,))

    # -- admission ----------------------------------------------------------------------------
    def admit(self, identity: DispatchIdentity, *, run_root: str, is_write: bool,
              title: str = "") -> Admission:
        """Admit a dispatch. THE duplicate-execution defence.

        First identical dispatch  -> a new attempt.
        Second identical dispatch -> the EXISTING attempt, and NO new worker.

        Both branches happen inside one ``BEGIN IMMEDIATE`` transaction, so two dispatchers
        racing on the same key cannot both take the "create" branch: the loser blocks on the
        write lock and then observes the winner's row.

        Note what this does NOT do: it never creates a second attempt for a key whose previous
        attempt is terminal. A finished run is still THE answer for that dispatch key; re-running
        it is a new decision that belongs to GPT or the owner, and giving it a new key (a new
        step_id, or a new expected_head) is how they express it. Silently re-attempting here is
        precisely the blind retry the spec forbids.
        """
        key = identity.dispatch_key()
        with self._tx():
            self.conn.execute(
                "INSERT OR IGNORE INTO workflow(workflow_id, title, created_at) VALUES(?,?,?)",
                (identity.workflow_id, title, self._now()))
            existing = self._one("SELECT * FROM dispatch WHERE dispatch_key=?", (key,))
            if existing is not None:
                run = self._one(
                    "SELECT * FROM attempt WHERE dispatch_key=? ORDER BY attempt_no DESC LIMIT 1",
                    (key,))
                self.append_event("dispatch.duplicate", run_id=(run or {}).get("run_id", ""),
                                  dispatch_key=key,
                                  detail={"note": "identical dispatch key already admitted; "
                                                  "returning the existing execution"})
                return Admission((run or {}).get("run_id", ""), key, False, run or {}, existing)

            now = self._now()
            self.conn.execute(
                "INSERT INTO dispatch(dispatch_key, workflow_id, step_id, prompt_sha256, repo_id,"
                " worktree_path, expected_branch, expected_head, authority_profile,"
                " capabilities_json, identity_json, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, identity.workflow_id, identity.step_id, identity.prompt_sha256,
                 identity.repo_id, canonical_path(identity.worktree_path),
                 identity.expected_branch, str(identity.expected_head).lower(),
                 identity.authority_profile,
                 canonical_json(sorted(set(identity.capabilities or ()))),
                 identity.to_json(), now))

            run_id = str(uuid.uuid4())
            nonce = uuid.uuid4().hex
            run_dir = os.path.join(str(run_root), run_id).replace("\\", "/")
            self.conn.execute(
                "INSERT INTO attempt(run_id, dispatch_key, attempt_no, run_nonce, execution_state,"
                " is_write, run_dir, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (run_id, key, 1, nonce, domain.CREATED, 1 if is_write else 0, run_dir, now, now))
            self.append_event("dispatch.admitted", run_id=run_id, dispatch_key=key,
                              to_state=domain.CREATED,
                              detail={"workflow_id": identity.workflow_id,
                                      "step_id": identity.step_id,
                                      "authority_profile": identity.authority_profile,
                                      "is_write": bool(is_write)})
            run = self._one("SELECT * FROM attempt WHERE run_id=?", (run_id,))
            disp = self._one("SELECT * FROM dispatch WHERE dispatch_key=?", (key,))
        return Admission(run_id, key, True, run, disp)

    # -- runs ---------------------------------------------------------------------------------
    def get_run(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM attempt WHERE run_id=?", (run_id,))

    def get_dispatch(self, dispatch_key: str) -> dict | None:
        return self._one("SELECT * FROM dispatch WHERE dispatch_key=?", (dispatch_key,))

    def runs_in_states(self, states: Sequence[str]) -> list:
        if not states:
            return []
        marks = ",".join("?" * len(states))
        return self._all("SELECT * FROM attempt WHERE execution_state IN (%s) ORDER BY created_at"
                         % marks, tuple(states))

    def transition(self, run_id: str, to_state: str, *, expect_from: str | None = None,
                   reason: str = "", detail: Mapping | None = None) -> dict:
        """Durable, guarded state transition. Raises TransitionRefused.

        Two guards, both necessary:
          * the edge must be legal in ``domain.TRANSITIONS`` (no teleporting into HANDOFF_READY);
          * when ``expect_from`` is given, the row must still be in that state -- an optimistic
            compare-and-set, so a dispatcher and a reconciler racing on one run cannot both
            believe they moved it.
        """
        with self._tx():
            row = self._one("SELECT * FROM attempt WHERE run_id=?", (run_id,))
            if row is None:
                raise TransitionRefused("no such run %r" % run_id)
            src = str(row["execution_state"])
            if expect_from is not None and src != expect_from:
                raise TransitionRefused(
                    "run %s is in %s, expected %s -- refusing the transition to %s"
                    % (run_id, src, expect_from, to_state))
            if not domain.can_transition(src, to_state):
                raise TransitionRefused(
                    "illegal transition %s -> %s for run %s" % (src, to_state, run_id))
            now = self._now()
            terminal_at = now if domain.is_terminal(to_state) else None
            self.conn.execute(
                "UPDATE attempt SET execution_state=?, updated_at=?, terminal_at=COALESCE(?, "
                "terminal_at), refusal_reason=COALESCE(?, refusal_reason) WHERE run_id=?",
                (to_state, now, terminal_at, (reason or None), run_id))
            self.append_event("state", run_id=run_id, dispatch_key=str(row["dispatch_key"]),
                              from_state=src, to_state=to_state,
                              detail={"reason": reason, **dict(detail or {})})
            out = self._one("SELECT * FROM attempt WHERE run_id=?", (run_id,))
        return out

    # -- leases -------------------------------------------------------------------------------
    def active_lease(self, worktree_path: str) -> dict | None:
        return self._one("SELECT * FROM lease WHERE worktree_path=? AND released_at IS NULL",
                         (canonical_path(worktree_path),))

    def acquire_lease(self, *, repo_id: str, worktree_path: str, expected_branch: str,
                      expected_head: str, run_id: str) -> dict:
        """Take the lease, or raise LeaseConflict. The UNIQUE partial index is the real guard."""
        path = canonical_path(worktree_path)
        with self._tx():
            active = self._one(
                "SELECT * FROM lease WHERE worktree_path=? AND released_at IS NULL", (path,))
            if active is not None:
                if str(active["holder_run_id"]) == str(run_id):
                    return active
                raise LeaseConflict(
                    "worktree %s is leased to run %s" % (path, active["holder_run_id"]))
            now = self._now()
            epoch = int(self.conn.execute(
                "SELECT COALESCE(MAX(epoch), 0) + 1 FROM lease WHERE worktree_path=?",
                (path,)).fetchone()[0])
            lease_id = str(uuid.uuid4())
            try:
                self.conn.execute(
                    "INSERT INTO lease(lease_id, repo_id, worktree_path, expected_branch,"
                    " expected_head, holder_run_id, epoch, acquired_at, heartbeat_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (lease_id, repo_id, path, expected_branch, str(expected_head).lower(),
                     run_id, epoch, now, now))
            except sqlite3.IntegrityError as exc:
                raise LeaseConflict("worktree %s is already leased (%s)" % (path, exc)) from exc
            self.append_event("lease.acquired", run_id=run_id,
                              detail={"worktree_path": path, "epoch": epoch,
                                      "expected_head": str(expected_head).lower(),
                                      "expected_branch": expected_branch})
            out = self._one("SELECT * FROM lease WHERE lease_id=?", (lease_id,))
        return out

    def heartbeat_lease(self, lease_id: str) -> None:
        self.conn.execute("UPDATE lease SET heartbeat_at=? WHERE lease_id=? AND released_at IS NULL",
                          (self._now(), lease_id))

    def release_lease(self, lease_id: str, *, reason: str = "") -> None:
        with self._tx():
            row = self._one("SELECT * FROM lease WHERE lease_id=?", (lease_id,))
            if row is None or row.get("released_at") is not None:
                return
            self.conn.execute("UPDATE lease SET released_at=?, release_reason=? WHERE lease_id=?",
                              (self._now(), reason, lease_id))
            self.append_event("lease.released", run_id=str(row["holder_run_id"]),
                              detail={"worktree_path": row["worktree_path"], "reason": reason})

    def lease_for_run(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM lease WHERE holder_run_id=? ORDER BY epoch DESC LIMIT 1",
                         (run_id,))

    # -- worker -------------------------------------------------------------------------------
    def record_spawn(self, run_id: str, *, spawn_pid: int, lock_path: str, stdout_path: str,
                     stderr_path: str) -> None:
        self.conn.execute(
            "INSERT INTO worker(run_id, spawn_pid, lock_path, stdout_path, stderr_path, spawned_at)"
            " VALUES(?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET spawn_pid=excluded.spawn_pid,"
            " lock_path=excluded.lock_path, stdout_path=excluded.stdout_path,"
            " stderr_path=excluded.stderr_path, spawned_at=excluded.spawned_at",
            (run_id, int(spawn_pid), str(lock_path), str(stdout_path), str(stderr_path),
             self._now()))
        self.append_event("worker.spawned", run_id=run_id,
                          detail={"spawn_pid": int(spawn_pid), "lock_path": str(lock_path)})

    def record_worker_started(self, run_id: str, *, worker_pid: int,
                              worker_create_time: str | None, lock_path: str) -> None:
        self.conn.execute(
            "INSERT INTO worker(run_id, worker_pid, worker_create_time, lock_path, started_at)"
            " VALUES(?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET worker_pid=excluded.worker_pid,"
            " worker_create_time=excluded.worker_create_time, lock_path=excluded.lock_path,"
            " started_at=excluded.started_at",
            (run_id, int(worker_pid), worker_create_time, str(lock_path), self._now()))
        self.append_event("worker.started", run_id=run_id,
                          detail={"worker_pid": int(worker_pid),
                                  "worker_create_time": worker_create_time})

    def record_child(self, run_id: str, *, child_pid: int | None,
                     child_create_time: str | None) -> None:
        self.conn.execute(
            "UPDATE worker SET child_pid=?, child_create_time=? WHERE run_id=?",
            (None if child_pid is None else int(child_pid), child_create_time, run_id))
        self.append_event("child.started", run_id=run_id, detail={"child_pid": child_pid})

    def record_worker_exit(self, run_id: str, *, exit_code: int | None, exit_class: str) -> None:
        self.conn.execute(
            "UPDATE worker SET finished_at=?, exit_code=?, exit_class=? WHERE run_id=?",
            (self._now(), None if exit_code is None else int(exit_code), str(exit_class), run_id))
        self.append_event("worker.exit", run_id=run_id,
                          detail={"exit_code": exit_code, "exit_class": exit_class})

    def get_worker(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM worker WHERE run_id=?", (run_id,))

    # -- result / evidence / handoff ----------------------------------------------------------
    def record_result(self, run_id: str, *, raw_sha256: str, outcome: str, valid: bool,
                      invalid_reason: str = "", session_id: str = "", claude_version: str = "",
                      handoff: Mapping | None = None) -> None:
        h = dict(handoff or {})
        self.conn.execute(
            "INSERT INTO result(run_id, received_at, raw_sha256, valid, outcome, invalid_reason,"
            " session_id, claude_version, prompt_disposition, program_verdict, next_authority,"
            " acceptance_state, owner_decision_required, authorized_scope_exhausted,"
            " continuation_allowed, smallest_blocker, next_action, summary, handoff_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(run_id) DO UPDATE SET received_at=excluded.received_at,"
            " raw_sha256=excluded.raw_sha256, valid=excluded.valid, outcome=excluded.outcome,"
            " invalid_reason=excluded.invalid_reason, session_id=excluded.session_id,"
            " claude_version=excluded.claude_version, handoff_json=excluded.handoff_json",
            (run_id, self._now(), raw_sha256, 1 if valid else 0, str(outcome),
             invalid_reason or None, session_id or None, claude_version or None,
             h.get("prompt_disposition"), h.get("program_verdict"), h.get("next_authority"),
             h.get("acceptance_state"),
             _as_int_bool(h.get("owner_decision_required")),
             _as_int_bool(h.get("authorized_scope_exhausted")),
             _as_int_bool(h.get("continuation_allowed")),
             h.get("smallest_blocker"), h.get("next_action"), h.get("summary"),
             canonical_json(h) if h else None))
        self.append_event("result.recorded", run_id=run_id,
                          detail={"outcome": outcome, "valid": bool(valid),
                                  "invalid_reason": invalid_reason,
                                  "prompt_disposition": h.get("prompt_disposition"),
                                  "program_verdict": h.get("program_verdict")})

    def runs_for_workflow(self, workflow_id: str) -> list:
        """Every run dispatched under one workflow, NEWEST FIRST. Read-only.

        Program runs dispatch with ``workflow_id == program_id``, so this is how a PROGRAM-level
        run is found at all: the planner and strategist seats bind to no lane, so ``lane_run``
        -- the table every other drill-down reads -- has no row for them. Without this query the
        most consequential runs in the system are unreachable.

        The filter is exact-or-``id-``-prefix, never a bare starts-with: "prog-11" must not be
        counted under "prog-1". Same rule handoff_outcomes already applies.
        """
        return self._all(
            "SELECT a.*, d.workflow_id AS workflow_id, d.step_id AS step_id,"
            " d.authority_profile AS authority_profile"
            " FROM attempt a JOIN dispatch d ON d.dispatch_key = a.dispatch_key"
            " WHERE d.workflow_id = ? OR substr(d.workflow_id, 1, length(?) + 1) = ? || '-'"
            " ORDER BY a.created_at DESC",
            (workflow_id, workflow_id, workflow_id))

    def get_result(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM result WHERE run_id=?", (run_id,))

    def record_evidence(self, run_id: str, envelope: Mapping) -> None:
        e = dict(envelope)
        self.conn.execute(
            "INSERT INTO evidence(run_id, collected_at, verdict, probe_ok, inspected_count,"
            " observed_change, envelope_json, reason) VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(run_id) DO UPDATE SET collected_at=excluded.collected_at,"
            " verdict=excluded.verdict, probe_ok=excluded.probe_ok,"
            " inspected_count=excluded.inspected_count, observed_change=excluded.observed_change,"
            " envelope_json=excluded.envelope_json, reason=excluded.reason",
            (run_id, self._now(), str(e.get("verdict")),
             1 if (e.get("before", {}).get("probe_ok") is True
                   and e.get("after", {}).get("probe_ok") is True) else 0,
             int(e.get("inspected_count") or 0), _as_int_bool(e.get("observed_change")),
             canonical_json(e), e.get("reason") or None))
        self.append_event("evidence.recorded", run_id=run_id,
                          detail={"verdict": e.get("verdict"),
                                  "inspected_count": e.get("inspected_count"),
                                  "disagreements": e.get("disagreements")})

    def get_evidence(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM evidence WHERE run_id=?", (run_id,))

    def record_handoff(self, run_id: str, payload: Mapping) -> None:
        self.conn.execute(
            "INSERT INTO handoff(run_id, ready_at, handoff_json) VALUES(?,?,?)"
            " ON CONFLICT(run_id) DO UPDATE SET ready_at=excluded.ready_at,"
            " handoff_json=excluded.handoff_json",
            (run_id, self._now(), canonical_json(dict(payload))))
        self.append_event("handoff.ready", run_id=run_id,
                          detail={"program_verdict": payload.get("program_verdict"),
                                  "prompt_disposition": payload.get("prompt_disposition")})

    def get_handoff(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM handoff WHERE run_id=?", (run_id,))

    # -- outcome measurement ------------------------------------------------------------------
    def outcome_summary(self, program_id: str | None = None) -> dict:
        """Count run outcomes in ONE bounded pass, so the native-handoff rate is MEASURED.

        WHY THIS EXISTS: the live LOCAL_GOVERNED program (2026-08-24) finished 24/32 valid with
        8 children answering in prose, and no query could say so -- a human re-read thirty-two
        rows. PRD.md §28.2 requires handoff strength to be CLASSIFIED rather than averaged
        (NATIVE_SCHEMA_VALIDATED / EXACT_TEXT_JSON / FENCED_JSON_RECOVERED) and §67.8 scores
        handoff reliability from qualification evidence; the superseded direction doc's
        ">99% native/degraded" figure is historical, not a PRD target. Either way a rate nobody
        can print is a rate nobody can move. ``native_rate`` is valid-native / valid; a valid
        run whose handoff package is missing or unparseable counts as valid but never as
        native, so the denominator cannot be flattered by absent evidence. Strength comes from
        the handoff package's own ``handoff_strength`` label (worker-written); failure classes
        come from the ``[CLASS]`` prefix on invalid_reason (see worker._classified) -- reasons
        without the prefix predate quaestor-4ci and are deliberately not laundered into a class.

        Program runs dispatch with workflow_id == program_id (orchestrator), so the program
        filter is an exact-or-``id-``-prefix match on workflow_id, never a bare starts-with
        that would let "prog-11" count under "prog-1". NEVER raises: a reporting helper that
        can crash its caller would hide exactly the number it exists to expose.
        """
        summary = {"runs_with_result": 0, "valid": 0, "invalid": 0,
                   "strength": {HANDOFF_STRENGTH_NATIVE: 0,
                                HANDOFF_STRENGTH_DEGRADED: 0,
                                HANDOFF_STRENGTH_WEAK: 0},
                   "failure_classes": {}, "native_rate": 0.0}
        try:
            rows = self._all(
                "SELECT r.valid AS valid, r.invalid_reason AS invalid_reason,"
                " h.handoff_json AS pkg"
                " FROM result r"
                " JOIN attempt a ON a.run_id = r.run_id"
                " JOIN dispatch d ON d.dispatch_key = a.dispatch_key"
                " LEFT JOIN handoff h ON h.run_id = r.run_id"
                " WHERE (? IS NULL OR d.workflow_id = ?"
                "        OR substr(d.workflow_id, 1, length(?) + 1) = ? || '-')",
                (program_id,) * 4)
        except sqlite3.Error:
            return summary
        natives = 0
        for row in rows:
            summary["runs_with_result"] += 1
            if not row["valid"]:
                summary["invalid"] += 1
                m = re.match(r"\[([A-Za-z0-9_]+)\]", str(row["invalid_reason"] or ""))
                if m:
                    cls = m.group(1)
                    summary["failure_classes"][cls] = summary["failure_classes"].get(cls, 0) + 1
                continue
            summary["valid"] += 1
            try:
                strength = str((json.loads(row["pkg"] or "") or {}).get(
                    "handoff_strength") or "")
            except (json.JSONDecodeError, TypeError, ValueError):
                strength = ""
            if strength:
                summary["strength"][strength] = summary["strength"].get(strength, 0) + 1
                if strength == HANDOFF_STRENGTH_NATIVE:
                    natives += 1
        if summary["valid"]:
            summary["native_rate"] = round(natives / summary["valid"], 4)
        return summary

    def mark_delivered(self, run_id: str) -> None:
        self.conn.execute("UPDATE handoff SET delivered_at=? WHERE run_id=?",
                          (self._now(), run_id))

    # -- owner grants -------------------------------------------------------------------------
    def add_owner_grant(self, capability: str, *, scope: str = "*", expires_at: float | None = None,
                        note: str = "") -> str:
        gid = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO owner_grant(grant_id, capability, scope, granted_at, expires_at, note)"
            " VALUES(?,?,?,?,?,?)", (gid, str(capability), str(scope), self._now(), expires_at,
                                     str(note)))
        self.append_event("owner.grant", detail={"capability": capability, "scope": scope,
                                                 "expires_at": expires_at})
        return gid

    def revoke_owner_grant(self, grant_id: str) -> None:
        self.conn.execute("UPDATE owner_grant SET revoked_at=? WHERE grant_id=?",
                          (self._now(), grant_id))
        self.append_event("owner.revoke", detail={"grant_id": grant_id})

    def owner_grants(self, scope: str = "*") -> list:
        return self._all("SELECT * FROM owner_grant WHERE scope IN ('*', ?)", (str(scope),))


class _Transaction:
    """``BEGIN IMMEDIATE`` ... COMMIT/ROLLBACK, re-entrancy tolerated.

    IMMEDIATE rather than DEFERRED: admission both reads and writes, and a deferred transaction
    would take its read lock first and only discover the conflict at write time -- which is a
    race the duplicate-execution defence cannot afford to lose.
    """

    def __init__(self, conn):
        self.conn = conn
        self.owns = False

    def __enter__(self):
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
            self.owns = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.owns:
            return False
        if exc_type is None:
            self.conn.execute("COMMIT")
        else:
            try:
                self.conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        return False


def _as_int_bool(v: Any) -> int | None:
    """Persist a LITERAL boolean as 0/1, and anything else as NULL.

    Not ``bool(v)``. A handoff field that arrived as the string "false" must not be stored as 1;
    it must be stored as "we do not have a boolean here", so the defect stays visible in the
    ledger instead of being laundered into a value.
    """
    if v is True:
        return 1
    if v is False:
        return 0
    return None

"""strategic_store -- durable canonical program state.

WHY A SEPARATE DATABASE FILE
----------------------------
The run store (``core.store``) is the qualified heart of the platform: every idempotency,
lease and reconciliation control in the suite runs against its schema. Adding tables to it during
an extraction would put that qualification at risk for no benefit, so the strategic layer opens
its OWN SQLite file alongside it. The two are joined by ids, not by foreign keys, which is also
what lets a deployment run the execution plane without the strategic plane at all.

WHAT THIS IS FOR
----------------
A new strategist session must be able to reconstruct enough authoritative state to continue
SAFELY without being handed the previous conversation. That is the entire design goal, and it is
why ``handoff_bundle`` exists: objective, immutable constraints, live decisions, lane states with
their task and acceptance criteria, blockers, open questions and the next action, assembled from
durable rows rather than from a transcript.

Thread-shareable by construction. The MCP transport is threaded, and a store whose writes fail
from a request thread would -- as this project has already measured once -- turn into silent
non-logging rather than a crash.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Mapping, Sequence

from quaestor import compat
from quaestor.core.canon import canonical_json, sha256_obj
from quaestor.core import classification
from quaestor.core import decisions as dec_mod
from quaestor.core import events as ev_mod
from quaestor.core import messages as msg_mod
from quaestor.core import programs as prog_mod

STRATEGIC_INSTRUMENT = "strategic_store/1"
STRATEGIC_FILE = "strategic.sqlite3"

#: The operational program layer's schema version. Bumped ONLY by a deliberate edit that also
#: extends ``_check_contract`` with a migration-or-refuse story.
STRATEGIC_SCHEMA_VERSION = "2"

SCHEMA = """
CREATE TABLE IF NOT EXISTS program (
    program_id TEXT PRIMARY KEY, title TEXT NOT NULL, objective TEXT NOT NULL DEFAULT '',
    project TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS lane (
    lane_id TEXT PRIMARY KEY, program_id TEXT NOT NULL, workflow_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT 'NOT_EVALUATED',
    workspace_id TEXT NOT NULL DEFAULT '', writable INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS lane_lease (
    lane_id TEXT PRIMARY KEY, owner_token TEXT NOT NULL, actor_id TEXT NOT NULL,
    fence INTEGER NOT NULL, acquired_at REAL NOT NULL, expires_at REAL NOT NULL,
    released_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lane_dependency (
    from_lane TEXT NOT NULL, to_lane TEXT NOT NULL, kind TEXT NOT NULL,
    PRIMARY KEY (from_lane, to_lane, kind)
);
CREATE TABLE IF NOT EXISTS message (
    message_id TEXT PRIMARY KEY, message_type TEXT NOT NULL, actor_id TEXT NOT NULL,
    program_id TEXT NOT NULL DEFAULT '', lane_id TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '', caused_by TEXT NOT NULL DEFAULT '',
    authority_context TEXT NOT NULL DEFAULT '[]', payload TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}', digest TEXT NOT NULL,
    answered_by TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL,
    protocol_version INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_message_digest ON message(digest);
CREATE INDEX IF NOT EXISTS ix_message_lane ON message(lane_id, created_at);
CREATE TABLE IF NOT EXISTS decision (
    decision_id TEXT PRIMARY KEY, program_id TEXT NOT NULL, lane_id TEXT NOT NULL DEFAULT '',
    question TEXT NOT NULL, decision TEXT NOT NULL DEFAULT '', authority TEXT NOT NULL,
    rationale TEXT NOT NULL DEFAULT '', evidence_refs TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL, supersedes TEXT NOT NULL DEFAULT '',
    superseded_by TEXT NOT NULL DEFAULT '', actor_id TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL, decided_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS event (
    event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, at REAL NOT NULL,
    program_id TEXT NOT NULL DEFAULT '', lane_id TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '', actor_id TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_event_lane ON event(lane_id, at);
CREATE TABLE IF NOT EXISTS store_contract (
    k TEXT PRIMARY KEY, v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS program_meta (
    program_id TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (program_id, k)
);
CREATE TABLE IF NOT EXISTS lane_task (
    lane_id TEXT PRIMARY KEY,
    task TEXT NOT NULL DEFAULT '',
    acceptance_json TEXT NOT NULL DEFAULT '[]',
    executor_json TEXT NOT NULL DEFAULT '{}',
    attempt INTEGER NOT NULL DEFAULT 0,
    checkpoint_json TEXT NOT NULL DEFAULT '{}',
    updated_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lane_run (
    lane_id TEXT NOT NULL, run_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'implementation',
    processed INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    PRIMARY KEY (lane_id, run_id)
);
CREATE INDEX IF NOT EXISTS ix_lane_run_run ON lane_run(run_id);
CREATE TABLE IF NOT EXISTS review_record (
    review_id TEXT PRIMARY KEY, program_id TEXT NOT NULL DEFAULT '',
    lane_id TEXT NOT NULL DEFAULT '', run_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS integration_state (
    program_id TEXT PRIMARY KEY, state TEXT NOT NULL,
    workspace_path TEXT NOT NULL DEFAULT '', base_head TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}', updated_at REAL NOT NULL
);
"""

DUPLICATE_MESSAGE = "DUPLICATE_MESSAGE"



class StoreContractMismatch(RuntimeError):
    """A store written under different execution-identity semantics. REFUSAL, not migration.

    The extraction changed the child-prompt contract, which is an input to the dispatch identity,
    so a store written before it computes different dispatch keys for the same logical work.
    Opening one silently would let completed work re-admit as new -- an invisible failure of the
    at-most-one-active-execution guarantee, discovered only after the duplicate ran.

    There is deliberately no automatic migration. A migration could only be correct if it could
    re-derive every historical key under the new contract, which requires the original prompts,
    which the store does not keep. So the honest outcome is an explicit refusal that names what
    is incompatible and leaves the operator to decide.
    """


class StrategicStore:
    def __init__(self, path: str):
        import os
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        # check_same_thread=False: the MCP transport is threaded. A store that raises from a
        # request thread becomes silent non-logging when its writers catch broadly -- measured
        # once already in this codebase, and once is enough.
        self.conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        ok, reason = self._check_contract()
        if not ok:
            self.close()
            raise StoreContractMismatch(reason)

    def close(self) -> None:
        try:
            with self._lock:
                self.conn.close()
        except sqlite3.Error:
            pass


    # -- store/contract compatibility ------------------------------------------------------------
    def _check_contract(self) -> tuple:
        """(ok, reason). Stamp a fresh store; REFUSE one written under other identity semantics."""
        expected = {
            "child_prompt_contract": compat.CHILD_PROMPT_CONTRACT,
            "dispatch_key_salt": compat.DISPATCH_KEY_SALT,
            "handoff_protocol": compat.HANDOFF_PROTOCOL,
            # v2: the operational program layer (lane_task / lane_run / review_record /
            # integration_state). A v1 strategic store has no lane_task rows, so a v2 scheduler
            # reading one would silently see "no work planned" -- which looks exactly like a
            # finished program. Refusing is the honest outcome; re-plan into a new store.
            "strategic_schema": STRATEGIC_SCHEMA_VERSION,
        }
        with self._lock:
            rows = {r["k"]: r["v"] for r in
                    self.conn.execute("SELECT k, v FROM store_contract").fetchall()}
            if not rows:
                for k, v in expected.items():
                    self.conn.execute("INSERT INTO store_contract(k, v) VALUES(?,?)", (k, v))
                self.conn.commit()
                return True, ""
        bad = {k: (rows.get(k), v) for k, v in expected.items() if rows.get(k) != v}
        if bad:
            return False, (
                "this store was written under different execution-identity semantics and will "
                "not be opened: %s (stored -> expected). Dispatch keys computed under the stored "
                "contract are not comparable with keys computed now, so reusing it would let "
                "completed work re-admit as new. Start a new store, or migrate deliberately with "
                "a key mapping." % bad)
        return True, ""

    def _all(self, sql: str, args: Sequence = ()) -> list:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(args)).fetchall()]

    def _write(self, sql: str, args: Sequence = ()) -> None:
        with self._lock:
            self.conn.execute(sql, tuple(args))
            self.conn.commit()

    # -- programs and lanes --------------------------------------------------------------------
    def create_program(self, title: str, *, objective: str = "", project: str = "",
                       now: float | None = None) -> str:
        pid = "prog_" + uuid.uuid4().hex[:16]
        t = float(now if now is not None else time.time())
        self._write("INSERT INTO program(program_id,title,objective,project,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?)", (pid, str(title), str(objective), str(project), t, t))
        return pid

    def get_program(self, program_id: str) -> dict | None:
        rows = self._all("SELECT * FROM program WHERE program_id=?", (program_id,))
        return rows[0] if rows else None

    def list_programs(self) -> list:
        """Every program, oldest first. Read-only. The retrieval surface's catalog."""
        return self._all("SELECT * FROM program ORDER BY created_at")

    def add_lane(self, lane: prog_mod.Lane) -> str:
        self._write(
            "INSERT INTO lane(lane_id,program_id,workflow_id,title,kind,state,verdict,"
            "workspace_id,writable,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (lane.lane_id, lane.program_id, lane.workflow_id, lane.title, lane.kind, lane.state,
             lane.verdict, lane.workspace_id, int(lane.writable), lane.created_at,
             lane.updated_at))
        self.append_event(ev_mod.new_event(ev_mod.LANE_CREATED, program_id=lane.program_id,
                                           lane_id=lane.lane_id))
        return lane.lane_id

    def _row_to_lane(self, r: Mapping) -> prog_mod.Lane:
        return prog_mod.Lane(
            lane_id=r["lane_id"], program_id=r["program_id"], workflow_id=r["workflow_id"],
            title=r["title"], kind=r["kind"], state=r["state"], verdict=r["verdict"],
            workspace_id=r["workspace_id"], writable=bool(r["writable"]),
            created_at=r["created_at"], updated_at=r["updated_at"])

    def lanes(self, program_id: str) -> list:
        return [self._row_to_lane(r) for r in
                self._all("SELECT * FROM lane WHERE program_id=? ORDER BY created_at",
                          (program_id,))]

    def get_lane(self, lane_id: str) -> prog_mod.Lane | None:
        rows = self._all("SELECT * FROM lane WHERE lane_id=?", (lane_id,))
        return self._row_to_lane(rows[0]) if rows else None

    def set_lane_state(self, lane_id: str, state: str, *, verdict: str | None = None,
                       actor_id: str = "", now: float | None = None) -> None:
        if state not in prog_mod.LANE_STATES:
            raise ValueError("unknown lane state %r" % state)
        lane = self.get_lane(lane_id)
        t = float(now if now is not None else time.time())
        if verdict is None:
            self._write("UPDATE lane SET state=?, updated_at=? WHERE lane_id=?",
                        (state, t, lane_id))
        else:
            self._write("UPDATE lane SET state=?, verdict=?, updated_at=? WHERE lane_id=?",
                        (state, verdict, t, lane_id))
        self.append_event(ev_mod.new_event(
            ev_mod.LANE_STATE_CHANGED, program_id=(lane.program_id if lane else ""),
            lane_id=lane_id, actor_id=actor_id,
            detail={"from": (lane.state if lane else None), "to": state, "verdict": verdict},
            now=t))

    def add_dependency(self, dep: prog_mod.Dependency) -> None:
        if dep.kind not in prog_mod.DEPENDENCY_KINDS:
            raise ValueError("unknown dependency kind %r" % dep.kind)
        self._write("INSERT OR IGNORE INTO lane_dependency(from_lane,to_lane,kind) VALUES(?,?,?)",
                    (dep.from_lane, dep.to_lane, dep.kind))

    def dependencies(self, program_id: str) -> list:
        lane_ids = {l.lane_id for l in self.lanes(program_id)}
        return [prog_mod.Dependency(r["from_lane"], r["to_lane"], r["kind"])
                for r in self._all("SELECT * FROM lane_dependency")
                if r["from_lane"] in lane_ids]

    # -- lane ownership ------------------------------------------------------------------------
    def _lease_row(self, lane_id: str) -> prog_mod.LaneLease | None:
        rows = self._all("SELECT * FROM lane_lease WHERE lane_id=?", (lane_id,))
        if not rows:
            return None
        r = rows[0]
        return prog_mod.LaneLease(r["lane_id"], r["owner_token"], r["actor_id"], int(r["fence"]),
                                  r["acquired_at"], r["expires_at"], r["released_at"])

    def claim_lane(self, lane_id: str, *, actor_id: str, owner_token: str = "",
                   lease_s: float = prog_mod.DEFAULT_LEASE_S,
                   now: float | None = None) -> tuple:
        """(outcome, lease_or_None, reason). Impure. Durable and fenced.

        THE READ AND THE WRITE ARE ONE TRANSACTION. An earlier version read the row, decided, and
        then wrote -- a read-evaluate-write race in which two strategists both observe "free" and
        both ACQUIRE, taking the same fence and defeating the entire point of the lease. The lock
        makes the decision atomic within a process, and the conditional UPDATE makes it atomic
        against the database: the write only lands if the row still looks the way it did when the
        decision was made.
        """
        t = float(now if now is not None else time.time())
        with self._lock:
            cur = self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.conn.execute("SELECT * FROM lane_lease WHERE lane_id=?",
                                        (lane_id,)).fetchone()
                existing = None
                if row:
                    existing = prog_mod.LaneLease(
                        row["lane_id"], row["owner_token"], row["actor_id"], int(row["fence"]),
                        row["acquired_at"], row["expires_at"], row["released_at"])
                outcome, lease, reason = prog_mod.evaluate_claim(
                    existing, actor_id=actor_id, now=t, owner_token=owner_token,
                    lease_s=lease_s)
                if outcome in (prog_mod.ACQUIRED, prog_mod.RENEWED):
                    lease = prog_mod.LaneLease(lane_id, lease.owner_token, lease.actor_id,
                                               lease.fence, lease.acquired_at, lease.expires_at)
                    self.conn.execute(
                        "INSERT INTO lane_lease(lane_id,owner_token,actor_id,fence,acquired_at,"
                        "expires_at,released_at) VALUES(?,?,?,?,?,?,0)"
                        " ON CONFLICT(lane_id) DO UPDATE SET"
                        " owner_token=excluded.owner_token, actor_id=excluded.actor_id,"
                        " fence=excluded.fence, acquired_at=excluded.acquired_at,"
                        " expires_at=excluded.expires_at, released_at=0"
                        " WHERE lane_lease.fence < excluded.fence"
                        "    OR lane_lease.owner_token = excluded.owner_token",
                        (lane_id, lease.owner_token, lease.actor_id, lease.fence,
                         lease.acquired_at, lease.expires_at))
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        if outcome in (prog_mod.ACQUIRED, prog_mod.RENEWED):
            self.append_event(ev_mod.new_event(ev_mod.LANE_CLAIMED, lane_id=lane_id,
                                               actor_id=actor_id,
                                               detail={"fence": lease.fence, "outcome": outcome},
                                               now=t))
        return outcome, lease, reason

    def guard_fence(self, lane_id: str, presented_fence: int) -> tuple:
        """(ok, reason). Impure. THE ENFORCEMENT POINT for the lease's fence.

        ``programs.check_fence`` is the pure decision; this is where it is actually CALLED. A
        fence that is computed and never consulted is a comment, and the review that found this
        was right to say so: every strategic WRITE goes through here, so a superseded writer's
        late call is refused rather than merged.
        """
        return prog_mod.check_fence(self._lease_row(lane_id), presented_fence)

    def set_lane_state_fenced(self, lane_id: str, state: str, *, fence: int,
                              verdict: str | None = None, actor_id: str = "",
                              now: float | None = None) -> tuple:
        """A lane-state write that REQUIRES a current fence. (ok, reason). Impure.

        The unfenced ``set_lane_state`` remains for single-writer and setup use; this is what a
        concurrent strategic writer must call, and a control asserts a stale fence is refused.
        """
        ok, reason = self.guard_fence(lane_id, fence)
        if not ok:
            return False, reason
        self.set_lane_state(lane_id, state, verdict=verdict, actor_id=actor_id, now=now)
        return True, ""

    def release_lane(self, lane_id: str, *, owner_token: str, now: float | None = None) -> bool:
        t = float(now if now is not None else time.time())
        existing = self._lease_row(lane_id)
        if existing is None or existing.owner_token != owner_token:
            return False
        self._write("UPDATE lane_lease SET released_at=? WHERE lane_id=?", (t, lane_id))
        self.append_event(ev_mod.new_event(ev_mod.LANE_RELEASED, lane_id=lane_id,
                                           actor_id=existing.actor_id, now=t))
        return True

    def lease_for(self, lane_id: str) -> prog_mod.LaneLease | None:
        return self._lease_row(lane_id)

    # -- messages ------------------------------------------------------------------------------
    def record_message(self, msg: msg_mod.Message) -> tuple:
        """(stored, existing_id_or_empty). Idempotent by CONTENT DIGEST.

        A redelivered message is the same message. The unique index on the digest is what makes
        that true at the storage layer instead of depending on every caller to check first.
        """
        outcome, reason = msg_mod.validate(msg.to_dict())
        if outcome != msg_mod.VALID:
            raise ValueError("refusing to record an invalid message: %s (%s)" % (outcome, reason))
        # CLASSIFY BEFORE PERSISTING. Engineering prose survives intact; a credential shape does
        # not become durable merely because a model wrote it. The digest is taken over the
        # SANITISED payload so idempotency is computed on what is actually stored.
        cls = classification.classify(msg.payload)
        if cls.modified:
            msg = msg_mod.Message(**{**msg.to_dict_ctor(), "payload": cls.text})
        digest = msg.digest()
        existing = self._all("SELECT message_id FROM message WHERE digest=?", (digest,))
        if existing:
            return False, existing[0]["message_id"]
        try:
            self._write(
                "INSERT INTO message(message_id,message_type,actor_id,program_id,lane_id,run_id,"
                "caused_by,authority_context,payload,detail_json,digest,created_at,protocol_version)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (msg.message_id, msg.message_type, msg.actor_id, msg.program_id, msg.lane_id,
                 msg.run_id, msg.caused_by, json.dumps(list(msg.authority_context)), msg.payload,
                 json.dumps(dict(msg.detail)), digest, msg.created_at, msg.protocol_version))
        except sqlite3.IntegrityError:
            # THE SELECT-ABOVE-INSERT RACE, CLOSED. `_all` and `_write` each take the lock, but
            # the CHECK-then-INSERT spans two acquisitions: two writers can both see no row for
            # this digest and both reach the INSERT. Exactly one commits; the losers used to leak
            # a raw IntegrityError to the caller -- measured as 5 of 6 concurrent writers erroring
            # on a loaded Linux runner while the same test passed on a quiet laptop. The unique
            # index remains the enforcement; the loser classifies itself as the dedupe it is and
            # reports the winner's identity.
            winner = self._all("SELECT message_id FROM message WHERE digest=?", (digest,))
            return False, winner[0]["message_id"] if winner else ""
        ev = {msg_mod.AUTHORITY_REQUEST: ev_mod.AUTHORITY_REQUESTED,
              msg_mod.CLARIFICATION_REQUEST: ev_mod.CLARIFICATION_REQUESTED,
              msg_mod.BLOCKER: ev_mod.BLOCKED,
              msg_mod.OWNER_ESCALATION: ev_mod.OWNER_ESCALATED,
              msg_mod.REVIEW_FINDING: ev_mod.REVIEW_FINDING}.get(
                  msg.message_type, ev_mod.EXECUTOR_MESSAGE)
        self.append_event(ev_mod.new_event(ev, program_id=msg.program_id, lane_id=msg.lane_id,
                                           run_id=msg.run_id, actor_id=msg.actor_id,
                                           detail={"message_id": msg.message_id,
                                                   "message_type": msg.message_type},
                                           now=msg.created_at))
        return True, ""

    def messages(self, lane_id: str) -> list:
        return self._all("SELECT * FROM message WHERE lane_id=? ORDER BY created_at", (lane_id,))

    def answer_message(self, message_id: str, answer_message_id: str) -> None:
        self._write("UPDATE message SET answered_by=? WHERE message_id=?",
                    (answer_message_id, message_id))

    def open_questions(self, lane_id: str) -> list:
        """Messages that await an answer and have not received one. Impure."""
        return [m for m in self.messages(lane_id)
                if m["message_type"] in msg_mod.AWAITING_TYPES and not m["answered_by"]]

    # -- decisions -----------------------------------------------------------------------------
    def record_decision(self, d: dec_mod.Decision) -> str:
        q = classification.classify(d.question)
        r = classification.classify(d.rationale)
        dv = classification.classify(d.decision)
        if q.modified or r.modified or dv.modified:
            d = dec_mod.Decision(**{**d.to_dict_for_replace(), "question": q.text,
                                    "rationale": r.text, "decision": dv.text})
        self._write(
            "INSERT INTO decision(decision_id,program_id,lane_id,question,decision,authority,"
            "rationale,evidence_refs,status,supersedes,superseded_by,actor_id,created_at,"
            "decided_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (d.decision_id, d.program_id, d.lane_id, d.question, d.decision, d.authority,
             d.rationale, json.dumps(list(d.evidence_refs)), d.status, d.supersedes,
             d.superseded_by, d.actor_id, d.created_at, d.decided_at))
        self.append_event(ev_mod.new_event(ev_mod.DECISION_RECORDED, program_id=d.program_id,
                                           lane_id=d.lane_id, actor_id=d.actor_id,
                                           detail={"decision_id": d.decision_id,
                                                   "authority": d.authority},
                                           now=d.created_at))
        return d.decision_id

    def supersede_decision(self, previous_id: str, *, decision: str, rationale: str,
                           authority: str = dec_mod.BY_STRATEGIST, actor_id: str = "",
                           now: float | None = None) -> str:
        prev = self.get_decision(previous_id)
        if prev is None:
            raise ValueError("no such decision %r" % previous_id)
        fresh, old = dec_mod.supersede(prev, decision=decision, rationale=rationale,
                                       authority=authority, actor_id=actor_id, now=now)
        self.record_decision(fresh)
        self._write("UPDATE decision SET status=?, superseded_by=? WHERE decision_id=?",
                    (dec_mod.SUPERSEDED, fresh.decision_id, old.decision_id))
        self.append_event(ev_mod.new_event(ev_mod.DECISION_SUPERSEDED, program_id=prev.program_id,
                                           lane_id=prev.lane_id, actor_id=actor_id,
                                           detail={"previous": previous_id,
                                                   "replacement": fresh.decision_id}))
        return fresh.decision_id

    def _row_to_decision(self, r: Mapping) -> dec_mod.Decision:
        return dec_mod.Decision(
            decision_id=r["decision_id"], program_id=r["program_id"], lane_id=r["lane_id"],
            question=r["question"], decision=r["decision"], authority=r["authority"],
            rationale=r["rationale"], evidence_refs=tuple(json.loads(r["evidence_refs"])),
            status=r["status"], supersedes=r["supersedes"], superseded_by=r["superseded_by"],
            actor_id=r["actor_id"], created_at=r["created_at"], decided_at=r["decided_at"])

    def get_decision(self, decision_id: str) -> dec_mod.Decision | None:
        rows = self._all("SELECT * FROM decision WHERE decision_id=?", (decision_id,))
        return self._row_to_decision(rows[0]) if rows else None

    def decisions(self, program_id: str) -> list:
        return [self._row_to_decision(r) for r in
                self._all("SELECT * FROM decision WHERE program_id=? ORDER BY created_at",
                          (program_id,))]

    # -- events --------------------------------------------------------------------------------
    def append_event(self, ev: ev_mod.Event) -> str:
        self._write("INSERT INTO event(event_id,event_type,at,program_id,lane_id,run_id,"
                    "actor_id,detail_json) VALUES(?,?,?,?,?,?,?,?)",
                    (ev.event_id, ev.event_type, ev.at, ev.program_id, ev.lane_id, ev.run_id,
                     ev.actor_id, json.dumps(dict(ev.detail))))
        return ev.event_id

    def events(self, *, program_id: str = "", lane_id: str = "") -> list:
        if lane_id:
            return self._all("SELECT * FROM event WHERE lane_id=? ORDER BY at", (lane_id,))
        if program_id:
            return self._all("SELECT * FROM event WHERE program_id=? ORDER BY at", (program_id,))
        return self._all("SELECT * FROM event ORDER BY at")

    # -- the operational program layer (v2) -----------------------------------------------------
    def set_program_meta(self, program_id: str, k: str, v: str) -> None:
        self._write("INSERT INTO program_meta(program_id,k,v) VALUES(?,?,?)"
                    " ON CONFLICT(program_id,k) DO UPDATE SET v=excluded.v",
                    (str(program_id), str(k), str(v)))

    def get_program_meta(self, program_id: str) -> dict:
        return {r["k"]: r["v"] for r in
                self._all("SELECT k, v FROM program_meta WHERE program_id=?", (program_id,))}

    def set_program_status(self, program_id: str, status: str, *, actor_id: str = "",
                           detail: Mapping | None = None, now: float | None = None) -> None:
        t = float(now if now is not None else time.time())
        prev = self.get_program_meta(program_id).get("status", "")
        self.set_program_meta(program_id, "status", status)
        self.append_event(ev_mod.new_event(ev_mod.PROGRAM_STATUS_CHANGED,
                                           program_id=program_id, actor_id=actor_id,
                                           detail={"from": prev, "to": status,
                                                   **dict(detail or {})}, now=t))

    def messages_for_program(self, program_id: str) -> list:
        return self._all("SELECT * FROM message WHERE program_id=? ORDER BY created_at",
                         (program_id,))

    def message(self, message_id: str) -> dict | None:
        rows = self._all("SELECT * FROM message WHERE message_id=?", (message_id,))
        return rows[0] if rows else None

    def open_questions_for_program(self, program_id: str) -> list:
        out = []
        for l in self.lanes(program_id):
            for q in self.open_questions(l.lane_id):
                out.append(q)
        return out

    def set_lane_task(self, lane_id: str, *, task: str, acceptance=(), executor: Mapping | None = None,
                      now: float | None = None) -> None:
        t = float(now if now is not None else time.time())
        self._write(
            "INSERT INTO lane_task(lane_id,task,acceptance_json,executor_json,attempt,"
            "checkpoint_json,updated_at) VALUES(?,?,?,?,0,'{}',?)"
            " ON CONFLICT(lane_id) DO UPDATE SET task=excluded.task,"
            " acceptance_json=excluded.acceptance_json, updated_at=excluded.updated_at",
            (lane_id, str(task), json.dumps([str(a) for a in (acceptance or ())]),
             json.dumps(dict(executor or {})), t))
        lane = self.get_lane(lane_id)
        self.append_event(ev_mod.new_event(ev_mod.LANE_TASK_SET, program_id=lane.program_id if lane else "",
                                           lane_id=lane_id, detail={"task_bytes": len(str(task))},
                                           now=t))

    def get_lane_task(self, lane_id: str) -> dict:
        rows = self._all("SELECT * FROM lane_task WHERE lane_id=?", (lane_id,))
        if not rows:
            return {"lane_id": lane_id, "task": "", "acceptance": (), "executor": {},
                    "attempt": 0, "checkpoint": {}, "updated_at": 0.0}
        r = rows[0]
        try:
            acc = tuple(json.loads(r["acceptance_json"] or "[]"))
        except ValueError:
            acc = ()
        try:
            ex = json.loads(r["executor_json"] or "{}")
        except ValueError:
            ex = {}
        try:
            ckpt = json.loads(r["checkpoint_json"] or "{}")
        except ValueError:
            ckpt = {}
        return {"lane_id": lane_id, "task": r["task"], "acceptance": acc, "executor": ex,
                "attempt": int(r["attempt"]), "checkpoint": ckpt, "updated_at": r["updated_at"]}

    def bump_attempt(self, lane_id: str) -> int:
        cur = self.get_lane_task(lane_id)["attempt"]
        nxt = int(cur) + 1
        self._write("UPDATE lane_task SET attempt=?, updated_at=? WHERE lane_id=?",
                    (nxt, time.time(), lane_id))
        return nxt

    def save_checkpoint(self, lane_id: str, checkpoint: Mapping, *,
                        program_id: str = "", run_id: str = "") -> None:
        """Durable resume state for a paused or finished lane. The structured-handoff model.

        RESUMPTION MECHANISM, CHOSEN DELIBERATELY: a lane resumes as a FRESH executor run from
        this checkpoint plus the answered directive -- never by replaying an opaque model
        session. Reasons, in order of weight: (1) a checkpoint survives worker death, server
        restart and machine reboot by construction, while a live conversation survives none of
        them; (2) a fresh run binds a fresh dispatch identity, so the at-most-one-active-
        execution guarantee keeps applying; (3) what the resumed child receives is exactly what
        the record shows was decided, which makes resumption auditable.

        MERGE SEMANTICS, ENFORCED HERE: this store-level merge is load-bearing. A caller that
        writes {summary} must not erase {worktree_path} written by another component -- measured
        exactly that way when the worker overwrote the scheduler's workspace identity and lanes
        lost their worktrees.
        """
        t = time.time()
        with self._lock:
            row = self.conn.execute("SELECT checkpoint_json FROM lane_task WHERE lane_id=?",
                                    (lane_id,)).fetchone()
            base = {}
            if row:
                try:
                    loaded = json.loads(row["checkpoint_json"] or "{}")
                    if isinstance(loaded, dict):
                        base = loaded
                except ValueError:
                    base = {}
            base.update(dict(checkpoint or {}))
            self.conn.execute(
                "INSERT INTO lane_task(lane_id,task,acceptance_json,executor_json,attempt,"
                "checkpoint_json,updated_at) VALUES(?, '', '[]', '{}', 0, ?, ?)"
                " ON CONFLICT(lane_id) DO UPDATE SET checkpoint_json=excluded.checkpoint_json,"
                " updated_at=excluded.updated_at",
                (lane_id, json.dumps(base), t))
        self.append_event(ev_mod.new_event(ev_mod.CHECKPOINT_SAVED, program_id=program_id,
                                           lane_id=lane_id, run_id=run_id,
                                           detail={"keys": sorted(dict(checkpoint or {}))},
                                           now=t))

    def bind_run(self, lane_id: str, run_id: str, *, role: str = "implementation") -> None:
        self._write("INSERT OR IGNORE INTO lane_run(lane_id,run_id,role,processed,created_at)"
                    " VALUES(?,?,?,0,?)", (lane_id, run_id, str(role), time.time()))
        lane = self.get_lane(lane_id)
        self.append_event(ev_mod.new_event(ev_mod.RUN_BOUND, program_id=lane.program_id if lane else "",
                                           lane_id=lane_id, run_id=run_id,
                                           detail={"role": role}))

    def runs_for_lane(self, lane_id: str) -> list:
        return self._all("SELECT * FROM lane_run WHERE lane_id=? ORDER BY created_at", (lane_id,))

    def lane_for_run(self, run_id: str) -> dict | None:
        rows = self._all("SELECT * FROM lane_run WHERE run_id=?", (run_id,))
        return rows[0] if rows else None

    def mark_run_processed(self, lane_id: str, run_id: str) -> None:
        self._write("UPDATE lane_run SET processed=1 WHERE lane_id=? AND run_id=?",
                    (lane_id, run_id))

    def record_review(self, review_id: str, *, program_id: str, lane_id: str, kind: str,
                      outcome: str, result: Mapping, run_id: str = "") -> None:
        self._write(
            "INSERT INTO review_record(review_id,program_id,lane_id,run_id,kind,outcome,"
            "result_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (review_id, program_id, lane_id, run_id, kind, outcome,
             json.dumps(dict(result or {}), default=str), time.time()))
        self.append_event(ev_mod.new_event(ev_mod.REVIEW_COMPLETED, program_id=program_id,
                                           lane_id=lane_id, run_id=run_id,
                                           detail={"review_id": review_id, "kind": kind,
                                                   "outcome": outcome}))

    def reviews_for(self, program_id: str, lane_id: str = "") -> list:
        if lane_id:
            return self._all("SELECT * FROM review_record WHERE program_id=? AND lane_id=?"
                             " ORDER BY created_at", (program_id, lane_id))
        return self._all("SELECT * FROM review_record WHERE program_id=? ORDER BY created_at",
                         (program_id,))

    def set_integration_state(self, program_id: str, state: str, *, workspace_path: str = "",
                              base_head: str = "", detail: Mapping | None = None,
                              now: float | None = None) -> None:
        t = float(now if now is not None else time.time())
        self._write(
            "INSERT INTO integration_state(program_id,state,workspace_path,base_head,detail_json,"
            "updated_at) VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(program_id) DO UPDATE SET state=excluded.state,"
            " workspace_path=excluded.workspace_path, base_head=excluded.base_head,"
            " detail_json=excluded.detail_json, updated_at=excluded.updated_at",
            (program_id, str(state), workspace_path, base_head,
             json.dumps(dict(detail or {}), default=str), t))
        self.append_event(ev_mod.new_event(ev_mod.INTEGRATION_STATE_CHANGED, program_id=program_id,
                                           detail={"to": state}, now=t))

    def get_integration_state(self, program_id: str) -> dict | None:
        rows = self._all("SELECT * FROM integration_state WHERE program_id=?", (program_id,))
        if not rows:
            return None
        r = rows[0]
        try:
            d = json.loads(r["detail_json"] or "{}")
        except ValueError:
            d = {}
        return {"program_id": r["program_id"], "state": r["state"],
                "workspace_path": r["workspace_path"], "base_head": r["base_head"],
                "detail": d, "updated_at": r["updated_at"]}

    # -- the point of all of it ------------------------------------------------------------------
    def handoff_bundle(self, program_id: str) -> dict:
        """Everything a NEW strategist needs to continue safely. Impure.

        Deliberately assembled from durable rows, not from a transcript: the acceptance test for
        this platform is that a fresh session can pick up a program without being handed the
        previous conversation. It reports its own inspection counts, and a bundle assembled from
        nothing is VACUOUS rather than an empty-looking success.

        WHAT "EVERYTHING" HAD TO GROW TO INCLUDE. The first version carried live decisions, lane
        STATES and open questions -- and omitted the three things a resuming strategist cannot
        act without: the program's IMMUTABLE CONSTRAINTS (meta ``constraints_json``), each lane's
        TASK text, and each lane's ACCEPTANCE criteria. A bundle that shows a lane is BLOCKED but
        not what it was told to do, or an objective without the constraints bounding it, hands
        the next holder a state display rather than a brief. All three are durable rows already;
        omitting them was a gap in this method, not a limit of the store.
        """
        prog = self.get_program(program_id)
        meta = self.get_program_meta(program_id)
        lanes = self.lanes(program_id)
        tasks = {l.lane_id: self.get_lane_task(l.lane_id) for l in lanes}
        deps = self.dependencies(program_id)
        decs = dec_mod.live_decisions(self.decisions(program_id))
        agg = prog_mod.aggregate(lanes)
        blocking = prog_mod.blocking_dependencies({l.lane_id: l for l in lanes}, deps)
        questions = []
        for l in lanes:
            for q in self.open_questions(l.lane_id):
                questions.append({"lane_id": l.lane_id, "message_id": q["message_id"],
                                  "message_type": q["message_type"], "payload": q["payload"],
                                  "created_at": q["created_at"]})
        lane_docs = []
        for l in lanes:
            doc = l.to_dict()
            t = tasks[l.lane_id]
            # The brief, not just the state: what this lane was told to do and what would make
            # it acceptable. Both are read straight off ``lane_task`` -- no second policy.
            doc["task"] = t["task"]
            doc["acceptance"] = list(t["acceptance"])
            doc["attempt"] = t["attempt"]
            lane_docs.append(doc)
        try:
            parsed = json.loads(meta.get("constraints_json") or "[]")
        except ValueError:
            parsed = None
        # A malformed row is reported as NO constraints, never as a silent partial read: the
        # caller sees an empty list beside a non-empty program and can say so. The isinstance
        # check matters as much as the parse -- a JSON OBJECT would otherwise iterate to its
        # KEYS and present them as constraints nobody wrote.
        constraints = [str(c) for c in parsed] if isinstance(parsed, list) else []
        return {
            "program": prog,
            "objective": (prog or {}).get("objective", ""),
            "constraints": constraints,
            "status": meta.get("status", ""),
            "lanes": lane_docs,
            "dependencies": [d.to_dict() for d in deps],
            "blocking": blocking,
            "workspace_conflicts": prog_mod.workspace_conflicts(lanes),
            "decisions": [d.to_dict() for d in decs],
            "open_questions": questions,
            "aggregate": agg,
            "next_authority": agg["next_authority"],
            "inspected": {"lanes": len(lanes), "decisions": len(decs),
                          "constraints": len(constraints),
                          "acceptance": sum(len(d["acceptance"]) for d in lane_docs),
                          "open_questions": len(questions), "events": len(self.events(
                              program_id=program_id))},
            "vacuous": prog is None and not lanes,
            "note": ("assembled from durable rows. A resuming strategist needs no transcript: "
                     "if something is not here, it was never recorded, and that absence is "
                     "itself the finding."),
            "instrument": STRATEGIC_INSTRUMENT,
        }

    # -- context capsules (direction section 14.1) -----------------------------------------------
    #: ~4 characters per token for code-adjacent prose; the budget is expressed in tokens and
    #: enforced in characters, so the conversion constant lives exactly once.
    CHARS_PER_TOKEN = 4
    #: How many recent observations are CONSIDERED at all, before budgeting. Without a window,
    #: one chatty lane's oldest-first fill would starve every section after it.
    CAPSULE_OBSERVATION_WINDOW = 8
    #: Per-entry excerpt bound. THE NO-TRANSCRIPT RULE IS STRUCTURAL: there is no field in a
    #: capsule that could hold a transcript -- message payloads enter only as excerpts of this
    #: size, and stdout/transcript/report artifacts are simply never read during assembly.
    CAPSULE_EXCERPT_CHARS = 240

    def context_capsule(self, lane_id: str, *, token_budget: int = 4000,
                        role: str = "implementation") -> dict:
        """A role-shaped, token-budgeted CONTEXT CAPSULE built ONLY from durable rows.

        Direction section 14.1: when any seat changes holders -- provider failover, crash
        recovery, model swap -- the new holder receives a capsule reconstructed from CANONICAL
        STATE, never a transcript replay ("Claude disappears; Codex takes the seat; Quaestor
        constructs the capsule"). Properties pinned here:

          * reproducible  -- pure assembly over durable rows; identical state yields an
            identical document AND an identical ``capsule_sha256``;
          * hashable/versioned -- the hash is sha256 over the canonical JSON of the content,
            instrument-tagged, computed over the document WITHOUT the hash fields themselves;
          * budgeted      -- sections emit entries OLDEST-FIRST under a hard character budget;
            whatever does not fit is dropped and replaced by an explicit truncation marker --
            an omitted fact is stated as omitted, never silently absent;
          * role-specific -- review seats get findings before history; builders get dependency
            outputs first (the order IS the shaping).
        """
        excerpt = _excerpt
        lane = self.get_lane(lane_id)
        program_id = str(lane.program_id) if lane else ""
        prog = self.get_program(program_id) if program_id else None
        meta = self.get_program_meta(program_id) if program_id else {}
        task_doc = self.get_lane_task(lane_id)
        ckpt = task_doc.get("checkpoint") or {}

        # Section pools, each ordered OLDEST-FIRST by construction.
        decisions = ["%s %s: %s" % (d.status, d.decision or "(open)", excerpt(d.rationale, 200))
                     for d in reversed(dec_mod.live_decisions(self.decisions(program_id)))]
        dep_rows = []
        lanes_by_id = {l.lane_id: l for l in self.lanes(program_id)} if program_id else {}
        for dep in self.dependencies(program_id):
            upstream = lanes_by_id.get(dep.to_lane)
            if dep.from_lane != lane_id or dep.kind != prog_mod.REQUIRES or upstream is None \
                    or upstream.state != prog_mod.LANE_COMPLETE:
                continue
            up_ckpt = (self.get_lane_task(upstream.lane_id).get("checkpoint") or {})
            dep_rows.append("%s (%s, %s): %s" % (
                upstream.lane_id, upstream.title, upstream.verdict,
                excerpt(str(up_ckpt.get("summary") or ""), self.CAPSULE_EXCERPT_CHARS)))
        findings = []
        for f in list(ckpt.get("fix_findings") or []) + list(ckpt.get("pending_findings") or []):
            findings.append("[%s] %s: %s" % (f.get("severity"), f.get("title"),
                                             excerpt(str(f.get("failure_mode") or ""), 200)))
        msgs = self.messages(lane_id)
        blockers = [excerpt(m["payload"], self.CAPSULE_EXCERPT_CHARS)
                    for m in msgs if m["message_type"] == msg_mod.BLOCKER][-5:]
        open_questions = [excerpt(m["payload"], self.CAPSULE_EXCERPT_CHARS)
                          for m in msgs if m["message_type"] in msg_mod.AWAITING_TYPES
                          and not m["answered_by"]]
        observations = [excerpt(m["payload"], self.CAPSULE_EXCERPT_CHARS)
                        for m in msgs if m["message_type"] == msg_mod.OBSERVATION]
        recent_observations = observations[-self.CAPSULE_OBSERVATION_WINDOW:]
        artifact_refs = sorted(["branch:%s" % ckpt[k] for k in ("worktree_branch",)
                                if ckpt.get(k)]
                               + ["commit:%s" % ckpt[k] for k in ("commit_sha",)
                                  if ckpt.get(k)])
        evidence_refs = ([b["run_id"] for b in self.runs_for_lane(lane_id)]
                         + ["review:%s" % r["review_id"]
                            for r in self.reviews_for(program_id, lane_id=lane_id)])
        constraints = [str(c) for c in json.loads(meta.get("constraints_json") or "[]")]

        pools = {"decisions": decisions, "dependency_outputs": dep_rows,
                 "review_findings": findings, "blockers": blockers,
                 "open_questions": open_questions, "recent_observations": recent_observations}
        # ROLE SHAPING: the fill order is the emphasis. A reviewer inheriting this seat must see
        # outstanding findings before anything else; a builder must see what its dependencies
        # produced before it sees chatter. Unknown roles get the builder order, recorded as-is.
        review_role = role in ("research", "verification", "adversarial_review")
        section_order = (("review_findings", "decisions", "dependency_outputs", "blockers",
                          "open_questions", "recent_observations") if review_role else
                         ("decisions", "dependency_outputs", "review_findings", "blockers",
                          "open_questions", "recent_observations"))

        content = {
            "instrument": "context_capsule/1", "version": 1,
            "lane_id": lane_id, "program_id": program_id, "role": str(role),
            "token_budget": int(token_budget),
            "objective": excerpt(str((prog or {}).get("objective") or ""), 1200),
            "lane_objective": excerpt("%s: %s" % ((lane.title if lane else ""),
                                                  task_doc.get("task") or ""), 1600),
            "constraints": constraints,
        }
        for name in section_order:
            content[name] = []
        budget_chars = max(64, int(token_budget) * self.CHARS_PER_TOKEN)
        truncated_note = []
        for name in section_order:
            pool = pools[name]
            kept = 0
            for entry in pool:
                candidate = list(content[name]) + [entry]
                trial = {k: (candidate if k == name else v) for k, v in content.items()}
                if len(canonical_json(trial)) > budget_chars:
                    omitted = len(pool) - kept
                    if omitted > 0:
                        marker = ("[...truncated: %d entr%s omitted (budget %d chars)]"
                                  % (omitted, "y" if omitted == 1 else "ies", budget_chars))
                        content[name] = candidate + [marker]
                else:
                    content[name] = candidate
                    kept += 1
                    continue
                truncated_note.append(name)
                break
        content["truncated_sections"] = truncated_note
        used = len(canonical_json(content))
        content["budget_used_chars"] = used
        content["capsule_sha256"] = sha256_obj(content)
        return content


def capsule_text(capsule: Mapping) -> str:
    """Render a capsule as the text block appended to a resumed child's task. PURE.

    Deterministic given the capsule (which is itself deterministic), so the rendered bytes are
    reproducible evidence of exactly what the new seat holder was told.
    """
    lines = ["OBJECTIVE: %s" % capsule.get("objective", ""),
             "LANE OBJECTIVE: %s" % capsule.get("lane_objective", "")]
    for section in ("constraints", "decisions", "dependency_outputs", "review_findings",
                    "blockers", "open_questions", "recent_observations"):
        entries = capsule.get(section) or []
        if not entries:
            continue
        lines.append("%s:" % section.replace("_", " ").upper())
        lines.extend("- %s" % e for e in entries)
    lines.append("(capsule_sha256=%s; %s chars; assembled from durable state -- never a "
                 "transcript)" % (capsule.get("capsule_sha256", ""),
                                  capsule.get("budget_used_chars", 0)))
    return "\n".join(lines)


def _excerpt(text, limit: int) -> str:
    """Bounded excerpt with an explicit ellipsis. PURE. The unit of the no-transcript rule."""
    t = str(text or "").strip()
    return t if len(t) <= int(limit) else t[:int(limit)].rstrip() + " [...]"


def strategic_path(home: str) -> str:
    import os
    return os.path.join(home, STRATEGIC_FILE)


def strategic_path_for_run_db(db_path: str) -> str:
    """The strategic store that belongs to a run store, by directory. PURE.

    The worker knows only the run store's path (``<home>/orchestrator.sqlite3``); the strategic
    store lives beside it by convention, which is what lets the execution plane and the strategic
    plane be joined by ids rather than foreign keys while still being findable from one path.
    """
    import os
    return os.path.join(os.path.dirname(os.path.abspath(db_path)), STRATEGIC_FILE)

"""transport_ledger -- durable, non-secret identity for every MCP call.

TRANSPORT IDENTITY IS NOT ORCHESTRATION IDENTITY
------------------------------------------------
A ``transport_request_id`` names one call over one channel. A ``dispatch_key`` names one logical
execution. They are different things and the ledger never lets one stand in for the other: two
transport requests may legitimately map to ONE dispatch key, and that is exactly what proves the
idempotency contract survives a retry.

The reverse -- one transport request creating two dispatch keys -- is the failure this ledger
makes visible, because both rows carry the key they resolved to.

WHAT IS DELIBERATELY NOT STORED
-------------------------------
The task prose is stored as a DIGEST, not as text. A transport ledger is an audit trail, not a
conversation log; the orchestrator's own run record already holds the prompt where it is needed,
under the retention policy that governs it. Storing it twice doubles the exposure and doubles the
number of places a retention rule has to be remembered.

Its own SQLite file, not a new table in ``orchestrator.sqlite3``: the transport is an adapter that
must be removable without migrating the control plane's schema.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Mapping, Sequence

LEDGER_INSTRUMENT = "transport_ledger/1"
LEDGER_FILE = "transport.sqlite3"

SCHEMA = """
CREATE TABLE IF NOT EXISTS transport_request (
    transport_request_id TEXT PRIMARY KEY,
    received_at          REAL NOT NULL,
    completed_at         REAL,
    channel              TEXT NOT NULL,
    tool                 TEXT NOT NULL,
    tool_schema_version  TEXT NOT NULL,
    protocol_version     TEXT,
    caller_identity      TEXT,
    caller_token_id      TEXT,
    payload_sha256       TEXT NOT NULL,
    result_sha256        TEXT,
    disposition          TEXT NOT NULL,
    reason               TEXT,
    workflow_id          TEXT,
    step_id              TEXT,
    run_id               TEXT,
    dispatch_key         TEXT,
    transport_mode       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tr_dispatch_key ON transport_request(dispatch_key);
CREATE INDEX IF NOT EXISTS ix_tr_payload      ON transport_request(payload_sha256);
CREATE INDEX IF NOT EXISTS ix_tr_run          ON transport_request(run_id);
"""

# Dispositions
ACCEPTED = "ACCEPTED"
REFUSED = "REFUSED"
UNAUTHENTICATED = "UNAUTHENTICATED"
FAILED = "FAILED"


def digest(obj) -> str:
    """Canonical digest of a payload. PURE."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


class TransportLedger:
    """Append-mostly. One row per call, written before the call runs and closed after."""

    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        # THREAD-SHAREABLE ON PURPOSE. The HTTP transport is a ThreadingHTTPServer, so every
        # request runs on a NEW thread. sqlite3's default `check_same_thread=True` raises from
        # any other thread -- and because the ledger's writers catch broadly, that turned into
        # SILENT NON-LOGGING of every HTTP call rather than a crash. An audit trail that fails
        # quietly is worse than none, because it is believed.
        self.conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        try:
            with self._lock:
                self.conn.close()
        except sqlite3.Error:
            pass

    # -- write ---------------------------------------------------------------------------------
    def open_request(self, *, channel: str, tool: str, tool_schema_version: str,
                     payload, protocol_version: str = "", caller_identity: str = "",
                     caller_token_id: str = "", transport_mode: str = "",
                     now: float | None = None) -> str:
        rid = "tr_" + uuid.uuid4().hex
        with self._lock:
            self.conn.execute(
                "INSERT INTO transport_request(transport_request_id, received_at, channel, tool,"
                " tool_schema_version, protocol_version, caller_identity, caller_token_id,"
                " payload_sha256, disposition, transport_mode)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, float(now if now is not None else time.time()), str(channel), str(tool),
                 str(tool_schema_version), str(protocol_version), str(caller_identity),
                 str(caller_token_id), digest(payload), "OPEN", str(transport_mode)))
            self.conn.commit()
        return rid

    def close_request(self, rid: str, *, disposition: str, result=None, reason: str = "",
                      workflow_id: str = "", step_id: str = "", run_id: str = "",
                      dispatch_key: str = "", now: float | None = None) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE transport_request SET completed_at=?, disposition=?, result_sha256=?,"
                " reason=?, workflow_id=?, step_id=?, run_id=?, dispatch_key=?"
                " WHERE transport_request_id=?",
                (float(now if now is not None else time.time()), str(disposition),
                 (digest(result) if result is not None else None), str(reason or ""),
                 str(workflow_id or ""), str(step_id or ""), str(run_id or ""),
                 str(dispatch_key or ""), rid))
            self.conn.commit()

    # -- read ----------------------------------------------------------------------------------
    def _query(self, sql: str, args=()) -> list:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(args)).fetchall()]

    def get(self, rid: str) -> dict | None:
        rows = self._query("SELECT * FROM transport_request WHERE transport_request_id=?", (rid,))
        return rows[0] if rows else None

    def all_rows(self) -> list:
        return self._query("SELECT * FROM transport_request ORDER BY received_at")

    def count(self) -> int:
        with self._lock:
            return int(self.conn.execute(
                "SELECT COUNT(*) FROM transport_request").fetchone()[0])

    def dispatch_keys(self) -> list:
        return [str(r["dispatch_key"]) for r in self._query(
            "SELECT DISTINCT dispatch_key FROM transport_request"
            " WHERE dispatch_key IS NOT NULL AND dispatch_key<>''")]

    def requests_for_key(self, key: str) -> list:
        return self._query(
            "SELECT * FROM transport_request WHERE dispatch_key=? ORDER BY received_at",
            (str(key),))

    def idempotency_report(self) -> dict:
        """Transport calls vs distinct logical dispatches. EMITS ITS INSPECTION COUNT.

        The number that matters is ``max_requests_per_key``: greater than one is the retry case
        working. ``keys`` greater than ``dispatch_calls`` would be the failure -- more logical
        executions than calls -- and cannot happen unless something created a key without a row.
        """
        rows = self.all_rows()
        calls = [r for r in rows if r["tool"] == "orchestrator_dispatch"]
        keys = {}
        for r in calls:
            k = str(r["dispatch_key"] or "")
            if k:
                keys.setdefault(k, []).append(r["transport_request_id"])
        return {"transport_rows": len(rows), "dispatch_calls": len(calls),
                "distinct_dispatch_keys": len(keys),
                "max_requests_per_key": max([len(v) for v in keys.values()] or [0]),
                "keys": {k: len(v) for k, v in sorted(keys.items())},
                "inspected_count": len(rows), "vacuous": len(rows) == 0,
                "instrument": LEDGER_INSTRUMENT}


def ledger_path(home: str) -> str:
    return os.path.join(home, LEDGER_FILE)


def redact_row(row: Mapping | None) -> dict | None:
    """The remote-safe view of a ledger row. Digests only; no prose, no paths."""
    if not row:
        return None
    keep = ("transport_request_id", "received_at", "completed_at", "channel", "tool",
            "tool_schema_version", "protocol_version", "caller_identity", "payload_sha256",
            "result_sha256", "disposition", "transport_mode")
    return {k: row[k] for k in keep if k in row}


def summarize(rows: Sequence[Mapping]) -> dict:
    by_tool, by_disp = {}, {}
    for r in rows:
        by_tool[str(r["tool"])] = by_tool.get(str(r["tool"]), 0) + 1
        by_disp[str(r["disposition"])] = by_disp.get(str(r["disposition"]), 0) + 1
    return {"total": len(rows), "by_tool": by_tool, "by_disposition": by_disp,
            "inspected_count": len(rows), "vacuous": not rows,
            "instrument": LEDGER_INSTRUMENT}

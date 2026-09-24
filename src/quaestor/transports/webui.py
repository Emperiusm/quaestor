"""webui -- the local loopback dashboard: reads and governed writes over ONE orchestrator.

WHY THIS EXISTS
---------------
PRD.md §13.3 defines this surface as the Local Core Console: an authenticated loopback
recovery/admin/diagnostics UI, explicitly NOT the primary organization-wide product UI (that is
Quaestor Web, PRD.md §13 -- contract, not code at HEAD). It exists so cloud or network failure
never removes control of local execution, which is why it stays interactive: the same page that
observes programs can also drive them. This module serves a single HTML page plus a small JSON API
over the SAME orchestrator functions the CLI invokes (orch.create_program / plan_lane / tick /
answer / cancel_program, transports.mcp.mode.write_mode) -- so there is exactly one reading of
program state AND exactly one writing of it, and this surface cannot drift from the operator CLI.

THE GOVERNING RULE (PRD.md §13.1, §13.3)
-----------------------------------------
The transport invokes governed operations; it never grants authority. Every POST route maps 1:1
onto an existing governed operation -- no new authority path is created here, and OWNER-gated
things stay out: no grants, no push, no destructive capability, and answering is recorded as the
STRATEGIST authority only. A dashboard route that could widen what it may do would collapse
"drive" and "authorize" into one surface, which is precisely the conflation the owner channel
exists to prevent.

OBSERVER HTTPD PRECEDENT
------------------------
This server copies its discipline from the qualified observer httpd in transports.mcp.server and
the bearer machinery in transports.mcp.auth:

    * LOOPBACK ONLY. The bind host is a module constant, not a parameter -- the same posture as
      ``mcp.server.assert_loopback`` but stronger: there is no ``host`` argument to validate,
      because a configuration knob eventually gets set. Nothing on this machine serves anything
      but 127.0.0.1; the zero-account local posture depends on the socket never leaving the box.
    * BEARER REQUIRED. Every route except ``/health`` demands ``Authorization: Bearer`` -- reads
      and writes alike. The refusal is ONE identical string for absent, malformed and wrong values
      (no oracle), checked timing-safely over SHA-256 digests, exactly like
      ``transport_auth.authenticate_http``.
    * ROUTE-SCOPED WRITES, NOT BLANKET TRUST. The original GET-only contract evolved (PRD.md
      §13.1/§13.3): POST exists ONLY on named write routes mapped to governed ops, each demanding
      an explicit JSON body (mode set additionally demands {"confirm": true} and refuses unknown
      mode values). GET on a write route answers 405; POST on anything unmapped answers 404 --
      after authentication, so the route map is never advertised to whoever knocks.
    * BOUNDED BODIES AND RESPONSES. Request bodies are capped BEFORE authentication and responses
      after serialization; either side exceeding its bound is answered with a loud bounded-envelope
      error rather than an arbitrarily large stream, mirroring the MCP server's request bound.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
No accounts, no sessions, no OAuth, no cookies-as-auth, no TLS theatre on loopback, no external
assets (the page works offline), and no token in any response body ever. The token lives in one
file under the deployment home, mode 0o600; startup prints the PATH, never the value.
"""
from __future__ import annotations

import hashlib
import hmac
import html as html_mod
import json
import os
import secrets
import sys

from quaestor import branding

WEBUI_INSTRUMENT = "webui/1"

#: THE BIND HOST IS NOT CONFIGURABLE. See module docstring: a flag would eventually be set.
LOOPBACK_HOST = "127.0.0.1"

#: The token file, under the deployment home. Separate FILE from the MCP transport tokens:
#: separate secrets with separate lifetimes must not share a blast radius (same rule that put the
#: remote tunnel token in its own file).
TOKEN_FILE = "web-ui-token"

#: 48 hex chars. Compared over digests so the comparison length never varies with input.
TOKEN_HEX_CHARS = 24 * 2

#: Largest response body emitted. A local dashboard has no excuse for a multi-megabyte answer;
#: exceeding the bound is a pathology we NAME rather than silently stream.
MAX_RESPONSE_BYTES = 1 << 20

#: Largest request body accepted, enforced BEFORE authentication (MCP server precedent): an
#: unauthenticated flood must not buy parse work either. Write bodies here are tiny JSON
#: documents; anything near this bound is abuse or a bug, and both deserve the same refusal.
MAX_BODY_BYTES = 64 << 10

#: The POST write routes. Kept as data so the route contract is stated once and the controls can
#: read it back -- each maps 1:1 onto a governed operation (PRD.md §13.1, §13.3).
WRITE_PROGRAM_ACTIONS = ("plan", "tick", "answer", "cancel", "autonomy", "approve",
                         "discard")

#: Programs list ceiling, mirroring the retrieval surface's SEARCH_LIMIT discipline: a bounded,
#: honestly-labelled truncation beats an unbounded dump.
PROGRAMS_LIMIT = 200

#: The single refusal string. Identical for absent, malformed and wrong credentials, on purpose --
#: a difference between them is an oracle (transports.mcp.auth: "FAILURE MUST NOT BE INFORMATIVE").
REFUSAL = "web ui authentication failed"


# ---------------------------------------------------------------------------------------------
# the bearer token: one file, 0o600, compared over digests
# ---------------------------------------------------------------------------------------------
def resolve_token_file(home: str, token_file: str | None = None) -> str:
    """Where the token lives. An explicit --token-file wins; otherwise <home>/<TOKEN_FILE>."""
    return token_file if token_file else os.path.join(home, TOKEN_FILE)


def ensure_token(token_file: str) -> str:
    """Create the token file if absent; return its path either way. Impure.

    Created with mode 0o600 AT OPEN (never world-readable for an instant), parent directories made
    on demand. An existing file is reused: restarting the dashboard must not rotate the secret out
    from under a browser tab that already holds it.
    """
    parent = os.path.dirname(os.path.abspath(token_file))
    if parent:
        os.makedirs(parent, exist_ok=True)
    try:
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return token_file
    try:
        os.write(fd, secrets.token_hex(TOKEN_HEX_CHARS // 2).encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    _harden(token_file)
    return token_file


def load_token(token_file: str) -> str:
    """The current token value, or "". Impure. NEVER raises -- a missing/corrupt file is just a
    refusal at the door, worded identically to every other refusal."""
    try:
        with open(token_file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def tokens_match(presented: str, expected: str) -> bool:
    """Timing-safe bearer comparison. PURE.

    Mirrors transports.mcp.auth.authenticate_http: compare SHA-256 DIGESTS, not raw values, so the
    comparison length is constant regardless of what either side holds and no early-exit path
    depends on how much of the token matched.
    """
    if not presented or not expected:
        return False
    return hmac.compare_digest(_digest(presented), _digest(expected))


def rotate_token_file(token_file: str) -> str:
    """Atomically replace the bearer secret; return the new value. Impure.

    Temp-file + atomic rename (runfiles discipline): a reader NEVER sees a torn or empty token
    file, so there is no window where every request fails. The old value stops working the
    instant the rename lands -- load_token reads the file per request by design.
    """
    value = secrets.token_hex(TOKEN_HEX_CHARS // 2)
    tmp = "%s.tmp.%d" % (token_file, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value.encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, token_file)
    _harden(token_file)
    return value


def rotation_payload(bound_port: int, token_file: str, token_value: str) -> dict:
    """The rotate response: a fresh one-step URL whose token rides ONLY in the fragment, exactly
    like startup_payload. This is the ONE response body that deliberately contains a token
    value -- the caller just proved possession of the OLD secret, which makes this a credential-
    management reply, not a leak (a password-change flow echoes the new password once)."""
    clean_url = "http://%s:%d/" % (LOOPBACK_HOST, bound_port)
    return {"rotated": True, "url": clean_url,
            "open": clean_url + "#t=" + token_value,
            "token_file": token_file,
            "note": ("the previous token stopped working when this call completed; reconnect "
                     "every tab with the fresh one-step URL")}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _harden(path: str) -> None:
    """Defence in depth ONLY; never the mechanism. NEVER raises. Best-effort chmod for POSIX plus
    an explicit ACL for Windows, mirroring transport_auth._restrict -- NTFS permissions are not
    carried by the C runtime's chmod, so on the primary development platform the icacls call IS
    the 0o600 promise."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name != "nt":
        return
    user = os.environ.get("USERNAME") or ""
    if not user:
        return
    try:
        import subprocess
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "%s:(F)" % user],
                       capture_output=True, shell=False, timeout=60)
    except Exception:  # noqa: BLE001
        pass


def _looks_like_id(v: str) -> bool:
    """Plain identifiers only, so a path or URL cannot ride in a lookup field. Same shape rule as
    transports.mcp.schemas._looks_like_id; kept local because the schema module's private helper
    is that module's contract, not this one's."""
    return bool(v) and all(c.isalnum() or c in "-_" for c in v)


#: How much of an over-bound body we will read and DISCARD so the 413 is actually deliverable.
#: Closing on a peer that is still sending resets the connection and destroys the response we
#: already wrote, which turned a named refusal into a transport error. Discarding costs no parse
#: work and no retained memory, so this bound is about patience, not safety.
DRAIN_LIMIT_BYTES = 1 << 20


def drain_bounded(rfile, length: int, limit: int = DRAIN_LIMIT_BYTES) -> int:
    """Read and DISCARD up to ``limit`` bytes of an over-bound body. Returns bytes discarded.

    Exists as its own function so a control can falsify it. The end-to-end form could not:
    loopback buffers absorb a few hundred KB before a close can race the peer's send, so the
    413 arrived whether or not anything was drained -- and the race still fired under a full
    suite, where it read as a flaky ConnectionAbortedError rather than as the defect it was.
    """
    remaining = min(int(length), int(limit))
    drained = 0
    while remaining > 0:
        chunk = rfile.read(min(65536, remaining))
        if not chunk:
            break
        drained += len(chunk)
        remaining -= len(chunk)
    return drained


class BodyTooLarge(Exception):
    """The request body exceeds MAX_BODY_BYTES. Refused before authentication, like the MCP
    server enforces its own bound."""


def is_write_route(path: str) -> bool:
    """Does this path exist ONLY as a POST write route (so GET must answer 405)? PURE.

    Stated as data so the wire contract has one definition: the create route, the mode-set
    route, and the four per-program actions under /api/program/<id>/.
    """
    parts = [p for p in path.split("/") if p]
    if path in ("/api/program/create", "/api/mode/set", "/api/token/rotate",
                "/api/connect/manifest", "/api/seats/set"):
        return True
    return len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
        and parts[3] in WRITE_PROGRAM_ACTIONS


def is_read_route(path: str) -> bool:
    """Does this path exist as a GET read (so POST there answers 405 Allow: GET)? PURE."""
    parts = [p for p in path.split("/") if p]
    if path in ("/", "/api/programs", "/api/events", "/api/mode", "/api/settings"):
        return True
    if len(parts) == 3 and parts[0] == "api" and parts[1] == "programs":
        return True
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "programs" \
            and parts[3] in ("inbox", "lanes", "cost"):
        return True
    # Lane drill-down: the runs bound to one lane of one program.
    if len(parts) == 6 and parts[0] == "api" and parts[1] == "program" \
            and parts[3] == "lane" and parts[5] == "runs":
        return True
    # The run viewer: one run's result, evidence and handoff package.
    if len(parts) == 3 and parts[0] == "api" and parts[1] == "run":
        return True
    # The relay briefing (ru1.14): the copyable packet a human carries to an outside agent.
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
            and parts[3] == "briefing":
        return True
    # The autonomy setting for one program (EPIC P6).
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
            and parts[3] == "autonomy-state":
        return True
    # Program-level turns: the seats that bind to no lane (EPIC P6).
    if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
            and parts[3] == "turns":
        return True
    # The onboarding wizard's detection read (ru1.10), the seat matrix and the
    # first-run readiness view (ru1.15/ru1.16).
    return path in ("/api/connect/detect", "/api/seats", "/api/readiness")


# ---------------------------------------------------------------------------------------------
# the read surface: thin views OVER orch.status_view / orch.inbox / the durable run rows --
# never a second reading. The lane drill-down (ru1.8) reads the SAME Store rows the dispatcher
# and worker wrote; it re-derives nothing.
# ---------------------------------------------------------------------------------------------
def _sstore_for(home: str):
    """A fresh StrategicStore PER REQUEST. SQLite connections are thread-bound; the server is a
    ThreadingHTTPServer. Opening per request costs nothing locally and removes the whole class of
    cross-thread connection bugs."""
    from quaestor.core import strategic_store as ss_mod
    return ss_mod.StrategicStore(ss_mod.strategic_path(home))


def programs_payload(home: str) -> dict:
    """Every program, oldest first, bounded and honestly labelled. Read-only."""
    sstore = _sstore_for(home)
    try:
        rows = sstore.list_programs()
        listed = [{k: r[k] for k in ("program_id", "title", "created_at")}
                  for r in rows[:PROGRAMS_LIMIT]]
        meta = {r["program_id"]: r for r in rows[:PROGRAMS_LIMIT]}
        for row in listed:
            row["status"] = (sstore.get_program_meta(row["program_id"]).get("status", ""))
            row["updated_at"] = meta[row["program_id"]].get("updated_at")
        return {"programs": listed, "count": len(listed),
                "total": len(rows), "truncated": len(rows) > len(listed)}
    finally:
        sstore.close()


def status_payload(home: str, program_id: str) -> dict | None:
    """orch.status_view verbatim (None when the program does not exist). THE canonical reading.

    Existence is decided by the program ROW, deliberately not by the view's own ``vacuous`` flag:
    status_view builds ``prog = get_program(...) or {}`` first, so its ``prog is None`` test can
    never fire and a MISSING program would sail through as a 200 with an empty title. We do not
    edit the qualified core for a display concern -- we simply ask the store directly.
    """
    from quaestor.core import orchestrator as orch
    from quaestor.core.store import Store
    sstore = _sstore_for(home)
    store = Store(os.path.join(home, "orchestrator.sqlite3"))
    try:
        if sstore.get_program(program_id) is None:
            return None
        # The MEASURED provider record travels with the view, so the cockpit and the CLI cannot
        # disagree about whether a real agent ran. status_view's `store` parameter existed and
        # every production caller passed None, which is how a program executed entirely by the
        # test double came to present as a plain PASS.
        return orch.status_view(sstore, store, program_id)
    finally:
        store.close()
        sstore.close()


def inbox_payload(home: str, program_id: str) -> dict | None:
    """orch.inbox verbatim -- the intervention queue. None when the program does not exist.

    Existence is decided by the program ROW, not by the inbox's own ``vacuous`` flag: an empty
    inbox on a real program is a legitimate answer ("nothing needs attention"), and collapsing it
    into 404 would make an idle program indistinguishable from a missing one.
    """
    from quaestor.core import orchestrator as orch
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None
        return orch.inbox(sstore, program_id)
    finally:
        sstore.close()


def lanes_payload(home: str, program_id: str) -> dict | None:
    """The lanes table for one program, derived FROM status_view -- deliberately NOT a second
    query shaped differently, so this table cannot disagree with the detail view beside it."""
    view = status_payload(home, program_id)
    if view is None:
        return None
    return {"program_id": program_id, "title": view.get("title", ""),
            "status": view.get("status", ""), "lanes": view.get("lanes", []),
            "inspected": view.get("inspected", {})}


#: Long free-text fields in drill-down payloads are clipped like status_view clips ``summary``:
#: the viewer shows enough to identify; the durable row keeps the whole.
BRIEF_CHARS = 160


def _clip(value, limit: int = BRIEF_CHARS) -> str:
    return str(value or "")[:limit]


def _load_json(text) -> dict | None:
    """Parsed JSON object, or None when absent/unreadable. NEVER raises (runfiles discipline)."""
    try:
        loaded = json.loads(str(text or ""))
    except (ValueError, TypeError, UnicodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _result_brief(res: dict) -> dict:
    """The result fields a drill-down shows. ``valid`` is tri-state: absent row -> None."""
    if not res:
        return {"valid": None, "outcome": "", "prompt_disposition": "",
                "program_verdict": "", "invalid_reason": "", "summary": ""}
    return {"valid": bool(res.get("valid")),
            "outcome": _clip(res.get("outcome")),
            "prompt_disposition": _clip(res.get("prompt_disposition")),
            "program_verdict": _clip(res.get("program_verdict")),
            "invalid_reason": _clip(res.get("invalid_reason")),
            "summary": _clip(res.get("summary"))}


def lane_runs_payload(home: str, program_id: str, lane_id: str):
    """Everything "click a lane" means (PRD.md §13.3): the runs bound to the lane,
    its review findings, the candidate record and its context capsule.

    Returns ``(payload, refusal_name)`` -- exactly one of the two is None, so the route can
    distinguish a missing PROGRAM from a missing LANE from success without stringly-typed
    probing by the caller. Runs are read through the SAME Store rows the dispatcher wrote;
    nothing here re-derives state. A lane_run binding whose attempt row is gone is listed with
    ``attempt_absent`` -- an honest hole, never a silent omission.
    """
    from quaestor.core.store import Store
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None, "NO_SUCH_PROGRAM"
        lane = sstore.get_lane(lane_id)
        if lane is None or lane.program_id != program_id:
            # Containment check deliberate: a valid lane id under the wrong program is a 404
            # on THIS route, not a leak of another program's drill-down.
            return None, "NO_SUCH_LANE"
        store = Store(os.path.join(home, "orchestrator.sqlite3"))
        try:
            runs = []
            for b in sstore.runs_for_lane(lane_id):
                run = store.get_run(b["run_id"]) or {}
                res = store.get_result(b["run_id"]) or {}
                runs.append({
                    "run_id": b["run_id"], "role": str(b.get("role") or ""),
                    "bound_at": b.get("created_at"), "processed": bool(b.get("processed")),
                    "execution_state": run.get("execution_state"),
                    "is_write": bool(run.get("is_write")),
                    "created_at": run.get("created_at"), "terminal_at": run.get("terminal_at"),
                    "refusal_reason": run.get("refusal_reason"),
                    "attempt_absent": not run,
                    "has_evidence": store.get_evidence(b["run_id"]) is not None,
                    "has_handoff": store.get_handoff(b["run_id"]) is not None,
                    "outcome": _result_brief(res)})
        finally:
            store.close()
        reviews = [{"review_id": r["review_id"], "kind": r["kind"], "outcome": r["outcome"],
                    "run_id": r.get("run_id", ""), "created_at": r["created_at"],
                    "result": _load_json(r.get("result_json"))}
                   for r in sstore.reviews_for(program_id, lane_id=lane_id)]
        task_doc = sstore.get_lane_task(lane_id) or {}
        ckpt = task_doc.get("checkpoint") or {}
        candidate = {
            "commit_sha": ckpt.get("commit_sha") or "",
            "worktree_branch": ckpt.get("worktree_branch") or "",
            "claimed_files_changed": list(ckpt.get("claimed_files_changed") or []),
            "verification": ckpt.get("verification") or {},
            "note": ("commit/branch are the lane checkpoint's durable record; "
                     "claimed_files_changed is the executor's CLAIM -- bridge evidence, "
                     "not the claim, is what verifies it")}
        capsule = sstore.context_capsule(lane_id)
        return {"program_id": program_id, "lane_id": lane_id,
                "title": lane.title, "state": lane.state, "verdict": lane.verdict,
                "runs": runs, "reviews": reviews, "candidate": candidate,
                "context_capsule": capsule,
                "inspected": {"runs": len(runs), "reviews": len(reviews)}}, None
    finally:
        sstore.close()


def run_payload(home: str, run_id: str) -> dict | None:
    """One run's viewer payload: the attempt, its result brief, the bridge's evidence envelope,
    and the handoff package verbatim -- including the cost-equivalent figure the package already
    carries, labelled exactly as worker.build_handoff_package labelled it. None when the run
    does not exist."""
    from quaestor.core.store import Store
    store = Store(os.path.join(home, "orchestrator.sqlite3"))
    try:
        run = store.get_run(run_id)
        if run is None:
            return None
        res = store.get_result(run_id) or {}
        ev = store.get_evidence(run_id)
        ho = store.get_handoff(run_id)
    finally:
        store.close()
    sstore = _sstore_for(home)
    try:
        binding = sstore.lane_for_run(run_id) or {}
    finally:
        sstore.close()
    pkg = _load_json(ho.get("handoff_json")) if ho else None
    tel = (pkg or {}).get("child_telemetry") or {}
    evidence_out = None
    if ev is not None:
        observed = ev["observed_change"]
        evidence_out = {"collected_at": ev["collected_at"], "verdict": ev["verdict"],
                        "probe_ok": bool(ev["probe_ok"]),
                        "inspected_count": ev["inspected_count"],
                        "observed_change": None if observed is None else bool(observed),
                        "reason": ev["reason"],
                        "envelope": _load_json(ev["envelope_json"])}
    return {"run_id": run_id,
            "run": {"execution_state": run["execution_state"],
                    "dispatch_key": run["dispatch_key"], "attempt_no": run["attempt_no"],
                    "is_write": bool(run["is_write"]), "created_at": run["created_at"],
                    "updated_at": run["updated_at"], "terminal_at": run["terminal_at"],
                    "refusal_reason": run["refusal_reason"]},
            "lane": None if not binding else {"lane_id": binding["lane_id"],
                                              "role": str(binding.get("role") or "")},
            "result": _result_brief(res),
            "evidence": evidence_out,
            "handoff_package": pkg,
            "cost_usd_reported": {"value": tel.get("total_cost_usd_reported"),
                                  "note": str(tel.get("cost_note") or "")},
            "inspected": {"has_evidence": ev is not None, "has_handoff": ho is not None}}


# ---------------------------------------------------------------------------------------------
# cost visibility (ru1.13): roll-ups OVER the handoff packages' own telemetry. The number is
# what the executor CLI REPORTED -- recorded verbatim by envelope_telemetry and deliberately
# NOT interpreted as billing; the auth preflight, not this number, establishes the billing
# path. Every surface here repeats that label, because a dollar-shaped number next to a sum
# invites exactly the inference the contract refuses to make.
# ---------------------------------------------------------------------------------------------
#: Roll-up scan ceiling: newest N handoff packages. A bounded, honestly-flagged truncation
#: beats an unbounded dump (PROGRAMS_LIMIT discipline).
COST_SCAN_LIMIT = 2000

#: The one honesty label, stated once and served verbatim everywhere cost appears.
COST_LABEL = ("reported cost-equivalent -- recorded by the executor CLI and NOT interpreted "
              "as a billed charge; the auth preflight is what establishes the billing path")


#: Program-level turn listing ceiling. Same honestly-labelled-truncation discipline as
#: PROGRAMS_LIMIT: a long-running program accumulates turns, and an unbounded dump would cross
#: the response bound and answer 500 -- losing the whole view rather than part of it.
TURNS_LIMIT = 100


def program_turns_payload(home: str, program_id: str) -> dict | None:
    """The PROGRAM-level runs: strategist turns, planner turns, plan challenges. Read-only.

    THE GAP THIS CLOSES. A seat that binds to no lane leaves no ``lane_run`` row, and every
    existing drill-down reads that table -- so the strategist seat, the most consequential agent
    in an unattended program, was structurally invisible. This is the sibling of
    ``lane_runs_payload`` for runs that belong to the program itself.

    Reads the SAME rows the dispatcher and worker wrote, joined to the ``run.provenance`` event
    for the MEASURED role and provider. Nothing here re-derives state, and the role is never
    guessed from the step id.
    """
    from quaestor.core.store import Store
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None
        store = Store(os.path.join(home, "orchestrator.sqlite3"))
        try:
            rows = store.runs_for_workflow(program_id)
            turns = []
            for run in rows:
                run_id = str(run["run_id"])
                # LANE-BOUND RUNS BELONG TO THE LANE DRILL-DOWN. Listing them here too would
                # duplicate them in the cockpit and make the turn list read as busier than the
                # program is.
                if sstore.lane_for_run(run_id) is not None:
                    continue
                prov = {}
                for ev in store.events_for(run_id):
                    if ev["kind"] == "run.provenance":
                        prov = _load_json(ev["detail_json"]) or {}
                        break
                res = store.get_result(run_id) or {}
                turns.append({
                    "run_id": run_id,
                    "step_id": str(run.get("step_id") or ""),
                    # MEASURED, from run.provenance -- never inferred from the step id, which is
                    # a display string a refactor may reshape at any time.
                    "role": str(prov.get("role") or ""),
                    "provider": str(prov.get("provider") or ""),
                    "provider_source": str(prov.get("source") or ""),
                    "execution_state": run.get("execution_state"),
                    "authority_profile": str(run.get("authority_profile") or ""),
                    "is_write": bool(run.get("is_write")),
                    "created_at": run.get("created_at"),
                    "session_id": str(res.get("session_id") or ""),
                    "result": _result_brief(res),
                })
                if len(turns) >= TURNS_LIMIT:
                    break
            return {"program_id": program_id, "turns": turns, "count": len(turns),
                    "truncated": len(turns) >= TURNS_LIMIT,
                    "note": ("runs belonging to the PROGRAM rather than to a lane -- strategist "
                             "and planner seats bind to no lane, so the lane drill-down cannot "
                             "reach them")}
        finally:
            store.close()
    finally:
        sstore.close()


def _cost_facts(pkg) -> dict | None:
    """(value, provider, role) from one handoff package, or None when it reports NO usable
    figure. PURE. Absent or malformed telemetry contributes NOTHING -- never a silent zero:
    collapsing absence into 0.0 would make "no handoff" indistinguishable from "free"."""
    if not isinstance(pkg, dict):
        return None
    value = ((pkg.get("child_telemetry") or {}).get("total_cost_usd_reported"))
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    seat = pkg.get("seat") or {}
    prov = pkg.get("provenance") or {}
    return {"value": float(value),
            "provider": str(seat.get("provider") or prov.get("executor") or "unknown"),
            "role": str(seat.get("role") or "unknown")}


def _aggregate_costs(facts_list) -> dict:
    """Sum by total / provider / role over per-run facts. PURE."""
    agg = {"total": 0.0, "runs_counted": 0, "by_provider": {}, "by_role": {}}
    for f in facts_list:
        agg["total"] += f["value"]
        agg["runs_counted"] += 1
        for bucket, key in (("by_provider", "provider"), ("by_role", "role")):
            agg[bucket][f[key]] = round(agg[bucket].get(f[key], 0.0) + f["value"], 6)
    agg["total"] = round(agg["total"], 6)
    return agg


def _cost_scan_rows(home: str) -> list:
    """Newest COST_SCAN_LIMIT handoff packages with their program attribution (the dispatch's
    workflow_id -- the SAME exact-or-prefix convention store.outcome_summary relies on)."""
    from quaestor.core.store import Store
    store = Store(os.path.join(home, "orchestrator.sqlite3"))
    try:
        return store._all(
            "SELECT d.workflow_id AS workflow_id, h.run_id AS run_id, h.handoff_json AS pkg"
            " FROM handoff h JOIN attempt a ON a.run_id = h.run_id"
            " JOIN dispatch d ON d.dispatch_key = a.dispatch_key"
            " ORDER BY h.ready_at DESC LIMIT ?", (COST_SCAN_LIMIT,))
    finally:
        store.close()


def _scan_truncated(rows: list) -> bool:
    return len(rows) >= COST_SCAN_LIMIT


def program_cost_payload(home: str, program_id: str) -> dict | None:
    """One program's reported cost-equivalent, summed by provider and role. None when the
    program does not exist."""
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None
    finally:
        sstore.close()
    rows = _cost_scan_rows(home)
    facts = []
    for row in rows:
        if row["workflow_id"] != program_id:
            continue
        f = _cost_facts(_load_json(row["pkg"]))
        if f:
            facts.append(f)
    out = _aggregate_costs(facts)
    return {"program_id": program_id, **out, "label": COST_LABEL,
            "scan_limit": COST_SCAN_LIMIT, "truncated": _scan_truncated(rows),
            "inspected": {"runs_with_handoff_scanned": len(facts)}}


def home_cost_summary(home: str) -> dict:
    """The Settings view's home-wide totals over the same scanned packages."""
    rows = _cost_scan_rows(home)
    facts_by_program = {}
    for row in rows:
        f = _cost_facts(_load_json(row["pkg"]))
        if f:
            facts_by_program.setdefault(str(row["workflow_id"]), []).append(f)
    all_facts = [f for fs in facts_by_program.values() for f in fs]
    agg = _aggregate_costs(all_facts)
    by_program = [{"program_id": pid,
                   "total": round(sum(f["value"] for f in fs), 6),
                   "runs_counted": len(fs)}
                  for pid, fs in facts_by_program.items()]
    by_program.sort(key=lambda e: -e["total"])
    return {**agg, "programs_seen": len(by_program), "by_program_top": by_program[:20],
            "label": COST_LABEL, "scan_limit": COST_SCAN_LIMIT,
            "truncated": _scan_truncated(rows)}


#: Events-delta ceiling (ru1.9): one poll returns at most this many NEW events. A client that
#: falls further behind fast-forwards by the returned ids -- the gap is FLAGGED, never faked.
EVENTS_DELTA_LIMIT = 200


def events_payload(home: str, since: int | None = None) -> dict:
    """Recent-events COUNT SUMMARY -- or, when ``since`` is given, the DELTA of event rows NEWER
    than that position. Both modes carry ``now_seq`` so a client can track its position; the
    delta is bounded by EVENTS_DELTA_LIMIT with an explicit ``truncated`` flag rather than an
    unbounded dump. Grouped SQL keeps the summary bounded by the event VOCABULARY, never table
    size.

    THE CURSOR IS THE APPEND-ONLY LOG'S ``rowid``, served under the name ``seq``: the strategic
    event table keys on a random event_id and carries no integer column of its own, but its
    insertion rowid is monotonic for an append-only log (no updates, no deletes -- the same
    trigger discipline as the orchestrator store's event log), which is exactly what a
    "newer than" cursor needs.
    """
    sstore = _sstore_for(home)
    try:
        now_rows = sstore._all("SELECT COALESCE(MAX(rowid), 0) AS n FROM event")
        now_seq = int(now_rows[0]["n"]) if now_rows else 0
        if since is not None:
            rows = sstore._all(
                "SELECT rowid AS seq, event_type, at FROM event WHERE rowid > ?"
                " ORDER BY rowid LIMIT ?", (int(since), EVENTS_DELTA_LIMIT))
            return {"delta": True, "since": int(since),
                    "events": [{"seq": int(r["seq"]), "event_type": r["event_type"],
                                "at": r["at"]} for r in rows],
                    "now_seq": now_seq,
                    "truncated": len(rows) >= EVENTS_DELTA_LIMIT,
                    "delta_limit": EVENTS_DELTA_LIMIT}
        total = sstore._all("SELECT COUNT(*) AS n FROM event")
        by_type = sstore._all(
            "SELECT event_type, COUNT(*) AS n FROM event GROUP BY event_type ORDER BY n DESC,"
            " event_type")
        latest = sstore._all("SELECT event_type, at FROM event ORDER BY rowid DESC LIMIT 20")
        return {"total_events": int(total[0]["n"]) if total else 0,
                "by_type": [{"event_type": r["event_type"], "count": int(r["n"])} for r in by_type],
                "latest": [{"event_type": r["event_type"], "at": r["at"]} for r in latest],
                "latest_limit": 20, "now_seq": now_seq}
    finally:
        sstore.close()


def _query_param(raw_path: str, name: str) -> str | None:
    """The FIRST value of a query parameter, or None. PURE."""
    from urllib.parse import parse_qs
    _, _, qs = raw_path.partition("?")
    values = parse_qs(qs).get(name)
    return str(values[0]) if values else None


# ---------------------------------------------------------------------------------------------
# the write surface: POST routes mapped 1:1 onto the SAME governed ops the CLI invokes.
# The transport invokes governed operations; it never grants authority -- so there is no new
# policy here, only the same orchestrator calls `program create/plan/tick/answer/cancel` and
# `mode set` make, under the same bearer gate, with actor provenance "webui".
# ---------------------------------------------------------------------------------------------
def _project_config(project_arg: str) -> tuple:
    """cli._resolve_project VERBATIM -- the one config resolution `program create` uses.

    Imported rather than copied: a second resolution of project manifests would be a second
    policy about manifests (the same rule that keeps the read surface on orch.status_view).
    """
    from quaestor.transports import cli as cli_mod
    return cli_mod._resolve_project(project_arg)


def _err(code: int, error: str, **detail):
    """A named, bounded refusal. Validation failures NAME themselves; nothing else."""
    return code, dict({"error": error, "instrument": WEBUI_INSTRUMENT}, **detail)


def _field(body: dict, name: str, *, required=True, default=""):
    """A string body field. Missing-required is a NAMED validation refusal, not a KeyError."""
    v = body.get(name, None)
    if v is None and not required:
        return default, None
    if not isinstance(v, str) or not v.strip():
        return None, _err(400, "FIELD_REQUIRED", field=name,
                          detail="a non-empty string is required")
    return v.strip(), None


def _split_list(value: str, sep: str) -> list:
    """CLI-shaped list fields: pipe-separated acceptance items, comma-separated lane ids."""
    return [x.strip() for x in str(value or "").split(sep) if x.strip()]


def _program_exists(sstore, program_id: str) -> bool:
    # Existence decided by the program ROW, exactly like the read surface above.
    return sstore.get_program(program_id) is not None


def write_program_create(home: str, body: dict):
    """orch.create_program + repository meta + main lane -- cmd_program_create's exact calls."""
    from quaestor.core import orchestrator as orch
    title, e = _field(body, "title")
    if e:
        return e
    objective, e = _field(body, "objective")
    if e:
        return e
    project, e = _field(body, "project")
    if e:
        return e
    constraints = _split_list(str(body.get("constraints") or ""), "|")
    acceptance = _split_list(str(body.get("acceptance") or ""), "|")
    try:
        max_concurrent = int(body.get("max_concurrent") or 1)
    except (TypeError, ValueError):
        return _err(400, "FIELD_INVALID", field="max_concurrent",
                    detail="must be an integer")
    cfg, reason = _project_config(project)
    if cfg is None:
        return _err(400, "PROJECT_CONFIG_MISSING", detail=reason)
    sstore = _sstore_for(home)
    try:
        pid = orch.create_program(sstore, title=title, objective=objective,
                                  constraints=constraints,
                                  policy=orch.ProgramPolicy(max_concurrent_executors=max_concurrent),
                                  actor_id="webui")
        sstore.set_program_meta(pid, "repository", cfg.repository)
        sstore.set_program_meta(pid, "project_name", cfg.name)
        sstore.set_program_meta(pid, "project_config", cfg.source_path)
        lane_id = orch.plan_lane(sstore, pid, title=title or "main", task=objective,
                                 kind=orch.KIND_IMPLEMENTATION, acceptance=acceptance,
                                 actor_id="webui")
        return 200, {"program_id": pid, "lane_id": lane_id, "repository": cfg.repository,
                     "project_name": cfg.name}
    finally:
        sstore.close()


def write_program_plan(home: str, program_id: str, body: dict):
    """orch.plan_lane -- cmd_program_plan's exact call (executor stays server-side absent)."""
    from quaestor.core import orchestrator as orch
    title, e = _field(body, "title")
    if e:
        return e
    task, e = _field(body, "task")
    if e:
        return e
    kind = str(body.get("kind") or orch.KIND_IMPLEMENTATION)
    depends_on = _split_list(str(body.get("depends_on") or ""), ",")
    acceptance = _split_list(str(body.get("acceptance") or ""), "|")
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        try:
            lane_id = orch.plan_lane(sstore, program_id, title=title, task=task, kind=kind,
                                     depends_on=depends_on, acceptance=acceptance,
                                     actor_id="webui")
        except ValueError as exc:
            return _err(400, "PLAN_REFUSED", detail=str(exc))
        return 200, {"lane_id": lane_id, "program_id": program_id}
    finally:
        sstore.close()


def write_program_tick(home: str, program_id: str):
    """orch.tick(spawn=True) over the program's repository config -- cmd_program_tick verbatim."""
    from quaestor.core import orchestrator as orch
    from quaestor.core.store import Store
    sstore = _sstore_for(home)
    store = Store(os.path.join(home, "orchestrator.sqlite3"))
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        repo = sstore.get_program_meta(program_id).get("repository", "")
        cfg, reason = _project_config(repo) if repo else (None, "program has no repository")
        if cfg is None:
            return _err(400, "PROJECT_CONFIG_MISSING", detail=reason)
        report = orch.tick(home, sstore, store, program_id=program_id, cfg=cfg,
                           preflight=orch._preflight_for(cfg), spawn=True)
        return 200, report
    finally:
        sstore.close()
        store.close()


def write_program_answer(home: str, program_id: str, body: dict):
    """orch.answer at authority STRATEGIST -- the dashboard records strategist decisions ONLY.

    The CLI can carry --authority OWNER because it speaks for an interactive human through the
    attested channel; a bearer on a loopback socket does not certify OWNERSHIP, and inventing a
    second path to owner authority is exactly what this transport must never do.
    """
    from quaestor.core import decisions as dec_mod
    from quaestor.core import orchestrator as orch
    message_id, e = _field(body, "message_id")
    if e:
        return e
    text, e = _field(body, "text")
    if e:
        return e
    rationale = str(body.get("rationale") or "").strip()
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        try:
            directive = orch.answer(sstore, program_id, message_id, decision_text=text,
                                    rationale=rationale, authority=dec_mod.BY_STRATEGIST,
                                    actor_id="webui")
        except ValueError as exc:
            return _err(400, "ANSWER_REFUSED", detail=str(exc))
        return 200, {"directive_id": directive, "answered": message_id,
                     "authority": dec_mod.BY_STRATEGIST,
                     "note": "the lane resumes from its checkpoint on the next tick"}
    finally:
        sstore.close()


def write_program_cancel(home: str, program_id: str, body: dict):
    """orch.cancel_program -- cmd_program_cancel's exact call."""
    from quaestor.core import orchestrator as orch
    reason, e = _field(body, "reason")
    if e:
        return e
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        out = orch.cancel_program(sstore, program_id, reason=reason, actor_id="webui")
        return 200, {"cancelled": True, **out}
    finally:
        sstore.close()


def relay_surfaces(program_id: str, bound_port: int | None = None) -> dict:
    """How a human relays an outside agent's directive back. Vocabulary read from its OWN source.

    PUBLIC and shared: the CLI's ``program briefing`` builds the same packet, and two copies of
    this would drift into telling two different operators two different things about the same
    deployment. ``bound_port=None`` is the HEADLESS case -- no dashboard is running, so the
    dashboard line is ABSENT rather than pointing at a port nothing is listening on.

    The CLI verb comes from ``cli.command_verbs`` (derived from the real parser) and the tool name
    from ``mcp.schemas``: a briefing that prints a paste-ready command line has to be a command
    that still parses, and a retyped one drifts the first time a verb is renamed. If the answer
    verb ever stops existing, the cli line is simply ABSENT from the packet rather than wrong.

    THE DASHBOARD URL IS THE CLEAN ONE. Never the ``#t=`` one-step form: this string is going into
    a third party's chat log by design, and the single response body allowed to carry a token is
    the rotation reply to a caller who already proved possession of the old one.
    """
    from quaestor.transports import cli as cli_mod
    from quaestor.transports.mcp import schemas as mcp_schemas
    verbs = cli_mod.command_verbs("program")
    cli_answer = ""
    if "answer" in verbs:
        cli_answer = ('python -m quaestor.transports.cli program answer %s <message_id> '
                      '--text "<directive>" --rationale "<why>"' % program_id)
    return {"dashboard_url": ("http://%s:%d/" % (LOOPBACK_HOST, bound_port)
                             if bound_port else ""),
            "cli_answer": cli_answer,
            "cli_verbs": list(verbs),
            "mcp_decide_tool": mcp_schemas.T_PROGRAM_DECIDE,
            "mcp_tools": list(mcp_schemas.TOOLS)}


def briefing_payload(home: str, program_id: str, bound_port: int) -> dict | None:
    """The outside-agent relay packet for one program (ru1.14). Read-only. None when no program.

    A THIN VIEW, like every other read here: the store assembles the handoff bundle, core.briefing
    renders it, and this function adds only the relay vocabulary the core layer cannot import
    (core does not import transports). There is no second reading of program state and no policy
    invented at the transport.

    This route creates NO authority path. The packet it serves instructs a HUMAN, who then uses
    the same governed answer surface they already had; an outside agent that reads it gains
    exactly nothing it did not have before, which is why serving it over the existing bearer-gated
    read surface is the whole of the security story.
    """
    from quaestor.core import briefing as briefing_mod
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None
        bundle = sstore.handoff_bundle(program_id)
    finally:
        sstore.close()
    return briefing_mod.briefing(bundle, surfaces=relay_surfaces(program_id, int(bound_port)))


def write_program_autonomy(home: str, program_id: str, body: dict):
    """Set THIS program's autonomy mode. The same governed act the CLI would perform.

    Per PROGRAM, not per deployment: the mode is read by core during a tick, and a deployment
    file would have to be handed down through a transport, which is the layering edge core is
    forbidden. The granularity is also better -- a routine refactor can run AUTO while the
    program touching the payment path runs SAFE.

    An unknown value is refused BEFORE anything is written, like mode set: a mistyped autonomy
    mode that silently became the fallback would be a policy the operator believes they chose
    and did not.
    """
    from quaestor.core import autonomy as auto_mod
    value = body.get("value")
    if not isinstance(value, str) or value not in auto_mod.KNOWN_MODES:
        return _err(400, "UNKNOWN_AUTONOMY_MODE",
                    known_modes=list(auto_mod.KNOWN_MODES),
                    detail="refusing to write an unrecognised autonomy mode")
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        sstore.set_program_meta(program_id, auto_mod.AUTONOMY_MODE_KEY, value)
        return 200, {"ok": True, "program_id": program_id, "autonomy_mode": value,
                     "note": ("takes effect on the next strategist turn; owner-routed asks "
                              "escalate to you in every mode, including AUTO")}
    finally:
        sstore.close()


def write_program_approve(home: str, program_id: str, body: dict):
    """Apply ONE queued directive -- the human half of the propose-only autonomy mode."""
    from quaestor.core import orchestrator as orch
    message_id, e = _field(body, "message_id")
    if e:
        return e
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        try:
            out = orch.approve_pending_directive(sstore, program_id, message_id,
                                                 actor_id="webui")
        except ValueError as exc:
            return _err(404, "NO_SUCH_PENDING_DIRECTIVE", detail=str(exc))
        return 200, out
    finally:
        sstore.close()


def write_program_discard(home: str, program_id: str, body: dict):
    """Drop ONE queued directive without applying it. The QUESTION stays open for a human."""
    from quaestor.core import orchestrator as orch
    message_id, e = _field(body, "message_id")
    if e:
        return e
    sstore = _sstore_for(home)
    try:
        if not _program_exists(sstore, program_id):
            return _err(404, "NO_SUCH_PROGRAM", program_id=program_id)
        try:
            out = orch.discard_pending_directive(sstore, program_id, message_id)
        except ValueError as exc:
            return _err(404, "NO_SUCH_PENDING_DIRECTIVE", detail=str(exc))
        return 200, dict(out, note="the question remains open; answer it yourself below")
    finally:
        sstore.close()


def autonomy_payload(home: str, program_id: str) -> dict | None:
    """This program's autonomy mode plus the vocabulary, served from core. None when missing."""
    from quaestor.core import autonomy as auto_mod
    from quaestor.core import strategist as strat_mod
    sstore = _sstore_for(home)
    try:
        if sstore.get_program(program_id) is None:
            return None
        meta = sstore.get_program_meta(program_id)
        raw = meta.get(auto_mod.AUTONOMY_MODE_KEY)
        try:
            pending = json.loads(meta.get(strat_mod.PENDING_DIRECTIVES_KEY) or "{}")
        except ValueError:
            pending = {}
        return {"program_id": program_id,
                "autonomy_mode": auto_mod.resolve_mode(raw),
                "explicit": raw in auto_mod.KNOWN_MODES,
                "known_modes": list(auto_mod.KNOWN_MODES),
                "fallback_mode": auto_mod.FALLBACK_MODE,
                "strategist_seat": (str(meta.get(strat_mod.STRATEGY_MODE_KEY) or "")
                                    == strat_mod.STRATEGIST_SEAT),
                "consecutive_refusals": int(meta.get(strat_mod.STRATEGIST_REFUSALS_KEY) or 0),
                "halt_after": strat_mod.MAX_CONSECUTIVE_REFUSALS,
                "pending_directives": len((pending or {}).get("directives") or ()),
                "note": ("owner-routed asks escalate to a human in EVERY mode, including "
                         "AUTO; a model seat never reaches owner capability")}
    finally:
        sstore.close()


def seats_payload(path: str) -> dict:
    """Every assignable seat, its current pin, the candidates, and each candidate's MEASURED
    preflight verdict. Read-only.

    OWNER never appears. It is not filtered out here as a display choice -- it is absent from
    ``ASSIGNABLE_ROLES`` itself, and this view iterates that tuple, so the seat cannot be shown
    even by mistake.

    Preflight verdicts are the measured ones each provider module computes; nothing here decides
    whether a provider works. A provider with no preflight module reports ``unmeasured`` rather
    than a cheerful default, because "we did not check" and "we checked and it is fine" are
    different facts and the operator is entitled to know which one they are looking at.
    """
    from quaestor.adapters import registry as cap_reg
    from quaestor.projects import config as cfg_mod
    manifest = cfg_mod.find_config(path) if path else ""
    cfg, reason = (cfg_mod.load(manifest) if manifest else (None, "no manifest"))
    pins = dict(getattr(cfg, "role_executor", None) or {})
    candidates = []
    for kind, row in cap_reg.PROVIDER_REGISTRY.items():
        candidates.append({"kind": kind,
                           "provider_family": row["provider_family"],
                           "write_capable": bool(row["write_capable"]),
                           "fact_status": row["fact_status"],
                           "credential_mode": list(row["credential_mode"]),
                           "resumes_session": bool(row.get("resumes_session")),
                           "is_gateway": kind in cap_reg.GATEWAY_KINDS,
                           "preflight": _preflight_verdict(kind)})
    seats = []
    for role in cfg_mod.ASSIGNABLE_ROLES:
        pinned = str(pins.get(role) or "")
        decision = cap_reg.resolve_seat(role, {}, pins)
        seats.append({"role": role, "pinned": pinned,
                      "resolves_to": decision.kind, "refusal": decision.refusal,
                      "rationale": list(decision.rationale)})
    return {"path": str(path or ""), "manifest": manifest, "parse_reason": reason,
            "seats": seats, "candidates": candidates,
            "owner_note": ("OWNER is absent by construction: it is not in ASSIGNABLE_ROLES, so "
                           "no manifest and no button can assign it")}


#: Which provider modules can actually MEASURE their own credential state. A kind absent here is
#: reported "unmeasured" -- never "ok" -- because "we did not check" and "we checked and it is
#: fine" are different facts.
_PREFLIGHT_MODULES = {
    "claude-cli": ("quaestor.executors.claude_auth", {}),
    "codex-cli": ("quaestor.executors.codex_auth", {}),
    "openrouter": ("quaestor.executors.openrouter_auth", {}),
    "chatgpt-web": ("quaestor.executors.chatgpt_web_auth", {}),
}


def _preflight_verdict(kind: str) -> dict:
    """One provider's measured credential state, or an honest 'unmeasured'. NEVER raises.

    Deliberately does NOT run the browser or network preflights here: this view is served on
    every Settings render, and attaching a browser or calling an API because someone opened a
    page would be a side effect nobody asked for. Those report ``on_demand``.

    ``on_demand`` says the check is DEFERRED, not that it is guaranteed to happen: whether the
    seat's own preflight actually runs is the dispatch path's business, and this view has no way
    to know. The earlier wording claimed "measured on dispatch", which was a promise about code
    this function does not own -- and was false at the time, because the executor registry had
    no preflight branch for either kind. A control now pins the wording against what the
    registry can actually do, so the two cannot drift apart again.
    """
    entry = _PREFLIGHT_MODULES.get(str(kind))
    if entry is None:
        return {"measured": False, "state": "unmeasured",
                "detail": "this build ships no credential preflight for %s" % kind}
    if kind in ("openrouter", "chatgpt-web"):
        return {"measured": False, "state": "on_demand",
                "detail": ("deferred: running it here would attach a browser or call a paid API "
                           "because a settings page was opened. Whether it runs at dispatch is "
                           "the executor's own preflight, not this view's to promise"),
                "preflight_module": _PREFLIGHT_MODULES[str(kind)][0]}
    module_name, kwargs = entry
    try:
        import importlib
        module = importlib.import_module(module_name)
        decision = module.run_preflight(**kwargs)
    except Exception as exc:  # noqa: BLE001 - an unreadable preflight is a REPORTED fact
        return {"measured": False, "state": "unreadable",
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    return {"measured": True, "state": "ok" if decision.accepted else "refused",
            "reason": str(decision.reason or ""), "detail": str(decision.detail or "")[:300],
            "credential_class": str(decision.auth_class or "")}


def write_seats(body: dict):
    """Set ``executors.roles`` in the manifest -- the same reviewed file `init` writes.

    Refuses BEFORE touching the file when a seat is not assignable, a kind is undeclared, or the
    pin could not hold the seat. The last one matters most: pinning a non-write-capable transport
    to ``implementation`` would produce a manifest that parses and a program that cannot run.
    """
    from quaestor.adapters import registry as cap_reg
    from quaestor.projects import config as cfg_mod
    path, e = _field(body, "path")
    if e:
        return e
    roles = body.get("roles")
    if not isinstance(roles, dict):
        return _err(400, "FIELD_REQUIRED", field="roles",
                    detail="roles must be a mapping of seat -> executor kind")
    # WRITE-CAPABILITY IS CHECKED HERE, not left to the file. A manifest that parses but names a
    # seat nothing can fill is a worse outcome than a refusal an operator can read.
    for role, kind in roles.items():
        if str(role) not in ("implementation", "integration"):
            continue
        if str(kind) and not cap_reg.PROVIDER_REGISTRY.get(
                cap_reg.split_gateway_kind(str(kind))[0], {}).get("write_capable"):
            return _err(400, "SEAT_REQUIRES_WRITE", role=str(role), kind=str(kind),
                        detail=("%s touches a repository, and %s is declared non-write-capable; "
                                "it is a transport, not a builder" % (role, kind)))
    out = cfg_mod.write_role_assignments(path, roles)
    if not out.get("ok"):
        return _err(400, str(out.get("reason") or "SEATS_REFUSED"), **{
            k: v for k, v in out.items() if k not in ("ok", "reason")})
    return 200, out


def readiness_payload(home: str, path: str = "") -> dict:
    """"Is my deployment ready?" in one answer. ASSEMBLY ONLY -- no new measurement.

    Every field comes from a payload that already exists, so this view cannot disagree with
    ``doctor``, with Settings, or with the seat router beside it. Closes quaestor-ru1.15 and
    quaestor-ru1.16.
    """
    from quaestor.transports.mcp import mode as transport_mode
    resolved, record = transport_mode.resolve_mode(home)
    sstore = _sstore_for(home)
    try:
        repos = []
        for row in sstore.list_programs()[:PROGRAMS_LIMIT]:
            repo = str(sstore.get_program_meta(row["program_id"]).get("repository") or "")
            if repo and repo not in repos:
                repos.append(repo)
    finally:
        sstore.close()
    seats = seats_payload(path) if path else None
    return {
        "execution_mode": {"value": resolved, "source": str((record or {}).get("source") or ""),
                           "consequence": (
                               "real constrained execution through the governed ladder"
                               if resolved == transport_mode.LOCAL_GOVERNED
                               else "executor-inert: no real provider process can be launched")},
        "autonomy_note": ("autonomy is set PER PROGRAM, not per deployment; an unset program is "
                          "propose-only, and owner-routed asks escalate in every mode"),
        "connected_repositories": repos,
        "seats": seats,
        "providers": settings_payload(home).get("providers", []),
        "ready": bool(repos) and (seats is not None and not any(
            s["refusal"] for s in (seats or {}).get("seats", []))),
        "note": ("assembled from the mode record, the program rows and the seat router; nothing "
                 "here is measured fresh, so it cannot disagree with doctor"),
    }


def mode_payload(home: str) -> dict:
    """cmd_mode show's reading: the resolved mode plus the record that explains its source."""
    from quaestor.transports.mcp import mode as transport_mode
    resolved, record = transport_mode.resolve_mode(home)
    return {"transport_execution_mode": resolved, "record": record,
            "known_modes": sorted(transport_mode.KNOWN_MODES),
            "operational_executor_kinds": sorted(transport_mode.OPERATIONAL_EXECUTOR_KINDS),
            "operational_authority_profiles":
                sorted(transport_mode.OPERATIONAL_AUTHORITY_PROFILES)}


def write_mode_set(home: str, body: dict):
    """transport_mode.write_mode -- the SAME local act `mode set` performs, typed confirm first.

    The explicit {"confirm": true} is wire-level evidence of intent, mirroring the MCP schemas'
    confirm discipline; the KNOWN_MODES check refuses unknown values BEFORE anything is written,
    exactly like the CLI's ValueError path. There is deliberately no other writer of mode.json.
    """
    from quaestor.transports.mcp import mode as transport_mode
    if body.get("confirm") is not True:
        return _err(400, "CONFIRMATION_REQUIRED",
                    detail='mode changes require {"confirm": true} in the body')
    value = body.get("value")
    if not isinstance(value, str) or value not in transport_mode.KNOWN_MODES:
        return _err(400, "UNKNOWN_MODE",
                    known_modes=sorted(transport_mode.KNOWN_MODES),
                    detail="refusing to write an unrecognised execution mode")
    try:
        out = transport_mode.write_mode(home, value)
    except ValueError as exc:
        return _err(400, "UNKNOWN_MODE", detail=str(exc))
    return 200, {"ok": True, **out,
                 "note": "takes effect the next time the MCP server or CLI resolves the deployment"}


def connect_detect_payload(path: str) -> dict:
    """projects.connect.detect_repository VERBATIM (ru1.10 wizard step 1). Read-only.

    Imported rather than retyped: a second detection would be a second policy about what counts
    as a fact. The result carries its own authority block -- detection never widens capability
    -- and this transport adds nothing to it. A bad path is the module's structured
    ``ok:false`` answer served verbatim, not a transport-level 404: the wizard shows the reason.
    """
    from quaestor.projects import connect as connect_mod
    return connect_mod.detect_repository(path)


def write_connect_manifest(home: str, body: dict):
    """projects.connect.connect_repository(write_manifest=True) -- wizard step 2.

    The SAME conservative starter manifest `quaestor init` writes; there is no force over HTTP
    (an ALREADY_CONFIGURED refusal comes back structured for the UI to show), because silently
    overwriting a reviewed manifest from a browser tab is exactly the write this surface must
    never grow. The chosen executor/authority stay in the human-reviewed file; the wizard only
    ever writes READ_ONLY-default conservatism.
    """
    path, e = _field(body, "path")
    if e:
        return e
    from quaestor.projects import connect as connect_mod
    return 200, connect_mod.connect_repository(path, write_manifest=True)


def settings_payload(home: str) -> dict:
    """The Settings view's data: handoff health, provider registry, registered adapters,
    and the durably RECORDED assurance levels (bd quaestor-ru1.18).

    Every source is an existing helper -- cli.read_outcome_summary (what doctor reports),
    adapters.registry.PROVIDER_REGISTRY (declarations with their honesty labels),
    adapters.registry_summary (who actually registered), and cli.read_assurance_summary (the
    latest COMPUTED assurance per adapter, read from the durable adapter.assurance records the
    doctor sweep writes). The first three are declarations; only the last is a measurement, and
    it is shown as one -- claimed vs computed side by side, with refusals naming the gaps.
    """
    from quaestor.adapters import registry as cap_reg
    from quaestor.adapters import registry_summary
    from quaestor.transports import cli as cli_mod
    providers = [{"kind": kind,
                  "provider_family": row["provider_family"],
                  "fact_status": row["fact_status"],
                  "credential_mode": list(row["credential_mode"])}
                 for kind, row in cap_reg.PROVIDER_REGISTRY.items()]
    return {"handoff_health": cli_mod.read_outcome_summary(home),
            "providers": providers,
            "adapters": registry_summary(),
            "assurance": cli_mod.read_assurance_summary(home),
            "cost_summary": home_cost_summary(home)}



#: Inline CSS/JS, no external assets: the deployment is offline/privacy-first, and a dashboard
#: that phones home for jquery would contradict the reason it binds to loopback in the first place.
#: @@TOKENS@@ below are substituted with .replace (NOT %-formatting -- the CSS owns the % signs).
_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>@@PRODUCT_TITLE@@ - local console</title>
<style>
body{background:#101214;color:#c9d1d9;font:14px/1.45 Consolas,Menlo,monospace;margin:0;padding:1rem}
h1{font-size:15px;letter-spacing:.08em;text-transform:uppercase;color:#8b949e}
h2{font-size:13px;border-bottom:1px solid #30363d;padding-bottom:.25rem;color:#e6edf3}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.25rem}
td,th{border:1px solid #30363d;padding:2px 8px;text-align:left;font-size:12px}
th{color:#8b949e;background:#161b22}
.bar{display:flex;gap:.5rem;align-items:center;margin:.75rem 0 1.25rem;border:1px solid #30363d;padding:.5rem}
input{background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:3px 6px;width:26em}
button{background:#21262d;color:#c9d1d9;border:1px solid #363b42;padding:3px 10px;cursor:pointer}
#state{font-size:12px;color:#8b949e}
.err{color:#f85149}.ok{color:#3fb950}
footer{margin-top:2rem;border-top:1px solid #30363d;padding-top:.5rem;font-size:12px;color:#8b949e}
ul{padding-left:1.2em}li{margin:.15rem 0}
.empty{color:#8b949e;font-style:italic}
tr.lane td{color:#8b949e;background:#0d1117}
tr.lane{cursor:pointer}
tr.lane:hover td{color:#e6edf3}
tr.runrow{cursor:pointer}
tr.runrow:hover td{background:#1b2430;color:#e6edf3}
tr.laneruns td{background:#10161d;padding:.4rem .5rem}
pre{background:#0d1117;border:1px solid #30363d;padding:.5rem;max-width:90ch;
overflow:auto;font-size:11px;white-space:pre-wrap}
tr.sel td{background:#1b2430;color:#e6edf3}
nav.tabs{display:flex;gap:.4rem;margin:.5rem 0 1rem}
label{color:#8b949e;margin-right:.35rem}
p{margin:.3rem 0}
h3{font-size:12px;color:#8b949e;margin:.8rem 0 .2rem}
select{background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:3px 6px}
section section{margin-bottom:1.25rem}
</style>
</head>
<body>
<h1>@@PRODUCT_TITLE@@ &middot; local console</h1>
<div class="bar">
<label for="tok">bearer</label>
<input id="tok" type="password" autocomplete="off" placeholder="value of @@TOKEN_FILE_NAME@@">
<button onclick="connect()">connect</button><span id="state">server-rendered snapshot below;
live polling off until connected</span>
</div>
<nav class="tabs">
<button type="button" onclick="tab('programs')">Programs</button>
<button type="button" onclick="tab('settings')">Settings</button>
</nav>
<main>
<section id="tab-programs">
<section><h2>Start</h2>
<p class="empty">connect a repo &rarr; detect agents &rarr; choose seats &rarr; objective &rarr; Run.
Every step below is an existing governed operation; this panel only sequences them.</p>
<p><label>1. repo path</label><input id="np-project" placeholder="folder holding quaestor.toml/yaml">
<button type="button" onclick="detectInto()">detect</button>
<button type="button" onclick="loadSeats()">load seats</button></p>
<div id="start-detect" class="empty">detection reports non-authoritative facts only.</div>
<h3>2. seats</h3>
<div id="seats"><span class="empty">enter a repo path and click load seats</span></div>
<p><button type="button" onclick="saveSeats()">save seats to manifest</button>
<span class="empty">writes executors.roles into the reviewed manifest; every other line,
comments included, is preserved. OWNER is not assignable and is not shown.</span></p>
<h3>3. objective</h3>
<p><label>title</label><input id="np-title"></p>
<p><label>objective</label><input id="np-objective"></p>
<p><label>acceptance (| separated, optional)</label><input id="np-acceptance"></p>
<p><label>strategist seat</label><select id="np-seatmode"></select>
<label>autonomy</label><select id="np-autonomy"></select></p>
<p><button type="button" onclick="createProgram()">4. create</button>
<button type="button" onclick="startRun()">5. Run</button>
<span class="empty">Run creates the program, applies the seat/autonomy choice, and starts the
tick loop</span></p>
</section>
<section><h2>Programs</h2><div id="programs">@@PROGRAMS_HTML@@</div>
<p class="empty">click a lane (&#8627;) to expand its runs; click a run to open it in the
viewer below</p></section>
<section><h2>Agent turns (program-level)</h2>
<p id="turns-note" class="empty">strategist and planner seats bind to no lane, so the lane
drill-down cannot reach them. Select a program to list its turns.</p>
<div id="turns"></div>
<h3>Turn detail</h3>
<p id="tv-name" class="empty">none selected (click a turn)</p>
<div id="tv-body"><span class="empty">shows the sanitised packet Quaestor sent and what came
back, or the named refusal if the response was rejected</span></div>
</section>
<section><h2>Run viewer</h2>
<p id="rv-name" class="empty">none selected (click a run in an expanded lane)</p>
<div id="rv-body"><span class="empty">shows the run's result, bridge evidence, handoff package
and reported cost-equivalent</span></div>
</section>
<section><h2>Selected program</h2>
<p id="selname" class="empty">none selected (click a program row)</p>
<p><label>serve interval s</label><input id="loop-interval" value="3" size="2"
 autocomplete="off"><button type="button" id="loop-btn" onclick="toggleLoop()">Run</button>
<span id="loop-state" class="empty">idle -- Run loops the tick endpoint; it pauses itself on
WAITING_FOR_STRATEGIST / WAITING_FOR_OWNER or a terminal status</span></p>
<button type="button" onclick="tickSel()">Tick</button>
<button type="button" onclick="cancelSel()">Cancel</button>
<h3>Plan lane</h3>
<p><label>title</label><input id="pl-title"></p>
<p><label>task</label><input id="pl-task"></p>
<p><label>kind</label><select id="pl-kind"></select></p>
<p><label>depends on (comma-separated lane ids, optional)</label><input id="pl-deps"></p>
<button type="button" onclick="planLane()">plan lane</button>
<h3>Reported cost-equivalent</h3>
<div id="sel-cost" class="empty">select a program to load its cost roll-up</div>
<h3>Strategist autonomy</h3>
<p><label>mode</label><select id="au-mode"></select>
<button type="button" onclick="setAutonomy()">set</button>
<span id="au-state" class="empty">select a program to load its autonomy mode</span></p>
<p class="empty">SAFE applies routine answers and asks about everything else; DEFAULT proposes
every directive for one click; AUTO runs unattended. Owner-routed asks escalate to you in
EVERY mode -- a model seat never reaches owner capability.</p>
<h3>Orchestrator relay packet</h3>
<p><button type="button" onclick="copyBriefing()">Copy orchestrator prompt</button>
<button type="button" onclick="showBriefing()">Show</button>
<span class="empty">a self-contained briefing to paste into any outside chat agent (GPT Web,
a colleague's assistant). It carries no token and grants nothing: the agent decides, YOU relay
its directive back through the intervention queue below.</span></p>
<pre id="brief-text" class="empty">select a program, then Copy or Show. The packet is shown here
in full so you can read exactly what you are about to hand over -- and select it by hand if the
browser refuses clipboard access.</pre>
</section>
<section><h2>Intervention queue</h2><div id="queue">@@QUEUE_HTML@@</div></section>
<section><h2>Recent events (counts)</h2><div id="events">@@EVENTS_HTML@@</div>
<h3>Live tail</h3><ul id="evtail" class="empty">connect to stream new events here</ul></section>
</section>
<section id="tab-settings" style="display:none">
<section><h2>Dashboard access</h2>
<p><button type="button" onclick="rotateToken()">Rotate token</button>
<label>one-step URL</label><input id="open-url" readonly autocomplete="off"
 placeholder="rotate to mint a fresh #t= URL">
<button type="button" onclick="copyOpenUrl()">Copy</button></p>
<p class="empty">rotation regenerates web-ui-token (0600) server-side; the URL printed at
startup dies with the old token, and every open tab must reconnect.</p>
</section>
<section><h2>Connect a repository</h2>
<p><label>repo path</label><input id="cn-path" autocomplete="off"
 placeholder="folder holding your project">
<button type="button" onclick="detectRepo()">Detect</button>
<button type="button" onclick="writeManifest()">Write starter manifest</button></p>
<div id="cn-detect" class="empty">detection reports non-authoritative facts only -- git root,
languages, test-command candidates, locally available agents. Nothing is written until you
click Write starter manifest (the same conservative quaestor.yaml `init` writes; authority
stays READ_ONLY until you edit it).</div>
</section>
<section><h2>Execution mode</h2>
<p>current: <span id="mode-now">connect to load</span></p>
<p><label>new value</label><select id="mode-val"></select>
<label>typed confirmation</label><input id="mode-confirm" autocomplete="off"
 placeholder="type the chosen value exactly"></p>
<button type="button" onclick="setMode()">set mode</button>
<p class="empty">writes mode.json through the same transport_mode.write_mode the CLI uses;
an unknown value is refused.</p>
</section>
<section><h2>Deployment readiness</h2>
<div id="readiness"><span class="empty">connect to load</span></div></section>
<section><h2>Handoff health</h2><div id="handoff"><span class="empty">connect to load</span></div></section>
<section><h2>Provider registry (declared facts, honestly labelled)</h2><div id="providers"><span class="empty">connect to load</span></div></section>
<section><h2>Registered adapters</h2><div id="adapters"><span class="empty">connect to load</span></div></section>
<section><h2>Reported cost-equivalent (home-wide)</h2>
<p class="empty">sums of the cost figures executor CLIs reported per run -- recorded verbatim,
NOT interpreted as a billed charge; the auth preflight establishes the billing path.</p>
<div id="homewide-cost"><span class="empty">connect to load</span></div></section>
<section><h2>Browser notifications</h2>
<p><button type="button" id="notify-btn" onclick="toggleNotify()">Enable</button>
<span id="notify-state" class="empty">off -- fires when a program ENTERS
WAITING_FOR_STRATEGIST or WAITING_FOR_OWNER (transitions only; permission-gated by the
browser, preference lives in this tab's session storage)</span></p>
</section>
</section>
</main>
<footer>This page reads and writes locally through governed operations: every write maps 1:1 onto
the same functions the operator CLI invokes (PRD.md §13.1, §13.3) -- the transport invokes
governed ops; it never grants authority, and it never mutates anything beyond them. Owner-only
capabilities (grants, push, destructive) are not exposed here; answering records STRATEGIST
authority only. Loopback only; bearer required everywhere except /health.</footer>
<script>
"use strict";
var SEL="";
var OPEN={};   /* lane_id -> true: lanes whose runs table is expanded */
var RUNSEL=""; /* the run currently shown in the viewer */
var LOOP={timer:null}; /* the serve toggle: a self-rescheduling tick loop */
var LASTSEQ=null;      /* last event seq this tab has seen (delta polling) */
var EVTAIL=[];         /* newest-first capped stream of delta events */
var PAUSE_STATES=@@PAUSE_STATES_JSON@@;
var ALERT_STATES=["WAITING_FOR_STRATEGIST","WAITING_FOR_OWNER"];
var NOTIFY_KEY="qst.web.notify"; /* per-tab preference; the API permission is the browser's */
var PREV_STATUS={};
var LANE_KINDS=@@LANE_KINDS_JSON@@;
/* The product name is SUBSTITUTED, never typed here: branding.py is the one place it
   lives, and a notification title is emitted text like any other. */
var PRODUCT="@@PRODUCT_TITLE@@";
function hdrs(){var t=sessionStorage.getItem("qst.web.token")||"";
  return t?{"Authorization":"Bearer "+t}:{};}
function get(path){return fetch(path,{headers:hdrs()}).then(function(r){
  if(r.status===401){throw new Error("unauthorized");}
  return r.json();});}
/* WRITE HELPER: every POST carries the stored bearer AND the JSON content-type; a non-2k
   answer surfaces its NAMED error into #state instead of dying quietly in a promise. */
function post(path,obj){return fetch(path,{method:"POST",
  headers:(function(){var h={"Content-Type":"application/json"};
    var t=sessionStorage.getItem("qst.web.token")||"";
    if(t)h.Authorization="Bearer "+t;return h;})(),
  body:JSON.stringify(obj||{})}).then(function(r){
    return r.json().then(function(d){
      if(r.status===401){throw new Error("unauthorized");}
      if(!r.ok){throw new Error((d&&(d.error||d.detail))||("HTTP "+r.status));}
      return d;});});}
function cell(row,v){var td=document.createElement("td");td.textContent=v==null?"":String(v);
  row.appendChild(td);return td;}
function table(head){var t=document.createElement("table");var tr=document.createElement("tr");
  head.forEach(function(h){var th=document.createElement("th");th.textContent=h;tr.appendChild(th);});
  t.appendChild(tr);return t;}
function inp(id){var el=document.getElementById(id);return el?el.value.trim():"";}
function say(msg,cls){var s=document.getElementById("state");s.textContent=msg;s.className=cls||"";}
function fail(e){say(e.message==="unauthorized"
  ?"401 - paste the value of @@TOKEN_FILE_NAME@@ and connect":"error: "+e.message,"err");}
function connect(){sessionStorage.setItem("qst.web.token",
  document.getElementById("tok").value.trim());refresh();}
function selectProg(id){setLoop(false);SEL=id;refresh();}
function loopIntervalMs(){var v=parseFloat(inp("loop-interval"));
  return (isFinite(v)&&v>=0.5)?Math.round(v*1000):3000;}
function setLoop(on){
  if(LOOP.timer){clearTimeout(LOOP.timer);LOOP.timer=null;}
  document.getElementById("loop-btn").textContent=on?"Pause":"Run";
  var ls=document.getElementById("loop-state");
  ls.textContent=on?"serving":"idle";
  ls.className=on?"":"empty";}
function toggleLoop(){
  if(LOOP.timer){setLoop(false);say("serve paused","");return;}
  if(!needSel())return;
  setLoop(true);tickOnce();}
function tickOnce(){
  post("/api/program/"+encodeURIComponent(SEL)+"/tick",{}).then(function(){
    return get("/api/programs/"+encodeURIComponent(SEL));}).then(function(v){
    refresh();
    if(PAUSE_STATES.indexOf(v.status||"")>=0){setLoop(false);
      say("serve paused: "+(v.status||""),"err");return;}
    LOOP.timer=setTimeout(tickOnce,loopIntervalMs());})
   .catch(function(e){setLoop(false);fail(e);});}
function toggleLane(lid){if(OPEN[lid])delete OPEN[lid];else OPEN[lid]=true;refresh();}
function selectRun(rid){RUNSEL=rid;renderRun();}
function flag(v){return v?"yes":"-";}
function renderCostInto(el,c){
  el.textContent="";
  if(!c){el.innerHTML='<span class="empty">no cost data</span>';return;}
  var t=table(["reported cost-equivalent","value"]);
  var rows=[["total",c.total],["runs counted",c.runs_counted]];
  Object.keys(c.by_provider||{}).sort().forEach(function(k){
    rows.push(["provider: "+k,c.by_provider[k]]);});
  Object.keys(c.by_role||{}).sort().forEach(function(k){
    rows.push(["role: "+k,c.by_role[k]]);});
  rows.forEach(function(kv){var tr=document.createElement("tr");
    cell(tr,kv[0]);cell(tr,String(kv[1]==null?"":kv[1]));t.appendChild(tr);});
  el.appendChild(t);
  if(c.programs_seen!=null){var pp=document.createElement("p");
    pp.textContent="programs seen: "+c.programs_seen;pp.className="empty";el.appendChild(pp);}
  if(c.truncated){var tp=document.createElement("p");tp.className="empty";
    tp.textContent="scan hit its limit of "+c.scan_limit+" newest handoff packages;"
      +" totals cover the scanned newest runs only";el.appendChild(tp);}
  var lp=document.createElement("p");lp.className="empty";
  lp.textContent=c.label||"";el.appendChild(lp);}
function loadSelCost(){
  var el=document.getElementById("sel-cost");
  if(!SEL){el.textContent="select a program to load its cost roll-up";el.className="empty";return;}
  get("/api/programs/"+encodeURIComponent(SEL)+"/cost")
   .then(function(c){renderCostInto(el,c);}).catch(function(e){
    el.textContent="cost unavailable: "+e.message;el.className="err";});}
function attachRunsRow(t,pid,lid){
  var sub=document.createElement("tr");sub.className="laneruns";
  var td=document.createElement("td");td.colSpan=3;
  td.textContent="runs\\u2026";sub.appendChild(td);t.appendChild(sub);
  get("/api/program/"+encodeURIComponent(pid)+"/lane/"+encodeURIComponent(lid)+"/runs")
   .then(function(d){
    td.textContent="";
    if(!(d.runs||[]).length){td.innerHTML='<span class="empty">no runs bound</span>';return;}
    var rt=table(["run","state","role","valid","evidence","handoff"]);
    d.runs.forEach(function(r){var rr=document.createElement("tr");
      rr.className="runrow";
      rr.onclick=(function(rid){return function(){selectRun(rid);};})(r.run_id);
      if(RUNSEL===r.run_id)rr.className="runrow sel";
      cell(rr,r.run_id);
      cell(rr,(r.execution_state||"")+(r.attempt_absent?" (attempt row absent)":""));
      cell(rr,r.role);
      var o=r.outcome||{};
      cell(rr,o.valid==null?"":String(o.valid)+(o.program_verdict?" / "+o.program_verdict:""));
      cell(rr,flag(r.has_evidence));cell(rr,flag(r.has_handoff));
      rt.appendChild(rr);});
    td.appendChild(rt);
    var rv=d.reviews||[];
    if(rv.length){var p=document.createElement("p");
      p.textContent="reviews: "+rv.map(function(x){
        return x.outcome+" ("+x.kind+")";}).join(", ");
      p.className="empty";td.appendChild(p);}
    var cap=d.context_capsule||{};
    if(cap.capsule_sha256){var cp=document.createElement("p");cp.className="empty";
      cp.textContent="context capsule "+String(cap.capsule_sha256).slice(0,16)+"\\u2026";
      td.appendChild(cp);}
  }).catch(function(e){td.textContent="runs unavailable: "+e.message;td.className="err";});}
function renderRun(){
  var nm=document.getElementById("rv-name"),bd=document.getElementById("rv-body");
  if(!RUNSEL){nm.textContent="none selected (click a run in an expanded lane)";
    nm.className="empty";return;}
  nm.textContent="run "+RUNSEL;nm.className="";
  bd.textContent="loading\\u2026";
  get("/api/run/"+encodeURIComponent(RUNSEL)).then(function(d){
    bd.textContent="";
    var r=d.run||{},o=d.result||{};
    var st=document.createElement("p");
    st.textContent="state: "+(r.execution_state||"?")
      +(o.outcome?" | outcome: "+o.outcome:"")
      +(o.prompt_disposition?" | disposition: "+o.prompt_disposition:"")
      +(o.program_verdict?" | verdict: "+o.program_verdict:"");
    if(o.invalid_reason)st.textContent+=" | invalid: "+o.invalid_reason;
    if(o.summary)st.textContent+=" | "+o.summary;
    bd.appendChild(st);
    var cost=d.cost_usd_reported||{};
    var cl=document.createElement("p");cl.className="empty";
    cl.textContent="cost-equivalent reported: "+(cost.value==null?"none recorded":cost.value)
      +(cost.note?" -- "+cost.note:"");
    bd.appendChild(cl);
    if(d.evidence){var ev=d.evidence;
      var et=table(["evidence","value"]);
      [["verdict",ev.verdict],["probe_ok",flag(ev.probe_ok)],
       ["inspected_count",ev.inspected_count],
       ["observed_change",ev.observed_change==null?"n/a":flag(ev.observed_change)],
       ["reason",ev.reason||""]].forEach(function(kv){
        var tr=document.createElement("tr");cell(tr,kv[0]);cell(tr,String(kv[1]==null?"":kv[1]));
        et.appendChild(tr);});
      bd.appendChild(et);}
    else{var ne=document.createElement("p");ne.className="empty";
      ne.textContent="no bridge evidence recorded for this run";bd.appendChild(ne);}
    if(d.handoff_package){
      var hp=document.createElement("p");hp.textContent="handoff package:";bd.appendChild(hp);
      var pre=document.createElement("pre");
      pre.textContent=JSON.stringify(d.handoff_package,null,2);bd.appendChild(pre);}
    else{var nh=document.createElement("p");nh.className="empty";
      nh.textContent="no handoff package (run did not reach HANDOFF_READY)";bd.appendChild(nh);}
  }).catch(function(e){bd.textContent="run unavailable: "+e.message;bd.className="err";});}
function needSel(){if(!SEL){say("select a program first (click a program row)","err");}return !!SEL;}
function createProgram(){
  var b={title:inp("np-title"),objective:inp("np-objective"),project:inp("np-project")};
  var acc=inp("np-acceptance");if(acc)b.acceptance=acc;
  post("/api/program/create",b).then(function(d){SEL=d.program_id;
    say("created "+d.program_id,"ok");refresh();}).catch(fail);}
function planLane(){
  if(!needSel())return;
  var b={title:inp("pl-title"),task:inp("pl-task"),kind:inp("pl-kind"),depends_on:inp("pl-deps")};
  post("/api/program/"+encodeURIComponent(SEL)+"/plan",b).then(function(d){
    say("planned lane "+d.lane_id,"ok");refresh();}).catch(fail);}
function tickSel(){
  if(!needSel())return;
  post("/api/program/"+encodeURIComponent(SEL)+"/tick",{}).then(function(d){
    say("tick done: status "+(d.status_out||"?"),"ok");refresh();}).catch(fail);}
function cancelSel(){
  if(!needSel())return;
  if(!confirm("Cancel program "+SEL+"? Non-terminal lanes are abandoned."))return;
  var reason=prompt("cancellation reason","cancelled from dashboard");
  if(!reason)return;
  post("/api/program/"+encodeURIComponent(SEL)+"/cancel",{reason:reason}).then(function(d){
    say("cancelled","ok");refresh();}).catch(fail);}
function sendAnswer(pid,mid,tid,rid){
  if(!confirm("Answer "+mid+"? A DIRECTIVE is recorded at STRATEGIST authority."))return;
  post("/api/program/"+encodeURIComponent(pid)+"/answer",
       {message_id:mid,text:inp(tid),rationale:inp(rid)}).then(function(d){
    say("answered "+mid,"ok");refresh();}).catch(fail);}
function setMode(){
  var val=document.getElementById("mode-val").value;
  var typed=inp("mode-confirm");
  if(typed!==val){say("type the mode value ("+val+") exactly to confirm","err");return;}
  post("/api/mode/set",{value:val,confirm:true}).then(function(d){
    document.getElementById("mode-confirm").value="";
    say("mode set: "+d.transport_execution_mode,"ok");refreshSettings();}).catch(fail);}
function rotateToken(){
  if(!confirm("Rotate the dashboard token? Every existing tab (including this one) stops"
    +" working until reconnected with the fresh URL."))return;
  post("/api/token/rotate",{}).then(function(d){
    var m=String(d.open||"").match(/[#&]t=([0-9a-f]{16,})/i);
    document.getElementById("open-url").value=d.open||"";
    if(m){sessionStorage.setItem("qst.web.token",m[1]);
      say("token rotated; this tab reconnected. The old token is dead.","ok");}
    else{sessionStorage.removeItem("qst.web.token");
      say("token rotated -- reconnect with the new URL","err");}
  }).catch(fail);}
function copyOpenUrl(){
  var el=document.getElementById("open-url");
  if(!el.value){say("nothing to copy yet - rotate first","err");return;}
  copyText(el.value,"one-step URL");}
/* CLIPBOARD, WITH AN HONEST FAILURE. 127.0.0.1 is a secure context so the async API is
   normally available; when it is not (or the user denies it) we fall back to a detached
   textarea, and if THAT fails we say so rather than reporting a copy that never happened --
   the packet is rendered in full on the page precisely so a manual selection still works. */
function copyText(text,label){
  var done=function(){say(label+" copied to the clipboard","ok");};
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done,function(){fallbackCopy(text,done);});}
  else{fallbackCopy(text,done);}}
function fallbackCopy(text,done){
  var ta=document.createElement("textarea");ta.value=text;
  ta.setAttribute("readonly","");ta.style.position="fixed";ta.style.opacity="0";
  document.body.appendChild(ta);ta.select();
  try{if(document.execCommand("copy"))done();
    else say("the browser refused the copy -- select the packet below by hand","err");}
  catch(e){say("the browser refused the copy -- select the packet below by hand","err");}
  finally{document.body.removeChild(ta);}}
/* THE RELAY BRIDGE (ru1.14). Fetched ON DEMAND, never on the 5s refresh: assembling a packet
   for every program every tick would burn the store for a document nobody asked to see. */
function renderBriefing(d){
  var el=document.getElementById("brief-text");
  el.textContent=d.prompt||"";el.className="";
  var c=d.classification||{};
  if(d.vacuous){say("that program has no recorded state -- the packet says so","err");return;}
  if(c.modified){say("packet assembled and sanitised: "+c.secrets_removed
    +" credential-shaped and "+c.paths_removed+" host-path-shaped span(s) withheld","");return;}
  say("relay packet assembled for "+d.program_id,"ok");}
/* AUTONOMY (EPIC P6): per-program, because core reads it during a tick and a deployment-wide
   file would have to be handed down through a transport -- the one import edge core forbids. */
function loadAutonomy(){
  if(!SEL){return;}
  get("/api/program/"+encodeURIComponent(SEL)+"/autonomy-state").then(function(a){
    var sel=document.getElementById("au-mode");
    if(!sel.options.length){
      (a.known_modes||[]).forEach(function(k){var o=document.createElement("option");
        o.value=k;o.textContent=k;sel.appendChild(o);});}
    sel.value=a.autonomy_mode;
    var st=document.getElementById("au-state");st.className="";
    var bits=[a.autonomy_mode+(a.explicit?"":" (unset, falling back)")];
    bits.push(a.strategist_seat?"model seat ON":"human seat");
    if(a.pending_directives)bits.push(a.pending_directives+" awaiting approval");
    if(a.consecutive_refusals)bits.push(a.consecutive_refusals+"/"+a.halt_after+" refusals");
    st.textContent=bits.join(" - ");}).catch(fail);}
function setAutonomy(){
  if(!needSel())return;
  var v=document.getElementById("au-mode").value;
  post("/api/program/"+encodeURIComponent(SEL)+"/autonomy",{value:v}).then(function(d){
    say("autonomy for "+d.program_id+": "+d.autonomy_mode,"ok");loadAutonomy();}).catch(fail);}
function approveDirective(pid,mid){
  post("/api/program/"+encodeURIComponent(pid)+"/approve",{message_id:mid})
    .then(function(d){say("directive applied ("+d.remaining+" still queued)","ok");
      refresh();}).catch(fail);}
function discardDirective(pid,mid){
  post("/api/program/"+encodeURIComponent(pid)+"/discard",{message_id:mid})
    .then(function(d){say("directive discarded; the question is still open","");
      refresh();}).catch(fail);}
/* THE COCKPIT (EPIC P6). Program-level turns, seat assignment, readiness, and a start flow
   that only sequences operations that already exist -- no new governed op, which is what keeps
   this a cockpit rather than a second control plane. */
var SEATS=null, TURNSEL="";
function renderSeats(d){
  SEATS=d;
  var el=document.getElementById("seats");el.textContent="";
  if(!d.seats||!d.seats.length){el.innerHTML='<span class="empty">no seats</span>';return;}
  var t=table(["seat","pinned","resolves to","status"]);
  d.seats.forEach(function(s){
    var tr=document.createElement("tr");
    cell(tr,s.role);
    var td=document.createElement("td");
    var sel=document.createElement("select");sel.id="seat-"+s.role;
    var none=document.createElement("option");none.value="";none.textContent="(default)";
    sel.appendChild(none);
    (d.candidates||[]).forEach(function(c){
      /* A seat that touches a repository cannot be filled by a transport. Offering the choice
         and refusing it afterwards would be a worse UI than not offering it. */
      if((s.role==="implementation"||s.role==="integration")&&!c.write_capable)return;
      var o=document.createElement("option");o.value=c.kind;
      o.textContent=c.kind+" ("+(c.provider_family||"gateway")+", "+c.fact_status+")";
      sel.appendChild(o);});
    /* A GATEWAY PIN IS NOT A REGISTRY KEY. "openrouter:google/gemini-2.5-pro" names a model,
       and the options above are bare kinds, so assigning it silently leaves the select on ""
       -- the seat then drops out of the POST and the operator's pin is invisible. Carry the
       actual pin as its own option so what is configured is what is shown. */
    if(s.pinned&&!Array.prototype.some.call(sel.options,
        function(o){return o.value===s.pinned;})){
      var pin=document.createElement("option");pin.value=s.pinned;
      pin.textContent=s.pinned+" (configured)";
      sel.insertBefore(pin,sel.options[1]||null);}
    sel.value=s.pinned||"";
    td.appendChild(sel);tr.appendChild(td);
    cell(tr,s.resolves_to||"-");
    cell(tr,s.refusal?("REFUSED: "+s.refusal):"ok");
    if(s.refusal)tr.className="sel";
    t.appendChild(tr);});
  el.appendChild(t);
  var n=document.createElement("p");n.className="empty";n.textContent=d.owner_note;
  el.appendChild(n);}
function loadSeats(){
  var p=inp("np-project");
  if(!p){say("enter a repo path first","err");return;}
  get("/api/seats?path="+encodeURIComponent(p)).then(function(d){
    renderSeats(d);say("seats loaded from "+(d.manifest||"(no manifest)"),"ok");}).catch(fail);}
function saveSeats(){
  var p=inp("np-project");
  if(!p||!SEATS){say("load seats first","err");return;}
  var roles={};
  (SEATS.seats||[]).forEach(function(s){
    var el=document.getElementById("seat-"+s.role);
    if(el&&el.value)roles[s.role]=el.value;});
  post("/api/seats/set",{path:p,roles:roles}).then(function(d){
    say("seats written to "+d.manifest,"ok");loadSeats();}).catch(fail);}
function detectInto(){
  var p=inp("np-project");
  if(!p){say("enter a repo path first","err");return;}
  get("/api/connect/detect?path="+encodeURIComponent(p)).then(function(d){
    var el=document.getElementById("start-detect");el.textContent="";el.className="";
    if(!d.ok){el.textContent="detection: "+(d.reason||"failed");el.className="err";return;}
    var ul=document.createElement("ul");
    var add=function(t){var li=document.createElement("li");li.textContent=t;
      ul.appendChild(li);};
    add("git root: "+(d.git_root||"none"));
    (d.languages||[]).forEach(function(l){add("language: "+l.language);});
    (d.available_agents||[]).forEach(function(a){add("agent: "+a.agent+" ("+a.evidence+")");});
    el.appendChild(ul);say("detected "+d.path,"ok");}).catch(fail);}
function startRun(){
  if(!SEL){say("create the program first (step 4), then Run","err");return;}
  var mode=document.getElementById("np-autonomy").value;
  post("/api/program/"+encodeURIComponent(SEL)+"/autonomy",{value:mode}).then(function(){
    setLoop(true);say("running "+SEL+" at autonomy "+mode,"ok");}).catch(fail);}
function renderTurns(d){
  var el=document.getElementById("turns");el.textContent="";
  document.getElementById("turns-note").textContent=
    d.count?(d.count+" program-level turn(s)"+(d.truncated?" (truncated)":"")):d.note;
  if(!d.turns||!d.turns.length)return;
  var t=table(["role","provider","state","outcome","run"]);
  d.turns.forEach(function(tn){
    var tr=document.createElement("tr");tr.className="runrow";
    if(TURNSEL===tn.run_id)tr.className="runrow sel";
    cell(tr,tn.role||"-");cell(tr,tn.provider||"-");cell(tr,tn.execution_state);
    cell(tr,(tn.result&&tn.result.outcome)||"-");cell(tr,tn.run_id);
    tr.onclick=(function(r){return function(){TURNSEL=r;selectRun(r);renderTurnDetail(d);};})
      (tn.run_id);
    t.appendChild(tr);});
  el.appendChild(t);}
function renderTurnDetail(d){
  var hit=(d.turns||[]).filter(function(x){return x.run_id===TURNSEL;})[0];
  var name=document.getElementById("tv-name");
  var body=document.getElementById("tv-body");body.textContent="";
  if(!hit){name.textContent="none selected";name.className="empty";return;}
  name.textContent=hit.role+" via "+hit.provider+" ("+hit.run_id+")";name.className="";
  var t=table(["field","value"]);
  var add=function(k,v){var tr=document.createElement("tr");cell(tr,k);cell(tr,v);
    t.appendChild(tr);};
  add("authority", hit.authority_profile);
  add("session", hit.session_id||"(none)");
  add("provider source", hit.provider_source);
  add("valid", hit.result?flag(hit.result.valid):"-");
  add("outcome", (hit.result||{}).outcome||"-");
  /* A REFUSED response is the case an operator most needs to see: the seat answered, and the
     answer was rejected by deterministic admission. */
  add("refusal", (hit.result||{}).invalid_reason||"-");
  add("summary", (hit.result||{}).summary||"-");
  body.appendChild(t);
  var n=document.createElement("p");n.className="empty";
  n.textContent="the full prompt and evidence for this run are in the Run viewer below";
  body.appendChild(n);}
function loadTurns(){
  if(!SEL)return;
  get("/api/program/"+encodeURIComponent(SEL)+"/turns").then(function(d){
    renderTurns(d);if(TURNSEL)renderTurnDetail(d);}).catch(fail);}
function renderReadiness(d){
  var el=document.getElementById("readiness");el.textContent="";
  var t=table(["check","state"]);
  var add=function(k,v){var tr=document.createElement("tr");cell(tr,k);cell(tr,v);
    t.appendChild(tr);};
  add("execution mode", d.execution_mode.value+" -- "+d.execution_mode.consequence);
  add("connected repositories", (d.connected_repositories||[]).join(", ")||"none");
  add("ready", d.ready?"yes":"no");
  el.appendChild(t);
  var n=document.createElement("p");n.className="empty";n.textContent=d.autonomy_note;
  el.appendChild(n);
  var n2=document.createElement("p");n2.className="empty";n2.textContent=d.note;
  el.appendChild(n2);}
function briefingFor(pid){
  return get("/api/program/"+encodeURIComponent(pid)+"/briefing");}
function copyBriefing(){
  if(!needSel())return;
  briefingFor(SEL).then(function(d){renderBriefing(d);
    copyText(d.prompt||"","orchestrator prompt");}).catch(fail);}
function showBriefing(){
  if(!needSel())return;
  briefingFor(SEL).then(renderBriefing).catch(fail);}
function copyDirective(pid,mid){
  briefingFor(pid).then(function(d){
    var hit=(d.directives||[]).filter(function(x){return x.message_id===mid;})[0];
    if(!hit){say(d.directives_truncated
      ?("more than "+d.directives_limit+" questions are open; only the first "+d.directives_limit
        +" carry a pre-built packet -- copy the whole orchestrator prompt instead")
      :"no directive packet for that item: it is not an open question a strategist"
       +" answers with one directive","err");return;}
    var el=document.getElementById("brief-text");
    el.textContent=hit.prompt;el.className="";
    copyText(hit.prompt,"directive request");}).catch(fail);}
function renderDetect(d){
  var el=document.getElementById("cn-detect");el.textContent="";el.className="";
  if(!d.ok){el.textContent="detection: "+(d.reason||"failed")
    +(d.detail?" -- "+d.detail:"");el.className="err";return;}
  var ul=document.createElement("ul");
  var add=function(t){var li=document.createElement("li");li.textContent=t;ul.appendChild(li);};
  add("git root: "+(d.git_root||"none"));
  (d.languages||[]).forEach(function(l){
    add("language: "+l.language+" ("+l.markers.join(", ")+")");});
  (d.test_command_candidates||[]).forEach(function(tc){
    add("test candidates ["+tc.language+"]: "+tc.candidates.join(" | "));});
  (d.available_agents||[]).forEach(function(a){add("agent: "+a.agent+" ("+a.evidence+")");});
  (d.transcript_locations||[]).forEach(function(t){
    if(t.exists)add("transcripts: "+t.kind+" at "+t.path);});
  var note=document.createElement("li");note.className="empty";
  note.textContent=d.authority.note+" (authority default: "
    +((d.authority||{}).default||"READ_ONLY")+")";ul.appendChild(note);
  el.appendChild(ul);
  document.getElementById("np-project").value=d.path;
  say("detected "+d.path,"ok");}
function detectRepo(){
  var p=inp("cn-path");
  if(!p){say("enter a repository path first","err");return;}
  get("/api/connect/detect?path="+encodeURIComponent(p)).then(renderDetect).catch(fail);}
function writeManifest(){
  var p=inp("cn-path");
  if(!p){say("enter a repository path first","err");return;}
  post("/api/connect/manifest",{path:p}).then(function(d){
    var el=document.getElementById("cn-detect");el.textContent="";el.className="";
    if(!d.ok){el.textContent="manifest not written: "+(d.reason||"?")
      +(d.detail?" -- "+d.detail:"");el.className="err";
      if(d.reason==="ALREADY_CONFIGURED")say("already configured -- review the existing"
        +" manifest","");return;}
    var s=document.createElement("p");
    s.textContent="starter manifest written: "+((d.manifest||{}).manifest||"quaestor.yaml");
    el.appendChild(s);
    var n=document.createElement("p");n.className="empty";
    n.textContent="review it (authority, executor, security.protected_roots), then create"
      +" programs against this path -- it is pre-filled in New program.";
    el.appendChild(n);
    document.getElementById("np-project").value=d.path;
    say("connected "+d.path,"ok");}).catch(fail);}
function tab(name){
  document.getElementById("tab-programs").style.display=(name==="programs")?"":"none";
  document.getElementById("tab-settings").style.display=(name==="settings")?"":"none";
  if(name==="settings")refreshSettings();}
function refreshSettings(){
  get("/api/mode").then(function(m){
    document.getElementById("mode-now").textContent=
      m.transport_execution_mode+" (source: "+((m.record||{}).source||"")+")";
    var sel=document.getElementById("mode-val");sel.textContent="";
    (m.known_modes||[]).forEach(function(k){var o=document.createElement("option");
      o.value=k;o.textContent=k;sel.appendChild(o);});
    return get("/api/settings");}).then(function(s){
    var hh=document.getElementById("handoff");hh.textContent="";
    var t1=table(["metric","value"]);
    Object.keys(s.handoff_health||{}).sort().forEach(function(k){
      var tr=document.createElement("tr");cell(tr,k);cell(tr,String(s.handoff_health[k]));
      t1.appendChild(tr);});
    hh.appendChild(t1);
    var pv=document.getElementById("providers");pv.textContent="";
    var t2=table(["kind","family","fact_status","credential mode"]);
    (s.providers||[]).forEach(function(p){var tr=document.createElement("tr");
      cell(tr,p.kind);cell(tr,p.provider_family);cell(tr,p.fact_status);
      cell(tr,(p.credential_mode||[]).join(" | "));t2.appendChild(tr);});
    pv.appendChild(t2);
    var ad=document.getElementById("adapters");ad.textContent="";
    var t3=table(["adapter","class","capabilities"]);
    (s.adapters||[]).forEach(function(a){var tr=document.createElement("tr");
      cell(tr,a.adapter);cell(tr,a["class"]);cell(tr,(a.capabilities||[]).join(", "));
      t3.appendChild(tr);});
    ad.appendChild(t3);
    renderCostInto(document.getElementById("homewide-cost"),s.cost_summary);
    return get("/api/readiness");}).then(renderReadiness).catch(fail);}
function answerForm(it){
  var wrap=document.createElement("div");
  /* A PENDING DIRECTIVE is not a question to answer -- it is a proposed answer to review. */
  if(it.kind==="DIRECTIVE_PENDING_APPROVAL"){
    var ap=document.createElement("button");ap.type="button";ap.textContent="approve";
    ap.onclick=function(){approveDirective(it.program_id,it.message_id);};
    var di=document.createElement("button");di.type="button";di.textContent="discard";
    di.onclick=function(){discardDirective(it.program_id,it.message_id);};
    wrap.appendChild(ap);wrap.appendChild(di);
    return wrap;}
  var ti=document.createElement("input");ti.id="ans-"+it.message_id;
  ti.placeholder="directive text";ti.autocomplete="off";
  var ra=document.createElement("input");ra.id="rat-"+it.message_id;
  ra.placeholder="rationale (optional)";ra.autocomplete="off";
  var bt=document.createElement("button");bt.type="button";bt.textContent="answer";
  bt.onclick=function(){sendAnswer(it.program_id,it.message_id,ti.id,ra.id);};
  wrap.appendChild(ti);wrap.appendChild(ra);wrap.appendChild(bt);
  /* Only items that ARE an open question have a directive packet. LANE_FAILED and
     INTEGRATION_CONFLICT reach this queue without one, and offering a button that could only
     answer "no such directive" would be worse than not offering it. */
  if(it.message_id){var cp=document.createElement("button");cp.type="button";
    cp.textContent="copy directive prompt";
    cp.onclick=function(){copyDirective(it.program_id,it.message_id);};
    wrap.appendChild(cp);}
  return wrap;}
function refresh(){
 var items=[];
 get("/api/programs").then(function(d){
   var progs=d.programs||[];
   var el=document.getElementById("programs");el.textContent="";
   var sn=document.getElementById("selname");
   sn.textContent=SEL?("selected: "+SEL):"none selected (click a program row)";
   sn.className=SEL?"":"empty";
   var t=null;if(progs.length){t=table(["program","title","status"]);}
   var seq=Promise.resolve();
   progs.forEach(function(p){seq=seq.then(function(){
     maybeAlert(p);
     var tr=document.createElement("tr");
     if(SEL===p.program_id)tr.className="sel";
     tr.onclick=(function(pid){return function(){selectProg(pid);};})(p.program_id);
     cell(tr,p.program_id);cell(tr,p.title);cell(tr,p.status);t.appendChild(tr);
     return Promise.all([
       get("/api/programs/"+encodeURIComponent(p.program_id)),
       get("/api/programs/"+encodeURIComponent(p.program_id)+"/inbox")
     ]).then(function(rs){
        (rs[0].lanes||[]).forEach(function(l){var lr=document.createElement("tr");
          lr.className="lane";
          cell(lr,"\\u21b3 "+(l.title||l.lane_id));cell(lr,l.state+" ("+l.kind+")");
          cell(lr,l.verdict);
          lr.onclick=(function(lid){return function(){toggleLane(lid);};})(l.lane_id);
          t.appendChild(lr);
          if(OPEN[l.lane_id])attachRunsRow(t,p.program_id,l.lane_id);});
       (rs[1].items||[]).forEach(function(it){it.program_id=p.program_id;items.push(it);});});});});
   return seq.then(function(){
     if(t)el.appendChild(t);
     if(d.truncated){var n=document.createElement("p");n.className="empty";
       n.textContent="showing "+d.count+" of "+d.total+" programs";el.appendChild(n);}
     var q=document.getElementById("queue");q.textContent="";
     if(!items.length){q.innerHTML='<span class="empty">nothing needs attention</span>';}
     else{var u=document.createElement("ul");items.forEach(function(it){
       var li=document.createElement("li");
       var head=document.createElement("div");
       head.textContent="["+it.route+"] "+it.kind+" - "+it.payload+" ("+it.program_id+")";
       li.appendChild(head);li.appendChild(answerForm(it));u.appendChild(li);});q.appendChild(u);}});
 }).then(function(){
   /* LIVE TAIL ORDERING MATTERS: the delta poll runs BEFORE the summary fetch advances
      anything, and LASTSEQ advances only from the DELTA's own now_seq -- otherwise events
      landing between the two calls would be silently skipped. */
   var pending=(LASTSEQ==null)?Promise.resolve(null)
     :get("/api/events?since="+LASTSEQ).catch(function(){return null;});
   return pending.then(function(delta){
     return get("/api/events").then(function(ev){
       var el=document.getElementById("events");el.textContent="";
       var t=table(["event type","count"]);(ev.by_type||[]).forEach(function(r){
         var tr=document.createElement("tr");cell(tr,r.event_type);cell(tr,r.count);
         t.appendChild(tr);});
       el.appendChild(t);
       var p=document.createElement("p");p.className="empty";
       p.textContent="total events: "+ev.total_events;p.id="evtotal";el.appendChild(p);
       if(delta&&delta.delta){ingestDelta(delta);}
       else{LASTSEQ=(typeof ev.now_seq==="number")?ev.now_seq:LASTSEQ;
         var ul=document.getElementById("evtail");ul.textContent="";
         ul.innerHTML='<span class="empty">streaming from event #'+LASTSEQ+"</span>";}
     });});})
 .then(function(){
   if(RUNSEL)renderRun();
   loadSelCost();
   loadAutonomy();
   loadTurns();
   say("live @ "+new Date().toLocaleTimeString(),"ok");
 }).catch(fail);
}
function ingestDelta(d){
  EVTAIL=d.events.concat(EVTAIL).slice(0,30);
  LASTSEQ=d.now_seq;
  var ul=document.getElementById("evtail");ul.textContent="";ul.className="";
  if(!EVTAIL.length){ul.innerHTML='<span class="empty">no new events</span>';return;}
  if(d.truncated){var gap=document.createElement("li");gap.className="empty";
    gap.textContent="\\u2026newer events beyond the "+d.delta_limit+"-event poll limit"
      +" were skipped";ul.appendChild(gap);}
  EVTAIL.forEach(function(e){var li=document.createElement("li");
    li.textContent="#"+e.seq+" "+e.event_type;ul.appendChild(li);});}
function notifyOn(){return sessionStorage.getItem(NOTIFY_KEY)==="1";}
function setNotifyUI(){
  document.getElementById("notify-btn").textContent=notifyOn()?"Disable":"Enable";
  var st=document.getElementById("notify-state");
  st.textContent=notifyOn()?"on -- alerts on strategist/owner transitions":"off";
  st.className=notifyOn()?"":"empty";}
function toggleNotify(){
  if(notifyOn()){sessionStorage.removeItem(NOTIFY_KEY);setNotifyUI();return;}
  if(typeof Notification==="undefined"){
    say("this browser has no Notification API","err");return;}
  var arm=function(){sessionStorage.setItem(NOTIFY_KEY,"1");setNotifyUI();
    say("browser notifications armed","ok");};
  if(Notification.permission==="granted"){arm();return;}
  Notification.requestPermission().then(function(p){
    if(p!=="granted"){say("notification permission refused by the browser","err");return;}
    arm();}).catch(fail);}
function maybeAlert(p){
  /* TRANSITIONS ONLY: a program already sitting in WAITING_FOR_STRATEGIST when this tab first
     sees it is not news; the CHANGE is. First sighting seeds PREV_STATUS silently. */
  var st=p.status||"",prev=PREV_STATUS[p.program_id];
  PREV_STATUS[p.program_id]=st;
  if(prev===null||prev===undefined||prev===st)return;
  if(ALERT_STATES.indexOf(st)<0)return;
  if(!notifyOn()||typeof Notification==="undefined"
    ||Notification.permission!=="granted")return;
  try{new Notification(PRODUCT+": input needed",{body:(p.title||p.program_id)
    +" entered "+st+" and needs a strategist"});}catch(e){}}
(function(){var s=document.getElementById("pl-kind");
  LANE_KINDS.forEach(function(k){var o=document.createElement("option");
    o.value=k;o.textContent=k;s.appendChild(o);});
  var sm=document.getElementById("np-seatmode");
  [["","human strategist (default)"],["strategist_seat","model holds the seat"]]
    .forEach(function(p){var o=document.createElement("option");
      o.value=p[0];o.textContent=p[1];sm.appendChild(o);});
  var au=document.getElementById("np-autonomy");
  ["SAFE","DEFAULT","AUTO"].forEach(function(k){var o=document.createElement("option");
    o.value=k;o.textContent=k;au.appendChild(o);});
  au.value="DEFAULT";})();
setInterval(function(){if(sessionStorage.getItem("qst.web.token"))refresh();},5000);
/* ONE-STEP BOOTSTRAP: the server console prints a URL ending in #t=<hex>.
   The fragment never reaches the server (browsers strip it before sending), so it
   cannot leak into logs; it only ever traveled inside this machine's own console.
   Capture it, persist for the session, clean the address bar, and connect. */
(function(){var m=location.hash.match(/[#&]t=([0-9a-f]{16,})/i);
  if(m){sessionStorage.setItem("qst.web.token",m[1]);
    history.replaceState(null,"",location.pathname+location.search);}
  setNotifyUI();
  if(sessionStorage.getItem("qst.web.token")){refresh();}
  else{document.getElementById("tok").focus();}})();
</script>
</body>
</html>
"""


def _esc(value) -> str:
    return html_mod.escape(str(value if value is not None else ""), quote=True)


def _lane_kinds_json() -> str:
    """The governed lane vocabulary for the plan form's <select>. Read-only; lazy import.

    Sourced from orch.LANE_KINDS rather than retyped: a kind the core adds must appear here
    without this file being edited, or the form would silently refuse legal plans.
    """
    from quaestor.core import orchestrator as orch
    return json.dumps(list(orch.LANE_KINDS))


def _pause_states_json() -> str:
    """The program statuses at which the serve loop stops itself (ru1.9). Read-only.

    Also sourced from core, not retyped: both waiting-for-a-human states (the loop cannot make
    progress without one) and every terminal status. A new terminal status in core must pause
    the loop without this file being edited.
    """
    from quaestor.core import orchestrator as orch
    states = [orch.PROGRAM_WAITING_STRATEGIST, orch.PROGRAM_WAITING_OWNER,
              orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
              orch.PROGRAM_CANCELLED]
    for s in states:
        assert s in (orch.PROGRAM_DRAFT, orch.PROGRAM_PLANNED, orch.PROGRAM_RUNNING,
                     orch.PROGRAM_WAITING_STRATEGIST, orch.PROGRAM_WAITING_OWNER,
                     orch.PROGRAM_CANDIDATE_PASS, orch.PROGRAM_CANDIDATE_FAIL,
                     orch.PROGRAM_CANCELLED), "stale pause vocabulary: %s" % s
    return json.dumps(states)


def render_page(home: str) -> str:
    """The server-rendered snapshot: same payloads the JSON API serves, escaped for HTML.

    Server-rendering matters for correctness, not nostalgia -- the page must show real state even
    where JavaScript does not run, and the control suite asserts the seeded program title appears
    in the served document itself.
    """
    prog_rows = []
    queue_rows = []
    try:
        progs = programs_payload(home)
        for p in progs["programs"]:
            prog_rows.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                             % (_esc(p["program_id"]), _esc(p["title"]), _esc(p["status"])))
            # The per-program lanes table comes from the SAME status_view the detail route serves.
            view = status_payload(home, p["program_id"]) or {}
            for l in view.get("lanes", []):
                prog_rows.append("<tr class='lane'><td>&#8627; %s</td><td>%s (%s)</td><td>%s</td></tr>"
                                 % (_esc(l.get("title") or l.get("lane_id")), _esc(l.get("state")),
                                    _esc(l.get("kind")), _esc(l.get("verdict"))))
            ib = inbox_payload(home, p["program_id"]) or {}
            for it in ib.get("items", []):
                queue_rows.append("<li>[%s] %s - %s (%s)</li>"
                                  % (_esc(it.get("route")), _esc(it.get("kind")),
                                     _esc(it.get("payload")), _esc(p["program_id"])))
        ev = events_payload(home)
        ev_rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (_esc(r["event_type"]), r["count"])
                          for r in ev["by_type"])
        ev_total = ev["total_events"]
    except Exception as exc:  # noqa: BLE001 - a broken store renders an honest error, not a 500
        prog_rows = ["<tr><td colspan='3' class='err'>state unreadable: %s</td></tr>"
                     % _esc(type(exc).__name__)]
        queue_rows = []
        ev_rows = ""
        ev_total = 0
    programs_html = ("<table><tr><th>program</th><th>title</th><th>status</th></tr>%s</table>"
                     % "".join(prog_rows)) if prog_rows else "<span class='empty'>no programs</span>"
    queue_html = ("<ul>%s</ul>" % "".join(queue_rows)) if queue_rows \
        else "<span class='empty'>nothing needs attention</span>"
    events_html = ("<table><tr><th>event type</th><th>count</th></tr>%s</table>"
                   "<p class='empty'>total events: %s</p>" % (ev_rows, ev_total)) if ev_rows \
        else "<span class='empty'>no events recorded</span>"
    return (_PAGE_TEMPLATE
            .replace("@@PRODUCT_TITLE@@", branding.PRODUCT_TITLE)
            .replace("@@TOKEN_FILE_NAME@@", TOKEN_FILE)
            .replace("@@PROGRAMS_HTML@@", programs_html)
            .replace("@@QUEUE_HTML@@", queue_html)
            .replace("@@EVENTS_HTML@@", events_html)
            .replace("@@LANE_KINDS_JSON@@", _lane_kinds_json())
            .replace("@@PAUSE_STATES_JSON@@", _pause_states_json()))


# ---------------------------------------------------------------------------------------------
# the httpd
# ---------------------------------------------------------------------------------------------
def build_webui_server(home: str, *, port: int = 0, token_file: str | None = None):
    """A loopback-bound, bearer-enforced dashboard server: GET reads, POST governed writes.
    Returns (httpd, bound_port). Impure.

    NOTE THE ABSENT PARAMETER: there is no ``host``. Loopback-only is enforced by construction,
    not by validation (see module docstring; precedent mcp.server.LOOPBACK_ONLY).
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    tf = resolve_token_file(home, token_file)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "%s-webui/%s" % (branding.PRODUCT_NAME, branding.PRODUCT_VERSION)

        def log_message(self, fmt, *a):     # noqa: A003 - the default logger spams stderr
            pass

        # -- plumbing ---------------------------------------------------------------------------
        def _headers_common(self, extra) -> None:
            # ON EVERY RESPONSE, success or refusal: no caching of state that changes underneath
            # you, and no MIME sniffing of anything we serve.
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)

        def _send_json(self, code: int, obj, extra=None) -> None:
            raw = json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")
            if len(raw) > MAX_RESPONSE_BYTES:
                # LOUD, not silently truncated: a read-only view that exceeds its bound is a bug
                # worth surfacing, and a bounded envelope error is itself small by construction.
                raw = json.dumps({"error": "RESPONSE_BOUND_EXCEEDED",
                                  "bound_bytes": MAX_RESPONSE_BYTES,
                                  "route": "bounded before send",
                                  "instrument": WEBUI_INSTRUMENT},
                                 sort_keys=True).encode("utf-8")
                code = 500
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self._headers_common(extra)
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, code: int, text: str) -> None:
            raw = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self._headers_common({})
            self.end_headers()
            self.wfile.write(raw)

        def _refuse_auth(self) -> None:
            # ONE refusal for absent, malformed and wrong. No difference between them: that
            # difference is an oracle (transports.mcp.auth discipline).
            self._send_json(401, {"error": REFUSAL, "instrument": WEBUI_INSTRUMENT},
                            {"WWW-Authenticate": "Bearer"})

        def _bearer(self) -> str:
            for k, v in self.headers.items():
                if str(k).lower() == "authorization":
                    raw = str(v or "")
                    return raw[7:].strip() if raw[:7].lower() == "bearer " else ""
            return ""

        def _authorized(self) -> bool:
            return tokens_match(self._bearer(), load_token(tf))

        # -- verbs ------------------------------------------------------------------------------
        def do_GET(self):                    # noqa: N802
            path = self.path.split("?", 1)[0]
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/") or "/"
            if path == "/health":
                # Unauthenticated, and therefore carrying NOTHING but liveness -- the same rule
                # as the MCP /healthz, which once leaked version banners to callers who had
                # proved nothing.
                return self._send_json(200, {"status": "ok"})
            # AUTHENTICATE BEFORE ANYTHING ELSE: before stores open, before routes resolve. An
            # unauthenticated caller must not learn which routes exist (precedent: authenticate
            # before any orchestrator invocation).
            #
            # BROWSER NAVIGATION EXCEPTION: a human typing/refreshing a URL (Accept includes
            # text/html, path outside /api/) gets the CONNECT PAGE with 200 instead of a raw
            # 401 JSON corpse -- found live when a refresh on a deep link met the bare refusal.
            # The page is data-free (name + paste field only), so serving it early leaks
            # nothing. /api/* stays machine-strict: 401 JSON always.
            accepts_html = "text/html" in str(self.headers.get("Accept") or "")
            if not self._authorized():
                if accepts_html and not path.startswith("/api/"):
                    return self._send_html(200, render_page(home))
                return self._refuse_auth()

            if path == "/":
                return self._send_html(200, render_page(home))
            if path == "/api/programs":
                return self._send_json(200, programs_payload(home))
            if path == "/api/events":
                raw_since = _query_param(self.path, "since")
                if raw_since is None:
                    return self._send_json(200, events_payload(home))
                try:
                    since = int(raw_since)
                except ValueError:
                    since = -1
                if since < 0:
                    return self._send_json(400, {"error": "BAD_SINCE",
                                                 "detail": "since must be a non-negative integer"
                                                           " event seq",
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, events_payload(home, since=since))
            parts = [p for p in path.split("/") if p]
            # WRITE-ONLY NAMESPACES UNDER GET -> 405 with Allow: POST. Answered AFTER auth like
            # every route decision, so the write-route map is not advertised to whoever knocks.
            if is_write_route(path):
                return self._send_json(405, {"error": "METHOD_NOT_ALLOWED",
                                             "detail": "this route answers POST only",
                                             "instrument": WEBUI_INSTRUMENT},
                                        {"Allow": "POST"})
            if path == "/api/mode":
                return self._send_json(200, mode_payload(home))
            if path == "/api/settings":
                return self._send_json(200, settings_payload(home))
            if path == "/api/seats":
                return self._send_json(200, seats_payload(
                    (_query_param(self.path, "path") or "").strip()))
            if path == "/api/readiness":
                return self._send_json(200, readiness_payload(
                    home, (_query_param(self.path, "path") or "").strip()))
            if path == "/api/connect/detect":
                target = _query_param(self.path, "path")
                if not target or not target.strip():
                    return self._send_json(400, {"error": "FIELD_REQUIRED", "field": "path",
                                                 "detail": "a repository path is required",
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, connect_detect_payload(target.strip()))
            if len(parts) >= 3 and parts[0] == "api" and parts[1] == "programs":
                pid = parts[2]
                if not _looks_like_id(pid):
                    return self._send_json(400, {"error": "BAD_PROGRAM_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                if len(parts) == 3:
                    view = status_payload(home, pid)
                    if view is None:
                        return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                     "program_id": pid,
                                                     "instrument": WEBUI_INSTRUMENT})
                    return self._send_json(200, view)
                if len(parts) == 4 and parts[3] == "inbox":
                    ib = inbox_payload(home, pid)
                    if ib is None:
                        return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                     "program_id": pid,
                                                     "instrument": WEBUI_INSTRUMENT})
                    return self._send_json(200, ib)
                if len(parts) == 4 and parts[3] == "lanes":
                    lv = lanes_payload(home, pid)
                    if lv is None:
                        return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                     "program_id": pid,
                                                     "instrument": WEBUI_INSTRUMENT})
                    return self._send_json(200, lv)
                if len(parts) == 4 and parts[3] == "cost":
                    cp = program_cost_payload(home, pid)
                    if cp is None:
                        return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                     "program_id": pid,
                                                     "instrument": WEBUI_INSTRUMENT})
                    return self._send_json(200, cp)
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
                    and parts[3] == "turns":
                pid = parts[2]
                if not _looks_like_id(pid):
                    return self._send_json(400, {"error": "BAD_PROGRAM_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                tp = program_turns_payload(home, pid)
                if tp is None:
                    return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                 "program_id": pid,
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, tp)
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
                    and parts[3] == "autonomy-state":
                pid = parts[2]
                if not _looks_like_id(pid):
                    return self._send_json(400, {"error": "BAD_PROGRAM_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                ap = autonomy_payload(home, pid)
                if ap is None:
                    return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                 "program_id": pid,
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, ap)
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
                    and parts[3] == "briefing":
                pid = parts[2]
                if not _looks_like_id(pid):
                    return self._send_json(400, {"error": "BAD_PROGRAM_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                bp = briefing_payload(home, pid, self.server.server_address[1])
                if bp is None:
                    return self._send_json(404, {"error": "NO_SUCH_PROGRAM",
                                                 "program_id": pid,
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, bp)
            if len(parts) == 6 and parts[0] == "api" and parts[1] == "program" \
                    and parts[3] == "lane" and parts[5] == "runs":
                pid, lid = parts[2], parts[4]
                if not (_looks_like_id(pid) and _looks_like_id(lid)):
                    return self._send_json(400, {"error": "BAD_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                payload, refusal = lane_runs_payload(home, pid, lid)
                if payload is None:
                    return self._send_json(404, {"error": refusal,
                                                 "program_id": pid, "lane_id": lid,
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, payload)
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "run":
                rid = parts[2]
                if not _looks_like_id(rid):
                    return self._send_json(400, {"error": "BAD_RUN_ID",
                                                 "instrument": WEBUI_INSTRUMENT})
                payload = run_payload(home, rid)
                if payload is None:
                    return self._send_json(404, {"error": "NO_SUCH_RUN", "run_id": rid,
                                                 "instrument": WEBUI_INSTRUMENT})
                return self._send_json(200, payload)
            # Everything else does not exist. Answered AFTER auth so the route map is not
            # advertised to whoever knocks.
            return self._send_json(404, {"error": "not found", "instrument": WEBUI_INSTRUMENT})

        def _method_not_allowed(self) -> None:
            # THE SURFACE, STATED ON THE WIRE: exactly two verbs exist here -- mapped GET reads
            # and mapped POST writes. A write route is not a new authority path: it invokes the
            # same governed operation the CLI would (PRD.md §13.1, §13.3).
            self._send_json(405, {"error": "METHOD_NOT_ALLOWED",
                                  "detail": "only mapped GET reads and POST writes exist here",
                                  "instrument": WEBUI_INSTRUMENT},
                            {"Allow": "GET, POST"})

        # -- writes ------------------------------------------------------------------------------
        def _read_body_bounded(self) -> bytes:
            """The request body, capped BEFORE authentication (MCP server precedent)."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > MAX_BODY_BYTES:
                # DRAIN, BOUNDED, BEFORE REFUSING. See drain_bounded: without this the close
                # raced the peer's send, the RST discarded the 413 we had already written, and
                # the client saw a transport error instead of a named refusal.
                drain_bounded(self.rfile, length)
                raise BodyTooLarge()
            return self.rfile.read(length) if length > 0 else b""

        def _dispatch_post(self, path: str, body: dict):
            """One POST route -> one governed operation. No route here invents policy."""
            parts = [p for p in path.split("/") if p]
            if path == "/api/program/create":
                return write_program_create(home, body)
            if path == "/api/mode/set":
                return write_mode_set(home, body)
            if path == "/api/token/rotate":
                # Credential management over a proven bearer: regenerate the dashboard's own
                # secret. The response carries the NEW one-step URL (fragment-only token) --
                # the deliberate single exception to "no token in any response", earned by
                # possession of the old secret.
                bound = self.server.server_address[1]
                value = rotate_token_file(tf)
                return 200, rotation_payload(bound, tf, value)
            if path == "/api/connect/manifest":
                return write_connect_manifest(home, body)
            if path == "/api/seats/set":
                return write_seats(body)
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "program" \
                    and parts[3] in WRITE_PROGRAM_ACTIONS:
                pid = parts[2]
                if not _looks_like_id(pid):
                    return _err(400, "BAD_PROGRAM_ID")
                action = parts[3]
                if action == "plan":
                    return write_program_plan(home, pid, body)
                if action == "tick":
                    return write_program_tick(home, pid)
                if action == "answer":
                    return write_program_answer(home, pid, body)
                if action == "autonomy":
                    return write_program_autonomy(home, pid, body)
                if action == "approve":
                    return write_program_approve(home, pid, body)
                if action == "discard":
                    return write_program_discard(home, pid, body)
                return write_program_cancel(home, pid, body)
            # A resource that exists but only reads says so; anything else was never here.
            # Both answered AFTER auth: no route map for whoever knocks.
            if is_read_route(path):
                return _err(405, "METHOD_NOT_ALLOWED", detail="this route answers GET only")
            return _err(404, "not found")

        def do_POST(self):                   # noqa: N802
            path = self.path.split("?", 1)[0]
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/") or "/"
            try:
                raw = self._read_body_bounded()
            except BodyTooLarge:
                # Connection: close -- an over-bound body is drained only up to
                # DRAIN_LIMIT_BYTES, so this keep-alive socket may still hold unread bytes and
                # must not be reused for a next request it would corrupt.
                return self._send_json(413, {"error": "REQUEST_BODY_BOUND_EXCEEDED",
                                             "bound_bytes": MAX_BODY_BYTES,
                                             "instrument": WEBUI_INSTRUMENT},
                                        {"Connection": "close"})
            # AUTHENTICATE BEFORE ANYTHING ELSE -- reads and writes share one gate.
            if not self._authorized():
                return self._refuse_auth()
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                code, obj = _err(400, "INVALID_JSON")
                return self._send_json(code, obj)
            if not isinstance(body, dict):
                code, obj = _err(400, "BODY_NOT_OBJECT", detail="the body must be a JSON object")
                return self._send_json(code, obj)
            code, obj = self._dispatch_post(path, body)
            extra = {"Allow": "GET"} if code == 405 else None
            return self._send_json(code, obj, extra)

        def do_PUT(self):                    # noqa: N802
            self._method_not_allowed()

        def do_DELETE(self):                 # noqa: N802
            self._method_not_allowed()

        def do_PATCH(self):                  # noqa: N802
            self._method_not_allowed()

        def do_HEAD(self):                   # noqa: N802
            self._method_not_allowed()

    httpd = ThreadingHTTPServer((LOOPBACK_HOST, int(port)), Handler)
    httpd.daemon_threads = True
    return httpd, httpd.server_address[1]


def _default_browser_opener(url: str) -> None:
    """Hand a URL to the desktop's browser. Impure. The seam controls substitute."""
    import webbrowser
    webbrowser.open(str(url))


def startup_payload(bound_port: int, token_file: str, token_value: str) -> dict:
    """The console block an operator sees at startup. PURE.

    ONE-STEP SETUP: includes a pre-authenticated URL whose token rides in the URL FRAGMENT
    (#t=...), which browsers strip before any request -- the fragment never reaches the
    server, any log, or the network beyond loopback. The trust domain is unchanged: only
    someone able to read this console can already read the 0600 token file. The bare `url`
    stays fragment-free for paste-the-value operators; both paths work.
    """
    clean_url = "http://%s:%d/" % (LOOPBACK_HOST, bound_port)
    return {
        "instrument": WEBUI_INSTRUMENT,
        "url": clean_url,
        "open": clean_url + "#t=" + token_value,
        "token_file": token_file,
        "surface": "loopback dashboard: reads + governed writes (POST routes map 1:1 onto "
                   "CLI-invoked operations)",
        "note": ("open 'open' for one-step access (the token rides in the fragment and is "
                 "never sent to the server), or open 'url' and paste the value of "
                 "token_file. Ctrl+C stops the server."),
    }


def serve(home: str, *, port: int = 0, token_file: str | None = None, stdout=None,
          open_browser: bool = False, opener=None) -> int:
    """Run the dashboard until Ctrl+C. Blocking. Returns a process exit code.

    Prints ONE startup JSON line -- url and token-file PATH, never the token value -- mirroring
    the once-only setup print of ``tunnel serve``.
    """
    stdout = stdout or sys.stdout
    tf = ensure_token(resolve_token_file(home, token_file))
    try:
        httpd, bound = build_webui_server(home, port=int(port), token_file=tf)
    except OSError as exc:
        stdout.write(json.dumps({"error": "WEBUI_START_FAILED",
                                 "detail": "%s: %s" % (type(exc).__name__, exc),
                                 "instrument": WEBUI_INSTRUMENT}) + "\n")
        return 2
    clean_url = "http://%s:%d/" % (LOOPBACK_HOST, bound)
    token_value = load_token(tf)
    payload = startup_payload(bound, tf, token_value)
    stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
    stdout.flush()
    if open_browser:
        # OPT-IN ONLY. Launching a browser is a side effect on the operator's desktop, so it
        # happens on an explicit flag and never by default. The URL carries the token in its
        # FRAGMENT, which browsers strip before any request -- so this hands the secret to the
        # local browser and to nothing else, exactly as the printed one-step URL already does.
        # A failure to launch is reported and IGNORED: the server is up and the URL is on
        # screen, so a missing default browser must not take the deployment down with it.
        try:
            (opener or _default_browser_opener)(payload["open"])
        except Exception as exc:  # noqa: BLE001
            stdout.write(json.dumps({"open_browser": False,
                                     "detail": "%s: %s" % (type(exc).__name__, exc),
                                     "note": "the server is running; open the url above"}) + "\n")
            stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0

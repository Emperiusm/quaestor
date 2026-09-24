"""corerelay -- Core OWNS a relay's process lifetime. It does not reimplement the relay.

THE GAP THIS CLOSES
-------------------
Core could see relays and could not run one. A relay ran in the foreground of whichever CLI
started it, so closing the terminal ended the work, and the two acceptance criteria that depend
on it -- "a client can start Core on demand" and "Core re-attaches to a running relay" -- had
nothing to attach to.

WHAT CORE OWNS, AND WHAT IT MUST NOT
------------------------------------
Core owns exactly the process lifetime: start it detached, know whether it is alive, ask it to
stop, and find it again after a restart. Everything that makes a relay CORRECT -- the kernel,
the state machine, message identity, delivery, dedup, governance, completion corroboration, the
probe, the retry bound, repository observation -- stays where it already is. Core spawns the
SAME ``relay start`` / ``relay resume`` the operator would type, so there is exactly one
orchestration path and no second one to keep in agreement.

THE LEDGER IS STILL THE TRUTH
-----------------------------
No second canonical store. The relay's own sqlite says what a relay IS; this module answers only
"is a process holding it right now", and it answers that with a LOCK rather than a record --
the same doctrine Core uses for itself, and for the same reason: a pid in a file is a claim, and
the OS holding a lock is evidence. The one file written here is a discovery hint that is
explicitly allowed to be wrong and is reconciled against the lock every time it is read.

A CLIENT SUBMITS A REQUEST, NOT A COMMAND LINE
----------------------------------------------
The argv is built HERE, from a profile an operator registered, against a project an operator
authorised. Nothing a client sends becomes a flag, a path, an executable, an environment
variable or a working directory. That is not a convenience to be traded away later: the moment a
client can shape the command line, Core stops being a boundary and becomes a shell with a token.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import coreid, proc

CORERELAY_INSTRUMENT = "core.relay/1"

PROFILES_FILE = "relay-profiles.json"
#: Per-relay discovery hint. NON-AUTHORITATIVE by construction -- see the module docstring.
PROCESS_FILE = "core-process.json"
LOCK_NAME = "relay.lock"
#: How long a start waits for the relay to take its lock. Bounded, because a start that never
#: answers is indistinguishable to a client from one that is still working.
SPAWN_WAIT_S = float(os.environ.get(branding.env_var("core", "spawn", "wait"), "12"))
REQUESTS_DIR = "core-requests"

#: The ONLY fields an operator-registered profile may carry, and the flag each becomes. A field
#: not in this table cannot reach the command line, so a profile written by hand -- or a future
#: bug that lets a client edit one -- still cannot inject an arbitrary argument.
PROFILE_FIELDS = {
    "orchestrator": "--orchestrator",
    "orchestrator_model": "--orchestrator-model",
    "orchestrator_base_url": "--orchestrator-base-url",
    "orchestrator_key_var": "--orchestrator-key-var",
    "orchestrator_key_file": "--orchestrator-key-file",
    "orchestrator_key_field": "--orchestrator-key-field",
    "browser_endpoint": "--browser-endpoint",
    "browser_transport": "--browser-transport",
    "conversation_id": "--conversation-id",
    "agent": "--agent",
    "agent_base_url": "--agent-base-url",
    "agent_model": "--agent-model",
    "session_id": "--session-id",
    "profile": "--profile",
    "max_exchanges": "--max-exchanges",
    "max_duration": "--max-duration",
    "receive_timeout": "--receive-timeout",
    "verify_timeout": "--verify-timeout",
    "completion_attempts": "--completion-attempts",
    "incomplete_retries": "--incomplete-retries",
}
#: Repeatable, and the one place a command string legitimately appears. It is OPERATOR-supplied
#: at profile registration and never client-supplied -- a client that could add a --verify would
#: have arbitrary execution, which is precisely what this boundary exists to deny.
PROFILE_LIST_FIELDS = {"verify": "--verify"}
PROFILE_FLAG_FIELDS = {"require_repo_change": "--require-repo-change",
                       "no_probe": "--no-probe", "no_observe": "--no-observe"}

# -- ownership verdicts ------------------------------------------------------------------------
OWNED_RUNNING = "RUNNING"
OWNED_NOT_RUNNING = "NOT_RUNNING"
#: The lock could not be read. NOT the same as free: starting a second process on the strength
#: of an unreadable lock is how one logical relay becomes two.
OWNED_UNKNOWN = "UNKNOWN"


def relay_dir(home: str, relay_id: str) -> str:
    return os.path.join(home, "relay", str(relay_id))


def lock_path(home: str, relay_id: str) -> str:
    return os.path.join(relay_dir(home, relay_id), LOCK_NAME)


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return dict(doc) if isinstance(doc, Mapping) else {}
    except (OSError, ValueError):
        return {}


def _write_json(path: str, doc: Mapping) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(dict(doc), fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------------------------
# profiles -- the operator's registered relay shapes
# ---------------------------------------------------------------------------------------------
#: Values a profile field may take, where taking any other is a mistake an operator cannot see
#: until a relay dies. The child's parser enforces these too; catching them at REGISTRATION is
#: what turns "RELAY_EXITED, exit code 2" into a sentence naming the field.
PROFILE_CHOICES = {"browser_transport": ("auto", "cdp", "playwright")}
PROFILE_NUMERIC = ("max_exchanges", "max_duration", "receive_timeout", "verify_timeout",
                   "completion_attempts", "incomplete_retries")


def validate_profile(fields: Mapping) -> list:
    """What is wrong with this shape? PURE. Empty means nothing is.

    The allowlist decides which fields may REACH the command line and says nothing about their
    values, so a typo -- ``--browser-transport cpd`` -- registered cleanly, built an argv the
    child's parser rejected, and surfaced to the client as an exit code with no detail.
    """
    problems = []
    fields = dict(fields or {})
    for key, allowed in PROFILE_CHOICES.items():
        if key in fields and str(fields[key]) not in allowed:
            problems.append({"field": key, "value": str(fields[key]), "allowed": list(allowed)})
    for key in PROFILE_NUMERIC:
        if key not in fields:
            continue
        try:
            float(str(fields[key]))
        except (TypeError, ValueError):
            problems.append({"field": key, "value": str(fields[key]), "allowed": "a number"})
    verify = fields.get("verify")
    if verify is not None and not isinstance(verify, (list, tuple)):
        # A STRING HERE IS NOT ONE COMMAND. ``for value in "make test"`` yields nine characters,
        # so a hand-edited profile became nine one-letter verification commands.
        problems.append({"field": "verify", "value": str(verify)[:60],
                         "allowed": "a list of commands"})
    return problems


def register_profile(home: str, *, name: str, project_id: str, fields: Mapping,
                     now: float = 0.0) -> dict:
    """Record a relay shape an operator is willing to have started. Impure.

    AN OPERATOR ACT. No Core operation calls this, for the same reason none calls
    ``coreid.authorize``: a client that could register its own profile could name its own
    executable, and the boundary would be decoration.
    """
    unknown = sorted(set(fields or {})
                     - set(PROFILE_FIELDS) - set(PROFILE_LIST_FIELDS) - set(PROFILE_FLAG_FIELDS))
    if unknown:
        return {"ok": False, "error": "UNKNOWN_PROFILE_FIELD", "fields": unknown,
                "known": sorted(set(PROFILE_FIELDS) | set(PROFILE_LIST_FIELDS)
                                | set(PROFILE_FLAG_FIELDS))}
    if not str(dict(fields or {}).get("profile") or "").strip():
        # THE ONE FIELD THAT DECIDES WHAT THE AGENT MAY DO had the most permissive implicit
        # default in the tree: omitted, no --profile reached the command line and the child's
        # argparse supplied STANDARD_EDIT, which grants repository WRITE. A shape a client can
        # trigger must name its authority out loud.
        return {"ok": False, "error": "AUTHORITY_PROFILE_REQUIRED",
                "detail": "a registered relay shape must name the authority profile it runs "
                          "under; there is no safe default for what an agent may do"}
    bad = validate_profile(fields)
    if bad:
        return {"ok": False, "error": "INVALID_PROFILE_FIELD", "fields": bad}
    if not any(str(p.get("project_id")) == str(project_id) for p in coreid.projects(home)):
        return {"ok": False, "error": "PROJECT_NOT_AUTHORIZED", "project_id": str(project_id)}
    path = os.path.join(home, PROFILES_FILE)
    doc = _read_json(path)
    rows = dict(doc.get("profiles") or {})
    rows[str(name)] = {"name": str(name), "project_id": str(project_id),
                       "fields": dict(fields or {}),
                       "registered_at": float(now or time.time())}
    _write_json(path, {"profiles": rows, "instrument": CORERELAY_INSTRUMENT})
    return {"ok": True, "name": str(name), "project_id": str(project_id)}


def profiles(home: str, project_id: str = "") -> list:
    """Registered profiles, optionally for one project. Impure. NEVER raises."""
    rows = list((_read_json(os.path.join(home, PROFILES_FILE)).get("profiles") or {}).values())
    if project_id:
        rows = [r for r in rows if str(r.get("project_id")) == str(project_id)]
    rows.sort(key=lambda r: str(r.get("name") or ""))
    return rows


def _base_argv(launcher: Sequence, home: str, relay_id: str, verb: str) -> list:
    """The verb and the flags every relay invocation carries. PURE.

    ``launcher`` IS SUPPLIED BY THE CALLER, and this is not a style choice. This module is in
    ``core``, the bottom layer, and the layering rule is that core names nothing above it --
    statically OR as a string, because a module path in a literal is the same coupling written
    differently. Which program takes these flags is a fact about the transport that runs it, so
    the transport passes it in. What core knows is how a registered profile becomes flags.
    """
    return [*[str(part) for part in launcher],
            "--home", str(home), "relay", str(verb), "--relay-id", str(relay_id),
            "--started-by", "core"]


def resume_argv(home: str, relay_id: str, *, launcher: Sequence) -> list:
    """The command line that CONTINUES a relay. PURE. Deliberately carries NO policy.

    Everything a resumed relay needs -- both ends, the objective, the authority profile, the
    ceilings, the completion policy, the probe policy -- is in its own durable record, and
    ``relay resume`` reads it from there. Passing a profile would mean choosing which policy to
    impose on a relay that already has one: the shape this replaced fell back to an ARBITRARY
    registered profile when the named one was missing, which is policy loss wearing a default's
    clothes. There is nothing to choose here, so nothing is passed.
    """
    return _base_argv(launcher, home, relay_id, "resume")


def build_argv(home: str, profile: Mapping, *, launcher: Sequence, project_root: str,
               relay_id: str, objective: str) -> list:
    """The command line, built HERE from registered fields only. PURE-ish.

    Every value comes from the profile an operator registered or from the registry's own record
    of the project root. The objective is the ONE string a client supplies, and it is passed as
    a single argv element to a ``shell=False`` spawn, so it is data to the child and can never
    be a second argument, a flag, or a shell fragment.
    """
    argv = _base_argv(launcher, home, relay_id, "start")
    argv += ["--project", str(project_root), "--objective", str(objective)]
    fields = dict(profile.get("fields") or {})
    for key, flag in PROFILE_FIELDS.items():
        if key in fields and str(fields[key]) != "":
            argv += [flag, str(fields[key])]
    for key, flag in PROFILE_LIST_FIELDS.items():
        values = fields.get(key) or ()
        # NOT A STRING. Iterating one yields characters, and each character became its own
        # --verify. ``validate_profile`` refuses this at registration; this refuses it again at
        # the only place it could do damage.
        if isinstance(values, str):
            values = [values]
        for value in values:
            argv += [flag, str(value)]
    for key, flag in PROFILE_FLAG_FIELDS.items():
        if fields.get(key):
            argv.append(flag)
    return argv


# ---------------------------------------------------------------------------------------------
# ownership
# ---------------------------------------------------------------------------------------------
def owned(home: str, relay_id: str) -> dict:
    """Is a process holding this relay right now? Impure. NEVER raises.

    THE LOCK IS THE EVIDENCE. The process record beside it is a hint and is reported as such:
    a killed relay leaves it behind, and believing it is how a dead relay looks alive.

    LOCK_ABSENT and LOCK_FREE are BOTH reported NOT_RUNNING here, which is narrower than
    ``proc.classify_liveness``, where absent is UNKNOWN. That is deliberate: a relay_id that has
    never run has no lock file at all, and calling that "unknown" would make every fresh start
    inconclusive. The cost is that the lock FILE becomes part of the durable record -- delete it
    while a relay holds it and ``hold`` will create a new inode and acquire that, so two
    processes could drive one relay. Nothing under ``<home>/relay/`` is a scratch directory.
    """
    verdict = proc.probe_lock(lock_path(home, relay_id))
    record = _read_json(os.path.join(relay_dir(home, relay_id), PROCESS_FILE))
    if verdict == proc.LOCK_HELD:
        return {"ownership": OWNED_RUNNING, "lock": verdict, "process": record}
    if verdict == proc.LOCK_UNKNOWN:
        return {"ownership": OWNED_UNKNOWN, "lock": verdict, "process": record}
    return {"ownership": OWNED_NOT_RUNNING, "lock": verdict, "process": record,
            "stale_process_record": bool(record)}


def spawn_log_path(home: str, relay_id: str) -> str:
    return os.path.join(relay_dir(home, relay_id), "spawn.log")


def spawn_log_tail(home: str, relay_id: str, limit: int = 400) -> str:
    """The last of what the relay process said before it went. Impure. NEVER raises.

    Every failure a relay can have at start -- an endpoint it cannot build, a credential
    variable that is not set, a flag the parser rejects -- is reported by the child as a JSON
    line on stdout. It used to go to DEVNULL, so the client received "exit code 2" and nothing
    else, for a boundary whose whole justification is that the command line is built here.
    """
    try:
        with open(spawn_log_path(home, relay_id), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()[-int(limit):].strip()
    except OSError:
        return ""


def spawn(home: str, argv: list, relay_id: str, ready=None) -> dict:
    """Start a relay DETACHED and wait for it to OWN ITSELF. Impure. NEVER raises.

    DETACHED IS THE POINT. The relay must not be a child of the HTTP request, of Core, or of
    whichever UI asked for it: the acceptance criterion is that the initiating client can vanish
    and the work continues. ``spawn_detached_kwargs`` is the same primitive Core uses for its
    own detachment, so this platform has one answer to "how is a process detached" -- and on
    Windows it carries CREATE_NO_WINDOW, so starting work does not throw a console at whoever
    happens to be at the machine.

    ``argv`` is never a caller's. It comes from ``build_argv`` or ``resume_argv`` directly
    above, and both build it element by element from an operator-registered profile. The spawn
    is ``shell=False``, so not one element can become a second argument or a shell fragment.
    """
    os.makedirs(relay_dir(home, relay_id), exist_ok=True)
    try:
        log = open(spawn_log_path(home, relay_id), "wb")
    except OSError:
        log = None
    try:
        child = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL,
                                 stdout=(log or subprocess.DEVNULL),
                                 stderr=(log or subprocess.DEVNULL),
                                 shell=False, **proc.spawn_detached_kwargs())
    except OSError as exc:
        if log is not None:
            log.close()
        return {"ok": False, "error": "RELAY_SPAWN_FAILED", "started": False,
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    if log is not None:
        log.close()          # the child holds its own handle
    # HOLDING THE LOCK IS NOT BEING A RELAY. The relay takes its lock before it builds a single
    # endpoint, so "the lock is held" was true for a process that went on to fail, and Core
    # answered "started: true" for work whose durable row never existed -- unlistable,
    # unstoppable, and with its request identity burnt. ``ready`` is the caller's test for the
    # thing it actually promised, and BOTH must hold.
    deadline = time.time() + SPAWN_WAIT_S
    while time.time() < deadline:
        exited = child.poll()
        if owned(home, relay_id)["ownership"] == OWNED_RUNNING and (ready is None or ready()):
            return {"ok": True, "relay_id": relay_id, "pid": child.pid, "started": True}
        if exited is not None:
            return {"ok": False, "error": "RELAY_EXITED", "started": False,
                    "detail": "the relay process exited before it was running",
                    "exit_code": child.returncode, "pid": child.pid,
                    "log": spawn_log_tail(home, relay_id)}
        time.sleep(0.2)
    # STILL COMING UP. Not a failure and not a success: a model-exercising probe against a slow
    # provider legitimately takes longer than any client should hold a connection open for. The
    # caller reports it as such and the client asks again.
    return {"ok": False, "error": "RELAY_STILL_STARTING", "started": False, "starting": True,
            "detail": "the relay process is alive and had not finished starting within %.0fs"
                      % SPAWN_WAIT_S,
            "pid": child.pid}


def hold(home: str, relay_id: str):
    """Take the relay's ownership lock, or None. Impure.

    Called by the RELAY PROCESS ITSELF, which then holds it for its lifetime. Two processes
    cannot both hold it, which is what makes "one logical relay, one process" true without any
    coordination between Core and the relay beyond the filesystem.
    """
    os.makedirs(relay_dir(home, relay_id), exist_ok=True)
    lock = proc.WorkerLock(lock_path(home, relay_id))
    return lock if lock.acquire() else None


def record_process(home: str, relay_id: str, *, pid: int, started_at: float = 0.0,
                   started_by: str = "") -> None:
    """Write the discovery hint. Impure. NEVER raises."""
    try:
        _write_json(os.path.join(relay_dir(home, relay_id), PROCESS_FILE),
                    {"relay_id": str(relay_id), "pid": int(pid),
                     "started_at": float(started_at or time.time()),
                     "started_by": str(started_by), "instrument": CORERELAY_INSTRUMENT,
                     "note": "a DISCOVERY HINT, not authority. The lock beside this file is the "
                             "evidence that a process is alive; the relay's own ledger is the "
                             "evidence of what the relay is."})
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------
# request identity -- a retried start must not become a second relay
# ---------------------------------------------------------------------------------------------
def request_key(*, project_id: str, client_id: str, request_id: str) -> str:
    """One opaque key per (project, client, request). PURE.

    HASHED, not sanitised. The shape this replaced dropped every character outside
    ``[A-Za-z0-9-_]`` and truncated to 128, so ``a/b`` and ``ab`` -- and any two long ids
    sharing a prefix -- named the same file, and a client that guessed one was handed back a
    relay_id belonging to work it was never told about. SCOPED to the client and project as
    well, because a request identity belongs to whoever chose it: two clients may pick the same
    word without meaning the same work, and a shared namespace makes one of them wrong.
    """
    raw = "\0".join((str(project_id), str(client_id), str(request_id)))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _request_path(home: str, key: str) -> str:
    return os.path.join(home, "relay", REQUESTS_DIR, "%s.json" % str(key))


def reserve_request(home: str, key: str, relay_id: str, fingerprint: str = "") -> str:
    """Claim ``key`` for ``relay_id``, or return the relay_id that already holds it. Impure.

    EXCLUSIVE CREATE, so two retries of one request arriving together converge on one relay
    instead of both concluding they are first -- Core is threaded, and "read, then write" is
    two steps a second thread fits between.

    Written BEFORE the relay is spawned, which is the whole point: a reservation made
    afterwards cannot cover the window it exists for. Core dying between the spawn and the
    write leaves a running relay that no retry can find, and the retry starts a SECOND relay
    against the same repository with the same objective.

    The FINGERPRINT is what the request asked for. An idempotency key that ignores the body
    lets a client reuse a stable id -- a ticket number, a nightly job name -- for genuinely
    different work and be handed back the old relay while believing the new objective is under
    way. Stored here so the reuse can be refused instead.

    Returns "" when the reservation could not be recorded at all. That is a refusal, not a
    detail: starting work whose identity was not written down is how one request becomes two
    relays the next time the client retries.
    """
    path = _request_path(home, key)
    doc = json.dumps({"relay_id": str(relay_id), "fingerprint": str(fingerprint or ""),
                      "at": time.time(), "instrument": CORERELAY_INSTRUMENT},
                     indent=2, sort_keys=True)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(doc)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        _unlink(tmp)
        return ""
    try:
        # WRITTEN WHOLE, THEN MADE VISIBLE. ``O_CREAT|O_EXCL`` is exclusive but publishes an
        # EMPTY file first, and a reader arriving in that window -- the client's own retry, a
        # millisecond later -- read zero bytes, concluded there was no reservation, and was told
        # the identity could not be recorded while a relay was already starting. Worse, a crash
        # in that window left the empty file forever and wedged the identity permanently.
        # ``link`` publishes a file that is already complete.
        os.link(tmp, path)
    except FileExistsError:
        _unlink(tmp)
        return str(_read_json(path).get("relay_id") or "")
    except OSError:
        # A filesystem without hard links. Fall back to exclusive create, which is still correct
        # against concurrency and only reopens the narrow crash window described above.
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            _unlink(tmp)
            return str(_read_json(path).get("relay_id") or "")
        except OSError:
            _unlink(tmp)
            return ""
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(doc)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            _unlink(tmp)
            return ""
    _unlink(tmp)
    return str(relay_id)


def release_request(home: str, key: str) -> bool:
    """Give a request identity back, because nothing was started under it. Impure. NEVER raises.

    ONLY ON PROOF THAT NO RELAY EXISTS -- the spawn itself failed, or the process exited without
    ever writing a durable row. Without this a start that failed for any reason burned the
    identity forever: every retry was answered ``200 reused`` for a relay that had never existed
    and never would, and the only way forward was a NEW request id, which is precisely how one
    request becomes two relays against one repository.
    """
    return _unlink(_request_path(home, str(key)))


def _unlink(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def recall_request(home: str, key: str) -> str:
    """Which relay holds this key? Impure. NEVER raises. For inspection; starting reserves."""
    return str(_read_json(_request_path(home, str(key))).get("relay_id") or "")


def recall_fingerprint(home: str, key: str) -> str:
    """What did the request that holds this key ask for? Impure. NEVER raises."""
    return str(_read_json(_request_path(home, str(key))).get("fingerprint") or "")


def reconcile(home: str, relays: Sequence[Mapping]) -> list:
    """For each relay row, say whether a process still holds it. Impure. NEVER raises.

    THIS IS WHAT CORE DOES AFTER A RESTART. It does not resurrect anything and it does not
    assume: it asks the lock. A relay whose durable state says RUNNING while no process holds
    the lock is ORPHANED -- the work stopped without recording why -- and that is reported as
    its own condition rather than quietly shown as running.
    """
    out = []
    for row in relays or ():
        rid = str(row.get("relay_id") or "")
        state = str(row.get("state") or "")
        own = owned(home, rid)
        orphaned = (state == "RUNNING" and own["ownership"] == OWNED_NOT_RUNNING)
        out.append({**dict(row), "ownership": own["ownership"], "orphaned": orphaned,
                    "process": own.get("process") or {}})
    return out

"""coreservice -- Quaestor Core: the authenticated local boundary around the proven runtime.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
---------------------------------------------
It is a lightweight per-user loopback service that future clients -- a browser extension, a web
UI, a tray -- reach instead of reaching the machine. It is NOT a new execution path. Every
answer it gives is read from the durable stores the CLI already writes, and every operation it
performs calls the governed code that already owns that effect.

THE ONE RULE THIS FILE EXISTS TO KEEP
-------------------------------------
A service boundary is worth having only if it is NARROWER than the machine behind it. So there
is deliberately no ``execute``, no ``read_file``, no ``write_file``, no path parameter that
reaches the filesystem, and no way to name a repository that an operator has not authorised.
A client asks for QUAESTOR OPERATIONS; it does not get machine powers with a token attached.

Concretely, and asserted by controls rather than promised here:

    no endpoint runs a subprocess
    no endpoint writes a file the caller named
    a READ operation opens the relay ledger read-only and cannot migrate it
    no endpoint takes a filesystem path from the request at all
    a project is named by its ID, and the ID must be in the caller's own grant
    every effect route goes through the same governed function the CLI calls
    no route answers a request addressed to an authority that is not Core's

WHY BINDING LOOPBACK IS NOT ENOUGH
----------------------------------
Loopback says the request came from this machine. It does not say it came from the operator: a
web page the operator merely visits runs on this machine too, and a site that answers DNS for its
own name with 127.0.0.1 reaches this socket with the browser treating the reply as SAME-ORIGIN.
So the bind check is paired with ``authority_refusal``, which reads the two fields such a page
cannot forge -- ``Host`` and ``Origin`` are written by the browser from the URL it loaded.

WHY THE STATE IS NOT DUPLICATED
-------------------------------
Core opens the SAME sqlite the relay CLI writes. A second canonical store for "the service's
view" would be a second truth, and the first thing it would do is disagree during a crash --
which is precisely the situation the operator started the service to survive.

AND A READ OF IT DOES NOT WRITE
-------------------------------
Core opens that store to answer ``relay.list``, ``relay.status`` and its own idle check --
unattended, once a second while it is obligated. Opening it the way the relay does runs the
schema script and then ``ALTER TABLE``, so a surface documented as reading was migrating an
operator's ledger: nothing corrupted and no relay row changed, but a claim the code did not
keep, and no way for an operator to reason about what a read costs. The read paths therefore
use ``RelayState.open_read_only``, where SQLite refuses the write rather than this file
promising not to make one.

What a read still costs is stated rather than denied: a WAL database cannot be read without its
shared-memory index, so ``-shm`` and a zero-length ``-wal`` may appear beside the file. The
ledger itself is byte-identical. The relay CLI is deliberately NOT changed -- it is this store's
writer, it runs in the operator's own foreground, and creating and migrating the file is its
job, not a side effect of somebody asking a question.

A store older than this build is REFUSED BY NAME rather than answered from, and the refusal
reaches the idle watchdog: arriving as "no relays" is what lets Core shut down on top of a live
one.

SINGLE INSTANCE
---------------
``core.proc.WorkerLock`` is the tree's only mutual-exclusion primitive and it is reused rather
than reinvented. The lock is held for the process's lifetime, so the OS publishes Core's death:
a stale endpoint file left by a killed Core is detected because its lock can be taken, not
because it left a tidy note behind.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from typing import Mapping

from quaestor import branding
from quaestor.core import coreauth, coreid, corerelay, proc

CORE_INSTRUMENT = "core.service/1"

#: How many relays a listing shows. A CAP ON A DISPLAY, never on addressing: naming one relay
#: by id reads it directly, so nothing becomes unreachable by being old.
RELAY_LIST_LIMIT = 200
#: How many live relays one project may have at once. A scoped token is the credential a browser
#: extension holds, and an extension is a program untrusted pages talk to: without a ceiling, a
#: loop over fresh request identities spawns detached processes and paid conversations without
#: bound. Deliberately small; an operator who wants more says so.
MAX_LIVE_RELAYS_PER_PROJECT = int(
    os.environ.get(branding.env_var("core", "max", "live", "relays"), "4"))

#: The program a relay is started as. NAMED HERE, in the transport, because ``core.corerelay``
#: builds the flags and must not know which command takes them -- core names nothing above it.
RELAY_LAUNCHER = (proc.python_executable(), "-m", "quaestor.transports.cli")

#: The wire contract. A client that speaks a different major version is refused with a named
#: error rather than being allowed to guess -- PRD section 69 asks for exactly that.
PROTOCOL_VERSION = 1

LOOPBACK_HOST = "127.0.0.1"
#: A caller on loopback has proven only that it is on this machine. Necessary, never sufficient.
LOOPBACK_ONLY = ("127.0.0.1", "::1", "localhost")

#: The authorities Core will ANSWER TO, which is a different question from the address it binds.
#: Binding loopback proves only that a request came from this machine -- and a page the operator
#: is merely VISITING runs on this machine too. A hostile site whose DNS answers its own name
#: with 127.0.0.1 (rebinding) reaches this socket while the browser still believes the response
#: belongs to the ATTACKER'S origin, so script on the page is allowed to read it. What that page
#: cannot do is choose the authority: ``Host`` and ``Origin`` are written by the browser from the
#: URL it loaded, never by script. The authority is therefore the one field in a rebound request
#: that still tells the truth about who is asking, and it is what ``authority_refusal`` reads.
LOOPBACK_AUTHORITIES = ("127.0.0.1", "localhost", "::1")

ENDPOINT_FILE = "core-endpoint.json"
LOCK_FILE = "core.lock"

#: Bodies are small: this API carries identifiers and verdicts, never content. A megabyte would
#: mean somebody is using it for something it is not.
MAX_BODY_BYTES = 64 * 1024
#: How long Core stays up with nothing to do. Configurable, and 0 means "stay up".
DEFAULT_IDLE_S = 900.0


def endpoint_path(home: str) -> str:
    return os.path.join(home, ENDPOINT_FILE)


def lock_path(home: str) -> str:
    return os.path.join(home, LOCK_FILE)


def assert_loopback(host: str) -> str:
    """Raise unless ``host`` is loopback. No flag, no override.

    Same discipline as the MCP server: exposing this on another interface is not a
    configuration change, it is a different threat model.
    """
    h = str(host or "").strip()
    if h not in LOOPBACK_ONLY:
        raise ValueError("refusing to bind %r: Core binds loopback only (%s)"
                         % (h, list(LOOPBACK_ONLY)))
    return h


def _authority_host(raw: str) -> str:
    """The host of an HTTP authority -- lowercased, port removed -- or "" if it is not one. PURE.

    A BRACKETED IPv6 LITERAL IS PARSED, NOT SPLIT. ``"[::1]:9000".split(":")[0]`` is ``"["``, so
    a splitter refuses the exact form ``http.client`` emits for a v6 loopback and Core would hand
    a legitimate client a 403 it has no way to fix. A BARE ``::1`` is refused rather than guessed:
    it is not a legal authority, and guessing means deciding whether the last colon began a port.
    """
    h = str(raw or "").strip().lower().split("/")[0]
    if h.startswith("["):
        end = h.find("]")
        return h[1:end] if end > 1 else ""
    # More than one colon and no brackets is not an authority anything should try to read.
    if h.count(":") > 1:
        return ""
    return h.split(":")[0]


def authority_refusal(host: str, origin: str) -> dict:
    """Why this request's authority is not Core's, or {} if it is. PURE. NEVER raises.

    ABSENT ORIGIN IS NORMAL, and getting that backwards would break every non-browser client.
    Only a browser sends ``Origin``; the CLI, the qualification harness and curl send none, so an
    absent one must pass. A PRESENT one is the browser naming the page that asked -- and a page
    is not a Core client, whatever token it managed to reach.

    A PRESENT-BUT-NOT-LOOPBACK ``Origin`` includes ``null`` (a sandboxed frame, a ``file://``
    document, some redirects) and ``chrome-extension://...``. The browser extension this boundary
    exists for (bd quaestor-pr4.20) will have to be admitted BY NAME by an operator when it
    exists: a scheme wildcard would trust every extension the user has ever installed, and that
    is not a decision anyone has made.

    THE PORT IS DELIBERATELY NOT CHECKED. A rebinding page connects to the port it is already
    talking to, so comparing it to the bound port refuses nothing an attacker would send while
    refusing an honest client reaching Core through a local forward.

    NO ``Host`` AT ALL IS A REFUSAL. HTTP/1.1 requires one, and a request that does not say which
    authority it was addressed to is not a request this check can clear.

    THE REFUSAL NAMES NOBODY, and that is the whole point of refusing ``/health`` too. The one
    caller that ever sees this body is the one caller who must not be told what is here: a
    rebound page reads a same-origin response in full, so ``instrument``, the ``authorities``
    list and the ``Server`` banner would hand it the identification that covering ``/health`` was
    meant to withhold, on every route instead of one. An error CODE naming the header at fault is
    what an honestly misconfigured client needs; the product's name is not part of that.
    """
    if _authority_host(host) not in LOOPBACK_AUTHORITIES:
        return {"error": "HOST_NOT_LOOPBACK",
                "detail": "this request is addressed to an authority this endpoint does not "
                          "answer to; a name that merely resolves to a loopback address is "
                          "somebody else's origin wearing it"}
    text = str(origin or "").strip()
    if not text:
        return {}
    scheme, sep, rest = text.partition("://")
    if (not sep or scheme.lower() not in ("http", "https")
            or _authority_host(rest) not in LOOPBACK_AUTHORITIES):
        return {"error": "ORIGIN_NOT_LOOPBACK",
                "detail": "this request names a web origin, and no web origin is admitted here "
                          "until an operator admits one by name"}
    return {}


def read_endpoint(home: str) -> dict:
    """Where a client should look for Core. Impure. NEVER raises.

    The record is a HINT, not proof: a client must still connect, and Core must still
    authenticate it. A stale file from a killed Core is ordinary and is detected by
    ``running()`` taking the lock, never by trusting what the file says.
    """
    try:
        with open(endpoint_path(home), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return dict(doc) if isinstance(doc, Mapping) else {}
    except (OSError, ValueError):
        return {}


def running(home: str) -> dict:
    """Is a Core alive for this home? Impure. NEVER raises.

    THE LOCK IS THE EVIDENCE, not the endpoint file. If this process can take the lock, nobody
    holds it, so no Core is running -- whatever the file claims. That is the only way a stale
    record and a live service are told apart without asking a pid to vouch for itself, which
    ``core.proc`` is explicit is not evidence.
    """
    verdict = proc.probe_lock(lock_path(home))
    endpoint = read_endpoint(home)
    if verdict == proc.LOCK_HELD:
        return {"running": True, "lock": verdict, "endpoint": endpoint,
                "stale_endpoint": False}
    if verdict == proc.LOCK_UNKNOWN:
        # COULD NOT ASK. Not the same as "nobody is there", and reported as itself so a caller
        # does not start a second Core on the strength of an unreadable lock file.
        return {"running": None, "lock": verdict, "endpoint": endpoint,
                "stale_endpoint": False}
    return {"running": False, "lock": verdict, "endpoint": endpoint,
            "stale_endpoint": bool(endpoint)}


# ---------------------------------------------------------------------------------------------
# the operations. Each one is a NAMED capability; none of them is a machine power.
# ---------------------------------------------------------------------------------------------
def _read_relays(home: str, project_id: str = "", *, relay_id: str = "",
                 limit: int = RELAY_LIST_LIMIT) -> tuple:
    """``(rows, unreadable)`` -- relay state, read from the SAME durable store the CLI writes.
    Impure. NEVER raises. READS: the store is opened read-only and is not migrated.

    THE SECOND HALF OF THE ANSWER IS NOT DECORATION. "No rows" and "could not read" arrive here
    in the same shape, and only one of them is permission for the idle watchdog to shut Core
    down. Returning the bare list flattened them, so a ledger this build refuses to answer from
    -- one written by an older build, one whose file will not open -- read as "nothing is
    running" to the one caller whose whole job is to decide whether anything is.

    THE GRANT IS APPLIED BEFORE ANY WORK, and resolved from the REGISTRY rather than from git.
    The first version called ``coreid.project_identity`` on every relay row and filtered the
    RESULT -- so a client scoped to one project made Core run six git children inside every
    other project's working tree, directories no operator had authorised. Measured on a live
    Core: one ``relay.list`` returning a single row spawned 78 git children across 13 checkouts,
    and the idle watchdog repeated it once a second. Two things were wrong at once: the filter
    was applied after the work, and the identity was being recomputed when the registry already
    knew it. Comparing the stored canonical root to the row's project root costs nothing and
    touches nothing outside the grant.
    """
    from quaestor.relay import cli as relay_cli
    from quaestor.relay import kernel as kernel_mod
    from quaestor.relay import state as state_mod
    from quaestor.core.canon import canonical_path
    db, _work = relay_cli.relay_paths(home)
    # NOT UNREADABLE. No relay has ever run in this home, which is reachable before the CLI has
    # ever been used, and it is a complete answer -- an empty listing and nothing to be
    # obligated by. It must not become a crash and it must not become an obligation.
    if not os.path.exists(db):
        return [], ""
    # root -> project_id, straight from the registry. No subprocess, no filesystem walk.
    #
    # A ROOT CLAIMED BY TWO RECORDS ATTRIBUTES TO NEITHER. ``authorize`` keys on project_id
    # and never prunes by root, so a directory reused for a second repository leaves TWO
    # records naming ONE root. Keying this map by root made the LATER record silently win,
    # and then every relay row recorded at that directory -- rows belonging to the project
    # that was displaced -- was relabelled with the successor's id and served to it: measured
    # over a real socket, a token scoped only to the successor listed the displaced
    # project's relay, was told it owned it, and STOPPED it. That is the mirror of the gate
    # in ``_project`` below, one function away, and it must fail the same way -- CLOSED. A
    # contested root serves its rows to nobody and claims ownership for nobody.
    #
    # The row's own ``repo_id`` is NOT the answer today: ``relay/kernel.py`` writes it as
    # ``origin_url or project_root`` rather than through ``repo_id_for``, and writes it
    # EMPTY when a start is refused, so it does not agree with a project_id -- an
    # inconsistency ``coreid``'s own docstring records as tracked rather than fixed.
    claims: dict = {}
    for r in coreid.projects(home):
        root = str(r.get("root") or "")
        if root:
            claims.setdefault(root, []).append(str(r.get("project_id") or ""))
    roots = {root: pids[0] for root, pids in claims.items() if len(pids) == 1}
    want_pid = str(project_id or "")
    if want_pid and want_pid not in set(roots.values()):
        return [], ""
    st = None
    try:
        # READ-ONLY, and enforced by SQLite rather than by this function's good intentions.
        # ``RelayState(db)`` runs the schema script and ``_migrate``, so this line -- reached
        # once a second by the idle watchdog -- was writing the operator's ledger to answer a
        # question about it.
        st = state_mod.RelayState.open_read_only(db)
        out = []
        # ADDRESSING ONE RELAY IS NOT SEARCHING A LIST. The listing cap was applied globally and
        # BEFORE the project filter, so on a machine with more relays than the cap a live relay
        # older than the newest N vanished from every surface: unlistable, unstoppable, and its
        # request identity reporting that it did not exist.
        rows = ([st.get(relay_id)] if relay_id else st.list_relays(limit=limit))
        for row in rows:
            if row is None:
                continue
            row_root = canonical_path(row.get("project_root") or "")
            # EXACT PROJECT IDENTITY, never a path prefix. The prefix test read "is this relay
            # somewhere under my root", and a nested checkout -- a submodule, a vendored
            # dependency, a fixture repo -- is a DIFFERENT authorised project with a different
            # id that happens to live inside this one. A client scoped to the outer project was
            # handed the inner project's relays and could resume and stop them; the row it got
            # back even carried the other project's id, so the code emitted the proof that it
            # was outside the grant.
            if want_pid and roots.get(row_root, "") != want_pid:
                continue
            summary = kernel_mod.summarise(st, row["relay_id"])
            ident = {"project_id": roots.get(row_root, "")}
            out.append({
                "relay_id": summary.get("relay_id"), "state": summary.get("state"),
                "stop_reason": summary.get("stop_reason"),
                "project_id": ident.get("project_id", ""),
                "exchanges": summary.get("exchanges"),
                "round_trips": summary.get("round_trips"),
                "owner_hold": summary.get("owner_hold"),
                "waiting_on": summary.get("waiting_on"),
                "orchestrator": (summary.get("orchestrator") or {}).get("kind"),
                "execution": (summary.get("execution") or {}).get("kind"),
                "last_activity_at": summary.get("last_activity_at"),
            })
        return out, ""
    except Exception as exc:  # noqa: BLE001 - an unreadable store is a verdict, never a crash
        # NAMED, not swallowed. A listing still shows nothing -- there is nothing honest to
        # show -- but the reason travels so a caller that can act on it does.
        return [], "%s: %s" % (type(exc).__name__, exc)
    finally:
        if st is not None:
            try:
                st.close()
            except Exception:  # noqa: BLE001
                pass


def _relay_rows(home: str, project_id: str = "", *, relay_id: str = "",
                limit: int = RELAY_LIST_LIMIT) -> list:
    """The rows alone, for the surfaces that have nothing to say about the difference. Impure.

    ``relay.list`` and ``relay.status`` report what is there; a ledger they cannot read has no
    rows to report either way. ``has_obligations`` is the caller that must tell them apart, and
    it uses ``_read_relays``.
    """
    return _read_relays(home, project_id, relay_id=relay_id, limit=limit)[0]


def _unreadable_refusal(reason: str) -> tuple:
    """A ledger nobody could read is not a ledger that does not hold this relay. PURE.

    ``_relay_rows`` answers [] for both, and three surfaces below turn [] into an AFFIRMATIVE
    404 -- "not in this project". Said over a store that merely would not open, that is Core
    inventing a fact about the operator's machine: relay.resume, relay.stop and relay.status
    would each report a live relay as absent, and relay.start would let the per-project ceiling
    through because nothing counted against it. 503 rather than 404 because the answer is "ask
    again", not "there is no such thing", and the reason travels so an operator can act on it.
    """
    return 503, {"error": "RELAY_STORE_UNREADABLE",
                 "detail": "the relay ledger could not be read, so Core cannot say whether this "
                           "relay exists; this is not an answer that it does not",
                 "unmeasured": str(reason), "instrument": CORE_INSTRUMENT}


#: A ceiling on the ONE string a client contributes to a command line. Not a security
#: boundary on its own -- the argv is built element by element and never through a shell -- but
#: an unbounded argument is a denial of service on Windows, where the whole command line shares
#: a fixed buffer, and an objective is a sentence.
MAX_OBJECTIVE_CHARS = 4000


def _objective(raw) -> tuple:
    """(objective, error_body). PURE.

    Control characters are refused rather than stripped. They cannot appear in a sentence a
    human wrote, they are how an argument is smuggled into a log line or a terminal, and
    silently rewriting a caller's text would make the relay's recorded objective differ from
    the one the client believes it asked for.
    """
    text = str(raw or "").strip()
    if not text:
        return "", {"error": "OBJECTIVE_REQUIRED",
                    "detail": "a relay is started by naming what it is for"}
    if len(text) > MAX_OBJECTIVE_CHARS:
        return "", {"error": "OBJECTIVE_TOO_LONG", "limit": MAX_OBJECTIVE_CHARS,
                    "length": len(text)}
    if text.startswith("-"):
        # ARGPARSE READS A LEADING DASH AS A FLAG, so "--help" was accepted here and then made
        # the child exit 2 before it did anything -- burning the request identity on the way.
        return "", {"error": "OBJECTIVE_NOT_TEXT",
                    "detail": "an objective may not begin with '-'; it is passed as a command "
                              "line argument and a leading dash reads as a flag"}
    import unicodedata
    for ch in text:
        # BY CATEGORY, not by codepoint range. The range test caught C0 and DEL and let through
        # U+2028 LINE SEPARATOR, U+0085 NEL and the bidi overrides U+202E/U+200F -- which are
        # exactly the characters that smuggle an argument into a log line or reverse what a
        # terminal renders. Cs catches a lone surrogate, which no encoder can encode and which
        # made the spawn raise a UnicodeEncodeError the router does not catch.
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp"):
            return "", {"error": "OBJECTIVE_NOT_TEXT",
                        "detail": "an objective is one line of prose; control, format, "
                                  "surrogate and line-separator characters are refused rather "
                                  "than stripped",
                        "category": unicodedata.category(ch)}
    return text, None


#: The ONE way this module causes a process to exist, and it is not this module's code.
#: ``coreservice`` is the TRANSPORT: it authenticates, authorises, and routes. It imports no
#: subprocess machinery of its own, and a control asserts that by walking this file's parse
#: tree -- so the question "what can a client make this machine run" has exactly one place to
#: be answered, in ``core.corerelay``, next to the allowlist that builds the argv.
_spawn_relay = corerelay.spawn


#: The states an operator may still stop through Core. A relay in OWNER_HOLD has no process
#: and no way to discharge itself, so leaving it unstoppable pinned Core's idle watchdog for the
#: life of the home over a decision nobody was going to make.
STOPPABLE_STATES = ("RUNNING", "PAUSED", "OWNER_HOLD")

#: Stop reasons that mean the relay is FINISHED, not merely not-running. Resuming one clears its
#: stop_reason and re-delivers a directive already accounted for as the end of the work, so the
#: durable answer to "why did this end" is destroyed by the act of asking it to continue.
TERMINAL_STOPS = ("OBJECTIVE_COMPLETE", "MAX_EXCHANGES_REACHED", "MAX_DURATION_REACHED",
                  "COMPLETION_UNCORROBORATED")


def _not_resumable(home: str, row: Mapping) -> dict:
    """Why this relay must not be resumed through Core, or {}. Impure. NEVER raises."""
    reason = str(row.get("stop_reason") or "")
    if reason in TERMINAL_STOPS:
        return {"error": "RELAY_NOT_RESUMABLE", "stop_reason": reason,
                "detail": "this relay finished; resuming it would clear the record of why and "
                          "re-deliver a directive already accounted for. Start new work with a "
                          "new request identity."}
    blocking = _owner_holds_blocking(home, str(row.get("relay_id") or ""))
    if blocking:
        # CORE IS NOT THE OWNER. It refuses here so a client is told what is actually needed
        # without a process being started -- but this is a COURTESY, not the guarantee. The
        # guarantee is that the relay itself re-gates every outstanding requirement on resume,
        # so a caller that bypasses Core entirely gets the same answer. Both ask the SAME
        # kernel function; there is no second copy of this decision to drift.
        return {"error": "OWNER_ACTION_REQUIRED", "owner_hold": row.get("owner_hold"),
                "holds": blocking,
                "detail": "this relay is waiting on an explicit OWNER decision. Grant the "
                          "named capability through the owner channel; authenticating to Core "
                          "is not OWNER authority, and neither is asking again."}
    return {}


def _owner_holds_blocking(home: str, relay_id: str) -> list:
    """Which outstanding owner requirements are still uncovered? Impure. NEVER raises.

    FAIL CLOSED. If the authority state cannot be read at all, the relay is reported as waiting
    on the owner rather than waved through: an unreadable disposition store is not an approval.
    """
    if not relay_id:
        return []
    from quaestor.relay import cli as relay_cli
    from quaestor.relay import kernel as kernel_mod
    from quaestor.relay import state as state_mod
    db, _work = relay_cli.relay_paths(home)
    if not os.path.isfile(db):
        return []
    st = None
    try:
        # A READ. Core answers "what is this relay still waiting on"; it does not repair the
        # store to do it. An old store raises here and is reported as unreadable below, which
        # is already this function's fail-closed answer.
        st = state_mod.RelayState.open_read_only(db)
        row = st.get(relay_id) or {}
        grants, channel = relay_cli._owner_hooks(home, scope=relay_id)
        return [{"hold_id": h.get("hold_id"), "gate": h.get("gate"),
                 "effect_class": h.get("effect_class"),
                 "required": list(h.get("required") or ())}
                for h in kernel_mod.owner_holds_blocking(
                    st, relay_id,
                    profile=str(row.get("authority_profile") or ""),
                    owner_grants=grants(), now=time.time(), channel_state=channel())]
    except Exception:  # noqa: BLE001
        return [{"hold_id": "", "gate": "unreadable", "effect_class": "",
                 "required": [], "detail": "the authority state could not be read, which is "
                                           "not an approval"}]
    finally:
        if st is not None:
            try:
                st.close()
            except Exception:  # noqa: BLE001
                pass


def _reused_start(home: str, pid: str, key: str, owner: str, fingerprint: str) -> tuple:
    """Answer a start whose request identity already exists. PURE-ish.

    A retry is answered with the relay it already made. A request identity reused for DIFFERENT
    work is refused rather than silently handed the old relay: a client that derives its id from
    a ticket or a job name will eventually change what it is asking for, and being told "reused"
    while believing the new objective is under way is worse than an error.
    """
    recorded = corerelay.recall_fingerprint(home, key)
    if recorded and fingerprint and recorded != fingerprint:
        return 409, {"error": "REQUEST_ID_REUSED", "relay_id": owner,
                     "detail": "this request identity already names different work; choose a "
                               "new request_id for a new objective or profile",
                     "instrument": CORE_INSTRUMENT}
    rows = _relay_rows(home, pid, relay_id=owner)
    return 200, {"relay_id": owner, "reused": True, "exists": bool(rows),
                 "relays": corerelay.reconcile(home, rows),
                 "detail": "this request identity already started a relay",
                 "instrument": CORE_INSTRUMENT}


def core_status(home: str, *, started_at: float = 0.0, idle_s: float = 0.0) -> dict:
    """Core's OWN health. Deliberately says nothing about a provider or a relay.

    PR #9 exists because "the endpoint is fine", "the model answers" and "the relay is running"
    are three different questions that were being collapsed into one. This surface keeps them
    apart: Core reports Core, and names the other answers as separate operations.
    """
    dev = coreid.device(home)
    return {
        # NO ``home``. The absolute state-home path carries the OS account name, and a client
        # -- including one scoped to nothing -- has no business learning where on this machine
        # anything lives. An operator who wants it runs ``core status`` locally.
        "core": {"running": True, "protocol_version": PROTOCOL_VERSION,
                 "version": branding.PRODUCT_VERSION, "started_at": started_at,
                 "idle_shutdown_s": idle_s},
        "device": {"device_id": dev.get("device_id", "")},
        "cloud": {"connected": False, "state": "UNAVAILABLE",
                  "detail": "no cloud channel is implemented; this is reported rather than "
                            "left blank so a client cannot read absence as connected"},
        "instrument": CORE_INSTRUMENT,
    }


def handle(home: str, op: str, params: Mapping, auth: Mapping, *,
           started_at: float = 0.0, idle_s: float = 0.0) -> tuple:
    """Route ONE authenticated operation. Returns ``(http_status, body)``. NEVER raises.

    THE PROJECT CHECK IS HERE, once, for every operation that names one. A route that reads a
    project without passing through ``_project`` would be the bypass this whole module exists to
    prevent, and a control walks the source to prove none does.
    """
    name = str(op or "")

    def _project():
        """(project_id, error_body) -- the ONE place a project is resolved and checked."""
        pid = str((params or {}).get("project_id") or "")
        if not pid:
            return "", {"error": "PROJECT_REQUIRED",
                        "detail": "this operation names a project by id"}
        if not coreauth.may_reach(auth, pid):
            # DELIBERATELY the same answer as "no such project": telling an authenticated client
            # that a project it cannot reach EXISTS is a disclosure it did not earn.
            return "", {"error": "PROJECT_NOT_AUTHORIZED",
                        "detail": "this client's grant does not include that project"}
        rows = {str(r.get("project_id")): r for r in coreid.projects(home)}
        if pid not in rows:
            return "", {"error": "PROJECT_NOT_AUTHORIZED",
                        "detail": "this client's grant does not include that project"}
        # AUTHORISED ONCE IS NOT AUTHORISED NOW. If the checkout has moved or stopped being a
        # readable working tree, the grant names something that is no longer there, and serving
        # it would let a caller inherit an authorisation granted to a different thing. This is
        # the only production caller of ``classify`` -- without it the STALE verdict was a
        # verdict nothing ever asked for.
        verdict = coreid.classify(home, rows[pid].get("root") or "")
        if verdict.get("verdict") != coreid.AUTHORIZED:
            return "", {"error": "PROJECT_STALE", "verdict": verdict.get("verdict"),
                        "detail": "the authorised checkout is no longer where it was; "
                                  "re-authorise it"}
        # AND IT MUST STILL BE *THIS* PROJECT. "Some authorised repository is at that path" is
        # a strictly weaker claim than "the project this token is scoped to is at that path",
        # and the registry can hold both at once: ``authorize`` keys on project_id and never
        # prunes by root, so a directory REUSED for a second repository leaves TWO records
        # naming one root. ``classify`` then answers AUTHORIZED -- earned by the OTHER record
        # -- and discarding the identity it came back with is exactly how a token scoped to
        # project X starts a relay, carrying X's profile authority, inside repository Y.
        if str(verdict.get("project_id") or "") != pid:
            # The id actually found is NOT reported, for the same reason the grant refusal
            # above is deliberately indistinguishable from "no such project": naming the
            # project that is really there discloses one this client may not reach.
            return "", {"error": "PROJECT_IDENTITY_MISMATCH",
                        "detail": "that path no longer holds the project this grant names; "
                                  "re-authorise it"}
        return pid, None

    if name == "core.status":
        return 200, core_status(home, started_at=started_at, idle_s=idle_s)

    if name == "core.identity":
        return 200, {"device": coreid.device(home),
                     "client": {"client_id": auth.get("client_id", ""),
                                "name": auth.get("name", ""),
                                "project_ids": list(auth.get("project_ids") or ())},
                     "instrument": CORE_INSTRUMENT}

    if name == "projects.list":
        # ONLY the projects this client may reach. An operator listing every project on the
        # machine is a CLI act, not something a scoped client is entitled to.
        reach = {str(p) for p in (auth.get("project_ids") or ())}
        rows = [r for r in coreid.projects(home) if str(r.get("project_id")) in reach]
        return 200, {"projects": rows, "instrument": CORE_INSTRUMENT}

    if name == "relay.list":
        pid, err = _project()
        if err:
            return 403, err
        # RECONCILED, exactly as relay.status is. A row whose durable state says RUNNING while
        # no process holds its lock is ORPHANED, and two listings of the same relays that
        # disagree about which are alive would make a client choose which surface to believe.
        return 200, {"relays": corerelay.reconcile(home, _relay_rows(home, pid)),
                     "instrument": CORE_INSTRUMENT}

    if name == "relay.profiles":
        pid, err = _project()
        if err:
            return 403, err
        # ``.get``, because ``profiles`` reads a JSON file it is documented never to trust and
        # subscripting reintroduces the raise its reader removed.
        return 200, {"profiles": [{"name": str(p.get("name") or ""),
                                   "project_id": str(p.get("project_id") or "")}
                                  for p in corerelay.profiles(home, pid)],
                     "instrument": CORE_INSTRUMENT}

    if name == "relay.start":
        # AUTHORISATION BEFORE WORK, in this order and no other. The project is resolved and
        # checked against the caller's grant BEFORE anything is read, spawned or inspected --
        # the review of the previous slice found this exact ordering inverted, and it made a
        # scoped read run git across a dozen unauthorised checkouts.
        pid, err = _project()
        if err:
            return 403, err
        # AN EFFECTFUL OPERATION IS RETRIED BY IDENTITY, and there is no way to opt out. The
        # earlier shape treated a missing request_id as "no deduplication wanted", which is
        # never what a client means: it means the client does not yet know it will have to
        # retry. Every lost response then became a second relay.
        request_id = str((params or {}).get("request_id") or "").strip()
        if not request_id:
            return 400, {"error": "REQUEST_ID_REQUIRED",
                         "detail": "a client that loses the answer to a start cannot otherwise "
                                   "tell a retry from a second relay"}
        if len(request_id) > 200:
            return 400, {"error": "REQUEST_ID_TOO_LONG", "limit": 200}
        wanted = str((params or {}).get("profile") or "")
        match = [p for p in corerelay.profiles(home, pid) if str(p.get("name")) == wanted]
        if not match:
            # A CLIENT PICKS A REGISTERED SHAPE; it does not describe one. Every endpoint,
            # model, credential source and limit comes from what an operator registered.
            return 403, {"error": "NO_SUCH_PROFILE", "detail": "relay profiles are registered "
                         "by an operator; a client may name one but never describe one"}
        objective, why = _objective((params or {}).get("objective"))
        if why:
            return 400, why
        key = corerelay.request_key(project_id=pid,
                                    client_id=str(auth.get("client_id") or ""),
                                    request_id=request_id)
        fingerprint = hashlib.sha256(("%s\0%s" % (wanted, objective)).encode("utf-8")).hexdigest()
        prior = corerelay.recall_request(home, key)
        if prior:
            return _reused_start(home, pid, key, prior, fingerprint)
        seen, unreadable = _read_relays(home, pid)
        if unreadable:
            # THE CEILING CANNOT BE ENFORCED FROM AN UNREADABLE LEDGER. Counting [] here would
            # let a start through on a machine that may already be at the limit -- and each one
            # is a process and a paid conversation.
            return _unreadable_refusal(unreadable)
        live = [r for r in corerelay.reconcile(home, seen)
                if r.get("ownership") == corerelay.OWNED_RUNNING]
        if len(live) >= MAX_LIVE_RELAYS_PER_PROJECT:
            return 429, {"error": "TOO_MANY_LIVE_RELAYS", "live": len(live),
                         "limit": MAX_LIVE_RELAYS_PER_PROJECT,
                         "detail": "this project already has as many relays running as Core "
                                   "will start; each one is a process and a paid conversation"}
        # RESERVE, THEN SPAWN, in that order. A reservation written after the spawn cannot
        # cover the window it exists for: Core dying in between leaves a running relay no
        # retry can find, and the retry starts a second one on the same repository.
        relay_id = "relay-%s" % uuid.uuid4().hex[:12]
        owner = corerelay.reserve_request(home, key, relay_id, fingerprint)
        if not owner:
            return 503, {"error": "REQUEST_NOT_RECORDABLE",
                         "detail": "the request identity could not be written down; starting "
                                   "work whose identity is unrecorded is how one request "
                                   "becomes two relays on the next retry"}
        if owner != relay_id:
            return _reused_start(home, pid, key, owner, fingerprint)
        root = ""
        for row in coreid.projects(home):
            if str(row.get("project_id")) == pid:
                root = str(row.get("root") or "")
        argv = corerelay.build_argv(home, match[0], launcher=RELAY_LAUNCHER,
                                    project_root=root, relay_id=relay_id,
                                    objective=objective)
        # READY MEANS THE LEDGER HAS IT, not merely that a process took the lock. A relay that
        # took its lock and then failed to build an endpoint left no durable row, and Core used
        # to report it started -- unlistable and unstoppable ever after.
        out = _spawn_relay(home, argv, relay_id,
                           ready=lambda: bool(_relay_rows(home, pid, relay_id=relay_id)))
        if out.get("starting"):
            # ACCEPTED, not finished. A model-exercising probe against a slow provider takes
            # longer than a client should hold a connection open, and the honest answer is the
            # relay's id plus "ask again", not a guess in either direction.
            return 202, {**out, "relay_id": relay_id, "reused": False,
                         "instrument": CORE_INSTRUMENT}
        if not out.get("ok"):
            # NOTHING WAS STARTED, so the identity goes back. Burning it would answer every
            # future retry with "reused" for a relay that never existed, and the only way
            # forward would be a new request id -- which is how one request becomes two relays.
            #
            # RE-READ FIRST. "The process exited and there was no row" is measured a moment
            # before this line, and a row created in between would make releasing the identity
            # the very mistake it exists to prevent: the retry would allocate a SECOND relay_id
            # for work that already exists.
            exists = bool(_relay_rows(home, pid, relay_id=relay_id))
            if not exists:
                corerelay.release_request(home, key)
            return 502, {**out, "relay_id": relay_id, "exists": exists,
                         "request_id_released": not exists,
                         "instrument": CORE_INSTRUMENT}
        return 200, {"relay_id": relay_id, "reused": False, "started": True,
                     "instrument": CORE_INSTRUMENT}

    if name == "relay.resume":
        pid, err = _project()
        if err:
            return 403, err
        rid = str((params or {}).get("relay_id") or "")
        if not rid:
            return 400, {"error": "RELAY_ID_REQUIRED",
                         "detail": "this operation names one relay by id"}
        rows, unreadable = _read_relays(home, pid, relay_id=rid)
        if unreadable:
            return _unreadable_refusal(unreadable)
        mine = {r["relay_id"]: r for r in rows}
        if rid not in mine:
            # A relay in another project answers exactly as one that does not exist.
            return 404, {"error": "NO_SUCH_RELAY", "detail": "not in this project"}
        own = corerelay.owned(home, rid)
        if own["ownership"] != corerelay.OWNED_NOT_RUNNING:
            return 409, {"error": "RELAY_ALREADY_RUNNING", "ownership": own["ownership"],
                         "detail": "a process already holds this relay"}
        blocked = _not_resumable(home, mine[rid])
        if blocked:
            return 409, blocked
        # NO PROFILE, and therefore no policy. A resumed relay's ends, ceilings, objective,
        # authority profile, completion policy and probe policy all come from its own durable
        # record. The shape this replaced looked up a profile and fell back to an ARBITRARY
        # registered one when the named profile was missing, which would have imposed another
        # relay's ceilings on this one.
        #
        # RESUMED MEANS THE RELAY SAID SO. Holding the lock is true for a process that has not
        # yet re-gated anything, so reading ownership alone reported "resumed: true" for a
        # relay that was, a second later, going to refuse its own hold and exit. The relay
        # writes RUNNING only once it has decided it may continue.
        def resumed():
            row = ([r for r in _relay_rows(home, pid, relay_id=rid)] or [{}])[0]
            return str(row.get("state") or "") == "RUNNING"

        out = _spawn_relay(home, corerelay.resume_argv(home, rid, launcher=RELAY_LAUNCHER),
                           rid, ready=resumed)
        row = ([r for r in _relay_rows(home, pid, relay_id=rid)] or [{}])[0]
        own = corerelay.owned(home, rid)
        body = {"relay_id": rid, "resumed": bool(out.get("ok")), "ownership": own["ownership"],
                "state": row.get("state"), "stop_reason": row.get("stop_reason"),
                "owner_hold": row.get("owner_hold"), "instrument": CORE_INSTRUMENT}
        if out.get("ok"):
            return 200, body
        if row.get("owner_hold") or str(row.get("state") or "") == "OWNER_HOLD":
            return 409, {**body, "error": "OWNER_HOLD_STANDS",
                         "detail": "the relay re-gated its held request and refused to continue "
                                   "past it; Core authentication is not OWNER authority"}
        if out.get("starting"):
            return 202, {**body, **{k: v for k, v in out.items() if k != "ok"}}
        # ALWAYS AN ERROR NAME on a failure. This branch used to strip "ok" from a successful
        # spawn and return a 502 with no ``error`` key at all, so a client that branches on the
        # error name got nothing to branch on.
        return 502, {**body, "error": str(out.get("error") or "RELAY_DID_NOT_RESUME"),
                     **{k: v for k, v in out.items() if k not in ("ok", "error")}}

    if name == "relay.stop":
        pid, err = _project()
        if err:
            return 403, err
        rid = str((params or {}).get("relay_id") or "")
        if not rid:
            return 400, {"error": "RELAY_ID_REQUIRED",
                         "detail": "this operation names one relay by id"}
        rows, unreadable = _read_relays(home, pid, relay_id=rid)
        if unreadable:
            return _unreadable_refusal(unreadable)
        mine = {r["relay_id"]: r for r in rows}
        if rid not in mine:
            return 404, {"error": "NO_SUCH_RELAY", "detail": "not in this project"}
        # GRACEFUL, AND NOT A KILL. The durable record is marked stopped through the relay's own
        # state model; the running loop checks that record at each step boundary and leaves
        # between exchanges, so nothing is interrupted mid-delivery and no send becomes
        # ambiguous. Core does not signal the process, and says so rather than pretending the
        # process is gone.
        from quaestor.relay import cli as relay_cli
        from quaestor.relay import kernel as kernel_mod
        from quaestor.relay import state as state_mod
        db, _w = relay_cli.relay_paths(home)
        st = None
        try:
            st = state_mod.RelayState(db)
            # CONDITIONAL ON STILL RUNNING. A relay that already stopped carries the reason it
            # stopped, and overwriting OBJECTIVE_COMPLETE with STOPPED_BY_OPERATOR would
            # destroy the answer to "why did this end" while inventing an operator act.
            applied = st.request_stop(rid, kernel_mod.STOP_OPERATOR,
                                      from_states=STOPPABLE_STATES,
                                      by=str(auth.get("client_id") or ""))
            after = st.get(rid) or {}
        except Exception as exc:  # noqa: BLE001
            return 502, {"error": "STOP_FAILED",
                         "detail": "%s: %s" % (type(exc).__name__, exc)}
        finally:
            if st is not None:
                try:
                    st.close()
                except Exception:  # noqa: BLE001
                    pass
        own = corerelay.owned(home, rid)
        return 200, {"relay_id": rid, "stop_requested": bool(applied),
                     "stopped_by_client": str(auth.get("client_id") or ""),
                     "state": str(after.get("state") or ""),
                     "stop_reason": str(after.get("stop_reason") or ""),
                     "process_still_running": own["ownership"] == corerelay.OWNED_RUNNING,
                     "detail": "the durable record is marked stopped; a running relay leaves at "
                               "its next step boundary rather than being killed mid-delivery"
                     if applied else
                     "this relay was already not running; its recorded reason is left intact",
                     "instrument": CORE_INSTRUMENT}

    if name == "relay.status":
        pid, err = _project()
        if err:
            return 403, err
        rid = str((params or {}).get("relay_id") or "")
        rows, unreadable = _read_relays(home, pid, relay_id=rid)
        # ONLY WHEN ONE RELAY IS NAMED. A bare listing has nothing to say about the difference
        # and reports what it can see -- that is this surface's contract, and control 398 pins
        # it. Naming a relay is different: the answer would be the AFFIRMATIVE "not in this
        # project", which an unreadable ledger cannot support.
        if rid and unreadable:
            return _unreadable_refusal(unreadable)
        if rid and not rows:
            return 404, {"error": "NO_SUCH_RELAY", "detail": "not in this project"}
        return 200, {"relays": corerelay.reconcile(home, rows),
                     "instrument": CORE_INSTRUMENT}

    return 404, {"error": "NO_SUCH_OPERATION", "operation": name,
                 "detail": "Core exposes named operations, not machine powers",
                 "operations": OPERATIONS}


#: The whole API. Small on purpose: every addition is a widening of a trust boundary, and this
#: list is what a reviewer reads to see how wide it is.
OPERATIONS = ("core.status", "core.identity", "projects.list", "relay.profiles",
              "relay.list", "relay.status", "relay.start", "relay.resume", "relay.stop")

#: The operations that CHANGE something. Listed apart because a reviewer asking "what can a
#: client make this machine do" should not have to read the router to find out.
MUTATION_OPERATIONS = ("relay.start", "relay.resume", "relay.stop")


def build_server(home: str, *, port: int = 0, idle_s: float = DEFAULT_IDLE_S,
                 started_at: float = 0.0):
    """(httpd, bound_port). Impure. The caller owns serve_forever and shutdown."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    assert_loopback(LOOPBACK_HOST)
    began = float(started_at or time.time())
    state = {"last_request_at": began}

    class Handler(BaseHTTPRequestHandler):
        #: An unauthenticated caller that opens a connection and stops talking must not pin a
        #: worker thread for the life of the process. BaseHTTPRequestHandler honours this on the
        #: connection socket.
        timeout = 20.0
        protocol_version = "HTTP/1.1"
        server_version = branding.resource("core")
        sys_version = ""

        def log_message(self, *_a):     # noqa: D102 - stdout belongs to the startup record
            return

        #: True once this request has been refused for its AUTHORITY. Read by ``version_string``.
        _anonymous = False

        def version_string(self):
            """The ``Server`` banner, EMPTY for a caller refused on its authority. Overrides.

            The stdlib stamps the product name on every response, and the only caller that ever
            receives an authority refusal is the one caller that must learn nothing: a rebound
            page reads a same-origin reply in full, headers included. A banner would answer "what
            is running on this port" on EVERY route, which is precisely the question covering
            ``/health`` was meant to leave unanswered.
            """
            return "" if self._anonymous else super().version_string()

        def _send(self, code: int, body: Mapping, *, close: bool = False) -> None:
            raw = json.dumps(dict(body), default=str).encode("utf-8")
            self.send_response(int(code))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if close:
                # A refusal decided before the route runs ends the connection rather than
                # offering a caller Core has just declined a keep-alive to reuse.
                self.send_header("Connection", "close")
            if int(code) == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(raw)

        def _drain(self) -> None:
            """Read the body of a request answered without reading it. Impure. NEVER raises.

            NOT POLITENESS. Where closing a socket over bytes still sitting in the receive buffer
            sends RST, the RST discards whatever the client has not read yet -- which would be
            the refusal itself, so an honestly misconfigured client sees a dropped connection
            instead of the code naming the header at fault.

            AND THAT IS NOT WHAT WINDOWS DOES, MEASURED. Sweeping declared bodies from 1 KiB to
            2 MiB with this function disabled, the client read the 403 in full every time; the
            only losses were above the bound, where it does not drain anyway. So this is a
            defence for the platforms that do RST and NOT something a control on this OS can
            catch by outcome -- which is why control 369 pins what this function DOES (exactly
            the declared body is consumed, and nothing after it) rather than a symptom this
            platform does not show.

            BOUNDED BY THE SAME LIMIT A REAL BODY GETS: a foreign authority does not earn a
            larger read than a trusted one, so an enormous declared length is left unread.
            """
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                return
            if 0 < length <= MAX_BODY_BYTES:
                try:
                    self.rfile.read(length)
                except OSError:
                    pass

        def parse_request(self):
            """Refuse a foreign authority before any route runs. Overrides the stdlib hook.

            EVERY ROUTE, ``/health`` INCLUDED, AND EVERY METHOD -- including ones Core does not
            implement. This is the dispatch choke point: the stdlib calls a ``do_*`` method only
            after this returns True, so a route added later cannot forget the check and an
            unimplemented method cannot answer 501 either. Exempting liveness was the tempting
            shape and it is wrong: ``/health`` is unauthenticated on purpose, but "is Quaestor up
            on this machine, and on which port" is exactly the discovery step a rebinding attack
            begins with, and it was the one working probe a rebound page kept.

            AND THE REFUSAL MUST NOT BE THAT PROBE WEARING A 403. A rebound page is same-origin
            with everything it fetches from this authority, so it reads status, headers and body
            in full; an answer that carried ``instrument``, the ``authorities`` list or the
            ``Server`` banner would identify Quaestor on EVERY route, which is worse than the one
            route it replaced. So this path sends no banner (``version_string``) and a body that
            names only the header at fault. What a rebound page still learns is that something on
            this port speaks HTTP and declines it -- which the successful connect already told
            it.

            BEFORE AUTHENTICATION AND BEFORE THE IDLE CLOCK. No token is read on this path, so
            the refusal cannot differ for a valid one and is not an oracle; and a refused request
            never reaches ``do_POST``, so a foreign caller cannot hold Core open past its idle
            shutdown by knocking.

            403, NOT 421. Misdirected Request tells a client to retry on a fresh connection, which
            is what a hostile page would do forever and what an honest client would do instead of
            surfacing an error to its operator. This answer is terminal.
            """
            if not super().parse_request():
                return False
            hosts = self.headers.get_all("Host") or []
            origins = self.headers.get_all("Origin") or []
            if len(hosts) > 1 or len(origins) > 1:
                # A check handed TWO authorities has to CHOOSE one, and choosing is how a
                # smuggled header rides through on the copy that was not the one read.
                refusal = {"error": "HOST_NOT_LOOPBACK",
                           "detail": "a request carries one Host and at most one Origin; two of "
                                     "either is not an authority that can be checked"}
            else:
                refusal = authority_refusal(hosts[0] if hosts else "",
                                            origins[0] if origins else "")
            if not refusal:
                self._anonymous = False
                return True
            self._anonymous = True
            self._drain()
            self._send(403, refusal, close=True)
            return False

        def _bearer(self) -> str:
            for k, v in self.headers.items():
                if str(k).lower() == "authorization":
                    raw = str(v or "")
                    return raw[7:].strip() if raw[:7].lower() == "bearer " else ""
            return ""

        def do_GET(self):               # noqa: N802
            # LIVENESS ONLY, and deliberately unauthenticated: a client must be able to discover
            # that Core is up before it has a credential. It reveals nothing about projects,
            # relays, the device, or whether any credential would work. Unauthenticated is not
            # unaddressed, though -- ``parse_request`` has already refused a foreign authority,
            # so "before a credential" means the operator's own client, not any page.
            if self.path.split("?")[0] == "/health":
                return self._send(200, {"status": "ok", "protocol_version": PROTOCOL_VERSION,
                                        "instrument": CORE_INSTRUMENT})
            return self._send(404, {"error": "NO_SUCH_ROUTE",
                                    "detail": "Core speaks POST /rpc"})

        def do_POST(self):              # noqa: N802
            state["last_request_at"] = time.time()
            if self.path.split("?")[0] != "/rpc":
                return self._send(404, {"error": "NO_SUCH_ROUTE"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                return self._send(400, {"error": "BAD_CONTENT_LENGTH"})
            # A NEGATIVE LENGTH IS NOT A SMALL ONE. ``length > MAX_BODY_BYTES`` is False for -1,
            # and ``rfile.read(-1)`` then reads until EOF -- an unauthenticated, unbounded read
            # straight past the bound. Both ends of the range are checked.
            if length < 0 or length > MAX_BODY_BYTES:
                return self._send(413, {"error": "BODY_TOO_LARGE", "limit": MAX_BODY_BYTES})
            try:
                doc = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except (OSError, ValueError, UnicodeDecodeError):
                return self._send(400, {"error": "BAD_REQUEST"})
            if not isinstance(doc, Mapping):
                return self._send(400, {"error": "BAD_REQUEST"})

            # NOTHING BEFORE THE CREDENTIAL MAY RAISE. A non-numeric protocol_version used to
            # throw inside the handler, and a handler that dies answers NOTHING: the caller sees
            # a dropped connection rather than a refusal, from an UNAUTHENTICATED request.
            try:
                version = int(doc.get("protocol_version", PROTOCOL_VERSION) or 0)
            except (TypeError, ValueError):
                return self._send(400, {"error": "PROTOCOL_VERSION_MISMATCH",
                                        "server": PROTOCOL_VERSION,
                                        "client": doc.get("protocol_version")})
            if version != PROTOCOL_VERSION:
                # FAIL CLEARLY on a version mismatch rather than guessing what an older or newer
                # client meant. PRD section 69 asks for this by name.
                return self._send(400, {"error": "PROTOCOL_VERSION_MISMATCH",
                                        "server": PROTOCOL_VERSION, "client": version})

            params = doc.get("params") or {}
            if not isinstance(params, Mapping):
                return self._send(400, {"error": "BAD_REQUEST"})

            auth = coreauth.authenticate(home, self._bearer())
            if not auth.get("ok"):
                # ONE refusal for absent, malformed, unknown and revoked. The distinction is
                # real and is kept locally; returning it would be a guessing oracle.
                return self._send(401, {"error": auth.get("refusal", coreauth.REFUSAL),
                                        "instrument": CORE_INSTRUMENT})

            try:
                code, body = handle(home, doc.get("operation"), params, auth,
                                    started_at=began, idle_s=float(idle_s))
            except Exception:  # noqa: BLE001 - a route that dies must still answer
                code, body = 500, {"error": "INTERNAL", "instrument": CORE_INSTRUMENT}
            # The request id travels back untouched so a client can match a reply to a call.
            rid = doc.get("request_id")
            if rid is not None:
                body = dict(body, request_id=rid)
            return self._send(code, body)

        def do_PUT(self):               # noqa: N802
            return self._send(405, {"error": "METHOD_NOT_ALLOWED"})

        do_DELETE = do_PATCH = do_PUT

    httpd = ThreadingHTTPServer((LOOPBACK_HOST, int(port)), Handler)
    httpd.daemon_threads = True
    httpd.quaestor_state = state        # noqa: B010 - read by the idle watchdog
    return httpd, int(httpd.server_address[1])


def has_obligations(home: str) -> dict:
    """Is there work that must outlive an idle timer? Impure. NEVER raises.

    Core may only shut itself down when there is nothing it is responsible for. A relay that is
    RUNNING, or paused holding an owner hold, is an obligation: going away would leave an
    operator's held decision with nothing listening for it.
    """
    from quaestor.relay import cli as relay_cli
    db, _work = relay_cli.relay_paths(home)
    if os.path.exists(db):
        try:
            with open(db, "rb") as fh:
                fh.read(1)
        except OSError as exc:
            # UNREADABLE IS NOT UNOBLIGATED. Shutting down because the ledger could not be read
            # would discard an owner hold precisely when something is already wrong.
            return {"obligated": True, "live_relays": [], "owner_holds": [],
                    "unmeasured": "%s: %s" % (type(exc).__name__, exc)}
    live, held, unmeasured = [], [], []
    # UNBOUNDED. This was reading a capped listing, so on a busy machine a standing owner hold
    # older than the newest N relays was invisible and Core idle-shut-down on top of it.
    rows, unreadable = _read_relays(home, limit=-1)
    if unreadable:
        # THE SAME RULE AS THE UNREADABLE FILE ABOVE, and it has to be said twice because a
        # ledger stops answering in more than one way. A store written by an older build cannot
        # be migrated by a read, so a read REFUSES it -- and a refusal that arrived here as an
        # empty list would read as "nothing is running" and shut Core down on top of a live
        # relay or a standing owner hold.
        return {"obligated": True, "live_relays": [], "owner_holds": [],
                "unmeasured": unreadable}
    for row in rows:
        rid = str(row.get("relay_id") or "")
        state = str(row.get("state") or "")
        # THE LOCK IS ASKED FOR EVERY ROW, whatever the row says. A relay asked to stop is
        # marked STOPPED immediately and then keeps working until its next step boundary, so
        # skipping non-RUNNING rows let Core idle-shut-down on top of a live process. A process
        # holding a relay's lock is work in flight, and that is the whole test.
        ownership = corerelay.owned(home, rid)["ownership"]
        if ownership == corerelay.OWNED_RUNNING:
            live.append(rid)
        elif ownership == corerelay.OWNED_UNKNOWN:
            unmeasured.append(rid)
        elif row.get("owner_hold") or state == "OWNER_HOLD":
            # A HOLD IS DURABLE AND HAS NO PROCESS. It is an obligation precisely because
            # nothing is running: an owner's decision needs somewhere to arrive.
            held.append(rid)
    return {"obligated": bool(live or held or unmeasured),
            "live_relays": live, "owner_holds": held,
            "unmeasured_relays": unmeasured}


def serve(home: str, *, port: int = 0, idle_s: float = DEFAULT_IDLE_S,
          stdout=None, clock=time.time) -> int:
    """Run Core until idle or interrupted. Impure. Returns a process exit code.

    Refuses to start a second Core for the same home: the lock is taken FIRST, and a caller who
    cannot take it is told where the live one is rather than racing it.
    """
    import sys
    out = stdout or sys.stdout
    os.makedirs(home, exist_ok=True)
    lock = proc.WorkerLock(lock_path(home))
    if not lock.acquire():
        out.write(json.dumps({"started": False, "error": "CORE_ALREADY_RUNNING",
                              "endpoint": read_endpoint(home),
                              "instrument": CORE_INSTRUMENT}, indent=2) + "\n")
        return 3

    began = float(clock())
    try:
        httpd, bound = build_server(home, port=port, idle_s=idle_s, started_at=began)
    except OSError as exc:
        lock.release()
        out.write(json.dumps({"started": False, "error": "CORE_BIND_FAILED",
                              "detail": "%s: %s" % (type(exc).__name__, exc)}, indent=2) + "\n")
        return 2

    dev = coreid.device(home)
    record = {"url": "http://%s:%d" % (LOOPBACK_HOST, bound), "port": bound,
              "pid": os.getpid(), "device_id": dev.get("device_id", ""),
              "protocol_version": PROTOCOL_VERSION, "started_at": began,
              "instrument": CORE_INSTRUMENT}
    try:
        tmp = endpoint_path(home) + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, endpoint_path(home))
    except OSError:
        pass
    out.write(json.dumps({"started": True, **record}, indent=2, sort_keys=True) + "\n")
    out.flush()

    stop = threading.Event()

    def watchdog():
        """Shut down when idle AND unobligated. Never while a relay is live or a hold stands."""
        if not idle_s:
            return
        while not stop.wait(1.0):
            quiet = float(clock()) - float(httpd.quaestor_state["last_request_at"])
            if quiet < float(idle_s):
                continue
            if has_obligations(home)["obligated"]:
                continue
            httpd.shutdown()
            return

    watcher = threading.Thread(target=watchdog, daemon=True)
    watcher.start()
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try:
            httpd.server_close()
        except OSError:
            pass
        try:
            os.remove(endpoint_path(home))
        except OSError:
            pass
        lock.release()
    return 0

"""core_relay_qualification -- the LIVE, opt-in proof that Core owns a relay's process lifetime.

    python -m tests.core_relay_qualification

WHY THIS IS NOT IN THE SUITE
-----------------------------
It starts real detached processes, binds real sockets, and drives a relay whose ends are REAL
providers. The relay CLI deliberately refuses scripted endpoints -- "a relay that reported a
finished conversation no model took part in would be indistinguishable from a real one" -- and
that refusal is not weakened for a test, so a relay that starts at all is a relay talking to
something. None of that belongs in a gate that must run offline on someone else's machine, so
the deterministic controls (335-350) prove the semantics and this proves the semantics hold over
real processes.

THE SLICE IT PROVES, in one pass and one pass only:

    Core starts detached
        a client asks for a relay          -- authenticated, over a real socket
    Core spawns the relay in ITS OWN process
        the initiating client PROCESS EXITS -- and the relay does not care
        a retried request identity          -- returns the same relay, not a second one
        a duplicate start                   -- refused by the OS lock
    ONLY Core is killed                     -- not its process tree
        the relay is untouched              -- same pid, same lock, same durable identity
    Core restarts
        it reconciles the SAME relay        -- no second relay, no duplicate message identity
        the relay's POLICY is intact        -- read from the ledger, not rebuilt from defaults
    stop                                    -- durable and graceful, never a kill
    resume                                  -- through Core, carrying no policy of its own

WHY THE PREVIOUS RUN OF THIS DID NOT COUNT
-------------------------------------------
It leaked detached Cores, ran on past its caller, and measured the Core-survival assertion with
``taskkill /T`` -- a TREE kill, which took the relay down with Core and then reported the
product broken. All three faults were the harness. The ownership, the ceiling and the
single-process termination now live in ``tests.procsafe``, are exercised by controls 347-350,
and everything this fixture creates is tracked as it is created and released in a ``finally``
whether the product passes, fails, times out, or raises.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "src"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests import procsafe                                              # noqa: E402

from quaestor.core import coreauth, coreid, corerelay, proc             # noqa: E402
from quaestor.relay import cli as relay_cli                             # noqa: E402
from quaestor.relay import state as state_mod                           # noqa: E402
from quaestor.transports import coreservice as cs                       # noqa: E402

#: The WHOLE run, not one step. Reaching it is a FAIL that still cleans up.
DEADLINE_S = float(os.environ.get("QUAESTOR_QUAL_DEADLINE", "780"))
#: Core's own idle shutdown. FINITE, and defence in depth only: the fixture's ``finally`` is the
#: cleanup. An earlier run passed 0 -- "never shut down" -- and left Cores on the machine.
CORE_IDLE_S = "300"

ORCH_BASE = os.environ.get("QUAESTOR_RELAY_ORCH_BASE_URL", "https://opencode.ai/zen/v1")
ORCH_MODEL = os.environ.get("QUAESTOR_RELAY_ORCH_MODEL", "nemotron-3.5-lightning-free")
ORCH_KEY_FILE = os.environ.get("QUAESTOR_RELAY_ORCH_KEY_FILE",
                               os.path.expanduser("~/.local/share/opencode/auth.json"))
ORCH_KEY_FIELD = os.environ.get("QUAESTOR_RELAY_ORCH_KEY_FIELD", "opencode.key")
AGENT_MODEL = os.environ.get("QUAESTOR_RELAY_AGENT_MODEL", "opencode/mimo-v2.5-free")

#: What the relay is asked to do. NAMED ONCE, because a request identity now carries a
#: fingerprint of what was asked: a retry that quietly changes the objective is a different
#: request, and Core refuses it rather than handing back the old relay.
OBJECTIVE = ("keep a short conversation going while a qualification measures the process "
             "lifetime")


class Result:
    def __init__(self):
        self.steps: list = []

    def step(self, name: str, ok, detail="") -> bool:
        ok = bool(ok)
        self.steps.append({"step": name, "ok": ok, "detail": str(detail)[:400]})
        sys.stdout.write("%-62s %s  %s\n"
                         % (name, "PASS" if ok else "FAIL", str(detail)[:70]))
        sys.stdout.flush()
        return ok

    @property
    def passed(self) -> int:
        return sum(1 for s in self.steps if s["ok"])


def free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def rpc(url: str, token: str, operation: str, params=None, timeout=90.0) -> tuple:
    """One authenticated call over a REAL loopback socket. The boundary IS the transport."""
    body = json.dumps({"operation": operation, "params": params or {},
                       "protocol_version": cs.PROTOCOL_VERSION}).encode("utf-8")
    req = urllib.request.Request(url + "/rpc", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return int(response.status), json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return int(exc.code), json.loads(exc.read().decode("utf-8"))
        except (ValueError, OSError):
            return int(exc.code), {}
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": "UNREACHABLE", "detail": "%s: %s" % (type(exc).__name__, exc)}


def make_repo(fleet, path: str) -> str:
    os.makedirs(path, exist_ok=True)
    for args in (["init", "-q"], ["config", "user.email", "q@example.invalid"],
                 ["config", "user.name", "Q"]):
        fleet.run(["git", *args], what="git", cwd=path, timeout_s=60)
    with open(os.path.join(path, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("a qualification fixture\n")
    fleet.run(["git", "add", "-A"], what="git", cwd=path, timeout_s=60)
    fleet.run(["git", "commit", "-qm", "init"], what="git", cwd=path, timeout_s=60)
    return path


def ledger_row(home: str, relay_id: str) -> dict:
    """Read the relay's DURABLE record directly. The ledger is the truth about what a relay is."""
    db, _work = relay_cli.relay_paths(home)
    if not os.path.isfile(db):
        return {}
    st = state_mod.RelayState(db)
    try:
        row = st.get(relay_id) or {}
        messages = st.messages(relay_id, limit=0)
        return {"row": dict(row), "messages": [dict(m) for m in messages]}
    finally:
        st.close()


def ledger_events(home: str, relay_id: str) -> list:
    """The relay's durable event log. Impure. NEVER raises."""
    db, _work = relay_cli.relay_paths(home)
    if not os.path.isfile(db):
        return []
    st = state_mod.RelayState(db)
    try:
        return [dict(e) for e in st.events(relay_id, limit=0)]
    except Exception:                                                  # noqa: BLE001
        return []
    finally:
        st.close()


def wait_for(predicate, *, fleet, timeout_s: float, tick: float = 1.0):
    """Poll a predicate under the run's global ceiling. Returns the last value."""
    deadline = time.time() + float(timeout_s)
    value = None
    while time.time() < deadline:
        fleet.check_deadline("wait")
        value = predicate()
        if value:
            return value
        time.sleep(tick)
    return value


def start_core(fleet, home: str, *, what: str) -> tuple:
    """Spawn Core detached and wait for the endpoint it writes. Returns (url, pid)."""
    endpoint = cs.endpoint_path(home)
    try:
        os.remove(endpoint)
    except OSError:
        pass
    child = fleet.spawn([proc.python_executable(), "-m", "quaestor.transports.cli",
                         "--home", home, "serve", "--port", "0", "--idle", CORE_IDLE_S],
                        what=what, cwd=ROOT)

    def ready():
        record = cs.read_endpoint(home)
        url = str((record or {}).get("url") or "")
        if not url:
            return None
        code, _body = rpc(url, "", "core.status", timeout=10)
        return url if code in (200, 401) else None

    url = wait_for(ready, fleet=fleet, timeout_s=90, tick=0.5)
    return str(url or ""), child.pid


def qualify(fleet, result: Result) -> dict:
    evidence: dict = {}
    home = fleet.temp_dir("quaestor-core-relay-home-")
    work = fleet.temp_dir("quaestor-core-relay-work-")
    repo_a = make_repo(fleet, os.path.join(work, "alpha"))
    repo_b = make_repo(fleet, os.path.join(work, "beta"))

    # -- OPERATOR acts, in-process. Authorising a project, registering a relay shape and minting
    # a client are things a person does at a terminal; none is reachable through the API, and
    # spawning a CLI to perform each one would prove nothing about the boundary while filling
    # the operator's screen with consoles.
    pid_a = coreid.authorize(home, repo_a)["project_id"]
    pid_b = coreid.authorize(home, repo_b)["project_id"]
    agent_port = free_port()
    evidence["agent_port"] = agent_port
    registered = corerelay.register_profile(
        home, name="qualification", project_id=pid_a,
        fields={"orchestrator": "openai-chat", "orchestrator_base_url": ORCH_BASE,
                "orchestrator_model": ORCH_MODEL, "orchestrator_key_file": ORCH_KEY_FILE,
                "orchestrator_key_field": ORCH_KEY_FIELD,
                "agent": "opencode", "agent_base_url": "http://127.0.0.1:%d" % agent_port,
                "agent_model": AGENT_MODEL,
                # A DISTINCTIVE, NON-DEFAULT POLICY. Every one of these differs from the flag
                # default, so a resume that rebuilt policy from defaults is visible rather than
                # merely suspected.
                "max_exchanges": "200", "max_duration": "1800", "receive_timeout": "240",
                "incomplete_retries": "0", "completion_attempts": "3",
                "profile": "STANDARD_EDIT"})
    result.step("an operator registered a relay shape", registered.get("ok"), registered)
    token = coreauth.issue(home, name="ui", project_ids=[pid_a])["value_returned_once"]
    token_b = coreauth.issue(home, name="other", project_ids=[pid_b])["value_returned_once"]

    # -- the ExecutionEnd's server. Ours, on our port, and ours to end.
    opencode = shutil.which("opencode")
    if not opencode:
        result.step("an opencode server is available", False, "opencode is not on PATH")
        return evidence
    fleet.spawn([opencode, "serve", "--port", str(agent_port)], what="opencode serve", cwd=work)
    listening = wait_for(lambda: _listening(agent_port), fleet=fleet, timeout_s=90, tick=1.0)
    # ADOPT WHAT ACTUALLY LISTENS. On Windows ``opencode`` resolves to a .CMD, so the pid the
    # fleet holds is a cmd.exe wrapper and the server itself is a different process. Ending only
    # the wrapper would leave the server running -- a leak of exactly the kind this harness
    # exists to prevent -- and reaching for a tree kill to fix it is the mistake that invalidated
    # the previous run. So the listener is tracked as its own pid and ended as its own pid.
    listener = _listening_pid(agent_port)
    if listener:
        fleet.adopt(listener, "opencode listener on %d" % agent_port)
    result.step("the execution agent's server is listening", listening,
                "127.0.0.1:%d pid=%s" % (agent_port, listener))
    if not listening:
        return evidence

    # ============================================================ Core, and a client
    url, core_pid = start_core(fleet, home, what="core #1")
    result.step("Core started detached and published its endpoint", bool(url), url)
    if not url:
        return evidence
    evidence["core_pid_1"] = core_pid

    code, _body = rpc(url, "", "relay.list", {"project_id": pid_a})
    result.step("an unauthenticated caller reaches no relay operation", code == 401, code)

    code, body = rpc(url, token_b, "relay.start",
                     {"project_id": pid_a, "profile": "qualification",
                      "objective": "x", "request_id": "trespass-1"})
    result.step("a client scoped elsewhere cannot start work in this project",
                code == 403 and body.get("error") == "PROJECT_NOT_AUTHORIZED", body.get("error"))
    result.step("...and that refusal created no relay", _relay_dirs(home) == [],
                _relay_dirs(home))

    code, body = rpc(url, token, "relay.start",
                     {"project_id": pid_a, "profile": "a-shape-i-invented",
                      "objective": "x", "request_id": "invent-1"})
    result.step("a client may NAME a relay shape and never describe one",
                code == 403 and body.get("error") == "NO_SUCH_PROFILE", body.get("error"))

    # ============================================================ the initiating client EXITS
    # The start is issued by a SEPARATE, SHORT-LIVED process which then exits. Nothing about the
    # relay may depend on that process, on its connection, or on this one.
    caller = os.path.join(work, "initiating_client.py")
    with open(caller, "w", encoding="utf-8") as fh:
        fh.write(_CALLER_SOURCE)
    started = fleet.run([proc.python_executable(), caller, url, token, pid_a,
                         "qualification", "start-once-1", OBJECTIVE],
                        what="initiating client", timeout_s=120)
    try:
        answer = json.loads((started.stdout or b"").decode("utf-8", "replace"))
    except ValueError:
        answer = {"_raw": (started.stdout or b"").decode("utf-8", "replace")[:300],
                  "_err": (started.stderr or b"").decode("utf-8", "replace")[:300]}
    relay_id = str(answer.get("relay_id") or "")
    # 200 or 202: a start that is still coming up -- a model-exercising probe against a slow
    # provider -- is ACCEPTED with its relay id, not guessed at in either direction.
    result.step("a separate client process asked Core for a relay",
                started.returncode == 0 and bool(relay_id), answer)
    if not relay_id:
        return evidence
    evidence["relay_id"] = relay_id

    # THE DISCOVERY HINT IS WRITTEN BY THE RELAY, just after it takes its lock, so it can be a
    # moment behind. Waited for, because a pid this run cannot learn is a process this run
    # cannot promise to clean up -- and continuing anyway is how "left nothing behind" passes
    # while a real relay driving real providers is still running.
    relay_pid = int(wait_for(
        lambda: int(((corerelay.owned(home, relay_id).get("process")) or {}).get("pid") or 0),
        fleet=fleet, timeout_s=30, tick=0.5) or 0)
    own = corerelay.owned(home, relay_id)
    fleet.adopt(relay_pid, "relay %s" % relay_id)
    result.step("the relay runs in its OWN process, holding its own lock",
                own["ownership"] == corerelay.OWNED_RUNNING and relay_pid > 0,
                "pid=%s ownership=%s" % (relay_pid, own["ownership"]))
    evidence["relay_pid"] = relay_pid
    if not relay_pid:
        result.step("this run can account for every process it caused", False,
                    "the relay's pid could not be read, so it cannot be cleaned up")
        return evidence
    # ``fleet.run`` WAITS: by the time this line executes the initiating client has already
    # exited, taking its connection with it. Whatever keeps the relay alive from here on, it is
    # not the process or the socket that asked for it.
    result.step("the initiating client process has EXITED", started.returncode == 0,
                "returncode=%s" % started.returncode)

    # WAIT FOR THE RELAY TO REALLY BE A RELAY. Holding the lock proves a process is under way;
    # the ledger row is written after both ends are bound and the repository has been read, and
    # that is what everything below measures against.
    live = wait_for(lambda: str((ledger_row(home, relay_id).get("row") or {}).get("state") or "")
                    == state_mod.RUNNING, fleet=fleet, timeout_s=180, tick=2.0)
    result.step("the relay bound both ends and reached RUNNING in the ledger", live,
                (ledger_row(home, relay_id).get("row") or {}).get("state"))
    if not live:
        return evidence

    time.sleep(5.0)
    result.step("the relay outlives the client that asked for it",
                corerelay.owned(home, relay_id)["ownership"] == corerelay.OWNED_RUNNING
                and fleet.alive(relay_pid))

    # ============================================================ replay and duplicate start
    code, body = rpc(url, token, "relay.start",
                     {"project_id": pid_a, "profile": "qualification",
                      "objective": OBJECTIVE, "request_id": "start-once-1"})
    result.step("a retried request identity returns the SAME relay",
                code == 200 and body.get("relay_id") == relay_id and body.get("reused") is True,
                "reused=%s id=%s" % (body.get("reused"), body.get("relay_id")))

    # ...and the same identity asking for DIFFERENT work is refused rather than silently handed
    # the old relay, which would let a client believe the new objective was under way.
    code, body = rpc(url, token, "relay.start",
                     {"project_id": pid_a, "profile": "qualification",
                      "objective": "something else entirely", "request_id": "start-once-1"})
    result.step("the same identity asking for different work is refused",
                code == 409 and body.get("error") == "REQUEST_ID_REUSED", body.get("error"))

    code, body = rpc(url, token, "relay.list", {"project_id": pid_a})
    result.step("exactly ONE relay exists for this project",
                code == 200 and len(body.get("relays") or []) == 1,
                len(body.get("relays") or []))

    code, body = rpc(url, token, "relay.resume", {"project_id": pid_a, "relay_id": relay_id})
    result.step("a running relay cannot be resumed into a second process",
                code == 409 and body.get("error") == "RELAY_ALREADY_RUNNING", body.get("error"))

    # A DELIVERY MUST HAVE HAPPENED before Core is killed, or "no duplicate delivery across
    # the restart" is a claim about an empty set. The first run of this fixture passed that step
    # with zero messages, which proves nothing at all.
    moved = wait_for(lambda: len(ledger_row(home, relay_id).get("messages") or ()) >= 1,
                     fleet=fleet, timeout_s=240, tick=3.0)
    result.step("the relay actually moved a message before Core is killed", moved,
                "messages=%d" % len(ledger_row(home, relay_id).get("messages") or ()))

    before = ledger_row(home, relay_id)
    evidence["before_core_death"] = _digest_row(before)

    # ============================================================ kill ONLY Core
    # SINGLE PROCESS. procsafe.kill_argv refuses a tree kill by construction; the first run of
    # this fixture used one and reported the product broken when the test was.
    fleet.terminate(core_pid, what="core #1")
    gone = fleet.wait_gone(core_pid, timeout_s=45)
    # AND THAT IT LET GO. The pid leaving the process table happens BEFORE the kernel releases
    # what the process held, so "Core is gone" is only half the question; the half that matters
    # for everything below is whether the next Core can take the lock.
    released = fleet.wait_released(cs.lock_path(home), timeout_s=45)
    if gone:
        fleet.forget(core_pid)          # only once it really is gone; otherwise cleanup retries
    result.step("Core is gone, and has released its lock",
                gone and released and not fleet.alive(core_pid),
                "pid=%s gone=%s released=%s" % (core_pid, gone, released))
    stale = cs.read_endpoint(home)
    result.step("...nothing answers, and the endpoint file it left is NOT believed",
                rpc(url, token, "core.status", timeout=8)[0] == 0 and bool(stale),
                "stale endpoint on disk: %s" % bool(stale))

    time.sleep(6.0)
    after_kill = corerelay.owned(home, relay_id)
    survivor = ledger_row(home, relay_id)
    result.step("the relay SURVIVES Core-only death, same process, same lock",
                after_kill["ownership"] == corerelay.OWNED_RUNNING
                and fleet.alive(relay_pid)
                and int((after_kill.get("process") or {}).get("pid") or 0) == relay_pid,
                "ownership=%s pid=%s" % (after_kill["ownership"], relay_pid))
    result.step("Core's death manufactured no terminal state",
                str(survivor.get("row", {}).get("state") or "") == state_mod.RUNNING
                and not str(survivor.get("row", {}).get("stop_reason") or ""),
                "state=%s stop=%s" % (survivor.get("row", {}).get("state"),
                                      survivor.get("row", {}).get("stop_reason")))

    # ============================================================ Core restarts and reconciles
    url2, core_pid2 = start_core(fleet, home, what="core #2")
    result.step("Core restarted", bool(url2), url2)
    if not url2:
        return evidence
    evidence["core_pid_2"] = core_pid2

    code, body = rpc(url2, token, "relay.status", {"project_id": pid_a, "relay_id": relay_id})
    rows = body.get("relays") or []
    row = rows[0] if rows else {}
    result.step("the restarted Core reconciles the SAME relay",
                code == 200 and len(rows) == 1 and row.get("relay_id") == relay_id
                and row.get("ownership") == corerelay.OWNED_RUNNING
                and row.get("orphaned") is False,
                "ownership=%s state=%s orphaned=%s"
                % (row.get("ownership"), row.get("state"), row.get("orphaned")))

    code, body = rpc(url2, token, "relay.list", {"project_id": pid_a})
    result.step("it did not manufacture a second relay",
                code == 200 and len(body.get("relays") or []) == 1,
                len(body.get("relays") or []))
    result.step("no second relay process exists on disk either",
                _relay_dirs(home) == [relay_id], _relay_dirs(home))

    after = ledger_row(home, relay_id)
    evidence["after_core_restart"] = _digest_row(after)
    ids = [m["message_id"] for m in after.get("messages") or ()]
    natives = [m["native_id"] for m in after.get("messages") or () if m.get("native_id")]
    result.step("no message identity is duplicated across the restart",
                len(ids) >= 1 and len(ids) == len(set(ids))
                and len(natives) == len(set(natives)),
                "messages=%d unique=%d native=%d unique=%d"
                % (len(ids), len(set(ids)), len(natives), len(set(natives))))
    result.step("the durable identity is unchanged",
                after.get("row", {}).get("relay_id") == before.get("row", {}).get("relay_id")
                and after.get("row", {}).get("started_at")
                == before.get("row", {}).get("started_at"))

    saved = json.loads(after.get("row", {}).get("config_json") or "{}")
    result.step("the relay's POLICY survived Core, unread from any flag default",
                saved.get("max_exchanges") == 200 and saved.get("max_duration_s") == 1800.0
                and saved.get("receive_timeout_s") == 240.0
                and saved.get("incomplete_retry_limit") == 0
                and saved.get("completion_attempt_limit") == 3,
                {k: saved.get(k) for k in ("max_exchanges", "max_duration_s",
                                           "receive_timeout_s", "incomplete_retry_limit",
                                           "completion_attempt_limit")})

    result.step("Core will not idle-shut-down while it owns a live relay",
                cs.has_obligations(home)["obligated"], cs.has_obligations(home))

    # ============================================================ stop, and what stop means
    code, body = rpc(url2, token, "relay.stop", {"project_id": pid_a, "relay_id": relay_id})
    result.step("stop is accepted, and does not claim to have killed anything",
                code == 200 and body.get("stop_requested") is True
                and body.get("state") == state_mod.STOPPED,
                json.dumps(body)[:140])
    # A GRACEFUL STOP COSTS A TURN. The relay checks the record at each step boundary, so it
    # leaves after finishing the exchange it is in rather than mid-delivery -- which is the
    # point, and which is why this waits rather than killing anything.
    left = wait_for(lambda: corerelay.owned(home, relay_id)["ownership"]
                    != corerelay.OWNED_RUNNING, fleet=fleet, timeout_s=240, tick=2.0)
    result.step("the relay left at a step boundary and released its lock", left,
                corerelay.owned(home, relay_id)["ownership"])
    if left:
        fleet.forget(relay_pid)
    stopped = ledger_row(home, relay_id)
    reason = str(stopped.get("row", {}).get("stop_reason") or "")
    # THE RELAY IS THE AUTHORITY ON WHY IT ENDED. Core's stop is a request honoured at the next
    # step boundary, and a relay that finishes the objective in that very step writes
    # OBJECTIVE_COMPLETE over it -- correctly. Asserting one specific reason would be asserting
    # the outcome of a race with a model. What must hold either way: the relay is stopped, the
    # reason is a real one, and the operator's request is in the event log whether or not it is
    # the reason that won.
    events = ledger_events(home, relay_id)
    requested = [e for e in events if e.get("kind") == "relay.stop_requested"]
    result.step("durable state survives the stop and is inspectable",
                str(stopped.get("row", {}).get("state")) == state_mod.STOPPED
                and reason in ("STOPPED_BY_OPERATOR", "OBJECTIVE_COMPLETE")
                and len(requested) == 1,
                "%s / %s, stop_requested events=%d"
                % (stopped.get("row", {}).get("state"), reason, len(requested)))
    evidence["stop_reason"] = reason

    code, body = rpc(url2, token, "relay.status", {"project_id": pid_a, "relay_id": relay_id})
    srow = (body.get("relays") or [{}])[0]
    result.step("a stopped relay reads as stopped, not orphaned",
                srow.get("ownership") == corerelay.OWNED_NOT_RUNNING
                and srow.get("orphaned") is False,
                "ownership=%s orphaned=%s" % (srow.get("ownership"), srow.get("orphaned")))

    # ============================================================ resume, carrying no policy
    code, body = rpc(url2, token, "relay.resume", {"project_id": pid_a, "relay_id": relay_id})
    if reason == "OBJECTIVE_COMPLETE":
        # A FINISHED RELAY IS NOT RESUMED. Resuming it clears the record of why it ended and
        # re-delivers a directive already accounted for as the end of the work, so a client
        # cannot reopen it -- it starts new work under a new request identity. This branch is
        # the SAME property as the one below, measured from the other side.
        result.step("a relay that finished cannot be resumed back into life",
                    code == 409 and body.get("error") == "RELAY_NOT_RESUMABLE",
                    "%s %s" % (code, body.get("error")))
        result.step("...and its record still says why it ended",
                    str((ledger_row(home, relay_id).get("row") or {}).get("stop_reason"))
                    == "OBJECTIVE_COMPLETE")
        evidence["resume_branch"] = "refused-complete"
    else:
        # 200 RESUMED, or 202 STILL STARTING. A resumed relay re-probes its endpoints before it
        # writes RUNNING, and a model-exercising probe against a free-tier provider takes
        # longer than any client should hold a connection open for. Both are honest.
        result.step("Core accepts the resume and names the relay",
                    code in (200, 202) and body.get("relay_id") == relay_id,
                    "%s %s" % (code, json.dumps(body)[:110]))
        running_again = wait_for(
            lambda: str((ledger_row(home, relay_id).get("row") or {}).get("state") or "")
            == "RUNNING", fleet=fleet, timeout_s=180, tick=2.0)
        result.step("the relay is RUNNING again under the SAME id", running_again,
                    (ledger_row(home, relay_id).get("row") or {}).get("state"))
        resumed_own = corerelay.owned(home, relay_id)
        resumed_pid = int((resumed_own.get("process") or {}).get("pid") or 0)
        if resumed_pid:
            fleet.adopt(resumed_pid, "relay %s (resumed)" % relay_id)
        evidence["resumed_pid"] = resumed_pid
        result.step("the resumed relay is a NEW process for the SAME relay",
                    resumed_own["ownership"] == corerelay.OWNED_RUNNING
                    and resumed_pid not in (0, relay_pid),
                    "pid=%s (was %s)" % (resumed_pid, relay_pid))
        again = json.loads(ledger_row(home, relay_id).get("row", {}).get("config_json") or "{}")
        result.step("the resume did not rewrite the relay's policy",
                    {k: again.get(k) for k in saved} == dict(saved),
                    {k: again.get(k) for k in ("max_exchanges", "incomplete_retry_limit")})
        evidence["resume_branch"] = "resumed"

    # Best-effort tidy: the durable record is what matters, and the fleet's finally owns the
    # process either way.
    rpc(url2, token, "relay.stop", {"project_id": pid_a, "relay_id": relay_id})
    wait_for(lambda: corerelay.owned(home, relay_id)["ownership"] != corerelay.OWNED_RUNNING,
             fleet=fleet, timeout_s=90, tick=2.0)
    evidence["final"] = _digest_row(ledger_row(home, relay_id))
    return evidence


def after_cleanup(agent_port: int, result: Result, cleanup: dict) -> None:
    """What the machine looks like once this run has let go. Impure.

    The leak report says what the fleet ENDED. This says what is actually gone -- including the
    execution agent's server, which on Windows is not the process the fleet spawned but the one
    that launcher started, and which a report of "nothing leaked" would happily omit.
    """
    result.step("no process this run created is still alive", not (cleanup.get("leaked") or []),
                cleanup.get("leaked"))
    if agent_port:
        result.step("the port this run bound is free again", not _listening(agent_port),
                    "127.0.0.1:%d" % agent_port)


_CALLER_SOURCE = '''"""The INITIATING CLIENT. It asks for a relay, prints the answer, and dies."""
import json
import sys
import urllib.request

url, token, project_id, profile, request_id, objective = sys.argv[1:7]
body = json.dumps({"operation": "relay.start", "protocol_version": 1,
                   "params": {"project_id": project_id, "profile": profile,
                              "objective": objective,
                              "request_id": request_id}}).encode("utf-8")
req = urllib.request.Request(url + "/rpc", data=body, method="POST",
                             headers={"Content-Type": "application/json",
                                      "Authorization": "Bearer " + token})
with urllib.request.urlopen(req, timeout=120) as response:
    sys.stdout.write(response.read().decode("utf-8"))
'''


def _listening_pid(port: int):
    """Which pid owns the listening socket on this port? Impure. NEVER raises; None if unclear.

    Read from the OS rather than assumed from the process we started, because a launcher script
    is not the server it launches.
    """
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                                 shell=False, timeout=60)
        else:
            out = subprocess.run(["ss", "-lptnH"], capture_output=True, shell=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    needle = ":%d" % int(port)
    for line in (out.stdout or b"").decode("utf-8", "replace").splitlines():
        if needle not in line or "LISTEN" not in line.upper():
            continue
        parts = line.split()
        if os.name == "nt" and parts and parts[-1].isdigit():
            return int(parts[-1])
        for token in parts:
            if token.startswith("pid="):
                return int(token[4:].split(",")[0])
    return None


def _listening(port: int) -> bool:
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _relay_dirs(home: str) -> list:
    base = os.path.join(home, "relay")
    try:
        return sorted(d for d in os.listdir(base)
                      if d.startswith("relay-") and os.path.isdir(os.path.join(base, d)))
    except OSError:
        return []


def _digest_row(snapshot: dict) -> dict:
    row = dict(snapshot.get("row") or {})
    return {"relay_id": row.get("relay_id"), "state": row.get("state"),
            "stop_reason": row.get("stop_reason"), "exchange_no": row.get("exchange_no"),
            "round_trips": row.get("round_trips"), "started_at": row.get("started_at"),
            "orchestrator_conversation": bool(row.get("orchestrator_conversation")),
            "execution_session": bool(row.get("execution_session")),
            "messages": len(snapshot.get("messages") or ())}


def main(argv=None) -> int:
    del argv
    result = Result()
    evidence: dict = {}
    verdict = "FAIL"
    fleet = procsafe.Fleet(deadline_s=DEADLINE_S,
                           log=lambda m: sys.stdout.write("[fleet] %s\n" % m))
    try:
        try:
            evidence = qualify(fleet, result)
            verdict = "PASS" if all(s["ok"] for s in result.steps) and result.steps else "FAIL"
        except procsafe.DeadlineExceeded as exc:
            result.step("the run stayed inside its wall-clock ceiling", False, exc)
            verdict = "TIMEOUT"
        except Exception as exc:                                       # noqa: BLE001
            result.step("the run completed without raising", False,
                        "%s: %s" % (type(exc).__name__, exc))
            verdict = "ERROR"
    finally:
        # THE PROMISE. Pass, fail, timeout, exception, Ctrl-C: everything this run created is
        # released here, and a run that leaked is a run that FAILED whatever else it proved.
        cleanup = fleet.close()
    after_cleanup(int(evidence.get("agent_port") or 0), result, cleanup)
    if any(not s["ok"] for s in result.steps):
        verdict = "FAIL" if verdict == "PASS" else verdict

    doc = {"verdict": verdict, "passed": result.passed, "total": len(result.steps),
           "steps": result.steps, "evidence": evidence, "cleanup": cleanup,
           "deadline_s": DEADLINE_S,
           "look_alikes_after": procsafe.independent_leak_check(),
           "note": "PROCESS-qualified and LIVE-PROVIDER-qualified: real detached processes, "
                   "real loopback sockets, and a relay whose ends are real providers -- the "
                   "relay CLI refuses scripted endpoints and that refusal was not weakened.",
           "at": time.time()}
    dest = os.path.join(ROOT, "var", "relay-qualification")
    os.makedirs(dest, exist_ok=True)
    # TWO FILES: a stable name for "the latest", and a STAMPED one so a run never
    # destroys the evidence of the one before it. Overwriting is how a passing run's
    # evidence disappeared behind a later run that failed for an unrelated reason.
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    path = os.path.join(dest, "core-relay-lifecycle.json")
    for name in (path, os.path.join(dest, "core-relay-lifecycle-%s.json" % stamp)):
        with open(name, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True, default=str)
    sys.stdout.write("\n%s -- %d/%d steps -> %s\n"
                     % (verdict, result.passed, len(result.steps),
                        os.path.relpath(path, ROOT)))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

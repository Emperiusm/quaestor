"""opencode -- an ExecutionEnd attached to an ALREADY-RUNNING OpenCode server session.

WHY THIS PROVIDER FIRST
-----------------------
The architecture's hardest existing-session requirement is that detection is not enough. Four
separate things must be provable:

    1. the correct project/workspace              -> GET /path, GET /project/current
    2. the correct live or resumable session      -> GET /session?directory=..., session ids
    3. a NEW completed turn, never stale output   -> assistant messages after our own user
                                                     message id, each carrying time.completed
    4. the next instruction into the SAME context -> POST /session/{id}/prompt_async

OpenCode's local server answers all four with real endpoints, which is why it is the first real
ExecutionEnd rather than the most strategically important one.

THE PROPERTY THAT MAKES CRASH RECOVERY EXACT
--------------------------------------------
``prompt_async`` accepts a CALLER-SUPPLIED ``messageID``. The relay therefore delivers under its
OWN message id, and after a crash it can ask a question with a real answer -- "does the session
already contain message X?" -- instead of choosing between duplicating work in the repository
and dropping it. Very few agent integrations offer this; where one does not, ``holds`` must be
absent so the kernel stops rather than guessing.

WHAT IS DELIBERATELY NOT USED
-----------------------------
``/vcs/status`` and ``/session/{id}/diff`` would report the repository over the agent's own
transport. Repository truth is observed by ``relay.observe`` with this process's git, because
evidence supplied by the party it describes is not evidence.

WHAT THIS ENDPOINT DOES NOT PROVE
---------------------------------
Confinement. The agent runs on the host with the operator's own permissions; nothing here can
demonstrate it is unable to reach outside the project. ``proves_confinement`` is False and
``can_mutate_repo`` is True -- those are different facts and the relay records both. Assurance
is computed from the proofs, so this endpoint lands where its evidence puts it and no higher.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from quaestor.relay.contracts import (END_BUSY, END_FAILED, END_IDLE, END_SESSION_LOST,
                                      END_UNREACHABLE, END_WORKSPACE_MISMATCH, PROBE_OK,
                                      PROBE_REFUSED, PROBE_UNSUPPORTED, PROBE_UPSTREAM_FAILED,
                                      EndFacts, EndProbe,
                                      EndStatus, FROM_EXECUTION, RESUME_LOST, RESUME_RESUMED,
                                      RelayEnd, RelayMessage, ROLE_EXECUTION, SendReceipt)

OPENCODE_INSTRUMENT = "relay.ends.opencode/1"

DEFAULT_BASE = "http://127.0.0.1:4096"

#: OpenCode message ids must match ``^msg``. The relay's own ids are longer and contain
#: characters the server rejects, so a delivery id is DERIVED here -- deterministically, from
#: the relay's id, so the same delivery recomputes the same server id after a restart. That
#: determinism is what makes ``holds`` answerable at all.
def native_message_id(relay_message_id: str) -> str:
    """relay id -> a stable ``msg_``-prefixed id the server will accept. PURE."""
    import hashlib
    h = hashlib.sha256(str(relay_message_id).encode("utf-8")).hexdigest()
    return "msg_" + h[:26]


class _Http:
    """The JSON client. Every failure is an OUTCOME with a name, never an exception escaping."""

    def __init__(self, base: str, timeout: float = 120.0, opener=None):
        self.base = str(base).rstrip("/")
        self.timeout = float(timeout)
        self._opener = opener

    def __call__(self, method: str, path: str, body=None, *, timeout: float = 0.0, **query):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items()
                                                 if v not in (None, "")})
        if self._opener is not None:
            return self._opener(method, url, body)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=float(timeout or self.timeout)) as r:  # noqa: S310
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else None


def _canon(path: str) -> str:
    """Compare filesystem paths the way the platform does. PURE-ish (normcase on Windows)."""
    return os.path.normcase(os.path.normpath(os.path.abspath(str(path or ""))))


def unresolved(worktree: str) -> bool:
    """Did the server fail to resolve the directory at all? PURE.

    MEASURED behaviour (2026-08-29): asking this server about a directory that does not exist
    yet returns ``worktree: "/"``, and the answer is CACHED -- creating the directory afterwards
    does not fix it for the life of the server process. So a relay that probed a path before
    building its fixture gets a permanent, silent refusal.

    This is worth telling apart from a real mismatch. "I could not resolve that" and "that is a
    different repository" are different facts and want different advice: restart the server
    versus check which project you meant. Reporting the first as the second sends an operator
    hunting for a workspace confusion that never happened.
    """
    w = str(worktree or "").strip()
    if not w or w in ("/", "\\"):
        return True
    # A bare drive root ("C:\\") is the same shape of non-answer on Windows.
    drive, tail = os.path.splitdrive(os.path.normpath(w))
    return bool(drive) and tail in ("\\", "/", "")


def preflight(*, base_url: str = DEFAULT_BASE, project_root: str = "", session_id: str = "",
              model: str = "", **_ignored) -> dict:
    """MEASURED readiness: is a server listening, does it agree about the project? Impure."""
    http = _Http(base_url, timeout=15.0)
    try:
        health = http("GET", "/global/health")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": "opencode", "proves": "UNREACHABLE",
                "detail": ("no server answered at %s (%s: %s). Start one with "
                           "`opencode serve --port <port>` in the project, or point "
                           "--agent-base-url at the one you already have."
                           % (base_url, type(exc).__name__, exc))}
    if not project_root:
        return {"ok": True, "kind": "opencode", "proves": "SERVER_REACHABLE",
                "detail": "server reachable at %s; no project was named to verify against"
                          % base_url, "health": health}
    try:
        paths = http("GET", "/path", directory=os.path.abspath(project_root)) or {}
        project = http("GET", "/project/current",
                       directory=os.path.abspath(project_root)) or {}
        sessions = http("GET", "/session", directory=os.path.abspath(project_root)) or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": "opencode", "proves": "SERVER_ERROR",
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    worktree = str(paths.get("worktree") or "")
    could_not_resolve = unresolved(worktree)
    agrees = (not could_not_resolve) and _canon(worktree) == _canon(project_root)
    if agrees:
        proves, detail = ("WORKSPACE_IDENTITY_CONFIRMED",
                          "the server reports worktree %r for this directory" % worktree)
    elif could_not_resolve:
        proves, detail = ("WORKSPACE_UNRESOLVED",
                          "the server could not resolve %r (it answered worktree %r) and caches "
                          "that answer for the life of its process; restart the agent server or "
                          "use a path it can see" % (project_root, worktree))
    else:
        proves, detail = ("WORKSPACE_MISMATCH",
                          "the server reports worktree %r for directory %r; refusing to bind a "
                          "relay to a workspace the agent does not agree about"
                          % (worktree, project_root))
    out = {"ok": bool(agrees), "kind": "opencode", "proves": proves, "detail": detail,
           "worktree": worktree, "project_id": str(project.get("id") or ""),
           "vcs": str(project.get("vcs") or ""), "model": model,
           "sessions": [{"id": s.get("id"), "title": s.get("title"),
                         "directory": s.get("directory"),
                         "updated": ((s.get("time") or {}).get("updated"))}
                        for s in (sessions or [])[:20]]}
    if session_id:
        out["session_present"] = any(s.get("id") == session_id for s in (sessions or []))
        if not out["session_present"]:
            out["ok"] = False
            out["proves"] = "SESSION_NOT_FOUND"
            out["detail"] = ("session %s is not among the sessions this server holds for %s"
                             % (session_id, project_root))
    return out


class OpenCodeExecutionEnd(RelayEnd):
    """One live OpenCode session, bound to one authorised project directory."""

    def __init__(self, *, project_root: str, base_url: str = DEFAULT_BASE,
                 session_id: str = "", model: str = "", agent: str = "",
                 create_if_absent: bool = True, attach_latest: bool = False,
                 poll_interval_s: float = 2.0, timeout_s: float = 120.0,
                 opener=None, clock=time.time, sleep=time.sleep):
        if not str(project_root or "").strip():
            raise ValueError("an opencode execution end requires a project_root: a session must "
                             "be bound to an explicitly authorised project, never to whatever "
                             "directory the server happened to start in")
        self._root = os.path.abspath(project_root)
        self._http = _Http(base_url, timeout=timeout_s, opener=opener)
        self._session_id = str(session_id or "")
        self._model = str(model or "")
        self._agent = str(agent or "")
        self._create_if_absent = bool(create_if_absent)
        self._attach_latest = bool(attach_latest)
        self._poll = float(poll_interval_s)
        self._clock = clock
        self._sleep = sleep
        self._base_url = str(base_url).rstrip("/")
        self._worktree = ""
        self._project_id = ""
        self.facts = EndFacts(
            kind="opencode", role=ROLE_EXECUTION, provider_family="", model=self._model,
            can_send=True, can_receive=True, can_observe=True,
            # TRUE, and separately unproven-to-be-confined. Those are different facts.
            can_mutate_repo=True,
            # The relay attaches to a server the OPERATOR runs. It does not start it, stop it,
            # or own its lifetime, and saying otherwise would claim control it does not have.
            manages_lifecycle=False,
            supports_session_resume=True, supports_conversation_resume=False,
            proves_message_identity=True,
            proves_workspace_identity=True,
            proves_capability_surface=False, proves_readonly_behavior=False,
            proves_confinement=False,
            limits=(
                "the agent runs on the host with the operator's own permissions; this build "
                "cannot prove it is confined to the project directory",
                "the relay attaches to a server the operator started; it does not manage that "
                "server's lifetime and cannot restart it",
                "tool permissions are the agent's own configuration, not something the relay "
                "enforces",
            ))

    # -- workspace and session identity ---------------------------------------------------------
    def _verify_workspace(self) -> tuple:
        """(ok, detail). Proof 1: the server agrees which worktree this directory is."""
        try:
            paths = self._http("GET", "/path", directory=self._root) or {}
            project = self._http("GET", "/project/current", directory=self._root) or {}
        except Exception as exc:  # noqa: BLE001
            return False, "%s: %s" % (type(exc).__name__, exc)
        self._worktree = str(paths.get("worktree") or "")
        self._project_id = str(project.get("id") or "")
        if unresolved(self._worktree):
            return False, (
                "the server could not resolve directory %r (it answered worktree %r). This "
                "server caches that answer for the life of its process, so a directory it was "
                "asked about BEFORE the directory existed stays unresolvable. Restart the agent "
                "server, or point the relay at a path that already existed when the server "
                "first saw it." % (self._root, self._worktree))
        if _canon(self._worktree) != _canon(self._root):
            return False, ("the server reports worktree %r for directory %r; refusing to bind a "
                           "relay to a workspace the agent does not agree about"
                           % (self._worktree, self._root))
        return True, "worktree %s (project %s)" % (self._worktree, self._project_id)

    def _sessions(self) -> list:
        try:
            return list(self._http("GET", "/session", directory=self._root) or [])
        except Exception:  # noqa: BLE001 - an unreadable list is an EMPTY answer, named by caller
            return []

    def open(self) -> EndStatus:
        """Attach. Proofs 1 and 2. NEVER starts a server the operator did not start."""
        ok, detail = self._verify_workspace()
        if not ok:
            state = END_WORKSPACE_MISMATCH if self._worktree else END_UNREACHABLE
            return EndStatus(state, self._session_id, detail)
        sessions = self._sessions()
        known = {s.get("id"): s for s in sessions}
        if self._session_id:
            if self._session_id not in known:
                return EndStatus(END_SESSION_LOST, self._session_id,
                                 "session %s is not among the %d sessions this server holds "
                                 "for %s" % (self._session_id, len(sessions), self._root))
        elif self._attach_latest and sessions:
            # ``/session`` is documented as sorted by most recently updated, and this branch is
            # reached only when the operator asked for it explicitly -- silently adopting a
            # stranger's session would bind a relay to work it knows nothing about.
            self._session_id = str(sessions[0].get("id") or "")
        elif self._create_if_absent:
            try:
                created = self._http("POST", "/session", {}, directory=self._root) or {}
            except Exception as exc:  # noqa: BLE001
                return EndStatus(END_FAILED, "", "could not create a session: %s: %s"
                                 % (type(exc).__name__, exc))
            self._session_id = str(created.get("id") or "")
        if not self._session_id:
            return EndStatus(END_SESSION_LOST, "",
                             "no session was named, none could be adopted, and creation was "
                             "not permitted")
        st = self.status()
        return EndStatus(st.state if st.usable else st.state, self._session_id,
                         "%s; session %s" % (detail, self._session_id), facts=st.facts)

    def status(self) -> EndStatus:
        """One liveness reading. NEVER raises.

        ABSENT FROM THE STATUS MAP MEANS IDLE, but only for a session the server still lists --
        a session that has vanished is LOST, not idle, and conflating them would let the relay
        wait forever on something that no longer exists.
        """
        try:
            statuses = self._http("GET", "/session/status", directory=self._root) or {}
        except Exception as exc:  # noqa: BLE001
            return EndStatus(END_UNREACHABLE, self._session_id,
                             "%s: %s" % (type(exc).__name__, exc))
        if not self._session_id:
            return EndStatus(END_FAILED, "", "no session is bound")
        entry = statuses.get(self._session_id)
        if entry is not None:
            kind = str((entry or {}).get("type") or "")
            if kind == "busy":
                return EndStatus(END_BUSY, self._session_id, "the agent loop is running",
                                 facts={"raw": entry})
            if kind == "retry":
                return EndStatus(END_BUSY, self._session_id,
                                 "the agent is retrying: %s" % (entry or {}).get("message"),
                                 facts={"raw": entry})
            return EndStatus(END_IDLE, self._session_id, "idle", facts={"raw": entry})
        if any(s.get("id") == self._session_id for s in self._sessions()):
            return EndStatus(END_IDLE, self._session_id,
                             "idle (absent from the status map, present in the session list)")
        return EndStatus(END_SESSION_LOST, self._session_id,
                         "the server no longer lists session %s" % self._session_id)

    def identity(self) -> str:
        return self._session_id

    def resume(self, identity: str) -> tuple:
        """Re-bind to a session the SERVER still holds. Proof 2, after a restart.

        The session lives in the server, not in this process, so continuity here is real rather
        than reconstructed -- which is exactly the difference between this endpoint and a
        stateless chat conversation, and the reason both report their resume support separately.
        """
        self._session_id = str(identity or self._session_id)
        ok, detail = self._verify_workspace()
        if not ok:
            return RESUME_LOST, detail
        if not any(s.get("id") == self._session_id for s in self._sessions()):
            return RESUME_LOST, ("the server no longer holds session %s for %s"
                                 % (self._session_id, self._root))
        return RESUME_RESUMED, ("re-attached to live session %s in %s; the session's own history "
                                "was never in this process" % (self._session_id, self._worktree))

    # -- messages --------------------------------------------------------------------------------
    #: The listing returns the NEWEST N messages, so the anchor is in the window as long as one
    #: agent turn does not exceed it. Generous, because falling out of the window would look
    #: like "the reply never came".
    MESSAGE_WINDOW = 200

    def _messages(self, limit: int = 0, *, strict: bool = False) -> list:
        """The session's newest messages, or [] when they could not be read.

        ``strict=True`` RAISES instead of returning []. The distinction is load-bearing:
        "the session has no such message" and "I could not ask" must never be the same answer to
        ``holds``. Swallowing the error there would let a transport blip look like "the endpoint
        does not have it", and the kernel would re-deliver a message the agent may already be
        acting on -- duplicating work in somebody's repository, which is the single failure the
        whole ledger exists to prevent.
        """
        try:
            return list(self._http("GET", "/session/%s/message" % self._session_id,
                                   directory=self._root,
                                   limit=int(limit or self.MESSAGE_WINDOW)) or [])
        except Exception:  # noqa: BLE001
            if strict:
                raise
            return []


    #: Ceiling on the probe. A model that cannot answer "OK" inside this is not one the relay
    #: should discover at exchange 1 either.
    PROBE_TIMEOUT_S = 60.0

    def probe(self) -> EndProbe:
        """Make the configured MODEL answer once, for real. NEVER raises.

        WHY THIS IS NOT ``status()``. status() asks the SERVER whether the session is busy. It
        answers IDLE for a model that errors on every inference -- live-observed with
        ``opencode/nemotron-3-ultra-free``, which returns an APIError to a bare "PONG" and made
        a relay disconnect on turn 1 with nothing to tell the operator except "the execution end
        went away". The server was fine. The model was not.

        NEITHER THE RELAY'S SESSION NOR THE PROJECT IS TOUCHED. The probe runs in a THROWAWAY
        session bound to a scratch directory, so the agent cannot reach the authorised
        repository and the bound conversation gains no messages. The cost is one trivial
        inference and one abandoned session, paid once at start instead of at exchange 1.
        """
        started = float(self._clock())
        try:
            # A NEUTRAL PREFIX. Control 172 keeps the product name in ``branding`` alone.
            scratch = tempfile.mkdtemp(prefix="relay-probe-")
        except OSError as exc:
            # A FULL DISK OR AN UNWRITABLE TMPDIR IS NOT A STATEMENT ABOUT THE PROVIDER.
            # Reporting it as PROBE_REFUSED would tell the operator their MODEL was rejected and
            # send them to change something that is fine. Nothing was asked, so nothing is
            # claimed -- and an unmeasurable probe must not block a relay whose provider may be
            # perfectly healthy.
            return EndProbe(PROBE_UNSUPPORTED,
                            "no scratch directory could be created, so the model was never "
                            "asked (%s: %s)" % (type(exc).__name__, exc), model=self._model)
        try:
            try:
                created = self._http("POST", "/session", {}, directory=scratch) or {}
            except Exception as exc:  # noqa: BLE001
                return EndProbe(PROBE_UPSTREAM_FAILED,
                                "the server would not open a probe session (%s: %s)"
                                % (type(exc).__name__, exc), float(self._clock()) - started, self._model)
            sid = str(created.get("id") or "")
            if not sid:
                return EndProbe(PROBE_UPSTREAM_FAILED, "the server returned no probe session id",
                                float(self._clock()) - started, self._model)
            body = {"parts": [{"type": "text", "text": "Reply with the single word OK."}]}
            if self._model:
                # SAME RULE AS send(), which refuses to guess a vendor. Fabricating
                # providerID=modelID from a bare name spends a real inference on a vendor nobody
                # configured and then reports the MODEL unusable -- the probe exists to improve
                # diagnosis, so it must not manufacture a worse one than send() already gives.
                provider, _, model = str(self._model).partition("/")
                if not model:
                    return EndProbe(PROBE_REFUSED,
                                    "opencode models are named '<provider>/<model>'; %r has no "
                                    "provider, and guessing one would probe a different vendor "
                                    "than the record claims" % self._model,
                                    float(self._clock()) - started, self._model)
                body["model"] = {"providerID": provider, "modelID": model}
            if self._agent:
                # The persona the relay will actually run under. Probing the server's DEFAULT
                # agent would measure a configuration the relay never uses.
                body["agent"] = self._agent
            try:
                self._http("POST", "/session/%s/prompt_async" % sid, body, directory=scratch)
            except Exception as exc:  # noqa: BLE001
                return EndProbe(PROBE_REFUSED,
                                "the server refused a prompt for model %r (%s: %s)"
                                % (self._model, type(exc).__name__, exc),
                                float(self._clock()) - started, self._model)
            deadline = started + float(self.PROBE_TIMEOUT_S)
            while float(self._clock()) < deadline:
                self._sleep(1.0)
                try:
                    msgs = list(self._http("GET", "/session/%s/message" % sid,
                                           directory=scratch) or [])
                except Exception:  # noqa: BLE001
                    continue
                for m in msgs:
                    info = (m or {}).get("info") or {}
                    if str(info.get("role") or "") != "assistant":
                        continue
                    # AN ERROR ON THE TURN IS THE ANSWER WE CAME FOR. This is precisely how an
                    # unusable model presents: the server is healthy, the session exists, and
                    # the assistant turn carries an APIError instead of text.
                    if info.get("error"):
                        return EndProbe(PROBE_REFUSED,
                                        "model %s answered with an error: %s"
                                        % (self._model, json.dumps(info["error"])[:300]),
                                        float(self._clock()) - started, self._model)
                    text = " ".join(str(p.get("text") or "") for p in (m.get("parts") or ())
                                    if (p or {}).get("type") == "text").strip()
                    if text:
                        return EndProbe(PROBE_OK,
                                        "model %s answered in %.1fs"
                                        % (self._model, float(self._clock()) - started),
                                        float(self._clock()) - started, self._model)
            return EndProbe(PROBE_UPSTREAM_FAILED,
                            "model %s produced nothing within %.0fs"
                            % (self._model, self.PROBE_TIMEOUT_S),
                            float(self._clock()) - started, self._model)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def holds(self, message_id: str) -> bool:
        """Does the session already contain this delivery? Proof that reconciliation is exact.

        The relay delivered under a derived, deterministic server id, so this is a lookup rather
        than an inference. An endpoint without this property must not define ``holds`` at all --
        the kernel stops on an unanswerable reconciliation instead of guessing, and a failure to
        ASK propagates for exactly that reason rather than being reported as "no".
        """
        native = native_message_id(message_id)
        for m in self._messages(strict=True):
            if str(((m or {}).get("info") or {}).get("id") or "") == native:
                return True
        return False

    def send(self, text: str, *, message_id: str) -> SendReceipt:
        """Deliver into the SAME session, asynchronously, under the relay's own id. Proof 4.

        ASYNC ON PURPOSE. A synchronous prompt would tie the agent's whole turn to one HTTP
        request, so a relay killed mid-turn would lose the work entirely. Firing the prompt and
        then polling means the agent keeps working across a relay restart and the completed turn
        is still there to collect.
        """
        native = native_message_id(message_id)
        body = {"messageID": native, "parts": [{"type": "text", "text": str(text)}]}
        if self._model:
            provider, _, model = str(self._model).partition("/")
            if not model:
                return SendReceipt(False, reason=(
                    "opencode models are named '<provider>/<model>'; %r has no provider, and "
                    "guessing one would run a different vendor than the record claims"
                    % self._model))
            body["model"] = {"providerID": provider, "modelID": model}
        if self._agent:
            body["agent"] = self._agent
        try:
            self._http("POST", "/session/%s/prompt_async" % self._session_id, body,
                       directory=self._root)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", "replace")[:500]
            except Exception:  # noqa: BLE001
                detail = ""
            return SendReceipt(False, reason="the server answered HTTP %s: %s"
                                             % (getattr(exc, "code", "?"), detail))
        except Exception as exc:  # noqa: BLE001
            return SendReceipt(False, reason="%s: %s" % (type(exc).__name__, exc))
        return SendReceipt(True, native_id=native,
                           detail={"session_id": self._session_id, "base_url": self._base_url})

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0):
        """Wait for the session's next COMPLETED turn after ``after_id``. Proof 3.

        The anchor is the user message the relay just delivered, so "new" means "after MY
        instruction" rather than "newer than something this process remembers". That is what
        makes stale output structurally unreachable: a restarted relay re-derives the same
        anchor and cannot mistake last week's answer for this turn's.

        A turn is complete only when every assistant message after the anchor carries
        ``time.completed`` AND the session is no longer busy. Either alone is insufficient --
        between two tool steps the last message is complete while the agent is still working.
        """
        deadline = float(self._clock()) + float(timeout_s or 600.0)
        anchor = str(after_id or "")
        last_err = ""
        missing_while_idle = 0
        while float(self._clock()) < deadline:
            st = self.status()
            if st.state == END_SESSION_LOST:
                return RelayMessage(
                    message_id="%s:lost:%d" % (self._session_id, int(self._clock())),
                    direction=FROM_EXECUTION, text="", complete=False,
                    observed_at=float(self._clock()), session_id=self._session_id,
                    error="%s: %s" % (END_SESSION_LOST, st.detail))
            if st.state == END_UNREACHABLE:
                last_err = st.detail
                self._sleep(self._poll)
                continue
            msgs = self._messages()
            idx = -1
            for i, m in enumerate(msgs):
                if str(((m or {}).get("info") or {}).get("id") or "") == anchor:
                    idx = i
            if idx < 0:
                # Our own delivery is not visible yet. Usually not an error: prompt_async
                # returns before the message is durable, so waiting is correct and concluding
                # "no reply" would drop a turn that is about to exist.
                #
                # But an IDLE session that still cannot see our message after several polls is
                # not slow, it is wrong -- the prompt was dropped, or the anchor fell out of the
                # listing window. Waiting the full receive timeout for that turns a ten-second
                # diagnosis into a five-minute hang with nothing to show for it.
                missing_while_idle = missing_while_idle + 1 if st.state == END_IDLE else 0
                if missing_while_idle >= 5:
                    return RelayMessage(
                        message_id="%s:lost:%d" % (self._session_id, int(self._clock())),
                        direction=FROM_EXECUTION, text="", complete=False,
                        observed_at=float(self._clock()), session_id=self._session_id,
                        error=("the session is idle but does not contain the message the relay "
                               "delivered (%s). Either the prompt was dropped, or this turn is "
                               "older than the %d-message listing window."
                               % (anchor, self.MESSAGE_WINDOW)))
                self._sleep(self._poll)
                continue
            missing_while_idle = 0
            after = [m for m in msgs[idx + 1:]
                     if str(((m or {}).get("info") or {}).get("role") or "") == "assistant"]
            if not after or st.state == END_BUSY:
                self._sleep(self._poll)
                continue
            if not all((((m.get("info") or {}).get("time") or {}).get("completed"))
                       for m in after):
                self._sleep(self._poll)
                continue
            return self._compose(after)
        return RelayMessage(
            message_id="%s:timeout:%d" % (self._session_id, int(self._clock())),
            direction=FROM_EXECUTION, text="", complete=False,
            observed_at=float(self._clock()), session_id=self._session_id,
            error="no completed turn within %ss%s"
                  % (timeout_s, (" (last transport error: %s)" % last_err) if last_err else ""))

    def _compose(self, assistant_msgs: list) -> RelayMessage:
        """Fold one agent turn -- possibly several assistant messages -- into one relay message.

        Tool calls are summarised by NAME, never by output: the agent's tool transcript is often
        larger than the whole conversation, and the Orchestrator is told what the repository
        shows by ``relay.observe`` rather than by the agent's own tool log.
        """
        texts, tools, err = [], [], ""
        last_info = {}
        for m in assistant_msgs:
            info = (m or {}).get("info") or {}
            last_info = info
            if info.get("error"):
                e = info["error"]
                err = "%s: %s" % (e.get("name"),
                                  ((e.get("data") or {}).get("message") or ""))[:600]
            for p in (m or {}).get("parts") or []:
                kind = str(p.get("type") or "")
                if kind == "text" and str(p.get("text") or "").strip():
                    texts.append(str(p["text"]).strip())
                elif kind == "tool":
                    name = str(p.get("tool") or "")
                    if name:
                        tools.append(name)
        body = "\n\n".join(texts)
        if tools:
            counts: dict = {}
            for t in tools:
                counts[t] = counts.get(t, 0) + 1
            body = (body + ("\n\n" if body else "")
                    + "[tools used this turn: %s]"
                    % ", ".join("%s x%d" % (k, v) for k, v in sorted(counts.items())))
        mid = str(last_info.get("id") or "")
        return RelayMessage(
            message_id=mid or ("%s:turn:%d" % (self._session_id, int(self._clock()))),
            direction=FROM_EXECUTION, text=body, complete=True,
            observed_at=float(self._clock()), session_id=self._session_id,
            provenance={"kind": "opencode", "base_url": self._base_url,
                        "session_id": self._session_id, "project_id": self._project_id,
                        "worktree": self._worktree,
                        "model": "%s/%s" % (last_info.get("providerID") or "",
                                            last_info.get("modelID") or ""),
                        "messages_in_turn": len(assistant_msgs),
                        "instrument": OPENCODE_INSTRUMENT},
            error=err)

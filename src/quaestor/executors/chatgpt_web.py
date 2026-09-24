"""chatgpt_web -- a real ChatGPT conversation, held as a NON-WRITING seat.

WHAT THIS IS
------------
Quaestor submits a strategist packet into a conversation in the operator's own signed-in
browser, waits for the answer to actually finish, captures it, and returns it as an ordinary run.
The seat is registered ``write_capable=False``, so seat resolution can never place it anywhere
that touches a repository -- requirement 6 is a property of the routing table, not a promise in
this docstring.

ONE CONVERSATION PER PROGRAM
-----------------------------
``config.conversation_id`` binds the seat to a thread. Given one, the seat resumes it, so the
model keeps whatever context that conversation accumulated. Given none, it starts a fresh one and
REPORTS the id it landed on, in the envelope and in ``conversation.json``, so the caller can bind
it for next time. The report is how the binding gets made: this executor deliberately writes no
program state, because an executor that reached into the strategic store would be a second writer
of it.

EVERY FAILURE IS NAMED, AND NOTHING IS RETRIED
-----------------------------------------------
Signed out, page rotted, timed out, browser gone: each is a distinct named outcome recorded to
stderr, and none is retried here. A retry loop against a UI that just refused you is how an
account gets flagged, and requirement 13 already lists "authentication/session recovery" as
legitimate human interruption. The seat's job is to fail in a way an operator can act on.

A PARTIAL ANSWER IS NEVER A RESULT
-----------------------------------
On timeout the partial text is written to ``partial.txt`` as EVIDENCE and stdout is left empty.
Nothing downstream can mistake it for an answer, and an operator can still see what was on
screen. See ``chatgpt_web_page`` for why an early capture is the failure that matters most.
"""
from __future__ import annotations

import json
import os

from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK,
                                             EXIT_SPAWN_FAILED, EXIT_TIMEOUT,
                                             ExecOutcome, ExecRequest, Executor)

CHATGPT_WEB_INSTRUMENT = "chatgpt_web/1"



def synthesise_envelope(text: str, *, conversation_id: str, transport: str) -> dict:
    """The captured answer as the result envelope ``parse_envelope`` consumes. PURE.

    No usage block: a browser session reports no token counts, and inventing zeros would make
    the cost surfaces show a confident 0.00 for a seat that genuinely cost something.
    """
    return {"type": "result", "subtype": "success", "is_error": False,
            "result": str(text),
            # BOTH names, deliberately. ``conversation_id`` is what a human reading this file
            # expects; ``session_id`` is what the platform already calls it -- the worker
            # extracts that key into result.session_id with no change to core, which is how the
            # seat gets to resume its own thread on the next turn.
            "conversation_id": str(conversation_id), "session_id": str(conversation_id),
            "transport": str(transport), "instrument": CHATGPT_WEB_INSTRUMENT}


class ChatGptWebExecutor(Executor):
    """One ChatGPT conversation, driven as a seat. Attaches; never launches, never authenticates."""

    name = "chatgpt-web"

    def __init__(self, *, conversation_id: str = "", endpoint: str = "", prefer: str = "auto",
                 open_transport=None, page=None, poll_s: float = None, stable_polls: int = None):
        self._conversation_id = str(conversation_id or "")
        self._endpoint = str(endpoint or "")
        self._prefer = str(prefer or "auto")
        self._open = open_transport            # control seam
        self._page = page                      # control seam: a page module double
        self._poll_s = poll_s
        self._stable_polls = stable_polls

    # -- helpers -----------------------------------------------------------------------------
    def _write(self, path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def _fail(self, req: ExecRequest, exit_class: str, reason: str, detail: str,
              *, started: bool) -> ExecOutcome:
        self._write(req.stderr_path, ("%s: %s\n" % (reason, detail)).encode("utf-8"))
        self._write(req.stdout_path, b"")
        return ExecOutcome(started, None, exit_class, error="%s: %s" % (reason, detail))

    # -- the contract ------------------------------------------------------------------------
    def execute(self, req: ExecRequest) -> ExecOutcome:
        page_mod = self._page
        if page_mod is None:
            from quaestor.executors import chatgpt_web_page as page_mod  # noqa: PLW0127
        from quaestor.executors import browser_transport as bt

        try:
            self._write(os.path.join(req.run_dir, "command.json"), json.dumps({
                "executor": self.name, "transport_preference": self._prefer,
                "endpoint": self._endpoint or bt.DEFAULT_CDP_ENDPOINT,
                "conversation_id": self._conversation_id,
                "prompt_bytes": len(str(req.prompt).encode("utf-8")),
                "prompt_location": "page_composer",
                "launches_browser": False, "handles_credential": False,
                "instrument": CHATGPT_WEB_INSTRUMENT}, indent=2).encode("utf-8"))
        except OSError as exc:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="cannot write run files: %s" % exc)

        opener = self._open or bt.open_transport
        kwargs = {"prefer": self._prefer, "match": page_mod.CHATGPT_ORIGIN,
                  "timeout": float(req.timeout_s)}
        if self._endpoint:
            kwargs["endpoint"] = self._endpoint
        try:
            transport, why = opener(**kwargs)
        except bt.BrowserUnavailable as exc:
            # NEVER STARTED: no request was made of the page, so this must not reconcile as a
            # run that produced nothing.
            return self._fail(req, EXIT_SPAWN_FAILED, exc.reason, str(exc), started=False)
        except Exception as exc:  # noqa: BLE001
            return self._fail(req, EXIT_SPAWN_FAILED, "BROWSER_ATTACH_FAILED",
                              "%s: %s" % (type(exc).__name__, exc), started=False)

        try:
            return self._drive(req, transport, why, page_mod)
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    #: How long to wait for a navigation to settle, and how still the page must be first. The
    #: message list is fetched after mount, so "the count stopped changing" is the only signal
    #: available without a selector this module cannot verify.
    SETTLE_POLLS = 3
    SETTLE_INTERVAL_S = 0.5

    def _await_conversation(self, transport, page_mod, target: str, *, timeout_s: float) -> str:
        """'OK', or a NAMED refusal. Impure. Waits for the requested thread to stop loading.

        Two conditions, both necessary: the URL must be the conversation we asked for (a
        redirect to /auth/login or to a different thread is not our thread), and the assistant
        message count must hold still across consecutive polls (the list arrives after mount,
        so a count read too early is a count of the previous page).
        """
        import time as _t
        want = page_mod.conversation_id(target)
        deadline = _t.monotonic() + max(2.0, min(float(timeout_s), 60.0))
        stable, last = 0, None
        while _t.monotonic() < deadline:
            snap = page_mod.probe(transport)
            state = page_mod.classify(snap)
            if state == page_mod.STATE_LOGGED_OUT:
                return page_mod.STATE_LOGGED_OUT
            here = page_mod.conversation_id(str(snap.get("href") or ""))
            on_target = (here == want) if want else True
            count = int(snap.get("count") or 0)
            if on_target and state != page_mod.STATE_NO_COMPOSER and count == last:
                stable += 1
                if stable >= self.SETTLE_POLLS:
                    return "OK"
            else:
                stable = 0
            last = count
            _t.sleep(self.SETTLE_INTERVAL_S)
        return "CONVERSATION_NOT_READY"

    def _drive(self, req: ExecRequest, transport, why: str, page_mod) -> ExecOutcome:
        from quaestor.executors import browser_transport as bt

        target = ("%s/c/%s" % (page_mod.CHATGPT_ORIGIN, self._conversation_id)
                  if self._conversation_id else page_mod.NEW_CONVERSATION_URL)
        try:
            transport.goto(target)
            # WAIT FOR THE THREAD TO BE THE ONE WE ASKED FOR. Page.navigate returns as soon as
            # navigation is INITIATED, and Playwright's goto waits only for 'load' while the
            # message list is fetched after mount. Taking the baseline immediately therefore
            # counted the messages of whatever was on screen a moment ago -- so a PRE-EXISTING
            # assistant turn could satisfy "a new message appeared" and its stale text be
            # captured as this turn's answer. That is the same class of failure as capturing a
            # half-streamed reply, and just as silent.
            settled = self._await_conversation(transport, page_mod, target,
                                               timeout_s=float(req.timeout_s))
            if settled != "OK":
                return self._fail(req, EXIT_NONZERO, settled,
                                  "the target conversation never became ready to accept a "
                                  "packet", started=True)
            ok, reason, baseline = page_mod.submit(transport, str(req.prompt))
        except bt.BrowserUnavailable as exc:
            return self._fail(req, EXIT_NONZERO, exc.reason, str(exc), started=True)
        if not ok:
            # STARTED: the page was reached and refused. That is a measured outcome of a run.
            return self._fail(req, EXIT_NONZERO, reason,
                              "the page would not accept the packet", started=True)

        wait_kwargs = {"baseline": baseline, "timeout_s": float(req.timeout_s)}
        if self._poll_s is not None:
            wait_kwargs["poll_s"] = self._poll_s
        if self._stable_polls is not None:
            wait_kwargs["stable_polls"] = self._stable_polls
        try:
            out = page_mod.await_completion(transport, **wait_kwargs)
        except bt.BrowserUnavailable as exc:
            return self._fail(req, EXIT_NONZERO, exc.reason, str(exc), started=True)

        href = str((out.get("snapshot") or {}).get("href") or "")
        landed = page_mod.conversation_id(href) or self._conversation_id
        try:
            self._write(os.path.join(req.run_dir, "conversation.json"), json.dumps({
                "conversation_id": landed, "href": href, "transport": why,
                "bound_on_entry": bool(self._conversation_id),
                "polls": out.get("polls"), "elapsed_s": out.get("elapsed"),
                "state": out.get("state")}, indent=2).encode("utf-8"))
        except OSError:
            pass

        state = str(out.get("state") or "")
        if state != page_mod.STATE_COMPLETE:
            partial = str(out.get("partial") or "")
            if partial:
                # EVIDENCE, not a result. stdout stays empty so nothing downstream can read it
                # as an answer.
                self._write(os.path.join(req.run_dir, "partial.txt"), partial.encode("utf-8"))
            exit_class = EXIT_TIMEOUT if state in (page_mod.STATE_TIMEOUT,
                                                   page_mod.STATE_NO_ANSWER) else EXIT_NONZERO
            return self._fail(req, exit_class, state,
                              "the conversation did not produce a completed answer "
                              "(%d polls, %.1fs)" % (int(out.get("polls") or 0),
                                                     float(out.get("elapsed") or 0.0)),
                              started=True)

        envelope = synthesise_envelope(out.get("text") or "", conversation_id=landed,
                                       transport=why)
        self._write(req.stdout_path, json.dumps(envelope).encode("utf-8"))
        self._write(req.stderr_path, b"")
        return ExecOutcome(True, 0, EXIT_OK,
                           note="captured a completed answer from conversation %s via %s"
                                % (landed or "(unbound)", why))

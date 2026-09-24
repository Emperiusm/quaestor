"""chatgpt_web -- an OrchestratorEnd holding a real ChatGPT conversation in the operator's browser.

WHAT THIS IS, AND WHAT IT IS NOT
---------------------------------
It is ONE adapter. The relay kernel has no idea its Orchestrator is browser-hosted: it calls the
same ``open/status/identity/resume/send/receive/holds/close`` it calls on an HTTP endpoint, and
every ChatGPT-shaped fact stops here. Nothing in ``relay.kernel``, ``relay.state``,
``relay.effects``, ``relay.observe`` or ``relay.packets`` mentions a browser, and a control walks
the import graph to keep that true.

It is NOT a second relay architecture, and it is NOT the Program Mode seat. ``executors.chatgpt_web``
remains what it was: one bounded turn, one run, one envelope. This is a persistent conversation.
Both drive the same page through the same primitives, which is the point -- the fragile,
vendor-specific half of this feature exists ONCE, in ``executors.chatgpt_web_page``, and a
selector that rots breaks one file for both.

THE THREE HARD PROBLEMS, AND WHERE EACH IS SOLVED
--------------------------------------------------
1. COMPLETION. A streamed answer looks finished at every instant except the last, and forwarding
   a half-written directive is the worst failure this endpoint can have. Solved by REUSING
   ``chatgpt_web_page.await_completion``'s three independent facts (a new message exists; the
   stop affordance is gone; the text is byte-identical across consecutive polls). This module
   adds nothing to that logic and must never weaken it.

2. STALENESS. "There is assistant text on screen" is not "there is an answer to MY message".
   Solved by the ANCHOR: ``send`` captures the assistant-message count BEFORE submitting and
   returns it inside the receipt's ``native_id``; the kernel persists that receipt in its ledger
   and hands it back to ``receive`` as ``after_id``. So the baseline survives a crash, and a
   restarted relay re-derives exactly the same "newer than what?" that the dead one had. An
   in-memory counter would have reset to zero and re-read the previous answer as new.

3. IDENTITY. The relay ledger deduplicates on ``message_id``, so the id must be stable across a
   restart. ChatGPT's DOM may or may not attach a per-message id, and that is measured rather
   than assumed -- see ``chatgpt_web_page.turns``. When it does, that native id is used. When it
   does not, the id is MINTED deterministically from conversation + turn index + content key, so
   recomputing it after a restart yields the same string.

RECONCILIATION IS ASKED OF THE PAGE, NOT OF A FILE
---------------------------------------------------
``holds`` exists so the kernel can resolve a delivery interrupted by a crash without choosing
between duplicating work and dropping it. It answers by reading the LIVE CONVERSATION and
looking for the user turn the relay sent -- matched on a content key computed identically in the
page and here. A local record alone would only prove what this process believed before it died.

And when the page cannot be read, or the thread is long enough that the rendered turn list may
not contain every turn, ``holds`` RAISES rather than answering "no". The kernel turns that into
UNRECONCILABLE_DELIVERY and stops for a human. Guessing "no" would re-send an instruction the
model may already be acting on; guessing "yes" would silently drop a turn.

WHAT THIS ENDPOINT DOES NOT CLAIM
----------------------------------
No lifecycle control: the browser is the operator's, was already open, and is never launched,
closed or authenticated by this code. No billing evidence: a browser session does not say which
plan is paying, and ``executors.chatgpt_web_auth`` refuses to guess. No workspace identity: an
Orchestrator does not touch the repository at all.
"""
from __future__ import annotations

import json
import os
import time

from quaestor.relay.contracts import (END_BUSY, END_FAILED, END_IDLE, END_NOT_AUTHENTICATED,
                                      END_PROVIDER_ERROR, END_SESSION_LOST, END_UNREACHABLE,
                                      END_WORKSPACE_MISMATCH, PROBE_UNSUPPORTED, EndFacts, EndProbe, EndStatus,
                                      FROM_ORCHESTRATOR, RESUME_LOST, RESUME_RESUMED, RelayEnd,
                                      RelayMessage, ROLE_ORCHESTRATOR, SendReceipt)

CHATGPT_WEB_END_INSTRUMENT = "relay.ends.chatgpt_web/1"

#: The anchor scheme. ``send`` mints one, the kernel stores it in its ledger as ``native_id``,
#: and hands it back to ``receive`` as ``after_id``. Everything ``receive`` needs to know
#: "newer than what?" travels in this string, so a restarted process reconstructs the same
#: question the dead one was asking. Versioned because it is persisted: a later scheme must be
#: able to recognise an older anchor rather than misparse it.
#: v2 adds ``user_id`` -- the page's own id for the turn the relay submitted. v1 anchors are
#: still parsed so a ledger written by an earlier build degrades rather than misparsing.
ANCHOR_PREFIX = "cw2"
ANCHOR_PREFIX_V1 = "cw1"
ANCHOR_SEP = "|"

#: WHEN IS "I DID NOT FIND IT" EVIDENCE?
#:
#: MEASURED (2026-08-30): ChatGPT virtualises the thread aggressively -- a conversation with six
#: user turns rendered only the most recent three. So a cap on rendered turns is the WRONG test;
#: the window is small and the site is free to change it.
#:
#: The right test compares the rendered view against what this relay KNOWS it delivered to this
#: conversation. If the page shows at least as many user turns as we have recorded deliveries,
#: the view covers our whole contribution and a miss is real. If it shows fewer, we are looking
#: at a window and a miss proves nothing -- so the question is refused.
#:
#: Kept as a named constant only as a final backstop for an absurdly long render list.
TURN_WINDOW_TRUSTED = 400


def make_anchor(*, conversation_id: str, baseline: int, sent_key: str,
                prior_id: str = "", user_id: str = "") -> str:
    """The receive anchor for one delivery. PURE.

    Everything ``receive`` needs to identify THE answer to THIS message, in descending order of
    strength, so a page that stops supplying one degrades instead of breaking:

        user_id    the page's own id for the turn we submitted. Immune to rendering.
        sent_key   a content key over that turn's text. MEASURED UNRELIABLE for anything
                   containing markdown -- the renderer drops code-fence characters, so a
                   4339-char charter hashed 8857ba87 here and 48c189de in the DOM. Kept only
                   as a fallback for a build that attaches no ids.
        prior_id   the last assistant turn before this delivery.
        baseline   the assistant count before it.

    The kernel persists the whole string, so a restarted relay reconstructs the same question.
    """
    return ANCHOR_SEP.join([ANCHOR_PREFIX, str(conversation_id or ""), str(int(baseline)),
                            str(sent_key or ""), str(prior_id or ""), str(user_id or "")])


def parse_anchor(anchor: str) -> dict:
    """``{conversation_id, baseline, sent_key, ok}``. PURE and TOTAL.

    An unparseable anchor is NOT an error to raise: the kernel hands back whatever it stored,
    and a relay whose ledger predates this scheme must degrade to "no baseline known" rather
    than crash. ``ok`` False means the caller must not trust ``baseline``.
    """
    empty = {"conversation_id": "", "baseline": 0, "sent_key": "", "prior_id": "",
             "user_id": "", "ok": False}
    parts = str(anchor or "").split(ANCHOR_SEP)
    # EVERY SHAPE THIS SCHEME HAS EVER WRITTEN is accepted: 4 and 5 fields under the v1 prefix,
    # 6 under v2. An anchor already sitting in a ledger must degrade to the weaker question it
    # was written with, never be misparsed into a different one.
    if not parts or parts[0] not in (ANCHOR_PREFIX, ANCHOR_PREFIX_V1):
        return empty
    if parts[0] == ANCHOR_PREFIX_V1 and len(parts) not in (4, 5):
        return empty
    if parts[0] == ANCHOR_PREFIX and len(parts) != 6:
        return empty
    try:
        baseline = int(parts[2])
    except (TypeError, ValueError):
        return empty
    return {"conversation_id": parts[1], "baseline": baseline, "sent_key": parts[3],
            "prior_id": parts[4] if len(parts) > 4 else "",
            "user_id": parts[5] if len(parts) > 5 else "", "ok": True}


def preflight(*, endpoint: str = "", prefer: str = "auto", conversation_id: str = "",
              timeout_s: float = 20.0, **_ignored) -> dict:
    """MEASURED readiness: is a browser attached, and is it signed in? Impure. NEVER raises.

    Delegates to the provider's OWN preflight rather than re-deriving the answer, so the relay
    and Program Mode agree about what "this browser is usable" means -- including the part where
    a browser session can never prove which plan is paying.
    """
    from quaestor.executors import chatgpt_web_auth as auth
    from quaestor.core import credential_policy as cp

    decision = auth.run_preflight(endpoint=endpoint, prefer=prefer, timeout_s=timeout_s)
    record = dict(decision.record or {})
    ok = decision.decision == cp.ACCEPT
    return {
        "ok": bool(ok),
        "kind": "chatgpt-web",
        "proves": ("BROWSER_ATTACHED_AND_SIGNED_IN" if ok else (decision.reason or "REFUSED")),
        "detail": decision.detail,
        "page_state": record.get("page_state", ""),
        "transport": record.get("transport", ""),
        "conversation_id": conversation_id or record.get("conversation_id", ""),
        # STATED EVERY TIME, including on success: the accepting answer and the unverifiable
        # billing path are not in tension, and the honest limit must travel with the good news.
        "auth_class": decision.auth_class,
        "instrument": CHATGPT_WEB_END_INSTRUMENT,
    }


class ChatGptWebOrchestratorEnd(RelayEnd):
    """One ChatGPT conversation, driven as the relay's Orchestrator."""

    def __init__(self, *, conversation_id: str = "", endpoint: str = "", prefer: str = "auto",
                 state_path: str = "", poll_s: float = None, stable_polls: int = None,
                 settle_timeout_s: float = 60.0, attach_timeout_s: float = 30.0,
                 open_transport=None, page=None, clock=time.time, sleep=time.sleep):
        self._conversation_id = str(conversation_id or "")
        self._endpoint = str(endpoint or "")
        self._prefer = str(prefer or "auto")
        self._state_path = str(state_path or "")
        self._poll_s = poll_s
        self._stable_polls = stable_polls
        self._settle_timeout_s = float(settle_timeout_s)
        self._attach_timeout_s = float(attach_timeout_s)
        self._open_transport = open_transport      # control seam
        self._page = page                          # control seam
        self._clock = clock
        self._sleep = sleep
        self._transport_why = ""
        self._native_ids_seen = False
        self._record = {"conversation_id": self._conversation_id, "deliveries": {},
                        "replies": {}, "refusals": {}}
        self._load()
        self.facts = EndFacts(
            kind="chatgpt-web", role=ROLE_ORCHESTRATOR,
            # The VENDOR is openai whatever surface carries it -- the same family the direct
            # providers use, so a cross-vendor independence check collides correctly.
            provider_family="openai",
            model="chatgpt-web",
            can_send=True, can_receive=True, can_observe=False,
            # An Orchestrator does not touch the repository. This is not a limitation being
            # confessed; it is the role.
            can_mutate_repo=False,
            # The browser is the operator's. This code never launches, closes, authenticates or
            # navigates away from it beyond the bound conversation.
            manages_lifecycle=False,
            supports_session_resume=False,
            # TRUE, and for a stronger reason than the HTTP endpoint's: the thread lives at the
            # VENDOR, so continuity survives this process dying without the relay having kept a
            # transcript at all.
            supports_conversation_resume=True,
            # DECLARED FALSE, MEASURED AT open(). Whether the page attaches a per-message id is
            # a property of a third party's build, so the floor is "unproven" and the measured
            # answer is reported in open()'s status facts and in the qualification evidence. An
            # endpoint that declared this True and then met a page without ids would be
            # claiming a proof it did not have.
            proves_message_identity=False,
            proves_workspace_identity=False, proves_capability_surface=False,
            proves_readonly_behavior=False, proves_confinement=False,
            limits=(
                "attaches to a browser the operator started and signed into; never launches "
                "one, never handles the credential, and cannot restart it",
                "a browser session carries no evidence of which plan is paying, so the billing "
                "path is permanently UNVERIFIED and is never reported as subscription",
                "message identity is the page's own per-message id when it exposes one, and a "
                "deterministic content key when it does not; which applied is measured at "
                "attach and recorded",
                "a long thread is rendered through a virtualised list, so beyond "
                "%d rendered turns a crash-reconciliation question is REFUSED rather than "
                "answered from a partial view" % TURN_WINDOW_TRUSTED,
                "selectors are a third party's build detail; when they rot this endpoint fails "
                "by name rather than guessing (see executors.chatgpt_web_page.SELECTORS)",
            ))

    # -- the provider modules, resolved late so construction does no I/O -----------------------
    def _page_mod(self):
        if self._page is not None:
            return self._page
        from quaestor.executors import chatgpt_web_page as page_mod
        return page_mod

    def _bt(self):
        from quaestor.executors import browser_transport as bt
        return bt

    def _attach(self):
        """(transport, why). Impure. Raises BrowserUnavailable -- callers translate to a state.

        ATTACHED PER OPERATION, not held for the life of the relay. A relay runs for many
        minutes and a devtools socket held across all of it is a socket that dies somewhere in
        the middle; re-attaching costs one HTTP GET and one websocket connect, and it means a
        browser the operator restarted is simply picked up again on the next call.
        """
        page_mod = self._page_mod()
        bt = self._bt()
        opener = self._open_transport or bt.open_transport
        kwargs = {"prefer": self._prefer, "match": page_mod.CHATGPT_ORIGIN,
                  "timeout": self._attach_timeout_s}
        if self._endpoint:
            kwargs["endpoint"] = self._endpoint
        transport, why = opener(**kwargs)
        self._transport_why = str(why)
        return transport, why

    # -- the sidecar ----------------------------------------------------------------------------
    def _load(self) -> bool:
        """Read the sidecar. False means "there is nothing usable here", never a crash.

        Callers that merely want the conversation binding can treat False as "nothing yet".
        ``holds`` must not: for it the difference between "no record" and "a record that says
        nothing about this id" decides between refusing and answering, so it calls
        ``_load_ok`` instead.
        """
        if not self._state_path or not os.path.isfile(self._state_path):
            return False
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001 - an unreadable sidecar is NO sidecar, not a crash
            return False
        if not isinstance(doc, dict):
            return False
        self._record = {"conversation_id": str(doc.get("conversation_id") or ""),
                        "deliveries": dict(doc.get("deliveries") or {}),
                        "replies": dict(doc.get("replies") or {}),
                        "refusals": dict(doc.get("refusals") or {})}
        if not self._conversation_id:
            self._conversation_id = self._record["conversation_id"]
        return True

    def _load_ok(self) -> bool:
        """Did the sidecar PARSE? Distinct from ``_load``'s "was there anything useful".

        A corrupt file and an honest empty one are different facts, and reconciliation is
        exactly where conflating them turns a lost record into a duplicate delivery.
        """
        try:
            with open(self._state_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(doc, dict):
            return False
        self._record = {"conversation_id": str(doc.get("conversation_id") or ""),
                        "deliveries": dict(doc.get("deliveries") or {}),
                        "replies": dict(doc.get("replies") or {}),
                        "refusals": dict(doc.get("refusals") or {})}
        return True

    def _save(self) -> None:
        """Atomically. A torn sidecar would make a reconciliation question unanswerable."""
        if not self._state_path:
            return
        self._record["conversation_id"] = self._conversation_id
        os.makedirs(os.path.dirname(os.path.abspath(self._state_path)) or ".", exist_ok=True)
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._record, fh)
            # DURABLE, NOT MERELY ATOMIC. os.replace makes the swap all-or-nothing against a
            # concurrent reader; it does nothing about power loss. This record is written
            # BEFORE the submit precisely so a crash between the two is answerable, and a
            # record still sitting in the page cache when the machine dies cannot answer.
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._state_path)

    # -- page helpers ---------------------------------------------------------------------------
    def _target_url(self, page_mod) -> str:
        return ("%s/c/%s" % (page_mod.CHATGPT_ORIGIN, self._conversation_id)
                if self._conversation_id else page_mod.NEW_CONVERSATION_URL)

    def _settle(self, transport, page_mod, *, timeout_s: float = 0.0) -> str:
        """'OK' or a NAMED refusal. Impure. Waits for the bound thread to be ready.

        The same two conditions the Program Mode seat waits for, and for the same measured
        reason: ``Page.navigate`` returns when navigation STARTS, and the message list is
        fetched after mount -- so a baseline taken too early counts the previous page's
        messages, and a PRE-EXISTING answer then satisfies "a new message appeared".
        """
        want = page_mod.conversation_id(self._target_url(page_mod))
        limit = max(2.0, min(float(timeout_s or self._settle_timeout_s), 120.0))
        deadline = float(self._clock()) + limit
        stable, last = 0, None
        while float(self._clock()) < deadline:
            snap = page_mod.probe(transport)
            state = page_mod.classify(snap)
            if state == page_mod.STATE_LOGGED_OUT:
                return page_mod.STATE_LOGGED_OUT
            here = page_mod.conversation_id(str(snap.get("href") or ""))
            on_target = (here == want) if want else True
            count = int(snap.get("count") or 0)
            if on_target and state != page_mod.STATE_NO_COMPOSER and count == last:
                stable += 1
                if stable >= 3:
                    return "OK"
            else:
                stable = 0
            last = count
            self._sleep(0.5)
        return "CONVERSATION_NOT_READY"

    def _measure_identity(self, transport, page_mod) -> dict:
        """Does this build of the page attach its own per-message id? Impure. NEVER raises."""
        try:
            reading = page_mod.turns(transport)
        except Exception as exc:  # noqa: BLE001
            return {"measured": False, "reason": "%s: %s" % (type(exc).__name__, exc)}
        rows = reading.get("turns") or []
        native = page_mod.exposes_message_ids(rows)
        self._native_ids_seen = bool(native)
        return {"measured": True, "turns_rendered": len(rows),
                "native_message_ids": bool(native),
                "identity_source": "page_message_id" if native else "content_key"}

    # -- identity -------------------------------------------------------------------------------
    def _reply_id(self, *, native_id: str, index: int, text: str, page_mod) -> str:
        """A stable id for one assistant turn. PURE given its inputs.

        The native id wins when the page supplies one -- it is the vendor's identity and cannot
        collide. Otherwise the id is DERIVED, never counted: an incrementing counter would reset
        to zero after a restart and make an already-delivered turn look new, which is the single
        failure the whole delivery ledger exists to prevent.
        """
        if str(native_id or "").strip():
            return "%s:%s" % (self._conversation_id or "unbound", str(native_id).strip())
        return "%s:a%03d:%s" % (self._conversation_id or "unbound", int(index),
                                page_mod.text_key(text))

    def holds(self, message_id: str) -> bool:
        """Does the LIVE conversation already contain the delivery the relay made under this id?

        RAISES when it cannot tell. That is the whole contract: the kernel turns an exception
        into UNRECONCILABLE_DELIVERY and stops for a human, which is correct, because the two
        available guesses are "re-send an instruction the model may already be acting on" and
        "silently drop a turn".

        THREE THINGS ADVERSARIAL REVIEW FOUND, all fixed here:

        1. It read whatever tab ``_attach`` reached rather than the bound thread, so a miss in
           some other conversation was reported as a definite "no". It now NAVIGATES to the
           bound conversation first and verifies it landed there.
        2. It read an absent sidecar entry as proof the submit never happened. That inference
           only holds when the record is durable AND readable; a lost, unreadable or never-
           configured sidecar is now a REFUSAL, not a "no".
        3. It trusted a rendered turn list that may be a window of a virtualised thread. It now
           compares what is rendered against what this relay recorded delivering.
        """
        page_mod = self._page_mod()

        # (2) THE SIDECAR MUST BE ABLE TO ANSWER, NOT MERELY BE SILENT.
        if not self._state_path:
            raise RuntimeError(
                "this endpoint was built without a state path, so nothing about delivery %s was "
                "ever persisted and 'was it sent?' has no answer here; refusing to guess"
                % message_id)
        if not os.path.isfile(self._state_path):
            # NO FILE. If THIS process still holds deliveries in memory it can answer from what
            # it knows; the record simply has not been written where a later process could read
            # it. With nothing in memory either, the absence is evidence of a LOST record --
            # the file is written BEFORE every submit -- and the question is unanswerable.
            if not (self._record.get("deliveries") or {}):
                raise RuntimeError(
                    "the delivery record at %s does not exist and this process holds none in "
                    "memory. It is written BEFORE each submit, so its absence is evidence of a "
                    "LOST record rather than of an unsent message; refusing to guess between "
                    "duplicating work and dropping it" % self._state_path)
        elif not self._load_ok():
            raise RuntimeError(
                "the delivery record at %s could not be read, so 'does the conversation already "
                "hold this?' cannot be answered from it; refusing to guess" % self._state_path)

        entry = (self._record.get("deliveries") or {}).get(str(message_id))
        if not entry:
            # A READABLE record that simply does not mention this id. NOW the original
            # inference is sound: the record is written before the submit, so its silence
            # means the submit was never reached.
            return False
        want_key = str(entry.get("key") or "")
        want_id = str(entry.get("user_id") or "")
        if not (want_id or want_key):
            raise RuntimeError(
                "the record has no identity for delivery %s, so the conversation cannot be "
                "asked whether it already holds it" % message_id)

        # (1) ASK THE RIGHT THREAD. The delivery names the conversation it went to; that is the
        # one to read, not whichever tab happens to be in front.
        target = str(entry.get("conversation_id") or self._conversation_id or "")
        transport, _why = self._attach()
        try:
            if target:
                here = page_mod.conversation_id(str(transport.url() or ""), bindable_only=True)
                if here != target:
                    transport.goto("%s/c/%s" % (page_mod.CHATGPT_ORIGIN, target))
                    self._settle(transport, page_mod)
                landed = page_mod.conversation_id(str(transport.url() or ""),
                                                  bindable_only=True)
                if landed != target:
                    raise RuntimeError(
                        "delivery %s went to conversation %s but the browser could not be "
                        "brought to it (it is showing %r); refusing to answer a "
                        "reconciliation question about the wrong thread"
                        % (message_id, target, landed or "no bindable conversation"))
            reading = page_mod.turns(transport)
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

        rows = reading.get("turns") or []
        if not rows:
            raise RuntimeError(
                "the conversation rendered no turns, so 'does it already contain this message?' "
                "has no answer; refusing to guess between duplicating work and dropping it")
        for row in rows:
            if str(row.get("role") or "") != "user":
                continue
            # THE PAGE'S ID FIRST. The content key is a fallback and a MEASURED-unreliable one
            # for any message carrying markdown, so it is never allowed to overrule an id.
            if want_id:
                if str(row.get("id") or "") == want_id:
                    return True
            elif str(row.get("key") or "") == want_key:
                return True

        # (3) NOT FOUND. Whether that is EVIDENCE depends on whether we are looking at the whole
        # thread or at a window of it.
        if not want_id and any(str(r.get("id") or "") for r in rows):
            raise RuntimeError(
                "delivery %s was recorded without the page's own turn id, and this page DOES "
                "attach them -- so the only matcher left is a content key the renderer is known "
                "to defeat. Refusing rather than reporting a turn that may well be there as "
                "absent." % message_id)
        rendered_user_turns = sum(1 for r in rows if str(r.get("role") or "") == "user")
        recorded = [d for d in (self._record.get("deliveries") or {}).values()
                    if str(d.get("conversation_id") or "") == target]
        if rendered_user_turns < len(recorded) or len(rows) >= TURN_WINDOW_TRUSTED:
            raise RuntimeError(
                "the delivery is not among the %d rendered turns (%d of them user turns), but "
                "this relay has recorded %d deliveries to conversation %s -- the page is showing "
                "a WINDOW of a virtualised thread, so a miss is not evidence of absence. "
                "Refusing rather than answering wrongly."
                % (len(rows), rendered_user_turns, len(recorded), target or "(unbound)"))
        return False

    # -- the contract ---------------------------------------------------------------------------
    def open(self, *, adopt_current: bool = False) -> EndStatus:
        """Attach, verify the page is usable, and bind the conversation. NEVER launches a browser.

        ``adopt_current`` decides what an UNBOUND endpoint does with a thread already on screen,
        and the two callers want opposite things:

          * ``start`` -> False. A fresh relay with no ``--conversation-id`` must open its OWN
            thread. Silently continuing whatever the operator happened to be reading would put
            relay traffic into an unrelated personal conversation.
          * ``resume`` -> True. Here the thread on screen may be the only surviving trace of a
            delivery whose id was never recorded -- navigating away destroys the one artefact
            reconciliation could still have used.
        """
        page_mod = self._page_mod()
        bt = self._bt()
        try:
            transport, why = self._attach()
        except bt.BrowserUnavailable as exc:
            return EndStatus(END_UNREACHABLE, self._conversation_id, str(exc))
        except Exception as exc:  # noqa: BLE001
            return EndStatus(END_UNREACHABLE, self._conversation_id,
                             "%s: %s" % (type(exc).__name__, exc))
        try:
            # ADOPT BEFORE NAVIGATING -- the same rule ``send`` follows, and for a sharper
            # reason here. While no thread is bound, ``_target_url`` is the NEW conversation
            # page, so an unconditional goto walks the tab off whatever thread it is showing.
            # ``resume`` calls this BEFORE reconcile(), so on a crash during the first delivery
            # -- the window where the optimistic client-side id is not yet bindable and nothing
            # was recorded -- that navigation destroyed the only artefact that still knew which
            # thread received the message, and guaranteed UNRECONCILABLE.
            here = page_mod.conversation_id(str(transport.url() or ""), bindable_only=True)
            if adopt_current and not self._conversation_id and here:
                self._conversation_id = here
                self._save()
            if self._conversation_id != here:
                transport.goto(self._target_url(page_mod))
            settled = self._settle(transport, page_mod)
            snap = page_mod.probe(transport)
            state = page_mod.classify(snap)
            if state == page_mod.STATE_LOGGED_OUT:
                return EndStatus(END_NOT_AUTHENTICATED, self._conversation_id,
                                 "the attached browser is not signed in to ChatGPT; sign in "
                                 "once in that window (this platform never handles the "
                                 "credential)")
            if state == page_mod.STATE_NO_COMPOSER:
                return EndStatus(END_FAILED, self._conversation_id,
                                 "the attached page has no composer: either it is not a "
                                 "ChatGPT conversation, or the selectors in "
                                 "executors.chatgpt_web_page.SELECTORS have rotted")
            if settled != "OK" and self._conversation_id:
                return EndStatus(END_SESSION_LOST, self._conversation_id,
                                 "conversation %s never became ready to accept a message (%s)"
                                 % (self._conversation_id, settled))
            landed = page_mod.conversation_id(str(snap.get("href") or ""), bindable_only=True)
            if landed:
                self._conversation_id = landed
            identity = self._measure_identity(transport, page_mod)
            self._save()
            return EndStatus(
                END_IDLE if state != page_mod.STATE_GENERATING else END_BUSY,
                self._conversation_id,
                "attached to ChatGPT conversation %s via %s (%s)"
                % (self._conversation_id or "(new, unbound until first send)",
                   self._transport_why, identity.get("identity_source", "unmeasured")),
                facts={"page_state": state, "transport": self._transport_why,
                       "identity": identity, "settled": settled,
                       # The MEASURED answer to the fact declared False at construction.
                       "measured_proves_message_identity":
                           bool(identity.get("native_message_ids")),
                       "instrument": CHATGPT_WEB_END_INSTRUMENT})
        except bt.BrowserUnavailable as exc:
            return EndStatus(END_UNREACHABLE, self._conversation_id, str(exc))
        except Exception as exc:  # noqa: BLE001
            return EndStatus(END_PROVIDER_ERROR, self._conversation_id,
                             "%s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass


    def probe(self) -> EndProbe:
        """DECLINED, and the reason is the point. NEVER raises.

        Exercising this provider means submitting a message, and the only place to submit it is
        the operator's own ChatGPT conversation -- the one the relay exists to preserve. A probe
        that posts "Reply with OK" into somebody's thread has damaged the thing it was
        protecting, and would do it on every start.

        So this endpoint reports PROBE_UNSUPPORTED, which is an honest answer and never a
        passing one: ``measured`` is False, nothing about the model path has been established,
        and the first real exchange is still where a browser fault will surface. What IS
        measured before start is the page state -- signed in, composer present, not mid-stream --
        which ``open()`` and ``status()`` already prove.
        """
        return EndProbe(PROBE_UNSUPPORTED,
                        "a browser-hosted conversation cannot be probed without posting into "
                        "the operator's own thread; page state is measured instead, and the "
                        "model path is not claimed",
                        model=self.facts.model)

    def status(self) -> EndStatus:
        """One liveness reading. NEVER raises."""
        page_mod = self._page_mod()
        try:
            transport, _why = self._attach()
        except Exception as exc:  # noqa: BLE001
            return EndStatus(END_UNREACHABLE, self._conversation_id,
                             "%s: %s" % (type(exc).__name__, exc))
        try:
            snap = page_mod.probe(transport)
        except Exception as exc:  # noqa: BLE001
            return EndStatus(END_UNREACHABLE, self._conversation_id,
                             "%s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass
        state = page_mod.classify(snap)
        mapped = {page_mod.STATE_GENERATING: END_BUSY,
                  page_mod.STATE_LOGGED_OUT: END_NOT_AUTHENTICATED,
                  page_mod.STATE_NO_COMPOSER: END_FAILED}.get(state, END_IDLE)
        return EndStatus(mapped, self._conversation_id, "page state %s" % state,
                         facts={"page_state": state, "href": snap.get("href", ""),
                                "assistant_turns": snap.get("count", 0)})

    def identity(self) -> str:
        return self._conversation_id

    def resume(self, identity: str) -> tuple:
        """Re-bind to a conversation the VENDOR still holds.

        Stronger than a stateless provider's resume and honestly so: the thread and its whole
        context live at ChatGPT, not in a transcript this process kept, so continuity here does
        not depend on the dead process having written anything down.
        """
        self._conversation_id = str(identity or self._conversation_id)
        if not self._conversation_id:
            return RESUME_LOST, ("no conversation id was recorded, so there is no thread to "
                                 "re-bind to")
        wanted = self._conversation_id
        self._load()
        self._conversation_id = wanted
        # ADOPT: see ``open``. If the id was never recorded -- the crash-during-first-delivery
        # window -- the thread still on screen is the only trace left of where the message went.
        st = self.open(adopt_current=True)
        if not st.usable:
            return RESUME_LOST, ("conversation %s could not be re-bound: %s"
                                 % (wanted, st.detail))
        # LANDING SOMEWHERE IS NOT LANDING HERE. A thread that has been deleted, or that belongs
        # to another account, redirects to a NEW empty conversation -- which opens perfectly
        # well and would otherwise be reported as a successful resume. That would fabricate the
        # single property restart-recovery exists to establish, so the id is compared.
        if self._conversation_id != wanted:
            return RESUME_LOST, (
                "asked for ChatGPT conversation %s but the browser landed on %r; the thread is "
                "gone, renamed, or belongs to a different account -- refusing to call a "
                "different conversation a resumed one"
                % (wanted, self._conversation_id or "(a new, empty thread)"))
        return RESUME_RESUMED, (
            "re-bound to ChatGPT conversation %s in the operator's browser; the thread and its "
            "whole context live at the vendor and were never in this process"
            % self._conversation_id)

    def send(self, text: str, *, message_id: str) -> SendReceipt:
        """Type one relay turn into the bound conversation and submit it.

        The receipt's ``native_id`` is the ANCHOR (see ``make_anchor``). The kernel persists it,
        so the "newer than what?" baseline survives this process.
        """
        page_mod = self._page_mod()
        bt = self._bt()
        try:
            transport, _why = self._attach()
        except bt.BrowserUnavailable as exc:
            return SendReceipt(False, reason="%s: %s" % (exc.reason, exc))
        except Exception as exc:  # noqa: BLE001
            return SendReceipt(False, reason="%s: %s" % (type(exc).__name__, exc))
        try:
            # ADOPT BEFORE NAVIGATING. While no thread is bound, ``_target_url`` is the NEW
            # conversation page -- so navigating unconditionally would abandon a thread this
            # relay had already started and begin a second one. That is reachable: the id is
            # not bindable until the server replaces the optimistic one, so a first receive
            # that failed would leave the relay unbound with a real conversation on screen.
            here = page_mod.conversation_id(str(transport.url() or ""), bindable_only=True)
            if not self._conversation_id and here:
                self._conversation_id = here
                self._save()
            if self._conversation_id != here:
                transport.goto(self._target_url(page_mod))
            settled = self._settle(transport, page_mod)
            if settled != "OK":
                return SendReceipt(False, reason=settled,
                                   detail={"conversation_id": self._conversation_id})
            # THE LAST ASSISTANT MESSAGE BEFORE THIS DELIVERY. This, not the count, is what
            # makes "a new answer arrived" answerable on a thread the page has virtualised.
            before_snap = page_mod.probe(transport)
            prior_id = str(before_snap.get("last_id") or "")
            # AND THE LAST USER TURN BEFORE IT, so the one that appears next is provably OURS.
            prior_user_id = ""
            try:
                prior_user_id = page_mod.last_user_id(transport)
            except Exception:  # noqa: BLE001
                prior_user_id = ""
            sent_key = page_mod.text_key(text)
            # RECORDED BEFORE THE SUBMIT. ``holds`` needs the content key to ask the page
            # whether this delivery landed; writing it afterwards would leave a crash between
            # submit and record unanswerable, which is the exact case reconciliation exists for.
            self._record.setdefault("deliveries", {})[str(message_id)] = {
                "key": sent_key, "at": float(self._clock()),
                "conversation_id": self._conversation_id}
            self._save()

            ok, reason, baseline = page_mod.submit(transport, str(text))
            if not ok:
                return SendReceipt(False, reason=str(reason or "SUBMIT_REFUSED"),
                                   detail={"conversation_id": self._conversation_id})
            # THE PAGE'S OWN ID FOR THE TURN WE JUST SENT. It is what makes the reply
            # identifiable at all: the content key cannot be trusted because the renderer does
            # not echo what was typed (see ``make_anchor``).
            #
            # WAIT FOR IT TO CHANGE, do not read it once. The submit returns as soon as the
            # click lands, and the turn is rendered a moment later -- so a single read can
            # return the id of the PREVIOUS user turn, which would anchor the whole exchange to
            # somebody else's message. Comparing against what was there before the submit is
            # what makes the id provably ours.
            user_id = self._await_own_user_id(transport, page_mod, prior_user_id)
            if user_id:
                self._record["deliveries"][str(message_id)]["user_id"] = user_id
                self._save()
            href = str(transport.url() or "")
            # BINDABLE ONLY. Immediately after submitting a NEW thread the URL carries an
            # optimistic client-side id that the server later replaces with a different one;
            # recording it would bind the relay to a URL that never exists. Not finding a
            # bindable id here is normal -- ``receive`` re-reads it once the answer lands and
            # the URL has settled.
            landed = page_mod.conversation_id(href, bindable_only=True)
            if landed:
                self._conversation_id = landed
                self._record["deliveries"][str(message_id)]["conversation_id"] = landed
                self._save()
            return SendReceipt(
                True,
                native_id=make_anchor(conversation_id=self._conversation_id,
                                      baseline=int(baseline), sent_key=sent_key,
                                      prior_id=prior_id, user_id=user_id),
                detail={"conversation_id": self._conversation_id, "baseline": int(baseline),
                        "prior_id": prior_id, "user_id": user_id,
                        "transport": self._transport_why})
        except bt.BrowserUnavailable as exc:
            return SendReceipt(False, reason="%s: %s" % (exc.reason, exc))
        except Exception as exc:  # noqa: BLE001
            return SendReceipt(False, reason="%s: %s" % (type(exc).__name__, exc))
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    def _conversation_matches(self, href: str, anchor: dict) -> tuple:
        """(ok, detail). Is the page we are reading the thread the anchor names? PURE-ish.

        THE CHECK ADVERSARIAL REVIEW FOUND MISSING, and it was the worst gap in this endpoint.
        ``make_anchor`` has always carried the conversation id and nothing ever read it, so
        ``receive`` returned the answer from whatever ChatGPT tab ``_attach`` happened to reach
        and then rebound the endpoint to that thread. A second tab, or the operator clicking
        another conversation during a round trip, was enough to feed an unrelated stale answer
        to the execution agent as a directive.

        The identical check already existed in ``resume`` -- "LANDING SOMEWHERE IS NOT LANDING
        HERE" -- and ``receive`` is the one page-reading operation where being on the wrong page
        yields wrong CONTENT marked complete rather than a named refusal.

        An anchor naming no bindable conversation is the first delivery into a brand-new thread,
        where the optimistic client-side id is deliberately not recorded. That case adopts.
        """
        want = str(anchor.get("conversation_id") or "")
        here = self._page_mod().conversation_id(href, bindable_only=True)
        if not want:
            return True, "the anchor names no thread yet (first delivery into a new one)"
        if not here:
            return False, ("the page is not on a bindable conversation (href %r) while the "
                           "anchor names %s" % (href[:120], want))
        if here != want:
            return False, ("the browser is showing conversation %s but this turn was sent to "
                           "%s -- refusing to read another thread's answer as the reply"
                           % (here, want))
        return True, "on conversation %s" % here

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0):
        """Wait for the COMPLETED answer TO THE TURN THIS ANCHOR NAMES.

        Three things make this THE reply rather than merely A reply, and all three come from the
        anchor the kernel persisted:

          * ``conversation_id`` -- the page must be the thread the message went to;
          * ``sent_key``        -- the answer must FOLLOW our own user turn, located by content
                                   key, so another writer interleaving a turn cannot supply it;
          * the refusal ledger  -- an assistant turn already judged incomplete is not accepted
                                   later merely because its stop affordance went away.

        Every non-COMPLETE outcome is a RelayMessage with ``complete=False`` and a NAMED error:
        the kernel must record why a relay paused, and "the browser went away", "the model is
        still typing" and "that is a different conversation" are different facts.
        """
        page_mod = self._page_mod()
        bt = self._bt()
        anchor = parse_anchor(after_id)
        try:
            transport, _why = self._attach()
        except Exception as exc:  # noqa: BLE001
            return self._failed_turn("%s: %s" % (END_UNREACHABLE, exc))
        try:
            # DO NOT SETTLE HERE. ``_settle`` waits for the message count to STOP changing,
            # which is exactly what a page that is answering will not do -- so re-settling
            # before the wait spent the whole settle budget fighting a healthy generation and
            # then started polling with almost none of the receive timeout left. MEASURED:
            # a probe run burned two full 60s settles and never reached the wait.
            snap = page_mod.probe(transport)
            state = page_mod.classify(snap)
            if state == page_mod.STATE_LOGGED_OUT:
                return self._failed_turn(
                    "%s: the browser is no longer signed in to ChatGPT" % END_NOT_AUTHENTICATED)
            if state == page_mod.STATE_NO_COMPOSER:
                return self._failed_turn(
                    "%s: the attached page is no longer a usable ChatGPT conversation"
                    % END_SESSION_LOST)
            ok, detail = self._conversation_matches(str(snap.get("href") or ""), anchor)
            if not ok:
                return self._failed_turn("%s: %s" % (END_WORKSPACE_MISMATCH, detail))

            sent_key = str(anchor.get("sent_key") or "")
            user_id = str(anchor.get("user_id") or "")
            # THE SAME SEAMS THE REST OF THE ENDPOINT USES. Without them the wait reached for
            # the real clock while every other part of a controlled run used an injected one,
            # so a control could not bound it and a poll interval of zero became a spin.
            wait_kwargs = {"timeout_s": float(timeout_s or page_mod.DEFAULT_TIMEOUT_S),
                           "clock": self._clock, "sleep": self._sleep}
            if self._poll_s is not None:
                wait_kwargs["poll_s"] = self._poll_s
            if self._stable_polls is not None:
                wait_kwargs["stable_polls"] = self._stable_polls
            if user_id or sent_key:
                out = page_mod.await_reply(transport, user_key=sent_key, user_id=user_id,
                                           **wait_kwargs)
                anchored = "user_turn_id" if user_id else "user_turn_content_key"
            else:
                # NO KEY IN THE ANCHOR. Only reachable for a ledger written before this scheme;
                # degrade to the older question rather than refuse a relay mid-flight, and SAY
                # SO in the provenance so a reader is never misled about which guarantee held.
                out = page_mod.await_completion(
                    transport, baseline=int(anchor["baseline"]),
                    prior_id=str(anchor.get("prior_id") or ""), **wait_kwargs)
                anchored = "legacy_anchor"

            state = str(out.get("state") or "")
            native = str(out.get("id") or (out.get("snapshot") or {}).get("last_id") or "")
            text = str(out.get("text") or "")
            if state != page_mod.STATE_COMPLETE:
                partial = str(out.get("partial") or "")
                # THE PARTIAL IS NEVER THE TEXT. It is reported in the error so an operator can
                # see what was on screen, and ``complete=False`` keeps the kernel from
                # forwarding any of it as work. It is also REMEMBERED -- see below.
                self._remember_refusal(after_id, native_id=native, partial=partial,
                                       state=state, page_mod=page_mod)
                return self._failed_turn(
                    "%s after %d polls / %.1fs%s"
                    % (state, int(out.get("polls") or 0), float(out.get("elapsed") or 0.0),
                       (" (partial on screen: %d chars)" % len(partial)) if partial else ""))

            # A TURN REFUSED ONCE IS NOT ACCEPTED LATER UNCHANGED. A stream that died mid-token
            # loses its stop affordance and stops mutating, which makes it satisfy every
            # completion fact BETTER than a healthy one -- so on the next receive for the same
            # anchor the truncated text would come back as the finished answer. Comparing what
            # was refused against what is now offered tells "it finished" from "it is still the
            # same dead half-answer".
            stale = self._previously_refused(after_id, native_id=native, text=text,
                                             page_mod=page_mod)
            if stale:
                return self._failed_turn(stale)

            snapshot = out.get("snapshot") or {}
            href = str(snapshot.get("href") or "")
            landed = page_mod.conversation_id(href, bindable_only=True)
            if landed:
                self._conversation_id = landed
            index = int(snapshot.get("assistant_index") or snapshot.get("count") or 0)
            message_id = self._reply_id(native_id=native, index=index, text=text,
                                        page_mod=page_mod)
            self._record.setdefault("replies", {})[message_id] = {
                "at": float(self._clock()), "index": index,
                "native": bool(native), "key": page_mod.text_key(text)}
            self._save()
            return RelayMessage(
                message_id=message_id, direction=FROM_ORCHESTRATOR, text=text, complete=True,
                observed_at=float(self._clock()), conversation_id=self._conversation_id,
                provenance={"kind": "chatgpt-web", "provider_family": "openai",
                            "conversation_id": self._conversation_id,
                            "transport": self._transport_why,
                            "identity_source": "page_message_id" if native else "content_key",
                            "anchored_by": anchored,
                            "assistant_turn_index": index,
                            "rendered_turns": snapshot.get("rendered"),
                            "anchor_parsed": bool(anchor["ok"]),
                            "polls": int(out.get("polls") or 0),
                            "elapsed_s": float(out.get("elapsed") or 0.0),
                            "instrument": CHATGPT_WEB_END_INSTRUMENT})
        except bt.BrowserUnavailable as exc:
            return self._failed_turn("%s: %s" % (exc.reason, exc))
        except Exception as exc:  # noqa: BLE001
            return self._failed_turn("%s: %s: %s"
                                     % (END_PROVIDER_ERROR, type(exc).__name__, exc))
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    #: How long to wait for the page to render the turn we just submitted, and how often to look.
    #: Short: the turn appears optimistically, so this is a rendering delay, not a network one.
    OWN_TURN_TIMEOUT_S = 15.0
    OWN_TURN_POLL_S = 0.25
    #: Consecutive EMPTY reads before concluding this page attaches no ids at all. Must be more
    #: than one: a brand-new thread reads empty for the moment before it renders.
    OWN_TURN_EMPTY_READS = 8

    def _await_own_user_id(self, transport, page_mod, prior_user_id: str) -> str:
        """The page's id for the turn THIS call submitted, or "" if it never appeared.

        Returns only an id that DIFFERS from the last user turn before the submit. An empty
        answer is honest and survivable -- the anchor falls back to the content key and says so
        -- whereas the previous turn's id would silently anchor the exchange to the wrong
        message, which is the failure this whole identity scheme exists to prevent.
        """
        deadline = float(self._clock()) + self.OWN_TURN_TIMEOUT_S
        empty_reads = 0
        while float(self._clock()) < deadline:
            try:
                now = page_mod.last_user_id(transport)
            except Exception:  # noqa: BLE001 - a read that failed is simply not an answer yet
                now = ""
            if now and now != str(prior_user_id or ""):
                return now
            # A page that attaches no ids at all will never satisfy this, and spending the whole
            # budget proving a known absence makes every send slow. But "no id yet" is also what
            # a BRAND-NEW thread looks like for the moment before it renders -- giving up on the
            # first empty read there abandoned the id on exactly the conversation that needed it
            # most. So it takes several consecutive empty reads, not one.
            empty_reads = empty_reads + 1 if not now else 0
            if empty_reads >= self.OWN_TURN_EMPTY_READS:
                return ""
            self._sleep(self.OWN_TURN_POLL_S)
        return ""

    # -- the refusal ledger ----------------------------------------------------------------------
    def _remember_refusal(self, anchor: str, *, native_id: str, partial: str, state: str,
                          page_mod) -> None:
        """Record that THIS assistant turn, in THIS shape, was judged not-finished."""
        if not partial and not native_id:
            return
        self._record.setdefault("refusals", {})[str(anchor)] = {
            "native_id": str(native_id), "key": page_mod.text_key(partial),
            "state": str(state), "at": float(self._clock())}
        self._save()

    def _previously_refused(self, anchor: str, *, native_id: str, text: str, page_mod) -> str:
        """A refusal reason when the offered turn is byte-for-byte what was refused before.

        UNCHANGED is the whole test. If the model really did carry on, the text differs and so
        does its key, so a genuinely finished answer is accepted on the next poll. What is
        rejected is only the case where nothing moved -- a dead stream wearing a finished
        stream's affordances.
        """
        prior = (self._record.get("refusals") or {}).get(str(anchor))
        if not prior:
            return ""
        same_turn = bool(native_id) and str(prior.get("native_id") or "") == str(native_id)
        same_text = str(prior.get("key") or "") == page_mod.text_key(text)
        if same_turn and same_text:
            return ("%s: this exact assistant turn was already judged %s and its text has not "
                    "changed since. A stream that died mid-token loses its stop affordance and "
                    "stops mutating, so it satisfies every completion check -- refusing to "
                    "forward it as a finished answer."
                    % (page_mod.STATE_STREAM_ERROR, prior.get("state")))
        return ""

    def _failed_turn(self, error: str) -> RelayMessage:
        """A non-answer, shaped so the kernel records a named pause and forwards nothing."""
        return RelayMessage(
            message_id="%s:err:%d" % (self._conversation_id or "unbound", int(self._clock())),
            direction=FROM_ORCHESTRATOR, text="", complete=False,
            observed_at=float(self._clock()), conversation_id=self._conversation_id,
            error=str(error))

    def close(self) -> None:
        """Persist the sidecar. THE BROWSER IS NOT CLOSED: it is the operator's."""
        try:
            self._save()
        except Exception:  # noqa: BLE001
            pass

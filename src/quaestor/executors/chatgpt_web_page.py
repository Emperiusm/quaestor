"""chatgpt_web_page -- everything that knows what a ChatGPT page looks like. One module.

WHY ALL THE FRAGILITY LIVES HERE
---------------------------------
Selectors rot. The page this drives is a third party's product, redesigned without notice and
A/B-tested between sessions, so the honest design goal is not "never break" -- it is "break in
exactly one file, loudly, with the cause named". ``SELECTORS`` below is the first thing to check
when this feature stops working, and it is deliberately the only place a CSS selector appears in
this codebase.

Everything here runs through ``browser_transport``'s four-method interface, so it is identical
whether the browser is reached by the stdlib CDP client or by Playwright. That is why the
interface was kept small: two copies of THIS logic would drift, and the copy nobody exercised
would be the one that broke.

COMPLETION DETECTION IS THE WHOLE PROBLEM
------------------------------------------
A streamed answer looks like a finished answer at every instant except the last. Capturing one
early puts a truncated directive into a decision ledger that later runs read as binding -- the
single worst failure this feature can have, and a silent one.

So "done" requires THREE independent facts, not one:

    1. a NEW assistant message exists (the count rose above the pre-submit baseline);
    2. the generating affordance is gone (no stop button);
    3. the message text is byte-identical across ``STABLE_POLLS`` consecutive polls.

Any one alone is a known false positive. The stop button flickers between tokens on some
builds; text is briefly stable mid-stream whenever a chunk is slow; and a new message element
appears the instant generation STARTS. Requiring all three, with the text check last, is what
makes an early capture unlikely rather than merely unlucky.

ONE SNAPSHOT PER POLL
---------------------
``PROBE_JS`` returns every fact in a single evaluation. Reading them one at a time would let the
page change between reads and produce a snapshot that never existed -- a stop button from before
the last token and text from after it, which is precisely the combination that reads as
"complete".

WHAT THIS MODULE WILL NOT DO
-----------------------------
No fingerprint or user-agent alteration, no CAPTCHA handling, no retry through an interstitial.
When the page presents a challenge or a logged-out state, this returns a NAMED state and stops.
"""
from __future__ import annotations

import json
import re
import time as _time

CHATGPT_PAGE_INSTRUMENT = "chatgpt_web_page/1"

CHATGPT_ORIGIN = "https://chatgpt.com"
NEW_CONVERSATION_URL = CHATGPT_ORIGIN + "/"

#: THE FIRST THING TO CHECK WHEN THIS BREAKS. Every CSS selector this codebase contains lives
#: here. Each is a LIST of candidates tried in order, because the page ships variants and a
#: single selector is a single point of rot.
SELECTORS = {
    "composer": ["#prompt-textarea", "textarea[data-id]", "div[contenteditable='true']"],
    "send": ["[data-testid='send-button']", "button[aria-label*='Send']"],
    "stop": ["[data-testid='stop-button']", "button[aria-label*='Stop']"],
    "assistant": ["[data-message-author-role='assistant']"],
    "login": ["[data-testid='login-button']", "a[href*='/auth/login']"],
    #: Best-effort evidence that the stream ENDED BADLY, split by WHAT MAKES THE MATCH MEAN
    #: SOMETHING. See STATE_STREAM_ERROR for what this can and cannot establish.
    #:
    #: PRESENCE IS THE SIGNAL. A retry affordance is rendered only when there is something to
    #: retry, so finding one is itself the evidence.
    "error": ["[data-testid='regenerate-button']", "button[aria-label*='Regenerate']"],
    #: PRESENCE IS NOT THE SIGNAL; NON-EMPTY TEXT IS.
    #:
    #: MEASURED against the live signed-in site (2026-08-29): chatgpt.com renders a PERMANENT,
    #: EMPTY screen-reader live region --
    #:
    #:     <div aria-live="assertive" aria-atomic="true" class="sr-only"
    #:          id="aria-notify-live-region-assertive" role="alert"><span></span></div>
    #:
    #: -- on every page, healthy or not. Treating its mere presence as an error made ``classify``
    #: return STREAM_ERROR for a perfectly good conversation, which would abort every run at the
    #: first poll. The bug was invisible to the unit suite because those controls feed
    #: ``classify`` a synthetic ``error`` boolean; only a real page could show it. So the
    #: classifier's rule was right and its INPUT was wrong, and the fix belongs here.
    "error_text": ["[role='alert']", ".result-streaming-error"],
    #: Identity. Every turn in the thread, and the per-message id the page attaches to it when
    #: it attaches one at all -- see ``turns`` for why both are read and what happens when the
    #: second is absent.
    "turn": ["[data-message-author-role]"],
    "message_id": ["[data-message-id]"],
}

#: ATTRIBUTE names, DERIVED from the table above rather than retyped. The selector-hygiene
#: control requires every selector-shaped literal to live inside ``SELECTORS``; deriving keeps
#: that true and keeps a rename to one place.
TURN_ROLE_ATTR = SELECTORS["turn"][0].strip("[]")
MESSAGE_ID_ATTR = SELECTORS["message_id"][0].strip("[]")

# ---- named states -----------------------------------------------------------------------------
STATE_COMPLETE = "COMPLETE"
STATE_GENERATING = "GENERATING"
STATE_LOGGED_OUT = "LOGGED_OUT"
STATE_NO_COMPOSER = "NO_COMPOSER"
STATE_TIMEOUT = "TIMEOUT"
STATE_NO_ANSWER = "NO_ANSWER"
#: The page is showing an error/retry affordance beside a half-written answer.
#:
#: THE HONEST LIMIT, STATED. When a stream dies mid-token the page removes the stop affordance
#: and stops mutating the text -- which is indistinguishable, from the affordances alone, from
#: a stream that finished. So this state is BEST EFFORT: when an error affordance is present we
#: name it and refuse; when it is not, a truncated answer can still satisfy all three completion
#: facts and be returned.
#:
#: What actually protects the ledger in that case is downstream, and deliberately so: the seat's
#: response must be one parseable JSON document, and a truncated one fails
#: ``strategist.validate_directive_response`` as DIRECTIVE_INVALID. Defence in depth beats a
#: DOM signal this module cannot verify exists.
STATE_STREAM_ERROR = "STREAM_ERROR"

#: Consecutive identical polls before text is believed final. Three at the default interval is
#: ~3s of silence -- longer than any inter-token gap observed, short enough not to add latency
#: worth caring about on a turn that already took many seconds.
STABLE_POLLS = 3
POLL_INTERVAL_S = 1.0
DEFAULT_TIMEOUT_S = 600.0


def _selector_js(name: str) -> str:
    """A JS expression returning the first matching element for a named selector list. PURE."""
    return "(%s)" % " || ".join(
        "document.querySelector(%s)" % json.dumps(sel) for sel in SELECTORS[name])


def _nonempty_js(name: str) -> str:
    """A JS expression: does any element match ``name`` AND carry non-empty text? PURE.

    The counterpart to ``_selector_js`` for the selectors whose PRESENCE means nothing. See
    ``SELECTORS["error_text"]``.
    """
    return "[%s].some(s => Array.from(document.querySelectorAll(s)).some(" \
           "n => ((n.innerText || n.textContent || '').trim().length > 0)))" \
           % ", ".join(json.dumps(sel) for sel in SELECTORS[name])


#: One snapshot of every fact a poll needs. See "ONE SNAPSHOT PER POLL" above.
PROBE_JS = """(() => {
  const assistants = Array.from(document.querySelectorAll(%(assistant)s));
  const last = assistants.length ? assistants[assistants.length - 1] : null;
  return {
    href: location.href,
    composer: !!%(composer)s,
    send: !!%(send)s,
    stop: !!%(stop)s,
    login: !!%(login)s,
    error: (!!%(error)s) || (%(error_text)s),
    count: assistants.length,
    text: last ? (last.innerText || last.textContent || "") : "",
    last_id: last ? (last.getAttribute(%(id_attr)s)
                     || (last.closest(%(id_sel)s)
                         ? last.closest(%(id_sel)s).getAttribute(%(id_attr)s) : "")
                     || (last.querySelector(%(id_sel)s)
                         ? last.querySelector(%(id_sel)s).getAttribute(%(id_attr)s) : "")
                     || "") : ""
  };
})()"""


def probe_expression() -> str:
    """The probe, with selectors substituted. PURE."""
    return PROBE_JS % {
        "assistant": json.dumps(SELECTORS["assistant"][0]),
        "composer": _selector_js("composer"),
        "send": _selector_js("send"),
        "stop": _selector_js("stop"),
        "login": _selector_js("login"),
        "error": _selector_js("error"),
        "error_text": _nonempty_js("error_text"),
        "id_attr": json.dumps(MESSAGE_ID_ATTR),
        "id_sel": json.dumps(SELECTORS["message_id"][0]),
    }


def probe(transport) -> dict:
    """One consistent snapshot of the page. Impure. Returns {} when the page answers nothing."""
    got = transport.evaluate(probe_expression())
    return dict(got) if isinstance(got, dict) else {}


def classify(snapshot) -> str:
    """The page's state from one snapshot, ignoring history. PURE.

    Logged-out is checked FIRST: a signed-out page has no composer either, and reporting the
    downstream symptom would send an operator hunting a selector change that never happened.
    """
    snap = snapshot if isinstance(snapshot, dict) else {}
    if snap.get("login") or "/auth/login" in str(snap.get("href") or ""):
        return STATE_LOGGED_OUT
    if not snap.get("composer"):
        return STATE_NO_COMPOSER
    if snap.get("stop"):
        return STATE_GENERATING
    if snap.get("error"):
        # Checked AFTER generating: the retry affordance can be present beside an earlier turn
        # while a new one is still streaming, and calling that an error would abort a healthy
        # run. Checked BEFORE complete: an error beside a stopped stream is the case this state
        # exists for.
        return STATE_STREAM_ERROR
    return STATE_COMPLETE


# ---------------------------------------------------------------------------------------------
# TURN IDENTITY
# ---------------------------------------------------------------------------------------------
# A relay must be able to ask two questions a Program Mode seat never had to: "is this answer
# the one to MY message, or an older one?", and after a crash, "does this conversation already
# contain the message I was in the middle of sending?".
#
# Answering them from ``count`` and ``text`` alone -- which is all the poll snapshot carries --
# is not good enough. A count resets when the page reloads, and text is not an identity: the
# same instruction sent twice is indistinguishable from one instruction seen twice.
#
# So identity is read from the page, in this order of strength:
#
#   1. the page's OWN per-message id, when it attaches one (``MESSAGE_ID_ATTR``). Strongest:
#      it is the vendor's identity, not ours.
#   2. a CONTENT KEY over the normalised turn text. Weaker but sufficient for the question the
#      relay actually asks about USER turns, which is "did MY exact text land here?" -- the
#      relay knows byte-for-byte what it sent, so it can look for exactly that.
#
# The content key is computed IN THE PAGE and mirrored in Python, so a match is decided on
# identical inputs. FNV-1a is chosen over a cryptographic digest for one reason: it is
# reproducible in four lines of JavaScript with no async crypto API, and this is a lookup key,
# not a security boundary.
FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193


#: THE WHITESPACE CLASS, WRITTEN OUT ONCE AND SHARED BY BOTH NORMALISERS.
#:
#: ``\s`` IS NOT THE SAME SET IN THE TWO LANGUAGES, and the difference is not academic:
#:
#:     Python's ``\s`` matches U+001C-U+001F and U+0085; JavaScript's does not.
#:     JavaScript's ``\s`` and ``String.trim()`` match U+FEFF; Python's ``\s`` and
#:     ``str.strip()`` do not.
#:
#: A byte-order mark surviving inside a file the agent quoted is enough to make the two sides
#: hash the SAME landed turn to two different keys -- so ``holds`` would miss a delivery that
#: really is on the page and the kernel would send it a second time. That is precisely the
#: duplicate-delivery failure the content key exists to prevent, hidden in a character class.
#:
#: So neither language's shorthand is used. This is the UNION of both, spelled out, and the
#: JavaScript twin is GENERATED from it rather than retyped.
WHITESPACE_CODEPOINTS = (
    "\t\n\v\f\r\x1c\x1d\x1e\x1f\x20\x85\xa0 "
    "           "
    "    　﻿"
)

#: The same set as a JS/Python character-class body, escaped so it is safe in both.
_WS_CLASS = "".join("\\u%04x" % ord(c) for c in WHITESPACE_CODEPOINTS)
_WS_RE = re.compile("[%s]+" % _WS_CLASS)


def normalise(text) -> str:
    """Collapse whitespace the way the page does when it renders. PURE.

    The DOM is not a byte-faithful echo of what was typed: it re-wraps, and ``innerText``
    collapses runs of whitespace. Comparing raw strings would therefore miss a turn that IS
    ours, so both sides are normalised identically before hashing -- see
    ``WHITESPACE_CODEPOINTS`` for why "identically" needed spelling out.
    """
    return _WS_RE.sub(" ", str(text or "")).strip(WHITESPACE_CODEPOINTS)


def text_key(text) -> str:
    """The content key for one turn. PURE. Mirrors ``TEXT_KEY_JS`` exactly.

    Iterates UTF-16 CODE UNITS, not codepoints, because that is what JavaScript's
    ``charCodeAt`` yields. An astral character would otherwise hash differently on the two
    sides and a turn that matched would look like one that did not.
    """
    h = FNV_OFFSET
    units = normalise(text).encode("utf-16-le")
    for i in range(0, len(units), 2):
        h ^= units[i] | (units[i + 1] << 8)
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return "%08x" % h


#: The same function, in the page. GENERATED from the shared class above rather than retyped:
#: two hand-written copies of a character set are two copies that can disagree, and this pair
#: already did. ``trim()`` is replaced by an explicit strip of the same class for the same
#: reason -- the built-in trims JavaScript's set, not this one.
TEXT_KEY_JS = """((t) => {
  const WS = /[%(ws)s]/;
  const RUN = /[%(ws)s]+/g;
  let s = String(t == null ? "" : t).replace(RUN, " ");
  let a = 0, b = s.length;
  while (a < b && WS.test(s.charAt(a))) a++;
  while (b > a && WS.test(s.charAt(b - 1))) b--;
  s = s.slice(a, b);
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return ("0000000" + h.toString(16)).slice(-8);
})""" % {"ws": _WS_CLASS}

#: Every turn in the thread, with both identities. Deliberately does NOT return turn text: a
#: long conversation would be megabytes on every poll, and the relay only ever needs to MATCH a
#: turn, never to read one back.
TURNS_JS = """(() => {
  const key = %(text_key)s;
  const nodes = Array.from(document.querySelectorAll(%(turn)s));
  return {
    href: location.href,
    turns: nodes.map((n, i) => {
      const holder = n.closest(%(id_sel)s) || n.querySelector(%(id_sel)s) || n;
      const raw = (n.innerText || n.textContent || "");
      return {
        index: i,
        role: n.getAttribute(%(role_attr)s) || "",
        id: holder.getAttribute(%(id_attr)s) || "",
        key: key(raw),
        len: raw.length
      };
    })
  };
})()"""


def turns_expression() -> str:
    """The turn probe, with selectors substituted. PURE."""
    return TURNS_JS % {
        "text_key": TEXT_KEY_JS,
        "turn": json.dumps(SELECTORS["turn"][0]),
        "id_sel": json.dumps(SELECTORS["message_id"][0]),
        "role_attr": json.dumps(TURN_ROLE_ATTR),
        "id_attr": json.dumps(MESSAGE_ID_ATTR),
    }


def turns(transport) -> dict:
    """``{href, turns: [{index, role, id, key, len}, ...]}``. Impure.

    Returns ``{"href": "", "turns": []}`` when the page answers nothing -- an unreadable page is
    an EMPTY reading, and callers must not treat it as "the thread is empty" (see
    ``ends.chatgpt_web``, which refuses to answer a reconciliation question from one).
    """
    got = transport.evaluate(turns_expression())
    if not isinstance(got, dict):
        return {"href": "", "turns": []}
    rows = got.get("turns")
    return {"href": str(got.get("href") or ""),
            "turns": [dict(r) for r in rows if isinstance(r, dict)]
            if isinstance(rows, list) else []}


#: ONE SNAPSHOT, ANCHORED TO A SPECIFIC USER TURN.
#:
#: ``PROBE_JS`` answers "what is the last assistant message on this page?". That is the wrong
#: question for a relay, and adversarial review demonstrated both ways it goes wrong:
#:
#:   * the page may not be the conversation the caller thinks it is (another tab, or the
#:     operator clicked a different thread), and
#:   * even on the right thread, the last assistant turn is not necessarily the answer to the
#:     caller's message -- the operator can type into the same thread while the relay waits,
#:     and their answer would be returned as the relay's.
#:
#: So this asks the RIGHT question: find the user turn whose content key is ``want``, and report
#: the first assistant turn AFTER it. Everything else -- the affordances completion needs, the
#: href identity needs -- comes back in the same evaluation, because reading them separately
#: would produce a snapshot the page was never in.
REPLY_JS = """(() => {
  const key = %(text_key)s;
  const want = %(want)s;
  const wantId = %(want_id)s;
  const idOf = (n) => {
    const h = n.closest(%(id_sel)s) || n.querySelector(%(id_sel)s) || n;
    return h.getAttribute(%(id_attr)s) || "";
  };
  const nodes = Array.from(document.querySelectorAll(%(turn)s));
  let ui = -1;
  for (let i = 0; i < nodes.length; i++) {
    const r = nodes[i].getAttribute(%(role_attr)s) || "";
    if (r !== "user") continue;
    // THE PAGE'S OWN ID WINS. A content key is computed over innerText, and the renderer does
    // not echo what was typed -- it drops markdown fence characters, so a message containing a
    // code block hashes differently on the two sides and would never be found.
    if (wantId) { if (idOf(nodes[i]) === wantId) ui = i; }
    else if (key(nodes[i].innerText || nodes[i].textContent || "") === want) ui = i;
  }
  let ai = -1;
  if (ui >= 0) {
    for (let i = ui + 1; i < nodes.length; i++) {
      if ((nodes[i].getAttribute(%(role_attr)s) || "") === "assistant") { ai = i; break; }
    }
  }
  const a = ai >= 0 ? nodes[ai] : null;
  const holder = a ? (a.closest(%(id_sel)s) || a.querySelector(%(id_sel)s) || a) : null;
  return {
    href: location.href,
    composer: !!%(composer)s,
    login: !!%(login)s,
    stop: !!%(stop)s,
    error: (!!%(error)s) || (%(error_text)s),
    rendered: nodes.length,
    user_found: ui >= 0,
    user_index: ui,
    assistant_found: ai >= 0,
    assistant_index: ai,
    id: holder ? (holder.getAttribute(%(id_attr)s) || "") : "",
    text: a ? (a.innerText || a.textContent || "") : ""
  };
})()"""


def reply_expression(user_key: str, user_id: str = "") -> str:
    """The reply probe for one specific user turn, with selectors substituted. PURE."""
    return REPLY_JS % {
        "text_key": TEXT_KEY_JS,
        "want": json.dumps(str(user_key or "")),
        "want_id": json.dumps(str(user_id or "")),
        "turn": json.dumps(SELECTORS["turn"][0]),
        "id_sel": json.dumps(SELECTORS["message_id"][0]),
        "role_attr": json.dumps(TURN_ROLE_ATTR),
        "id_attr": json.dumps(MESSAGE_ID_ATTR),
        "composer": _selector_js("composer"),
        "login": _selector_js("login"),
        "stop": _selector_js("stop"),
        "error": _selector_js("error"),
        "error_text": _nonempty_js("error_text"),
    }


def reply_probe(transport, user_key: str, user_id: str = "") -> dict:
    """One snapshot of the answer to ONE user turn. Impure. ``{}`` when the page says nothing."""
    got = transport.evaluate(reply_expression(user_key, user_id))
    return dict(got) if isinstance(got, dict) else {}


#: The id the page attached to the LAST user turn, or "". Impure.
#:
#: Read straight after a submit so the relay learns what the vendor called the message it just
#: sent. That id is the anchor everything else hangs off, and it is worth one extra evaluation
#: because the alternative -- hashing rendered text -- is defeated by the renderer.
LAST_USER_ID_JS = """(() => {
  const nodes = Array.from(document.querySelectorAll(%(turn)s))
    .filter(n => (n.getAttribute(%(role_attr)s) || "") === "user");
  if (!nodes.length) return "";
  const n = nodes[nodes.length - 1];
  const h = n.closest(%(id_sel)s) || n.querySelector(%(id_sel)s) || n;
  return h.getAttribute(%(id_attr)s) || "";
})()"""


def last_user_id(transport) -> str:
    """The page's id for the newest user turn. Impure. "" when it attaches none."""
    got = transport.evaluate(LAST_USER_ID_JS % {
        "turn": json.dumps(SELECTORS["turn"][0]),
        "role_attr": json.dumps(TURN_ROLE_ATTR),
        "id_sel": json.dumps(SELECTORS["message_id"][0]),
        "id_attr": json.dumps(MESSAGE_ID_ATTR)})
    return str(got or "")


#: The reply was located, but the turn it belongs to is not on screen, so nothing can be said.
STATE_USER_TURN_NOT_RENDERED = "USER_TURN_NOT_RENDERED"


def await_reply(transport, *, user_key: str, user_id: str = "",
                timeout_s: float = DEFAULT_TIMEOUT_S,
                poll_s: float = POLL_INTERVAL_S, stable_polls: int = STABLE_POLLS,
                clock=None, sleep=None) -> dict:
    """Poll until the answer TO ``user_key`` is final. Impure. The relay's completion path.

    Keeps ``await_completion``'s three facts and only changes what FACT 1 means: instead of "an
    assistant turn exists that was not there before", it is "the assistant turn that FOLLOWS MY
    user turn exists". That is a strictly stronger question, and it is immune to both the
    virtualised-count plateau and to another writer interleaving a turn.

    Returns ``{state, text, id, polls, elapsed, snapshot}``; ``text`` is non-empty only for
    COMPLETE, and a partial is reported separately so a caller can show it without any risk of
    forwarding it.
    """
    now = clock or _time.monotonic
    rest = sleep or _time.sleep
    started = now()
    last_text = None
    stable = 0
    polls = 0
    snapshot: dict = {}
    saw_user = False

    while (now() - started) < float(timeout_s):
        polls += 1
        snapshot = reply_probe(transport, user_key, user_id)
        state = classify(snapshot)
        if state in (STATE_LOGGED_OUT, STATE_NO_COMPOSER, STATE_STREAM_ERROR):
            return {"state": state, "text": "", "id": str(snapshot.get("id") or ""),
                    "partial": str(snapshot.get("text") or ""), "polls": polls,
                    "elapsed": now() - started, "snapshot": snapshot}
        if snapshot.get("user_found"):
            saw_user = True
        # FACT 1, ANCHORED: the answer to MY message must exist.
        if not snapshot.get("assistant_found"):
            stable = 0
            last_text = None
            rest(poll_s)
            continue
        # FACT 2: the generating affordance must be gone.
        if state == STATE_GENERATING:
            stable = 0
            last_text = str(snapshot.get("text") or "")
            rest(poll_s)
            continue
        # FACT 3: the text must be byte-identical across consecutive polls.
        text = str(snapshot.get("text") or "")
        if text and text == last_text:
            stable += 1
            if stable >= int(stable_polls):
                return {"state": STATE_COMPLETE, "text": text,
                        "id": str(snapshot.get("id") or ""), "polls": polls,
                        "elapsed": now() - started, "snapshot": snapshot}
        else:
            stable = 0
        last_text = text
        rest(poll_s)

    partial = str(snapshot.get("text") or "")
    # NEVER SAW THE USER TURN AT ALL is a different failure from "the answer never finished",
    # and it wants different advice: the thread scrolled past it, or this is the wrong page.
    if not saw_user:
        return {"state": STATE_USER_TURN_NOT_RENDERED, "text": "", "partial": "",
                "id": "", "polls": polls, "elapsed": now() - started, "snapshot": snapshot}
    return {"state": STATE_TIMEOUT if partial else STATE_NO_ANSWER,
            "text": "", "partial": partial, "id": str(snapshot.get("id") or ""),
            "polls": polls, "elapsed": now() - started, "snapshot": snapshot}


def exposes_message_ids(turn_rows) -> bool:
    """Did the page attach its own id to EVERY turn it rendered? PURE.

    All-or-nothing on purpose. A page that ids some turns and not others cannot be used as an
    identity source without a rule for the gaps, and inventing one would be exactly the kind of
    quiet guess this platform refuses. Partial coverage therefore reads as "no native identity"
    and the content key carries it instead.
    """
    rows = [r for r in (turn_rows or []) if isinstance(r, dict)]
    return bool(rows) and all(str(r.get("id") or "").strip() for r in rows)


#: A SERVER-ASSIGNED conversation id, as it appears in the URL.
#:
#: MEASURED against the live site (2026-08-29): the moment a new thread is submitted the page
#: puts an OPTIMISTIC, CLIENT-SIDE id in the URL first --
#:
#:     https://chatgpt.com/c/WEB:6cace67f-d164-4fed-9bc6-84acdac59d12
#:
#: -- and replaces it with the real one a few seconds later:
#:
#:     https://chatgpt.com/c/6a93a855-96c8-83ea-8003-9cb2a12bc9ba
#:
#: They are DIFFERENT ids, not a prefix of one another. Binding to the placeholder produces a
#: durable record pointing at a URL that will never exist, so a later resume navigates nowhere
#: and reports the thread lost. Anything that is not a bare UUID is therefore NOT BINDABLE.
_SERVER_CONVERSATION_ID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def is_bindable_conversation_id(value) -> bool:
    """Is this an id a later navigation can actually reach? PURE.

    False for the client-side placeholder above, for an empty string, and for anything else the
    page may put in that slot. Callers bind only what this accepts and re-read later for the
    rest -- an unbindable id is a "not yet", never an error.
    """
    return bool(_SERVER_CONVERSATION_ID.match(str(value or "").strip()))


def conversation_id(href: str, *, bindable_only: bool = False) -> str:
    """The conversation id in a ChatGPT URL, or ''. PURE.

    ``https://chatgpt.com/c/<id>`` -> ``<id>``. A URL with no id means the thread has not been
    created yet, which is a legitimate state and not an error.

    ``bindable_only`` additionally rejects the optimistic client-side id described above. It
    defaults False so the Program Mode seat -- which only ever REPORTS the id it landed on, in
    one bounded turn -- keeps its existing behaviour unchanged; a relay, which will navigate
    back to this id after a crash, passes True.
    """
    text = str(href or "")
    marker = "/c/"
    if marker not in text:
        return ""
    tail = text.split(marker, 1)[1]
    for cut in ("?", "#", "/"):
        tail = tail.split(cut, 1)[0]
    tail = tail.strip()
    if bindable_only and not is_bindable_conversation_id(tail):
        return ""
    return tail


#: Sets the composer's value the way a REAL keystroke would. A framework-controlled input
#: ignores a plain ``value =`` assignment: React tracks the previous value on the node and
#: swallows the synthetic event as a no-op, so the send button stays disabled and the turn
#: silently does nothing. Calling the native setter first is what makes the framework observe
#: the change.
SUBMIT_JS = """((text) => {
  const el = %(composer)s;
  if (!el) return "NO_COMPOSER";
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
    const proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, text);
  } else {
    el.textContent = text;
  }
  el.dispatchEvent(new Event("input", { bubbles: true }));
  return "OK";
})(%(text)s)"""

SEND_JS = """(() => {
  const btn = %(send)s;
  if (!btn) return "NO_SEND";
  if (btn.disabled) return "SEND_DISABLED";
  btn.click();
  return "OK";
})()"""


def fill_composer(transport, text: str) -> str:
    """Put ``text`` in the composer. Impure. Returns 'OK' or a named refusal."""
    return str(transport.evaluate(SUBMIT_JS % {"composer": _selector_js("composer"),
                                               "text": json.dumps(str(text))}) or "")


def press_send(transport) -> str:
    """Click send. Impure. Returns 'OK' or a named refusal."""
    return str(transport.evaluate(SEND_JS % {"send": _selector_js("send")}) or "")


def submit(transport, text: str) -> tuple:
    """(ok, reason, baseline_count). Impure.

    The assistant-message count is captured BEFORE sending and returned, because "a new message
    appeared" is one of the three facts completion requires and it is only meaningful relative
    to what was there first.
    """
    before = probe(transport)
    state = classify(before)
    if state in (STATE_LOGGED_OUT, STATE_NO_COMPOSER):
        return False, state, 0
    baseline = int(before.get("count") or 0)
    filled = fill_composer(transport, text)
    if filled != "OK":
        return False, filled or STATE_NO_COMPOSER, baseline
    sent = press_send(transport)
    if sent != "OK":
        return False, sent, baseline
    return True, "", baseline


def await_completion(transport, *, baseline: int, prior_id: str = "",
                     timeout_s: float = DEFAULT_TIMEOUT_S,
                     poll_s: float = POLL_INTERVAL_S, stable_polls: int = STABLE_POLLS,
                     clock=None, sleep=None) -> dict:
    """Poll until the answer is FINAL. Impure. ``clock``/``sleep`` are the control seams.

    Returns ``{state, text, polls, elapsed, snapshot}``. ``text`` is non-empty only when
    ``state`` is COMPLETE -- a partial capture is never returned as a result, though the
    partial text IS reported on TIMEOUT so the operator can see what was on screen without
    anything downstream mistaking it for an answer (the caller records it as evidence, not as
    the result; see ``chatgpt_web``).
    """
    now = clock or _time.monotonic
    rest = sleep or _time.sleep
    started = now()
    last_text = None
    stable = 0
    polls = 0
    snapshot: dict = {}

    while (now() - started) < float(timeout_s):
        polls += 1
        snapshot = probe(transport)
        state = classify(snapshot)
        if state in (STATE_LOGGED_OUT, STATE_NO_COMPOSER, STATE_STREAM_ERROR):
            # A STREAM_ERROR carries its partial text out as evidence, never as a result: the
            # answer on screen is half an answer, and returning it would put a truncated
            # directive into a ledger later runs read as binding.
            return {"state": state, "text": "",
                    "partial": str(snapshot.get("text") or ""), "polls": polls,
                    "elapsed": now() - started, "snapshot": snapshot}
        count = int(snapshot.get("count") or 0)
        text = str(snapshot.get("text") or "")

        # FACT 1: a new message must exist. An element appears the instant generation STARTS,
        # so this is necessary and nowhere near sufficient.
        #
        # HOW "NEW" IS DECIDED, AND WHY IT IS NOT ALWAYS THE COUNT. MEASURED on the live site
        # (2026-08-30): chatgpt.com VIRTUALISES a long thread -- it renders only the most recent
        # turns, so as new ones arrive old ones leave the DOM and the assistant COUNT STOPS
        # RISING. A relay that waited for `count > baseline` on a conversation past that window
        # therefore waited forever while the answer sat on screen. (Program Mode never hit this
        # because its seat takes exactly one turn.)
        #
        # So when the caller supplies the id of the last assistant message it saw BEFORE
        # submitting, and the page attaches per-message ids, "new" means "the last assistant
        # message is a DIFFERENT one" -- which is true regardless of how many turns the page
        # has since scrolled out of the DOM. The count remains the fallback for a build that
        # attaches no ids, where it is still the best available signal.
        if str(prior_id or "") and str(snapshot.get("last_id") or ""):
            is_new = str(snapshot.get("last_id")) != str(prior_id)
        else:
            is_new = count > baseline
        if not is_new:
            stable = 0
            last_text = None
            rest(poll_s)
            continue
        # FACT 2: the generating affordance must be gone. It flickers between tokens on some
        # builds, which is why its absence resets nothing but is required every poll.
        if state == STATE_GENERATING:
            stable = 0
            last_text = text
            rest(poll_s)
            continue
        # FACT 3: the text must be byte-identical across consecutive polls. Text is briefly
        # stable mid-stream whenever a chunk is slow, so one identical pair proves nothing.
        if text and text == last_text:
            stable += 1
            if stable >= int(stable_polls):
                return {"state": STATE_COMPLETE, "text": text, "polls": polls,
                        "elapsed": now() - started, "snapshot": snapshot}
        else:
            stable = 0
        last_text = text
        rest(poll_s)

    partial = str(snapshot.get("text") or "")
    return {"state": STATE_TIMEOUT if partial else STATE_NO_ANSWER,
            "text": "", "partial": partial, "polls": polls,
            "elapsed": now() - started, "snapshot": snapshot}

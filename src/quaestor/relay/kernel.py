"""kernel -- the relay loop. Transport-neutral, provider-free, and paranoid about delivering
the same turn twice.

WHAT THIS FILE OWNS
-------------------
    exchange identity          which turn number we are on
    message identity           endpoint-native ids, recorded before anything moves
    deduplication              a turn is delivered at most once, across restarts
    causal linkage             which message provoked which
    bounded context            packets, not transcripts
    loop protection            repetition, no-progress, ceilings
    persistence and recovery   the ledger in ``state``
    governance hooks           the three gates in ``effects``
    independent observation    ``observe``, taken by this process

WHAT IT DOES NOT OWN
--------------------
Strategy. The kernel never composes an instruction, never decides whether work is finished, and
never edits anything. If a change here starts to look like judgement about the engineering task,
it belongs in the Orchestrator.

THE LOOP, AND WHY IT IS SHAPED THIS WAY
---------------------------------------
Each ``step`` moves exactly ONE message and then waits for exactly one reply:

    take the pending message  ->  DELIVERING  ->  send  ->  DELIVERED
                              ->  observe the repository (execution side only)
                              ->  gate
                              ->  record the reply as the next pending message

Writing DELIVERING *before* the send is the only reason a crash is recoverable rather than
ambiguous. Doing the repository reading around the execution turn -- rather than trusting the
agent's account -- is the only reason the Orchestrator is told the truth. Everything else is
bookkeeping in service of those two.

NO PROVIDER IMPORTS. The kernel is handed endpoint objects; it never builds one, never names
one, and contains no branch on which provider is in use.
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping

from quaestor.relay import corroborate as corroborate_mod
from quaestor.relay import effects as effects_mod
from quaestor.relay import observe as observe_mod
from quaestor.relay import packets as packets_mod
from quaestor.relay import state as state_mod
from quaestor.relay.contracts import (COUNTERPART, FROM_EXECUTION, FROM_ORCHESTRATOR,
                                      FROM_RELAY, PROBE_REFUSED, RESUME_RESUMED,
                                      RESUME_UNSUPPORTED, ROLE_EXECUTION, ROLE_ORCHESTRATOR,
                                      computed_assurance)

KERNEL_INSTRUMENT = "relay.kernel/1"

# Terminal / pause reasons. Every one of these is printed by ``relay status``; none is a bare
# boolean, because "the relay stopped" without a name is not a diagnosis.
STOP_OBJECTIVE_COMPLETE = "OBJECTIVE_COMPLETE"
STOP_MAX_EXCHANGES = "MAX_EXCHANGES_REACHED"
STOP_MAX_DURATION = "MAX_DURATION_REACHED"
STOP_NO_PROGRESS = "NO_PROGRESS"
STOP_ORCHESTRATOR_LOOP = "ORCHESTRATOR_REPEATING"
STOP_EXECUTION_LOOP = "EXECUTION_REPEATING"
STOP_ORCHESTRATOR_DISCONNECT = "ORCHESTRATOR_DISCONNECTED"
STOP_EXECUTION_DISCONNECT = "EXECUTION_DISCONNECTED"
STOP_OWNER_HOLD = "OWNER_HOLD"
STOP_UNRECONCILABLE = "UNRECONCILABLE_DELIVERY"
STOP_START_REFUSED = "START_REFUSED"
STOP_OPERATOR = "STOPPED_BY_OPERATOR"
#: The Orchestrator kept claiming completion and independent measurement kept disagreeing. This
#: is NOT ``OBJECTIVE_COMPLETE`` and must never be reported as it: the relay stopped because the
#: claim could not be corroborated, which is a different outcome for a human to act on.
STOP_COMPLETION_UNCORROBORATED = "COMPLETION_UNCORROBORATED"
#: An endpoint that is still healthy kept returning INCOMPLETE turns until the bounded retry ran
#: out. Distinct from ``*_DISCONNECTED``, which means the endpoint itself is gone: one is a
#: provider that will not finish a sentence, the other is a provider that is not there.
STOP_EXECUTION_INCOMPLETE = "EXECUTION_INCOMPLETE"
STOP_ORCHESTRATOR_INCOMPLETE = "ORCHESTRATOR_INCOMPLETE"
#: A model-exercising probe proved the provider path is unusable. Distinct from *_DISCONNECTED
#: (the endpoint is gone) and from *_INCOMPLETE (it will not finish a sentence): here the
#: endpoint is healthy and the MODEL behind it is not, which is a different thing to fix.
STOP_ORCHESTRATOR_UNUSABLE = "ORCHESTRATOR_MODEL_UNUSABLE"
STOP_EXECUTION_UNUSABLE = "EXECUTION_MODEL_UNUSABLE"

#: The Orchestrator's completion marker. A MACHINE COMPLETION MARKER is one of the few places
#: the architecture allows a structured token in an otherwise natural conversation: "the work is
#: done" is a claim the relay must act on, and inferring it from prose would either end runs
#: early or never end them.
COMPLETION_MARKER = "RELAY-OBJECTIVE-COMPLETE"


#: Characters that may hug the marker without changing what was said: whitespace, quoting,
#: markdown emphasis, brackets and terminal punctuation. Deliberately NO letters and NO digits,
#: and deliberately not ``-``, which is a marker character -- a hyphen treated as decoration
#: would read "NOT-RELAY-OBJECTIVE-COMPLETE" as the marker itself. Deliberately not ``?``
#: either: a question mark does not decorate, it SPEAKS -- it is the whole difference between
#: asserting the marker and asking about it, and "Is this RELAY-OBJECTIVE-COMPLETE?" must not
#: stop a relay. Nor ``~``, whose only use around a token is the ``~~strikethrough~~`` a model
#: writes to RETRACT it. ``!`` stays, because an exclamation asserts what it ends.
_MARKER_DECORATION = " \t\"'`*_()[]{}<>.,:;!"

#: Quote characters. A marker wrapped in these INSIDE a sentence is MENTIONED, not uttered:
#: 'Reply ending with the single line "RELAY-OBJECTIVE-COMPLETE"' is the protocol instruction
#: the relay prints on every packet, quoted back at it.
_QUOTES = ("\"", "'", "`")

#: Words that DENY what they govern.
_NEGATIONS = frozenset((
    "not", "cannot", "unable", "never", "no", "none", "nor", "neither", "without",
    "refuse", "refuses", "refused", "refusing",
    "decline", "declines", "declined", "declining",
    "withhold", "withholds", "withholding", "withheld",
))

#: Words that DEFER what they govern. A promise to say the marker is not the marker, and it is
#: the single most common way a model says "not yet" -- the list above catches none of it,
#: because "I will write RELAY-OBJECTIVE-COMPLETE once CI is green" contains no negative word at
#: all while meaning exactly the opposite of a claim.
_DEFERRALS = frozenset((
    "will", "shall", "would", "gonna",
    "yet", "premature", "prematurely", "pending",
    "defer", "defers", "deferring", "deferred",
    "before", "until", "once", "unless", "after",
))

#: Verbs of UTTERING the marker. These are what make a negation or a deferral be ABOUT the claim
#: rather than about the work: "no failures" negates a problem and is the ordinary shape of
#: success, while "cannot write" negates the saying and is a denial. Kept to verbs that take the
#: marker as their object -- generic ones ("report", "answer") appear in success prose too.
_UTTERANCE = frozenset((
    "write", "writes", "writing", "wrote", "written",
    "say", "says", "saying", "said",
    "state", "states", "stating", "stated",
    "emit", "emits", "emitting", "emitted",
    "declare", "declares", "declaring", "declared",
    "claim", "claims", "claiming", "claimed",
    "reply", "replies", "replying", "replied",
    "send", "sends", "sending", "sent",
    "output", "outputs", "print", "prints",
    "mark", "marks", "marking", "marked",
))

#: Distancing that no single word carries. "far from RELAY-OBJECTIVE-COMPLETE" is a denial built
#: entirely out of words that are innocent apart.
_DISTANCING = ("far from", "short of", "yet to", "instead of", "rather than",
               "holding back", "hold back", "hold off", "stop short", "stops short")

#: A word, for this purpose, KEEPS its underscores and inner hyphens. The evidence the charter
#: asks for is full of identifiers, and splitting them into English turned the proof of success
#: into a denial of it: "test_not_found now passes" was read as carrying "not", "--no-verify"
#: as carrying "no", "assert_not_called" as carrying "not".
_WORD = re.compile(r"[a-z][a-z'_-]*")

#: Characters that may trail a sentence without hiding how it ended, so ``**Done.**`` is still
#: recognised as a sentence that CLOSED.
_CLOSERS = " \t\"'`*_)]}>"


def _denies_marker(prose: str) -> bool:
    """Does the clause that GOVERNS the marker deny or defer it? PURE.

    Only the last SENTENCE counts, because a negation in a sentence that has already closed is
    not about the claim: "The tests are not failing. RELAY-OBJECTIVE-COMPLETE" is a claim.

    Within that sentence a negative word is not enough, and that is the whole of the rule. Both
    directions of error are fatal and they meet here:

    * Accepting a denial writes OBJECTIVE_COMPLETE into the durable record, stops the work and
      bypasses corroboration -- indistinguishable from real success.
    * Refusing a genuine claim is not one lost exchange, it is DETERMINISTIC: a model that
      phrases completion one way phrases it that way again on every retry, so the run burns to
      MAX_EXCHANGES with the objective met and never recorded. A blunt word list did exactly
      that, because ordinary success states an ABSENCE -- "all 42 tests pass with no failures",
      "no blockers remain", "nothing is outstanding".

    So the negation must be shown to govern the CLAIM: either nothing stands between it and the
    marker ("the objective is not RELAY-OBJECTIVE-COMPLETE", "I withhold it"), or it governs a
    verb of uttering the marker ("I cannot write ...", "I will emit ..."). A negation governing
    anything else is talking about the work, and talk about the work is what success sounds like.
    """
    clause = re.split(r"[.;!?]", prose)[-1].lower()
    if any(phrase in clause for phrase in _DISTANCING):
        return True
    words = _WORD.findall(clause)
    for i, word in enumerate(words):
        if not (word in _NEGATIONS or word in _DEFERRALS
                or word.endswith("n't") or word.endswith("'ll")):
            continue
        if i == len(words) - 1:
            return True                   # nothing stands between the denial and the marker
        if any(w in _UTTERANCE for w in words[i + 1:]):
            return True                   # it denies the SAYING, not the work
    return False


def claims_completion(text: str) -> bool:
    """Did this turn CLAIM the objective is met? PURE.

    The marker must be the LAST THING SAID, and it must be said AS A WHOLE UTTERANCE rather than
    merely fall at the end of a sentence. Both halves are load-bearing, and each was learned from
    a failure:

    * A bare substring test cannot be used: every packet the relay sends the Orchestrator ends by
      naming the token verbatim to teach the protocol, so the model is handed the exact trigger
      string on every turn. Measured against a bare ``in`` test, the turn "The suite is still
      red. I am NOT writing RELAY-OBJECTIVE-COMPLETE yet. Agent: fix the 401." ended the relay
      OBJECTIVE_COMPLETE at exchange 1 having delivered no instruction at all.
    * ``endswith`` on the last line is not enough either, and fails the same way for the same
      reason. "The objective is not RELAY-OBJECTIVE-COMPLETE", "I cannot write
      RELAY-OBJECTIVE-COMPLETE", "I am unable to say RELAY-OBJECTIVE-COMPLETE" and "I did not
      write RELAY-OBJECTIVE-COMPLETE" are four ordinary English DENIALS that all end in the
      marker, and all four used to stop the relay OBJECTIVE_COMPLETE. That is the worst failure
      available here: in the durable record it is indistinguishable from real success, it stops
      the work, and corroboration never runs because the claim is accepted before it is reached.

    So a claim is recognised only when the marker ends the last non-blank line as its own token
    -- nothing but decoration after it, no word or hyphen glued in front of it -- and the clause
    that carries it neither denies nor defers it (see ``_denies_marker``).

    ON CASE AND PUNCTUATION, the two ways this test could be loosened:

    * CASE IS NOT FOLDED. The marker is a machine token, printed uppercase in the charter and in
      every packet; a case-insensitive test would also match the model's own lowercase PROSE
      about the marker, which is precisely the widened surface this bug lives in. A model that
      emits it in lowercase has not followed the protocol, and the cost of saying so is one more
      exchange.
    * PUNCTUATION IS IGNORED ONLY WHERE IT DECORATES, never where it speaks. ``**MARKER**`` and
      ``MARKER.`` are the same claim as ``MARKER`` and used to be refused outright, which is the
      other direction of error -- a relay that cannot recognise success burns every run to its
      ceiling. But only the non-word characters immediately around the marker are dropped: a WORD
      after it ("... RELAY-OBJECTIVE-COMPLETE yet") still refuses, because that word is the rest
      of the sentence and the sentence is what is being tested. ``?`` is not dropped at all, and
      a marker QUOTED inside a sentence is a mention of the token rather than an utterance of it:
      both are ways of talking ABOUT the marker, which is the surface this bug lives in.

    A LINE BREAK IS NOT A FULL STOP. The charter asks for the marker on a line of its own, so
    that is the line a model reaches for when it displays or wraps the token -- "I cannot write:"
    on one line and the marker on the next is a denial written in the charter's own shape. When
    the marker's line carries no prose and the line above did not end its sentence, that line is
    where the governing clause lives, so that is where it is looked for.
    """
    lines = [ln.strip() for ln in str(text or "").strip().splitlines() if ln.strip()]
    if not lines:
        return False
    line = lines[-1]
    idx = line.rfind(COMPLETION_MARKER)
    if idx < 0:
        return False
    tail = line[idx + len(COMPLETION_MARKER):]
    if tail.strip(_MARKER_DECORATION):
        return False                      # a word -- or a "?" -- follows: not the last thing said
    if idx and (line[idx - 1].isalnum() or line[idx - 1] == "-"):
        return False                      # glued to a preceding word, e.g. NOT-<marker>
    prose = line[:idx]
    if (prose[-1:] in _QUOTES and tail[:1] == prose[-1:]
            and prose.strip(_MARKER_DECORATION)):
        return False                      # quoted mid-sentence: the token is MENTIONED, not said
    if not prose.strip(_MARKER_DECORATION) and len(lines) > 1:
        above = lines[-2]
        if not above.rstrip(_CLOSERS).endswith((".", "!", "?")):
            prose = above + " " + prose   # the sentence runs on into the marker's own line
    return not _denies_marker(prose)


def persisted_policy(config) -> dict:
    """The policy fields written into a relay's durable record. PURE. THE ONLY WRITER.

    Reader and writer must not drift. ``relay.cli.apply_recorded_policy`` reads exactly these
    keys, and a field added to ``RelayConfig`` without being added here is a field every resume
    silently resets to a flag default -- which is the same defect three consecutive reviews of
    this relay have found, in three different fields. A control asserts the two sets match.
    """
    return {"max_exchanges": int(config.max_exchanges),
            "max_duration_s": float(config.max_duration_s),
            "receive_timeout_s": float(config.receive_timeout_s),
            "completion_checks": list(config.completion_checks or ()),
            "completion_requires_repo_change": bool(config.completion_requires_repo_change),
            "completion_attempt_limit": int(config.completion_attempt_limit),
            "check_timeout_s": float(config.check_timeout_s),
            "incomplete_retry_limit": int(config.incomplete_retry_limit),
            "probe_endpoints": bool(config.probe_endpoints),
            "observe_repo": bool(config.observe_repo)}


#: The durable record of an authority requirement, and of its discharge. Events, not a new
#: table: the relay's event log is already append-only, already survives a restart, and is
#: already what ``_release_owner_held`` reads. A second store for approvals is exactly what a
#: system with one signed owner channel must not grow.
EVENT_HOLD_RAISED = "relay.owner_hold.raised"
EVENT_HOLD_DISCHARGED = "relay.owner_hold.discharged"

#: WHY THE RELAY STOPPED IS THE ONE FIELD THAT TELLS AN OPERATOR WHAT TO FIX, so a resume
#: that supersedes it says so durably and names what it replaced. ``request_stop`` already
#: refuses to overwrite a stop reason with a generic one; a resume is not entitled to what
#: an operator's own stop is refused.
EVENT_RESUME_SUPERSEDED = "relay.resume.superseded"
PREVIOUS_STOP_REASON = "previous_stop_reason"


#: A hold we can see but cannot identify. It has no capability set, so NO grant can match it and
#: nothing discharges it automatically -- which is the point.
HOLD_UNIDENTIFIED = "unidentified"


def outstanding_owner_holds(st, relay_id: str) -> list:
    """Every authority requirement raised and not since discharged. Impure. NEVER raises.

    WALKED IN ORDER, and this is the whole correctness of it. The first version subtracted the
    set of discharged ids from the set of raised ids, and because a hold id is content-addressed
    the SAME requirement refused a second time carries the SAME id -- so one discharge absorbed
    every future raising of it, forever. An owner who granted a push once, whose grant then
    expired or was revoked, would have had every later push waved through: the hold was born
    discharged, nothing blocked, and the column was actively cleared. That is the original bug
    with an extra step, and it also silently neutralised the expiry enforcement shipped beside
    it. A discharge settles the raising it followed, not the identity for all time.

    ``st.events`` returns oldest-first, so the last event for an id decides.

    UNREADABLE IS NOT EMPTY. If the row itself cannot be read, no owner decision can be shown
    to have happened, so one is not assumed: the relay blocks. Unreadable EVENTS alone do not,
    because a readable owner_hold column still answers the question on its own.

    TWO FAIL-CLOSED RECOVERIES for rows that predate this record, both reached only when the
    relay has raised NOTHING -- an owner_hold column with no event of its own:

      * the requirement is RECONSTRUCTED from the last refusing gate event, which already
        carried the capabilities and the effect class. That is evidence, not a guess.
      * failing that, an UNIDENTIFIED hold is reported. It carries no capabilities, so nothing
        can match it and no resume discharges it; an owner who wants that relay to continue
        stops it and starts the work again.
    """
    open_holds, saw_raised, last_refusal = {}, False, None
    try:
        events = st.events(relay_id, limit=0) or ()
    except Exception:                                          # noqa: BLE001
        events = ()
    for ev in events:
        kind = str(ev.get("kind") or "")
        payload = dict(ev.get("payload") or {})
        if kind.startswith("relay.gate.") and not kind.endswith("regated") \
                and payload.get("allowed") is False:
            last_refusal = (kind, payload)
        hid = str(payload.get("hold_id") or "")
        if not hid:
            continue
        if kind == EVENT_HOLD_RAISED:
            open_holds[hid] = payload
            saw_raised = True
        elif kind == EVENT_HOLD_DISCHARGED:
            # A REPLAYED discharge pops nothing and is therefore still idempotent.
            open_holds.pop(hid, None)
    if saw_raised:
        return list(open_holds.values())
    unreadable = False
    try:
        row = st.get(relay_id) or {}
    except Exception:                                          # noqa: BLE001
        # THE STORE COULD NOT BE ASKED, which is not the same answer as "there is no hold".
        # resume, the CLI pre-check, Core's _not_resumable and summarise ALL read this one
        # function, so returning [] here would let an unreadable ledger discharge every
        # outstanding requirement at once -- the exact bypass quaestor-7ze was about, reached
        # by a failing disk instead of a missing branch.
        row, unreadable = {}, True
    if not unreadable and not str(row.get("owner_hold") or ""):
        # A READABLE, EMPTY column is real evidence of absence: every gate that raises a hold
        # sets it, and only a discharge clears it. So unreadable EVENTS on their own do not
        # block -- the column still answers the question that matters.
        return []
    if last_refusal is not None:
        kind, payload = last_refusal
        caps = list(payload.get("required") or ())
        effect_class = str(payload.get("effect_class") or "")
        gate = kind.rsplit(".", 1)[-1]
        return [{"hold_id": effects_mod.hold_id(relay_id, gate, effect_class, caps),
                 "gate": gate, "effect_class": effect_class,
                 "required": caps, "message_id": str(payload.get("message_id") or ""),
                 "reason": str(payload.get("reason") or row.get("owner_hold") or ""),
                 "reconstructed": True}]
    return [{"hold_id": "", "gate": HOLD_UNIDENTIFIED, "effect_class": "", "required": [],
             "message_id": "", "unidentified": True,
             "reason": str(row.get("owner_hold") or "") or "the relay ledger could not be read",
             "unreadable": unreadable,
             "note": "this relay records an owner hold whose requirement cannot be recovered, "
                     "so nothing can be shown to discharge it"}]


def owner_holds_blocking(st, relay_id: str, *, profile: str, owner_grants, now: float,
                         channel_state) -> list:
    """The outstanding holds that a matching owner decision does NOT yet cover. Impure.

    THE ONE PLACE THIS QUESTION IS ANSWERED. The kernel asks it on every resume, and the Core
    boundary asks it to tell a client the truth without starting a process -- but Core asking is
    a courtesy, not the guarantee. The guarantee is that the kernel asks, because every way of
    continuing a relay goes through ``resume``: the CLI, Core, a future Web client, an extension,
    or a caller constructing a kernel directly.

    Re-evaluated against the grants in force NOW, never against the decision recorded when the
    hold was raised. That is the whole point: resuming is not approving, and time passing is not
    approving either.
    """
    blocking = []
    for hold in outstanding_owner_holds(st, relay_id):
        caps = list(hold.get("required") or ())
        if not caps:
            # NO CAPABILITY MEANS NOTHING CAN MATCH IT. ``_require`` with an empty list is
            # trivially allowed, which would turn a hold we cannot identify into a hold we have
            # decided to ignore -- the exact fail-open this whole change exists to remove.
            blocking.append({**hold, "missing": [],
                             "reason": str(hold.get("reason") or "an owner hold whose "
                                           "requirement cannot be identified")})
            continue
        decision = effects_mod._require(profile, caps, owner_grants=owner_grants, now=now,
                                        channel_state=channel_state)
        if not decision.allowed:
            blocking.append({**hold, "missing": list(getattr(decision, "missing", ()) or ()),
                             "reason": decision.reason})
    return blocking


@dataclass(frozen=True)
class RelayConfig:
    """Ceilings and cadences. Every one exists because an unbounded relay is a runaway relay."""

    objective: str = ""
    authority_profile: str = "STANDARD_EDIT"
    max_exchanges: int = 40
    max_duration_s: float = 3600.0
    receive_timeout_s: float = 600.0
    #: How many identical consecutive turns from one side before the relay calls it a loop. Two
    #: is deliberate: one repetition is a model restating itself, two is a stuck conversation.
    repeat_limit: int = 2
    #: Sleep between polls of an endpoint that is still working.
    poll_interval_s: float = 2.0
    observe_repo: bool = True
    #: Exercise each endpoint's MODEL before the first exchange. status() only proves the
    #: endpoint's LOCAL situation -- a credential exists, a server listens -- and a relay was
    #: live-observed running against a gateway returning 503 to everything and a model that
    #: errors on every inference, both reporting IDLE. Off only when the operator says so.
    probe_endpoints: bool = True
    #: Verification commands the RELAY runs itself, in the project root, to corroborate an
    #: Orchestrator's completion claim. Empty means the claim cannot be corroborated and will be
    #: recorded as UNVERIFIED rather than confirmed -- honest, and weaker than the operator
    #: probably wants.
    completion_checks: tuple = ()
    #: Whether a completion claim additionally requires the repository to have actually moved.
    completion_requires_repo_change: bool = False
    #: How many times a refuted completion claim may be handed back before the relay stops. Two
    #: is deliberate: one is a model over-claiming and correcting, two is a model that cannot
    #: tell that it has not finished.
    completion_attempt_limit: int = 2
    #: Ceiling on ONE verification command.
    check_timeout_s: float = 300.0
    #: How many times a still-healthy endpoint may hand back an INCOMPLETE turn before the relay
    #: gives up on it. Only the RECEIVE is retried -- never the send -- so a retry cannot
    #: duplicate a delivery or repeat an ambiguous write.
    incomplete_retry_limit: int = 2


@dataclass
class StepResult:
    """What one half-exchange did. Returned so a caller can drive the loop itself."""

    delivered: str = ""
    received: str = ""
    direction: str = ""
    exchange_no: int = 0
    stop: str = ""
    hold: Mapping = field(default_factory=dict)
    observation: Mapping = field(default_factory=dict)
    note: str = ""


class RelayKernel:
    """One relay: one Orchestrator, one Execution Agent, one authorised project."""

    def __init__(self, *, st: state_mod.RelayState, orchestrator, execution,
                 project_root: str, config: RelayConfig, relay_id: str = "",
                 owner_grants: Callable[[], list] | None = None,
                 channel_state: Callable[[], str] | None = None,
                 clock=time.time, sleep=time.sleep, log: Callable[[str], None] | None = None):
        self.state = st
        self.orchestrator = orchestrator
        self.execution = execution
        self.project_root = project_root
        self.config = config
        self.relay_id = relay_id or ("relay-" + uuid.uuid4().hex[:12])
        self._clock = clock
        self._sleep = sleep
        self._log = log or (lambda _m: None)
        # AUTHORITY IS INJECTED, NEVER READ FROM A FIELD THIS PROCESS COULD SET. The callables
        # go to the platform's own ledger and owner channel; the kernel holds no way to widen
        # them, which is what stops "the relay decided it had authority" from being possible.
        self._owner_grants = owner_grants or (lambda: [])
        self._channel_state = channel_state or (lambda: None)
        self._last_repo = None
        #: Set when a completion claim is refused, consumed by the NEXT packet back to the
        #: Orchestrator so it learns WHICH check disagreed rather than only that it was wrong.
        #: In memory on purpose: the durable record of the refusal is the event log, and losing
        #: a hint across a crash costs one re-measured claim, while the bound that actually
        #: matters -- how many refusals are allowed -- is counted from those events.
        self._completion_blocker = ""
        self._stopped = False

    # -- small helpers -------------------------------------------------------------------------
    def _now(self) -> float:
        return float(self._clock())

    def _end_for(self, role: str):
        return self.orchestrator if role == ROLE_ORCHESTRATOR else self.execution

    def _row(self) -> dict:
        r = self.state.get(self.relay_id)
        if r is None:
            raise LookupError("relay %s is not in the durable record" % self.relay_id)
        return r

    def _event(self, kind: str, payload: Mapping | None = None) -> None:
        self.state.append_event(self.relay_id, kind, payload or {})

    def _finish(self, reason: str, *, state: str = state_mod.STOPPED,
                detail: Mapping | None = None) -> StepResult:
        """Park the relay with a named reason. Impure.

        WHATEVER THIS OVERWRITES IS NAMED HERE. The ``stop_reason`` already on the row is the
        diagnosis an operator was going to act on, and a stop that replaces it with a different
        name -- a resume refused by reconciliation, an owner hold that still stands, a ceiling
        reached on the way back up, an endpoint that is simply gone -- destroys the answer
        unless it says what it displaced. Read ONCE, in the one place every stop goes through,
        rather than hand-threaded through twenty call sites: the call site that forgets is
        exactly the one that loses the diagnosis.
        """
        previous = str((self.state.get(self.relay_id) or {}).get("stop_reason") or "")
        payload = dict(detail or {})
        if previous and previous != reason:
            payload[PREVIOUS_STOP_REASON] = previous
        self.state.update(self.relay_id, state=state, stop_reason=reason,
                          last_activity_at=self._now())
        self._event("relay.stopped", {"reason": reason, "state": state, **payload})
        self._stopped = True
        self._log("relay stopped: %s" % reason)
        return StepResult(stop=reason, hold=payload)

    # -- start ---------------------------------------------------------------------------------
    def start(self) -> StepResult:
        """Bind both ends to the project, apply the profile ceiling, and seed the conversation.

        The ceiling is checked BEFORE the first message moves. Discovering at exchange nine that
        the agent should never have been allowed to edit anything would be a report of a breach
        rather than the prevention of one.
        """
        repo = observe_mod.snapshot(self.project_root, at=self._now())
        if not repo.get("probe_ok"):
            # THE POLICY IS RECORDED EVEN WHEN THE START IS REFUSED. A relay refused because
            # its project root was not yet a git tree is precisely the one an operator fixes and
            # resumes -- and it used to come back with an EMPTY record, so every ceiling, every
            # verification command and the probe policy reverted to flag defaults.
            self.state.create(self.relay_id, project_root=self.project_root, repo_id="",
                              objective=self.config.objective,
                              orchestrator_kind=self.orchestrator.facts.kind,
                              execution_kind=self.execution.facts.kind,
                              authority_profile=self.config.authority_profile,
                              config=persisted_policy(self.config))
            return self._finish(STOP_START_REFUSED, state=state_mod.FAILED,
                                detail={"reason": "the project root is not a readable git "
                                                  "working tree: %s" % repo.get("probe_error")})

        self.state.create(self.relay_id, project_root=repo["project_root"],
                          repo_id=repo.get("origin_url") or repo["project_root"],
                          objective=self.config.objective,
                          orchestrator_kind=self.orchestrator.facts.kind,
                          execution_kind=self.execution.facts.kind,
                          authority_profile=self.config.authority_profile,
                          # THE POLICY comes from the one writer above; WHAT THE ENDS ARE is
                          # recorded beside it so ``relay status`` can answer "what was this
                          # talking to" from the record alone.
                          config={**persisted_policy(self.config),
                                  "orchestrator_facts": self.orchestrator.facts.to_dict(),
                                  "execution_facts": self.execution.facts.to_dict(),
                                  "orchestrator_assurance":
                                      computed_assurance(self.orchestrator.facts),
                                  "execution_assurance":
                                      computed_assurance(self.execution.facts)})
        self._last_repo = repo
        self.state.record_observation(self.relay_id, 0,
                                     {"snapshot": repo, "phase": "START"})

        gate = effects_mod.gate_start(
            profile=self.config.authority_profile,
            execution_can_mutate=self.execution.facts.can_mutate_repo,
            owner_grants=self._owner_grants(), now=self._now(),
            channel_state=self._channel_state())
        self._event("relay.gate.start", gate.to_dict())
        if not gate.allowed:
            self._raise_owner_hold(gate, gate_name="start")
            return self._finish(STOP_START_REFUSED, state=state_mod.OWNER_HOLD,
                                detail=gate.to_dict())

        for end, role in ((self.orchestrator, ROLE_ORCHESTRATOR),
                          (self.execution, ROLE_EXECUTION)):
            st = end.open()
            self._event("relay.end.opened", {"role": role, "kind": end.facts.kind,
                                             "state": st.state, "identity": st.identity,
                                             "detail": st.detail,
                                             "assurance": computed_assurance(end.facts)})
            if not st.usable:
                return self._finish(
                    STOP_ORCHESTRATOR_DISCONNECT if role == ROLE_ORCHESTRATOR
                    else STOP_EXECUTION_DISCONNECT,
                    state=state_mod.FAILED,
                    detail={"role": role, "state": st.state, "detail": st.detail})
            # THE MODEL, NOT JUST THE ENDPOINT. Refusing here is the whole point: an unusable
            # model discovered at exchange 1 costs the operator a started relay, a delivered
            # opening packet and a stop reason that blames the wrong thing.
            if self.config.probe_endpoints:
                probe = self._probe(end)
                self._event("relay.end.probed", {"role": role, "kind": end.facts.kind,
                                                 **probe.to_dict()})
                if probe.measured and not probe.ok:
                    return self._finish(
                        STOP_ORCHESTRATOR_UNUSABLE if role == ROLE_ORCHESTRATOR
                        else STOP_EXECUTION_UNUSABLE,
                        state=state_mod.FAILED,
                        detail={"role": role, "probe": probe.to_dict()})

        self.state.update(self.relay_id,
                          orchestrator_conversation=self.orchestrator.identity(),
                          execution_session=self.execution.identity())

        seed = packets_mod.opening_packet(
            objective=self.config.objective, project_root=repo["project_root"], repo=repo,
            execution_facts=self.execution.facts.to_dict(),
            orchestrator_facts=self.orchestrator.facts.to_dict(),
            assurance=computed_assurance(self.execution.facts) or "",
            profile=self.config.authority_profile)
        self._enqueue(FROM_RELAY, "seed:%s" % self.relay_id, seed, exchange_no=0,
                      raw=self.config.objective)
        self._event("relay.started", {"project_root": repo["project_root"],
                                      "head": repo.get("head"),
                                      "conversation": self.orchestrator.identity(),
                                      "session": self.execution.identity()})
        return StepResult(note="started", exchange_no=0)

    # -- the ledger's write side ----------------------------------------------------------------
    def _enqueue(self, direction: str, message_id: str, payload: str, *, exchange_no: int,
                 causal_parent: str = "", raw: str = "", provenance: Mapping | None = None,
                 observed_at: float = 0.0) -> bool:
        """Record a turn as OBSERVED with the payload that will be delivered.

        Returns False when the id was already known -- the stale-replay guard. It is deliberately
        an INSERT OR IGNORE in SQL and not a Python membership test: two readers of one endpoint
        must not both conclude "new".
        """
        from quaestor.relay.contracts import RelayMessage
        msg = RelayMessage(message_id=message_id, direction=direction, text=raw or payload,
                           complete=True, observed_at=observed_at or self._now(),
                           provenance=dict(provenance or {}))
        fresh = self.state.observe(self.relay_id, msg, exchange_no=exchange_no,
                                   causal_parent=causal_parent, text=payload)
        if fresh:
            self._event("relay.observed", {"message_id": message_id, "direction": direction,
                                           "exchange_no": exchange_no,
                                           "digest": msg.content_digest,
                                           "chars": len(raw or payload),
                                           "provenance": dict(provenance or {}),
                                           "text": (raw or payload)[:20000]})
        return fresh

    def _deliver(self, row: Mapping) -> tuple:
        """The three-move delivery. Returns ``(ok, detail)``.

        Move one writes DELIVERING. If this process dies before move three, that row is the
        evidence that reconciliation -- not repetition -- is the correct next action.
        """
        target_role = COUNTERPART[row["direction"]]
        end = self._end_for(target_role)
        delivery_id = uuid.uuid4().hex[:12]
        self.state.begin_delivery(self.relay_id, row["message_id"], delivery_id=delivery_id)
        self._event("relay.delivering", {"message_id": row["message_id"], "to": target_role,
                                         "delivery_id": delivery_id,
                                         "exchange_no": row["exchange_no"]})
        try:
            receipt = end.send(row["text"], message_id=row["message_id"])
        except Exception as exc:  # noqa: BLE001 - a transport fault is an OUTCOME, not a crash
            self._event("relay.delivery.failed", {"message_id": row["message_id"],
                                                  "to": target_role,
                                                  "error": "%s: %s" % (type(exc).__name__, exc)})
            return False, {"error": "%s: %s" % (type(exc).__name__, exc), "role": target_role}
        if not receipt.accepted:
            self._event("relay.delivery.refused", {"message_id": row["message_id"],
                                                   "to": target_role, "reason": receipt.reason})
            return False, {"error": receipt.reason or "endpoint refused the message",
                           "role": target_role}
        self.state.complete_delivery(self.relay_id, row["message_id"],
                                     native_id=receipt.native_id)
        self._event("relay.delivered", {"message_id": row["message_id"], "to": target_role,
                                        "native_id": receipt.native_id,
                                        "exchange_no": row["exchange_no"]})
        return True, {"native_id": receipt.native_id, "role": target_role}

    # -- recovery -------------------------------------------------------------------------------
    def reconcile(self) -> StepResult | None:
        """Resolve every DELIVERING row left by a crash. ASK THE ENDPOINT; never assume.

        Three outcomes, and the third is the honest one that stops the relay:

            the endpoint holds it        -> CONFIRMED_AFTER_CRASH, never sent again
            the endpoint does not        -> REDELIVERABLE, sent once more
            the endpoint cannot say      -> UNRECONCILABLE, the relay stops and a human decides

        The third case is not a defect. Choosing silently between duplicating work in somebody's
        repository and dropping it is worse than saying "I do not know".
        """
        pending = self.state.pending_deliveries(self.relay_id)
        for row in pending:
            target_role = COUNTERPART[row["direction"]]
            end = self._end_for(target_role)
            holds = getattr(end, "holds", None)
            if holds is None:
                self.state.mark_delivery(self.relay_id, row["message_id"],
                                         state_mod.UNRECONCILABLE)
                self._event("relay.reconcile.unanswerable",
                            {"message_id": row["message_id"], "to": target_role,
                             "reason": "this endpoint cannot be asked whether it already holds "
                                       "a relay-assigned message id"})
                return self._finish(STOP_UNRECONCILABLE, state=state_mod.PAUSED,
                                    detail={"message_id": row["message_id"],
                                            "role": target_role})
            try:
                already = bool(holds(row["message_id"]))
            except Exception as exc:  # noqa: BLE001
                self.state.mark_delivery(self.relay_id, row["message_id"],
                                         state_mod.UNRECONCILABLE)
                self._event("relay.reconcile.failed",
                            {"message_id": row["message_id"], "to": target_role,
                             "error": "%s: %s" % (type(exc).__name__, exc)})
                return self._finish(STOP_UNRECONCILABLE, state=state_mod.PAUSED,
                                    detail={"message_id": row["message_id"],
                                            "role": target_role,
                                            "error": str(exc)})
            if already:
                self.state.complete_delivery(self.relay_id, row["message_id"],
                                             native_id=row.get("native_id") or "",
                                             state=state_mod.CONFIRMED_AFTER_CRASH)
                self._event("relay.reconcile.confirmed",
                            {"message_id": row["message_id"], "to": target_role,
                             "note": "the endpoint already holds this id; it is NOT re-sent"})
            else:
                self.state.mark_delivery(self.relay_id, row["message_id"],
                                         state_mod.REDELIVERABLE)
                self._event("relay.reconcile.redeliverable",
                            {"message_id": row["message_id"], "to": target_role,
                             "note": "the endpoint does not hold this id; delivering once more"})
        return None

    def resume(self) -> StepResult | None:
        """Re-attach both ends to the identities the durable record names.

        An endpoint that cannot resume answers RESUME_UNSUPPORTED and that answer is RECORDED AS
        SUCH. Reporting continuity the transport does not provide is the one failure this method
        exists to make impossible.

        THE PREVIOUS DIAGNOSIS IS NOT ERASED ON THE STRENGTH OF AN INTENTION. ``stop_reason``
        used to be blanked at the top of this method -- before reconciliation, before the
        ceiling, before a single message moved. So a relay parked on START_REFUSED, on
        COMPLETION_UNCORROBORATED or on EXECUTION_MODEL_UNUSABLE was resumed into a blank row,
        re-stopped a moment later for whatever generic reason came first, and the record then
        read STOPPED/NO_PROGRESS: the resume destroyed the answer and left a symptom in its
        place. So NOTHING is written to this row until reconciliation and the ceiling have both
        let the resume through; every stop taken on the way names the reason it displaced,
        which ``_finish`` does for all four of them; and the moment the reason is finally
        superseded is itself an event, written BEFORE the row is cleared so a crash between the
        two loses nothing.

        AND THE WRITE IS CONDITIONAL, exactly as ``request_stop`` is. This method spends a live
        round trip per pending delivery, and an operator stop landing in that window is not the
        resume's to erase -- so the transition to RUNNING applies only while the row still
        reads what was read at the top of this method, and reports whatever stopped it if not.

        It IS cleared once the resume proceeds. A RUNNING relay still advertising why it
        stopped last time is the same defect pointing the other way: every status surface reads
        that field -- Core's resume-readiness probe among them -- and a stale one describes a
        relay that no longer exists.
        """
        # AUTHORITY FIRST, BEFORE ANY PROVIDER IS CONTACTED. A relay that is not permitted to
        # continue has no business opening a conversation to find that out: it costs a
        # round-trip and possibly money on every attempt, and -- worse -- an endpoint that
        # cannot open MASKS the refusal, so the operator is told the provider is down when the
        # truth is that an owner has not decided. The hold is answered from the durable record
        # and the grant ledger, neither of which needs an endpoint.
        #
        # THE ROW IS READ BEFORE ANYTHING IS WRITTEN, the re-gate included.
        # ``_release_owner_held`` both writes ``owner_hold`` and can stop the relay outright,
        # so a read placed after it reads a row this method has already changed -- or, on the
        # path that stops, never happens at all.
        row = self._row()
        prior_state = str(row.get("state") or "")
        prior_stop = str(row.get("stop_reason") or "")
        held = self._release_owner_held()
        if held is not None:
            return held

        self._last_repo = observe_mod.snapshot(row["project_root"], at=self._now())
        for end, role, ident in ((self.orchestrator, ROLE_ORCHESTRATOR,
                                  row["orchestrator_conversation"]),
                                 (self.execution, ROLE_EXECUTION, row["execution_session"])):
            st = end.open()
            if not st.usable:
                return self._finish(
                    STOP_ORCHESTRATOR_DISCONNECT if role == ROLE_ORCHESTRATOR
                    else STOP_EXECUTION_DISCONNECT, state=state_mod.FAILED,
                    detail={"role": role, "state": st.state, "detail": st.detail})
            outcome, detail = (RESUME_UNSUPPORTED, "no identity was recorded to resume") \
                if not ident else end.resume(ident)
            self._event("relay.resume", {"role": role, "kind": end.facts.kind,
                                         "identity": ident, "outcome": outcome,
                                         "detail": detail})
            if outcome not in (RESUME_RESUMED, RESUME_UNSUPPORTED):
                return self._finish(
                    STOP_ORCHESTRATOR_DISCONNECT if role == ROLE_ORCHESTRATOR
                    else STOP_EXECUTION_DISCONNECT, state=state_mod.FAILED,
                    detail={"role": role, "resume": outcome, "detail": detail})
        # THE RELAY STAYS PARKED WHILE THIS IS DECIDED. Reconciliation and the ceiling can each
        # decide the resume never happens, so the durable row keeps the state AND the reason it
        # was parked on until both have let it through: a crash in that window leaves the
        # operator the diagnosis instead of a blank field, and no status surface -- Core's
        # resume-readiness probe included -- ever reads a row that says RUNNING and still names
        # why the relay stopped.
        unreconciled = self.reconcile()
        if unreconciled is not None:
            return unreconciled
        ceiling = self._ceiling_stop()
        if ceiling:
            # THE CEILING IS ASKED HERE, NOT LEFT TO THE FIRST STEP. A relay already at its
            # limit was announced RUNNING with an empty reason and only then stopped by
            # ``step`` -- a window in which the record claims the relay is working and says
            # nothing about why it is not.
            return self._finish(ceiling)
        if prior_stop:
            # SUPERSEDED, RECORDED AS SUPERSEDED, AND RECORDED FIRST. Whatever this relay stops
            # for next -- very possibly a generic NO_PROGRESS -- the event log still names what
            # it was parked on when the operator resumed it, and writing this before the row is
            # touched means a crash between the two costs nothing.
            self._event(EVENT_RESUME_SUPERSEDED,
                        {PREVIOUS_STOP_REASON: prior_stop, "previous_state": prior_state,
                         "note": "this resume got past reconciliation and the ceiling, so the "
                                 "diagnosis is superseded and kept here; the row itself is "
                                 "cleared only while it still carries this exact reason"})
        if not self.state.resume_running(self.relay_id, from_state=prior_state,
                                         from_stop_reason=prior_stop):
            # SOMEBODY ELSE WROTE THIS ROW WHILE THE RESUME WAS ASKING ENDPOINTS. An operator
            # stop applies to a parked relay, and reconciliation is a live round trip per
            # pending delivery, so the window is real and it is exactly the crash-recovery case
            # this method exists for. NOTHING is written back: the reason that landed is not
            # this resume's to erase, and the relay is reported as it now actually stands.
            now = self._row()
            self._stopped = True
            return StepResult(stop=str(now.get("stop_reason") or ""),
                              hold={"state": str(now.get("state") or ""),
                                    PREVIOUS_STOP_REASON: prior_stop,
                                    "detail": "the durable record moved while this resume was "
                                              "reconciling, so it was not overwritten"})
        self._stopped = False
        return None

    def _raise_owner_hold(self, gate, *, gate_name: str, message_id: str = "") -> str:
        """Record an authority requirement durably, and return its id. Impure.

        EVERY GATE COMES THROUGH HERE. Before this, only the DIRECTIVE gate left something a
        resume could re-evaluate -- it parked its message as OWNER_HELD -- so a hold raised by
        the observation gate or refused at start had no discharge path at all, and ``resume``
        walked straight past it with no owner grant consulted anywhere. The gate that raised a
        hold must not decide whether the hold is enforceable.

        ONLY AN AUTHORITY REFUSAL BECOMES A DURABLE REQUIREMENT. Returns the hold id, or "" for
        a refusal no owner decision could resolve.

        THE GATE'S OWN DATA DECIDES, NOT ITS NAME. This asked "is the hold one of these two
        names?" and the observation gate's authority refusal is a THIRD name
        (OBSERVED_UNGRANTED_EFFECT), so the one refusal quaestor-7ze was actually filed about
        fell through to the measurement branch and recorded nothing -- no event, and no column
        either, because the column write is below. A hand-maintained list of names has to be
        edited every time a gate is added, and it failed the first time it met a name that was
        not on it. A refusal that names MISSING CAPABILITIES is by construction one an owner
        grant could discharge; a refusal that names none cannot be discharged by any grant. That
        is the same question the list was trying to answer, asked of the data instead.
        """
        if not tuple(gate.required or ()):
            # NOT AN AUTHORITY QUESTION, so not an owner requirement. A repository that could
            # not be read on both sides of a turn, or an Orchestrator naming an effect class
            # this build does not model, is a MEASUREMENT failure: no capability is missing, so
            # no grant could ever discharge it and recording one would park the relay somewhere
            # no owner could release it from. It still stops -- the caller does that -- and it
            # is still recorded, but as what it is.
            self._event("relay.gate.refused",
                        {**gate.to_dict(), "gate": str(gate_name),
                         "message_id": str(message_id or ""),
                         "note": "a refusal with no missing capability: re-measured on the next "
                                 "resume rather than waiting for an owner who cannot help"})
            return ""
        hid = effects_mod.hold_id(self.relay_id, gate_name, gate.effect_class, gate.required)
        self._event(EVENT_HOLD_RAISED,
                    {"hold_id": hid, "gate": str(gate_name),
                     "effect_class": gate.effect_class,
                     "required": list(gate.required or ()),
                     "message_id": str(message_id or ""),
                     "profile": self.config.authority_profile,
                     "reason": gate.reason,
                     "note": "an authority requirement, outstanding until a matching owner "
                             "decision exists. Resuming is not approving."})
        self.state.update(self.relay_id, owner_hold=gate.reason)
        return hid

    def _release_owner_held(self) -> StepResult | None:
        """Re-gate every outstanding authority requirement. Returns a stop if any still stands.

        RESUMING IS NOT APPROVING. The operator who runs ``relay resume`` after an owner hold is
        saying "carry on", not "I grant GIT_PUSH" -- and the relay has no way to tell the two
        apart from the command alone. So every requirement recorded by ``_raise_owner_hold`` is
        re-evaluated against the grants in force NOW: if a human really did sign one through the
        owner channel, the hold is discharged and the relay continues; if not, it stands and the
        relay stops again with the same reason rather than quietly doing what it refused.

        EVERY HOLD, whichever gate raised it. The shape this replaces looked only at messages
        parked OWNER_HELD, which only the DIRECTIVE gate creates -- so a hold from the
        observation gate, or a refusal at start, found nothing to re-gate, returned None, and
        the resume proceeded with no owner decision consulted anywhere. That was quaestor-7ze.
        """
        holds = outstanding_owner_holds(self.state, self.relay_id)
        if not holds:
            # NOTHING OUTSTANDING. A relay that was held before this record existed still has
            # its owner_hold string set; clearing it here is what stops status printing a hold
            # the relay has genuinely walked past.
            if self._row().get("owner_hold"):
                self.state.update(self.relay_id, owner_hold="")
            return None

        blocked = None
        for hold in holds:
            caps = list(hold.get("required") or ())
            if not caps:
                # SEE ``owner_holds_blocking``: an empty requirement satisfies ``_require``
                # trivially, so it must be refused here rather than evaluated.
                blocked = blocked or effects_mod.Gate(
                    False, "", hold=effects_mod.HOLD_OWNER_REQUIRED,
                    reason=str(hold.get("reason") or "this relay records an owner hold whose "
                              "requirement cannot be identified, so nothing can discharge it"),
                    decision={"source": "REGATE_ON_RESUME", "unidentified": True})
                continue
            decision = effects_mod._require(
                self.config.authority_profile, caps,
                owner_grants=self._owner_grants(), now=self._now(),
                channel_state=self._channel_state())
            gate = effects_mod.Gate(
                decision.allowed, str(hold.get("effect_class") or ""), required=tuple(caps),
                hold="" if decision.allowed else effects_mod.HOLD_OWNER_REQUIRED,
                reason="" if decision.allowed else decision.reason,
                decision={"decision": decision.decision,
                          "missing": list(getattr(decision, "missing", ()) or ()),
                          "source": "REGATE_ON_RESUME"})
            self._event("relay.gate.regated",
                        {**gate.to_dict(), "hold_id": hold.get("hold_id"),
                         "gate": hold.get("gate"), "message_id": hold.get("message_id", ""),
                         "note": "re-evaluated on resume; resuming is not approving"})
            if not gate.allowed:
                # THE FIRST ONE THAT STILL STANDS DECIDES. Every hold is left outstanding, so a
                # later grant discharges what it actually covers and nothing more.
                blocked = blocked or gate
                continue
            # DISCHARGED, ONCE. The event is what makes it exactly once: a replayed approval or
            # a second resume finds this hold already discharged and does nothing again.
            self._event(EVENT_HOLD_DISCHARGED,
                        {"hold_id": hold.get("hold_id"),
                         "required": caps, "effect_class": hold.get("effect_class"),
                         "granted_by": [str(g) for g in
                                        (getattr(decision, "granted", ()) or ())],
                         "note": "a matching owner decision was in force at resume"})
            mid = str(hold.get("message_id") or "")
            if mid:
                # The directive the gate refused goes back into the delivery queue -- and only
                # now, with the grant that covers it recorded against this exact hold.
                self.state.mark_delivery(self.relay_id, mid, state_mod.OBSERVED)

        if blocked is not None:
            self.state.update(self.relay_id, owner_hold=blocked.reason)
            return self._finish(STOP_OWNER_HOLD, state=state_mod.OWNER_HOLD,
                                detail=blocked.to_dict())
        if self._row().get("owner_hold"):
            self.state.update(self.relay_id, owner_hold="")
        return None

    # -- ceilings -------------------------------------------------------------------------------
    def _ceiling_stop(self) -> str:
        row = self._row()
        if int(row["exchange_no"]) >= int(self.config.max_exchanges):
            return STOP_MAX_EXCHANGES
        if (self._now() - float(row["started_at"])) >= float(self.config.max_duration_s):
            return STOP_MAX_DURATION
        return ""

    def _repetition_stop(self, direction: str) -> str:
        digests = self.state.recent_digests(self.relay_id, direction,
                                            n=int(self.config.repeat_limit) + 1)
        if len(digests) < int(self.config.repeat_limit) + 1:
            return ""
        if len(set(digests)) == 1:
            return (STOP_ORCHESTRATOR_LOOP if direction == FROM_ORCHESTRATOR
                    else STOP_EXECUTION_LOOP)
        return ""

    # -- one half-exchange -----------------------------------------------------------------------
    def _corroborate_completion(self, row: Mapping) -> dict:
        """Measure the Orchestrator's completion claim. Impure (runs the checks). NEVER raises.

        Repository movement is answered from the observations this relay already took rather
        than re-derived here: those readings were taken by this process at the moments that
        matter, and a second weaker answer to a question already answered well is not evidence.
        """
        changed = None
        if self.config.completion_requires_repo_change:
            snaps = [(r.get("payload") or {}).get("snapshot") or {}
                     for r in (self.state.observations(self.relay_id, limit=0) or ())]
            measured = [s for s in snaps if s.get("probe_ok")]
            if len(measured) >= 2:
                # THE FIRST READING VERSUS THE LAST. "Any dirty tree" was wrong and was measured
                # wrong: a developer who starts a relay with uncommitted work already in the tree
                # is the most ordinary situation there is, and it made every completion claim
                # corroborate on a repository the relay had not touched. What this must answer is
                # whether the repo MOVED, so it compares the reading taken at start with the most
                # recent one -- head for commits, status digest for the set of changed paths, and
                # the diff hash for an edit that changes content without changing status.
                first, last = measured[0], measured[-1]
                changed = any(str(first.get(k) or "") != str(last.get(k) or "")
                              for k in ("head", "status_digest", "diff_sha256"))
        try:
            return corroborate_mod.verdict(
                project_root=str(row.get("project_root") or ""),
                checks=tuple(self.config.completion_checks or ()),
                require_repo_change=bool(self.config.completion_requires_repo_change),
                repo_changed=changed,
                timeout_s=float(self.config.check_timeout_s),
                at=self._now())
        except Exception as exc:  # noqa: BLE001
            # Corroboration itself failing must never read as a passing claim.
            return {"state": corroborate_mod.UNMEASURABLE,
                    "reason": "completion corroboration could not run: %s: %s"
                              % (type(exc).__name__, exc),
                    "checks": [], "repo": {}, "at": self._now(),
                    "instrument": corroborate_mod.CORROBORATE_INSTRUMENT}

    def _completion_refusals(self) -> int:
        """How many completion claims this relay has already refused. Durable, from events.

        Counted from the event log rather than memory so the bound survives a restart: a relay
        that could forget its refusals would let a model re-claim completion forever by crashing
        between attempts.
        """
        # limit=0 is EVERY event, deliberately. Counting from a window would let a long relay
        # push its early refusals out of view and re-claim completion indefinitely.
        n = 0
        for ev in (self.state.events(self.relay_id, limit=0) or ()):
            if ev.get("kind") != "relay.completion.claim":
                continue
            payload = ev.get("payload") or {}
            if str(payload.get("state") or "") in (corroborate_mod.REFUTED,
                                                   corroborate_mod.UNMEASURABLE):
                n += 1
        return n

    @staticmethod
    def _probe(end):
        """Exercise an endpoint's provider. NEVER raises -- a probe that crashes is not a pass.

        An endpoint whose probe blows up is reported as REFUSED rather than allowed through:
        the same direction every other unmeasured fact falls in.
        """
        from quaestor.relay.contracts import EndProbe, PROBE_REFUSED
        try:
            return end.probe()
        except Exception as exc:  # noqa: BLE001
            return EndProbe(PROBE_REFUSED,
                            "the endpoint's own probe raised %s: %s" % (type(exc).__name__, exc))

    @staticmethod
    def _endpoint_live(end) -> tuple:
        """Is this endpoint still usable? Returns ``(usable, state_name)``. NEVER raises.

        The distinction this exists to draw: an endpoint that DIED and an endpoint that merely
        failed to finish a sentence are different faults. Retrying the first is pointless;
        retrying the second is the whole remedy. An endpoint whose ``status()`` cannot be read
        is treated as NOT usable -- the same direction every other unmeasured fact falls in.
        """
        try:
            st = end.status()
        except Exception as exc:  # noqa: BLE001
            return False, "status unreadable: %s" % type(exc).__name__
        return bool(getattr(st, "usable", False)), str(getattr(st, "state", "") or "UNKNOWN")

    def _refresh_identities(self, row: Mapping) -> None:
        """Re-record either endpoint's identity if it has only just become knowable.

        IDENTITY CAN ARRIVE LATE, and assuming otherwise silently breaks recovery. ``start``
        records what each endpoint knew at attach time, which is right for an endpoint whose
        session exists before the relay does. It is wrong for one whose conversation does not
        EXIST until the first message creates it -- and for that endpoint the durable record
        would keep an empty identity forever, so ``resume`` would have nothing to re-bind to and
        would report the conversation lost.

        Provider-neutral on purpose: the kernel does not learn which endpoints are lazy, it just
        stops assuming none of them are. Only a transition from "" to a real value is written --
        an identity that CHANGES mid-run is a different conversation, and quietly overwriting the
        record would erase the binding this exists to preserve.
        """
        for end, column, current in (
                (self.orchestrator, "orchestrator_conversation",
                 str(row.get("orchestrator_conversation") or "")),
                (self.execution, "execution_session",
                 str(row.get("execution_session") or ""))):
            if current:
                continue
            try:
                found = str(end.identity() or "")
            except Exception:  # noqa: BLE001 - an endpoint that cannot say is simply not ready
                continue
            if not found:
                continue
            self.state.update(self.relay_id, **{column: found})
            self._event("relay.identity.bound",
                        {"column": column, "identity": found,
                         "note": "the endpoint's identity did not exist at attach time and has "
                                 "now been established; recording it so a restart can re-bind"})

    def _before_reading(self, row: Mapping, target_role: str, *, fresh: bool):
        """The repository reading to bracket an execution turn against.

        On the normal path it is taken NOW. On a resumed turn it must come from the durable
        record instead: the agent has been working since this process died, so a reading taken
        now would already include its changes and the delta would report nothing happened.
        """
        if not (self.config.observe_repo and target_role == ROLE_EXECUTION):
            return self._last_repo
        if fresh:
            snap = observe_mod.snapshot(row["project_root"], at=self._now())
            self.state.record_observation(self.relay_id, int(row["exchange_no"]) + 1,
                                          {"snapshot": snap, "phase": "BEFORE_TURN"})
            return snap
        for obs in reversed(self.state.observations(self.relay_id, limit=50)):
            if obs["payload"].get("phase") == "BEFORE_TURN":
                return obs["payload"].get("snapshot") or {}
        return self._last_repo or {}

    def step(self) -> StepResult:
        """Deliver the pending message and take the reply. One message each way per call."""
        row = self._row()
        if row["state"] not in (state_mod.RUNNING,):
            return StepResult(stop=row["stop_reason"] or row["state"])

        ceiling = self._ceiling_stop()
        if ceiling:
            return self._finish(ceiling)

        # -- RESUMING AN OUTSTANDING TURN ------------------------------------------------------
        # A relay killed while waiting for a slow agent has an EMPTY delivery queue and an
        # unfinished exchange. Re-delivering would duplicate work; stopping would abandon it.
        # The third option is the correct one: pick the same anchor back up and collect the
        # reply the endpoint has been holding all along.
        resuming = bool(row["awaiting_message_id"])
        if resuming:
            pending = self.state.seen(self.relay_id, row["awaiting_message_id"])
            if pending is None:
                self.state.update(self.relay_id, awaiting_message_id="", awaiting_native_id="",
                                  awaiting_role="")
                return self._finish(STOP_NO_PROGRESS,
                                    detail={"reason": "the awaited message is not in the "
                                                      "durable record"})
            target_role = row["awaiting_role"] or COUNTERPART[pending["direction"]]
            end = self._end_for(target_role)
            anchor = row["awaiting_native_id"] or pending["message_id"]
            exchange_no = int(row["exchange_no"])
            before = self._before_reading(row, target_role, fresh=False)
            self._event("relay.awaiting.resumed",
                        {"message_id": pending["message_id"], "role": target_role,
                         "anchor": anchor, "exchange_no": exchange_no,
                         "note": "collecting a reply that was outstanding when the relay died; "
                                 "the message is NOT re-delivered"})
        else:
            queue = self.state.undelivered(self.relay_id)
            if not queue:
                return self._finish(STOP_NO_PROGRESS,
                                    detail={"reason": "nothing is pending delivery and no "
                                                      "endpoint has been asked for a turn"})
            pending = queue[0]
            target_role = COUNTERPART[pending["direction"]]
            end = self._end_for(target_role)

            # -- the repository, BEFORE the agent acts ----------------------------------------
            before = self._before_reading(row, target_role, fresh=True)

            ok, detail = self._deliver(pending)
            if not ok:
                return self._finish(
                    STOP_EXECUTION_DISCONNECT if target_role == ROLE_EXECUTION
                    else STOP_ORCHESTRATOR_DISCONNECT, state=state_mod.FAILED, detail=detail)

            exchange_no = int(row["exchange_no"]) + 1
            # The ANCHOR is what the endpoint called the message we just delivered, taken from
            # the receipt rather than from ``pending`` -- that row was read before the send and
            # still carries an empty native id. Anchoring on the wrong message is how a relay
            # hands back the previous turn and calls it new.
            anchor = detail.get("native_id") or pending["message_id"]
            # WRITTEN BEFORE THE WAIT, for the same reason DELIVERING is written before the
            # send: what this process is in the middle of must survive this process.
            self.state.update(self.relay_id, exchange_no=exchange_no,
                              awaiting_message_id=pending["message_id"],
                              awaiting_native_id=anchor, awaiting_role=target_role,
                              last_activity_at=self._now())

        # -- take the reply --------------------------------------------------------------------
        # ONLY THE RECEIVE IS RETRIED. Re-reading an endpoint is idempotent; re-sending is how a
        # relay duplicates a delivery and repeats an ambiguous write, so the bound sits strictly
        # on this side of the send and the anchor never moves between attempts.
        disconnect = (STOP_EXECUTION_DISCONNECT if target_role == ROLE_EXECUTION
                      else STOP_ORCHESTRATOR_DISCONNECT)
        incomplete_stop = (STOP_EXECUTION_INCOMPLETE if target_role == ROLE_EXECUTION
                           else STOP_ORCHESTRATOR_INCOMPLETE)
        tries = max(1, int(self.config.incomplete_retry_limit) + 1)
        reply = None
        for attempt in range(1, tries + 1):
            try:
                reply = end.receive(after_id=anchor,
                                    timeout_s=float(self.config.receive_timeout_s))
            except Exception as exc:  # noqa: BLE001
                self._event("relay.receive.failed",
                            {"role": target_role, "attempt": attempt,
                             "error": "%s: %s" % (type(exc).__name__, exc)})
                return self._finish(
                    disconnect, state=state_mod.FAILED,
                    detail={"role": target_role,
                            "error": "%s: %s" % (type(exc).__name__, exc)})
            if reply is None:
                # The wait already happened. Retrying would only spend the timeout again against
                # an endpoint that produced nothing, so a silent wait is reported, not repeated.
                return self._finish(
                    disconnect, state=state_mod.PAUSED,
                    detail={"role": target_role, "attempt": attempt,
                            "reason": "no completed turn arrived within %ss"
                                      % self.config.receive_timeout_s})
            if reply.complete:
                break
            # AN INCOMPLETE TURN. A partial is never forwarded as work -- a streamed
            # half-sentence delivered as an instruction is how a relay produces confident
            # nonsense. But "the endpoint is gone" and "the endpoint did not finish a sentence"
            # are different faults with different remedies, so the endpoint is asked which
            # this is before the relay gives up on an otherwise healthy provider.
            alive, why = self._endpoint_live(end)
            # WHOSE FAULT IS THIS? status() can only see as far as its own gateway, so a healthy
            # local endpoint in front of a failing upstream reports IDLE. Asking the provider
            # for one real turn is what separates "the model will not finish a sentence" from
            # "the provider is down", and the operator needs those named differently.
            probe = self._probe(end) if self.config.probe_endpoints else None
            self._event("relay.receive.incomplete",
                        {"role": target_role, "attempt": attempt, "of": tries,
                         "endpoint_usable": alive, "endpoint_state": why,
                         "message_id": getattr(reply, "message_id", ""),
                         "error": getattr(reply, "error", ""),
                         "probe": probe.to_dict() if probe is not None else None})
            reply = None
            # ORDER MATTERS, and start() already has it right: liveness first. A dead endpoint
            # whose probe also fails is a DISCONNECT, not a model fault -- reporting it as
            # *_MODEL_UNUSABLE would send the operator hunting a bad model while the server they
            # need to restart is the thing that died.
            if not alive:
                return self._finish(
                    disconnect, state=state_mod.PAUSED,
                    detail={"role": target_role, "attempt": attempt, "endpoint_state": why,
                            "probe": probe.to_dict() if probe is not None else None,
                            "reason": "the endpoint returned an INCOMPLETE turn and is no "
                                      "longer usable; partial replies are never forwarded as "
                                      "completed work"})
            # A REFUSED probe is PERMANENT -- an unknown model, a rejected credential. Retrying
            # spends the whole bound learning nothing, so stop now and name the provider.
            # An UPSTREAM failure is TRANSIENT-SHAPED and must NOT short-circuit the retry: the
            # live run this whole bead exists for showed two HTTP 503 bursts that RECOVERED on
            # the next attempt. Collapsing the two verdicts here would have re-broken exactly
            # the slice the bounded retry was built to save.
            if probe is not None and probe.state == PROBE_REFUSED:
                return self._finish(
                    STOP_ORCHESTRATOR_UNUSABLE if target_role == ROLE_ORCHESTRATOR
                    else STOP_EXECUTION_UNUSABLE, state=state_mod.PAUSED,
                    detail={"role": target_role, "attempt": attempt,
                            "endpoint_state": why, "probe": probe.to_dict(),
                            "reason": "the endpoint is locally healthy and its provider REFUSED "
                                      "a probe; this is the model or credential, not a "
                                      "disconnect, and retrying cannot help"})
            if attempt >= tries:
                return self._finish(
                    incomplete_stop, state=state_mod.PAUSED,
                    detail={"role": target_role, "attempts": tries, "endpoint_state": why,
                            "reason": "the endpoint is still usable but returned an INCOMPLETE "
                                      "turn on every one of %d attempts; partial replies are "
                                      "never forwarded as completed work" % tries})
            self._sleep(float(self.config.poll_interval_s))

        if self.state.seen(self.relay_id, reply.message_id) is not None:
            # STALE REPLAY. The endpoint handed back something already in the ledger.
            self._event("relay.stale_replay", {"role": target_role,
                                               "message_id": reply.message_id})
            return self._finish(STOP_NO_PROGRESS,
                                detail={"role": target_role, "message_id": reply.message_id,
                                        "reason": "the endpoint returned a turn already in the "
                                                  "durable record; refusing to treat old "
                                                  "output as new work"})

        # THE TURN IS CLOSED. Cleared only now, after a genuinely new completed reply is in
        # hand: clearing it any earlier would reopen the gap this field exists to close.
        self.state.update(self.relay_id, awaiting_message_id="", awaiting_native_id="",
                          awaiting_role="", last_activity_at=self._now())
        self._refresh_identities(row)

        result = StepResult(delivered=pending["message_id"], received=reply.message_id,
                            direction=reply.direction, exchange_no=exchange_no)

        # -- the repository, AFTER the agent acted --------------------------------------------
        observation_text = ""
        observation_gate = None
        if target_role == ROLE_EXECUTION:
            after = observe_mod.snapshot(row["project_root"], at=self._now()) \
                if self.config.observe_repo else (before or {})
            d = observe_mod.delta(before or {}, after)
            observation_text = observe_mod.summarise(d)
            self._last_repo = after
            self.state.record_observation(self.relay_id, exchange_no,
                                          {"snapshot": after, "delta": d,
                                           "phase": "AFTER_TURN"})
            result.observation = d
            observation_gate = effects_mod.gate_observation(
                before or {}, after, profile=self.config.authority_profile,
                owner_grants=self._owner_grants(), now=self._now(),
                channel_state=self._channel_state())
            self._event("relay.gate.observation", observation_gate.to_dict())

        # -- SANITISE BEFORE IT CROSSES ---------------------------------------------------------
        # The agent has read this repository, its environment and its logs, and its turn is
        # about to be sent to a REMOTE PROVIDER. "It came from the model" is not a reason to
        # forward a credential. ``classification`` replaces only credential- and
        # host-path-shaped spans and marks each removal visibly, so the engineering content the
        # conversation exists to carry survives intact -- blanket redaction would leave the
        # Orchestrator reasoning from sentences with holes in them.
        #
        # Both directions, because the Orchestrator may quote back what the agent showed it.
        safe_text, report = packets_mod.sanitise(reply.text)
        if report.get("modified"):
            self._event("relay.sanitised",
                        {"message_id": reply.message_id, "direction": reply.direction,
                         **report})

        # -- RECORD FIRST, HOLD SECOND ---------------------------------------------------------
        # The reply, and the packet built from it, are written to the durable record BEFORE any
        # gate can stop the relay. Holding first would discard the agent's turn: the operator
        # would be interrupted about an effect with none of the work that produced it visible,
        # and a later resume would have nothing to hand the Orchestrator.
        if reply.direction == FROM_ORCHESTRATOR:
            gate = effects_mod.gate_directive(
                reply.text, profile=self.config.authority_profile,
                owner_grants=self._owner_grants(), now=self._now(),
                channel_state=self._channel_state())
            self._event("relay.gate.directive", {**gate.to_dict(),
                                                 "message_id": reply.message_id})
            payload = packets_mod.orchestrator_to_execution(
                exchange_no=exchange_no + 1, directive=safe_text,
                objective=row["objective"], first=(exchange_no <= 1))
            # THE SANITISED FORM IS WHAT IS PERSISTED. ``classification`` is explicit that a
            # credential is never written to durable storage, so the ledger and the event log
            # keep the classified text -- not the raw turn with the token still in it.
            self._enqueue(reply.direction, reply.message_id, payload,
                          exchange_no=exchange_no, causal_parent=pending["message_id"],
                          raw=safe_text, provenance=reply.provenance,
                          observed_at=reply.observed_at)
            if not gate.allowed:
                # The directive is RECORDED and NOT DELIVERED. Keeping it visible is the point:
                # the operator being interrupted should be able to read exactly what was asked.
                # OWNER_HELD, not OBSERVED: OBSERVED is the DELIVERY QUEUE, so a refused
                # directive parked there was picked straight back up by the next ``resume`` and
                # delivered with no grant and no re-gating. Releasing it now requires the gate to
                # pass against the grants in force at that moment -- see ``_release_owner_held``.
                self.state.mark_delivery(self.relay_id, reply.message_id, state_mod.OWNER_HELD)
                self._raise_owner_hold(gate, gate_name="directive",
                                       message_id=reply.message_id)
                result.hold = gate.to_dict()
                self._finish(STOP_OWNER_HOLD, state=state_mod.OWNER_HOLD, detail=gate.to_dict())
                result.stop = STOP_OWNER_HOLD
                return result
            if claims_completion(reply.text):
                # A COMPLETION MARKER IS A CLAIM, NOT AN OUTCOME. The party declaring the work
                # finished is the party that did not do it, cannot see the repository and cannot
                # run a test. So the claim is measured before it is believed.
                verdict = self._corroborate_completion(row)
                self._event("relay.completion.claim",
                            {"message_id": reply.message_id, "exchange_no": exchange_no,
                             **verdict})
                if verdict["state"] in (corroborate_mod.CORROBORATED,
                                        corroborate_mod.UNCONFIGURED):
                    self.state.mark_delivery(self.relay_id, reply.message_id,
                                             state_mod.OBSERVED)
                    self._finish(STOP_OBJECTIVE_COMPLETE,
                                 detail={"message_id": reply.message_id,
                                         "corroboration": verdict})
                    result.stop = STOP_OBJECTIVE_COMPLETE
                    result.note = verdict["reason"]
                    return result
                # REFUTED or UNMEASURABLE. The relay does NOT stop as complete, and does not
                # pretend the turn never happened either: the directive is still delivered, and
                # the disagreement rides back to the Orchestrator on the next packet so it can
                # act on what actually failed rather than being told only that it was wrong.
                # THIS claim's event is already in the log, so the count INCLUDES it -- adding
                # one here would stop the relay a whole attempt early.
                refusals = self._completion_refusals()
                self._completion_blocker = corroborate_mod.blocker_line(verdict)
                if refusals >= max(1, int(self.config.completion_attempt_limit)):
                    self.state.mark_delivery(self.relay_id, reply.message_id,
                                             state_mod.OBSERVED)
                    self._finish(STOP_COMPLETION_UNCORROBORATED, state=state_mod.PAUSED,
                                 detail={"message_id": reply.message_id,
                                         "refusals": refusals,
                                         "corroboration": verdict})
                    result.stop = STOP_COMPLETION_UNCORROBORATED
                    result.note = verdict["reason"]
                    return result
                result.note = verdict["reason"]
            self.state.update(self.relay_id, round_trips=int(row["round_trips"]) + 1)
        else:
            # A REFUSED COMPLETION CLAIM RIDES BACK HERE. Telling the Orchestrator only
            # that it was wrong invites it to re-assert; telling it which check failed, with
            # the measured output, is what lets it finish the work.
            blockers = tuple(b for b in (self._completion_blocker,) if b)
            self._completion_blocker = ""
            payload = packets_mod.execution_to_orchestrator(
                exchange_no=exchange_no, agent_text=safe_text,
                observation=observation_text or "Repository observation was not requested.",
                agent_error=reply.error, session_id=reply.session_id or row["execution_session"],
                blockers=blockers)
            # THE SANITISED FORM IS WHAT IS PERSISTED. ``classification`` is explicit that a
            # credential is never written to durable storage, so the ledger and the event log
            # keep the classified text -- not the raw turn with the token still in it.
            self._enqueue(reply.direction, reply.message_id, payload,
                          exchange_no=exchange_no, causal_parent=pending["message_id"],
                          raw=safe_text, provenance=reply.provenance,
                          observed_at=reply.observed_at)
            if observation_gate is not None and not observation_gate.allowed:
                # The agent did something the profile does not grant. Its turn is safely in the
                # record now, so the hold stops the relay without losing the work, the packet
                # the Orchestrator would have seen, or the evidence of what produced the effect.
                self._raise_owner_hold(observation_gate, gate_name="observation")
                result.hold = observation_gate.to_dict()
                self._finish(STOP_OWNER_HOLD, state=state_mod.OWNER_HOLD,
                             detail=observation_gate.to_dict())
                result.stop = STOP_OWNER_HOLD
                return result

        loop = self._repetition_stop(reply.direction)
        if loop:
            self._finish(loop, detail={"role": target_role,
                                       "reason": "the same turn arrived %d times in a row"
                                                 % (int(self.config.repeat_limit) + 1)})
            result.stop = loop
        return result

    # -- drive ------------------------------------------------------------------------------------
    def run(self, *, max_steps: int = 0) -> dict:
        """Drive until terminal. Returns the closing summary ``relay status`` prints."""
        steps = 0
        while True:
            row = self._row()
            if row["state"] != state_mod.RUNNING:
                break
            if max_steps and steps >= int(max_steps):
                break
            res = self.step()
            steps += 1
            self._log("exchange %d %s -> %s%s"
                      % (res.exchange_no, res.direction or "seed",
                         COUNTERPART.get(res.direction, "?") if res.direction else "ORCHESTRATOR",
                         (" [%s]" % res.stop) if res.stop else ""))
            if res.stop:
                break
        return self.summary()

    def stop(self, reason: str = STOP_OPERATOR) -> None:
        self._finish(reason)

    # -- the operator's question ---------------------------------------------------------------
    def summary(self) -> dict:
        return summarise(self.state, self.relay_id)


def summarise(st: state_mod.RelayState, relay_id: str) -> dict:
    """The status surface, built from the DURABLE RECORD ALONE. PURE-ish (one read).

    Deliberately not built from a live kernel: ``relay status`` runs in a different process from
    ``relay start``, and an operator asking what happened must get the same answer either way.
    """
    import json
    row = st.get(relay_id)
    if row is None:
        return {"found": False, "relay_id": relay_id}
    cfg = json.loads(row.get("config_json") or "{}")
    counts = st.counts(relay_id)
    last_o = st.last_message(relay_id, FROM_ORCHESTRATOR)
    last_e = st.last_message(relay_id, FROM_EXECUTION)
    obs = st.observations(relay_id, limit=1)
    return {
        "found": True,
        "relay_id": relay_id,
        "state": row["state"],
        "stop_reason": row["stop_reason"],
        "project": row["project_root"],
        "objective": row["objective"],
        "orchestrator": {"kind": row["orchestrator_kind"],
                         "conversation": row["orchestrator_conversation"],
                         "facts": cfg.get("orchestrator_facts", {}),
                         "assurance": cfg.get("orchestrator_assurance", "")},
        "execution": {"kind": row["execution_kind"], "session": row["execution_session"],
                      "facts": cfg.get("execution_facts", {}),
                      "assurance": cfg.get("execution_assurance", "")},
        "authority_profile": row["authority_profile"],
        "exchanges": int(row["exchange_no"]),
        "round_trips": int(row["round_trips"]),
        "messages_observed": counts["observed"],
        "messages_delivered": counts["delivered"],
        "owner_hold": row["owner_hold"],
        # WHAT THE OWNER IS ACTUALLY BEING ASKED FOR. A reason string tells a human something is
        # wrong; this tells them what to sign. Without it the only way to act on a hold was to
        # read the event log by hand.
        "owner_holds": [{"hold_id": h.get("hold_id"), "gate": h.get("gate"),
                         "effect_class": h.get("effect_class"),
                         "required": list(h.get("required") or ()),
                         "reason": h.get("reason", "")}
                        for h in outstanding_owner_holds(st, relay_id)],
        # WHY IS IT WAITING? The architecture's status surface must answer that without an
        # operator inspecting SQLite, and "which endpoint owes us a turn" is the answer for
        # every ordinary pause.
        "waiting_on": row["awaiting_role"] or "",
        "waiting_for_message": row["awaiting_message_id"] or "",
        "started_at": row["started_at"],
        "last_activity_at": row["last_activity_at"],
        "last_direction": (last_o or {}).get("direction") if
        (last_o or {}).get("observed_at", 0) >= (last_e or {}).get("observed_at", 0)
        else (last_e or {}).get("direction"),
        "repo": (obs[0]["payload"].get("snapshot") if obs else {}) or {},
        "instrument": KERNEL_INSTRUMENT,
    }

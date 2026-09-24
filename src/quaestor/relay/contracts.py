"""contracts -- the two relay endpoint interfaces, the message they carry, and the honest
separation between what an endpoint CAN DO and what this platform can PROVE about it.

WHY NOT ``Executor``
--------------------
``Executor.execute(req) -> ExecOutcome`` is a request/response over a child process. It has no
notion of "the same conversation", no notion of "a turn I already delivered", and no notion of
"resume". Growing it until it did would make Program Mode's admission path carry relay concerns
it has no use for, and would make every relay concern reachable only through a program. So the
relay declares its own contract, and the two live side by side.

The contract is SYNCHRONOUS. The architecture sketches ``async def``; the substrate this is
built on -- store, git probes, fingerprints, authority -- is entirely synchronous, and a single
relay drives exactly one conversation at a time by construction (that serialisation is what
makes duplicate-delivery reasoning tractable). Introducing an event loop would buy concurrency
the product contract explicitly does not want.

CAPABILITY IS NOT ASSURANCE
---------------------------
``adapters.registry`` carries one boolean, ``write_capable``, that is read in two incompatible
senses: "this participant cannot mutate a repository" and "we cannot prove this participant is
confined". Those are different facts and conflating them produces two opposite errors -- an
agent that really is editing files described as incapable of it, and a refusal to let a useful
weak integration participate at all.

``EndFacts`` separates them. Capability facts say what the endpoint DOES. Proof facts say what
this build can DEMONSTRATE. Assurance is then COMPUTED from the proof facts through the existing
``adapters.assurance`` ladder -- never declared by the endpoint about itself.

PURE module: dataclasses, string constants and one pure mapping into the assurance ladder.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Mapping

CONTRACTS_INSTRUMENT = "relay.contracts/1"

# ---------------------------------------------------------------------------------------------
# ROLES AND DIRECTIONS
# ---------------------------------------------------------------------------------------------
#: The two ends. A single module may implement both roles, but a given INSTANCE holds one:
#: an endpoint that could silently swap roles would make "who decided this?" unanswerable.
ROLE_ORCHESTRATOR = "ORCHESTRATOR"
ROLE_EXECUTION = "EXECUTION"

FROM_ORCHESTRATOR = "FROM_ORCHESTRATOR"
FROM_EXECUTION = "FROM_EXECUTION"
#: The opening brief. The relay AUTHORS it -- project identity, counterpart facts, objective --
#: so the ledger must not record it as something an endpoint said. A courier that filed its own
#: cover note under the sender's name would make "who decided this?" unanswerable at exactly the
#: message where the answer matters most.
FROM_RELAY = "FROM_RELAY"

#: Which end a message travels TO, given where it came from. The relay is a courier with exactly
#: two stops, so this is total and needs no configuration.
COUNTERPART = {FROM_ORCHESTRATOR: ROLE_EXECUTION,
               FROM_EXECUTION: ROLE_ORCHESTRATOR,
               FROM_RELAY: ROLE_ORCHESTRATOR}


# ---------------------------------------------------------------------------------------------
# NAMED REFUSALS -- an endpoint failure must always have a name a status surface can print.
# ---------------------------------------------------------------------------------------------
END_UNREACHABLE = "END_UNREACHABLE"
END_NOT_AUTHENTICATED = "END_NOT_AUTHENTICATED"
END_SESSION_LOST = "END_SESSION_LOST"
END_WORKSPACE_MISMATCH = "END_WORKSPACE_MISMATCH"
END_PROVIDER_ERROR = "END_PROVIDER_ERROR"
END_KIND_NOT_BUILDABLE = "END_KIND_NOT_BUILDABLE"

#: ``resume`` outcomes. UNSUPPORTED is a first-class ANSWER, not a failure: an endpoint that
#: cannot resume must say so rather than let the kernel believe continuity it does not have.
RESUME_RESUMED = "RESUMED"
RESUME_UNSUPPORTED = "RESUME_UNSUPPORTED"
RESUME_LOST = "RESUME_LOST"

#: Endpoint liveness, as OBSERVED. UNKNOWN is not IDLE: an endpoint we could not read must never
#: present as an endpoint we read and found ready.
END_IDLE = "IDLE"
END_BUSY = "BUSY"
END_UNKNOWN = "UNKNOWN"
END_FAILED = "FAILED"

# -- probe verdicts ---------------------------------------------------------------------------
# WHY THESE EXIST SEPARATELY FROM ``EndStatus``. ``status()`` answers "is this endpoint's LOCAL
# situation healthy?" -- is there a credential, is a server listening, is a page attached. It
# cannot see past its own gateway. A relay was live-observed running against an endpoint whose
# status() said IDLE while every upstream request returned HTTP 503, and against a model that
# answers a bare "PONG" probe with an APIError. From the kernel's side an unusable MODEL and a
# dead ENDPOINT were indistinguishable, so the operator learned at exchange 1 instead of at
# start. A probe answers the other question: does a real turn actually come back?
#: A real turn came back. The provider path works end to end.
PROBE_OK = "PROBE_OK"
#: The endpoint is reachable and the request failed upstream of it -- 5xx, 429, gateway timeout.
#: The fault is transient-shaped and belongs to the provider, not to this configuration.
PROBE_UPSTREAM_FAILED = "PROBE_UPSTREAM_FAILED"
#: The provider answered and REFUSED this model or these credentials -- an unknown model id, a
#: rejected key, a model that errors on every inference. Retrying will not help; the operator
#: must change something.
PROBE_REFUSED = "PROBE_REFUSED"
#: This endpoint cannot be probed without causing a side effect the operator did not ask for.
#: An HONEST answer, never a passing one: nothing was measured, so nothing is claimed.
PROBE_UNSUPPORTED = "PROBE_UNSUPPORTED"


@dataclass(frozen=True)
class EndProbe:
    """What a real exchange with the provider actually did. NEVER raises out of ``probe()``.

    ``ok`` is true for exactly one verdict. Every other outcome -- including "could not ask" --
    is false, so a caller cannot mistake an unmeasured endpoint for a working one.
    """

    state: str
    detail: str = ""
    latency_s: float = 0.0
    model: str = ""
    http_status: int = 0
    instrument: str = "relay.probe/1"

    def __post_init__(self):
        # REDACTED HERE, AT THE ONE PLACE EVERY PROBE DETAIL FLOWS THROUGH. ``detail`` embeds the
        # provider's own response body, and that body reaches the durable event log, the stop
        # detail, `relay doctor` and the CLI. Providers routinely echo request context into an
        # error -- a rejected key comes back inside the message that rejected it. The identical
        # defect shipped one PR earlier for verification-check output; classifying at each call
        # site was what let it happen, because a third call site was added and forgot. An end
        # author cannot forget this one.
        from quaestor.core import classification
        object.__setattr__(self, "detail", classification.classify(str(self.detail or "")).text)

    @property
    def ok(self) -> bool:
        return self.state == PROBE_OK

    @property
    def measured(self) -> bool:
        """Did anything actually get asked? UNSUPPORTED is not a measurement."""
        return self.state != PROBE_UNSUPPORTED

    def to_dict(self) -> dict:
        return {"state": self.state, "ok": self.ok, "measured": self.measured,
                "detail": self.detail, "latency_s": round(float(self.latency_s), 3),
                "model": self.model, "http_status": int(self.http_status),
                "instrument": self.instrument}


def digest(text) -> str:
    """The content digest used for replay and no-progress detection. PURE.

    Whitespace-normalised on purpose: a provider that re-emits the same answer with different
    trailing whitespace is repeating itself, and a loop guard that could be defeated by a
    newline would be decorative.
    """
    norm = " ".join(str(text or "").split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RelayMessage:
    """One completed turn observed at an endpoint.

    ``message_id`` is ENDPOINT-NATIVE and must be stable across a restart of this process --
    that stability is the whole basis of duplicate-delivery prevention. An endpoint that cannot
    supply a stable native id must MINT a deterministic one (see ``ends.http_chat``), never an
    incrementing counter held in memory.

    ``complete`` is the endpoint's own answer to "is this a finished turn?". A partial or
    still-streaming turn is never forwarded: the architecture is explicit that partial replies
    must not be delivered as complete work.

    ``error`` is PROVIDER-AUTHORED and is classified at construction; ``text`` deliberately is
    not. ``__post_init__`` says why the two fields have different owners.
    """

    message_id: str
    direction: str
    text: str
    complete: bool
    observed_at: float
    conversation_id: str = ""
    session_id: str = ""
    provenance: Mapping = field(default_factory=dict)
    error: str = ""

    def __post_init__(self):
        # CLASSIFIED HERE, AT THE ONE PLACE EVERY PROVIDER ERROR ENTERS THE RELAY. ``error`` is
        # written by the PROVIDER -- an HTTP response body, an exception string -- and it then
        # travels further than any other field on this contract:
        # ``packets.execution_to_orchestrator`` copies it VERBATIM into a packet that is BOTH
        # persisted as the delivery ledger's text column AND delivered to the REMOTE
        # Orchestrator, and ``relay.receive.incomplete`` writes it into the durable event log.
        # Providers echo request context into their errors -- a rejected key comes back inside
        # the message that rejected it, and a urllib exception carries the request URL.
        #
        # ``EndProbe`` closed this exact class one PR earlier, and its comment states the
        # lesson: classifying PER CALL SITE is what let the defect ship, because a new call site
        # was added and did not know. ``RelayMessage`` was the call site that was forgotten. An
        # end author cannot forget this one.
        #
        # ``text`` IS DELIBERATELY NOT CLASSIFIED HERE, and that is not an oversight. The kernel
        # sanitises the turn through ``packets.sanitise`` and emits ``relay.sanitised`` carrying
        # the COUNT of what it removed; that count is the evidence an auditor reads to know a
        # credential was caught. Classifying ``text`` at construction would leave the kernel
        # nothing to remove, the count would fall to zero, and the record would report a clean
        # turn for a turn that carried a token -- redaction that destroyed its own proof. One
        # owner per field: ``text`` belongs to the kernel, ``error`` belongs here.
        from quaestor.core import classification
        object.__setattr__(self, "error", classification.classify(str(self.error or "")).text)

    @property
    def content_digest(self) -> str:
        return digest(self.text)

    def to_dict(self) -> dict:
        return {"message_id": self.message_id, "direction": self.direction,
                "complete": bool(self.complete), "observed_at": self.observed_at,
                "conversation_id": self.conversation_id, "session_id": self.session_id,
                "content_digest": self.content_digest, "provenance": dict(self.provenance or {}),
                "error": self.error, "chars": len(self.text or "")}


@dataclass(frozen=True)
class SendReceipt:
    """What an endpoint says about a delivery ATTEMPT.

    ``accepted`` means the endpoint took the message. ``native_id`` is what the endpoint called
    it -- recorded so a reconciling process can ask the endpoint "do you already hold this?"
    instead of guessing whether a crashed delivery landed.

    ``reason`` is PROVIDER-AUTHORED and is classified at construction, for the same reason
    ``RelayMessage.error`` is.
    """

    accepted: bool
    native_id: str = ""
    reason: str = ""
    detail: Mapping = field(default_factory=dict)

    def __post_init__(self):
        # THE SAME FIELD BY A DIFFERENT NAME, SO THE SAME RULE. Classified in this commit rather
        # than left for a later audit because it is REACHABLE WITH PROVIDER TEXT TODAY, not in
        # principle: ``ends.opencode.send`` sets ``reason`` to "the server answered HTTP %s: %s"
        # carrying the first 500 bytes of the server's OWN response body, and a second end sets
        # it from a raw exception string. The kernel then writes that string into the durable
        # ``relay.delivery.refused`` event and returns it to the status surface as ``error``
        # -- the same destination ``RelayMessage.error`` reaches. A leak here would be the
        # identical defect wearing a different field name.
        #
        # ``detail`` is a MAPPING the ends fill with their own identifiers -- session id, base
        # url -- not with provider prose, so it is left alone: classification sanitises prose,
        # and walking a mapping to reach the strings inside it would be a second,
        # differently-shaped rule an end author would have to remember. ``native_id`` is
        # endpoint-native identity and must survive intact: it is what crash reconciliation
        # asks the endpoint about.
        from quaestor.core import classification
        object.__setattr__(self, "reason", classification.classify(str(self.reason or "")).text)


@dataclass(frozen=True)
class EndStatus:
    """One reading of an endpoint's liveness. NEVER raises out of ``status()``.

    ``detail`` is PROVIDER-AUTHORED prose and is classified at construction, for the same reason
    ``RelayMessage.error`` is.
    """

    state: str
    identity: str = ""
    detail: str = ""
    facts: Mapping = field(default_factory=dict)

    def __post_init__(self):
        # THIRD FIELD, SAME ROUTE, SAME RULE -- included on the same evidence-led test as
        # ``SendReceipt.reason``: it is reachable with provider text in the ends that exist.
        # ``ends.opencode.status`` composes it as "the agent is retrying: %s" from the server's
        # own message, and as "%s: %s" from a urllib exception, which embeds the request URL;
        # ``ends.http_chat.open`` reports the base url and where a credential was resolved from;
        # a third reports END_PROVIDER_ERROR carrying whatever the provider surface said. The
        # kernel writes it into the durable ``relay.end.opened`` event and into the stop
        # detail of a disconnect, so it lands in the same event log by the same route.
        #
        # ``state`` is a closed vocabulary of constants and ``facts`` is a structured mapping,
        # so neither is prose to classify. ``identity`` is the endpoint-native conversation or
        # session id and must survive byte-for-byte: duplicate-delivery prevention and resume
        # both compare it, so a redacted identity would silently break continuity rather than
        # protect anything.
        from quaestor.core import classification
        object.__setattr__(self, "detail", classification.classify(str(self.detail or "")).text)

    @property
    def usable(self) -> bool:
        return self.state in (END_IDLE, END_BUSY)


@dataclass(frozen=True)
class EndFacts:
    """WHAT THIS ENDPOINT DOES, and separately, WHAT THIS BUILD CAN PROVE ABOUT IT.

    Every field defaults to the honest floor: a capability nobody implemented is absent, and a
    proof nobody performed is absent. An endpoint author who forgets a field therefore
    understates rather than overstates -- the only safe direction for a fact a governance
    surface will print.
    """

    kind: str
    role: str
    provider_family: str = ""
    model: str = ""

    # -- capability: what it can actually do ---------------------------------------------------
    can_send: bool = False
    can_receive: bool = False
    can_observe: bool = False
    #: TRUE means the participant is able to change the repository. It says NOTHING about
    #: whether we can prove how tightly it is controlled -- that is the proof block below.
    can_mutate_repo: bool = False
    manages_lifecycle: bool = False
    supports_session_resume: bool = False
    supports_conversation_resume: bool = False

    # -- proof: what this build can demonstrate -----------------------------------------------
    proves_message_identity: bool = False
    proves_workspace_identity: bool = False
    proves_capability_surface: bool = False
    proves_readonly_behavior: bool = False
    proves_confinement: bool = False

    #: Free-text, printed verbatim in ``relay doctor``. The place to say what the transport
    #: genuinely cannot establish, so a limitation is visible without reading this file.
    limits: tuple = ()

    def to_dict(self) -> dict:
        return {"kind": self.kind, "role": self.role,
                "provider_family": self.provider_family, "model": self.model,
                "capability": {"can_send": self.can_send, "can_receive": self.can_receive,
                               "can_observe": self.can_observe,
                               "can_mutate_repo": self.can_mutate_repo,
                               "manages_lifecycle": self.manages_lifecycle,
                               "supports_session_resume": self.supports_session_resume,
                               "supports_conversation_resume":
                                   self.supports_conversation_resume},
                "proof": {"proves_message_identity": self.proves_message_identity,
                          "proves_workspace_identity": self.proves_workspace_identity,
                          "proves_capability_surface": self.proves_capability_surface,
                          "proves_readonly_behavior": self.proves_readonly_behavior,
                          "proves_confinement": self.proves_confinement},
                "limits": list(self.limits)}


def assurance_probes(facts: EndFacts) -> dict:
    """``EndFacts`` -> the probe vocabulary ``adapters.assurance`` already grades. PURE.

    The mapping is deliberately a translation and not a second ladder: reusing
    ``compute_assurance`` means a relay endpoint and a Program Mode adapter are graded by the
    same rules, and a rung nobody proved comes back unproven in both.

    Note which side of the split each probe reads. ``lifecycle``/``cancel_works`` are
    CAPABILITY questions -- can this thing be started and stopped by us at all. Everything at
    GOVERNED and above is a PROOF question. That is exactly why an unconfined agent that really
    does write files lands at DIALOGUE or MANAGED with ``can_mutate_repo=True``: honest about
    what it does, honest about what we cannot show.
    """
    return {
        "observe_probe": bool(facts.can_observe),
        "roundtrip": bool(facts.can_send and facts.can_receive),
        "message_id_preserved": bool(facts.proves_message_identity),
        "cancel_works": bool(facts.manages_lifecycle),
        "lifecycle": bool(facts.manages_lifecycle),
        "workspace_containment": bool(facts.proves_workspace_identity),
        "readonly_holds": bool(facts.proves_readonly_behavior),
        "container_validation": bool(facts.proves_confinement),
    }


def computed_assurance(facts: EndFacts) -> str:
    """The highest assurance rung this endpoint's PROOFS support, or "" for none. PURE."""
    from quaestor.adapters.assurance import CONFINED, compute_assurance
    level, _refusals = compute_assurance(assurance_probes(facts), CONFINED)
    return level


class RelayEnd:
    """The base both roles share. Subclasses override; none of these guess.

    Every method that talks to something outside this process must return a NAMED outcome
    rather than raise: a relay whose endpoint raised has no status to show an operator, and
    "the process died" is not a diagnosis.
    """

    #: Set by subclasses. Read by the registry, the doctor and the status surface.
    facts: EndFacts

    def open(self) -> EndStatus:
        """Attach. Never launches anything the operator did not ask for."""
        raise NotImplementedError

    def status(self) -> EndStatus:
        """One liveness reading. NEVER raises."""
        raise NotImplementedError

    def identity(self) -> str:
        """The durable conversation/session identity, or "" when there is none yet."""
        raise NotImplementedError

    def resume(self, identity: str) -> tuple:
        """``(outcome, detail)`` where outcome is one of the RESUME_* constants.

        RESUME_UNSUPPORTED is an honest answer and callers must treat it as one. Reporting
        RESUME_RESUMED for an endpoint that merely started a fresh conversation would fabricate
        the single property restart/recovery exists to establish.
        """
        raise NotImplementedError

    def send(self, text: str, *, message_id: str) -> SendReceipt:
        """Deliver one message. ``message_id`` is the RELAY's id for this delivery.

        An endpoint that can carry the id natively MUST, because that is what turns crash
        reconciliation from a guess into a question with an answer.
        """
        raise NotImplementedError

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0) -> RelayMessage | None:
        """The newest COMPLETED turn strictly newer than ``after_id``, or None.

        Returning a turn that was already returned is the stale-replay failure the kernel
        guards against; an endpoint should not rely on that guard to be correct.
        """
        raise NotImplementedError

    def probe(self) -> "EndProbe":
        """Exercise the provider for real and report what came back. NEVER raises.

        The default is PROBE_UNSUPPORTED, which is the honest floor: an endpoint whose author
        did not implement this has not proven anything, and must not inherit a pass from one
        that did. Overriding it is how an endpoint earns the right to be trusted at start.

        A probe MUST NOT disturb the relay's own conversation. Where exercising the model would
        mean writing into the operator's thread, the correct implementation is to decline with
        PROBE_UNSUPPORTED and say so -- a probe that pollutes the conversation it is protecting
        has cost more than it measured.
        """
        return EndProbe(PROBE_UNSUPPORTED,
                        "this endpoint does not implement a model-exercising probe, so nothing "
                        "about the provider path has been measured")

    def close(self) -> None:
        """Release local resources. Must never terminate a session the operator owns."""
        return None

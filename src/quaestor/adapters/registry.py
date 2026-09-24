"""registry -- the provider capability declarations and policy-driven seat routing.

WHAT THIS MODULE IS (PRD.md §7.5)
---------------------------------
PRD.md §7.5 asks for a provider/model registry of measured or declared facts, and that
"role/endpoint resolution should use those facts plus policy". Configuration says who MAY
hold a seat; this registry says who CAN. ``PROVIDER_REGISTRY`` is the CAN layer: one
declaration per executor kind, carrying the facts role resolution routes over.
``resolve_seat`` turns seat + policy constraints into a chosen kind; ``chain_next`` walks an
ordered provider chain with reconciliation-aware failover (PRD.md §7.3: "'try the next model'
must not become disguised duplicate execution"); ``check_pairing`` enforces the
epistemic-independence pairing policy of PRD.md §7.2.

DECLARATIONS, NOT MEASUREMENTS -- THE HONESTY BOUNDARY
------------------------------------------------------
Every fact in this file is DECLARED. A declared ``credential_mode`` says how the provider
is *meant* to be billed; only the provider's own preflight (credential_policy, measured at
dispatch) proves which credential actually exists. A declared context window is marketing
until measured. That is why ``current_health``/``quota_state`` default to None for every
entry and why entries carry ``fact_status``: "declared" (routable, unproven) or "buildable"
(executor constructible + real credential preflight shipped, bd quaestor-1ng -- still NOT
"measured"). The MEASURED truth about who actually ran lives in the durable
``run.provenance`` event, written from the resolved dispatch spec -- never from this table
and never from anything a model reports about itself. Routing may consult declarations;
claims may only cite measurements.

WHY THIS LIVES IN adapters/, NOT core/
--------------------------------------
The registry is data ABOUT providers but contains NO provider: importing it loads no
vendor code, so core's static import of this module adds no vendor edge to the layering
graph. The inversion seam (core.executors.registry via importlib) stays exactly where it
was for code that BUILDS executors; this module only decides WHO is offered the seat.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence
from typing import NamedTuple

REGISTRY_INSTRUMENT = "adapters.registry/1"

# ---- named refusals ---------------------------------------------------------------------------
#: No candidate satisfies the seat: unknown kind, non-assignable seat, or every candidate
#: rejected under policy. Always NAMED -- an unresolvable seat must never become a silent
#: fallback to whatever provider happened to be configured elsewhere (PRD.md §7 matrix).
SEAT_UNRESOLVABLE = "SEAT_UNRESOLVABLE"
#: Reconciliation-aware failover refusal (PRD.md §7.3): the previous holder died after a
#: POSSIBLE write, so switching providers would be a disguised blind retry.
CHAIN_BLOCKED_AMBIGUOUS_WRITE = "CHAIN_BLOCKED_AMBIGUOUS_WRITE"
#: Every chain member is exhausted (availability), none remains to try.
CHAIN_EXHAUSTED = "CHAIN_EXHAUSTED"
#: Every remaining chain member violates the epistemic-independence pairing policy; the seat
#: is refused rather than the pair breached ("exhausting openai->gemini onto claude while
#: implementation holds claude refuses the seat rather than violating the pair").
CHAIN_POLICY_REFUSED = "CHAIN_POLICY_REFUSED"
#: PAI-Bus rule (PRD.md §7.3 / P2.7): a chain must span >= 2 distinct vendor families --
#: a single-family "fallback" is one vendor wearing two hats.
CHAIN_SINGLE_FAMILY = "CHAIN_SINGLE_FAMILY"
#: Pairwise form: the named role pair shares a provider family.
EPISTEMIC_INDEPENDENCE_UNMET = "EPISTEMIC_INDEPENDENCE_UNMET"
#: Risk-class form: a candidate touching a protected risk class fails the distinct-provider
#: admission requirement that class escalates.
ROLE_PROVIDER_POLICY_REFUSED = "ROLE_PROVIDER_POLICY_REFUSED"


#: PRD.md §7.1: the assignable seats of the Role x Provider matrix. OWNER is
#: deliberately ABSENT -- "always human, never configurable, never delegated" -- so no
#: resolution path in this module can ever emit a kind for it. (Research lanes are a lane
#: kind, not a governed seat; they inherit the project default without entering the matrix.)
#:
#: THE ONE DECLARATION. ``projects.config.ASSIGNABLE_ROLES`` is an ALIAS of this tuple, not a
#: second copy: the two were separately maintained until adding STRATEGIST made them disagree
#: and a manifest parsed a seat the router then refused as non-existent. This module owns the
#: vocabulary because it is the layer that ROUTES seats, and it imports nothing that could make
#: the dependency awkward in the other direction.
#:
#: STRATEGIST joined last, deliberately: it was absent not because it is owner-like but because
#: nothing could fill it -- every decision path ended at a human. Now that a model may hold it,
#: the OWNER exclusion above stops being a formality and becomes the whole boundary. STRATEGIST
#: disposes of QUESTIONS; OWNER disposes of CAPABILITY; only the first is delegable.
ASSIGNABLE_SEATS = ("planner", "strategist", "implementation", "verification",
                    "adversarial_review", "integration")

#: Deterministic routing order for unpinned candidates. A dict preserves insertion order,
#: but an explicit tuple makes "first candidate wins" a stated contract rather than an
#: accident of alphabetical happenstance.
#: GATEWAY KINDS: one executor name fronting MANY vendors.
#:
#: Everything in this module assumes ONE family per kind -- ``claude-cli`` is anthropic, full
#: stop -- and every epistemic-independence guarantee is built on that. A gateway breaks it:
#: ``openrouter`` running anthropic/claude-opus and ``openrouter`` running openai/gpt-5 are two
#: different vendors sharing a kind name. If the gateway reported ITSELF as the family, two
#: Anthropic models would pass the cross-vendor check because the proxy name matched, and
#: adversarial review would silently become one vendor reviewing itself with nothing anywhere
#: reporting a problem.
#:
#: So a gateway kind carries no family of its own. The family comes from the MODEL, and a
#: gateway named WITHOUT one resolves to "" -- refused wherever a family is required, because an
#: unnamed model is an unknown vendor and an unknown vendor cannot be certified independent of
#: anything. The kind syntax is ``<gateway>:<vendor>/<model>``.
GATEWAY_KINDS = frozenset({"openrouter"})

#: Vendor prefix -> the SAME family vocabulary the direct providers use. That shared vocabulary
#: is the point: "openrouter:anthropic/..." and "claude-cli" must collide in check_pairing,
#: because routing an Anthropic model through a proxy buys a different bill, not a second
#: opinion. A prefix absent here yields "" rather than a guess -- a vendor this build has never
#: heard of must not be assumed independent of everything else.
GATEWAY_VENDOR_FAMILY = {
    "anthropic": "anthropic", "openai": "openai", "google": "google",
    "meta-llama": "meta", "mistralai": "mistral", "deepseek": "deepseek",
    "qwen": "qwen", "x-ai": "xai", "amazon": "amazon", "cohere": "cohere",
    "microsoft": "microsoft", "nvidia": "nvidia", "perplexity": "perplexity",
}

PROVIDER_ORDER = ("fake", "claude-cli", "claude-container", "gemini-cli", "codex-cli",
                  "gpt-plan", "local-llama")


def _entry(provider_family: str, credential_mode: tuple, write_capable: bool,
           local_or_remote: str, context_window_class: str, cost_class: str,
           fact_status: str = "declared", resumes_session: bool = False) -> dict:
    """One DECLARED capability row. PURE. health/quota start None: nothing has been proven.

    ``fact_status`` is the honesty label: "declared" (default) marks a routable-but-unproven
    entry; "buildable" marks one whose executor this build can actually construct AND whose
    credential preflight is a real measured function (bd quaestor-1ng). NEITHER value means
    "healthy": the MEASURED truth about who ran lives only in durable run.provenance.
    """
    return {"provider_family": provider_family,
            "credential_mode": tuple(credential_mode),
            "write_capable": bool(write_capable),
            "local_or_remote": local_or_remote,
            "context_window_class": context_window_class,
            "cost_class": cost_class,
            # Measured-at-runtime facts. None == UNPROVEN, not "healthy": an entry nobody
            # has probed must not look like one somebody checked.
            "current_health": None,
            "quota_state": None,
            "fact_status": str(fact_status),
            #: Can this provider be handed its OWN prior session and continue it? Declared,
            #: never assumed: an executor that does not know the field does not politely
            #: ignore it -- FakeConfig(**cfg) raises TypeError on an unexpected key, and a
            #: dispatch that dies constructing its executor looks like a broken installation
            #: rather than an unsupported option.
            "resumes_session": bool(resumes_session)}


#: The declarations themselves. claude-cli/fake are backed by buildable executors
#: (executors.registry.KNOWN_KINDS); gemini-cli/gpt-plan/local-llama are DECLARED-BUT-UNBUILDABLE
#: (bd quaestor-ubg): they stay declared as configuration targets for a build that ships their
#: executors, and dispatch ADMISSION refuses them by name (KIND_NOT_BUILDABLE_IN_THIS_BUILD) --
#: a seat can no longer be routed to one and then die in executors.registry.build().
#: codex-cli is "buildable" (bd quaestor-1ng): its executor constructs end to end and its
#: credential preflight is a real measured function -- still NOT "measured": only run.provenance
#: proves a run. command/file-inbox (bd quaestor-cjj, quaestor-ru1.19) are buildable bridges.
PROVIDER_REGISTRY: Mapping[str, Mapping] = {
    "fake": _entry("test", ("subscription", "api"), True, "local", "small", "free"),
    "claude-cli": _entry("anthropic", ("subscription", "api"), True, "remote", "large", "medium"),
    "claude-container": _entry("anthropic", ("api",), True, "remote", "large", "high"),
    "gemini-cli": _entry("google", ("api", "subscription"), True, "remote", "xlarge", "medium"),
    "codex-cli": _entry("openai", ("api", "subscription"), True, "remote", "large", "medium",
                        fact_status="buildable"),
    "gpt-plan": _entry("openai", ("api", "subscription"), False, "remote", "large", "medium"),
    # A GATEWAY (see GATEWAY_KINDS). provider_family is deliberately "": asking this table for
    # the kind's vendor is the wrong question, and returning a plausible answer would be worse
    # than returning none. Reachable ONLY through an explicit pin naming a model, which is why
    # it is absent from PROVIDER_ORDER. credential_mode is ("api",) and nothing else -- OpenRouter
    # is API-billed, and declaring subscription here would falsify the one fact
    # credential_policy exists to establish.
    "openrouter": _entry("", ("api",), True, "remote", "large", "medium",
                         fact_status="buildable"),
    # A DIALOGUE-tier transport, not a governed executor. write_capable=False is requirement 6
    # made structural: resolve_seat filters on it, so this kind cannot reach a seat that touches
    # a repository however it is pinned. fact_status stays "declared" PERMANENTLY -- a browser
    # session cannot produce the billing evidence "buildable" asserts, and labelling it
    # otherwise would falsify the one fact credential_policy exists to establish.
    "chatgpt-web": _entry("openai", ("subscription",), False, "remote", "large", "medium",
                          resumes_session=True),
    "local-llama": _entry("local", (), True, "local", "medium", "low"),
    # GENERIC TRANSPORT SEATS (bd quaestor-cjj, quaestor-ru1.19). These are §5.2 Tier 1 dialogue
    # bridges: prompt in, reply out, no containment proof, no lifecycle. Declared facts are the
    # honest minimum: provider_family "" -- a user-supplied command or an arbitrary external
    # consumer has NO vendor, and inventing one would corrupt every independence check that
    # reads this column; credential_mode () -- the bridge performs no credential-bearing
    # authentication of its own (run_preflight has an explicit NOT_APPLICABLE branch, so this
    # is a real explicit answer, not the fail-closed fallback); write_capable False -- neither
    # transport can prove confinement, so neither can ever hold a writing seat; context/cost
    # "unknown" -- we genuinely do not know what an operator's command costs or fits.
    # fact_status "buildable": the executor constructs end to end (executors.bridge) and the
    # preflight is an explicit branch -- still NOT "measured": only run.provenance proves a run.
    # Both are ABSENT from PROVIDER_ORDER on purpose, for the same reason the bare gateway is:
    # each requires explicit seat config (an argv template / a filebox root), so an unpinned
    # seat must never silently land on one.
    "command": _entry("", (), False, "local", "unknown", "unknown",
                      fact_status="buildable"),
    "file-inbox": _entry("", (), False, "local", "unknown", "unknown",
                         fact_status="buildable"),
}


def is_declared(kind: str) -> bool:
    """Is this executor kind part of the declared namespace? PURE.

    The namespace check is what makes a typo'd pin a NAMED refusal instead of a silent
    fallback: a seat pinned to 'typo-cli' must stop the program, not quietly inherit
    another provider's work.
    """
    return split_gateway_kind(kind)[0] in PROVIDER_REGISTRY


def split_gateway_kind(kind: str) -> tuple:
    """``'openrouter:anthropic/claude-opus-4'`` -> ``('openrouter', 'anthropic/claude-opus-4')``.

    PURE and TOTAL. A kind with no ``:`` is its own base with an empty model, so every caller
    can split unconditionally instead of testing for gateway-ness first.
    """
    raw = str(kind or "")
    base, sep, model = raw.partition(":")
    return (base, model) if sep else (raw, "")


def resumes_session(kind: str) -> bool:
    """Does this kind accept its own prior session id? PURE. False for anything undeclared.

    Gateway-aware, like ``provider_family``: the base kind is what builds the executor.
    """
    base, _model = split_gateway_kind(kind)
    row = PROVIDER_REGISTRY.get(base)
    return bool(row and row.get("resumes_session"))


def gateway_model(kind: str) -> str:
    """The model a gateway kind names, or '' for a direct kind. PURE."""
    base, model = split_gateway_kind(kind)
    return model if base in GATEWAY_KINDS else ""


def provider_family(kind: str) -> str:
    """The declared vendor family of a kind ('' when undeclared or unresolvable). PURE.

    A GATEWAY kind resolves through its MODEL: the vendor that actually answered is the vendor
    whose independence matters, not the proxy that billed for it. See GATEWAY_KINDS.
    """
    base, model = split_gateway_kind(kind)
    if base in GATEWAY_KINDS:
        vendor = str(model).split("/", 1)[0] if model else ""
        return GATEWAY_VENDOR_FAMILY.get(vendor, "")
    # SPLIT LIKE EVERY SIBLING. is_declared, resumes_session and resolve_seat all look up
    # split_gateway_kind()[0]; looking up the FULL string here meant a colon-bearing kind that
    # is NOT a gateway resolved to no family in this one function while the others found it --
    # so the same kind was both declared and family-less depending on who asked.
    row = PROVIDER_REGISTRY.get(base)
    return str(row["provider_family"]) if row else ""


@dataclass(frozen=True)
class AmbiguityState:
    """Reconciliation verdict carried INTO routing (PRD.md §7.3 failover semantics).

    ``possible_write`` means the previous attempt on this seat ended where a write MAY have
    landed (worker died dirty, AMBIGUOUS_EXECUTION). While it stands, no chain may advance:
    switching providers across an unmeasured write is exactly the blind retry the doctrine
    forbids. Only a MEASURED-unchanged workspace (or death before effects) permits a switch.
    """
    possible_write: bool = False
    reason: str = ""


class SeatDecision(NamedTuple):
    """Outcome of seat resolution/routing. ``refusal`` is '' on success, else a NAMED
    constant above; ``rationale`` is the ordered why-trace (every rejection names itself)."""
    kind: str
    refusal: str
    rationale: tuple


_ALLOWED_CONSTRAINTS = frozenset({
    "exclude_provider_families", "exclude_kinds", "write_capable",
    "credential_modes", "local_or_remote"})


def resolve_seat(role: str, policy_constraints, cfg_roles) -> SeatDecision:
    """Select the kind holding ``role`` under policy constraints. PURE.

    Candidates, deterministically ordered: the manifest pin for this seat first (explicit
    config outranks generic preference), then ``PROVIDER_ORDER``. Each candidate either
    satisfies every constraint or its rejection enters the trace BY NAME. An explicit pin
    to an UNDECLARED kind refuses immediately rather than falling through: silently
    promoting another provider into a named seat is the wrong-provider fallback that PRD.md
    §7 forbids. Unknown constraint keys raise: a mistyped constraint silently ignored is a
    weakened policy pretending to be enforced.

    ``policy_constraints`` (all optional): exclude_provider_families (pairwise independence),
    exclude_kinds (chain exhaustion), write_capable (authority-profile need),
    credential_modes (billing restriction), local_or_remote.
    """
    constraints = dict(policy_constraints or {})
    unknown = sorted(set(constraints) - _ALLOWED_CONSTRAINTS)
    if unknown:
        raise ValueError(
            "unknown seat-policy constraint(s) %s; known are %s. Refusing instead of "
            "ignoring: a constraint this function does not know is a policy that would "
            "not be enforced." % (unknown, sorted(_ALLOWED_CONSTRAINTS)))
    if role not in ASSIGNABLE_SEATS:
        return SeatDecision("", SEAT_UNRESOLVABLE, (
            "seat %r is not assignable: OWNER is always human, never configurable, never "
            "delegated, and %s is not a matrix seat (assignable: %s)"
            % (role, role, list(ASSIGNABLE_SEATS)),))
    pins = cfg_roles if isinstance(cfg_roles, Mapping) else {}
    excluded_families = {str(f) for f in (constraints.get("exclude_provider_families") or ())}
    exclude_kinds = {str(k) for k in (constraints.get("exclude_kinds") or ())}
    need_write = bool(constraints.get("write_capable"))
    allowed_modes = {str(m) for m in (constraints.get("credential_modes") or ())}
    want_loc = str(constraints.get("local_or_remote") or "")
    pinned = str(pins.get(role) or "")

    trace: list = []
    candidates = ([pinned] if pinned else []) + \
        [k for k in PROVIDER_ORDER if k != pinned]
    for cand in candidates:
        cand_base, cand_model = split_gateway_kind(cand)
        facts = PROVIDER_REGISTRY.get(cand_base)
        if facts is not None and cand_base in GATEWAY_KINDS and not cand_model:
            # FAIL CLOSED on a gateway with no model. It would otherwise resolve to a seat whose
            # vendor nobody knows, and every independence check downstream would be comparing an
            # empty string against an empty string -- passing every time, for the wrong reason.
            if cand == pinned:
                return SeatDecision("", SEAT_UNRESOLVABLE, tuple(trace) + (
                    "pinned kind %r names a gateway but no model; a gateway is not a vendor, "
                    "so %r cannot be certified independent of anything. Pin "
                    "'%s:<vendor>/<model>' instead." % (cand, cand, cand_base),))
            trace.append("candidate %s skipped: gateway named without a model" % cand)
            continue
        if facts is None:
            if cand == pinned:
                return SeatDecision("", SEAT_UNRESOLVABLE, tuple(trace) + (
                    "pinned kind %r for seat %r has no capability declaration; refusing "
                    "rather than silently seating a different provider" % (cand, role),))
            trace.append("candidate %s skipped: no capability declaration (not routable)"
                         % cand)
            continue
        # The family comes from provider_family(), NOT from the table row: for a gateway the
        # row deliberately holds "" and the model is what identifies the vendor.
        fam = provider_family(cand)
        # DELEGATED, so the router and the dispatch path cannot disagree about what a
        # constraint means. See constraint_refusals.
        why = constraint_refusals(cand, constraints)
        if why:
            trace.append("candidate %s (%s) rejected: %s" % (cand, fam, "; ".join(why)))
            continue
        trace.append("selected %s (family %s) for seat %s: first declared candidate "
                     "satisfying all constraints; facts are DECLARATIONS (section 3.2), "
                     "measured seat truth lives in run.provenance" % (cand, fam, role))
        return SeatDecision(cand, "", tuple(trace))
    return SeatDecision("", SEAT_UNRESOLVABLE, tuple(trace) + (
        "SEAT_UNRESOLVABLE: no declared candidate satisfies the policy for seat %r" % role,))


def chain_next(seat: str, chain, exhausted, ambiguity: AmbiguityState | None, *,
               pairing: Callable[[str], str] | None = None) -> SeatDecision:
    """Next live candidate of an ordered provider chain. PURE.

    Failover is RECONCILIATION-AWARE (PRD.md §7.3):
      * ``ambiguity.possible_write`` blocks ANY advance -- CHAIN_BLOCKED_AMBIGUOUS_WRITE.
        A provider that died after a possible write is never silently retried on the next
        model; escalation owns that decision.
      * members already marked exhausted (died BEFORE effects, or after a measured-unchanged
        workspace) are skipped;
      * a member the optional ``pairing(kind) -> refusal-or-''`` gate rejects is skipped too:
        exhausting a chain onto a provider that would breach require_distinct_provider_between
        refuses the seat (CHAIN_POLICY_REFUSED) rather than breaching the pair;
      * a chain must span >=2 distinct declared families (PAI-Bus rule); a single-family
        chain is refused by name wherever it is encountered.

    ``pairing`` is injected by the caller so this pure router needs no store access.
    """
    seq = [str(k) for k in (chain or ())]
    dead = {str(k) for k in (exhausted or ())}
    amb = ambiguity if isinstance(ambiguity, AmbiguityState) else AmbiguityState()
    trace: list = []
    if seat not in ASSIGNABLE_SEATS:
        return SeatDecision("", SEAT_UNRESOLVABLE, (
            "seat %r is not assignable; chains route matrix seats only (%s)"
            % (seat, list(ASSIGNABLE_SEATS)),))
    undeclared = [k for k in seq if not is_declared(k)]
    if undeclared:
        return SeatDecision("", SEAT_UNRESOLVABLE, tuple(trace) + (
            "chain member(s) %s have no capability declaration; refusing rather than "
            "routing to an unknown provider" % (undeclared,),))
    families = {provider_family(k) for k in seq}
    if "" in families:
        # FAIL CLOSED, exactly as resolve_seat does 40 lines above. An unresolvable family
        # counted as a DISTINCT vendor in the >=2-families rule below, so a chain of two
        # unknown-vendor gateway models satisfied the cross-vendor requirement by being equally
        # unidentifiable. "We cannot tell who this is" is not evidence of independence.
        unknown = sorted(k for k in seq if not provider_family(k))
        return SeatDecision("", CHAIN_SINGLE_FAMILY, tuple(trace) + (
            "chain member(s) %s resolve to no provider family, so their independence cannot be "
            "certified; refusing rather than counting an unknown vendor as a distinct one"
            % (unknown,),))
    if len(families) < 2:
        return SeatDecision("", CHAIN_SINGLE_FAMILY, tuple(trace) + (
            "chain %s spans families %s; a chain must contain >=2 distinct vendor "
            "families (PAI-Bus rule)" % (seq, sorted(families)),))
    if amb.possible_write:
        # "'try the next model' must not become a disguised blind retry": the write state
        # is UNMEASURED, so no member of any chain may take the seat until a human or a
        # measurement resolves what happened.
        return SeatDecision("", CHAIN_BLOCKED_AMBIGUOUS_WRITE, tuple(trace) + (
            "previous attempt on seat %r ended with a possible write%s; refusing to switch "
            "providers across an unmeasured effect" % (seat, ": " + amb.reason if amb.reason
                                                       else ""),))
    policy_blocked = False
    for cand in seq:
        if cand in dead:
            trace.append("candidate %s skipped: exhausted (availability)" % cand)
            continue
        if pairing is not None:
            why = pairing(cand)
            if why:
                policy_blocked = True
                trace.append("candidate %s (%s) skipped: pairing policy: %s"
                             % (cand, provider_family(cand), why))
                continue
        trace.append("selected %s (family %s): first non-exhausted, policy-clean candidate"
                     % (cand, provider_family(cand)))
        return SeatDecision(cand, "", tuple(trace))
    refusal = CHAIN_POLICY_REFUSED if policy_blocked else CHAIN_EXHAUSTED
    trace.append("%s: no chain member available for seat %r" % (refusal, seat))
    return SeatDecision("", refusal, tuple(trace))


def check_pairing(program_ctx, role_a: str, provider_a: str, role_b: str, provider_b: str,
                  risk_classes_hit=()) -> str:
    """Epistemic-independence admission (PRD.md §7.2). PURE. Returns '' when the
    pairing may proceed, else a NAMED refusal.

    Consulted AT ADMISSION -- schedule()/review dispatch -- with MEASURED provenance: the
    implementer's provider comes from its run.provenance event; the reviewer's candidate is
    checked BEFORE spawn. Two forms:
      * pairwise: a configured [role_a, role_b] pair (either order) may never share a
        declared family -> EPISTEMIC_INDEPENDENCE_UNMET;
      * risk-class: when the candidate touches a class listed in require_distinct_provider_for,
        the distinct-provider constraint escalates from preference to admission REQUIREMENT
        -> ROLE_PROVIDER_POLICY_REFUSED.

    ``program_ctx`` carries: require_distinct_between (pairs), require_distinct_for
    (classes), families ({role: provider-kind} measured so far) -- so the check also sees
    seats recorded EARLIER in the program, not just the two roles passed in.
    """
    ctx = program_ctx if isinstance(program_ctx, Mapping) else {}
    fam_a, fam_b = provider_family(provider_a), provider_family(provider_b)
    same_family = bool(fam_a) and bool(fam_b) and fam_a == fam_b
    between = [tuple(p) for p in (ctx.get("require_distinct_between") or ())]
    if same_family:
        for pair in between:
            if {role_a, role_b} == set(pair):
                return EPISTEMIC_INDEPENDENCE_UNMET
        recorded = ctx.get("families") or {}
        for pair in between:
            for x, y in ((pair[0], pair[1]), (pair[1], pair[0])):
                # y is the seat being admitted FOR (its partner x already ran earlier);
                # x != role_a keeps the direct form above authoritative for the pair we hold.
                if y == role_a and x != role_b:
                    other = provider_family(str(recorded.get(x) or ""))
                    if other and other == fam_a:
                        return EPISTEMIC_INDEPENDENCE_UNMET
    escalated = set(risk_classes_hit or ()) & set(ctx.get("require_distinct_for") or ())
    if escalated and same_family:
        return ROLE_PROVIDER_POLICY_REFUSED
    return ""


# ---- lane-checkpoint exhaustion hooks (pure; the caller persists) ------------------------------
def mark_chain_exhaustion(checkpoint, seat: str, kind: str) -> dict:
    """Record ``kind`` as exhausted for ``seat`` in a lane checkpoint copy. PURE.

    Called by the reconciliation hook AFTER a measured safe-to-switch outcome (death before
    effects / unchanged worktree). Idempotent and order-normalising so repeated crashes of
    the same provider cannot corrupt the record. The CALLER saves the returned dict -- this
    function performs no I/O, so orchestration wiring stays testable without stores.
    """
    ck = dict(checkpoint or {})
    per_seat = {str(k): {str(x) for x in (v or ())}
                for k, v in ((ck.get("chain_exhausted") or {}).items())}
    cur = per_seat.get(str(seat), set())
    if str(kind) in cur:
        return ck
    per_seat[str(seat)] = cur | {str(kind)}
    ck["chain_exhausted"] = {k: sorted(v) for k, v in sorted(per_seat.items())}
    return ck


def exhausted_for(checkpoint, seat: str) -> set:
    """The exhausted kinds recorded for ``seat``. PURE."""
    rows = ((checkpoint or {}).get("chain_exhausted") or {})
    return {str(x) for x in (rows.get(str(seat)) or ())}


def constraint_refusals(kind: str, constraints: Mapping | None) -> list:
    """Why this kind may NOT hold a seat under these constraints. PURE. [] means it may.

    THE ONE EVALUATOR. resolve_seat used to be the only place these rules existed, and
    resolve_seat has no production caller -- so every constraint except the write ceiling was
    advertised and never enforced. Both the router and the dispatch path now call this, because
    two implementations of an admission rule is one implementation and one decoration.

    Unknown constraint keys RAISE, exactly as resolve_seat's own guard does: a mistyped
    constraint silently ignored is a weakened policy pretending to be enforced.
    """
    c = dict(constraints or {})
    unknown = sorted(set(c) - _ALLOWED_CONSTRAINTS)
    if unknown:
        raise ValueError(
            "unknown seat-policy constraint(s) %s; known are %s. Refusing instead of ignoring: "
            "a constraint this function does not know is a policy that would not be enforced."
            % (unknown, sorted(_ALLOWED_CONSTRAINTS)))
    base, model = split_gateway_kind(kind)
    facts = PROVIDER_REGISTRY.get(base)
    if facts is None:
        return ["kind %r has no capability declaration" % kind]
    fam = provider_family(kind)
    why = []
    if base in GATEWAY_KINDS and not fam:
        why.append("model %r names a vendor this build cannot map to a provider family, so its "
                   "independence cannot be certified" % model)
    if kind in {str(k) for k in (c.get("exclude_kinds") or ())}:
        why.append("kind is exhausted/unavailable")
    if fam in {str(f) for f in (c.get("exclude_provider_families") or ())}:
        why.append("family %s excluded by pairing policy" % fam)
    if c.get("write_capable") and not facts["write_capable"]:
        # NAMES THE MEASURED FACT, not just the requirement. Folding the write ceiling into
        # the shared evaluator briefly reduced this to "seat requires write capability",
        # which states the policy and drops the declaration the refusal actually rests on.
        why.append("the seat requires write capability, and this kind is declared "
                   "non-write-capable; it is a transport, not a builder")
    allowed_modes = {str(m) for m in (c.get("credential_modes") or ())}
    if allowed_modes and not allowed_modes & set(facts["credential_mode"]):
        why.append("credential mode(s) %s outside policy %s"
                   % (sorted(facts["credential_mode"]), sorted(allowed_modes)))
    want_loc = str(c.get("local_or_remote") or "")
    if want_loc and str(facts["local_or_remote"]) != want_loc:
        why.append("requires %s execution" % want_loc)
    return why


def seat_constraints_for(profile_need_write: bool, builder_family: str = "",
                         extra_excluded_kinds: Sequence[str] = ()) -> dict:
    """Translate an authority profile need + measured program facts into resolver
    constraints. PURE. Kept tiny on purpose: today's routing constraints are exactly the
    ones PRD.md §7.5 names (READ_ONLY seat vs write-capable provider; pairwise family
    exclusion; exhaustion), and inventing more would be policy theatre."""
    out: dict = {"write_capable": bool(profile_need_write)}
    if builder_family:
        out["exclude_provider_families"] = [builder_family]
    if extra_excluded_kinds:
        out["exclude_kinds"] = [str(k) for k in extra_excluded_kinds]
    return out

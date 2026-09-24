"""briefing -- the packet a HUMAN carries from this control plane to an outside chat agent.

WHY THIS EXISTS
---------------
A strategist seat can be held by a model this deployment cannot reach: a browser tab logged into
someone's chat subscription, a colleague's assistant, a model behind a corporate proxy. Program
Mode has no connector to any of them and should not grow one -- every such connector is a new
inbound authority path, and PRD.md §6 spends its authority budget elsewhere ("no transport grants
authority", principle 5; "a browser tab ... never implies access to every local project",
principle 27). Relay Mode DOES reach a browser-hosted Orchestrator at HEAD, but through the
endpoint contract of PRD.md §8.1/§8.2 -- not by widening this path.

What DOES cross that gap is a person. So this module assembles the thing a person can carry: one
plain-text packet, complete enough that a chat agent reading it alone can act as strategist, and
inert enough that carrying it grants nothing. The human pastes it out; the human pastes the answer
back through the SAME governed answer path the operator already uses (dashboard queue, ``program
answer``, or the ``program_decide`` tool). No new surface is created here, because nothing on the
far side is trusted: the relay is a courier, and a courier is not an authority.

WHAT MAKES THIS SAFE TO PASTE INTO SOMEONE ELSE'S CHAT WINDOW
--------------------------------------------------------------
    * NO CREDENTIAL, STRUCTURALLY. The packet is built by ALLOWLIST from named bundle fields
      (transport_redact's argument): a denylist would ship whatever a future bundle key adds, and
      the keys a future version adds are exactly the ones nobody has decided are safe yet. The
      dashboard's bearer token is not merely omitted -- there is no field it could occupy, and
      the rendered text says so, because an agent that does not know a secret was withheld will
      ask the operator for one.
    * EVERY FREE-TEXT FIELD IS CLASSIFIED ON THE WAY OUT. Decision prose was already sanitised
      when it was PERSISTED (``StrategicStore.record_decision``), but objectives, constraints,
      lane titles and lane TASKS were not -- nothing forced them through the classifier, and a
      task naming an absolute home-directory path or an API key is exactly the sentence a human
      is about to paste into a third party's log. So ``core.classification`` runs over every
      string this packet renders. It is idempotent on already-clean prose, so this costs nothing
      where the store already did the work.
    * ABSENCES ARE STATED. A program with no recorded constraints renders a line SAYING no
      constraints were recorded, and the instructions tell the agent to report what it needed
      and stop rather than invent it. The bundle's own rule -- "if something is not here, it was
      never recorded, and that absence is itself the finding" -- has to survive the trip, or a
      confident chat agent will fill the hole with plausible fiction and the operator will relay
      it into the durable record as though someone had measured it.

PURE
----
Every function here is pure over ``StrategicStore.handoff_bundle`` output plus a ``surfaces``
mapping the TRANSPORT supplies. Core does not import transports (that layering is enforced), and
the relay instructions name real CLI verbs and real MCP tools -- so the caller passes that
vocabulary in from its own source of truth rather than this module retyping a command line that
can silently stop existing.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import classification

BRIEFING_INSTRUMENT = "briefing/1"

#: The keys a caller's ``surfaces`` mapping may carry. Stated as data so the transport and this
#: renderer cannot disagree about the name of a field, and so a control can assert the transport
#: fills every one of them.
SURFACE_FIELDS = ("dashboard_url", "cli_answer", "cli_verbs", "mcp_decide_tool", "mcp_tools")

#: What the far side is told about its own authority. Kept as a constant because it is the whole
#: safety argument of this feature in three sentences, and a reader who edits it should have to
#: edit it HERE, where the reasoning above it is visible.
BOUNDARY = (
    "This packet grants nothing. It carries no credential, no dashboard token and no host path; "
    "where one would have appeared you will see a visible withheld-marker instead. A directive "
    "relayed from this conversation is recorded under STRATEGIST authority only -- owner "
    "capabilities (capability grants, pushing, destructive operations) cannot be reached through "
    "this channel at all, by you or by the person relaying for you."
)

#: Said to the far side in the packet AND meant literally by the design: nothing the model writes
#: reaches the control plane except by a human deciding to carry it.
RELAY_RULE = (
    "You have no connection to the control plane. You cannot read its state, run its commands, or "
    "observe the result of anything you decide. A human operator pasted this text to you and will "
    "carry your answer back by hand."
)

#: WHO CARRIES THE ANSWER BACK. The packet's CONTENT is identical either way -- same durable
#: rows, same sanitising, same authority boundary. Only the sentences describing the return path
#: differ, which is exactly why this is a parameter and not a second renderer: a fork here would
#: drift, and the half that drifted would be the half nobody was reading.
CARRIER_HUMAN = "human"
CARRIER_SEAT = "seat"
CARRIERS = (CARRIER_HUMAN, CARRIER_SEAT)

#: Said to a MODEL dispatched into the seat. It has no more reach than the human relay does: its
#: entire output is one structured document, which the orchestrator validates (core.strategist)
#: and then disposes of according to the deployment's autonomy setting (core.autonomy). Saying
#: so plainly matters -- a seat that believes it is executing will write directives as though
#: they take effect the moment it emits them.
SEAT_RULE = (
    "You are being dispatched into this seat by the control plane itself. You have no tools, no "
    "repository access and no ability to execute anything: your entire output is the structured "
    "response described below, which the orchestrator validates before any part of it takes "
    "effect, and may hold for a human to approve."
)

#: The response shape the seat must emit. Stated in the packet because validation refuses
#: anything else -- a schema the model was never shown would make every refusal unfair and every
#: turn a wasted dispatch.
SEAT_SCHEMA_LINES = (
    "  Return ONE JSON object and nothing else:",
    '    {"directives": [{"message_id": "<the id printed above, copied verbatim>",',
    '                     "directive": "<one imperative instruction>",',
    '                     "rationale": "<why, one or two sentences>"}]}',
    "  Answer ONLY STRATEGIST-routed questions. Omit any question you cannot decide from this "
    "packet: an omitted question is escalated to a human, which is the correct outcome when the "
    "packet is genuinely insufficient. A directive naming an id that is not open above, or "
    "carrying any authority field, is refused outright.",
)


_ABSENT = "(none recorded -- treat that absence as a finding, not as freedom)"

#: How many per-question directive packets one briefing carries. Each of them repeats the shared
#: context (objective, constraints, live decisions), which makes this the ONE multiplicative term
#: in the document and the only part that can outrun a transport's response bound on a busy
#: program -- where the failure would be a 500 that loses the whole packet rather than a partial
#: one. Bounded and LABELLED, like every other listing on this platform: the program briefing
#: still names every open question, so nothing is concealed; only the pre-rendered convenience
#: packets stop, and ``directives_truncated`` says so.
DIRECTIVE_LIMIT = 20

#: Asks that belong to the OWNER seat. Mirrors ``orchestrator.inbox``'s routing rule rather than
#: inventing a second one: telling a strategist relay it may answer an authority request would be
#: a lie about its ceiling, and the ceiling is the only thing making this packet safe to hand out.
_OWNER_ROUTED = ("AUTHORITY_REQUEST", "OWNER_ESCALATION")


# ---------------------------------------------------------------------------------------------
# sanitising: the classifier that guards the STORE also guards the clipboard
# ---------------------------------------------------------------------------------------------
class _Scrubber:
    """Runs ``classification.classify`` over every rendered string and COUNTS what it removed.

    The count is the point. A packet that silently replaced a credential would be safe and
    dishonest at once: the operator must be able to see that this text was modified before it was
    handed over, and the far side must be able to tell a marker from prose.
    """

    def __init__(self):
        self.secrets = 0
        self.paths = 0

    def text(self, value) -> str:
        c = classification.classify("" if value is None else str(value))
        self.secrets += c.secrets_removed
        self.paths += c.paths_removed
        return c.text

    def seq(self, values: Sequence | None) -> list:
        return [self.text(v) for v in (values or ())]

    @property
    def modified(self) -> int:
        return self.secrets + self.paths

    def to_dict(self) -> dict:
        return {"secrets_removed": self.secrets, "paths_removed": self.paths,
                "modified": bool(self.modified)}


# ---------------------------------------------------------------------------------------------
# assembly: bundle -> packet document
# ---------------------------------------------------------------------------------------------
def briefing(bundle: Mapping, *, surfaces: Mapping | None = None,
             carrier: str = CARRIER_HUMAN) -> dict:
    """The whole relay packet for one program. PURE.

    ``carrier`` selects who carries the answer back -- a human with a clipboard
    (``CARRIER_HUMAN``, the default and the only behaviour that existed first) or a model
    dispatched into the seat (``CARRIER_SEAT``). An unknown carrier RAISES rather than
    defaulting: silently rendering human-relay instructions into a machine seat's prompt would
    produce a packet that reads correctly and cannot possibly be answered correctly.

    ``bundle`` is ``StrategicStore.handoff_bundle`` output -- already assembled from durable rows,
    so this function reads NO store and can be exercised against a literal. ``surfaces`` is the
    caller's own vocabulary (see ``SURFACE_FIELDS``); absent, the relay section says the surface
    was not supplied rather than printing a command line nobody verified.
    """
    if carrier not in CARRIERS:
        raise ValueError("unknown briefing carrier %r; known are %s"
                         % (carrier, list(CARRIERS)))
    sc = _Scrubber()
    surf = dict(surfaces or {})
    prog = dict(bundle.get("program") or {})
    program_id = str(prog.get("program_id") or "")
    blocking = dict(bundle.get("blocking") or {})

    lanes = []
    acceptance = []
    for lane in bundle.get("lanes") or []:
        lid = str(lane.get("lane_id") or "")
        criteria = sc.seq(lane.get("acceptance"))
        title = sc.text(lane.get("title"))
        lanes.append({
            "lane_id": lid, "title": title,
            "kind": str(lane.get("kind") or ""), "state": str(lane.get("state") or ""),
            "verdict": str(lane.get("verdict") or ""), "attempt": int(lane.get("attempt") or 0),
            "task": sc.text(lane.get("task")),
            "acceptance": criteria,
            "blocked_by": [str(b) for b in (blocking.get(lid) or [])],
        })
        if criteria:
            acceptance.append({"lane_id": lid, "title": title, "criteria": criteria})

    # Titles come back from the rows just built, NEVER re-scrubbed: classify() is idempotent on
    # its own output, but running it twice over the same span would count that span twice and
    # the counters are shown to the operator as "what was removed before hand-off".
    titles = {row["lane_id"]: row["title"] for row in lanes}
    questions = []
    for q in bundle.get("open_questions") or []:
        lid = str(q.get("lane_id") or "")
        kind = str(q.get("message_type") or "")
        questions.append({
            "message_id": str(q.get("message_id") or ""), "lane_id": lid,
            "lane_title": titles.get(lid, ""),
            "kind": kind,
            "route": "OWNER" if kind in _OWNER_ROUTED else "STRATEGIST",
            "question": sc.text(q.get("payload")),
        })

    decisions = [{"question": sc.text(d.get("question")), "decision": sc.text(d.get("decision")),
                  "authority": str(d.get("authority") or ""),
                  "rationale": sc.text(d.get("rationale"))}
                 for d in (bundle.get("decisions") or [])]

    doc = {
        "instrument": BRIEFING_INSTRUMENT,
        "program_id": program_id,
        "title": sc.text(prog.get("title")),
        "objective": sc.text(bundle.get("objective")),
        "status": str(bundle.get("status") or ""),
        "constraints": sc.seq(bundle.get("constraints")),
        "acceptance": acceptance,
        "lanes": lanes,
        "decisions": decisions,
        "open_questions": questions,
        "next_authority": str(bundle.get("next_authority") or ""),
        "surfaces": {k: surf.get(k) for k in SURFACE_FIELDS},
        "boundary": BOUNDARY,
        "carrier": str(carrier),
        "inspected": dict(bundle.get("inspected") or {}),
        "vacuous": bool(bundle.get("vacuous")) or not program_id,
    }
    doc["classification"] = sc.to_dict()
    doc["prompt"] = render(doc)
    shown = questions[:DIRECTIVE_LIMIT]
    doc["directives"] = [dict(q, prompt=render_directive(doc, q)) for q in shown]
    doc["directives_limit"] = DIRECTIVE_LIMIT
    doc["directives_truncated"] = len(questions) > len(shown)
    return doc


# ---------------------------------------------------------------------------------------------
# rendering: the plain text a person actually pastes
# ---------------------------------------------------------------------------------------------
def _relay_lines(doc: Mapping) -> list:
    """How the operator carries an answer back. Named surfaces only -- never invented ones."""
    if doc.get("carrier") == CARRIER_SEAT:
        # A dispatched seat has no operator and no clipboard: the "surface" is the structured
        # document it returns, so naming a dashboard URL here would describe a path it cannot
        # take and invite it to ask for credentials to take it.
        return list(SEAT_SCHEMA_LINES)
    s = doc.get("surfaces") or {}
    out = []
    if s.get("dashboard_url"):
        out.append("  dashboard : %s -> Intervention queue -> paste the directive -> answer"
                   % s["dashboard_url"])
    if s.get("cli_answer"):
        out.append("  cli       : %s" % s["cli_answer"])
    if s.get("mcp_decide_tool"):
        out.append("  mcp tool  : %s" % s["mcp_decide_tool"])
    if not out:
        out.append("  (no relay surface was supplied with this packet -- ask the operator which "
                   "of the dashboard, the CLI or the MCP tool they will use)")
    out.append("  the dashboard is loopback-only and its bearer token is deliberately absent "
               "from this packet; do not ask for it.")
    return out


def render(doc: Mapping) -> str:
    """The packet as plain text. PURE.

    Plain text on purpose: it survives a paste into any chat box, an email, or a terminal, and it
    cannot execute. A markdown or JSON shape would tempt the far side to treat it as a protocol
    rather than as a briefing it must reason about.
    """
    title = doc.get("title") or "(untitled)"
    # The product name comes from ``branding``, never a literal: this header is EMITTED
    # text, so a rename that missed it would leave every future packet self-describing under a
    # name the product no longer has.
    lines = ["%s PROGRAM BRIEFING -- %s (%s)"
             % (branding.PRODUCT_TITLE.upper(), title, doc.get("program_id") or "?"),
             "assembled by %s from durable program rows. No transcript was read to build it."
             % BRIEFING_INSTRUMENT, ""]
    if doc.get("vacuous"):
        lines += ["THIS PROGRAM HAS NO RECORDED STATE.",
                  "There is nothing here to brief you on. Tell the operator the packet came back "
                  "vacuous -- either the program id is wrong or nothing has been recorded against "
                  "it yet. Do not proceed on assumptions.", ""]
        return "\n".join(lines)

    rule = SEAT_RULE if doc.get("carrier") == CARRIER_SEAT else RELAY_RULE
    lines += ["YOUR ROLE", "You are acting as the STRATEGIST for this program. " + rule, "",
              "WHAT THIS PACKET IS NOT", doc.get("boundary") or BOUNDARY, "",
              "OBJECTIVE", "  " + (doc.get("objective") or "(no objective recorded)"), ""]

    lines.append("IMMUTABLE CONSTRAINTS")
    constraints = doc.get("constraints") or []
    lines += ["  - " + c for c in constraints] if constraints else ["  " + _ABSENT]
    lines.append("")

    lines.append("ACCEPTANCE CRITERIA")
    acceptance = doc.get("acceptance") or []
    if acceptance:
        for entry in acceptance:
            lines.append("  [%s] %s" % (entry["lane_id"], entry["title"]))
            lines += ["      - " + c for c in entry["criteria"]]
    else:
        lines.append("  " + _ABSENT)
    lines.append("")

    lanes = doc.get("lanes") or []
    lines.append("LANES (%d)" % len(lanes))
    if not lanes:
        lines.append("  (no lanes planned yet)")
    for lane in lanes:
        lines.append("  %s  %s" % (lane["lane_id"], lane["title"]))
        lines.append("      kind=%s state=%s verdict=%s attempt=%d"
                     % (lane["kind"], lane["state"], lane["verdict"], lane["attempt"]))
        if lane["task"]:
            lines.append("      task: " + lane["task"])
        if lane["blocked_by"]:
            lines.append("      blocked by: " + ", ".join(lane["blocked_by"]))
    lines.append("")

    decisions = doc.get("decisions") or []
    lines.append("DECISIONS ALREADY MADE (live: %d)" % len(decisions))
    if not decisions:
        lines.append("  (none yet)")
    for d in decisions:
        lines.append("  Q: " + d["question"])
        lines.append("  A: %s   [%s]" % (d["decision"], d["authority"]))
        if d["rationale"]:
            lines.append("     because " + d["rationale"])
    lines.append("")

    questions = doc.get("open_questions") or []
    lines.append("OPEN QUESTIONS AWAITING AN ANSWER (%d)" % len(questions))
    if not questions:
        lines.append("  (none -- nothing is waiting on you right now)")
    for i, q in enumerate(questions, 1):
        lines.append("  [%d] message_id=%s  route=%s  kind=%s  lane=%s"
                     % (i, q["message_id"], q["route"], q["kind"], q["lane_title"] or q["lane_id"]))
        lines.append("      " + q["question"])
        if q["route"] == "OWNER":
            lines.append("      NOTE: this one is routed to the OWNER, not to you. Say so and "
                         "leave it; a strategist relay cannot answer it.")
    lines.append("")

    if doc.get("carrier") == CARRIER_SEAT:
        lines += ["WHAT TO PRODUCE",
                  "Answer only what was asked. If this packet does not contain something you "
                  "would need to decide well, omit that question rather than guessing: an "
                  "absence here means it was never recorded, and inventing it would put a fact "
                  "nobody measured into a permanent engineering record.", "",
                  "HOW YOUR ANSWER REACHES THE PROGRAM"]
    else:
        lines += ["WHAT TO PRODUCE",
                  "For each STRATEGIST-routed question above, write exactly:",
                  "  message_id: <the id printed above, copied verbatim>",
                  "  directive:  one instruction, imperative, decidable without another round trip",
                  "  rationale:  why -- a sentence or two, recorded beside the directive permanently",
                  "Answer only what was asked. If this packet does not contain something you would "
                  "need to decide well, say what is missing and stop. An absence here means it was "
                  "never recorded; inventing it would put a fact nobody measured into a permanent "
                  "engineering record.", "",
                  "HOW YOUR ANSWER REACHES THE PROGRAM (the operator does this, not you)"]
    lines += _relay_lines(doc)
    lines.append("")

    ins = doc.get("inspected") or {}
    lines += ["STATE OF THIS PACKET",
              "  program status: %s" % (doc.get("status") or "(unrecorded)"),
              "  next authority: %s" % (doc.get("next_authority") or "(none)"),
              "  inspected: " + ", ".join("%s=%s" % (k, ins[k]) for k in sorted(ins))]
    cls = doc.get("classification") or {}
    if cls.get("modified"):
        lines.append("  sanitised before hand-off: %d credential-shaped and %d host-path-shaped "
                     "span(s) were replaced by visible markers."
                     % (cls.get("secrets_removed", 0), cls.get("paths_removed", 0)))
    return "\n".join(lines)


def render_directive(doc: Mapping, question: Mapping) -> str:
    """A packet for ONE open question. PURE.

    Narrower than the program briefing on purpose: when the operator only needs one decision, a
    full brief invites the far side to re-litigate settled ones. This carries the objective, the
    constraints, the live decisions it must not contradict, and the single question.
    """
    lines = ["%s DIRECTIVE REQUEST -- %s (%s)"
             % (branding.PRODUCT_TITLE.upper(), doc.get("title") or "(untitled)",
                doc.get("program_id") or "?"),
             "assembled by %s from durable program rows." % BRIEFING_INSTRUMENT, "",
             "YOUR ROLE", "You are answering ONE question as the STRATEGIST for this program. "
             + RELAY_RULE, "",
             "WHAT THIS PACKET IS NOT", doc.get("boundary") or BOUNDARY, "",
             "OBJECTIVE", "  " + (doc.get("objective") or "(no objective recorded)"), ""]

    constraints = doc.get("constraints") or []
    lines.append("IMMUTABLE CONSTRAINTS")
    lines += ["  - " + c for c in constraints] if constraints else ["  " + _ABSENT]
    lines.append("")

    decisions = doc.get("decisions") or []
    if decisions:
        lines.append("DECISIONS YOU MUST NOT CONTRADICT (live: %d)" % len(decisions))
        for d in decisions:
            lines.append("  %s -> %s   [%s]" % (d["question"], d["decision"], d["authority"]))
        lines.append("")

    lane = next((l for l in (doc.get("lanes") or [])
                 if l["lane_id"] == question.get("lane_id")), None)
    if lane:
        lines += ["THE LANE THAT ASKED",
                  "  %s  %s (kind=%s state=%s)"
                  % (lane["lane_id"], lane["title"], lane["kind"], lane["state"])]
        if lane["task"]:
            lines.append("  task: " + lane["task"])
        for c in lane["acceptance"]:
            lines.append("  acceptance: " + c)
        lines.append("")

    lines += ["THE QUESTION  (message_id=%s, kind=%s, route=%s)"
              % (question.get("message_id"), question.get("kind"), question.get("route")),
              "  " + str(question.get("question") or ""), ""]
    if question.get("route") == "OWNER":
        lines += ["THIS ONE IS NOT YOURS",
                  "It is routed to the OWNER. A strategist relay cannot answer it: say so and "
                  "stop.", ""]
        return "\n".join(lines)

    heading = ("HOW YOUR ANSWER REACHES THE PROGRAM"
               if doc.get("carrier") == CARRIER_SEAT
               else "HOW YOUR ANSWER REACHES THE PROGRAM (the operator does this, not you)")
    lines += ["WHAT TO PRODUCE",
              "  directive:  one instruction, imperative, decidable without another round trip",
              "  rationale:  why -- a sentence or two, recorded permanently beside it",
              "If this packet does not contain what you would need, say what is missing and "
              "stop rather than assuming it.", "", heading]
    lines += _relay_lines(doc)
    return "\n".join(lines)

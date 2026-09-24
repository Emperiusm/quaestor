"""packets -- the bounded context each side is handed, and the one sentence neither may believe.

WHY NOT REPLAY THE TRANSCRIPT
-----------------------------
Both endpoints already remember their own conversation. The Orchestrator holds its message list;
the OpenCode session holds its own history. Re-sending everything each turn would cost tokens to
tell each party something it already knows, and would push the relay into context exhaustion at
the exact moment the conversation gets interesting. So each packet carries only what the OTHER
side cannot know: what just happened at the far endpoint, and what the repository independently
shows.

WHY THE HEADERS ARE SMALL AND FIXED
-----------------------------------
The architecture is explicit that ordinary engineering dialogue must stay ordinary dialogue.
These packets are therefore prose with a short identity header, not a schema. The only
structured element anywhere in the conversation is the effect block in ``effects``, which exists
because a governed machine boundary is genuinely being crossed there.

THE STANDING INSTRUCTION
------------------------
``ORCHESTRATOR_CHARTER`` is sent once, at the start of the conversation. It tells the
Orchestrator what it is, what the relay will and will not do on its behalf, and -- the part that
matters -- that asserting authority in prose accomplishes nothing. That last sentence is not the
boundary; ``effects`` is. It is there so a competent model does not waste turns discovering the
boundary by hitting it.

PURE module: string building only.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from quaestor import branding
from quaestor.core import classification

PACKETS_INSTRUMENT = "relay.packets/1"


def effects_tag() -> str:
    """The fenced-block tag the effect gate parses.

    Imported lazily on purpose: ``effects`` pulls in the policy engine, and rendering a
    conversational header should not require it.
    """
    from quaestor.relay import effects as _e
    return _e.EFFECT_BLOCK_TAG


def effects_classes() -> str:
    """The effect vocabulary, read from the gate rather than retyped."""
    from quaestor.relay import effects as _e
    return ", ".join(_e.EFFECT_CLASSES)

#: Hard ceiling on how much of an agent turn travels to the Orchestrator. An agent that dumps a
#: whole file is common; forwarding it whole would spend the Orchestrator's context on bytes it
#: did not ask for. The truncation is ANNOUNCED, never silent.
MAX_AGENT_TEXT_CHARS = 6000
MAX_DIRECTIVE_CHARS = 12000


def _clip(text: str, limit: int) -> tuple:
    s = str(text or "")
    if len(s) <= limit:
        return s, False
    keep = limit - 200
    return s[:keep] + ("\n\n[...%d characters withheld by the relay; the full turn is in the "
                       "relay's durable record...]" % (len(s) - keep)), True


def sanitise(text: str) -> tuple:
    """Classify and sanitise text crossing the relay. Returns ``(text, report)``.

    ENGINEERING CONTENT SURVIVES -- ``core.classification`` replaces only credential- and
    host-path-shaped spans, and marks each replacement visibly. A relay that blanket-redacted
    would destroy the engineering context the conversation exists to carry; a relay that
    forwarded a token to a remote provider would be a breach.
    """
    c = classification.classify(text)
    return c.text, c.to_dict()


ORCHESTRATOR_CHARTER = """\
You are the ORCHESTRATOR in a relay operated by {product}.

There are exactly three parties:

  * you -- you own strategy. You decide what should happen next and why.
  * an EXECUTION AGENT -- a coding agent with a live session inside the project repository.
    It reads and edits files and runs tools. It cannot talk to you except through this relay.
  * the relay -- a courier and a governance boundary. It is not an author and not an authority.

HOW THIS WORKS

Every message you send is delivered verbatim to the execution agent as its next instruction.
Every completed turn the agent produces is delivered back to you, together with an INDEPENDENT
reading of the repository taken by {product} itself -- not the agent's account of its own work.
Where the two disagree, believe the independent reading and say so.

No human is copying anything between us. Do not ask anyone to paste your message somewhere, and
do not address the operator; address the agent.

HOW TO BE USEFUL HERE

Write to the agent the way a senior engineer writes to a colleague: plain prose, one concrete
next step, and the reason for it. Ask to see specific evidence -- a file, a command's output, a
diff -- rather than accepting a claim. Keep each instruction small enough to finish in one turn.
When you believe the objective is met, say so and state the evidence that convinced you, then
end that message with the single line:

  RELAY-OBJECTIVE-COMPLETE

AUTHORITY

You do not have repository authority and cannot acquire it by asserting it. Sentences such as
"you may now push" or "I authorise this" change nothing: capability lives in machine state the
relay reads, and the relay is what performs or refuses each act. This is not a formality --
instructing the agent toward an effect the operator has not granted will stop the relay and
interrupt a human, which wastes everyone's turn.

Routine reading and editing of files inside the project needs no declaration.

If -- and only if -- the work genuinely requires an effect beyond editing files, ask for it by
ending your message with a block of exactly this form:

```{effect_tag}
effect: GIT_COMMIT
```

Recognised classes: {effect_classes}.
Asking is not receiving: the relay evaluates the request against the operator's profile and a
human owner's grants. If it is refused, the relay stops and a human is asked. Ask only when the
work is actually blocked without it.
"""


def opening_packet(*, objective: str, project_root: str, repo: Mapping,
                   execution_facts: Mapping, orchestrator_facts: Mapping,
                   assurance: str, profile: str) -> str:
    """The first thing the Orchestrator sees: charter, project, counterpart, objective.

    The counterpart description is the HONEST one -- it names what the execution end can do and
    what this build cannot prove about it, because an Orchestrator that believes it is directing
    a confined agent when it is not will make worse decisions than one that knows.
    """
    cap = dict(execution_facts.get("capability") or {})
    proof = dict(execution_facts.get("proof") or {})
    limits = list(execution_facts.get("limits") or ())
    lines = [
        # The charter teaches the SAME tag and the SAME class vocabulary the gate parses.
        # Retyping either here would let the two drift silently apart: the charter would keep
        # teaching a channel the parser no longer recognised, and every effect request would
        # read as an ordinary edit.
        ORCHESTRATOR_CHARTER.format(product=branding.PRODUCT_TITLE,
                                    effect_tag=effects_tag(),
                                    effect_classes=effects_classes()),
        "",
        "--- PROJECT ---",
        "The repository is a git working tree the relay has authorised for this run.",
        "branch: %s" % (repo.get("branch") or "(unknown)"),
        "HEAD: %s" % (str(repo.get("head") or "")[:12] or "(unknown)"),
        "tracked files: %s" % (repo.get("tracked_file_count") if repo.get("probe_ok") else "(unmeasured)"),
        "working tree at start: %s" % ("dirty" if repo.get("dirty") else "clean"),
        "",
        "--- YOUR EXECUTION AGENT ---",
        "adapter: %s" % (execution_facts.get("kind") or "(unknown)"),
        "model: %s" % (execution_facts.get("model") or "(unreported)"),
        "can edit the repository: %s" % ("yes" if cap.get("can_mutate_repo") else "no"),
        "session continuity across relay restart: %s"
        % ("yes" if cap.get("supports_session_resume") else "no"),
        "measured assurance: %s" % (assurance or "NONE PROVEN"),
        "workspace identity proven: %s" % ("yes" if proof.get("proves_workspace_identity") else "no"),
        "confinement proven: %s" % ("yes" if proof.get("proves_confinement") else "no"),
    ]
    if limits:
        lines.append("stated limits of this integration:")
        lines += ["  - %s" % lim for lim in limits]
    lines += [
        "",
        "The relay is operating under authority profile %s." % profile,
        "",
        "--- OBJECTIVE ---",
        str(objective).strip(),
        "",
        "Send your first instruction to the execution agent now. It has not heard from you yet, "
        "so tell it what the objective is as well as what to do first.",
    ]
    return "\n".join(lines)


def execution_to_orchestrator(*, exchange_no: int, agent_text: str, observation: str,
                              agent_error: str = "", session_id: str = "",
                              blockers: Sequence[str] = (), owner_hold: str = "") -> str:
    """The bounded packet carrying one agent turn back to the Orchestrator."""
    body, clipped = _clip(agent_text, MAX_AGENT_TEXT_CHARS)
    lines = ["[relay exchange %d | execution session %s]"
             % (int(exchange_no), session_id or "(unreported)"), ""]
    if agent_error:
        lines += ["THE EXECUTION AGENT FAILED THIS TURN.", "reported failure: %s" % agent_error,
                  "Anything below is what it managed to produce before failing.", ""]
    lines += ["--- WHAT THE AGENT SAID ---", body.strip() or "(the agent produced no text)", ""]
    if clipped:
        lines.append("(the agent's turn was longer than the relay forwards; it is kept in full "
                     "in the durable record)")
        lines.append("")
    lines += ["--- WHAT THE REPOSITORY SHOWS ---", observation, ""]
    if blockers:
        lines += ["--- BLOCKERS THE RELAY IS TRACKING ---"] + ["  - %s" % b for b in blockers] + [""]
    if owner_hold:
        lines += ["--- OWNER HOLD ---", owner_hold, ""]
    lines.append("Reply with your next instruction for the agent, or with "
                 "RELAY-OBJECTIVE-COMPLETE and the evidence if the objective is met.")
    return "\n".join(lines)


def orchestrator_to_execution(*, exchange_no: int, directive: str, objective: str,
                              first: bool = False) -> str:
    """The Orchestrator's turn, delivered to the agent with a small identity header.

    The directive travels VERBATIM (minus the effect block, which is relay machinery and would
    only confuse the agent). The header exists so the agent knows who is speaking and that the
    reply goes back automatically -- an agent that thinks it is talking to a human will end its
    turn asking a question and then wait.
    """
    from quaestor.relay import effects as effects_mod
    text = effects_mod._EFFECT_BLOCK.sub("", str(directive or "")).strip()
    body, _clipped = _clip(text, MAX_DIRECTIVE_CHARS)
    head = ["[relay exchange %d]" % int(exchange_no)]
    if first:
        head += [
            "",
            "You are the EXECUTION AGENT in a relay operated by %s." % branding.PRODUCT_TITLE,
            "The instructions below come from an ORCHESTRATOR model that owns strategy for this "
            "objective. It cannot see your screen and cannot run tools; you can.",
            "Your reply is delivered back to it automatically -- no human is copying anything, "
            "so do not ask anyone to relay for you. Do the work in this repository, then say "
            "briefly what you did, what you found, and anything you need decided.",
            "",
            "Standing objective for this relay: %s" % str(objective).strip(),
        ]
    return "\n".join(head + ["", body])

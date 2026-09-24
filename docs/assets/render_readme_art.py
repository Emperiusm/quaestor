"""Render the README's illustrated panels as light and dark SVG pairs.

GitHub strips CSS from Markdown, so the look of the README -- role colours, cards, pills, stat
tiles, the numbered exchange -- has to travel inside images. Every panel is drawn once per theme
and the README picks one with <picture>, which follows the reader's GitHub theme rather than their
operating system's. Text is laid out here, not by the browser, so wrapping uses a conservative
width estimate that leaves room for whichever system font the viewer ends up with.

Run from the repository root:  python docs/assets/render_readme_art.py
"""
from __future__ import annotations

import io
import os
from xml.sax.saxutils import escape

OUT = os.path.dirname(os.path.abspath(__file__))

THEMES = {
    "light": dict(ground="#F3F5F7", surface="#FFFFFF", sunk="#E8ECF0", ink="#14202B",
                  muted="#56626F", line="#CDD4DC",
                  orch="#0F7B5F", orch_soft="#DDF0E9", kern="#2C4FC4", kern_soft="#E1E7FA",
                  exec="#A8620B", exec_soft="#F7EAD6", bad="#B42C2C", bad_soft="#F8E1E1"),
    "dark": dict(ground="#11161C", surface="#182029", sunk="#1F2934", ink="#E4E9EF",
                 muted="#9AA6B3", line="#2E3A47",
                 orch="#4CC7A0", orch_soft="#15352C", kern="#8AA4FF", kern_soft="#1D2848",
                 exec="#E9A64E", exec_soft="#3A2A14", bad="#F07F7F", bad_soft="#3D1E1E"),
}

SANS = ('-apple-system,BlinkMacSystemFont,&quot;Segoe UI&quot;,&quot;Noto Sans&quot;,'
        'Helvetica,Arial,sans-serif')
MONO = 'ui-monospace,SFMono-Regular,&quot;SF Mono&quot;,Menlo,Consolas,&quot;Liberation Mono&quot;,monospace'
W = 1000
PAD = 24
#: Wrap at this share of the measured space: the estimate is for Arial-like metrics, and a viewer
#: whose fallback is a wider face must still see every word inside its card.
SLACK = 0.92


# ---------------------------------------------------------------------------------------------
# measurement and primitives
# ---------------------------------------------------------------------------------------------
def text_width(s, size, mono=False, bold=False):
    if mono:
        return len(s) * 0.602 * size
    em = 0.0
    for ch in s:
        if ch in "il.,:;'|!`":
            em += 0.26
        elif ch in "fjrt()[]-\"/":
            em += 0.36
        elif ch == " ":
            em += 0.28
        elif ch in "mwMW":
            em += 0.84
        elif ch.isupper() or ch in "@%&#":
            em += 0.67
        elif ch.isdigit():
            em += 0.56
        else:
            em += 0.54
    return em * size * (1.07 if bold else 1.0)


def wrap(s, size, width, mono=False, bold=False):
    limit = width * SLACK
    lines, cur = [], ""
    for word in s.split(" "):
        trial = word if not cur else cur + " " + word
        if text_width(trial, size, mono, bold) <= limit or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def text(x, y, s, size, fill, *, mono=False, bold=False, anchor="start", spacing=0.0,
         weight=None):
    fam = MONO if mono else SANS
    wt = weight or (700 if bold else 400)
    ls = ' letter-spacing="%.2f"' % spacing if spacing else ""
    return ('<text x="%.1f" y="%.1f" font-family="%s" font-size="%.1f" font-weight="%d" '
            'fill="%s" text-anchor="%s"%s>%s</text>'
            % (x, y, fam, size, wt, fill, anchor, ls, escape(s)))


def para(x, y, s, size, width, fill, *, lh=1.45, mono=False, bold=False):
    """A wrapped block whose first baseline sits at y. Returns (svg, height consumed)."""
    lines = wrap(s, size, width, mono, bold)
    out = [text(x, y + i * size * lh, ln, size, fill, mono=mono, bold=bold)
           for i, ln in enumerate(lines)]
    return "".join(out), len(lines) * size * lh


def rect(x, y, w, h, fill, stroke="none", rx=10, sw=1.5, dash=None):
    d = ' stroke-dasharray="%s"' % dash if dash else ""
    return ('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f" fill="%s" '
            'stroke="%s" stroke-width="%.1f"%s/>' % (x, y, w, h, rx, fill, stroke, sw, d))


PILL_KIND = {"ok": ("orch_soft", "orch"), "ro": ("kern_soft", "kern"),
             "warn": ("exec_soft", "exec"), "no": ("bad_soft", "bad")}


def pill(x, y, label, kind, t, size=12.5):
    """A status pill whose top-left is (x, y). Returns (svg, width)."""
    soft, strong = PILL_KIND[kind]
    w = text_width(label, size, mono=True) + 22
    h = size + 13
    svg = rect(x, y, w, h, t[soft], rx=h / 2, sw=0) + text(
        x + 11, y + h / 2 + size * 0.36, label, size, t[strong], mono=True, weight=500)
    return svg, w


def doc(width, height, body, t, title, desc):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" '
            'role="img" aria-labelledby="t d"><title id="t">%s</title><desc id="d">%s</desc>'
            '%s%s</svg>\n'
            % (width, height, width, height, escape(title), escape(desc),
               rect(0.75, 0.75, width - 1.5, height - 1.5, t["ground"], t["line"], rx=14, sw=1.5),
               body))


# ---------------------------------------------------------------------------------------------
# panels
# ---------------------------------------------------------------------------------------------
def hero(t):
    x, y, inner = PAD + 12, 58, W - 2 * (PAD + 12)
    parts = [text(x, y, "QUAESTOR  ·  RELAY MODE  ·  LOCAL-FIRST CONTROL PLANE", 13,
                  t["muted"], mono=True, weight=500, spacing=1.2)]
    y += 52
    for ln in wrap("ChatGPT thinks. Your coding agent types.", 36, inner, bold=True):
        parts.append(text(x, y, ln, 36, t["ink"], bold=True))
        y += 44
    parts.append(text(x, y, "Quaestor keeps the ledger.", 36, t["kern"], bold=True))
    y += 40
    body, h = para(x, y, "Quaestor runs a conversation between an Orchestrator (a ChatGPT "
                   "conversation in your own browser, or any OpenAI-compatible model) and an "
                   "Execution Agent (an OpenCode session) until the work is done. In between, "
                   "it reads the repository with its own git, refuses effects nobody authorized, "
                   "and never takes “I’m done” on faith.", 18, inner, t["muted"])
    parts.append(body)
    y += h + 14
    cx = x
    for key, label in (("orch", "Orchestrator · ChatGPT Web"),
                       ("kern", "Relay kernel · src/quaestor/relay/"),
                       ("exec", "Execution Agent · OpenCode")):
        w = text_width(label, 14.5) + 46
        if cx + w > x + inner:
            cx, y = x, y + 46
        parts.append(rect(cx, y, w, 34, t[key + "_soft"], t[key], rx=17, sw=1.2))
        parts.append('<circle cx="%.1f" cy="%.1f" r="5" fill="%s"/>' % (cx + 19, y + 17, t[key]))
        parts.append(text(cx + 32, y + 22, label, 14.5, t["ink"], weight=500))
        cx += w + 12
    height = y + 34 + 34
    return doc(W, int(height), "".join(parts), t, "Quaestor",
               "ChatGPT thinks. Your coding agent types. Quaestor keeps the ledger.")


def modes(t):
    gap = 24
    cw = (W - 2 * PAD - gap) / 2
    cards = [
        ("quaestor relay", "Relay Mode — conversation-first",
         "An Orchestrator endpoint and an Execution Agent endpoint talk turn after turn, joined "
         "by a kernel with no provider code. Ordinary engineering prose, no directive schema.",
         "ChatGPT directs the agent through a whole slice."),
        ("quaestor program", "Program Mode — state machine",
         "Programs, workflows, lanes, runs, seats, worktrees, leases and independent reviewers. "
         "A role says what an actor is for; it never grants authority.",
         "ChatGPT holds a read-only strategist seat, one packet at a time."),
    ]
    hs = []
    for _, _, body, role in cards:
        _, bh = para(0, 0, body, 15.5, cw - 40, t["muted"])
        _, rh = para(0, 0, role, 15, cw - 40, t["ink"])
        hs.append(130 + bh + rh)
    ch = max(hs)
    parts, top = [], PAD
    for i, (cmd, title, body, role) in enumerate(cards):
        cx = PAD + i * (cw + gap)
        parts.append(rect(cx, top, cw, ch, t["surface"], t["line"]))
        yy = top + 32
        parts.append(text(cx + 20, yy, cmd, 14, t["kern"], mono=True, weight=500))
        yy += 32
        parts.append(text(cx + 20, yy, title, 21, t["ink"], bold=True))
        yy += 30
        b, bh = para(cx + 20, yy, body, 15.5, cw - 40, t["muted"])
        parts.append(b)
        yy += bh + 6
        parts.append(text(cx + 20, yy, "CHATGPT’S ROLE", 11.5, t["muted"], mono=True,
                          weight=500, spacing=0.8))
        yy += 22
        r, _ = para(cx + 20, yy, role, 15, cw - 40, t["ink"])
        parts.append(r)
        mid = cx + cw / 2
        parts.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" '
                     'stroke-width="1.5" stroke-dasharray="4 4"/>'
                     % (mid, top + ch, mid, top + ch + 26, t["kern"]))
    by = top + ch + 26
    core = ("authority · owner channel · classification and redaction · "
            "independent repository observation · evidence · durable decisions")
    cb, cbh = para(PAD + 20, by + 56, core, 15.5, W - 2 * PAD - 40, t["ink"])
    bh = 56 + cbh + 6
    parts.append(rect(PAD, by, W - 2 * PAD, bh, t["kern_soft"], t["kern"]))
    parts.append(text(PAD + 20, by + 30, "SHARED CORE  ·  core/ imports nothing above it",
                      12, t["kern"], mono=True, weight=600, spacing=0.8))
    parts.append(cb)
    return doc(W, int(by + bh + PAD), "".join(parts), t, "Two product modes",
               "Relay Mode and Program Mode, two products on one shared core.")


def paths(t):
    gap = 16
    cw = (W - 2 * PAD - 2 * gap) / 3
    cards = [
        ("Relay Orchestrator", "chatgpt-web", True,
         "Quaestor drives your signed-in Chrome tab over the Chrome DevTools Protocol.",
         "Directs an Execution Agent through a whole slice, unattended unless a gate halts.",
         [("via the agent, gated", "warn"), ("LIVE_END_TO_END_QUALIFIED", "ok")]),
        ("MCP connector", "quaestor tunnel serve", False,
         "ChatGPT Developer mode reaches a loopback MCP server through an HTTPS tunnel.",
         "Reads run and program state: search, fetch, program status and inbox.",
         [("read-only token", "ro"), ("works on Plus / Pro", "ok")]),
        ("Program Mode seat", "chatgpt-web (seat)", False,
         "The same CDP browser attach, driven from executors/chatgpt_web.py.",
         "Answers one strategist packet inside a run Quaestor is already directing.",
         [("structurally refused", "no"), ("write_capable=False", "ro")]),
    ]
    inner = cw - 36
    heights = []
    for _, _, _, how, what, _ in cards:
        _, h1 = para(0, 0, how, 15, inner, t["ink"])
        _, h2 = para(0, 0, what, 15, inner, t["ink"])
        heights.append(30 + 24 + 30 + 20 + h1 + 16 + 20 + h2 + 16 + 20 + 2 * 36 + 8)
    ch = max(heights)
    parts = []
    for i, (name, kind, lead, how, what, pills) in enumerate(cards):
        cx = PAD + i * (cw + gap)
        parts.append(rect(cx, PAD, cw, ch, t["surface"], t["orch"] if lead else t["line"],
                          sw=2 if lead else 1.5))
        yy = PAD + 34
        parts.append(text(cx + 18, yy, name, 19, t["ink"], bold=True))
        yy += 24
        parts.append(text(cx + 18, yy, kind, 13, t["orch"] if lead else t["muted"], mono=True))
        yy += 34
        for label, body in (("HOW IT CONNECTS", how), ("WHAT CHATGPT DOES", what)):
            parts.append(text(cx + 18, yy, label, 11, t["muted"], mono=True, weight=500,
                              spacing=0.8))
            yy += 22
            b, bh = para(cx + 18, yy, body, 15, inner, t["ink"])
            parts.append(b)
            yy += bh + 14
        py = PAD + ch - 2 * 36 - 10
        for label, k in pills:
            svg, _ = pill(cx + 18, py, label, k, t)
            parts.append(svg)
            py += 36
    return doc(W, int(PAD + ch + PAD), "".join(parts), t, "Three ways ChatGPT meets Quaestor",
               "Relay Orchestrator over CDP, a read-only MCP connector, and a Program Mode seat.")


STEPS = [
    ("op", "YOU · ONCE", "Start a browser Quaestor can attach to, and sign in",
     "Chrome with --remote-debugging-port=9222 and a profile kept for this purpose. Quaestor "
     "never launches it, never sees the password, never closes it."),
    ("orch", "CHATGPT-WEB END · ATTACH", "Find the right tab over the DevTools endpoint",
     "GET :9222/json, keep page targets, prefer the ChatGPT URL, and open its WebSocket with a "
     "stdlib client, or Playwright’s connect_over_cdp."),
    ("kern", "KERNEL · BUILD THE PACKET",
     "Tell ChatGPT what the agent said, and what the repo shows",
     "The agent’s words verbatim up to a cap, plus a repository line from the relay’s "
     "own git. Secrets and host paths are redacted in both directions."),
    ("kern", "KERNEL · RECORD FIRST", "Write DELIVERING before sending anything",
     "Written and fsynced before the submit, so a crash between send and acknowledgement "
     "leaves evidence that a send may have happened."),
    ("orch", "CHATGPT-WEB END · SEND()", "Note what’s on screen, then type and submit",
     "Records the last data-message-id as the anchor, fills the composer and clicks Send via "
     "Runtime.evaluate, then waits for its own new user-turn id."),
    ("orch", "CHATGPT-WEB END · RECEIVE()",
     "Take the reply to our turn, once it has really finished",
     "Same conversation, or END_WORKSPACE_MISMATCH. Stop button gone, text stable. A partial "
     "reply is never forwarded."),
    ("kern", "KERNEL · DIRECTIVE GATE", "Check the reply for requested effects",
     "Anything beyond editing files needs a quaestor-effect block, and an owner-gated one becomes "
     "an OWNER_HOLD: recorded, never delivered."),
    ("exec", "OPENCODE END · DELIVER", "Hand the instruction to the agent verbatim",
     "prompt_async with a caller-supplied message id, so the agent keeps working even if the "
     "relay dies."),
    ("kern", "KERNEL · OBSERVE", "Read the repository again, independently",
     "If the difference implies a capability the profile lacks, such as a commit under "
     "STANDARD_EDIT, the relay holds. Otherwise the loop returns to step 3."),
    ("kern", "KERNEL · COMPLETION", "“Done” is a claim, and it gets measured",
     "RELAY-OBJECTIVE-COMPLETE as the last line makes the relay run every --verify command "
     "itself before it believes the claim."),
]


def exchange(t):
    lane_color = {"op": t["muted"], "orch": t["orch"], "kern": t["kern"], "exec": t["exec"]}
    parts, y = [], PAD + 30
    lx = PAD + 12
    for key, label in (("op", "you"), ("orch", "chatgpt-web end"), ("kern", "relay kernel"),
                       ("exec", "opencode end")):
        parts.append('<circle cx="%.1f" cy="%.1f" r="6" fill="%s"/>' % (lx + 6, y - 5,
                                                                         lane_color[key]))
        parts.append(text(lx + 18, y, label, 14, t["ink"]))
        lx += text_width(label, 14) + 48
    y += 30
    tx, width = PAD + 76, W - 2 * PAD - 76 - 70
    rows = []
    for lane, who, title, summary in STEPS:
        _, th = para(0, 0, title, 18, width, t["ink"], bold=True, lh=1.3)
        _, sh = para(0, 0, summary, 15.5, width, t["muted"])
        rows.append((lane, who, title, summary, 22 + th + 6 + sh + 22))
    centers = []
    cx = PAD + 34
    for i, (lane, who, title, summary, rh) in enumerate(rows):
        col = lane_color[lane]
        if i < len(rows) - 1:
            parts.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" '
                         'stroke-width="1.5"/>' % (cx, y + 36, cx, y + rh + 4, t["line"]))
        parts.append('<circle cx="%.1f" cy="%.1f" r="17" fill="%s" stroke="%s" '
                     'stroke-width="2"/>' % (cx, y + 18, t["surface"], col))
        parts.append(text(cx, y + 23.5, str(i + 1), 15, col, mono=True, bold=True,
                          anchor="middle"))
        parts.append(text(tx, y + 8, who, 11.5, col, mono=True, weight=600, spacing=0.8))
        b, th = para(tx, y + 32, title, 18, width, t["ink"], bold=True, lh=1.3)
        parts.append(b)
        s, _ = para(tx, y + 32 + th + 4, summary, 15.5, width, t["muted"])
        parts.append(s)
        centers.append(y + 18)
        y += rh
    # The real loop: steps 3-9 repeat on every exchange.
    lx = W - PAD - 24
    y3, y9 = centers[2], centers[8]
    parts.append('<path d="M%.1f %.1f H%.1f V%.1f H%.1f" fill="none" stroke="%s" '
                 'stroke-width="1.5" stroke-dasharray="5 4"/>'
                 % (lx - 18, y9, lx, y3, lx - 18, t["kern"]))
    parts.append('<path d="M%.1f %.1f l9 -5 v10 z" fill="%s"/>' % (lx - 22, y3, t["kern"]))
    my = (y3 + y9) / 2
    parts.append('<text x="%.1f" y="%.1f" font-family="%s" font-size="12" font-weight="600" '
                 'fill="%s" text-anchor="middle" letter-spacing="0.8" '
                 'transform="rotate(-90 %.1f %.1f)">EVERY EXCHANGE</text>'
                 % (lx + 16, my, MONO, t["kern"], lx + 16, my))
    return doc(W, int(y + PAD - 4), "".join(parts), t, "One relay exchange",
               "Ten steps from signing in to a measured completion; steps 3 to 9 repeat on "
               "every exchange.")


def cards_grid(t, items, cols, title, desc, top_rule=True):
    gap = 16
    cw = (W - 2 * PAD - (cols - 1) * gap) / cols
    inner = cw - 40
    measured = []
    for key, eyebrow, head, body in items:
        _, hh = para(0, 0, head, 19, inner, t["ink"], bold=True, lh=1.3)
        _, bh = para(0, 0, body, 15.5, inner, t["muted"])
        measured.append((28 if eyebrow else 8) + 26 + hh + 8 + bh + 20)
    parts = []
    rows = (len(items) + cols - 1) // cols
    y = PAD
    for r in range(rows):
        row = items[r * cols:(r + 1) * cols]
        rh = max(measured[r * cols:(r + 1) * cols])
        for c, (key, eyebrow, head, body) in enumerate(row):
            cx = PAD + c * (cw + gap)
            parts.append(rect(cx, y, cw, rh, t["surface"], t["line"]))
            if top_rule:
                parts.append('<path d="M%.1f %.1f H%.1f" stroke="%s" stroke-width="3.5" '
                             'stroke-linecap="round"/>' % (cx + 14, y + 1.8, cx + cw - 14, t[key]))
            yy = y + 30
            if eyebrow:
                parts.append(text(cx + 20, yy, eyebrow, 11.5, t[key], mono=True, weight=600,
                                  spacing=0.8))
                yy += 28
            b, hh = para(cx + 20, yy, head, 19, inner, t["ink"], bold=True, lh=1.3)
            parts.append(b)
            yy += hh + 4
            s, _ = para(cx + 20, yy, body, 15.5, inner, t["muted"])
            parts.append(s)
        y += rh + gap
    return doc(W, int(y - gap + PAD), "".join(parts), t, title, desc)


def page_identity(t):
    return cards_grid(t, [
        ("orch", "", "Threads virtualise",
         "ChatGPT renders only the most recent turns: six user turns rendered as three. A count "
         "stops rising, so the relay finds its own turn and takes the one after it."),
        ("orch", "", "Markdown eats content keys",
         "innerText drops code-fence backticks. On a 4,339-char charter the relay’s key was "
         "8857ba87 and the page’s 48c189de, diverging exactly at the fence."),
        ("kern", "", "So the page’s own ids win",
         "Each turn’s data-message-id becomes the relay message id. Without one, an id is "
         "minted from conversation, turn index and content key, and recomputes after a restart."),
        ("bad", "", "Absent from the window ≠ absent",
         "holds() navigates to the right conversation first and refuses to answer while it sees "
         "only a window. Guessing would re-send an instruction already being acted on."),
    ], 2, "Reading a chat page reliably",
        "Four facts about the ChatGPT page and how the relay handles each.")


def gates(t):
    return cards_grid(t, [
        ("kern", "1 · ONCE, AT START", "Profile ceiling",
         "A READ_ONLY relay pointed at an agent that can edit files is refused before the first "
         "message moves."),
        ("kern", "2 · PER MESSAGE", "Directive gate",
         "Fenced quaestor-effect requests run through core.authority.require. Owner-gated means "
         "a hold; an unmodelled effect class is refused, not ignored."),
        ("kern", "3 · AFTER THE FACT", "Observation gate",
         "Nobody can stop an unconfined agent from running git push. The relay refuses to "
         "instruct it, detects that it happened, and stops."),
    ], 3, "Three gates", "Profile ceiling, directive gate and observation gate.", top_rule=False)


def verdict_rows(t, rows, x, y, width, col=190):
    parts = []
    for i, (kind, label, body) in enumerate(rows):
        b, bh = para(x + col, y + 23, body, 15.5, width - col - 8, t["muted"])
        rh = max(bh, 26) + 22
        svg, _ = pill(x, y + 6, label, kind, t)
        parts.append(svg + b)
        y += rh
        if i < len(rows) - 1:
            parts.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s"/>'
                         % (x, y - 8, x + width, y - 8, t["line"]))
    return "".join(parts), y


def recovery(t):
    inner = W - 2 * PAD - 40
    body, end = verdict_rows(t, [
        ("ok", "already held", "The endpoint confirms it holds the relay-assigned id. Confirmed, "
         "never re-sent."),
        ("warn", "not held", "Re-sent exactly once."),
        ("no", "cannot answer", "Stops with UNRECONCILABLE_DELIVERY and a human decides. A "
         "transport error is never read as “no”."),
        ("ro", "outstanding turn", "Collected, not re-issued: the persisted anchor is picked back "
         "up and the reply the endpoint has been holding is read."),
    ], PAD + 20, PAD + 56, inner)
    head = text(PAD + 20, PAD + 34, "ON RESUME, FOR EVERY DELIVERY THAT WAS IN FLIGHT", 12,
                t["muted"], mono=True, weight=600, spacing=0.8)
    h = end + 4
    return doc(W, int(h + PAD), rect(PAD, PAD, W - 2 * PAD, h - PAD, t["surface"], t["line"])
               + head + body, t, "Surviving a crash", "How each in-flight delivery is reconciled.")


def record(t):
    tiles = [("30", "messages delivered · 15 round trips", False),
             ("15/15", "distinct Orchestrator ids, all from the page’s own message ids", False),
             ("0", "stale replies forwarded", True),
             ("0", "partial replies forwarded", True),
             ("0", "manual copy/paste steps after start", True),
             ("31", "independent repository observations", False)]
    gap = 12
    cw = (W - 2 * PAD - 2 * gap) / 3
    parts = [text(PAD, PAD + 18, "CHATGPT WEB QUALIFICATION RUN  ·  2026-08-30", 12,
                  t["muted"], mono=True, weight=600, spacing=0.8)]
    y = PAD + 36
    most = max(len(wrap(label, 14.5, cw - 40)) for _, label, _ in tiles)
    th = 84 + most * 14.5 * 1.35 + 12
    for i, (n, label, zero) in enumerate(tiles):
        cx = PAD + (i % 3) * (cw + gap)
        cy = y + (i // 3) * (th + gap)
        parts.append(rect(cx, cy, cw, th, t["surface"], t["line"]))
        parts.append(text(cx + 20, cy + 50, n, 40, t["orch"] if zero else t["ink"], bold=True))
        b, _ = para(cx + 20, cy + 80, label, 14.5, cw - 40, t["muted"], lh=1.35)
        parts.append(b)
    y += 2 * th + gap + 20
    body, end = verdict_rows(t, [
        ("ok", "work correct", "The fixture’s suite went from failing to 7 passing, re-run "
         "by the harness rather than believed."),
        ("ok", "restart", "Killed at exchange 2, then re-bound to the same ChatGPT conversation "
         "and OpenCode session. No duplicates, no re-deliveries."),
        ("ok", "owner hold", "An observed GIT_COMMIT under STANDARD_EDIT halted the relay. HEAD "
         "was unchanged."),
        ("warn", "billing path", "UNVERIFIED, permanently: a browser session carries no evidence "
         "of which plan is paying."),
    ], PAD + 20, y + 16, W - 2 * PAD - 40)
    parts.append(rect(PAD, y, W - 2 * PAD, end - y, t["surface"], t["line"]))
    parts.append(body)
    return doc(W, int(end + PAD), "".join(parts), t, "ChatGPT Web qualification run",
               "30 messages, 15 of 15 distinct ids, 0 stale, 0 partial, 0 copy/paste, "
               "31 independent observations.")


def ladder(t):
    rungs = ["Implemented", "Test qualified", "Live provider qualified",
             "Live end-to-end qualified", "Product supported"]
    gap = 26
    bw = (W - 2 * PAD - 4 * gap) / 5
    y, bh = PAD + 30, 76
    parts = [text(PAD, PAD + 16, "MATURITY LADDER  ·  PRD §67.1", 12, t["muted"],
                  mono=True, weight=600, spacing=0.8)]
    for i, name in enumerate(rungs):
        x = PAD + i * (bw + gap)
        reached, here, future = i < 3, i == 3, i == 4
        fill = t["orch_soft"] if here else t["surface"]
        stroke = t["orch"] if here else t["line"]
        parts.append(rect(x, y, bw, bh, fill, stroke, sw=2 if here else 1.5,
                          dash="5 4" if future else None))
        lines = wrap(name, 15.5, bw - 24, bold=here)
        ly = y + bh / 2 - (len(lines) - 1) * 10 + 5
        for j, ln in enumerate(lines):
            parts.append(text(x + bw / 2, ly + j * 20, ln, 15.5,
                              t["muted"] if future else t["ink"], anchor="middle",
                              weight=700 if here else (500 if reached else 400)))
        if i < 4:
            ax = x + bw + 5
            parts.append('<path d="M%.1f %.1f h%.1f" stroke="%s" stroke-width="1.5"/>'
                         '<path d="M%.1f %.1f l-6 -4.5 v9 z" fill="%s"/>'
                         % (ax, y + bh / 2, gap - 12, t["muted"], ax + gap - 6, y + bh / 2,
                            t["muted"]))
    right = PAD + 3 * (bw + gap) + bw
    parts.append('<path d="M%.1f %.1f v14" stroke="%s" stroke-width="2"/>'
                 % (right - bw / 2, y + bh, t["orch"]))
    parts.append(text(right, y + bh + 38, "Relay Mode is here: chatgpt-web · openai-chat "
                      "· opencode", 14.5, t["orch"], anchor="end", weight=600))
    return doc(W, int(y + bh + 62), "".join(parts), t, "Maturity ladder",
               "Relay Mode is live end-to-end qualified; nothing is product supported yet.")


TOPOLOGY = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1120 500" width="1120" height="500" role="img" aria-labelledby="t d">
<title id="t">Quaestor relay topology</title>
<desc id="d">Your Chrome with a signed-in ChatGPT tab connects over the Chrome DevTools Protocol on port 9222 to the chatgpt-web end, which plugs into the provider-neutral relay kernel. The kernel plugs into the opencode end, which talks HTTP on port 4096 to opencode serve, which edits the repository. The kernel independently observes the repository with its own git and runs verify commands. The owner starts, resumes and stops the relay and answers owner holds.</desc>
<style>
.sans{{font-family:{sans}}}
.mono{{font-family:{mono}}}
.title{{font-size:15px;font-weight:700;fill:{ink}}}
.sub{{font-size:11px;fill:{muted}}}
.lbl{{font-size:10.5px;fill:{muted}}}
.grp{{font-size:10.5px;font-weight:600;letter-spacing:.08em}}
</style>
<defs>
<marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{muted}"/></marker>
<marker id="ao" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{orch}"/></marker>
<marker id="ae" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{exec}"/></marker>
<marker id="ak" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{kern}"/></marker>
</defs>
<rect x="0.75" y="0.75" width="1118.5" height="498.5" rx="14" fill="{ground}" stroke="{line}" stroke-width="1.5"/>
<text x="24" y="34" class="mono grp" fill="{orch}">ORCHESTRATOR SIDE</text>
<text x="510" y="34" class="mono grp" fill="{kern}">RELAY KERNEL · NO PROVIDER IMPORTS</text>
<text x="770" y="34" class="mono grp" fill="{exec}">EXECUTION SIDE</text>
<line x1="24" y1="44" x2="472" y2="44" stroke="{orch}" stroke-width="2" opacity=".35"/>
<line x1="510" y1="44" x2="730" y2="44" stroke="{kern}" stroke-width="2" opacity=".35"/>
<line x1="770" y1="44" x2="1096" y2="44" stroke="{exec}" stroke-width="2" opacity=".35"/>
<rect x="24" y="76" width="200" height="156" rx="8" fill="{orch_soft}" stroke="{orch}" stroke-width="1.5"/>
<text x="40" y="102" class="sans title">Your Chrome</text>
<text x="40" y="121" class="mono sub">started by you with</text>
<text x="40" y="136" class="mono sub">--remote-debugging-port</text>
<rect x="38" y="150" width="172" height="66" rx="5" fill="{surface}" stroke="{line}" stroke-width="1.5"/>
<text x="50" y="171" class="mono sub" style="fill:{orch}">chatgpt.com tab</text>
<text x="50" y="188" class="mono sub">signed in once,</text>
<text x="50" y="203" class="mono sub">never by Quaestor</text>
<path d="M224 154 H260" stroke="{orch}" stroke-width="2" fill="none" marker-start="url(#ao)" marker-end="url(#ao)"/>
<text x="229" y="141" class="mono lbl">CDP</text>
<text x="227" y="175" class="mono lbl">:9222</text>
<rect x="262" y="76" width="210" height="156" rx="8" fill="{surface}" stroke="{orch}" stroke-width="1.5"/>
<text x="278" y="102" class="sans title">chatgpt-web end</text>
<text x="278" y="120" class="mono sub">relay/ends/chatgpt_web.py</text>
<text x="278" y="146" class="mono lbl">send()    types + submits</text>
<text x="278" y="163" class="mono lbl">receive() waits, then reads</text>
<text x="278" y="180" class="mono lbl">holds()   reconciles</text>
<text x="278" y="197" class="mono lbl">resume()  rebinds the thread</text>
<text x="278" y="214" class="mono lbl">probe()   declines</text>
<path d="M472 154 H508" stroke="{muted}" stroke-width="1.5" fill="none" marker-start="url(#a)" marker-end="url(#a)"/>
<rect x="510" y="66" width="220" height="250" rx="8" fill="{kern_soft}" stroke="{kern}" stroke-width="1.5"/>
<text x="526" y="94" class="sans title">Relay kernel</text>
<text x="526" y="112" class="mono sub">kernel · state · effects</text>
<text x="526" y="127" class="mono sub">observe · packets</text>
<line x1="526" y1="140" x2="714" y2="140" stroke="{kern}" opacity=".35"/>
<text x="526" y="160" class="mono lbl">message identity · dedup</text>
<text x="526" y="178" class="mono lbl">bounded packets</text>
<text x="526" y="196" class="mono lbl">secret + path redaction</text>
<text x="526" y="214" class="mono lbl">authority gates · owner holds</text>
<text x="526" y="232" class="mono lbl">completion corroboration</text>
<text x="526" y="250" class="mono lbl">crash recovery</text>
<rect x="526" y="266" width="188" height="34" rx="4" fill="{surface}" stroke="{line}" stroke-width="1.5"/>
<text x="538" y="287" class="mono lbl" style="fill:{kern}">durable ledger + event log</text>
<path d="M730 154 H768" stroke="{muted}" stroke-width="1.5" fill="none" marker-start="url(#a)" marker-end="url(#a)"/>
<rect x="770" y="76" width="160" height="156" rx="8" fill="{surface}" stroke="{exec}" stroke-width="1.5"/>
<text x="786" y="102" class="sans title">opencode end</text>
<text x="786" y="120" class="mono sub">relay/ends/</text>
<text x="786" y="135" class="mono sub">opencode.py</text>
<text x="786" y="163" class="mono lbl">prompt_async with</text>
<text x="786" y="180" class="mono lbl">caller-chosen id</text>
<text x="786" y="206" class="mono lbl">assurance: DIALOGUE</text>
<path d="M930 154 H970" stroke="{exec}" stroke-width="2" fill="none" marker-start="url(#ae)" marker-end="url(#ae)"/>
<text x="936" y="141" class="mono lbl">HTTP</text>
<text x="934" y="175" class="mono lbl">:4096</text>
<rect x="972" y="76" width="124" height="156" rx="8" fill="{exec_soft}" stroke="{exec}" stroke-width="1.5"/>
<text x="984" y="102" class="sans title" style="font-size:14px">opencode</text>
<text x="984" y="119" class="sans title" style="font-size:14px">serve</text>
<text x="984" y="140" class="mono sub">started by you</text>
<text x="984" y="162" class="mono lbl">existing or</text>
<text x="984" y="177" class="mono lbl">resumable</text>
<text x="984" y="192" class="mono lbl">session</text>
<text x="984" y="216" class="mono lbl">unconfined</text>
<rect x="770" y="380" width="326" height="92" rx="8" fill="{sunk}" stroke="{muted}" stroke-width="1.5"/>
<text x="786" y="410" class="sans title">Repository</text>
<text x="786" y="430" class="mono sub">the authorized project</text>
<text x="786" y="447" class="mono sub">ground truth</text>
<path d="M1034 232 V378" stroke="{exec}" stroke-width="2" fill="none" marker-end="url(#ae)"/>
<text x="1042" y="312" class="mono lbl" style="fill:{exec}">edits</text>
<text x="1042" y="327" class="mono lbl" style="fill:{exec}">files</text>
<path d="M620 316 V426 H768" stroke="{kern}" stroke-width="1.5" fill="none" stroke-dasharray="5 4" marker-end="url(#ak)"/>
<text x="630" y="350" class="mono lbl" style="fill:{kern}">its own git, before</text>
<text x="630" y="365" class="mono lbl" style="fill:{kern}">and after every turn</text>
<text x="630" y="412" class="mono lbl" style="fill:{kern}">--verify commands</text>
<rect x="24" y="380" width="448" height="92" rx="8" fill="{surface}" stroke="{muted}" stroke-width="1.5" stroke-dasharray="4 4"/>
<text x="40" y="410" class="sans title">You, the owner</text>
<text x="40" y="430" class="mono sub">quaestor relay start | status | resume | stop</text>
<text x="40" y="447" class="mono sub">answer owner holds; grants come only from you</text>
<path d="M472 400 H540 V318" stroke="{muted}" stroke-width="1.5" fill="none" marker-end="url(#a)"/>
</svg>
"""


def topology(t):
    return TOPOLOGY.format(sans=SANS.replace("&quot;", '"'), mono=MONO.replace("&quot;", '"'),
                           **t)


PANELS = {"hero": hero, "relay-topology": topology, "modes": modes, "chatgpt-paths": paths,
          "exchange": exchange, "page-identity": page_identity, "gates": gates,
          "recovery": recovery, "qualification": record, "maturity": ladder}


def main() -> int:
    written = 0
    for name, fn in PANELS.items():
        for theme, tokens in THEMES.items():
            path = os.path.join(OUT, "%s-%s.svg" % (name, theme))
            with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(fn(tokens))
            written += 1
    print("wrote %d files to %s" % (written, OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""adapters.command -- generic command/stdin-stdout and clipboard dialogue adapters (§5.2 T1).

Two Tier 1 transports that drive an opaque external agent with text and read text back. Neither
owns a lifecycle (no start/stop/pause claims), neither proves containment, and neither
self-declares an assurance level: DIALOGUE-or-below is whatever the conformance probes compute
(§5.3, §31). Weak transports still yield strong evidence because handoff measurement is
parent-side -- these adapters only have to be honest about what they carried.

PROMPT TRANSPORT (§5.13)
------------------------
The prompt travels via STDIN on every turn. It NEVER travels via argv: argv is readable from the
process table by any local process, so a prompt in argv publishes every task, credential and
owner instruction to anything that can run ``ps``. The spawn goes through the module-level
``_popen`` indirection so controls can substitute a recording launcher and MEASURE the leak
property instead of trusting this comment.

Clipboard is MANUAL MODE by design: Quaestor copies the prompt to the clipboard; a human or IDE
paste does the rest; the response is read back from the clipboard. Windows PowerShell
Get-Clipboard/Set-Clipboard via subprocess only -- no third-party dependency.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

from quaestor.adapters import register
from quaestor.adapters.base import AgentAdapter

COMMAND_INSTRUMENT = "adapters.command/1"

#: Spawn indirection: controls substitute a recording launcher HERE, so the production path and
#: the measured path are the same code (CONTROL_REACHABLE, not a test-only seam).
_popen = subprocess.Popen

#: The PowerShell script bodies ride argv as -EncodedCommand, which is safe under §5.13 because
#: they are PUBLIC CONSTANTS: the variable payload (the prompt / the clipboard answer) never
#: appears in argv -- it crosses as base64 over stdin/stdout so no console encoding can mangle it.
_PASTE_SCRIPT = ("$raw=[Console]::In.ReadToEnd();"
                 "Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString("
                 "[Convert]::FromBase64String($raw.Trim())))")
_FETCH_SCRIPT = ("[Console]::Out.Write([Convert]::ToBase64String("
                 "[Text.Encoding]::UTF8.GetBytes([string](Get-Clipboard -Raw))))")


class CommandTurnError(RuntimeError):
    """One turn failed loudly (non-zero exit). A failed turn is not a reply."""


class CommandTimeoutError(CommandTurnError):
    """The turn exceeded its budget and was killed. Loud failure beats a hung lane (§17)."""


class ClipboardUnsupportedError(RuntimeError):
    """Clipboard transport refused because this platform cannot honestly provide it."""


def _prompt_text(message) -> str:
    """Serialize one message for stdin. Structured messages stay structured (JSON)."""
    if isinstance(message, str):
        return message
    return json.dumps(message)


def _reply_value(raw_text: str):
    """Normalize captured stdout into a reply: JSON-looking output parses back to data.

    Round-trip honesty for structured turns; everything else stays verbatim text. Output that
    merely LOOKS parseable but fails stays raw rather than raising -- the turn succeeded, the
    format guess did not.
    """
    stripped = raw_text.strip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(stripped)
        except ValueError:
            pass
    return raw_text


@register
class CommandAdapter(AgentAdapter):
    """Run ONE command per turn: prompt -> stdin, stdout -> reply.

    ``command_template`` must be an argv SEQUENCE (a shell string would blur exactly where the
    prompt may and may not travel). The child's exit code decides whether a reply exists at all:
    non-zero raises loudly rather than packaging stderr as a plausible-sounding answer.
    """

    ADAPTER_KIND = "command"
    DECLARED_CAPABILITIES = ()
    #: Measured facts, not decoration: stdout exists to observe, and the prompt rides STDIN.
    conformance_harness = {"observe": True, "prompt_transport": "STDIN"}

    def __init__(self, command_template, cwd=None, *, timeout_s=30.0,
                 adapter_id="command"):
        super().__init__(adapter_id)
        if isinstance(command_template, str) or not command_template:
            raise ValueError(
                "command_template must be a non-empty sequence of argv items; a shell string "
                "would blur where the prompt may travel (§5.13)")
        self._template = [str(part) for part in command_template]
        if cwd is not None and not Path(cwd).is_dir():
            raise ValueError("cwd %r does not exist: refusing to spawn into nowhere" % (cwd,))
        self._cwd = None if cwd is None else str(cwd)
        self._timeout_s = float(timeout_s)
        self._replies: list = []

    def send(self, message) -> None:
        # PROMPT VIA STDIN ONLY. argv below carries the template and nothing else -- the control
        # suite asserts this with a recording launcher rather than taking our word for it.
        proc = _popen(self._template, cwd=self._cwd, stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      encoding="utf-8", errors="replace")
        try:
            out, err = proc.communicate(_prompt_text(message), timeout=self._timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()  # reap: a killed child must not linger as a zombie turn
            raise CommandTimeoutError(
                "command turn exceeded %.1fs and was killed (%s)"
                % (self._timeout_s, " ".join(self._template))) from None
        if proc.returncode != 0:
            raise CommandTurnError("command turn failed rc=%s: %s"
                                   % (proc.returncode, (err or "").strip()))
        self._replies.append(out)

    def receive(self):
        if not self._replies:
            return None  # loud-not-partial: no captured output is NO reply
        return _reply_value(self._replies.pop(0))


@register
class ClipboardAdapter(AgentAdapter):
    """Windows clipboard bridge: Set-Clipboard to send, Get-Clipboard to receive.

    MANUAL MODE (§5.2 Tier 1): the human/IDE completes the loop between our paste and their
    paste. Payload crosses as base64 over stdin/stdout through public-constant scripts, so the
    clipboard text itself never appears in argv. Same contract as CommandAdapter: JSON-shaped
    replies parse back to data, plain text stays verbatim, empty clipboard is None -- never a
    fabricated answer.
    """

    ADAPTER_KIND = "clipboard"
    DECLARED_CAPABILITIES = ()
    conformance_harness = {"observe": True, "prompt_transport": "STDIN"}

    SUPPORTED = sys.platform == "win32"

    def __init__(self, *, adapter_id="clipboard", timeout_s=20.0):
        super().__init__(adapter_id)
        self._timeout_s = float(timeout_s)

    def _run_ps(self, script: str, stdin_text: str) -> str:
        if not self.SUPPORTED:
            raise ClipboardUnsupportedError(
                "clipboard transport requires Windows PowerShell; refusing to pretend on %s"
                % sys.platform)
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        argv = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
        proc = subprocess.run(argv, input=stdin_text, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=self._timeout_s)
        if proc.returncode != 0:
            raise CommandTurnError("clipboard turn failed rc=%s: %s"
                                   % (proc.returncode, (proc.stderr or "").strip()))
        return proc.stdout

    def send(self, message) -> None:
        payload = base64.b64encode(_prompt_text(message).encode("utf-8")).decode("ascii")
        self._run_ps(_PASTE_SCRIPT, payload)

    def receive(self):
        raw = self._run_ps(_FETCH_SCRIPT, "").strip()
        if not raw:
            return None
        try:
            return _reply_value(base64.b64decode(raw).decode("utf-8"))
        except (ValueError, TypeError):
            # Clipboard held something we did not paste: surface it verbatim as text. It is
            # information, not authority -- the caller decides what it means.
            return raw

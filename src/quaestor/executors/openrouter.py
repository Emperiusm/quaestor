"""openrouter -- one model of ~300, in any seat, over one API key. Direct HTTP, no subprocess.

WHY THERE IS NO CHILD PROCESS
------------------------------
Every other executor here shells out because the vendor ships a CLI. This one is an HTTPS call,
so spawning anything would be theatre. What it does NOT skip is the run files: stdout, stderr and
``command.json`` are written exactly as a subprocess executor writes them, because the dispatcher,
the reaper, ``parse_envelope``, the evidence path and the handoff-strength classifier all read
those files, and none of them should have to learn that this provider is different. The seam is
the transport; the record is identical.

THE ENVELOPE IS SYNTHESISED, AND SAYS SO
-----------------------------------------
A CLI writes a result envelope; an HTTP API returns a chat completion. So this module BUILDS the
envelope from the completion and writes it to stdout in the shape ``parse_envelope`` already
consumes. That is a translation, not a measurement, which is why the raw provider response is
also written to ``response.json``: if the translation is ever wrong, the original is on disk to
prove it.

A REFUSAL IS AN OUTCOME, NOT A CRASH
-------------------------------------
An HTTP 4xx/5xx from the provider is ``started=True`` with a non-zero exit class -- the same shape
a CLI that ran and failed produces -- because it IS that: the request happened and was answered.
Only a failure to make the request at all is a spawn failure. Getting this backwards would make
every rate limit look like a broken installation.

THE KEY NEVER TOUCHES DISK
---------------------------
It is read from the environment at call time, used in one header, and never written to
``command.json``, never logged, never included in any recorded field. ``command.json`` records
that a key was present, not what it was.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Mapping

from quaestor import branding
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK,
                                             EXIT_SPAWN_FAILED, EXIT_TIMEOUT,
                                             ExecOutcome, ExecRequest, Executor)

OPENROUTER_INSTRUMENT = "openrouter/1"

COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
API_KEY_VAR = "OPENROUTER_API_KEY"


#: Sent so OpenRouter can attribute traffic. Neither identifies the operator nor their machine.
#: The product name comes from ``branding`` -- this is EMITTED text leaving the process, and a
#: rename that missed it would attribute this deployment's traffic to a name the product no
#: longer has. (Control 172 catches the literal; the reason is this.)
ATTRIBUTION_HEADERS = {"X-Title": branding.PRODUCT_TITLE}


class OpenRouterMisconfigured(ValueError):
    """The executor was constructed without a model. Named so the registry can refuse loudly."""


def build_payload(req: ExecRequest, *, model: str) -> dict:
    """The request body. PURE.

    The prompt travels in the JSON BODY, never a URL: a query string is logged by every proxy
    and reverse proxy between here and the provider, and the prompt carries the whole task.
    """
    return {"model": str(model),
            "messages": [{"role": "user", "content": str(req.prompt)}],
            "stream": False}


def synthesise_envelope(completion: Mapping, *, model: str) -> dict:
    """A chat completion -> the result envelope shape ``parse_envelope`` consumes. PURE.

    ``result`` holds the assistant text verbatim. Usage is copied under an allowlist so the cost
    surfaces already built (``_cost_facts``) see the same fields they see for a CLI.
    """
    text = ""
    choices = completion.get("choices") if isinstance(completion, Mapping) else None
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, Mapping):
            message = first.get("message")
            if isinstance(message, Mapping):
                text = str(message.get("content") or "")
    usage = completion.get("usage") if isinstance(completion, Mapping) else None
    env = {"type": "result", "subtype": "success", "is_error": False,
           "result": text, "model": str(model), "instrument": OPENROUTER_INSTRUMENT}
    if isinstance(usage, Mapping):
        env["usage"] = {k: usage[k] for k in
                        ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
                        if k in usage}
    return env


def _default_opener(url: str, headers: Mapping[str, str], body: bytes, timeout: float):
    """The real HTTP write. Replaced wholesale by controls so no test touches the network."""
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - fixed https URL
        return int(r.status), r.read().decode("utf-8", "replace")


class OpenRouterExecutor(Executor):
    """One OpenRouter model, dispatched as a seat. HTTP only; writes the standard run files."""

    name = "openrouter"

    def __init__(self, *, model: str, opener=None, env: Mapping[str, str] | None = None):
        if not str(model or "").strip():
            raise OpenRouterMisconfigured(
                "an OpenRouter executor requires a model: the gateway is not a vendor, so a "
                "seat built without one has no provider family and cannot be certified "
                "independent of anything")
        self._model = str(model).strip()
        self._opener = opener or _default_opener
        self._env = env

    # -- helpers -----------------------------------------------------------------------------
    def _key(self) -> str:
        env = os.environ if self._env is None else self._env
        return str((env or {}).get(API_KEY_VAR) or "").strip()

    def _write(self, path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    # -- the contract ------------------------------------------------------------------------
    def execute(self, req: ExecRequest) -> ExecOutcome:
        payload = build_payload(req, model=self._model)
        body = json.dumps(payload).encode("utf-8")
        key = self._key()

        # command.json records what DECIDED behaviour -- and records the key as present/absent,
        # never as a value.
        try:
            self._write(os.path.join(req.run_dir, "command.json"), json.dumps({
                "executor": self.name, "model": self._model, "url": COMPLETIONS_URL,
                "method": "POST", "transport": "https",
                "prompt_bytes": len(str(req.prompt).encode("utf-8")),
                "prompt_location": "json_body",
                "key_var": API_KEY_VAR, "key_present": bool(key),
                "instrument": OPENROUTER_INSTRUMENT}, indent=2).encode("utf-8"))
        except OSError as exc:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="cannot write run files: %s" % exc)

        if not key:
            self._write(req.stderr_path,
                        ("%s is not set; refusing to dispatch an OpenRouter seat\n"
                         % API_KEY_VAR).encode("utf-8"))
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="%s is not set" % API_KEY_VAR)

        headers = dict(ATTRIBUTION_HEADERS)
        headers.update({"Authorization": "Bearer " + key,
                        "Content-Type": "application/json"})
        try:
            status, text = self._opener(COMPLETIONS_URL, headers, body, float(req.timeout_s))
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            try:
                text = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                text = ""
        except TimeoutError as exc:
            self._write(req.stderr_path, ("timed out after %ss: %s\n"
                                          % (req.timeout_s, exc)).encode("utf-8"))
            return ExecOutcome(True, None, EXIT_TIMEOUT,
                               error="request exceeded %ss" % req.timeout_s)
        except Exception as exc:  # noqa: BLE001
            # THE REQUEST NEVER HAPPENED. That is a spawn failure, not a failed run: a run that
            # never started must not be reconciled as one that started and produced nothing.
            self._write(req.stderr_path,
                        ("%s: %s\n" % (type(exc).__name__, exc)).encode("utf-8"))
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="%s: %s" % (type(exc).__name__, exc))

        # The raw provider answer, always, before any translation of it.
        self._write(os.path.join(req.run_dir, "response.json"),
                    (text or "").encode("utf-8"))

        if status != 200:
            self._write(req.stderr_path,
                        ("OpenRouter answered HTTP %d\n%s\n" % (status, text[:4000]))
                        .encode("utf-8"))
            self._write(req.stdout_path, b"")
            # started=True: the request HAPPENED and was answered. A rate limit is a measured
            # outcome of a run, not a broken installation.
            return ExecOutcome(True, status, EXIT_NONZERO,
                               error="OpenRouter answered HTTP %d" % status)
        try:
            completion = json.loads(text or "{}")
        except (ValueError, TypeError) as exc:
            self._write(req.stderr_path,
                        ("unparseable OpenRouter response: %s\n" % exc).encode("utf-8"))
            self._write(req.stdout_path, b"")
            return ExecOutcome(True, 0, EXIT_NONZERO, error="unparseable response body")

        envelope = synthesise_envelope(completion, model=self._model)
        self._write(req.stdout_path, json.dumps(envelope).encode("utf-8"))
        self._write(req.stderr_path, b"")
        return ExecOutcome(True, 0, EXIT_OK, note="synthesised envelope from chat completion")

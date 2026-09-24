"""http_chat -- an OrchestratorEnd over the OpenAI-compatible chat-completions protocol.

ONE PROTOCOL, MANY VENDORS
--------------------------
OpenRouter, OpenCode Zen, OpenAI itself and every compatible gateway speak the same wire format.
So this endpoint is named for the PROTOCOL and takes a base URL, and the vendor identity comes
from the MODEL -- ``anthropic/claude-...`` is Anthropic whichever gateway carried the bytes.
That is the same rule ``adapters.registry`` enforces for Program Mode seats, and for the same
reason: if the proxy reported itself as the vendor, two models from one vendor would pass every
independence check by sharing a gateway name.

THE CONVERSATION LIVES HERE, NOT AT THE PROVIDER
------------------------------------------------
A chat-completions endpoint is stateless: each call carries the whole message list. So THIS
endpoint owns the transcript, and "conversation identity" means an id for a message list that
this process persists. That has a consequence worth stating plainly rather than hiding:

    conversation resume works because the relay kept the transcript,
    not because the provider remembers anything.

``supports_conversation_resume`` is True and ``proves_workspace_identity`` is False, and the
limits tuple says so, so nothing downstream can mistake this for a provider-side session.

MESSAGE IDENTITY
----------------
The protocol supplies no stable per-turn id, so one is MINTED deterministically from the
conversation id, the turn ordinal and the content digest. Deterministic matters: an incrementing
counter held in memory would restart at zero after a crash and make an already-delivered turn
look new, which is the one failure the whole ledger exists to prevent.

THE KEY NEVER TOUCHES DISK. It is read from the environment at call time and used in one header.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Mapping

from quaestor import branding
from quaestor.relay.contracts import (END_IDLE, END_NOT_AUTHENTICATED,
                                      END_PROVIDER_ERROR, PROBE_OK, PROBE_REFUSED,
                                      PROBE_UPSTREAM_FAILED, EndFacts, EndProbe, EndStatus,
                                      FROM_ORCHESTRATOR, RESUME_LOST, RESUME_RESUMED, RelayEnd,
                                      RelayMessage, ROLE_ORCHESTRATOR, SendReceipt, digest)

HTTP_CHAT_INSTRUMENT = "relay.ends.http_chat/1"

#: Sent so the provider can attribute traffic. Identifies neither the operator nor the machine.
#:
#: THE USER-AGENT IS NOT COSMETIC. ``urllib`` defaults to ``Python-urllib/<v>``, and at least one
#: provider behind Cloudflare answers that with HTTP 403 (error 1010) on every route -- MEASURED
#: against opencode.ai/zen on 2026-08-29, where the same request from curl returned 200. A
#: transport that is blocked by its own default header looks exactly like a rejected credential,
#: which is the most misleading failure this endpoint could produce.
ATTRIBUTION_HEADERS = {"X-Title": branding.PRODUCT_TITLE,
                       "User-Agent": "%s/%s" % (branding.PRODUCT_NAME,
                                                branding.PRODUCT_VERSION)}

#: Vendor prefix -> family, sharing ``adapters.registry``'s vocabulary on purpose: a model
#: reached through a gateway must collide with the same model reached directly.
def provider_family(model: str) -> str:
    """The VENDOR that actually answers, derived from the model. PURE.

    A model with no vendor prefix yields "" rather than a guess. An unknown vendor must not be
    assumed independent of anything, and the honest answer to "whose model is this?" for a bare
    name is "we do not know".
    """
    from quaestor.adapters.registry import GATEWAY_VENDOR_FAMILY
    name = str(model or "").strip()
    if "/" not in name:
        return ""
    return GATEWAY_VENDOR_FAMILY.get(name.partition("/")[0].lower(), "")


def _default_opener(url: str, headers: Mapping[str, str], body: bytes, timeout: float):
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - caller-pinned URL
        return int(r.status), r.read().decode("utf-8", "replace")


def _resolve_key(key_var: str, key_file: str = "", key_file_field: str = "") -> tuple:
    """``(key, source)``. Impure (env/file). Returns ("", reason) when there is none.

    A key file is supported because several local tools already store one, and asking an
    operator to re-enter a credential they have already provisioned is how credentials end up
    pasted into shell history. The VALUE is never returned to any caller but this module's own
    header construction, and never written anywhere.
    """
    val = str(os.environ.get(key_var) or "").strip()
    if val:
        return val, "env:%s" % key_var
    if key_file:
        try:
            with open(os.path.expanduser(key_file), "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception as exc:  # noqa: BLE001 - an unreadable key file is "no key", named
            return "", "key file %s unreadable: %s" % (key_file, type(exc).__name__)
        node = doc
        for part in [p for p in str(key_file_field or "").split(".") if p]:
            node = node.get(part) if isinstance(node, Mapping) else None
            if node is None:
                return "", "key file %s has no field %s" % (key_file, key_file_field)
        if isinstance(node, str) and node.strip():
            return node.strip(), "file:%s#%s" % (key_file, key_file_field)
        return "", "key file %s field %s is not a string" % (key_file, key_file_field)
    return "", "%s is not set" % key_var


def preflight(*, base_url: str = "", model: str = "", key_var: str = "",
              key_file: str = "", key_file_field: str = "", **_ignored) -> dict:
    """MEASURED readiness: is there a credential, and does the provider answer? Impure."""
    key, source = _resolve_key(key_var, key_file, key_file_field)
    if not key:
        return {"ok": False, "kind": "openai-chat", "detail": source,
                "proves": "NO_CREDENTIAL", "model": model,
                "provider_family": provider_family(model)}
    url = str(base_url).rstrip("/") + "/models"
    try:
        headers = dict(ATTRIBUTION_HEADERS)
        headers["Authorization"] = "Bearer " + key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20.0) as r:     # noqa: S310
            status = int(r.status)
            r.read(1)
    except urllib.error.HTTPError as exc:
        status = int(getattr(exc, "code", 0) or 0)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "kind": "openai-chat",
                "detail": "%s: %s" % (type(exc).__name__, exc), "proves": "UNREACHABLE",
                "model": model, "provider_family": provider_family(model)}
    return {"ok": status == 200, "kind": "openai-chat",
            "detail": "%s answered HTTP %d for a model listing" % (url, status),
            "proves": "CREDENTIAL_ACCEPTED" if status == 200 else "CREDENTIAL_REJECTED",
            "key_source": source, "model": model,
            "provider_family": provider_family(model)}


class HttpChatOrchestratorEnd(RelayEnd):
    """A persistent strategic conversation over a stateless chat-completions API."""

    def __init__(self, *, base_url: str, model: str, key_var: str = "",
                 key_file: str = "", key_file_field: str = "",
                 conversation_id: str = "", transcript_path: str = "",
                 temperature: float | None = None, max_tokens: int = 0,
                 timeout_s: float = 300.0, opener=None, clock=time.time):
        if not str(base_url or "").strip():
            raise ValueError("an http-chat orchestrator requires a base_url; there is no "
                             "default provider")
        if not str(model or "").strip():
            raise ValueError("an http-chat orchestrator requires a model: the gateway is not a "
                             "vendor, so an endpoint built without one has no provider family "
                             "and its provenance cannot be recorded honestly")
        self._base = str(base_url).rstrip("/")
        self._model = str(model).strip()
        self._key_var = str(key_var or "")
        self._key_file = str(key_file or "")
        self._key_file_field = str(key_file_field or "")
        self._timeout = float(timeout_s)
        self._temperature = temperature
        self._max_tokens = int(max_tokens or 0)
        self._opener = opener or _default_opener
        self._clock = clock
        self._conversation_id = str(conversation_id or "").strip() or ("conv-" + hashlib.sha256(
            ("%s|%s|%f" % (self._base, self._model, self._clock())).encode()).hexdigest()[:12])
        self._transcript_path = str(transcript_path or "")
        self._messages: list = []
        self._turn = 0
        self._pending_after: str = ""
        self.facts = EndFacts(
            kind="openai-chat", role=ROLE_ORCHESTRATOR,
            provider_family=provider_family(self._model), model=self._model,
            can_send=True, can_receive=True, can_observe=False, can_mutate_repo=False,
            manages_lifecycle=False, supports_session_resume=False,
            supports_conversation_resume=True,
            proves_message_identity=True, proves_workspace_identity=False,
            proves_capability_surface=False, proves_readonly_behavior=False,
            proves_confinement=False,
            limits=(
                "the provider is stateless: conversation continuity is provided by the relay's "
                "own transcript, not by anything the provider remembers",
                "no lifecycle control -- a request in flight cannot be cancelled by the relay",
                "the vendor identity is derived from the model name; a bare model name with no "
                "vendor prefix yields no provider family rather than a guess",
            ))

    # -- transcript persistence ----------------------------------------------------------------
    def _save(self) -> None:
        if not self._transcript_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self._transcript_path)) or ".",
                    exist_ok=True)
        tmp = self._transcript_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"conversation_id": self._conversation_id, "model": self._model,
                       "base_url": self._base, "turn": self._turn,
                       "messages": self._messages}, fh)
        os.replace(tmp, self._transcript_path)

    def _load(self) -> bool:
        if not self._transcript_path or not os.path.isfile(self._transcript_path):
            return False
        try:
            with open(self._transcript_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001 - an unreadable transcript is NO transcript, not a crash
            return False
        if str(doc.get("conversation_id") or "") != self._conversation_id:
            return False
        self._messages = list(doc.get("messages") or [])
        self._turn = int(doc.get("turn") or 0)
        return True

    # -- identity -----------------------------------------------------------------------------
    def _mint(self, turn: int, text: str) -> str:
        """A DETERMINISTIC message id. PURE given its inputs.

        Derived from conversation, ordinal and content, so the same turn recomputes the same id
        after a restart. An in-memory counter would reset to zero and make an already-delivered
        turn look new -- the single failure the delivery ledger exists to prevent.
        """
        return "%s:t%03d:%s" % (self._conversation_id, int(turn), digest(text)[:12])

    def holds(self, message_id: str) -> bool:
        """Does the transcript already carry this relay-assigned id? The reconciliation question.

        Answerable exactly because the transcript is ours and is persisted: every user message is
        stored with the relay id it was delivered under.
        """
        return any(str(m.get("relay_message_id") or "") == message_id for m in self._messages)

    def open(self) -> EndStatus:
        key, source = _resolve_key(self._key_var, self._key_file, self._key_file_field)
        if not key:
            return EndStatus(END_NOT_AUTHENTICATED, self._conversation_id, source)
        self._load()
        return EndStatus(END_IDLE, self._conversation_id,
                         "chat conversation %s on %s via %s (credential from %s)"
                         % (self._conversation_id, self._model, self._base, source))

    def status(self) -> EndStatus:
        key, source = _resolve_key(self._key_var, self._key_file, self._key_file_field)
        state = END_IDLE if key else END_NOT_AUTHENTICATED
        return EndStatus(state, self._conversation_id,
                         "%d turns held locally" % self._turn if key else source,
                         facts={"model": self._model, "base_url": self._base,
                                "key_source": source if key else ""})

    def identity(self) -> str:
        return self._conversation_id

    def resume(self, identity: str) -> tuple:
        """Re-bind to a persisted transcript. HONEST about where the continuity comes from."""
        self._conversation_id = str(identity or self._conversation_id)
        if self._load():
            return RESUME_RESUMED, ("re-bound to conversation %s: %d turns restored from the "
                                    "relay's own transcript (the provider is stateless and "
                                    "remembers nothing)" % (self._conversation_id, self._turn))
        if not self._transcript_path:
            return RESUME_LOST, ("conversation %s cannot be resumed: this endpoint was built "
                                 "without a transcript path, so nothing was persisted"
                                 % self._conversation_id)
        return RESUME_LOST, ("conversation %s has no persisted transcript at %s"
                             % (self._conversation_id, self._transcript_path))

    # -- the contract --------------------------------------------------------------------------
    def send(self, text: str, *, message_id: str) -> SendReceipt:
        """Append to the transcript. The provider call happens in ``receive``.

        The split is deliberate: a chat completion is one round trip, so "send" is the moment the
        message becomes durably part of the conversation, and that is exactly the moment the
        delivery ledger needs recorded. Persisting here is what makes ``holds`` answerable after
        a crash.
        """
        self._messages.append({"role": "user", "content": str(text),
                               "relay_message_id": str(message_id)})
        self._save()
        return SendReceipt(True, native_id=str(message_id))

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0):
        """Call the provider and return its completed turn.

        A chat completion is never partial: the call returns when the answer is finished, so
        ``complete`` is True for a 200 and the endpoint never has to guess. An HTTP error is
        returned as a FAILED turn rather than raised, so the kernel records a named outcome.
        """
        key, source = _resolve_key(self._key_var, self._key_file, self._key_file_field)
        if not key:
            return RelayMessage(message_id="%s:err:%d" % (self._conversation_id, self._turn),
                                direction=FROM_ORCHESTRATOR, text="", complete=False,
                                observed_at=float(self._clock()),
                                conversation_id=self._conversation_id,
                                error="%s: %s" % (END_NOT_AUTHENTICATED, source))
        payload = {"model": self._model,
                   "messages": [{"role": m["role"], "content": m["content"]}
                                for m in self._messages],
                   "stream": False}
        if self._temperature is not None:
            payload["temperature"] = float(self._temperature)
        if self._max_tokens:
            payload["max_tokens"] = int(self._max_tokens)
        headers = dict(ATTRIBUTION_HEADERS)
        headers.update({"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        url = self._base + "/chat/completions"
        body = json.dumps(payload).encode("utf-8")
        try:
            status, raw = self._opener(url, headers, body,
                                       float(timeout_s or self._timeout))
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            try:
                raw = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
        except Exception as exc:  # noqa: BLE001 - a transport fault is an outcome, not a crash
            return RelayMessage(message_id="%s:err:%d" % (self._conversation_id, self._turn),
                                direction=FROM_ORCHESTRATOR, text="", complete=False,
                                observed_at=float(self._clock()),
                                conversation_id=self._conversation_id,
                                error="%s: %s: %s" % (END_PROVIDER_ERROR, type(exc).__name__,
                                                      exc))
        if status != 200:
            return RelayMessage(message_id="%s:err:%d" % (self._conversation_id, self._turn),
                                direction=FROM_ORCHESTRATOR, text="", complete=False,
                                observed_at=float(self._clock()),
                                conversation_id=self._conversation_id,
                                error="%s: HTTP %d %s" % (END_PROVIDER_ERROR, status,
                                                          str(raw)[:600]))
        try:
            doc = json.loads(raw or "{}")
        except (TypeError, ValueError) as exc:
            return RelayMessage(message_id="%s:err:%d" % (self._conversation_id, self._turn),
                                direction=FROM_ORCHESTRATOR, text="", complete=False,
                                observed_at=float(self._clock()),
                                conversation_id=self._conversation_id,
                                error="%s: unparseable response: %s" % (END_PROVIDER_ERROR, exc))
        text, finish = "", ""
        choices = doc.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], Mapping):
            finish = str(choices[0].get("finish_reason") or "")
            msg = choices[0].get("message")
            if isinstance(msg, Mapping):
                text = str(msg.get("content") or "")
        # A truncated answer is NOT a completed turn. Forwarding a reply the provider cut off
        # mid-sentence as an instruction is the "partial delivered as complete" failure.
        complete = finish in ("", "stop", "end_turn", "eos")
        self._turn += 1
        mid = self._mint(self._turn, text)
        if complete:
            # AN INCOMPLETE TURN IS NOT WRITTEN TO THE TRANSCRIPT. Appending it would leave the
            # conversation ending on a half-finished assistant message with no new user message
            # after it, so the caller's RETRY would be answered as a CONTINUATION -- the provider
            # returns only the remaining tokens, and the head of the directive is lost. Measured:
            # a turn reading "Do not touch tests/current ... once you are confident," retried,
            # delivered only " delete the stale fixture files", with the guardrail gone and no
            # copy of it anywhere in the ledger. A retry must re-ask the SAME question.
            self._messages.append({"role": "assistant", "content": text,
                                   "relay_message_id": mid})
            self._save()
        usage = doc.get("usage") if isinstance(doc.get("usage"), Mapping) else {}
        return RelayMessage(
            message_id=mid, direction=FROM_ORCHESTRATOR, text=text, complete=complete,
            observed_at=float(self._clock()), conversation_id=self._conversation_id,
            provenance={"kind": "openai-chat", "base_url": self._base,
                        "model": str(doc.get("model") or self._model),
                        "provider_family": provider_family(self._model),
                        "finish_reason": finish,
                        "usage": {k: usage[k] for k in
                                  ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
                                  if k in usage},
                        "instrument": HTTP_CHAT_INSTRUMENT},
            error="" if complete else ("provider stopped for reason %r; a truncated answer is "
                                       "not a completed turn" % finish))


    #: Ceiling on a probe. Bounded well below the endpoint's own receive timeout because
    #: admission must be quick, but not so tight that a slow-but-healthy model is refused.
    PROBE_TIMEOUT_S = 120.0

    #: Upstream-shaped HTTP statuses. These say the provider could not serve the request right
    #: now; everything else in the 4xx range says it understood and refused.
    UPSTREAM_STATUSES = (408, 429, 500, 502, 503, 504, 529)

    def probe(self) -> EndProbe:
        """Ask the MODEL for one real token. NEVER raises. Does not touch the conversation.

        WHY THIS IS NOT ``status()``. status() reports whether a credential exists -- it makes
        no network call at all, so it answers IDLE for a model that errors on every inference
        and for a gateway that is returning 503 to everything. Both were live-observed. The
        probe is the only thing that distinguishes "I have a key" from "a turn comes back".

        THE CONVERSATION IS NOT DISTURBED. The request is built from a throwaway message list
        and the reply is discarded: ``self._messages`` and ``self._turn`` are untouched, so a
        probe leaves no trace in the transcript the relay resumes from.
        """
        key, source = _resolve_key(self._key_var, self._key_file, self._key_file_field)
        if not key:
            return EndProbe(PROBE_REFUSED, "no credential: %s" % source, model=self._model)
        # THE SHAPE THE REAL TURN SENDS, not a cheaper one. Hard-coding max_tokens here made
        # the probe measure a request ``receive()`` never makes: receive only sends max_tokens
        # when the operator configured one (default 0 = absent). Models that reject the
        # parameter -- OpenAI's reasoning models want max_completion_tokens, thinking-enabled
        # Anthropic models reject a cap below the thinking budget -- would answer HTTP 400, and
        # the relay would refuse to start for a configuration whose real turns work perfectly.
        payload = {"model": self._model, "stream": False,
                   "messages": [{"role": "user", "content": "Reply with the single word OK."}]}
        if self._max_tokens:
            payload["max_tokens"] = int(self._max_tokens)
        if self._temperature is not None:
            payload["temperature"] = float(self._temperature)
        headers = dict(ATTRIBUTION_HEADERS)
        headers.update({"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        started = time.time()
        try:
            status, raw = self._opener(self._base + "/chat/completions", headers,
                                       json.dumps(payload).encode("utf-8"),
                                       min(float(self._timeout), self.PROBE_TIMEOUT_S))
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            try:
                raw = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
        except Exception as exc:  # noqa: BLE001 - a transport fault is a verdict, not a crash
            return EndProbe(PROBE_UPSTREAM_FAILED,
                            "%s: %s" % (type(exc).__name__, exc), time.time() - started,
                            self._model)
        took = time.time() - started
        if status in self.UPSTREAM_STATUSES:
            return EndProbe(PROBE_UPSTREAM_FAILED,
                            "the provider answered HTTP %d: %s" % (status, str(raw)[:300]),
                            took, self._model, status)
        if status >= 400:
            return EndProbe(PROBE_REFUSED,
                            "the provider refused this request with HTTP %d: %s"
                            % (status, str(raw)[:300]), took, self._model, status)
        try:
            doc = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            return EndProbe(PROBE_UPSTREAM_FAILED,
                            "HTTP %d with an unparseable body (%s)" % (status, type(exc).__name__),
                            took, self._model, status)
        # A 200 CARRYING AN ERROR IS STILL AN ERROR. Gateways that multiplex many providers
        # routinely return 200 with an error object when the upstream model failed -- which is
        # exactly how the model that errors on every inference presented in the live run.
        err = doc.get("error") if isinstance(doc, Mapping) else None
        if err:
            return EndProbe(PROBE_REFUSED,
                            "the provider answered HTTP %d carrying an error: %s"
                            % (status, json.dumps(err)[:300]), took, self._model, status)
        choices = doc.get("choices") if isinstance(doc, Mapping) else None
        if not (isinstance(choices, list) and choices):
            return EndProbe(PROBE_REFUSED,
                            "HTTP %d with no choices: the model returned nothing" % status,
                            took, self._model, status)
        return EndProbe(PROBE_OK, "the model answered in %.2fs" % took, took, self._model, status)

    def close(self) -> None:
        self._save()

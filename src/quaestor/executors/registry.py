"""registry -- the provider-neutral executor factory.

THE INVERSION SEAM
------------------
``core`` must not import any provider: a core that statically depends on one executor cannot be
used with another, which would make "model-agnostic" a slogan. So the core declares the NEED --
"give me something that satisfies the Executor contract for this spec" -- and this module, which
lives in the provider layer, satisfies it.

The worker resolves this module at call time rather than importing it at module scope. That is
not indirection for its own sake: it is what keeps the layering rule mechanically checkable, and
a control walks the real import graph to prove ``core`` never reaches an outer layer.

Adding a provider is a change HERE and nowhere else in the platform.
"""
from __future__ import annotations

from typing import Mapping

from quaestor import branding

REGISTRY_INSTRUMENT = "executors.registry/1"

#: Every executor this build can construct. A kind absent from here is REFUSED, never guessed:
#: an unknown executor name must not silently degrade to the fake one, because a run that
#: reports success from a fake it did not ask for is the worst possible outcome.
#:
#: ONE VOCABULARY, DERIVED ONCE (bd quaestor-ubg): this tuple is the BUILDABLE subset of
#: adapters.registry.PROVIDER_REGISTRY, and ``is_buildable`` below is the predicate the
#: admission path consults. The declared-but-unconstructible remainder (gemini-cli, gpt-plan,
#: local-llama) is refused AT ADMISSION by name -- a seat can no longer be routed to a kind
#: that would only die later in ``build``.
KNOWN_KINDS = ("fake", "claude-cli", "claude-container", "codex-cli", "openrouter",
               "chatgpt-web", "command", "file-inbox")

#: Named admission-refusal marker for a kind that is declared but has no constructible
#: executor in this build. The refusal is the honest statement: "declared does not mean
#: shipped", and admission says so instead of letting dispatch discover it at build time.
NOT_BUILDABLE_IN_THIS_BUILD = "KIND_NOT_BUILDABLE_IN_THIS_BUILD"


def is_buildable(kind: str) -> bool:
    """Can this build construct an executor for ``kind``? PURE.

    The gateway split mirrors ``build`` below: a gateway kind arrives as
    ``<gateway>:<vendor>/<model>``, so its base names the executor. A kind that is declared
    in the capability registry but absent from ``KNOWN_KINDS`` is exactly the gap
    quaestor-ubg closed: it must be visible HERE so admission can refuse it, not only in
    the ValueError ``build`` would eventually raise.
    """
    base = str(kind or "").partition(":")[0]
    from quaestor.adapters.registry import GATEWAY_KINDS
    if base in GATEWAY_KINDS:
        return base in KNOWN_KINDS
    return str(kind or "") in KNOWN_KINDS


def build(spec: Mapping):
    """Build the executor named by ``request.json``. Impure (imports).

    The spec lives in the request artifact so a reconciling process can see WHICH executor a run
    used without re-deriving it from configuration that may since have changed.
    """
    # NO DEFAULT. An absent or empty kind used to become "fake", so a run could report success
    # from an executor nobody asked for -- the worst available outcome, because it looks like
    # work happened. KNOWN_KINDS is consulted here rather than being decorative.
    kind = str((spec or {}).get("kind") or "")
    # A GATEWAY kind arrives as "<gateway>:<vendor>/<model>" -- the model IS the provider
    # identity (adapters.registry.GATEWAY_KINDS), so the base names the executor to build and
    # the remainder names what it must run.
    base, _sep, pinned_model = kind.partition(":")
    # The gateway vocabulary is DECLARED ONCE, in adapters.registry. Retyping the tuple here
    # made a second copy that would not follow when a gateway is added.
    from quaestor.adapters.registry import GATEWAY_KINDS
    if base in GATEWAY_KINDS:
        kind = base
    if kind not in KNOWN_KINDS:
        raise ValueError(
            "executor kind %r is not one of %s. There is deliberately no default: a run that "
            "silently used a fake executor would report success for work that never happened."
            % (kind, list(KNOWN_KINDS)))
    if kind == "fake":
        from quaestor.executors.fake import FakeClaudeExecutor, FakeConfig
        cfg = dict((spec or {}).get("config") or {})
        return FakeClaudeExecutor(FakeConfig(**cfg))
    if kind == "claude-cli":
        from quaestor.executors.claude_code import ClaudeCliExecutor
        return ClaudeCliExecutor()
    if kind == "openrouter":
        # NO DEFAULT MODEL, EVER. An executor built without one would inherit the gateway's
        # empty provider family and silently defeat the cross-vendor pairing check -- the exact
        # failure the gateway identity work exists to prevent.
        from quaestor.executors.openrouter import OpenRouterExecutor
        cfg = dict((spec or {}).get("config") or {})
        named = str(pinned_model or "").strip()
        configured = str(cfg.get("model") or "").strip()
        # THE KIND WINS, AND A DISAGREEMENT IS A REFUSAL. Preferring config.model created a
        # SECOND, invisible channel for provider identity: every governance function --
        # provider_family, check_pairing, resolve_seat -- reads the vendor out of the KIND, so a
        # config.model naming a different vendor would have been billed and run while the
        # independence checks reasoned about the other one.
        if named and configured and named != configured:
            raise ValueError(
                "openrouter kind names model %r but config.model names %r; refusing rather "
                "than running one vendor while every independence check reasons about the "
                "other" % (named, configured))
        model = named or configured
        if not model:
            raise ValueError(
                "an openrouter executor requires a model: name it as 'openrouter:<vendor>/"
                "<model>' or in config.model. The gateway is not a vendor, so a seat built "
                "without one has no provider family and cannot be certified independent.")
        return OpenRouterExecutor(model=model)
    if kind == "chatgpt-web":
        # Attaches to a browser the operator already started and signed into. It builds without
        # any credential and without launching anything; if no browser is attached, the failure
        # belongs to execute() where it can be recorded as a named run outcome rather than to
        # construction, where it would look like a broken installation.
        from quaestor.executors.chatgpt_web import ChatGptWebExecutor
        cfg = dict((spec or {}).get("config") or {})
        return ChatGptWebExecutor(
            conversation_id=str(cfg.get("conversation_id") or cfg.get("session_id") or ""),
            endpoint=str(cfg.get("endpoint") or ""),
            prefer=str(cfg.get("transport") or "auto"))
    if kind == "codex-cli":
        # bd quaestor-1ng: the cross-vendor reviewer seat. Same construction discipline as
        # claude-cli; the binary is overridable per spec for tests and hermetic deployments.
        from quaestor.executors.codex_cli import CodexCliExecutor
        cfg = dict((spec or {}).get("config") or {})
        return CodexCliExecutor(binary=str(cfg.get("binary") or "codex"))
    if kind == "claude-container":
        # The DETACHED WORKER rebuilds the profile from the durable request artifact, so the
        # envelope that executes is the one the dispatcher validated -- not one re-derived from
        # configuration that may have changed since admission. run_confined then re-validates it
        # against the daemon's description of the created container before anything starts.
        from quaestor.sandbox import profile as cp
        from quaestor.executors.container import ClaudeContainerExecutor
        cfg = dict((spec or {}).get("config") or {})
        profile = cp.ContainerProfile.from_dict(cfg.get("profile") or {})
        return ClaudeContainerExecutor(
            profile,
            container_name=str(cfg.get("container_name") or branding.resource("child")),
            forbidden_host_paths=tuple(cfg.get("forbidden_host_paths") or ()),
            expected_rw_hosts=tuple(cfg.get("expected_rw_hosts") or ()),
            workspace_container_path=str(cfg.get("workspace_container_path") or "/workspace"),
            container_env=dict(cfg.get("container_env") or {}),
            permitted_exact_paths=tuple(cfg.get("permitted_exact_paths") or ()),
            never_exempt=tuple(cfg.get("never_exempt") or ()),
            remove=bool(cfg.get("remove", True)))
    if kind == "command":
        # The GENERIC command seat (bd quaestor-cjj): a user-supplied argv template, prompt on
        # STDIN only, one turn per execute(). Built from the request artifact's config so a
        # reconciling process sees exactly what was pinned.
        from quaestor.executors.bridge import CommandExecutor
        cfg = dict((spec or {}).get("config") or {})
        return CommandExecutor(cfg)
    if kind == "file-inbox":
        # The REFERENCE universal seat (bd quaestor-ru1.19): the file inbox/outbox adapter is
        # dispatchable end to end; the external writer answers in the outbox.
        from quaestor.executors.bridge import FileInboxExecutor
        cfg = dict((spec or {}).get("config") or {})
        return FileInboxExecutor(cfg)
    raise ValueError("unknown executor kind %r" % kind)


#: Backwards-compatible alias for the name the worker used before the inversion.
make_executor = build


def run_preflight(kind: str, *, claude_path: str = "", requires_write: bool = False):
    """The dispatch preflight for ``kind``, resolved in the PROVIDER layer. Impure (imports).

    Same inversion as ``build``, for the same reason: whether a run's authentication needs a
    credential-broker preflight is a property of the PROVIDER, and core must be able to ask
    without importing one. A kind that performs no credential-bearing authentication answers
    ACCEPT here -- the honest default for the fake executor, and the exact decision core used
    to make before this seam existed.
    """
    if kind == "claude-cli":
        from quaestor.executors.claude_auth import run_preflight as _rp
        return _rp(claude_path=claude_path or "claude", requires_write=requires_write)
    if kind == "codex-cli":
        # The MEASURED preflight for the codex seat: same credential_policy question, this
        # provider's own override variables and login-status reading. A missing binary or an
        # unrecognisable status REFUSES -- an honest instrument limitation, never a guess.
        from quaestor.executors.codex_auth import run_preflight as _rp_codex
        return _rp_codex(requires_write=requires_write)
    base = kind.partition(":")[0]
    if base == "openrouter":
        # MEASURED, not assumed. Without this branch an OpenRouter seat fell through to the
        # ACCEPT below and reported fine with NO API KEY AT ALL -- which silently defeats the
        # entire honest-credential story the preflight exists to tell.
        from quaestor.executors.openrouter_auth import run_preflight as _rp_or
        return _rp_or()
    if base == "chatgpt-web":
        # Attaches the browser and reads the page. It ACCEPTs a live session and still reports
        # UNVERIFIED billing -- see chatgpt_web_auth for why those are not in tension.
        from quaestor.executors.chatgpt_web_auth import run_preflight as _rp_cw
        return _rp_cw()
    from quaestor.core.credential_policy import (ACCEPT, PreflightDecision, REFUSE,
                                                 UNVERIFIED)
    if kind == "fake":
        return PreflightDecision(
            ACCEPT, "", "the fake executor performs no credential-bearing authentication",
            "NOT_APPLICABLE_FAKE_EXECUTOR", (),
            {"claude_binary_invoked": False, "credential_broker_opened": False})
    if kind in ("command", "file-inbox"):
        # EXPLICIT BRANCHES, not a fallback (bd quaestor-cjj): the transport bridges perform no
        # credential-bearing authentication of their OWN. Whatever credentials the external
        # command or the external outbox writer uses are theirs -- never supplied, never
        # inspected, never billed by this bridge -- so the subscription-vs-API question this
        # preflight exists to answer does not arise here. A future bridge that DOES touch a
        # credential must ship a measured preflight instead of widening this branch.
        return PreflightDecision(
            ACCEPT, "",
            "the %s bridge performs no credential-bearing authentication; the external "
            "participant's own credentials are out of this bridge's assessment scope" % kind,
            "NOT_APPLICABLE_TRANSPORT_BRIDGE", (),
            {"claude_binary_invoked": False, "credential_broker_opened": False})
    # FAIL CLOSED FOR EVERYTHING ELSE. The blanket ACCEPT was written when "fake" was the only
    # kind that reached it; every kind added since inherited a free pass it was never assessed
    # for. A provider this build ships no preflight for has not been checked, and "not checked"
    # must not present as "checked and fine".
    return PreflightDecision(
        REFUSE, "NO_PREFLIGHT_FOR_KIND",
        "this build ships no credential preflight for executor %r, so its billing path is "
        "unassessed; refusing rather than reporting an unchecked provider as healthy" % kind,
        UNVERIFIED, (),
        {"claude_binary_invoked": False, "credential_broker_opened": False})

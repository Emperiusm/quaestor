"""transport_mode -- the machine gate that makes P5-A dispatch incapable of running Claude.

WHY THIS IS A CONSTANT AND NOT A SETTING
----------------------------------------
There is no setter, no environment variable, no CLI flag and no request field that can change the
mode. Changing it is a source edit, reviewed under the authority of whichever phase needs it.

That is deliberate and it is the same shape as ``owner_channel.owner_channel_state()``: a value a
caller can influence is a value an attacker can influence, and "the prompt said not to execute" is
not a control. P5-A's requirement is that real execution be IMPOSSIBLE, not forbidden.

THREE INDEPENDENT BARRIERS, NOT ONE
-----------------------------------
    1. STRUCTURAL   the adapter dispatches with ``spawn=False``. No worker process is created,
                    so ``core.worker`` -- which is where an executor is constructed, by asking
                    ``executors.registry.build`` for one -- is never reached. Nothing to sandbox,
                    because nothing runs. (The factory moved behind a runtime lookup during the
                    extraction; that seam is covered by the layering control's by-site allowlist,
                    NOT by the static reachability walk below, which cannot see a string-named
                    import. Naming it here so the gap is stated rather than assumed.)
    2. EXECUTOR     the executor spec is a module constant here, never built from caller input,
                    and ``assert_inert`` refuses any kind outside ``ALLOWED_EXECUTOR_KINDS``.
    3. AUTHORITY    the profile allowlist admits READ_ONLY only. Every write profile, and
                    STANDARD_EDIT_CONFINED in particular, refuses at the transport edge -- before
                    the orchestrator's own authority engine, which would also refuse it.

Any ONE of the three is sufficient. They are kept separate so that a future edit which relaxes one
(P5-C will relax the first) does not silently relax the others.

WHAT THIS MODULE DOES NOT DECIDE
--------------------------------
It does not decide whether a run is authorised, whether a lease is valid, or whether evidence
passes. Those live in ``authority``, ``store`` and ``evidence`` and the transport must not
duplicate them -- a second opinion on a policy question is a second policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from quaestor.core import authority as authority_mod

MODE_INSTRUMENT = "transport_mode/1"

#: The only mode this source tree implements. P5-B/P5-C/P5-D would add others, under their own
#: authority, as an edit here -- which is a reviewable diff rather than a runtime accident.
QUALIFICATION_ONLY = "QUALIFICATION_ONLY"

#: The OPERATIONAL mode. Real constrained execution through the already-qualified admission
#: ladder: detached workers, real executors, READ_ONLY and STANDARD_EDIT envelopes, independent
#: evidence, fenced lanes. It deliberately does NOT mean unrestricted shell, unrestricted
#: filesystem, automatic push, automatic external writes or destructive operations -- those stay
#: owner-gated exactly as they were. See docs/OPERATIONS.md for the trust boundary.
LOCAL_GOVERNED = "LOCAL_GOVERNED"

#: Every mode this source tree implements. An unknown mode resolves to QUALIFICATION_ONLY
#: (fail-closed), never to the newest thing on disk.
KNOWN_MODES = (QUALIFICATION_ONLY, LOCAL_GOVERNED)

#: THE DEFAULT MODE. A constant. When no deployment decision file exists this source tree is
#: executor-inert, exactly as qualified. A deployment selects LOCAL_GOVERNED by writing the mode
#: file ONCE, locally, with ``quaestor mode set LOCAL_GOVERNED`` -- an act that requires the same
#: OS-user authority running this process already has, so it widens nothing against an attacker
#: who could otherwise reach the machine. What it must NEVER be is influenceable by a REQUEST:
#: see ``FORBIDDEN_FIELDS`` ("transport_mode") in transports.mcp.schemas.
TRANSPORT_EXECUTION_MODE = QUALIFICATION_ONLY

#: Executor kinds the transport may name in QUALIFICATION_ONLY. Only "fake" cannot reach a real
#: Claude process.
ALLOWED_EXECUTOR_KINDS = frozenset({"fake"})

#: Authority profiles the transport may name in QUALIFICATION_ONLY. NARROWER than what the
#: orchestrator's authority engine would permit -- the transport edge is allowed to be stricter
#: than the policy below it, never laxer.
ALLOWED_AUTHORITY_PROFILES = frozenset({authority_mod.READ_ONLY})

#: Executor kinds admissible in LOCAL_GOVERNED. The containerised provider exists and is built by
#: the registry, but the Windows-native deployment this mode was qualified for exercises the CLI
#: provider; admitting "claude-container" here would advertise confinement the host cannot
#: currently validate. Widening this set is a deliberate edit, reviewed as such.
OPERATIONAL_EXECUTOR_KINDS = frozenset({"fake", "claude-cli"})

#: Authority profiles admissible in LOCAL_GOVERNED. Deliberately EXACTLY the pair the mandate
#: names: ordinary inspection and ordinary bounded editing. Everything above STANDARD_EDIT --
#: GIT_PUSH, EXTERNAL_WRITE, PAID_EXECUTION, DESTRUCTIVE -- stays behind the owner gate no
#: matter what a project manifest asks for.
OPERATIONAL_AUTHORITY_PROFILES = frozenset({authority_mod.READ_ONLY,
                                            authority_mod.STANDARD_EDIT})

#: The executor spec written into every qualification dispatch. A CONSTANT: it is never
#: assembled from a request, so there is no field an MCP caller could influence.
#: The config keys must be REAL ``fake_executor.FakeConfig`` fields. An earlier version invented
#: ``stdout_mode``/``exit_code``/``note``, which ``FakeConfig(**cfg)`` would have rejected with a
#: TypeError -- so barrier 2 would have "held" only by crashing, which is not the barrier it
#: claims to be. A barrier that works for the wrong reason is not measured, it is lucky.
QUALIFICATION_EXECUTOR: Mapping = {
    "kind": "fake",
    "config": {"scenario": "OK_PASS", "session_id": "p5a-qualification-0001"},
}

#: Refusal reasons. Named, because "refused" without a reason is not actionable.
EXECUTION_MODE_REFUSED = "TRANSPORT_EXECUTION_MODE_REFUSED"
EXECUTOR_KIND_REFUSED = "TRANSPORT_EXECUTOR_KIND_REFUSED"
AUTHORITY_PROFILE_REFUSED = "TRANSPORT_AUTHORITY_PROFILE_REFUSED"


@dataclass(frozen=True)
class InertVerdict:
    """Why a request may or may not proceed as an inert qualification dispatch."""

    ok: bool
    reason: str = ""
    detail: str = ""
    checked: tuple = ()
    inspected_count: int = 0
    instrument: str = MODE_INSTRUMENT
    record: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason, "detail": self.detail,
                "checked": list(self.checked), "inspected_count": self.inspected_count,
                "instrument": self.instrument, "record": dict(self.record)}


def assert_inert(*, authority_profile: str, executor: Mapping | None = None,
                 spawn: bool = False) -> InertVerdict:
    """May this dispatch proceed under the current mode? PURE. NEVER raises.

    EMITS A COUNT OF WHAT IT CHECKED. A verdict that checked nothing is not a pass -- the same
    rule this project applies to every other gate, applied to the gate that matters most.
    """
    checked = []

    checked.append("mode")
    if TRANSPORT_EXECUTION_MODE != QUALIFICATION_ONLY:
        return InertVerdict(False, EXECUTION_MODE_REFUSED,
                            "transport mode is %r; this source tree implements only %r"
                            % (TRANSPORT_EXECUTION_MODE, QUALIFICATION_ONLY),
                            tuple(checked), len(checked))

    checked.append("spawn")
    if spawn:
        return InertVerdict(False, EXECUTION_MODE_REFUSED,
                            "a qualification dispatch may not spawn a worker: the worker is the "
                            "only process that ever constructs an executor",
                            tuple(checked), len(checked))

    checked.append("executor_kind")
    kind = str((executor or {}).get("kind") or "")
    if kind not in ALLOWED_EXECUTOR_KINDS:
        return InertVerdict(False, EXECUTOR_KIND_REFUSED,
                            "executor kind %r is not one of %s"
                            % (kind, sorted(ALLOWED_EXECUTOR_KINDS)),
                            tuple(checked), len(checked))

    checked.append("authority_profile")
    if str(authority_profile) not in ALLOWED_AUTHORITY_PROFILES:
        return InertVerdict(False, AUTHORITY_PROFILE_REFUSED,
                            "authority profile %r is not admitted by the transport in %s mode "
                            "(admitted: %s). This refusal is at the TRANSPORT edge; the "
                            "orchestrator's authority engine is unchanged and would apply its own."
                            % (authority_profile, QUALIFICATION_ONLY,
                               sorted(ALLOWED_AUTHORITY_PROFILES)),
                            tuple(checked), len(checked))

    return InertVerdict(True, "", "", tuple(checked), len(checked),
                        record={"mode": TRANSPORT_EXECUTION_MODE, "executor_kind": kind,
                                "authority_profile": str(authority_profile), "spawn": False})


# ---------------------------------------------------------------------------------------------
# The deployment decision. WHERE THE MODE COMES FROM, AND WHY THERE
# ---------------------------------------------------------------------------------------------
#
# A mode that a REQUEST could select would be no mode at all -- it would be a default with a
# suggestion box attached. So the operational mode is selected exactly once per deployment, by a
# LOCAL file this server reads at startup:
#
#     <home>/mode.json   {"transport_execution_mode": "LOCAL_GOVERNED"}
#
# written only by the local CLI (`quaestor mode set ...`), which requires the same OS-user
# authority this process already runs under. That is the honest boundary for a single-owner local
# deployment (see docs/THREAT-MODEL.md, LOCAL_SINGLE_OWNER): anyone who can write that file can
# already edit this source, so the file adds no new attack surface -- while a REMOTE caller still
# cannot reach the mode through any field, header or tool argument. Absent file -> fail-closed to
# QUALIFICATION_ONLY. An unreadable or unrecognised value is ALSO QUALIFICATION_ONLY, and says so.

MODE_FILE = "mode.json"
MODE_SOURCE_DEFAULT = "MODULE_CONSTANT"
MODE_SOURCE_DEPLOYMENT = "DEPLOYMENT_FILE"


def mode_file_path(home: str) -> str:
    """Where the deployment's mode decision lives. PURE."""
    import os
    return os.path.join(str(home or ""), MODE_FILE)


def resolve_mode(home: str) -> tuple:
    """(mode, record). Impure (reads one file). NEVER raises; fails CLOSED.

    The record states which source decided the mode and what was inspected, because a mode that
    silently fell back is indistinguishable from the default unless the fallback is NAMED.
    """
    import json
    import os

    path = mode_file_path(home)
    record = {"mode_file": path, "present": False, "source": MODE_SOURCE_DEFAULT}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        record["present"] = True
    except FileNotFoundError:
        return QUALIFICATION_ONLY, record
    except (OSError, ValueError) as exc:
        record["fallback_reason"] = "%s: %s" % (type(exc).__name__, exc)
        return QUALIFICATION_ONLY, record

    raw = ""
    if isinstance(doc, Mapping):
        raw = str(doc.get("transport_execution_mode") or "")
    if raw not in KNOWN_MODES:
        record["fallback_reason"] = ("transport_execution_mode %r is not one of %s; refusing to "
                                     "guess" % (raw, list(KNOWN_MODES)))
        record["declared"] = raw
        return QUALIFICATION_ONLY, record
    record["source"] = MODE_SOURCE_DEPLOYMENT
    record["declared"] = raw
    return raw, record


def write_mode(home: str, mode: str) -> dict:
    """Persist the deployment's mode decision. Impure. Raises ValueError on an unknown mode.

    Called ONLY by the local CLI. There is deliberately no MCP verb, no request field and no
    environment variable behind this: every one of those would let a strategist select its own
    execution model, which is the escalation this gate exists to prevent.
    """
    import json
    import os
    import time

    if mode not in KNOWN_MODES:
        raise ValueError("unknown transport mode %r; known modes are %s" % (mode, list(KNOWN_MODES)))
    path = mode_file_path(home)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    doc = {"transport_execution_mode": mode, "set_at": time.time(),
           "instrument": MODE_INSTRUMENT,
           "note": ("written by the local operator CLI. A remote transport caller cannot change "
                    "the execution mode.")}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return {"path": path, "transport_execution_mode": mode}


def assert_admissible(mode: str, *, authority_profile: str, executor: Mapping | None = None,
                      spawn: bool = False) -> InertVerdict:
    """May this dispatch proceed under THIS mode? PURE. NEVER raises.

    The mode-aware generalisation of ``assert_inert``. Each mode keeps its own three barriers
    (structural / executor / authority); they are checked separately so an edit relaxing one does
    not silently relax the others.
    """
    checked = []
    kind = str((executor or {}).get("kind") or "")

    checked.append("mode_known")
    if mode not in KNOWN_MODES:
        return InertVerdict(False, EXECUTION_MODE_REFUSED,
                            "transport mode %r is not implemented by this build (%s)"
                            % (mode, list(KNOWN_MODES)), tuple(checked), len(checked))

    checked.append("mode")
    if mode == QUALIFICATION_ONLY:
        # Delegate to the qualified ladder so its refusals keep their exact wording.
        return assert_inert(authority_profile=authority_profile, executor=executor, spawn=spawn)

    # ---- LOCAL_GOVERNED barriers --------------------------------------------------------------
    checked.append("executor_kind")
    if kind not in OPERATIONAL_EXECUTOR_KINDS:
        return InertVerdict(False, EXECUTOR_KIND_REFUSED,
                            "executor kind %r is not admitted in %s mode (admitted: %s)"
                            % (kind, LOCAL_GOVERNED, sorted(OPERATIONAL_EXECUTOR_KINDS)),
                            tuple(checked), len(checked))

    checked.append("authority_profile")
    if str(authority_profile) not in OPERATIONAL_AUTHORITY_PROFILES:
        return InertVerdict(
            False, AUTHORITY_PROFILE_REFUSED,
            "authority profile %r is not admitted by the transport in %s mode (admitted: %s). "
            "Higher capabilities remain owner-gated; this refusal is at the TRANSPORT edge and "
            "the orchestrator's authority engine still applies its own."
            % (authority_profile, LOCAL_GOVERNED, sorted(OPERATIONAL_AUTHORITY_PROFILES)),
            tuple(checked), len(checked))

    checked.append("spawn_shape")
    if not isinstance(spawn, bool):
        return InertVerdict(False, EXECUTION_MODE_REFUSED, "spawn must be a boolean",
                            tuple(checked), len(checked))

    return InertVerdict(True, "", "", tuple(checked), len(checked),
                        record={"mode": mode, "executor_kind": kind,
                                "authority_profile": str(authority_profile), "spawn": bool(spawn)})


#: Modules that must be unreachable, at import level, from the transport adapter. Enforced by a
#: static control walking the real import graph -- not by this list being written down.
#:
#: NOT LISTED: ``quaestor.dpapi``. It is the OS crypto primitive, not provider credential
#: material, and the OWNER-attestation channel -- which the authority chain must be able to consult
#: (core.authority -> core.owner_channel -> quaestor.attestation) -- legitimately needs it. The
#: provider credential path is what stays forbidden: its broker and its validator are the only
#: holders of provider blobs, and neither is reachable without the other being reachable first.
FORBIDDEN_TRANSPORT_IMPORTS = (
    "quaestor.core.worker",                # the process that constructs an executor
    "quaestor.executors.registry",         # the factory that chooses which one
    "quaestor.executors.claude_code",      # a native provider child
    "quaestor.executors.container",        # a containerised provider child
    "quaestor.sandbox.docker",             # any container at all
    "quaestor.secrets.store",              # the provider credential broker
    "quaestor.secrets.validate",           # the credential validation child
)

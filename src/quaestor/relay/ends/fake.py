"""fake -- scripted endpoints that prove the kernel's MECHANICS for free.

WHAT THESE ARE FOR, AND WHAT THEY ARE NOT FOR
---------------------------------------------
They exist so that message identity, deduplication, loop guards, the delivery ledger and crash
reconciliation can be proven deterministically, without burning provider capacity and without a
network. That is a real and useful property: those are the parts of a relay most likely to be
wrong and least likely to be exercised by a happy-path live run.

They are NOT evidence that Relay Mode works. The architecture is explicit: "Mocks may prove
Relay Kernel mechanics. Mocks may not be used to claim the Relay product works." So every fake
here reports ``fact_status``-equivalent honesty through ``EndFacts``: ``provider_family`` is
"test", nothing is proven above DIALOGUE, and ``can_mutate_repo`` is whatever the test asked for
rather than a flattering default.

THE CRASH SEAM
--------------
``fail_after_send`` makes an endpoint accept a message and then raise, which is the only way to
reach the DELIVERING-row-left-behind state deliberately. Without a seam like this the
reconciliation path is unreachable, and an unreachable branch is an untested one however many
controls point at it.
"""
from __future__ import annotations

import time
from typing import Callable, Sequence

from quaestor.relay.contracts import (END_IDLE, END_FAILED, PROBE_OK, EndFacts, EndProbe, EndStatus,
                                      FROM_EXECUTION, FROM_ORCHESTRATOR, RESUME_RESUMED,
                                      RESUME_UNSUPPORTED, RelayEnd, RelayMessage, SendReceipt,
                                      ROLE_EXECUTION, ROLE_ORCHESTRATOR)


class ScriptExhausted(RuntimeError):
    """The script ran out. Named so a control can tell "the fake ended" from "the kernel hung"."""


class _FakeEnd(RelayEnd):
    """Common machinery: a script of replies, a durable-ish inbox, and optional fault seams."""

    def __init__(self, role: str, *, replies: Sequence = (), kind: str = "fake",
                 identity: str = "", can_mutate_repo: bool = False,
                 supports_resume: bool = True, fail_after_send: int = -1,
                 fail_on_receive: int = -1, on_send: Callable | None = None,
                 probe_state: str = PROBE_OK, probe_detail: str = "scripted probe",
                 clock=time.time):
        self._role = role
        self._replies = list(replies)
        self._identity = identity or ("conv-fake-1" if role == ROLE_ORCHESTRATOR
                                      else "ses-fake-1")
        self._clock = clock
        self._sent: list = []
        self._turn = 0
        self._fail_after_send = int(fail_after_send)
        self._fail_on_receive = int(fail_on_receive)
        self._on_send = on_send
        self._probe_state = str(probe_state)
        self._probe_detail = str(probe_detail)
        self._probes = 0
        self._sends = 0
        self._receives = 0
        self._direction = FROM_ORCHESTRATOR if role == ROLE_ORCHESTRATOR else FROM_EXECUTION
        self.facts = EndFacts(
            kind=kind, role=role, provider_family="test", model="scripted",
            can_send=True, can_receive=True, can_observe=True,
            can_mutate_repo=bool(can_mutate_repo),
            manages_lifecycle=False,
            supports_session_resume=bool(supports_resume and role == ROLE_EXECUTION),
            supports_conversation_resume=bool(supports_resume and role == ROLE_ORCHESTRATOR),
            proves_message_identity=True,
            proves_workspace_identity=False, proves_capability_surface=False,
            proves_readonly_behavior=False, proves_confinement=False,
            limits=("scripted endpoint: proves kernel mechanics only, never product behaviour",))

    # -- inspection used by controls ----------------------------------------------------------
    @property
    def sent(self) -> list:
        """Every (message_id, text) this endpoint ACCEPTED. The duplicate-delivery oracle."""
        return list(self._sent)

    def open(self) -> EndStatus:
        return EndStatus(END_IDLE, self._identity, "scripted endpoint attached")

    def status(self) -> EndStatus:
        return EndStatus(END_IDLE, self._identity, "scripted endpoint")

    def probe(self) -> EndProbe:
        """Scripted. ``probe_state`` lets a control drive a healthy endpoint whose MODEL is not,
        which is the whole distinction this seam exists to make."""
        self._probes += 1
        return EndProbe(self._probe_state, self._probe_detail, 0.01, "scripted")

    def identity(self) -> str:
        return self._identity

    def resume(self, identity: str) -> tuple:
        supported = (self.facts.supports_session_resume
                     or self.facts.supports_conversation_resume)
        if not supported:
            return RESUME_UNSUPPORTED, ("this scripted endpoint was configured without resume "
                                        "support; continuity is not claimed")
        self._identity = str(identity or self._identity)
        return RESUME_RESUMED, "scripted endpoint re-bound to %s" % self._identity

    def holds(self, message_id: str) -> bool:
        """Does this endpoint already have the relay-assigned id? The reconciliation question."""
        return any(mid == message_id for mid, _ in self._sent)

    def send(self, text: str, *, message_id: str) -> SendReceipt:
        self._sends += 1
        if self._on_send is not None:
            self._on_send(self, text, message_id)
        # ACCEPT FIRST, THEN FAIL. The order is the whole point of this seam: the message really
        # did land, and the relay really did not learn that it landed.
        self._sent.append((message_id, text))
        if self._fail_after_send >= 0 and self._sends >= self._fail_after_send:
            raise ConnectionError("fake endpoint lost the connection after accepting %s"
                                  % message_id)
        return SendReceipt(True, native_id=message_id)

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0):
        self._receives += 1
        if self._fail_on_receive >= 0 and self._receives >= self._fail_on_receive:
            raise ConnectionError("fake endpoint lost the connection while receiving")
        if self._turn >= len(self._replies):
            raise ScriptExhausted("scripted endpoint %s has no reply %d"
                                  % (self._identity, self._turn))
        item = self._replies[self._turn]
        self._turn += 1
        if callable(item):
            item = item(self._turn, list(self._sent))
        text = str(item)
        return RelayMessage(
            message_id="%s:m%d" % (self._identity, self._turn),
            direction=self._direction, text=text, complete=True,
            observed_at=float(self._clock()),
            conversation_id=self._identity if self._role == ROLE_ORCHESTRATOR else "",
            session_id=self._identity if self._role == ROLE_EXECUTION else "",
            provenance={"kind": self.facts.kind, "provider_family": "test",
                        "model": "scripted"})


class FakeOrchestratorEnd(_FakeEnd):
    def __init__(self, **kw):
        super().__init__(ROLE_ORCHESTRATOR, **kw)


class FakeExecutionEnd(_FakeEnd):
    def __init__(self, **kw):
        kw.setdefault("can_mutate_repo", True)
        super().__init__(ROLE_EXECUTION, **kw)


class DeadEnd(RelayEnd):
    """An endpoint that cannot be reached at all. Proves the named-failure path."""

    def __init__(self, role: str, reason: str = "nothing is listening"):
        self._reason = reason
        self.facts = EndFacts(kind="dead", role=role, provider_family="test",
                              limits=("unreachable by construction",))

    def open(self) -> EndStatus:
        return EndStatus(END_FAILED, "", self._reason)

    def status(self) -> EndStatus:
        return EndStatus(END_FAILED, "", self._reason)

    def identity(self) -> str:
        return ""

    def resume(self, identity: str) -> tuple:
        return RESUME_UNSUPPORTED, self._reason

    def send(self, text: str, *, message_id: str) -> SendReceipt:
        return SendReceipt(False, reason=self._reason)

    def receive(self, *, after_id: str = "", timeout_s: float = 0.0):
        return None

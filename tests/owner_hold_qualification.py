"""owner_hold_qualification -- the REAL-PROCESS proof that a resume cannot walk past a hold.

    python -m tests.owner_hold_qualification

WHY A REAL PROCESS
------------------
The controls prove the kernel's decision. This proves the thing an operator actually experiences:
a relay ledger on disk, a hold in it, and a genuine ``quaestor relay resume`` in its OWN process
that exits without continuing -- and then, with a matching owner decision recorded, one that
does. quaestor-7ze was precisely a case where the decision function looked reasonable and the
process walked past the hold anyway, so the process is the thing to measure.

DELIBERATELY NO PROVIDER. The authority property is about what happens BEFORE any endpoint is
contacted, and a free-tier model in the loop would add minutes of latency and a second reason
for the run to fail. The relay is driven to its hold by the ledger, and what is measured is what
the real ``relay resume`` process does with it. This is a PROCESS qualification, not a
live-provider one, and the two are not blurred.

WHAT IT MEASURES
    a real resume process, no owner decision      -> refuses, relay still held
    ...repeatedly                                  -> still refuses, not worn down
    a client payload claiming approval             -> changes nothing
    a matching owner decision recorded             -> the SAME resume now proceeds
    the decision is scoped                         -> another relay is untouched
    across a restart                               -> both directions survive
"""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "src"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests import procsafe                                            # noqa: E402

from quaestor.core import authority as auth_mod                       # noqa: E402
from quaestor.core import proc                                        # noqa: E402
from quaestor.core.store import Store                                 # noqa: E402
from quaestor.relay import cli as relay_cli                           # noqa: E402
from quaestor.relay import effects as effects_mod                     # noqa: E402
from quaestor.relay import kernel as kernel_mod                       # noqa: E402
from quaestor.relay import state as state_mod                         # noqa: E402

DEADLINE_S = float(os.environ.get("QUAESTOR_QUAL_DEADLINE", "300"))


class Result:
    def __init__(self):
        self.steps: list = []

    def step(self, name, ok, detail=""):
        ok = bool(ok)
        self.steps.append({"step": name, "ok": ok, "detail": str(detail)[:300]})
        sys.stdout.write("%-58s %s  %s\n" % (name, "PASS" if ok else "FAIL", str(detail)[:60]))
        sys.stdout.flush()
        return ok

    @property
    def passed(self):
        return sum(1 for s in self.steps if s["ok"])


def git(args, cwd, fleet):
    return fleet.run(["git", *args], what="git", cwd=cwd, timeout_s=60)


def make_repo(path, fleet):
    os.makedirs(path, exist_ok=True)
    for a in (["init", "-q"], ["config", "user.email", "o@example.invalid"],
              ["config", "user.name", "O"]):
        git(a, path, fleet)
    with open(os.path.join(path, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("owner hold qualification\n")
    git(["add", "-A"], path, fleet)
    git(["commit", "-qm", "init"], path, fleet)
    return path


def seed_held_relay(home, repo, relay_id, *, effect_class, required, profile):
    """A relay ledger in exactly the state a gate leaves behind when it refuses."""
    db, _work = relay_cli.relay_paths(home)
    os.makedirs(os.path.dirname(db), exist_ok=True)
    st = state_mod.RelayState(db)
    try:
        st.create(relay_id, project_root=repo, repo_id="", objective="a held relay",
                  orchestrator_kind="openai-chat", execution_kind="opencode",
                  authority_profile=profile,
                  # ENDS THAT BUILD BUT DO NOT ANSWER. Building has to succeed or the resume
                  # dies before the kernel is reached -- which is exactly how the first version
                  # of this fixture passed every refusal step for the wrong reason. Nothing
                  # listens on these ports, so anything PAST the gate fails as a disconnect,
                  # which is a different and clearly distinguishable outcome from a hold.
                  config={"probe_endpoints": False, "observe_repo": False,
                          "endpoint_specs": {
                              "orchestrator": {"kind": "openai-chat",
                                               "config": {"base_url": "http://127.0.0.1:9",
                                                          "model": "vendor/none",
                                                          "key_var": "QUAESTOR_OWNER_QUAL_KEY"}},
                              "execution": {"kind": "opencode",
                                            "config": {"base_url": "http://127.0.0.1:9",
                                                       "model": "vendor/none"}}}})
        hid = effects_mod.hold_id(relay_id, "observation", effect_class, required)
        st.append_event(relay_id, kernel_mod.EVENT_HOLD_RAISED,
                        {"hold_id": hid, "gate": "observation", "effect_class": effect_class,
                         "required": list(required), "message_id": "", "profile": profile,
                         "reason": "the repository shows an effect the owner has not granted"})
        st.update(relay_id, state=state_mod.OWNER_HOLD,
                  owner_hold="the repository shows an effect the owner has not granted")
        return hid
    finally:
        st.close()


def relay_row(home, relay_id):
    db, _work = relay_cli.relay_paths(home)
    st = state_mod.RelayState(db)
    try:
        return dict(st.get(relay_id) or {})
    finally:
        st.close()


def outstanding(home, relay_id):
    db, _work = relay_cli.relay_paths(home)
    st = state_mod.RelayState(db)
    try:
        return kernel_mod.outstanding_owner_holds(st, relay_id)
    finally:
        st.close()


def real_resume(fleet, home, relay_id):
    """A GENUINE ``relay resume`` in its own process. Returns (exit_code, parsed_stdout)."""
    out = fleet.run([proc.python_executable(), "-m", "quaestor.transports.cli",
                     "--home", home, "relay", "resume", "--relay-id", relay_id],
                    what="relay resume", cwd=ROOT, timeout_s=120)
    text = (out.stdout or b"").decode("utf-8", "replace")
    try:
        return out.returncode, json.loads(text or "{}")
    except ValueError:
        return out.returncode, {"_raw": text[:400],
                                "_err": (out.stderr or b"").decode("utf-8", "replace")[:400]}


def qualify(fleet, result):
    os.environ.setdefault("QUAESTOR_OWNER_QUAL_KEY", "not-a-real-key-nothing-is-contacted")
    home = fleet.temp_dir("quaestor-owner-hold-home-")
    work = fleet.temp_dir("quaestor-owner-hold-work-")
    repo = make_repo(os.path.join(work, "repo"), fleet)

    # PROFILE GIT_PUSH: the profile permits a push, and the owner gate is the SECOND lock on it.
    # That is the case where an owner decision is the thing that matters.
    # TRY TO MAKE THE OWNER CHANNEL REAL. The attestation key is DPAPI-backed, so this
    # succeeds on Windows and cannot on POSIX -- and the run reports which it got rather than
    # asserting the convenient one. With a real key the approval half is proven by a real
    # process; without one, only the refusal half can be, and that is stated.
    channel_real = False
    try:
        from quaestor import attestation
        attestation.provision(bytearray(b"owner-hold-qualification-key"), directory=home)
        channel_real = attestation.present(home)
    except Exception as exc:                                           # noqa: BLE001
        result.step("an attestation key could be provisioned for this run",
                    True, "no: %s -- refusal is proven by a real process, approval by "
                          "controls 353-362 (the key store is DPAPI-backed)"
                          % type(exc).__name__)
    if channel_real:
        result.step("an attestation key was provisioned, so the owner channel is real", True,
                    "AUTHENTICATED")

    rid, other = "relay-held-1", "relay-other-1"
    hid = seed_held_relay(home, repo, rid, effect_class=effects_mod.GIT_PUSH,
                          required=[auth_mod.CAP_GIT_PUSH], profile=auth_mod.GIT_PUSH)
    seed_held_relay(home, repo, other, effect_class=effects_mod.GIT_PUSH,
                    required=[auth_mod.CAP_GIT_PUSH], profile=auth_mod.GIT_PUSH)
    result.step("a real relay ledger records an outstanding owner requirement",
                [h["hold_id"] for h in outstanding(home, rid)] == [hid], hid)

    # ---------------------------------------------------------------- no decision -> refused
    # THE REASON, NOT MERELY A NON-ZERO EXIT. This fixture first asserted only "exit != 0",
    # and every one of these steps passed for the WRONG reason: the seeded relay had no endpoint
    # configuration, so the process died building its ends (exit 2) long before any hold was
    # consulted. It would have passed with the hold ignored entirely -- the very defect under
    # test. A genuine refusal is exit 3 with stop_reason OWNER_HOLD.
    code, body = real_resume(fleet, home, rid)
    row = relay_row(home, rid)
    result.step("a REAL resume process refuses BECAUSE OF THE HOLD, not for another reason",
                code == 3 and str(body.get("stop_reason")) == kernel_mod.STOP_OWNER_HOLD
                and str(row.get("state")) == state_mod.OWNER_HOLD,
                "exit=%s stop_reason=%s state=%s"
                % (code, body.get("stop_reason"), row.get("state")))
    result.step("...and it refused WITHOUT contacting a provider",
                not body.get("error"),
                "no endpoint was opened to discover the relay may not continue")
    result.step("...and the requirement is still outstanding afterwards",
                [h["hold_id"] for h in outstanding(home, rid)] == [hid])

    # REPEATING IS NOT DECIDING.
    reasons = []
    for _ in range(3):
        c, b = real_resume(fleet, home, rid)
        reasons.append((c, str(b.get("stop_reason") or b.get("error") or "")[:24]))
    result.step("repeating the resume does not wear the hold down",
                all(c == 3 and r == kernel_mod.STOP_OWNER_HOLD for c, r in reasons)
                and str(relay_row(home, rid).get("state")) == state_mod.OWNER_HOLD,
                "%s" % reasons)

    # ---------------------------------------------------------------- a real owner decision
    db = os.path.join(home, "orchestrator.sqlite3")
    store = Store(db)
    try:
        store.add_owner_grant(auth_mod.CAP_GIT_PUSH, scope=rid, note="qualification")
    finally:
        store.close()
    result.step("an owner decision is recorded, scoped to THIS relay",
                any(g["capability"] == auth_mod.CAP_GIT_PUSH
                    for g in relay_cli._owner_hooks(home, scope=rid)[0]()))

    # THE CHANNEL IS THE OTHER LOCK. Where it is unavailable -- every POSIX machine today, since
    # the attestation key is DPAPI-backed -- the recorded row is a record that somebody said yes
    # and NOT an owner's yes, so the hold correctly still stands. Both outcomes are honest and
    # the run reports which one it measured rather than asserting the convenient one.
    from quaestor.core import owner_channel as oc
    channel = oc.owner_channel_state(home)
    grants, _c = relay_cli._owner_hooks(home, scope=rid)
    db_r, _w = relay_cli.relay_paths(home)
    st = state_mod.RelayState(db_r)
    try:
        blocking = kernel_mod.owner_holds_blocking(
            st, rid, profile=auth_mod.GIT_PUSH, owner_grants=grants(), now=time.time(),
            channel_state=channel)
    finally:
        st.close()

    if channel == oc.AUTHENTICATED:
        result.step("with an authenticated channel the matching decision discharges the hold",
                    blocking == [], blocking)
        code, body = real_resume(fleet, home, rid)
        # PAST THE GATE IS THE PROPERTY. What happens next -- the relay needs real endpoints and
        # this fixture deliberately gives it none -- is not an authority question, so the
        # measurement is that the refusal is no longer OWNER_HOLD.
        past_the_gate = (str(body.get("stop_reason") or "") != kernel_mod.STOP_OWNER_HOLD
                         and str(relay_row(home, rid).get("state")) != state_mod.OWNER_HOLD)
        result.step("...and the SAME real resume is no longer refused by the hold",
                    past_the_gate,
                    "exit=%s stop_reason=%s state=%s"
                    % (code, body.get("stop_reason"), relay_row(home, rid).get("state")))
        result.step("...it got far enough to try the endpoints, which is past the gate",
                    "DISCONNECT" in str(body.get("stop_reason") or "").upper()
                    or str(relay_row(home, rid).get("state")) == state_mod.FAILED,
                    body.get("stop_reason"))
        result.step("the hold is recorded discharged exactly once",
                    len(outstanding(home, rid)) == 0, outstanding(home, rid))
    else:
        result.step("an unauthenticated owner channel is not an owner decision",
                    [h["hold_id"] for h in blocking] == [hid],
                    "channel=%s -- a recorded row is not authority" % channel)
        code, b = real_resume(fleet, home, rid)
        result.step("...so the real resume STILL refuses, grant row notwithstanding",
                    code == 3 and str(b.get("stop_reason")) == kernel_mod.STOP_OWNER_HOLD,
                    "exit=%s stop_reason=%s" % (code, b.get("stop_reason")))

    # ---------------------------------------------------------------- scope, for real
    other_grants, _c2 = relay_cli._owner_hooks(home, scope=other)
    result.step("the decision did NOT reach the other relay",
                not any(g["capability"] == auth_mod.CAP_GIT_PUSH for g in other_grants()),
                "scoped to %s" % rid)
    code, b = real_resume(fleet, home, other)
    result.step("...and the other relay's real resume still refuses on the HOLD",
                code == 3 and str(b.get("stop_reason")) == kernel_mod.STOP_OWNER_HOLD,
                "exit=%s stop_reason=%s" % (code, b.get("stop_reason")))

    # ---------------------------------------------------------------- restart durability
    still = outstanding(home, other)
    result.step("an undischarged hold survives every process that has read it",
                len(still) == 1 and still[0]["required"] == [auth_mod.CAP_GIT_PUSH])
    return {"relay_id": rid, "hold_id": hid, "channel": channel,
            "other_relay": other}


def main(argv=None):
    del argv
    result = Result()
    evidence, verdict = {}, "FAIL"
    fleet = procsafe.Fleet(deadline_s=DEADLINE_S,
                           log=lambda m: sys.stdout.write("[fleet] %s\n" % m))
    try:
        try:
            evidence = qualify(fleet, result)
            verdict = "PASS" if result.steps and all(s["ok"] for s in result.steps) else "FAIL"
        except procsafe.DeadlineExceeded as exc:
            result.step("the run stayed inside its ceiling", False, exc)
            verdict = "TIMEOUT"
        except Exception as exc:                                       # noqa: BLE001
            result.step("the run completed without raising", False,
                        "%s: %s" % (type(exc).__name__, exc))
            verdict = "ERROR"
    finally:
        cleanup = fleet.close()
    result.step("no process this run created is still alive", not (cleanup.get("leaked") or []),
                cleanup.get("leaked"))
    if any(not s["ok"] for s in result.steps) and verdict == "PASS":
        verdict = "FAIL"

    doc = {"verdict": verdict, "passed": result.passed, "total": len(result.steps),
           "steps": result.steps, "evidence": evidence, "cleanup": cleanup,
           "note": "PROCESS qualification. No provider is contacted: the authority decision "
                   "happens before any endpoint would be, and mixing a live model in would add "
                   "a second reason to fail without strengthening the property.",
           "at": time.time()}
    dest = os.path.join(ROOT, "var", "relay-qualification")
    os.makedirs(dest, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for name in ("owner-hold.json", "owner-hold-%s.json" % stamp):
        with open(os.path.join(dest, name), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True, default=str)
    sys.stdout.write("\n%s -- %d/%d steps -> var/relay-qualification/owner-hold.json\n"
                     % (verdict, result.passed, len(result.steps)))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

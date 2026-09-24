"""P2.5 NEGATIVE CONTROLS -- the 34-entry confinement and hardening matrix.

TWO KINDS OF CONTROL HERE, AND THE DIFFERENCE MATTERS
------------------------------------------------------
  * POLICY controls (31-40, 49-64) run against pure functions and disposable fixtures. They are
    fast, deterministic, and spend no Docker or Claude capacity.
  * BEHAVIOURAL controls (41-48) assert against EXECUTED EVIDENCE captured from a real run:
    `tests/fixtures/p25_confinement_evidence.json` holds the deterministic preflight's 24 checks
    and the real Claude child's 15, verbatim. Re-running a container per test would make the
    suite something nobody runs, and re-deriving the evidence from our own expectations would be
    the consumes-its-own-output defect. So the recorded bytes are the input.

If the evidence fixture is absent the behavioural controls SKIP locally and FAIL under CI -- an
absent instrument is not a clean reading, and a suite that silently drops eight security controls
is exactly the VACUOUS case the gate exists to catch.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import authority
from quaestor.core import cancellation
from quaestor.core import concurrency
from quaestor.sandbox import profile as cp  # noqa: E402
from quaestor.sandbox import confinement
from quaestor.sandbox import docker as da
from quaestor.evidence import fingerprints as fp  # noqa: E402
from quaestor.evidence import floors
from quaestor.core import owner_channel
from quaestor.executors import claude_auth as pf
from quaestor.core import retention  # noqa: E402
from quaestor.evidence import test_collector as tc  # noqa: E402
from quaestor.core.canon import canonical_path  # noqa: E402
from quaestor.executors.claude_code import UnsafeCommand, build_command  # noqa: E402
from quaestor.core.executor_contract import ExecRequest  # noqa: E402
from quaestor.core.identity import RunBinding  # noqa: E402
from quaestor.core import handoff as handoff_mod  # noqa: E402
from tests import support  # noqa: E402
from tests.controls import control  # noqa: E402

EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                        "p25_confinement_evidence.json")

# The platform checkout, derived from this file rather than named. A constant naming
# one machine makes the control true only on that machine.
ORCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
# A synthetic PROTECTED ROOT. It replaces an absolute path to one operator's private
# repository: the platform must be testable on any machine by any user, and a control
# keyed to a directory that exists on exactly one laptop tests that laptop.
PROTECTED_ROOT = os.path.join(tempfile.gettempdir(), "quaestor-protected-root")
os.makedirs(PROTECTED_ROOT, exist_ok=True)
# FIXTURE HOST PATHS ARE PLATFORM-CONDITIONAL, AND MUST BE. The fixtures name absolute host
# paths OUTSIDE every forbidden root (the checkout, the protected root): a bind of one is
# permitted, an unknown RW bind of one is refused for being unknown -- not for accidentally
# resolving INTO the checkout. A POSIX shell resolves a `C:/...` spelling as a RELATIVE path,
# which under `canonical_path` lands inside the checkout and tests the wrong refusal entirely.
if sys.platform == "win32":
    FIXTURE_RW = "C:/quaestor-p25/p2-5-fixture-rw"
    FIXTURE_RO = "C:/quaestor-p25/p2-5-fixture-ro"
    FOREIGN_RO = "D:/somewhere/else"
else:
    # /opt, and NOT the tempdir: default_forbidden_paths forbids the PARENT of PROTECTED_ROOT,
    # and on POSIX that parent is /tmp itself -- a fixture under the tempdir is refused for
    # matching /tmp, which is the policy being right and the fixture being lazy. /opt is
    # outside every derived forbidden root on POSIX (home, /etc, /usr, /bin, /sbin, /boot,
    # /sys, /proc, the checkout, the protected root and its parent). These paths are never
    # created: the policy controls are pure profile validation.
    FIXTURE_RW = "/opt/quaestor-p25/p2-5-fixture-rw"
    FIXTURE_RO = "/opt/quaestor-p25/p2-5-fixture-ro"
    FOREIGN_RO = "/opt/somewhere-else/quaestor-p25"


def base_profile(**over):
    kw = dict(
        profile_id="test", image_ref=support.test_image("p25"), image_digest="sha256:" + "a" * 64,
        user="1001:1001", workdir="/workspace",
        mounts=(cp.Mount(canonical_path(FIXTURE_RW), "/workspace", cp.RW, cp.BIND),
                cp.Mount(canonical_path(FIXTURE_RO), "/evidence-readonly",
                         cp.RO, cp.BIND)),
        network="bridge", cap_drop=("ALL",), cap_add=(), privileged=False,
        pid_mode="", ipc_mode="", read_only_rootfs=True,
        security_opt=("no-new-privileges",))
    kw.update(over)
    return cp.ContainerProfile(**kw)


def validate(profile):
    return cp.validate_profile(profile,
                               forbidden_host_paths=cp.default_forbidden_paths(ORCH, PROTECTED_ROOT),
                               expected_rw_hosts=[FIXTURE_RW])


# =============================================================================================
# 31, 32 -- engine availability and the no-native-fallback rule
# =============================================================================================
class TestEngineAndConfinementRequirement(unittest.TestCase):
    @control(31)
    def test_an_unusable_engine_is_blocked_not_downgraded(self):
        for state in (da.ENGINE_UNAVAILABLE, da.ENGINE_WRONG_TYPE):
            st = da.EngineStatus(state, os_type="windows", error="simulated")
            self.assertFalse(st.usable, state)

    @control(31)
    def test_a_windows_container_engine_is_wrong_type(self):
        """Linux containers are required; a Windows engine must not silently proceed."""
        st = da.EngineStatus(da.ENGINE_WRONG_TYPE, os_type="windows")
        self.assertFalse(st.usable)

    def test_a_linux_engine_is_usable(self):
        """Control on the control."""
        self.assertTrue(da.EngineStatus(da.ENGINE_OK, os_type="linux").usable)

    @control(32)
    def test_confined_profile_refuses_to_run_unconfined(self):
        req = ExecRequest(run_id="r", run_dir="/t", cwd="/workspace", prompt="P",
                          binding=RunBinding("r", "w", "s", "n"),
                          json_schema=handoff_mod.HANDOFF_JSON_SCHEMA,
                          authority_profile=authority.STANDARD_EDIT_CONFINED,
                          stdout_path="/t/o", stderr_path="/t/e")
        with self.assertRaises(UnsafeCommand) as ctx:
            build_command(req)
        self.assertIn("container confinement", str(ctx.exception))

    @control(32)
    def test_confined_profile_builds_only_when_confinement_is_declared(self):
        req = ExecRequest(run_id="r", run_dir="/t", cwd="/workspace", prompt="P",
                          binding=RunBinding("r", "w", "s", "n"),
                          json_schema=handoff_mod.HANDOFF_JSON_SCHEMA,
                          authority_profile=authority.STANDARD_EDIT_CONFINED,
                          stdout_path="/t/o", stderr_path="/t/e", container_confined=True)
        cmd = build_command(req)
        self.assertEqual(cmd[-1], "P")
        self.assertNotIn("--dangerously-skip-permissions", cmd)


# =============================================================================================
# 33-40, 49 -- container policy refusals
# =============================================================================================
class TestContainerPolicy(unittest.TestCase):
    def test_the_reference_profile_is_permitted(self):
        """Control on the control: a policy that refuses everything proves nothing."""
        v = validate(base_profile())
        self.assertTrue(v.ok, v.reasons)

    @control(33)
    def test_privileged_is_refused(self):
        v = validate(base_profile(privileged=True))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("privileged" in r for r in v.reasons))

    @control(34)
    def test_host_pid_namespace_is_refused(self):
        self.assertTrue(any("PID" in r for r in validate(base_profile(pid_mode="host")).reasons))

    @control(34)
    def test_host_ipc_namespace_is_refused(self):
        self.assertTrue(any("IPC" in r for r in validate(base_profile(ipc_mode="host")).reasons))

    @control(35)
    def test_host_network_is_refused(self):
        v = validate(base_profile(network="host"))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("host networking" in r for r in v.reasons))

    @control(36)
    def test_a_mounted_docker_socket_is_refused(self):
        for sock in ("/var/run/docker.sock", "//./pipe/docker_engine"):
            p = base_profile(mounts=(cp.Mount(sock, "/var/run/docker.sock", cp.RO, cp.BIND),))
            v = validate(p)
            self.assertEqual(v.verdict, cp.POLICY_REFUSED, sock)
            self.assertFalse(v.checks["docker_socket_absent"], sock)

    @control(37)
    def test_a_user_profile_bind_is_refused(self):
        home = os.path.expanduser("~").replace("\\", "/")
        for path in (home, "C:/Users", home + "/.ssh", home + "/.aws", home + "/.claude"):
            v = validate(base_profile(mounts=(cp.Mount(path, "/mnt/x", cp.RO, cp.BIND),)))
            self.assertEqual(v.verdict, cp.POLICY_REFUSED, path)

    @control(38)
    def test_project_primary_mounted_rw_is_refused(self):
        v = validate(base_profile(mounts=(cp.Mount(PROTECTED_ROOT, "/workspace", cp.RW, cp.BIND),)))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)

    @control(38)
    def test_project_primary_mounted_readonly_is_also_refused(self):
        """RO is not a safe exposure for the governed repository in P2.5."""
        v = validate(base_profile(mounts=(cp.Mount(PROTECTED_ROOT, "/mnt-probe", cp.RO, cp.BIND),)))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)

    @control(39)
    def test_orchestrator_source_mounted_rw_is_refused(self):
        v = validate(base_profile(mounts=(cp.Mount(ORCH, "/workspace", cp.RW, cp.BIND),)))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)

    @control(39)
    def test_orchestrator_source_mounted_readonly_is_also_refused(self):
        v = validate(base_profile(mounts=(cp.Mount(ORCH, "/cp", cp.RO, cp.BIND),)))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)

    @control(40)
    def test_an_unknown_read_write_bind_is_refused(self):
        v = validate(base_profile(mounts=(
            cp.Mount(canonical_path(FIXTURE_RW), "/workspace", cp.RW, cp.BIND),
            cp.Mount(FOREIGN_RO, "/extra", cp.RW, cp.BIND))))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("UNKNOWN read-write bind" in r for r in v.reasons))

    def test_an_unknown_read_only_bind_is_permitted(self):
        """Control on the control: the allowlist governs WRITE surfaces, not visibility."""
        v = validate(base_profile(mounts=(
            cp.Mount(canonical_path(FIXTURE_RW), "/workspace", cp.RW, cp.BIND),
            cp.Mount(FOREIGN_RO, "/extra", cp.RO, cp.BIND))))
        self.assertTrue(v.ok, v.reasons)

    def test_an_unpinned_image_is_refused(self):
        v = validate(base_profile(image_digest=""))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("digest" in r for r in v.reasons))

    def test_root_user_and_added_capabilities_are_refused(self):
        self.assertEqual(validate(base_profile(user="0:0")).verdict, cp.POLICY_REFUSED)
        self.assertEqual(validate(base_profile(cap_add=("SYS_ADMIN",))).verdict, cp.POLICY_REFUSED)
        self.assertEqual(validate(base_profile(cap_drop=())).verdict, cp.POLICY_REFUSED)

    def test_path_containment_respects_separator_boundaries(self):
        """A sibling directory must not read as 'inside' its neighbour."""
        self.assertTrue(cp.path_is_within("C:/repo/sub", "C:/repo"))
        self.assertTrue(cp.path_is_within("C:/repo", "C:/repo"))
        self.assertFalse(cp.path_is_within("C:/repo-other", "C:/repo"))

    @control(49)
    def test_a_duplicate_conflicting_container_target_is_refused(self):
        v = validate(base_profile(mounts=(
            cp.Mount(canonical_path(FIXTURE_RW), "/workspace", cp.RW, cp.BIND),
            cp.Mount("D:/other", "/workspace", cp.RO, cp.BIND))))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("duplicate container target" in r for r in v.reasons))


# =============================================================================================
# 62, 49 -- the ENGINE's report vs the profile
# =============================================================================================
class TestActualContainerState(unittest.TestCase):
    def _inspect(self, **over):
        doc = {
            "Image": "sha256:" + "a" * 64,
            "Config": {"User": "1001:1001"},
            "HostConfig": {"Privileged": False, "PidMode": "", "IpcMode": "",
                           "NetworkMode": "bridge", "CapDrop": ["ALL"], "CapAdd": [],
                           "ReadonlyRootfs": True},
            "Mounts": [
                {"Type": "bind", "Source": FIXTURE_RW, "Destination": "/workspace", "RW": True},
                {"Type": "bind", "Source": FIXTURE_RO,
                 "Destination": "/evidence-readonly", "RW": False},
            ],
        }
        for k, v in over.items():
            if k in ("Config", "HostConfig"):
                doc[k].update(v)
            else:
                doc[k] = v
        return doc

    def _actual(self, doc, profile=None):
        return cp.validate_actual(profile or base_profile(), doc,
                                  forbidden_host_paths=cp.default_forbidden_paths(ORCH, PROTECTED_ROOT),
                                  expected_rw_hosts=[FIXTURE_RW])

    def test_a_matching_container_is_accepted(self):
        """Control on the control."""
        v = self._actual(self._inspect())
        self.assertTrue(v.ok, v.reasons)

    @control(62)
    def test_an_extra_actual_rw_mount_is_a_security_boundary_fail(self):
        doc = self._inspect()
        doc["Mounts"].append({"Type": "bind", "Source": "C:/Users/testuser",
                              "Destination": "/secret", "RW": True})
        v = self._actual(doc)
        self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL)
        self.assertFalse(v.checks["mount_set_matches_profile"])

    @control(62)
    def test_actual_privileged_or_host_namespace_is_a_security_boundary_fail(self):
        for over in ({"Privileged": True}, {"PidMode": "host"}, {"NetworkMode": "host"},
                     {"CapDrop": []}, {"CapAdd": ["SYS_ADMIN"]}, {"ReadonlyRootfs": False}):
            v = self._actual(self._inspect(HostConfig=over))
            self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL, over)

    @control(62)
    def test_an_actual_docker_socket_mount_is_a_security_boundary_fail(self):
        doc = self._inspect()
        doc["Mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock",
                              "Destination": "/var/run/docker.sock", "RW": True})
        v = self._actual(doc)
        self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL)
        self.assertFalse(v.checks["docker_socket_absent"])

    @control(62)
    def test_a_different_actual_image_is_a_security_boundary_fail(self):
        v = self._actual(self._inspect(Image="sha256:" + "b" * 64))
        self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL)

    @control(49)
    def test_a_wrong_host_to_container_mapping_is_refused(self):
        doc = self._inspect()
        doc["Mounts"][0] = {"Type": "bind", "Source": "C:/some/other/dir",
                            "Destination": "/workspace", "RW": True}
        v = self._actual(doc)
        self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL)

    @control(49)
    def test_a_readonly_mount_silently_promoted_to_rw_is_refused(self):
        doc = self._inspect()
        doc["Mounts"][1]["RW"] = True
        v = self._actual(doc)
        self.assertEqual(v.verdict, cp.SECURITY_BOUNDARY_FAIL)


# =============================================================================================
# 50, 63, 64 -- confinement evaluation refusals
# =============================================================================================
class TestConfinementEvaluation(unittest.TestCase):
    def _probe(self, **over):
        p = {
            "identity": {"uid": 1001, "gid": 1001, "cap_eff": "0000000000000000"},
            "pid_namespace": {"ok": True, "value": "python3"},
            "workspace_read": {"ok": True, "value": "CHAL"},
            "workspace_write": {"ok": True, "value": "x"},
            "readonly_read": {"ok": True, "value": "SENT"},
            "readonly_overwrite": {"ok": False, "error": "EROFS"},
            "readonly_create": {"ok": False, "error": "EROFS"},
            "readonly_unlink": {"ok": False, "error": "EROFS"},
            "host_escape_candidates": {c: {"exists": False} for c in
                                       confinement.HOST_ESCAPE_CANDIDATES},
            "traversal": {},
            "symlink_escape": {"write_through_link_to_readonly": {"ok": False, "error": "EROFS"},
                               "write_through_link_to_root": {"ok": False, "error": "EROFS"},
                               "write_outside_all_mounts": {"ok": False, "error": "EROFS"},
                               "write_to_home_root": {"ok": False, "error": "EROFS"}},
            "docker_control_plane": {s: {"exists": False} for s in confinement.DOCKER_SOCKETS},
            "forbidden_host_paths": {},
        }
        p["docker_control_plane"]["docker_cli_on_path"] = False
        p.update(over)
        return p

    def _fp(self, digest="d"):
        return fp.make(fp.DIRECTORY_BYTES, [digest], inspected_count=1, inputs="test")

    def _eval(self, probe, *, challenge="CHAL", sentinel="SENT", ro_after=None, forb_after=None):
        ro = self._fp()
        forb = fp.make(fp.FILE_BYTES, ["f"], inspected_count=1, inputs="test")
        return confinement.evaluate(
            probe, expected_challenge=challenge, expected_sentinel=sentinel,
            ro_digest_before=ro, ro_digest_after=ro_after or ro,
            forbidden_digest_before=forb, forbidden_digest_after=forb_after or forb,
            actual_verdict=cp.ProfileVerdict(cp.POLICY_OK))

    def test_a_clean_probe_passes(self):
        """Control on the control."""
        r = self._eval(self._probe())
        self.assertEqual(r.verdict, confinement.PASS, r.failures)
        self.assertGreaterEqual(r.inspected_count, 20)

    @control(50)
    def test_challenge_bytes_that_disagree_fail(self):
        r = self._eval(self._probe(workspace_read={"ok": True, "value": "SOMETHING ELSE"}))
        self.assertEqual(r.verdict, confinement.FAIL)
        self.assertTrue(any("challenge_bytes_match" in f for f in r.failures))

    @control(50)
    def test_a_missing_mount_fails_rather_than_passing_quietly(self):
        r = self._eval(self._probe(workspace_read={"ok": False, "error": "ENOENT"}))
        self.assertEqual(r.verdict, confinement.FAIL)

    @control(63)
    def test_a_changed_forbidden_sentinel_is_a_security_boundary_fail(self):
        other = fp.make(fp.FILE_BYTES, ["CHANGED"], inspected_count=1, inputs="test")
        r = self._eval(self._probe(), forb_after=other)
        self.assertEqual(r.verdict, confinement.FAIL)
        self.assertTrue(any("forbidden_sentinel_unchanged" in f for f in r.failures))

    @control(63)
    def test_changed_readonly_host_bytes_fail_even_if_the_probe_reported_denial(self):
        """The error message is not the evidence; the host-side digest is."""
        other = fp.make(fp.DIRECTORY_BYTES, ["CHANGED"], inspected_count=1, inputs="test")
        r = self._eval(self._probe(), ro_after=other)
        self.assertEqual(r.verdict, confinement.FAIL)
        self.assertTrue(any("readonly_host_bytes_unchanged" in f for f in r.failures))

    @control(64)
    def test_a_succeeded_forbidden_write_fails_the_boundary(self):
        for key in ("readonly_overwrite", "readonly_create", "readonly_unlink"):
            r = self._eval(self._probe(**{key: {"ok": True, "value": "WROTE"}}))
            self.assertEqual(r.verdict, confinement.FAIL, key)

    @control(64)
    def test_a_reachable_host_path_fails_the_boundary(self):
        esc = {c: {"exists": False} for c in confinement.HOST_ESCAPE_CANDIDATES}
        esc["/mnt/c"] = {"exists": True, "listing": ["Users"]}
        r = self._eval(self._probe(host_escape_candidates=esc))
        self.assertEqual(r.verdict, confinement.FAIL)

    @control(64)
    def test_a_reachable_docker_socket_fails_the_boundary(self):
        dock = {s: {"exists": False} for s in confinement.DOCKER_SOCKETS}
        dock["/var/run/docker.sock"] = {"exists": True, "connect": {"ok": True}}
        dock["docker_cli_on_path"] = False
        r = self._eval(self._probe(docker_control_plane=dock))
        self.assertEqual(r.verdict, confinement.FAIL)

    @control(64)
    def test_an_absent_probe_is_vacuous_not_pass(self):
        r = self._eval({})
        self.assertEqual(r.verdict, confinement.VACUOUS)
        self.assertEqual(r.inspected_count, 0)

    @control(64)
    def test_root_uid_or_retained_capabilities_fail(self):
        r = self._eval(self._probe(identity={"uid": 0, "cap_eff": "0000003fffffffff"}))
        self.assertEqual(r.verdict, confinement.FAIL)
        self.assertTrue(any("non_root_uid" in f for f in r.failures))
        self.assertTrue(any("all_capabilities_dropped" in f for f in r.failures))


# =============================================================================================
# 51 -- credential overrides inside the container
# =============================================================================================
class TestContainerAuthPreflight(unittest.TestCase):
    @control(51)
    def test_every_override_inside_the_container_refuses(self):
        good = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                "subscriptionType": "max"}
        for name in pf.OVERRIDE_VARS:
            d = pf.decide(env={name: "x"}, auth_status=good)
            self.assertEqual(d.decision, pf.REFUSE, name)
            self.assertEqual(d.reason, pf.REASON_OVERRIDE, name)

    @control(51)
    def test_container_console_auth_is_refused(self):
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "console",
                                           "apiProvider": "firstParty"})
        self.assertEqual(d.reason, pf.REASON_API_BILLED)

    def test_container_subscription_auth_is_accepted(self):
        """Control on the control -- and the shape actually observed inside the container."""
        d = pf.decide(env={}, auth_status={"loggedIn": True, "authMethod": "claude.ai",
                                           "apiProvider": "firstParty", "email": None,
                                           "orgId": None, "subscriptionType": "max"})
        self.assertTrue(d.accepted)
        self.assertEqual(d.auth_class, pf.SUBSCRIPTION)


# =============================================================================================
# 52 -- forged owner grants
# =============================================================================================
class TestOwnerChannel(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox()
        self.addCleanup(self.sb.close)

    def test_the_owner_channel_is_unavailable_in_this_phase(self):
        self.assertEqual(owner_channel.owner_channel_state(), owner_channel.UNAVAILABLE)

    @control(52)
    def test_a_forged_sqlite_owner_grant_does_not_unlock_a_capability(self):
        """Forge the row directly in the database, exactly as a compromised writer would."""
        self.sb.store.conn.execute(
            "INSERT INTO owner_grant(grant_id, capability, scope, granted_at, expires_at,"
            " revoked_at, note) VALUES('forged','git_push','*',1.0,NULL,NULL,'forged by test')")
        rows = self.sb.store.owner_grants()
        self.assertTrue(any(r["capability"] == "git_push" for r in rows),
                        "the forged row must really be present, or this proves nothing")

        d = authority.require(authority.GIT_PUSH, ["git_push"], owner_grants=rows, now=100.0)
        self.assertEqual(d.decision, authority.OWNER_REQUIRED)
        self.assertIn("git_push", d.ungranted)
        self.assertIn("not authority", d.reason.lower())
        self.assertIn("UNAVAILABLE", d.reason)

    @control(52)
    def test_every_owner_gated_capability_stays_locked_against_a_forged_grant(self):
        for cap in sorted(authority.OWNER_GATED):
            rows = [{"grant_id": "forged", "capability": cap, "revoked_at": None,
                     "expires_at": None}]
            dec = owner_channel.evaluate(cap, ledger_rows=rows)
            self.assertFalse(dec.usable, cap)
            self.assertEqual(dec.channel_state, owner_channel.UNAVAILABLE)
            self.assertEqual(dec.recorded_claims, ("forged",),
                             "the claim must still be REPORTED even though it is not authority")

    @control(52)
    def test_a_dispatch_requesting_an_owner_gated_capability_is_owner_required(self):
        from quaestor.core import domain
        from quaestor.core.dispatcher import DispatchSpec, dispatch
        self.sb.store.add_owner_grant("git_push", note="recorded claim")
        spec = DispatchSpec(workflow_id="wf", step_id="s1", task="t",
                            worktree_path=self.sb.repo(), authority_profile=authority.GIT_PUSH,
                            required_capabilities=("git_push",),
                            executor={"kind": "fake", "config": {}})
        res = dispatch(self.sb.store, spec, run_root=self.sb.runs,
                       preflight=support.preflight_stub(), spawn=False)
        self.assertEqual(res.state, domain.OWNER_REQUIRED)

    def test_non_owner_gated_capabilities_are_unaffected(self):
        """Control on the control: the tightening must not break ordinary edit runs."""
        d = authority.require(authority.STANDARD_EDIT, ["repo_read", "repo_write"])
        self.assertTrue(d.allowed, d.reason)


# =============================================================================================
# 53 -- fingerprint classes
# =============================================================================================
class TestFingerprintClasses(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox()
        self.addCleanup(self.sb.close)

    @control(53)
    def test_content_change_with_an_unchanged_status_set_is_detected(self):
        """THE P2 DEFECT, reproduced and now caught.

        Modify a tracked file that is ALREADY dirty: the porcelain status set does not move, so
        the STATUS fingerprint is unchanged -- exactly as in P2 -- while TRACKED_CONTENT moves.
        """
        repo = self.sb.repo()
        path = os.path.join(repo, "README.md")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("first modification\n")

        status_before = fp.status_fingerprint(repo)
        content_before = fp.tracked_content_fingerprint(repo)

        with open(path, "a", encoding="utf-8") as fh:
            fh.write("second modification, same dirty path set\n")

        status_after = fp.status_fingerprint(repo)
        content_after = fp.tracked_content_fingerprint(repo)

        self.assertEqual(fp.compare(status_before, status_after), fp.SAME,
                         "the status set should NOT have moved -- that is the whole point")
        self.assertEqual(fp.compare(content_before, content_after), fp.CHANGED,
                         "the CONTENT class must catch what the status class cannot")

    @control(53)
    def test_a_fingerprint_must_declare_its_inputs(self):
        with self.assertRaises(fp.FingerprintRefused):
            fp.Fingerprint(fp.STATUS, "d", 1, "")
        with self.assertRaises(fp.FingerprintRefused):
            fp.Fingerprint("MADE_UP_CLASS", "d", 1, "inputs")

    @control(53)
    def test_different_classes_are_uncomparable_not_equal(self):
        a = fp.make(fp.STATUS, ["x"], inspected_count=1, inputs="status")
        b = fp.make(fp.TRACKED_CONTENT, ["x"], inspected_count=1, inputs="content")
        self.assertEqual(fp.compare(a, b), fp.UNCOMPARABLE)

    @control(53)
    def test_two_failed_measurements_do_not_compare_equal(self):
        a = fp.unavailable(fp.STATUS, inputs="i", error="e1")
        b = fp.unavailable(fp.STATUS, inputs="i", error="e2")
        self.assertEqual(fp.compare(a, b), fp.UNCOMPARABLE)

    @control(53)
    def test_attribution_never_erases_the_mutation(self):
        out = fp.attribute_drift(fp.TRACKED_CONTENT, fp.CHANGED,
                                 foreign_paths=[".beads/issues.jsonl"],
                                 changed_paths=[".beads/issues.jsonl"])
        self.assertEqual(out["verdict"], fp.CHANGED)
        self.assertEqual(out["attribution"], fp.FOREIGN_DRIFT_OBSERVED)
        self.assertEqual(out["changed_paths"], [".beads/issues.jsonl"])

    @control(53)
    def test_an_unattributed_change_is_attributable_to_this_run(self):
        out = fp.attribute_drift(fp.TRACKED_CONTENT, fp.CHANGED,
                                 foreign_paths=[".beads/issues.jsonl"],
                                 changed_paths=[".beads/issues.jsonl", "src/thing.py"])
        self.assertEqual(out["attribution"], fp.P2_5_ATTRIBUTABLE)
        self.assertEqual(out["unattributed_paths"], ["src/thing.py"])

    def test_every_class_declares_a_scope(self):
        for cls in fp.ALL_CLASSES:
            self.assertTrue(fp.CLASS_SCOPE.get(cls), cls)


# =============================================================================================
# 54, 55 -- evidence floor provenance
# =============================================================================================
class TestFloorProvenance(unittest.TestCase):
    def _good(self):
        return floors.revision_tree_floor(tree_entries=7235, excluded_count=839,
                                          source_revision="cba0aa34", derived_at=1.0)

    def test_a_sound_derivation_with_a_sufficient_reading_passes(self):
        """Control on the control."""
        v = floors.adjudicate(self._good(), 6396, expected_revision="cba0aa34")
        self.assertEqual(v.verdict, floors.FLOOR_MET)

    @control(55)
    def test_a_missing_derivation_is_unproven_not_zero(self):
        v = floors.adjudicate(None, 999999)
        self.assertEqual(v.verdict, floors.FLOOR_UNPROVEN)

    @control(54)
    def test_a_child_supplied_floor_is_refused(self):
        v = floors.adjudicate(floors.child_supplied_floor(1), 10)
        self.assertEqual(v.verdict, floors.FLOOR_UNPROVEN)
        self.assertIn("child cannot set the bar", v.reason)

    @control(54)
    def test_a_floor_below_the_absolute_minimum_is_refused(self):
        d = floors.FloorDerivation(0, floors.METHOD_FIXED_MINIMUM, derived_by="bridge")
        self.assertEqual(floors.adjudicate(d, 10).verdict, floors.FLOOR_UNPROVEN)

    @control(54)
    def test_a_derivation_from_another_revision_is_stale(self):
        v = floors.adjudicate(self._good(), 6396, expected_revision="deadbeef")
        self.assertEqual(v.verdict, floors.FLOOR_STALE)

    @control(54)
    def test_an_unknown_derivation_method_is_refused(self):
        d = floors.FloorDerivation(10, "TRUST_ME", derived_by="bridge")
        self.assertEqual(floors.adjudicate(d, 100).verdict, floors.FLOOR_UNPROVEN)

    @control(55)
    def test_zero_inspected_is_vacuous(self):
        self.assertEqual(floors.adjudicate(self._good(), 0,
                                           expected_revision="cba0aa34").verdict, floors.VACUOUS)

    @control(55)
    def test_an_unmeasured_reading_is_unproven(self):
        self.assertEqual(floors.adjudicate(self._good(), None,
                                           expected_revision="cba0aa34").verdict,
                         floors.FLOOR_UNPROVEN)

    @control(54)
    def test_a_reading_below_the_floor_is_not_met(self):
        v = floors.adjudicate(self._good(), 12, expected_revision="cba0aa34")
        self.assertEqual(v.verdict, floors.FLOOR_NOT_MET)

    def test_each_method_requires_its_own_anchor(self):
        """A revision method needs a commit; a workspace method needs a content digest."""
        no_rev = floors.FloorDerivation(10, floors.METHOD_REVISION_TREE, derived_by="bridge")
        self.assertFalse(floors.validate_derivation(no_rev)[0])
        no_dig = floors.FloorDerivation(10, floors.METHOD_CONTAINER_WORKSPACE, derived_by="bridge")
        self.assertFalse(floors.validate_derivation(no_dig)[0])
        ok = floors.workspace_floor(file_count=6, source_digest="abc", derived_at=1.0)
        self.assertTrue(floors.validate_derivation(ok)[0])


# =============================================================================================
# 56, 57, 58 -- the TEST_EXECUTION collector
# =============================================================================================
class TestExecutionCollector(unittest.TestCase):
    def setUp(self):
        self.sb = support.Sandbox()
        self.addCleanup(self.sb.close)

    def _suite(self, name, body):
        d = os.path.join(self.sb.dir, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "test_x.py"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        return d

    def _run(self, cwd, timeout=120.0, floor=1):
        prof = tc.TestProfile("t", (sys.executable, "-m", "unittest", "discover", "-s", ".",
                                    "-p", "test_*.py"), timeout_s=timeout, expected_floor=floor)
        return tc.run_profile(prof, cwd=cwd, run_id="r")

    def test_a_real_passing_suite_measures_pass(self):
        """Control on the control."""
        d = self._suite("pass", "import unittest\nclass T(unittest.TestCase):\n"
                                "    def test_a(self):\n        self.assertTrue(True)\n")
        r = self._run(d)
        self.assertTrue(r.process_executed)
        self.assertEqual(r.test_verdict, tc.PASS, r.reason)
        self.assertEqual(r.discovered, 1)

    @control(56)
    def test_a_real_failing_suite_measures_fail_while_the_process_executed(self):
        d = self._suite("fail", "import unittest\nclass T(unittest.TestCase):\n"
                                "    def test_a(self):\n        self.assertEqual(1, 2)\n")
        r = self._run(d)
        self.assertTrue(r.process_executed, "PROCESS_EXECUTED and TEST_VERDICT are separate")
        self.assertEqual(r.test_verdict, tc.FAIL)
        self.assertEqual(r.failed, 1)

    @control(56)
    def test_a_forged_pass_claim_loses_to_the_collector(self):
        d = self._suite("fail2", "import unittest\nclass T(unittest.TestCase):\n"
                                 "    def test_a(self):\n        raise AssertionError('no')\n")
        r = self._run(d)
        cmp_ = tc.compare_claim("PASS", r)
        self.assertEqual(r.test_verdict, tc.FAIL)
        self.assertFalse(cmp_["agree"])
        self.assertEqual(cmp_["authority"], "independent collector")

    @control(57)
    def test_a_zero_test_suite_is_vacuous(self):
        d = self._suite("empty", "# no tests here at all\n")
        r = self._run(d)
        self.assertEqual(r.test_verdict, tc.VACUOUS)
        self.assertEqual(r.discovered, 0)

    @control(57)
    def test_a_suite_below_the_discovery_floor_is_vacuous(self):
        d = self._suite("thin", "import unittest\nclass T(unittest.TestCase):\n"
                                "    def test_a(self):\n        pass\n")
        r = self._run(d, floor=50)
        self.assertEqual(r.test_verdict, tc.VACUOUS)

    @control(58)
    def test_a_timeout_is_not_pass_and_not_fail(self):
        d = self._suite("slow", "import time, unittest\nclass T(unittest.TestCase):\n"
                                "    def test_a(self):\n        time.sleep(30)\n")
        r = self._run(d, timeout=3.0)
        self.assertEqual(r.process_outcome, tc.TIMED_OUT)
        self.assertEqual(r.test_verdict, tc.NOT_EVALUATED)
        self.assertNotEqual(r.test_verdict, tc.PASS)

    @control(58)
    def test_a_launch_failure_is_not_a_test_failure(self):
        prof = tc.TestProfile("t", ("a-binary-that-does-not-exist-anywhere",))
        r = tc.run_profile(prof, cwd=self.sb.dir, run_id="r")
        self.assertEqual(r.process_outcome, tc.LAUNCH_FAILED)
        self.assertFalse(r.process_executed)
        self.assertEqual(r.test_verdict, tc.NOT_EVALUATED)

    @control(58)
    def test_unparseable_output_yields_absent_counts_not_zero(self):
        parsed = tc.parse_unittest_output("this is not unittest output")
        self.assertIsNone(parsed["discovered"])
        verdict, _ = tc.classify(parsed, process_outcome=tc.LAUNCHED, exit_code=0,
                                 expected_floor=1)
        self.assertEqual(verdict, tc.NOT_EVALUATED)

    def test_the_bridge_owns_the_registry(self):
        """Claude cannot supply an argv: profiles are looked up by id and nothing else."""
        self.assertIsNone(tc.get_profile("rm -rf /"))
        self.assertIsNotNone(tc.get_profile("fixture-unittest"))


# =============================================================================================
# 59, 60 -- cancellation
# =============================================================================================
class TestCancellation(unittest.TestCase):
    def test_cancel_before_any_execution_is_clean(self):
        """Control on the control."""
        d = cancellation.classify_cancel(run_state="CREATED",
                                         stage=cancellation.STAGE_BEFORE_WORKER,
                                         is_write_capable=True, child_started=False,
                                         target_measurable=None, target_changed=None)
        self.assertEqual(d.outcome, cancellation.CANCELLED)

    def test_cancel_before_the_container_is_clean(self):
        d = cancellation.classify_cancel(run_state="DISPATCHED",
                                         stage=cancellation.STAGE_BEFORE_CONTAINER,
                                         is_write_capable=True, child_started=False,
                                         target_measurable=None, target_changed=None)
        self.assertEqual(d.outcome, cancellation.CANCELLED)

    def test_cancel_after_container_before_child_is_clean_only_when_measured(self):
        measured = cancellation.classify_cancel(
            run_state="RUNNING", stage=cancellation.STAGE_CONTAINER_NO_CHILD,
            is_write_capable=True, child_started=False, target_measurable=True,
            target_changed=False)
        self.assertEqual(measured.outcome, cancellation.CANCELLED)
        unmeasured = cancellation.classify_cancel(
            run_state="RUNNING", stage=cancellation.STAGE_CONTAINER_NO_CHILD,
            is_write_capable=True, child_started=False, target_measurable=None,
            target_changed=None)
        self.assertEqual(unmeasured.outcome, cancellation.INTERRUPTED)

    def test_cancelling_a_read_only_child_measured_unchanged_is_clean(self):
        d = cancellation.classify_cancel(run_state="RUNNING",
                                         stage=cancellation.STAGE_CHILD_RUNNING,
                                         is_write_capable=False, child_started=True,
                                         target_measurable=True, target_changed=False)
        self.assertEqual(d.outcome, cancellation.CANCELLED)

    @control(59)
    def test_cancel_after_a_measured_write_is_never_clean(self):
        d = cancellation.classify_cancel(run_state="RUNNING",
                                         stage=cancellation.STAGE_CHILD_RUNNING,
                                         is_write_capable=True, child_started=True,
                                         target_measurable=True, target_changed=True)
        self.assertEqual(d.outcome, cancellation.INTERRUPTED)
        self.assertNotEqual(d.outcome, cancellation.CANCELLED)
        self.assertFalse(d.may_redispatch)

    @control(59)
    def test_cancelling_an_unmeasurable_write_child_is_ambiguous(self):
        for measurable in (False, None):
            d = cancellation.classify_cancel(run_state="RUNNING",
                                             stage=cancellation.STAGE_CHILD_RUNNING,
                                             is_write_capable=True, child_started=True,
                                             target_measurable=measurable, target_changed=None)
            self.assertEqual(d.outcome, cancellation.AMBIGUOUS, measurable)
            self.assertFalse(d.may_redispatch)

    @control(59)
    def test_a_read_only_child_that_changed_the_target_is_not_clean(self):
        d = cancellation.classify_cancel(run_state="RUNNING",
                                         stage=cancellation.STAGE_CHILD_RUNNING,
                                         is_write_capable=False, child_started=True,
                                         target_measurable=True, target_changed=True)
        self.assertEqual(d.outcome, cancellation.INTERRUPTED)

    @control(60)
    def test_duplicate_cancel_is_an_idempotent_noop(self):
        for state in ("CANCELLED", "AMBIGUOUS_EXECUTION", "HANDOFF_READY", "INTERRUPTED"):
            d = cancellation.classify_cancel(run_state=state,
                                             stage=cancellation.STAGE_ALREADY_TERMINAL,
                                             is_write_capable=True, child_started=True,
                                             target_measurable=None, target_changed=None)
            self.assertTrue(d.idempotent_noop, state)
            self.assertEqual(d.outcome, cancellation.NOOP, state)
            self.assertFalse(d.may_redispatch, state)

    @control(60)
    def test_no_cancellation_outcome_ever_permits_redispatch(self):
        import itertools
        for stage, write, started, meas, changed in itertools.product(
                (cancellation.STAGE_BEFORE_WORKER, cancellation.STAGE_BEFORE_CONTAINER,
                 cancellation.STAGE_CONTAINER_NO_CHILD, cancellation.STAGE_CHILD_RUNNING),
                (True, False), (True, False), (True, False, None), (True, False, None)):
            d = cancellation.classify_cancel(run_state="RUNNING", stage=stage,
                                             is_write_capable=write, child_started=started,
                                             target_measurable=meas, target_changed=changed)
            self.assertFalse(d.may_redispatch)

    def test_stage_mapping_reflects_observable_facts(self):
        self.assertEqual(cancellation.stage_for("RUNNING", container_created=True,
                                                child_started=True),
                         cancellation.STAGE_CHILD_RUNNING)
        self.assertEqual(cancellation.stage_for("CREATED", container_created=False,
                                                child_started=False),
                         cancellation.STAGE_BEFORE_WORKER)
        self.assertEqual(cancellation.stage_for("CANCELLED", container_created=True,
                                                child_started=True),
                         cancellation.STAGE_ALREADY_TERMINAL)


# =============================================================================================
# 61 -- concurrency ceiling
# =============================================================================================
class TestConcurrencyCeiling(unittest.TestCase):
    def test_the_first_real_child_is_admitted(self):
        """Control on the control."""
        d = concurrency.decide(active_real_runs=[],
                               requested_executor={"kind": "claude-container"})
        self.assertTrue(d.admitted)
        self.assertEqual(d.limit, 1)

    @control(61)
    def test_a_second_real_child_is_refused(self):
        d = concurrency.decide(active_real_runs=[{"run_id": "already-running"}],
                               requested_executor={"kind": "claude-container"})
        self.assertEqual(d.decision, concurrency.CONCURRENCY_REFUSED)
        self.assertFalse(d.admitted)
        self.assertIn("already-running", d.active_run_ids)

    @control(61)
    def test_the_native_cli_executor_counts_toward_the_ceiling(self):
        d = concurrency.decide(active_real_runs=[{"run_id": "x"}],
                               requested_executor={"kind": "claude-cli"})
        self.assertEqual(d.decision, concurrency.CONCURRENCY_REFUSED)

    @control(61)
    def test_an_unknown_executor_kind_counts_as_real(self):
        """Fail-closed: an unclassified executor must not be exempt by default."""
        d = concurrency.decide(active_real_runs=[{"run_id": "x"}],
                               requested_executor={"kind": "something-new"})
        self.assertEqual(d.decision, concurrency.CONCURRENCY_REFUSED)

    def test_fake_executors_are_exempt(self):
        d = concurrency.decide(active_real_runs=[{"run_id": "x"}, {"run_id": "y"}],
                               requested_executor={"kind": "fake"})
        self.assertTrue(d.admitted)

    def test_the_governing_policy_travels_with_the_decision(self):
        d = concurrency.decide(active_real_runs=[],
                               requested_executor={"kind": "claude-container"})
        self.assertEqual(d.policy["max_active_real_children"], 1)


# =============================================================================================
# Retention
# =============================================================================================
class TestRetention(unittest.TestCase):
    def test_automatic_evidence_gc_is_off_and_sweep_deletes_nothing(self):
        out = retention.sweep([{"run_id": "a", "execution_state": "HANDOFF_READY",
                                "terminal_at": 1.0}], min_age_s=0.0, now=10 ** 9)
        self.assertFalse(out["automatic_evidence_gc"])
        self.assertEqual(out["deleted"], [])
        self.assertEqual(out["inspected_count"], 1)

    def test_uncertain_and_security_runs_are_owner_held(self):
        for state in retention.OWNER_HOLD_STATES:
            d = retention.classify(run_id="r", execution_state=state, age_s=10 ** 9,
                                   min_age_s=0.0)
            self.assertEqual(d.retention_class, retention.OWNER_HOLD, state)
            self.assertFalse(d.evidence_removable, state)
        d = retention.classify(run_id="r", execution_state="HANDOFF_READY",
                               refusal_reason="SECURITY_BOUNDARY_FAIL: mounts differ",
                               age_s=10 ** 9, min_age_s=0.0)
        self.assertEqual(d.retention_class, retention.OWNER_HOLD)

    def test_evidence_is_never_removable_even_when_eligible(self):
        d = retention.classify(run_id="r", execution_state="HANDOFF_READY", age_s=10 ** 9,
                               min_age_s=0.0)
        self.assertEqual(d.retention_class, retention.ELIGIBLE_FOR_GC)
        self.assertFalse(d.evidence_removable)
        self.assertFalse(d.auth_volume_removable)

    def test_active_runs_reclaim_nothing(self):
        d = retention.classify(run_id="r", execution_state="RUNNING")
        self.assertEqual(d.retention_class, retention.ACTIVE)
        self.assertFalse(d.container_removable)


# =============================================================================================
# 41-48 -- EXECUTED behavioural evidence
# =============================================================================================
class TestExecutedConfinementEvidence(unittest.TestCase):
    """Assertions against the verbatim record of a real confined run."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(EVIDENCE):
            if os.environ.get("CI"):
                raise AssertionError(
                    "the P2.5 confinement evidence fixture is absent and CI must not skip "
                    "eight security controls. The capture driver was NOT carried into this "
                    "repository -- the fixture at %s is the carried artefact, so restore it from "
                    "version control rather than looking for a script to regenerate it. A remedy "
                    "naming a file this repository does not contain is worse than none: it sends "
                    "the reader looking for something that was never here." % EVIDENCE)
            raise unittest.SkipTest(
                "no confinement evidence at %s; it is a carried fixture, not a generated one, so "
                "restore it from version control" % EVIDENCE)
        with open(EVIDENCE, "rb") as fh:
            cls.ev = json.loads(fh.read().decode("utf-8"))
        cls.pre = cls.ev["deterministic_preflight"]
        cls.child = cls.ev["real_child"]

    def _check(self, name):
        c = self.pre["checks"].get(name)
        self.assertIsNotNone(c, "preflight check %r is absent from the executed evidence" % name)
        return c

    def test_the_evidence_is_from_a_passing_run_that_inspected_things(self):
        self.assertEqual(self.pre["verdict"], "PASS")
        self.assertGreaterEqual(self.pre["inspected_count"], 20)
        self.assertEqual(self.pre["failures"], [])

    @control(41)
    def test_the_allowed_workspace_write_succeeded(self):
        self.assertTrue(self._check("workspace_writable")["ok"])
        self.assertTrue(self._check("workspace_readable")["ok"])
        self.assertTrue(self._check("challenge_bytes_match")["ok"],
                        "host->container object identity was proven by challenge bytes")
        self.assertTrue(self.child["checks"]["workspace_write_landed_on_host"],
                        "the real child's write must be visible on the HOST")
        self.assertTrue(set(self.child["host_evidence"]["workspace_new_files"]))

    @control(42)
    def test_a_direct_process_could_not_mutate_the_readonly_mount(self):
        for k in ("denied_readonly_overwrite", "denied_readonly_create", "denied_readonly_unlink"):
            self.assertTrue(self._check(k)["ok"], k)
        self.assertTrue(self._check("readonly_host_bytes_unchanged")["ok"])

    @control(43)
    def test_the_real_claude_builtin_tool_could_not_write_the_readonly_mount(self):
        self.assertTrue(self.child["checks"]["child_reports_readonly_builtin_denied"])
        self.assertTrue(self.child["checks"]["readonly_host_bytes_unchanged"],
                        "the host digest is the evidence, not the child's report")

    @control(44)
    def test_bash_could_not_write_the_readonly_mount(self):
        self.assertTrue(self.child["checks"]["child_reports_readonly_bash_denied"])
        self.assertEqual(str(self.child["child_measured_facts"].get("write_readonly_bash")),
                         "DENIED")
        self.assertTrue(self.child["checks"]["readonly_host_bytes_unchanged"])

    @control(45)
    def test_unmounted_host_targets_were_unreachable(self):
        self.assertTrue(self._check("forbidden_container_paths_absent")["ok"])
        self.assertTrue(self._check("forbidden_sentinel_unchanged")["ok"])
        self.assertTrue(self.child["checks"]["forbidden_sentinel_a_unchanged"],
                        "the sentinel under the orchestrator tree must be untouched")
        self.assertTrue(self.child["checks"]["forbidden_sentinel_b_unchanged"])
        self.assertTrue(self.child["checks"]["child_reports_unmounted_unreachable"])

    @control(46)
    def test_path_traversal_reached_no_host_filesystem(self):
        self.assertTrue(self._check("no_host_filesystem_spelling_reachable")["ok"])
        self.assertIn("none of", self._check("no_host_filesystem_spelling_reachable")["detail"])

    @control(47)
    def test_symlink_escape_produced_no_host_write(self):
        for k in ("denied_write_through_symlink_to_readonly",
                  "denied_write_through_symlink_to_root",
                  "denied_write_outside_all_mounts",
                  "denied_write_to_container_root"):
            self.assertTrue(self._check(k)["ok"], k)
        self.assertTrue(self.child["checks"]["child_reports_symlink_denied"])

    @control(48)
    def test_the_docker_control_plane_was_unavailable(self):
        for k in ("docker_socket_absent", "docker_daemon_unreachable", "docker_cli_absent"):
            self.assertTrue(self._check(k)["ok"], k)
        self.assertTrue(self.child["checks"]["child_reports_docker_unreachable"])

    def test_the_engine_confirmed_the_profile_and_the_child_was_unprivileged(self):
        self.assertTrue(self._check("engine_reported_config_matches_profile")["ok"])
        self.assertTrue(self._check("non_root_uid")["ok"])
        self.assertTrue(self._check("all_capabilities_dropped")["ok"])
        self.assertIn("0000000000000000", self._check("all_capabilities_dropped")["detail"])
        self.assertTrue(self._check("private_pid_namespace")["ok"])

    def test_the_owner_channel_was_unavailable_during_the_executed_run(self):
        self.assertEqual(self.ev["policy"]["owner_channel_state"], owner_channel.UNAVAILABLE)
        for cap, dec in self.ev["policy"]["owner_gated_usable"].items():
            self.assertFalse(dec["usable"], cap)

    def test_the_container_auth_was_subscription_backed_with_no_overrides(self):
        ca = self.ev["container_auth"]
        self.assertTrue(ca["ok"])
        self.assertEqual(ca["auth_class"], pf.SUBSCRIPTION)
        self.assertEqual(ca["offending_vars"], [])
        blob = json.dumps(ca)
        self.assertNotIn("sk-ant", blob)

    def test_the_test_claim_was_independently_corroborated(self):
        self.assertTrue(self.child["checks"]["test_claim_agrees_with_collector"])
        self.assertEqual(self.child["test_execution"]["profile_id"], "fixture-unittest")
        self.assertTrue(self.child["test_execution"]["process_executed"])
        self.assertGreaterEqual(self.child["test_execution"]["discovered"], 1)
        self.assertEqual(self.child["test_claim_comparison"]["authority"],
                         "independent collector")

    def test_no_project_content_was_attributable_to_this_run(self):
        cmpn = self.ev.get("baseline_comparison") or {}
        self.assertEqual(cmpn.get("p25_attributable_project_changes"), [])


if __name__ == "__main__":
    unittest.main()

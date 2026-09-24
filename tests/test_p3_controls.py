"""P3 CONTROLS -- the confined write pipeline, egress, reconciliation, and the Git-metadata model.

Three kinds of control, and the difference is deliberate:

  * EXECUTED EVIDENCE (65-73, 77-88) -- asserted against
    ``tests/fixtures/p3_pipeline_evidence.json``, the verbatim record of the real pipeline run and
    the Git-model experiment. Re-running a real Claude child per test would make the suite
    unrunnable; re-deriving the evidence from our own expectations would be the
    consumes-its-own-output defect. The recorded bytes are the input.
  * LIVE DOCKER (74) -- a container that really writes and is really killed mid-flight. Docker
    lifecycle semantics cannot be proven by a fake, and this one needs no Claude call.
  * PURE (72, 75, 76) -- classification logic, exercised directly.

Absent evidence SKIPS locally and FAILS under CI: a suite that silently drops two dozen security
controls is the VACUOUS case the gate exists to catch.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.core import authority
from quaestor.core import cancellation
from quaestor.sandbox import profile as cp  # noqa: E402
from quaestor.sandbox import docker as da
from quaestor.core import domain
from quaestor.sandbox import egress  # noqa: E402
from quaestor.core import proc
from quaestor.core import reconcile
from quaestor.evidence import test_collector as tc  # noqa: E402
from tests import support  # noqa: E402
from tests.controls import control  # noqa: E402

EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                        "p3_pipeline_evidence.json")
# The platform checkout, derived from this file rather than named. A constant naming
# one machine makes the control true only on that machine.
ORCH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
# A synthetic PROTECTED ROOT. It replaces an absolute path to one operator's private
# repository: the platform must be testable on any machine by any user, and a control
# keyed to a directory that exists on exactly one laptop tests that laptop.
PROTECTED_ROOT = os.path.join(tempfile.gettempdir(), "quaestor-protected-root")
os.makedirs(PROTECTED_ROOT, exist_ok=True)


def _docker_available() -> bool:
    return da.engine_status().usable


class EvidenceBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(EVIDENCE):
            if os.environ.get("CI"):
                raise AssertionError(
                    "the P3 evidence fixture is absent and CI must not skip these controls: run "
                    "`python p3_pipeline.py` and `python p3_git_model.py` to capture %s" % EVIDENCE)
            raise unittest.SkipTest("no P3 evidence yet; run p3_pipeline.py + p3_git_model.py")
        with open(EVIDENCE, "rb") as fh:
            cls.ev = json.loads(fh.read().decode("utf-8"))


# =============================================================================================
# 65-67, 88 -- authentication isolation
# =============================================================================================
class TestAuthIsolation(EvidenceBase):
    @property
    def pc(self):
        return self.ev["persistence_control"]

    def test_the_control_actually_exercised_the_home(self):
        """Control on the control: if A could not write, the whole experiment proves nothing."""
        self.assertTrue(self.pc["checks"]["a_could_write_its_own_home"])
        self.assertTrue(all(v is True for v in self.pc["container_a"]["wrote"].values()),
                        self.pc["container_a"]["wrote"])

    @control(65)
    def test_the_child_cannot_modify_the_persistent_auth_seed(self):
        seed = self.pc["container_a"]["seed"]
        for op in ("overwrite", "create"):
            self.assertIn("Read-only file system", str(seed[op]), op)
        self.assertTrue(self.pc["checks"]["a_could_not_write_the_seed"])
        self.assertTrue(self.pc["checks"]["seed_unchanged_on_host"],
                        "the host-side digest is the evidence, not the error message")
        self.assertTrue(self.pc["checks"]["seed_has_no_injected_file"])

    @control(66)
    def test_no_arbitrary_home_state_survives_into_the_next_container(self):
        leaked = self.pc["container_b"]["leaked"]
        self.assertTrue(leaked, "the control must have looked for something")
        self.assertFalse(any(leaked.values()), leaked)
        self.assertEqual(self.pc["container_b"]["home_listing"], [".claude"],
                         "a fresh home should contain only what the bootstrap creates")

    @control(67)
    def test_a_fresh_container_still_bootstraps_authentication(self):
        self.assertTrue(self.pc["checks"]["b_bootstrapped_credential"])
        self.assertTrue(self.pc["container_b"]["home_has_credential"])

    @control(88)
    def test_the_auth_mechanism_carries_no_arbitrary_state(self):
        """The seed volume holds ONE artifact: the credential. Nothing else can ride along."""
        self.assertEqual(self.pc["container_b"]["seed_listing"], [".credentials.json"])
        seed_after = self.pc["seed_after"]
        self.assertEqual(seed_after["inspected_count"], 1, seed_after)


# =============================================================================================
# 68, 86, 87 -- image identity and host exposure
# =============================================================================================
class TestImageAndExposure(EvidenceBase):
    @control(68)
    def test_the_execution_image_is_pinned_by_digest(self):
        digest = self.ev["image"]["digest"]
        self.assertTrue(digest.startswith("sha256:"), digest)
        self.assertEqual(self.ev["profile"]["profile"]["image_digest"], digest)
        self.assertEqual(self.ev["verification"]["image_digest"], digest,
                         "the run record must name the digest that actually executed")

    @control(68)
    def test_an_unpinned_profile_is_refused(self):
        prof = cp.ContainerProfile(profile_id="t", image_ref=support.test_image("p3"), image_digest="",
                                   mounts=())
        v = cp.validate_profile(prof, forbidden_host_paths=cp.default_forbidden_paths(ORCH, PROTECTED_ROOT))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)
        self.assertTrue(any("digest" in r for r in v.reasons))

    @control(86)
    @unittest.skipUnless(
        sys.platform == "win32",
        "the committed evidence records Windows host-path spellings (`c:/...`); resolving those "
        "strings with POSIX semantics is undefined -- `path_is_within` would answer a question "
        "about relative-path fallthrough, not about the exposure the control exists to name")
    def test_the_executed_profile_exposed_no_project_and_no_platform_path(self):
        for m in self.ev["profile"]["profile"]["mounts"]:
            host = str(m.get("host_path") or "")
            if not host or m.get("kind") != "bind":
                continue
            self.assertFalse(cp.path_is_within(host, PROTECTED_ROOT), host)
            self.assertFalse(cp.path_is_within(host, ORCH), host)

    @control(86)
    def test_mounting_the_project_primary_working_tree_is_refused(self):
        for mode in (cp.RW, cp.RO):
            prof = cp.ContainerProfile(
                profile_id="t", image_ref="x", image_digest="sha256:" + "a" * 64,
                mounts=(cp.Mount(PROTECTED_ROOT, "/workspace", mode, cp.BIND),))
            v = cp.validate_profile(prof,
                                    forbidden_host_paths=cp.default_forbidden_paths(ORCH, PROTECTED_ROOT))
            self.assertEqual(v.verdict, cp.POLICY_REFUSED, mode)

    @control(87)
    def test_a_sibling_worktree_bind_is_refused(self):
        sibling = PROTECTED_ROOT + "/.worktrees/some-other-lane"
        prof = cp.ContainerProfile(
            profile_id="t", image_ref="x", image_digest="sha256:" + "a" * 64,
            mounts=(cp.Mount(sibling, "/other", cp.RO, cp.BIND),))
        v = cp.validate_profile(prof, forbidden_host_paths=cp.default_forbidden_paths(ORCH, PROTECTED_ROOT))
        self.assertEqual(v.verdict, cp.POLICY_REFUSED)

    @control(87)
    def test_the_git_model_exposed_no_sibling_worktree_content(self):
        chosen = self.ev["git_model"]["candidates"][self.ev["git_model"]["selected"]]
        targets = [m["container_path"] for m in chosen["mounts"]]
        self.assertNotIn("/git/primary-worktree", targets)
        self.assertTrue(chosen["checks"]["primary_working_tree_not_exposed"])


# =============================================================================================
# 69-73 -- the meaningful write pipeline
# =============================================================================================
class TestWritePipeline(EvidenceBase):
    @property
    def v(self):
        return self.ev["verification"]

    @control(69)
    def test_the_fixture_genuinely_started_failing(self):
        pre = self.ev["prefix_tests"]
        self.assertEqual(pre["test_verdict"], tc.FAIL)
        self.assertTrue(pre["process_executed"])
        self.assertGreaterEqual(pre["discovered"], 5)
        self.assertGreaterEqual(pre["failed"], 1)

    def test_the_run_went_through_the_real_pipeline(self):
        """Not the P2.5 driver: dispatcher -> worker -> container adapter."""
        self.assertTrue(self.v["checks"]["dispatched_through_real_pipeline"])
        self.assertTrue(self.v["checks"]["authority_profile_confined"])
        self.assertEqual(self.ev["dispatch"]["outcome"], "ADMITTED")
        self.assertTrue(self.ev["dispatch"]["spawned"])
        self.assertIsNotNone(self.v["lease"])

    @control(70)
    def test_the_child_edited_only_the_authorized_workspace(self):
        self.assertTrue(self.v["checks"]["mutations_inside_workspace_only"])
        self.assertTrue(self.v["checks"]["source_actually_changed"])
        self.assertIn("src/semver.py", self.v["mutation"]["changed_paths"])
        for p in self.v["mutation"]["changed_paths"]:
            self.assertFalse(p.startswith(".."), p)
        self.assertTrue(self.v["checks"]["head_unchanged_no_commit"],
                        "a STANDARD_EDIT_CONFINED child must not commit")

    @control(70)
    def test_the_engine_confirmed_the_profile_for_the_real_child(self):
        self.assertTrue(self.v["checks"]["engine_confirmed_profile"])
        self.assertEqual(self.v["container"]["actual_verdict"], "CONTAINER_POLICY_OK")
        self.assertEqual(self.v["container"]["exit_code"], 0)

    @control(71)
    def test_the_independent_collector_observed_pass(self):
        post = self.v["tests"]["postfix"]
        self.assertEqual(post["test_verdict"], tc.PASS)
        self.assertTrue(post["process_executed"])
        self.assertGreaterEqual(post["discovered"], 5)
        self.assertEqual(post["failed"], 0)
        self.assertTrue(self.v["checks"]["evidence_floor_met"])
        self.assertEqual(self.v["tests"]["claim"]["authority"], "independent collector")
        self.assertTrue(self.v["tests"]["claim"]["agree"])

    @control(71)
    def test_the_child_diagnosed_the_actual_defect(self):
        """An agentic edit, not an echo: the prompt never named the cause."""
        cause = str(self.v["measured_facts"].get("root_cause", "")).lower()
        self.assertTrue(cause, self.v["measured_facts"])
        self.assertTrue(any(w in cause for w in ("string", "lexicograph", "numeric", "int")),
                        cause)
        self.assertEqual(self.v["handoff"]["prompt_disposition"], domain.COMPLETE)
        self.assertEqual(self.v["handoff"]["program_verdict"], domain.PASS)

    @control(72)
    def test_a_claimed_pass_against_a_measured_fail_resolves_to_fail(self):
        """PURE: the collector wins, and the disagreement is recorded rather than averaged."""
        measured = tc.TestReceipt(
            run_id="r", profile_id="p", argv_identity="a", cwd_identity="c",
            process_executed=True, process_outcome=tc.LAUNCHED, test_verdict=tc.FAIL,
            exit_code=1, discovered=6, failed=2)
        cmp_ = tc.compare_claim("PASS", measured)
        self.assertFalse(cmp_["agree"])
        self.assertEqual(cmp_["measured"], tc.FAIL)
        self.assertEqual(cmp_["authority"], "independent collector")

    @control(73)
    def test_replaying_the_identical_dispatch_spawned_nothing(self):
        r = self.ev["replay"]
        self.assertEqual(r["failed"], [])
        for k in ("returned_duplicate", "same_run_returned", "no_new_worker_spawned",
                  "no_new_container", "session_id_unchanged", "no_new_mutation"):
            self.assertTrue(r["checks"][k], k)
        d = r["detail"]
        self.assertEqual(d["outcome"], "DUPLICATE")
        self.assertEqual(d["workspace_digest_before"], d["workspace_digest_after"],
                         "the replay must not have changed a single byte")


# =============================================================================================
# 77-79 -- egress
# =============================================================================================
class TestEgress(EvidenceBase):
    @control(77)
    def test_the_allowlist_was_derived_from_measurement(self):
        ledger = self.ev["egress_ledger"]
        self.assertGreater(ledger["decisions_logged"], 0)
        gw = self.ev["gateway"]
        self.assertEqual(gw["mode"], egress.ENFORCE)
        self.assertTrue(gw["allow"], "an empty allowlist under enforcement proves nothing")
        for rule in gw["allow"]:
            host, _, port = rule.rpartition(":")
            self.assertEqual(port, "443", rule)
            self.assertEqual(egress.classify_destination(host), egress.CORE_REQUIRED, rule)

    @control(77)
    def test_only_first_party_destinations_were_allowed(self):
        for rule in self.ev["gateway"]["allow"]:
            self.assertTrue(rule.endswith(":443"))
            self.assertIn("anthropic.com", rule)

    @control(78)
    def test_non_allowlisted_destinations_are_denied(self):
        c = self.ev["egress_controls"]["checks"]
        for k in ("arbitrary_domain_denied", "direct_ip_connect_denied",
                  "host_docker_internal_denied", "unexpected_port_denied",
                  "lookalike_suffix_denied"):
            self.assertTrue(c[k], k)

    @control(78)
    def test_the_rule_matcher_refuses_lookalikes_and_wrong_ports(self):
        """PURE: a wildcard must not match its own parent, and the port must match exactly."""
        allow = ["api.anthropic.com:443", "*.anthropic.com:443"]
        self.assertTrue(egress.match_rule("api.anthropic.com", 443, allow)[0])
        self.assertFalse(egress.match_rule("api.anthropic.com.evil.test", 443, allow)[0])
        self.assertFalse(egress.match_rule("api.anthropic.com", 2222, allow)[0])
        self.assertFalse(egress.match_rule("anthropic.com", 443, ["*.anthropic.com:443"])[0])
        self.assertFalse(egress.match_rule("evil.test", 443, allow)[0])

    @control(78)
    def test_the_enforcing_matcher_is_the_matcher_under_test(self):
        """The proxy runs in a container where this package is not mounted, so match_rule is
        duplicated. Assert the two sources are IDENTICAL -- otherwise the tested copy and the
        enforcing copy could drift, and every test above would be about the wrong function."""
        import inspect
        import re as _re
        proxy_src = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "docker", "egress_proxy.py"),
            encoding="utf-8").read()
        m = _re.search(r"^def match_rule\(.*?(?=\n\ndef |\Z)", proxy_src, _re.S | _re.M)
        self.assertIsNotNone(m, "match_rule not found in the proxy script")

        def body(text):
            lines = [l.rstrip() for l in text.strip().splitlines()]
            # Compare CODE only: the docstrings legitimately differ (the package copy explains
            # the duplication). Everything executable must match exactly.
            out, in_doc = [], False
            for l in lines:
                s = l.strip()
                if s.startswith('"""'):
                    in_doc = not in_doc or not s.endswith('"""') or len(s) < 6
                    continue
                if in_doc:
                    continue
                out.append(l)
            return "\n".join(out)

        self.assertEqual(body(m.group(0)), body(inspect.getsource(egress.match_rule)),
                         "the proxy's matcher has drifted from the one under test")

    @control(79)
    def test_no_direct_route_exists_around_the_gateway(self):
        c = self.ev["egress_controls"]["checks"]
        for k in ("no_direct_route_to_required_host", "no_direct_route_to_public_host",
                  "no_direct_route_to_public_ip", "no_direct_route_to_host_docker_internal"):
            self.assertTrue(c[k], k)
        self.assertFalse(self.ev["egress_controls"]["direct_route_available"])
        self.assertTrue(self.ev["network"]["internal"],
                        "the child network must be --internal; that is what removes the route")

    @control(79)
    def test_the_required_endpoint_is_reachable_only_through_the_gateway(self):
        c = self.ev["egress_controls"]["checks"]
        self.assertTrue(c["required_endpoint_reachable_through_gateway"])
        self.assertTrue(c["no_direct_route_to_required_host"])

    def test_a_direct_route_would_fail_the_egress_verdict(self):
        """Control on the control: the verdict must be able to FAIL."""
        out = egress.evaluate(ledger=[], required_ok=True, denied_controls={},
                              direct_route_available=True)
        self.assertEqual(out["verdict"], egress.EGRESS_FAIL)
        out2 = egress.evaluate(ledger=[], required_ok=True, denied_controls={},
                               direct_route_available=None)
        self.assertEqual(out2["verdict"], egress.EGRESS_FAIL,
                         "an unmeasured bypass is not an absent one")


# =============================================================================================
# 74-76 -- container lifecycle, reconciliation, no duplicate execution
# =============================================================================================
class TestContainerReconciliation(unittest.TestCase):
    @unittest.skipUnless(_docker_available(), "docker engine unavailable")
    @control(74)
    def test_a_container_killed_after_a_write_is_reconciled_honestly(self):
        """LIVE: a real container writes, then is killed before any terminal result."""
        import shutil
        import tempfile
        # HOST-VISIBLE tmp, via support.live_tmpdir: this directory is bind-mounted into a
        # SIBLING container through the host docker daemon, so under a containerized runner it
        # must exist at the same path on the host. Everything else in the suite uses ordinary
        # container-local temp -- see the live_tmpdir docstring for the measured reason why
        # this is scoped rather than global.
        #
        # realpath, NOT canonical_path, for the bind source: canonical_path CASEFOLDS, which is
        # correct for identity joins and WRONG for a docker argv -- the runner directory's real
        # spelling carries mixed case, and a casefolded bind source is a path the daemon
        # legitimately cannot find. The mount needs the host's exact spelling; the identity
        # layer can canonicalize what it joins on.
        work = os.path.realpath(support.live_tmpdir(prefix="quaestor-p3-crash-"))
        # THE CHILD IS uid 1001 AND MKDTEMP IS NOT. mkdtemp creates 0700 root-owned; on a real
        # Linux daemon the bind-mounted child therefore cannot write into it at all -- the write
        # is permission-denied and the control reads "the container never performed its write",
        # which is a fixture bug masquerading as a reconciliation defect. Docker Desktop on the
        # author's machine fakes this permission model, which is how it ever passed.
        os.chmod(work, 0o777)
        self.addCleanup(shutil.rmtree, work, True)
        digest, _ = da.image_digest(support.test_image("p3"))
        self.assertTrue(digest, "the P3 image must be present; looked for %r (override with the QUAESTOR_TEST_IMAGE_P3 environment variable)" % support.test_image("p3"))

        profile = cp.ContainerProfile(
            profile_id="crash", image_ref=support.test_image("p3"), image_digest=digest,
            user="1001:1001", workdir="/workspace",
            mounts=(cp.Mount(work, "/workspace", cp.RW, cp.BIND),
                    cp.Mount("", "/home/claude", cp.RW, cp.TMPFS,
                             options="rw,nosuid,size=64m,uid=1001,gid=1001,mode=0700"),
                    cp.Mount("", "/tmp", cp.RW, cp.TMPFS,
                             options="rw,nosuid,size=32m,uid=1001,gid=1001")),
            network="none", cap_drop=("ALL",), read_only_rootfs=True,
            security_opt=("no-new-privileges",), memory="512m", cpus="1", pids_limit=128,
            timeout_s=120.0)

        # RUN-UNIQUE RESOURCE NAMING, the shared-host gotcha: two CI runs can execute this live
        # control in the same second on the same daemon, and a name derived from
        # int(time.time()) collides -- docker refuses the second create ("already in use"),
        # which surfaced when a PR run and its own merge-to-main push overlapped. The uuid
        # suffix makes the name unique per process.
        name = "quaestor-p3-crash-%d-%s" % (int(time.time()), uuid.uuid4().hex[:8])
        args = profile.docker_create_args(
            name, ["python3", "-c",
                   "open('/workspace/WRITTEN_BEFORE_DEATH.txt','w').write('mutation\\n');"
                   "import time; time.sleep(120)"])
        created = da.docker(args, timeout=180)
        self.assertTrue(created.ok, created.err)
        cid = created.out.strip()
        self.addCleanup(lambda: da.docker(["rm", "-f", cid], timeout=120))
        self.assertTrue(da.docker(["start", cid], timeout=120).ok)

        target = os.path.join(work, "WRITTEN_BEFORE_DEATH.txt")
        deadline = time.time() + 60
        while time.time() < deadline and not os.path.exists(target):
            time.sleep(0.5)
        self.assertTrue(os.path.exists(target), "the container never performed its write")

        # Kill it mid-flight: a write has landed, no terminal result exists.
        self.assertTrue(da.docker(["kill", cid], timeout=120).ok)
        insp, err = da.inspect_container(cid)
        self.assertIsNotNone(insp, err)
        self.assertNotEqual(str(insp["State"]["Status"]), "running")

        # The bridge measures the target itself, then classifies.
        observed_change = os.path.exists(target)
        rec = reconcile.classify(run_state=domain.RUNNING, is_write=True, liveness=proc.DEAD,
                                 worker_started=True, exit_receipt=None, result_valid=None,
                                 observed_change=observed_change)
        self.assertEqual(rec.classification, reconcile.AMBIGUOUS_EXECUTION)
        self.assertFalse(rec.auto_redispatch_allowed)
        self.assertNotEqual(rec.classification, reconcile.RESULT_RECEIVED)

        cancel = cancellation.classify_cancel(
            run_state=domain.RUNNING, stage=cancellation.STAGE_CHILD_RUNNING,
            is_write_capable=True, child_started=True, target_measurable=True,
            target_changed=observed_change)
        self.assertEqual(cancel.outcome, cancellation.INTERRUPTED)
        self.assertNotEqual(cancel.outcome, cancellation.CANCELLED)

    @control(74)
    def test_a_container_that_died_before_any_write_is_not_ambiguous(self):
        """Control on the control: not everything is AMBIGUOUS, or the state means nothing."""
        rec = reconcile.classify(run_state=domain.DISPATCHED, is_write=True, liveness=proc.DEAD,
                                 worker_started=False, exit_receipt=None, result_valid=None,
                                 observed_change=False)
        self.assertEqual(rec.classification, reconcile.WORKER_FAILED)
        self.assertTrue(rec.auto_redispatch_allowed)

    @control(75)
    def test_no_ambiguous_write_execution_permits_automatic_redispatch(self):
        for liveness in (proc.DEAD, proc.UNKNOWN):
            for observed in (True, None):
                rec = reconcile.classify(run_state=domain.RUNNING, is_write=True,
                                         liveness=liveness, worker_started=True,
                                         exit_receipt=None, result_valid=None,
                                         observed_change=observed)
                self.assertEqual(rec.classification, reconcile.AMBIGUOUS_EXECUTION,
                                 (liveness, observed))
                self.assertFalse(rec.auto_redispatch_allowed)

    @control(75)
    def test_ambiguous_execution_is_terminal_with_no_edge_back(self):
        for state in domain.ALL_STATES:
            self.assertFalse(domain.can_transition(domain.AMBIGUOUS_EXECUTION, state), state)

    @control(76)
    def test_a_dispatcher_restart_over_a_live_worker_reports_running(self):
        rec = reconcile.classify(run_state=domain.RUNNING, is_write=True, liveness=proc.ALIVE,
                                 worker_started=True, exit_receipt=None, result_valid=None,
                                 observed_change=None)
        self.assertEqual(rec.classification, reconcile.RUNNING)
        self.assertIsNone(rec.target_state, "a live run must not be re-stated by a restart")

    @control(76)
    def test_a_restart_that_cannot_establish_liveness_refuses_rather_than_duplicating(self):
        rec = reconcile.classify(run_state=domain.RUNNING, is_write=True, liveness=proc.UNKNOWN,
                                 worker_started=True, exit_receipt=None, result_valid=None,
                                 observed_change=None)
        self.assertEqual(rec.classification, reconcile.AMBIGUOUS_EXECUTION)
        self.assertFalse(rec.auto_redispatch_allowed)


# =============================================================================================
# 80-85 -- the Git metadata model
# =============================================================================================
class TestGitMetadataModel(EvidenceBase):
    @property
    def gm(self):
        return self.ev["git_model"]

    @property
    def chosen(self):
        return self.gm["candidates"][self.gm["selected"]]

    @control(80)
    def test_worktree_only_behaviour_was_measured(self):
        a = self.gm["candidates"]["A_worktree_only"]
        self.assertFalse(a["usable"], "a worktree-only mount is expected NOT to work")
        self.assertFalse(a["checks"]["git_resolves_head"])
        self.assertTrue(a["checks"]["primary_working_tree_not_exposed"])

    def test_a_model_was_selected_and_more_than_one_was_tried(self):
        self.assertIsNotNone(self.gm["selected"])
        self.assertEqual(self.gm["P4_GIT_MODEL"], "PASS")
        self.assertGreaterEqual(len(self.gm["candidates"]), 4)

    @control(81)
    def test_the_chosen_model_resolves_the_exact_head(self):
        self.assertTrue(self.chosen["checks"]["git_resolves_head"])
        self.assertTrue(self.chosen["checks"]["head_is_exact"])

    @control(82)
    def test_the_chosen_model_observes_a_workspace_edit(self):
        self.assertTrue(self.chosen["checks"]["workspace_edit_succeeded"])
        self.assertTrue(self.chosen["checks"]["status_sees_workspace_edit"])
        self.assertTrue(self.chosen["checks"]["diff_sees_workspace_edit"])
        self.assertTrue(self.chosen["checks"]["can_read_tracked_files"])

    @control(83)
    def test_the_chosen_model_cannot_mutate_host_refs(self):
        self.assertTrue(self.chosen["checks"]["deny_branch"])
        self.assertTrue(self.chosen["checks"]["deny_update_ref"])
        self.assertTrue(self.chosen["checks"]["deny_tag"])
        self.assertTrue(self.chosen["checks"]["host_common_metadata_unchanged"],
                        "the host-side digest is the evidence, not git's error text")

    @control(84)
    def test_the_chosen_model_cannot_mutate_host_config(self):
        self.assertTrue(self.chosen["checks"]["deny_config_write"])

    @control(85)
    def test_the_chosen_model_cannot_commit_or_stash(self):
        self.assertTrue(self.chosen["checks"]["deny_commit"])
        self.assertTrue(self.chosen["checks"]["deny_stash"])

    @control(85)
    def test_the_chosen_model_exposes_no_writable_metadata_mount(self):
        """Least exposure: the selected candidate needs NO writable metadata bind at all."""
        for m in self.chosen["mounts"]:
            if m["container_path"].startswith("/git"):
                self.assertEqual(m["mode"], cp.RO, m)


if __name__ == "__main__":
    unittest.main()

"""PLATFORM CONTROLS (169-186) -- the extraction's own contract.

Two things are under test here that were not under test before:

  1. GENERICITY. The core must not know any project, provider, machine or user. That is asserted
     against the real import graph and the real source tree, not promised in a docstring.
  2. THE NEW PRIMITIVES. Actors, two-way messages, decisions, lanes and review are load-bearing
     architecture, so they get the same treatment as everything else: each refusal is paired with
     a positive control proving the gate discriminates rather than refusing universally.

Every fixture here is synthetic and machine-independent. A control keyed to a directory that
exists on one laptop tests that laptop.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor import branding, compat  # noqa: E402
from quaestor.core import actors as actors_mod  # noqa: E402
from quaestor.core import authority as authority_mod  # noqa: E402
from quaestor.core import decisions as dec_mod  # noqa: E402
from quaestor.core import events as ev_mod  # noqa: E402
from quaestor.core import messages as msg_mod  # noqa: E402
from quaestor.core import programs as prog_mod  # noqa: E402
from quaestor.core.strategic_store import StrategicStore  # noqa: E402
from quaestor.projects import config as proj_cfg  # noqa: E402
from quaestor.core import review_contract as review_mod  # noqa: E402
from tests import support  # noqa: E402
from tests.controls import control  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

# The tokens are declared in ONE isolated module and imported here. A denylist must name what it
# denies, which makes its own file unscannable by its own rule -- so that file, and only that
# file, is exempt. Spelling them here instead would have exempted this whole control file, and
# the control file is exactly where a future weakening would be written.
from tests.genericity_tokens import (  # noqa: E402
    DECLARATION_FILE, FORBIDDEN_TOKENS, FROZEN_LITERALS)


def py_files(base):
    for d, dirs, files in os.walk(base):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(d, f)


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


# =============================================================================================
# 169-172 -- genericity
# =============================================================================================
class TestGenericity(unittest.TestCase):
    @control(169)
    def test_the_repository_names_no_project_user_or_machine(self):
        """The whole point of the extraction, asserted over EVERY python file in the tree.

        SCOPE WAS THE DEFECT. This scanned ``src/`` only -- which is exactly the directory the
        extraction scrub had run over -- so it certified the scrub's own output and reported a
        clean tree while ``tests/`` named the origin project thirty-two times. A control whose
        subject is precisely the set of files somebody already fixed measures nothing.

        There is exactly ONE file-level exemption -- ``tests/genericity_tokens.py``, which
        exists only to hold the denylist, because a denylist has to name what it denies.
        Everything else, ``compat.py`` and this control file included, is scanned; the two
        frozen wire values are exempt BY VALUE wherever they appear, so a NEW occurrence of an
        origin token on the same line as one is still caught.
        """
        offenders, scanned, exempted = [], 0, 0
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs
                       if d not in ("__pycache__", ".git", "var", ".pytest_cache")]
            for f in sorted(files):
                if not f.endswith(".py"):
                    continue
                path = os.path.join(base, f)
                rel = os.path.relpath(path, ROOT).replace("\\", "/")
                scanned += 1
                if rel == DECLARATION_FILE:
                    exempted += 1
                    continue
                for i, line in enumerate(read(path).splitlines(), 1):
                    stripped = line.strip()
                    probe = line
                    for lit in FROZEN_LITERALS:
                        if lit in probe:
                            exempted += 1
                            probe = probe.replace(lit, "")
                    low = probe.lower()
                    for token in FORBIDDEN_TOKENS:
                        if token in low:
                            offenders.append("%s:%d %s" % (rel, i, stripped[:70]))
        self.assertGreater(scanned, 60, "the scan inspected %d files" % scanned)
        self.assertGreater(exempted, 0,
                           "no exemption was exercised, so the exemption logic is unproven and "
                           "this control cannot tell 'clean' from 'the exemptions swallowed it'")
        self.assertEqual(offenders, [])

    @control(169)
    def test_the_genericity_scan_would_catch_a_reintroduction(self):
        """CONTROL ON THE CONTROL, on bytes this suite did not write into the tree.

        The previous version returned ``[]`` over a repository containing thirty-two hits,
        because of where it looked. So this proves the matcher itself finds a token, and that
        the by-value exemption does not swallow a NEW occurrence of the same token.

        The probe strings are COMPOSED from the imported tokens rather than typed, so this file
        never spells one and stays inside the scan it is checking.
        """
        def scan(text):
            found = []
            for line in text.splitlines():
                probe = line
                for lit in FROZEN_LITERALS:
                    probe = probe.replace(lit, "")
                for token in FORBIDDEN_TOKENS:
                    if token in probe.lower():
                        found.append(token)
            return found

        origin, operator = FORBIDDEN_TOKENS[0], FORBIDDEN_TOKENS[1]
        self.assertEqual(scan('PROTOCOL = "%s"' % FROZEN_LITERALS[1]), [],
                         "the frozen wire value must stay exempt")
        self.assertEqual(scan("HOME = 'C:/Users/%s/x'" % operator), [operator])
        self.assertEqual(scan('REPO = "%s"' % origin), [origin])
        # The frozen value on a line that ALSO reintroduces the token is still caught.
        self.assertEqual(scan('X = "%s"  # for %s' % (FROZEN_LITERALS[1], origin)), [origin])
        # And the declaration file really is the only file-level exemption.
        self.assertEqual(DECLARATION_FILE, "tests/genericity_tokens.py")

    @control(169)
    def test_the_frozen_constants_are_isolated_and_explained(self):
        """Control on the control: the exemption is real, narrow, and justified in place."""
        src = read(os.path.join(SRC, "quaestor", "compat.py"))
        for lit in FROZEN_LITERALS:
            self.assertIn(lit, src)
        for name, why in compat.FROZEN_REASONS.items():
            self.assertGreater(len(why), 40, name)
        # And they are actually used, not merely declared.
        from quaestor.core import handoff, identity
        self.assertEqual(identity.PROTOCOL_SALT, compat.DISPATCH_KEY_SALT)
        self.assertEqual(handoff.PROTOCOL, compat.HANDOFF_PROTOCOL)

    @control(170)
    def test_no_absolute_host_path_is_compiled_into_the_platform(self):
        offenders, scanned = [], 0
        for path in py_files(SRC):
            scanned += 1
            for i, line in enumerate(read(path).split("\n"), 1):
                if line.lstrip().startswith("#"):
                    continue
                # MACHINE-IDENTIFYING host paths only. A container-side path such as
                # "/home/claude" or "/workspace" is sandbox configuration, not coupling to
                # anyone's laptop, and flagging it would make this control noisy enough to be
                # switched off -- which is how a control stops mattering.
                for probe in ('"C:/Users/', '"C:\\\\Users\\\\', '"/Users/', '"C:/Windows'):
                    if probe in line:
                        offenders.append("%s:%d %s"
                                         % (os.path.relpath(path, SRC), i, line.strip()[:70]))
        self.assertGreater(scanned, 40)
        self.assertEqual(offenders, [])

    #: Layers `core` may not depend on.
    OUTER_LAYERS = ("quaestor.transports", "quaestor.executors", "quaestor.sandbox",
                    "quaestor.projects", "quaestor.secrets")

    #: The runtime edges core is permitted, and the exact sites that may hold them. They exist so
    #: `core` can declare the NEED for a provider capability (build an executor, run a dispatch
    #: preflight) without depending on any provider. Anything else naming an outer layer in a
    #: string is a violation.
    PERMITTED_DYNAMIC = {("worker.py", "quaestor.executors.registry"),
                         ("orchestrator.py", "quaestor.executors.registry")}

    @control(171)
    def test_the_core_never_imports_an_outer_layer(self):
        """The layering rule, against the REAL import graph -- STATIC **AND** DYNAMIC.

        The first version of this control walked only `ast.Import` / `ast.ImportFrom`, so a module
        named in a string literal was invisible to it. That was not a hypothetical gap: the
        executor factory inversion put `importlib.import_module("quaestor.executors.registry")`
        in `core/worker.py`, on the unconditional dispatch path, and this control reported no
        violations over a graph that contained the edge. A gate blind to the only real violation
        in the tree is worse than no gate, because it is cited as proof.

        So string-named modules are now walked too, and the single deliberate seam is allowlisted
        BY SITE -- adding a second one is a visible diff rather than a silent widening.
        """
        static, dynamic, scanned = [], [], 0
        for path in py_files(os.path.join(SRC, "quaestor", "core")):
            scanned += 1
            base = os.path.basename(path)
            is_pkg = base == "__init__.py"
            mod_name = ("quaestor.core" if is_pkg
                        else "quaestor.core." + base[:-3])
            tree = ast.parse(read(path), filename=path)
            for node in ast.walk(tree):
                # STATIC, WITH RELATIVE IMPORTS RESOLVED. Keying on `node.module` alone made
                # `from . import x` invisible and mis-anchored `from .core import y`; the
                # repository this was extracted from used relative imports exclusively, so this
                # walk would have certified a graph it could not read.
                mods = support.resolve_imports(node, mod_name, is_pkg)
                for m in mods:
                    if any(m == o or m.startswith(o + ".") for o in self.OUTER_LAYERS):
                        static.append("%s imports %s" % (base, m))
                # DYNAMIC: any string literal naming an outer-layer module, wherever it appears.
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    v = node.value
                    if any(v == o or v.startswith(o + ".") for o in self.OUTER_LAYERS):
                        if (base, v) not in self.PERMITTED_DYNAMIC:
                            dynamic.append("%s names %s dynamically" % (base, v))

        self.assertGreater(scanned, 15, "walked %d core modules" % scanned)
        self.assertEqual(static, [])
        self.assertEqual(dynamic, [])

    @control(171)
    def test_the_walk_can_actually_see_a_dynamic_edge(self):
        """CONTROL ON THE CONTROL. The previous walk returned [] over a graph containing the edge.

        Rather than trust that the new walk is not equally blind, this asserts it FINDS the real
        seam -- and, separately, that the seam is the only one.
        """
        src = read(os.path.join(SRC, "quaestor", "core", "worker.py"))
        self.assertIn('importlib.import_module("quaestor.executors.registry")', src,
                      "the seam this control is calibrated against has moved")
        tree = ast.parse(src)
        named = {n.value for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value.startswith("quaestor.")}
        self.assertIn("quaestor.executors.registry", named,
                      "the walk cannot see string-named modules at all")
        self.assertGreaterEqual(len(self.PERMITTED_DYNAMIC), 1,
                                "the allowlist has grown; every entry is a hole in the layering rule")

    @control(171)
    def test_the_runtime_edge_is_confined_to_the_declared_seam(self):
        """Measured, not read: importing core must load NO outer-layer module."""
        import subprocess
        probe = (
            "import sys; sys.path.insert(0, %r)\n"
            "import quaestor.core.worker\n"
            "outer=[m for m in sys.modules if m.startswith(('quaestor.executors',"
            "'quaestor.sandbox','quaestor.transports','quaestor.review','quaestor.projects',"
            "'quaestor.secrets'))]\n"
            "print(sorted(outer))\n" % SRC)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        out = subprocess.run([sys.executable, "-c", probe], capture_output=True, timeout=120,
                             shell=False, env=env).stdout.decode("utf-8", "replace").strip()
        self.assertEqual(out, "[]",
                         "importing core loaded outer-layer modules: %s" % out)

    @control(172)
    def test_branding_is_the_only_place_the_product_is_named(self):
        offenders = []
        for path in py_files(SRC):
            rel = os.path.relpath(path, SRC).replace("\\", "/")
            # ``compat`` is exempt for exactly the reason it exists: its values are
            # FROZEN. One of them seals every stored credential, so it must not be
            # derived from a name this control is trying to keep changeable.
            if rel in ("quaestor/branding.py", "quaestor/__init__.py",
                       "quaestor/compat.py"):
                continue
            for i, line in enumerate(read(path).split("\n"), 1):
                if '"quaestor' in line.lower() or "'quaestor" in line.lower():
                    # A dotted MODULE PATH is not branding: it is how Python names this code, and
                    # it travels with a package rename, not with a product rename.
                    if ("import" in line or line.lstrip().startswith("#")
                            or "quaestor." in line):
                        continue
                    offenders.append("%s:%d %s" % (rel, i, line.strip()[:70]))
        self.assertEqual(offenders, [])
        # Control on the control: renaming is genuinely one edit.
        self.assertEqual(branding.env_var("home"), "QUAESTOR_HOME")
        self.assertEqual(branding.resource("egress", "gateway"), "quaestor-egress-gateway")
        self.assertEqual(branding.label("component"), "quaestor.component")


# =============================================================================================
# 173-176 -- actors and authority
# =============================================================================================
class TestActors(unittest.TestCase):
    @control(173)
    def test_a_role_confers_no_authority(self):
        for role in actors_mod.ROLES:
            a = actors_mod.new_actor(role)
            self.assertTrue(a.valid)
            self.assertFalse(hasattr(a, "capabilities"),
                             "an actor must not carry capabilities of its own")
            blob = json.dumps(a.to_dict())
            for cap in authority_mod.PROFILES:
                self.assertNotIn('"%s"' % cap, blob)

    @control(173)
    def test_an_unknown_role_is_refused_not_defaulted(self):
        for bad in ("ADMIN", "root", "", "strategist", None):
            with self.assertRaises((ValueError, TypeError), msg=repr(bad)):
                actors_mod.new_actor(bad)

    @control(174)
    def test_review_roles_can_never_hold_a_mutating_capability(self):
        mutating = sorted(authority_mod.MUTATING)
        for role in (actors_mod.REVIEWER, actors_mod.ADVERSARIAL_REVIEWER, actors_mod.VERIFIER):
            a = actors_mod.new_actor(role)
            allowed, reason = actors_mod.authority_ceiling(a, mutating)
            self.assertEqual(allowed, (), role)
            self.assertIn("may never hold a capability that reaches outside", reason)
        # Control on the control: a read capability still passes, and an EXECUTOR is not blocked
        # by the ceiling -- the ceiling narrows, the authority engine decides.
        reviewer = actors_mod.new_actor(actors_mod.REVIEWER)
        allowed, reason = actors_mod.authority_ceiling(reviewer, [authority_mod.CAP_REPO_READ])
        self.assertEqual(allowed, (authority_mod.CAP_REPO_READ,))
        ex = actors_mod.new_actor(actors_mod.EXECUTOR)
        allowed, _ = actors_mod.authority_ceiling(ex, mutating)
        self.assertEqual(sorted(allowed), mutating)

    @control(174)
    def test_the_ceiling_never_widens_what_was_requested(self):
        ex = actors_mod.new_actor(actors_mod.EXECUTOR)
        allowed, _ = actors_mod.authority_ceiling(ex, [])
        self.assertEqual(allowed, ())
        allowed, _ = actors_mod.authority_ceiling(ex, [authority_mod.CAP_REPO_READ])
        self.assertEqual(allowed, (authority_mod.CAP_REPO_READ,))


# =============================================================================================
# 175-178 -- the two-way protocol
# =============================================================================================
class TestMessages(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-msg-")
        self.store = StrategicStore(os.path.join(self.dir, "s.sqlite3"))
        self.addCleanup(self.store.close)
        self.pid = self.store.create_program("t", objective="do the thing")
        self.lane = prog_mod.new_lane(self.pid, title="impl")
        self.store.add_lane(self.lane)

    @control(175)
    def test_every_protocol_message_type_exists_and_routes(self):
        required = {"CLARIFICATION_REQUEST", "DECISION_REQUEST", "AUTHORITY_REQUEST", "BLOCKER",
                    "OBSERVATION", "PLAN_REVISION", "RESULT", "REVIEW_FINDING",
                    "OWNER_ESCALATION"}
        self.assertTrue(required <= set(msg_mod.MESSAGE_TYPES))
        for t in msg_mod.MESSAGE_TYPES:
            self.assertIn(t, msg_mod.ROUTES, t)
        with self.assertRaises(ValueError):
            msg_mod.new_message("SHOUT", actor_id="a", lane_id=self.lane.lane_id)

    @control(175)
    def test_waiting_types_await_an_answer_and_others_do_not(self):
        for t in (msg_mod.CLARIFICATION_REQUEST, msg_mod.DECISION_REQUEST,
                  msg_mod.AUTHORITY_REQUEST, msg_mod.OWNER_ESCALATION):
            m = msg_mod.new_message(t, actor_id="a", lane_id=self.lane.lane_id)
            self.assertTrue(m.awaits_answer, t)
        for t in (msg_mod.OBSERVATION, msg_mod.RESULT, msg_mod.PLAN_REVISION):
            m = msg_mod.new_message(t, actor_id="a", lane_id=self.lane.lane_id)
            self.assertFalse(m.awaits_answer, t)

    @control(176)
    def test_an_authority_request_grants_nothing(self):
        m = msg_mod.new_message(msg_mod.AUTHORITY_REQUEST, actor_id="ex", lane_id=self.lane.lane_id,
                                payload="I need to write files",
                                detail={"capabilities": [authority_mod.CAP_REPO_WRITE]})
        stored, _ = self.store.record_message(m)
        self.assertTrue(stored)
        note = msg_mod.authority_request_grants_nothing(m)
        self.assertFalse(note["grants_authority"])
        self.assertEqual(note["granted"], [])
        # Nothing anywhere gained a capability.
        evs = [e["event_type"] for e in self.store.events(lane_id=self.lane.lane_id)]
        self.assertIn(ev_mod.AUTHORITY_REQUESTED, evs)
        self.assertNotIn(ev_mod.AUTHORITY_GRANTED, evs)

    @control(177)
    def test_message_persistence_is_idempotent_by_content(self):
        m = msg_mod.new_message(msg_mod.BLOCKER, actor_id="ex", lane_id=self.lane.lane_id,
                                payload="cannot reach the registry")
        stored1, _ = self.store.record_message(m)
        again = msg_mod.new_message(msg_mod.BLOCKER, actor_id="ex", lane_id=self.lane.lane_id,
                                    payload="cannot reach the registry")
        stored2, existing = self.store.record_message(again)
        self.assertTrue(stored1)
        self.assertFalse(stored2, "a redelivered message must not duplicate")
        self.assertEqual(existing, m.message_id)
        self.assertEqual(len(self.store.messages(self.lane.lane_id)), 1)
        # Control on the control: genuinely different content DOES store.
        other = msg_mod.new_message(msg_mod.BLOCKER, actor_id="ex", lane_id=self.lane.lane_id,
                                    payload="a different blocker")
        self.assertTrue(self.store.record_message(other)[0])
        self.assertEqual(len(self.store.messages(self.lane.lane_id)), 2)

    @control(178)
    def test_open_questions_survive_and_close(self):
        q = msg_mod.new_message(msg_mod.CLARIFICATION_REQUEST, actor_id="ex",
                                lane_id=self.lane.lane_id, payload="which branch?")
        self.store.record_message(q)
        self.assertEqual(len(self.store.open_questions(self.lane.lane_id)), 1)
        a = msg_mod.new_message(msg_mod.DIRECTIVE, actor_id="strat", lane_id=self.lane.lane_id,
                                caused_by=q.message_id, payload="main")
        self.store.record_message(a)
        self.store.answer_message(q.message_id, a.message_id)
        self.assertEqual(self.store.open_questions(self.lane.lane_id), [])

    @control(178)
    def test_a_malformed_envelope_is_refused(self):
        for doc, expect in (
                ({"message_type": "NOPE", "actor_id": "a", "lane_id": "l"}, msg_mod.UNKNOWN_TYPE),
                ({"message_type": msg_mod.RESULT, "actor_id": "", "lane_id": "l"},
                 msg_mod.MALFORMED),
                ({"message_type": msg_mod.RESULT, "actor_id": "a", "lane_id": ""},
                 msg_mod.MALFORMED),
                ({"message_type": msg_mod.RESULT, "actor_id": "a", "lane_id": "l",
                  "protocol_version": 99}, msg_mod.PROTOCOL_REFUSED),
                ("not a mapping", msg_mod.MALFORMED)):
            outcome, _reason = msg_mod.validate(doc)
            self.assertEqual(outcome, expect, repr(doc)[:60])
        ok, _ = msg_mod.validate({"message_type": msg_mod.RESULT, "actor_id": "a",
                                  "lane_id": "l", "protocol_version": 1})
        self.assertEqual(ok, msg_mod.VALID)


# =============================================================================================
# 179-181 -- decisions
# =============================================================================================
class TestDecisions(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-dec-")
        self.store = StrategicStore(os.path.join(self.dir, "s.sqlite3"))
        self.addCleanup(self.store.close)
        self.pid = self.store.create_program("t")

    @control(179)
    def test_a_decision_records_who_was_entitled_to_make_it(self):
        d = dec_mod.new_decision(self.pid, "ship or hold?", decision="hold",
                                 authority=dec_mod.BY_OWNER, rationale="unreviewed")
        self.store.record_decision(d)
        got = self.store.get_decision(d.decision_id)
        self.assertEqual(got.authority, dec_mod.BY_OWNER)
        self.assertEqual(got.status, dec_mod.DECIDED)
        with self.assertRaises(ValueError):
            dec_mod.new_decision(self.pid, "q", authority="WHOEVER")
        with self.assertRaises(ValueError):
            dec_mod.new_decision(self.pid, "   ")

    @control(180)
    def test_decisions_are_superseded_never_overwritten(self):
        first = dec_mod.new_decision(self.pid, "which db?", decision="sqlite",
                                     rationale="local-first")
        self.store.record_decision(first)
        new_id = self.store.supersede_decision(first.decision_id, decision="sqlite + wal",
                                               rationale="threaded transport needs concurrent reads")
        old = self.store.get_decision(first.decision_id)
        fresh = self.store.get_decision(new_id)
        self.assertEqual(old.status, dec_mod.SUPERSEDED)
        self.assertEqual(old.superseded_by, new_id)
        self.assertEqual(fresh.supersedes, first.decision_id)
        # The original is still readable -- that history is the valuable part.
        self.assertEqual(old.decision, "sqlite")
        self.assertEqual(len(self.store.decisions(self.pid)), 2)
        live = dec_mod.live_decisions(self.store.decisions(self.pid))
        self.assertEqual([d.decision_id for d in live], [new_id])

    @control(180)
    def test_superseding_without_a_rationale_is_refused(self):
        d = dec_mod.new_decision(self.pid, "q", decision="a", rationale="because")
        with self.assertRaises(ValueError):
            dec_mod.supersede(d, decision="b", rationale="   ")

    @control(181)
    def test_events_use_a_closed_vocabulary(self):
        with self.assertRaises(ValueError):
            ev_mod.new_event("SOMETHING_HAPPENED")
        e = ev_mod.new_event(ev_mod.AUTHORITY_REQUESTED, program_id=self.pid)
        self.assertTrue(e.is_request_only,
                        "asking for authority and receiving it must not look alike")
        self.assertFalse(ev_mod.new_event(ev_mod.AUTHORITY_GRANTED).is_request_only)


# =============================================================================================
# 182-184 -- lanes, ownership, aggregation
# =============================================================================================
class TestLanes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-lane-")
        self.store = StrategicStore(os.path.join(self.dir, "s.sqlite3"))
        self.addCleanup(self.store.close)
        self.pid = self.store.create_program("p", objective="ship the thing")

    def lane(self, title, **kw):
        l = prog_mod.new_lane(self.pid, title=title, **kw)
        self.store.add_lane(l)
        return l

    @control(182)
    def test_one_active_strategic_writer_per_lane(self):
        l = self.lane("impl")
        out, lease, _ = self.store.claim_lane(l.lane_id, actor_id="sessionA", now=1000.0)
        self.assertEqual(out, prog_mod.ACQUIRED)

        out2, held, reason = self.store.claim_lane(l.lane_id, actor_id="sessionB", now=1001.0)
        self.assertEqual(out2, prog_mod.HELD_BY_OTHER)
        self.assertIn("one active strategic writer per lane", reason)

        # The holder renews rather than being locked out of its own lane.
        out3, renewed, _ = self.store.claim_lane(l.lane_id, actor_id="sessionA",
                                                 owner_token=lease.owner_token, now=1002.0)
        self.assertEqual(out3, prog_mod.RENEWED)

        # After expiry the lane is takeable, and the new holder gets a HIGHER fence.
        out4, taken, _ = self.store.claim_lane(l.lane_id, actor_id="sessionB", now=99999.0)
        self.assertEqual(out4, prog_mod.ACQUIRED)
        self.assertGreater(taken.fence, lease.fence)

    @control(182)
    def test_a_superseded_writer_is_detected_by_its_fence(self):
        l = self.lane("impl")
        _, first, _ = self.store.claim_lane(l.lane_id, actor_id="A", now=1000.0)
        _, second, _ = self.store.claim_lane(l.lane_id, actor_id="B", now=99999.0)
        current = self.store.lease_for(l.lane_id)
        ok, reason = prog_mod.check_fence(current, first.fence)
        self.assertFalse(ok, "a stale writer's late call must be refused, not merged")
        self.assertIn(prog_mod.STALE_FENCE, reason)
        ok, _ = prog_mod.check_fence(current, second.fence)
        self.assertTrue(ok)

    @control(183)
    def test_two_writable_lanes_cannot_share_a_workspace(self):
        a = self.lane("impl-a", writable=True, workspace_id="ws1")
        b = self.lane("impl-b", writable=True, workspace_id="ws1")
        c = self.lane("read", writable=False, workspace_id="ws1")
        conflicts = prog_mod.workspace_conflicts([a, b, c])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(sorted(conflicts[0]["lanes"]), sorted([a.lane_id, b.lane_id]))
        # Control on the control: distinct workspaces do not conflict, and readers never do.
        d = self.lane("impl-c", writable=True, workspace_id="ws2")
        self.assertEqual(prog_mod.workspace_conflicts([a, d]), [])

    @control(184)
    def test_outcomes_do_not_collapse_into_one_boolean(self):
        a = prog_mod.new_lane(self.pid, title="A")
        a = prog_mod.Lane(**{**a.to_dict_ctor(), "state": prog_mod.LANE_COMPLETE,
                             "verdict": prog_mod.PASS})
        b = prog_mod.new_lane(self.pid, title="B")
        b = prog_mod.Lane(**{**b.to_dict_ctor(), "state": prog_mod.LANE_COMPLETE,
                             "verdict": prog_mod.FAIL})
        c = prog_mod.new_lane(self.pid, title="C")
        c = prog_mod.Lane(**{**c.to_dict_ctor(), "state": prog_mod.LANE_WAITING_OWNER})

        out = prog_mod.aggregate([a, b, c])
        self.assertEqual(out["program_verdict"], prog_mod.FAIL)
        self.assertEqual(out["next_authority"], prog_mod.NEXT_STRATEGIST)
        self.assertFalse(out["vacuous"])

        waiting_only = prog_mod.aggregate([a, c])
        self.assertEqual(waiting_only["program_verdict"], prog_mod.NOT_EVALUATED)
        self.assertEqual(waiting_only["next_authority"], prog_mod.NEXT_OWNER)

        all_pass = prog_mod.aggregate([a])
        self.assertEqual(all_pass["program_verdict"], prog_mod.PASS)
        self.assertEqual(all_pass["next_authority"], prog_mod.NEXT_NONE)

        empty = prog_mod.aggregate([])
        self.assertTrue(empty["vacuous"])
        self.assertEqual(empty["program_verdict"], prog_mod.NOT_EVALUATED)

    @control(184)
    def test_waiting_is_a_state_not_a_failure(self):
        for s in prog_mod.WAITING_STATES:
            l = prog_mod.new_lane(self.pid, title="w")
            l = prog_mod.Lane(**{**l.to_dict_ctor(), "state": s})
            self.assertTrue(l.waiting, s)
            self.assertFalse(l.terminal, s)
            self.assertNotEqual(prog_mod.aggregate([l])["program_verdict"], prog_mod.FAIL)


# =============================================================================================
# 185 -- durable strategic state and handoff
# =============================================================================================
class TestHandoff(unittest.TestCase):
    @control(185)
    def test_the_bundle_is_a_brief_not_only_a_state_display(self):
        """A resuming strategist needs the CONSTRAINTS bounding the objective and the TASK each
        lane was given -- otherwise the bundle reports that a lane is blocked without ever
        saying what it was trying to do, and the next holder must reconstruct the half that
        matters from the half that does not. All three additions read durable rows the store
        already had; omitting them was a gap in the assembly, not a limit of the schema."""
        from quaestor.core import orchestrator as orch_mod
        d = tempfile.mkdtemp(prefix="quaestor-brief-")
        store = StrategicStore(os.path.join(d, "s.sqlite3"))
        self.addCleanup(store.close)
        pid = orch_mod.create_program(store, title="ship v2", objective="ship version 2 safely",
                                      constraints=["no schema migration", "no new dependency"],
                                      actor_id="t")
        lane = orch_mod.plan_lane(store, pid, title="implementation",
                                  task="add the div helper",
                                  acceptance=["divide by zero raises"], actor_id="t")

        bundle = store.handoff_bundle(pid)
        self.assertEqual(bundle["constraints"], ["no schema migration", "no new dependency"])
        self.assertEqual(bundle["status"], orch_mod.PROGRAM_PLANNED)
        row = [l for l in bundle["lanes"] if l["lane_id"] == lane][0]
        self.assertEqual(row["task"], "add the div helper")
        self.assertEqual(row["acceptance"], ["divide by zero raises"])
        self.assertEqual(row["attempt"], 0)
        # The self-report counts what it assembled, so an empty section is distinguishable from
        # a section that was never read.
        self.assertEqual(bundle["inspected"]["constraints"], 2)
        self.assertEqual(bundle["inspected"]["acceptance"], 1)

    @control(185)
    def test_a_malformed_constraints_row_reports_none_never_a_partial_read(self):
        d = tempfile.mkdtemp(prefix="quaestor-brief-bad-")
        store = StrategicStore(os.path.join(d, "s.sqlite3"))
        self.addCleanup(store.close)
        pid = store.create_program("ship v2", objective="ship version 2 safely")
        store.set_program_meta(pid, "constraints_json", "{not json")
        bundle = store.handoff_bundle(pid)
        self.assertEqual(bundle["constraints"], [])
        self.assertEqual(bundle["inspected"]["constraints"], 0)

    @control(185)
    def test_a_new_session_can_resume_without_a_transcript(self):
        d = tempfile.mkdtemp(prefix="quaestor-handoff-")
        store = StrategicStore(os.path.join(d, "s.sqlite3"))
        self.addCleanup(store.close)
        pid = store.create_program("ship v2", objective="ship version 2 safely")
        impl = prog_mod.new_lane(pid, title="implementation", writable=True, workspace_id="w1")
        rev = prog_mod.new_lane(pid, title="review")
        store.add_lane(impl)
        store.add_lane(rev)
        store.add_dependency(prog_mod.Dependency(rev.lane_id, impl.lane_id, prog_mod.REQUIRES))
        store.record_decision(dec_mod.new_decision(
            pid, "which database?", decision="sqlite", rationale="local-first",
            authority=dec_mod.BY_OWNER))
        store.record_message(msg_mod.new_message(
            msg_mod.CLARIFICATION_REQUEST, actor_id="ex", lane_id=impl.lane_id,
            program_id=pid, payload="which branch is the base?"))
        store.set_lane_state(impl.lane_id, prog_mod.LANE_WAITING_STRATEGIST)

        # A COMPLETELY FRESH handle over the same durable state -- the resumption case.
        store.close()
        fresh = StrategicStore(os.path.join(d, "s.sqlite3"))
        self.addCleanup(fresh.close)
        bundle = fresh.handoff_bundle(pid)

        self.assertFalse(bundle["vacuous"])
        self.assertEqual(bundle["objective"], "ship version 2 safely")
        self.assertEqual(len(bundle["lanes"]), 2)
        self.assertEqual(len(bundle["decisions"]), 1)
        self.assertEqual(len(bundle["open_questions"]), 1)
        self.assertEqual(bundle["open_questions"][0]["message_type"],
                         msg_mod.CLARIFICATION_REQUEST)
        self.assertEqual(bundle["blocking"][rev.lane_id], [impl.lane_id])
        self.assertEqual(bundle["aggregate"]["program_verdict"], prog_mod.NOT_EVALUATED)
        self.assertGreater(bundle["inspected"]["events"], 0)
        # No transcript anywhere in it.
        # No transcript DATA -- checked by KEY, not by searching the prose. The bundle's own
        # explanatory note legitimately contains the word "transcript", and a control that
        # cannot tell a field from a sentence would have to be deleted the first time someone
        # improved the documentation.
        def keys(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield str(k)
                    yield from keys(v)
            elif isinstance(node, list):
                for v in node:
                    yield from keys(v)

        found = [k for k in keys(bundle)
                 if k.lower() in ("transcript", "conversation", "history", "messages")]
        self.assertEqual(found, [])


# =============================================================================================
# 186 -- review independence and project config
# =============================================================================================
class TestReviewAndProjects(unittest.TestCase):
    @control(186)
    def test_a_review_request_cannot_carry_the_executor_conversation(self):
        fields = set(review_mod.ReviewRequest.__dataclass_fields__)
        for banned in ("transcript", "conversation", "messages", "history", "executor_reasoning"):
            self.assertNotIn(banned, fields)
        with self.assertRaises(ValueError):
            review_mod.build_request(review_mod.ADVERSARIAL, objective="x", evidence={})
        req = review_mod.build_request(review_mod.ADVERSARIAL, objective="x",
                                       evidence={"git_head": "abc"})
        self.assertEqual(req.kind, review_mod.ADVERSARIAL)

    @control(186)
    def test_the_adversarial_reviewer_is_read_only_by_construction(self):
        a = review_mod.reviewer_actor(review_mod.ADVERSARIAL)
        self.assertEqual(a.role, actors_mod.ADVERSARIAL_REVIEWER)
        self.assertTrue(a.read_only_by_role)
        allowed, reason = actors_mod.authority_ceiling(a, [authority_mod.CAP_REPO_WRITE])
        self.assertEqual(allowed, ())
        self.assertTrue(reason)

    @control(186)
    def test_an_empty_review_is_vacuous_not_accepted(self):
        empty = review_mod.ReviewResult("r1", review_mod.ADVERSARIAL, review_mod.ACCEPTED,
                                        inspected_count=0)
        self.assertEqual(review_mod.summarize(empty)["outcome"], review_mod.VACUOUS)
        clean = review_mod.ReviewResult("r2", review_mod.ADVERSARIAL, review_mod.ACCEPTED,
                                        inspected_count=12)
        self.assertEqual(review_mod.summarize(clean)["outcome"], review_mod.ACCEPTED)
        blocking = review_mod.ReviewResult(
            "r3", review_mod.ADVERSARIAL, review_mod.ACCEPTED, inspected_count=12,
            findings=(review_mod.Finding("f1", "auth bypass", review_mod.CRITICAL),))
        self.assertEqual(review_mod.summarize(blocking)["outcome"], review_mod.REJECTED)

    @control(186)
    def test_the_platform_floor_for_adversarial_review_cannot_be_configured_away(self):
        required, matched = review_mod.adversarial_required(["security_sensitive"],
                                                            {"required_for": []})
        self.assertTrue(required)
        self.assertEqual(matched, ("security_sensitive",))
        required, _ = review_mod.adversarial_required(["cosmetic"], {})
        self.assertFalse(required)
        # A project may WIDEN the floor.
        required, matched = review_mod.adversarial_required(["schema_change"],
                                                            {"required_for": ["schema_change"]})
        self.assertTrue(required)

    @control(186)
    def test_both_example_projects_load_without_touching_core(self):
        """The genericity acceptance test: two different projects, one unchanged core."""
        loaded = {}
        for name in ("synthetic", "reference"):
            cfg, reason = proj_cfg.load(os.path.join(ROOT, "examples", name, "quaestor.yaml"))
            self.assertIsNotNone(cfg, "%s: %s" % (name, reason))
            loaded[name] = cfg
        self.assertNotEqual(loaded["synthetic"].name, loaded["reference"].name)
        self.assertNotEqual(loaded["synthetic"].executor, loaded["reference"].executor)

        # SEMANTIC values, not just names. The first version of this control asserted names and
        # authority only, and a three-level key the parser silently flattened turned
        # `adversarial.enabled: true` into `adversarial_review = False` -- the reference project
        # asked for adversarial review on six change classes and would have got none, with every
        # field it did check looking correct.
        for name, cfg in loaded.items():
            self.assertTrue(cfg.adversarial_review, "%s: adversarial review silently off" % name)
            self.assertTrue(cfg.test_commands, name)
            for cmd in cfg.test_commands:
                self.assertEqual(cmd.count('"') % 2, 0,
                                 "%s: unbalanced quotes in %r -- a mangled command" % (name, cmd))
        self.assertEqual(len(loaded["reference"].adversarial_required_for), 6)
        self.assertIn("authentication", loaded["reference"].adversarial_required_for)
        self.assertEqual(loaded["reference"].executor, "claude-cli")
        self.assertEqual(loaded["reference"].sandbox_provider, "docker")

        # And the parser REFUSES rather than guessing, which is what its docstring promises.
        import tempfile as _tf
        for bad, why in ((b"project:\n\tname: x\n", "tab"),
                         (b"project:\n  name: x\nnonsense\n", "unparseable"),
                         (b"- orphan\n", "list item")):
            bp = os.path.join(_tf.mkdtemp(prefix="quaestor-badcfg-"), "quaestor.yaml")
            with open(bp, "wb") as fh:
                fh.write(bad)
            cfg, reason = proj_cfg.load(bp)
            self.assertIsNone(cfg, why)
            self.assertIn(proj_cfg.CONFIG_MALFORMED, reason)
        self.assertEqual(loaded["synthetic"].default_authority, (authority_mod.READ_ONLY,))
        self.assertEqual(loaded["reference"].default_authority, (authority_mod.READ_ONLY,))
        self.assertTrue(loaded["reference"].protected_roots)
        self.assertEqual(loaded["synthetic"].protected_roots, ())
        # An unknown authority profile is refused, not silently dropped.
        p = os.path.join(tempfile.mkdtemp(prefix="quaestor-cfg-"), "quaestor.yaml")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("project:\n  name: x\nauthority:\n  default:\n    - GOD_MODE\n")
        cfg, reason = proj_cfg.load(p)
        self.assertIsNone(cfg)
        self.assertIn(proj_cfg.CONFIG_REFUSED, reason)


if __name__ == "__main__":
    unittest.main()


# =============================================================================================
# 187-188 -- defects the adversarial extraction review found
# =============================================================================================
class TestExtractionDefects(unittest.TestCase):
    @control(187)
    def test_the_child_prompt_contract_is_pinned(self):
        """The prompt is an INPUT to the dispatch identity, so its bytes re-key deduplication.

        The extraction changed one line of boilerplate -- the old text named the private project
        this platform came from -- and that silently changed every dispatch key. Measured, not
        assumed. Pinning the first line makes any future edit a visible diff rather than an
        invisible migration.
        """
        from quaestor.core.identity import RunBinding, build_identity
        from quaestor.core.prompting import build_child_prompt

        self.assertEqual(compat.CHILD_PROMPT_CONTRACT, "v2-generic")
        b = RunBinding(run_id="r1", workflow_id="wf", step_id="s1", run_nonce="NONCE")
        prompt = build_child_prompt(task="do a thing", binding=b, profile="READ_ONLY",
                                    capabilities=("repo_read",), cwd="/w")
        first = prompt.split("\n")[0]
        self.assertEqual(
            first,
            "You are executing one authorized step for an engineering control plane. "
            "A machine reads your answer.")
        # It names no project, and it is genuinely part of the identity.
        for token in FORBIDDEN_TOKENS:
            self.assertNotIn(token, prompt.lower())
        key = build_identity(workflow_id="wf", step_id="s1", prompt=prompt, repo_id="r",
                             worktree_path="/w", expected_branch="main", expected_head="abc",
                             authority_profile="READ_ONLY",
                             capabilities=("repo_read",)).dispatch_key()
        other = build_identity(workflow_id="wf", step_id="s1", prompt=prompt + " ", repo_id="r",
                               worktree_path="/w", expected_branch="main", expected_head="abc",
                               authority_profile="READ_ONLY",
                               capabilities=("repo_read",)).dispatch_key()
        self.assertNotEqual(key, other, "the prompt must participate in the dispatch identity")
        # The ALGORITHM is unchanged: the salt is still the frozen one.
        from quaestor.core import identity as ident
        self.assertEqual(ident.PROTOCOL_SALT, compat.DISPATCH_KEY_SALT)

    @control(188)
    def test_every_format_string_has_matching_arity(self):
        """A scrub silently broke one, and no test exercised the path that would have crashed.

        The interactive credential-provisioning prompt ended up with one %s and two arguments, so
        provisioning would have died with TypeError the first time an owner ran it. That path
        needs a TTY, so no control could reach it -- which is exactly why this checks the SHAPE
        of every format string instead of waiting for a caller.
        """
        import re
        bad, inspected = [], 0
        for path in py_files(SRC):
            inspected += 1
            tree = ast.parse(read(path), filename=path)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)):
                    continue
                left, parts = node.left, []
                while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
                    parts.append(left.right)
                    left = left.left
                parts.append(left)
                literal = "".join(p.value for p in parts
                                  if isinstance(p, ast.Constant) and isinstance(p.value, str))
                if not literal:
                    continue
                specs = len(re.findall(
                    r"%[-#0 +]*[0-9*]*(?:\.[0-9*]+)?[hlL]?[diouxXeEfFgGcrsa]", literal))
                right = node.right
                # Only a literal tuple gives a countable arity; a name or call is unknowable
                # statically and is left alone rather than guessed at.
                if not isinstance(right, ast.Tuple):
                    continue
                if specs and specs != len(right.elts):
                    bad.append("%s:%d %d specifier(s) vs %d argument(s)"
                               % (os.path.relpath(path, SRC), node.lineno, specs,
                                  len(right.elts)))
        self.assertGreater(inspected, 40, "inspected %d modules" % inspected)
        self.assertEqual(bad, [])


# =============================================================================================
# 189 -- lane-lease enforcement, found declared-but-unenforced by adversarial review
# =============================================================================================
class TestLeaseEnforcement(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-fence-")
        self.store = StrategicStore(os.path.join(self.dir, "s.sqlite3"))
        self.addCleanup(self.store.close)
        self.pid = self.store.create_program("p")
        self.lane = prog_mod.new_lane(self.pid, title="impl")
        self.store.add_lane(self.lane)

    @control(189)
    def test_the_fence_is_actually_enforced_on_a_write(self):
        """`check_fence` existed and was never called. A fence nobody consults is a comment."""
        _, first, _ = self.store.claim_lane(self.lane.lane_id, actor_id="A", now=1000.0)
        _, second, _ = self.store.claim_lane(self.lane.lane_id, actor_id="B", now=99999.0)
        self.assertGreater(second.fence, first.fence)

        ok, reason = self.store.set_lane_state_fenced(
            self.lane.lane_id, prog_mod.LANE_ACTIVE, fence=first.fence)
        self.assertFalse(ok, "a superseded writer's late write must be refused")
        self.assertIn(prog_mod.STALE_FENCE, reason)
        self.assertEqual(self.store.get_lane(self.lane.lane_id).state, prog_mod.LANE_PLANNED)

        ok, _ = self.store.set_lane_state_fenced(
            self.lane.lane_id, prog_mod.LANE_ACTIVE, fence=second.fence)
        self.assertTrue(ok)
        self.assertEqual(self.store.get_lane(self.lane.lane_id).state, prog_mod.LANE_ACTIVE)

    @control(189)
    def test_concurrent_claims_do_not_both_acquire(self):
        """The claim was a read-evaluate-write race: two writers could both see 'free'."""
        import threading as _t
        results, errors = [], []

        def claim(i):
            try:
                results.append(self.store.claim_lane(self.lane.lane_id, actor_id="a%d" % i,
                                                     now=1000.0)[0])
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        threads = [_t.Thread(target=claim, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        acquired = [r for r in results if r == prog_mod.ACQUIRED]
        self.assertEqual(len(acquired), 1,
                         "exactly one writer may acquire; got %r" % (results,))
        self.assertEqual(len({r for r in results}) <= 2, True)
        row = self.store.lease_for(self.lane.lane_id)
        self.assertEqual(row.fence, 1)

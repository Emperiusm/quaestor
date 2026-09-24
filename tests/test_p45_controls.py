"""P4.5 CONTROLS -- the owner credential broker (113-136).

EVERY TEST HERE USES A FRESHLY GENERATED FAKE SECRET. The owner's real token is never used, never
read, and never referenced. A leakage control that runs against the real credential would be a
control that puts the real credential into a test process, a temp directory and a diff -- the
exact outcome it exists to prevent.

The fake is unique per run (``uuid4``) and long enough that an accidental substring match is not
plausible, so "the fake never appears in X" is a real statement about X rather than about the
improbability of a collision.

DPAPI is Windows-only. Where a control needs real DPAPI it skips on other platforms and FAILS
under CI, because silently dropping the crypto controls is the VACUOUS case.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quaestor.sandbox import profile as cp
from quaestor.secrets import validate as credential_validate
from quaestor.secrets import credentials  # noqa: E402
from quaestor import dpapi
from quaestor.executors import claude_auth as pf
from quaestor import branding
from quaestor.secrets import store as secret_store  # noqa: E402
from quaestor.transports.cli import build_parser  # noqa: E402
from tests import support  # noqa: E402
from tests.controls import control  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Where each control's SOURCE-READING assertion should look after the extraction. Keyed by the
#: module's original flat name so the control bodies stay readable.
SRC = {
    "cli.py": ("src", "quaestor", "transports", "cli.py"),
    "credential_validate.py": ("src", "quaestor", "secrets", "validate.py"),
    "repo.py": ("src", "quaestor", "workspace", "git.py"),
    "mcp_adapter.py": ("src", "quaestor", "transports", "mcp", "adapter.py"),
    "mcp_server.py": ("src", "quaestor", "transports", "mcp", "server.py"),
    "transport_schemas.py": ("src", "quaestor", "transports", "mcp", "schemas.py"),
    "transport_ledger.py": ("src", "quaestor", "transports", "mcp", "ledger.py"),
    "transport_redact.py": ("src", "quaestor", "transports", "mcp", "redact.py"),
    "transport_mode.py": ("src", "quaestor", "transports", "mcp", "mode.py"),
    "transport_auth.py": ("src", "quaestor", "transports", "mcp", "auth.py"),
}

#: The CLI entry point, as a module path for ``python -m``.
CLI_MODULE = "quaestor.transports.cli"


def cli_env(extra=None):
    """Environment for a `python -m` child so it can import the installed-in-place package.

    The extraction moved the code under src/, so a subprocess no longer inherits an importable
    package from the working directory alone. Set explicitly rather than relying on the parent's
    sys.path, which a child does not inherit.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra or {})
    return env


# A synthetic PROTECTED ROOT. It replaces an absolute path to one operator's private
# repository: the platform must be testable on any machine by any user, and a control
# keyed to a directory that exists on exactly one laptop tests that laptop.
PROTECTED_ROOT = os.path.join(tempfile.gettempdir(), "quaestor-protected-root")
os.makedirs(PROTECTED_ROOT, exist_ok=True)


def fake_secret() -> str:
    """A unique, long, obviously-fake credential. Never the owner's token."""
    return "FAKE-oat-" + uuid.uuid4().hex + uuid.uuid4().hex


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def read_json(path: str) -> dict:
    return json.loads(read_text(path))


def write_json(path: str, doc) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


def dpapi_or_skip():
    if not dpapi.available():
        if os.environ.get("CI") and os.name == "nt":
            raise AssertionError("DPAPI unavailable on a Windows CI host; controls cannot skip")
        raise unittest.SkipTest("DPAPI unavailable (non-Windows or restricted host)")


class BrokerBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="quaestor-p45-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.secret = fake_secret()

    def provision(self, value=None):
        buf = bytearray((value or self.secret).encode("utf-8"))
        try:
            return secret_store.provision(buf, directory=self.dir)
        finally:
            secret_store.wipe_secret(buf)

    def blob_path(self):
        return os.path.join(self.dir, secret_store.BLOB_NAME)

    def meta_path(self):
        return os.path.join(self.dir, secret_store.META_NAME)


# =============================================================================================
# 113-114 -- the input path
# =============================================================================================
class TestInputPath(unittest.TestCase):
    def _credential_parser(self):
        ap = build_parser()
        sub = [a for a in ap._actions if getattr(a, "choices", None)
               and isinstance(a.choices, dict)][0]
        return sub.choices["credential"]

    @control(113)
    def test_the_cli_exposes_no_option_that_could_carry_a_secret(self):
        """An EXACT option set, not a substring heuristic.

        `--secret-dir` carries a PATH and would defeat a naive "contains 'secret'" check, while a
        future `--value` would slip past one. Pinning the exact set makes any new option a
        deliberate, reviewable change.
        """
        opts = sorted({o for act in self._credential_parser()._actions
                       for o in act.option_strings})
        self.assertEqual(opts, ["--deep", "--help", "--image", "--network", "--secret-dir", "-h"])

    @control(113)
    def test_a_token_argument_is_rejected_by_the_parser(self):
        ap = build_parser()
        for flag in ("--token", "--secret", "--value", "--password", "--credential"):
            with self.assertRaises(SystemExit, msg=flag):
                ap.parse_args(["credential", "provision", flag, "SECRET"])

    @control(113)
    def test_option_abbreviation_is_disabled_on_the_credential_parser(self):
        """`--secret <TOKEN>` must not silently bind to `--secret-dir`.

        argparse resolves unambiguous prefixes by default, which would have put the token in the
        process table and made it a directory name. This is the control that found it.
        """
        self.assertFalse(self._credential_parser().allow_abbrev)
        ap = build_parser()
        with self.assertRaises(SystemExit):
            ap.parse_args(["credential", "provision", "--secret", "TOKEN"])
        # Control on the control: the full option still works, so the fix hardened rather than
        # merely removed the surface.
        a = ap.parse_args(["credential", "status", "--secret-dir", "D"])
        self.assertEqual(a.secret_dir, "D")

    @control(113)
    def test_the_provision_path_reads_through_getpass(self):
        """The hidden-prompt call must exist in the source, and no echoing read beside it."""
        src = read_text(os.path.join(ROOT, *SRC["cli.py"]))
        self.assertIn("getpass.getpass(", src)
        self.assertNotIn("input(\"  token", src)
        self.assertNotIn("sys.stdin.read()", src)

    @control(114)
    def test_provisioning_refuses_a_non_tty_stdin(self):
        """A piped secret came from a file, a script or a shell history."""
        src = read_text(os.path.join(ROOT, *SRC["cli.py"]))
        self.assertIn("sys.stdin.isatty()", src)
        env = cli_env()
        p = subprocess.run([sys.executable, "-m", CLI_MODULE, "credential", "provision",
                            "--secret-dir", tempfile.mkdtemp(prefix="quaestor-p45-tty-")],
                           cwd=ROOT, capture_output=True, shell=False, timeout=120,
                           input=b"SHOULD-NEVER-BE-STORED\n", env=env)
        self.assertNotEqual(p.returncode, 0)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        self.assertIn("not a TTY", out)
        self.assertNotIn("SHOULD-NEVER-BE-STORED", out)


# =============================================================================================
# 115-122 -- storage, metadata, rotation, corruption
# =============================================================================================
class TestStorage(BrokerBase):
    @control(115)
    def test_nothing_is_stored_in_plaintext(self):
        dpapi_or_skip()
        st = self.provision()
        self.assertTrue(st.usable, st.reason)
        raw = read_bytes(self.blob_path())
        self.assertNotIn(self.secret.encode(), raw)
        self.assertNotIn(self.secret[:16].encode(), raw)
        self.assertGreater(len(raw), 32)
        # And it really is recoverable, or "no plaintext" would be trivially satisfiable by
        # storing nothing at all.
        got, _ = secret_store.load_transient(self.dir)
        self.assertIsNotNone(got)
        self.assertEqual(bytes(got).decode(), self.secret)
        secret_store.wipe_secret(got)

    @control(116)
    def test_metadata_carries_no_secret_derived_material(self):
        dpapi_or_skip()
        self.provision()
        meta = read_json(self.meta_path())
        blob = json.dumps(meta)
        self.assertNotIn(self.secret, blob)
        for n in (4, 6, 8, 12):
            self.assertNotIn(self.secret[:n], blob, "a %d-char prefix leaked" % n)
        import hashlib
        for algo in ("sha256", "sha1", "md5"):
            digest = hashlib.new(algo, self.secret.encode()).hexdigest()
            self.assertNotIn(digest, blob, "%s of the secret is still secret-derived" % algo)
            self.assertNotIn(digest[:16], blob)
        self.assertEqual(set(meta) - {"schema_version", "provider", "protection", "credential_id",
                                      "created_at", "rotated_at", "last_validated_at",
                                      "instrument", "note"}, set())

    @control(117)
    def test_the_default_store_is_outside_both_repositories(self):
        """One half of this was vacuous: PROTECTED_ROOT is a synthetic temp directory now, so
        "the credential store is not inside it" could not have failed. The containment
        predicate is therefore proven to DISCRIMINATE before it is trusted."""
        d = secret_store.default_dir()
        self.assertFalse(cp.path_is_within(d, ROOT), d)
        self.assertFalse(cp.path_is_within(d, PROTECTED_ROOT), d)
        self.assertIn(branding.STATE_DIR_NAME, d)

        # CONTROL ON THE CONTROL. A path that IS inside each root must be reported as inside,
        # or the three assertions above are satisfied by a predicate that answers False to
        # everything.
        self.assertTrue(cp.path_is_within(os.path.join(ROOT, "src"), ROOT))
        self.assertTrue(cp.path_is_within(os.path.join(PROTECTED_ROOT, "anything"),
                                          PROTECTED_ROOT))
        self.assertTrue(cp.path_is_within(os.path.join(d, "blob.bin"), d))

    @control(118)
    def test_a_corrupt_blob_refuses(self):
        dpapi_or_skip()
        self.provision()
        raw = bytearray(read_bytes(self.blob_path()))
        raw[len(raw) // 2] ^= 0xFF
        write_bytes(self.blob_path(), bytes(raw))

        st = secret_store.status(self.dir, deep=True)
        self.assertEqual(st.state, secret_store.CORRUPT)
        self.assertFalse(st.usable)
        got, st2 = secret_store.load_transient(self.dir)
        self.assertIsNone(got)
        self.assertEqual(st2.state, secret_store.CORRUPT)

    @control(119)
    def test_a_blob_from_a_different_context_cannot_be_used(self):
        """Entropy binds the ciphertext to THIS application.

        True cross-USER binding is DPAPI's own property and cannot be exercised without a second
        Windows account; that limit is stated rather than papered over. What is proven here is
        that a blob protected under different additional entropy -- the situation of a copy made
        by another tool, or carried from another app -- is refused rather than accepted.
        """
        dpapi_or_skip()
        # Provision first so METADATA is healthy: the refusal must be attributable to the blob,
        # not to a missing sidecar that would have refused anyway.
        self.provision()
        foreign = dpapi.protect(bytearray(self.secret.encode()), entropy=b"some-other-app/v9")
        write_bytes(self.blob_path(), foreign)
        st = secret_store.status(self.dir, deep=True)
        self.assertEqual(st.state, secret_store.CORRUPT)
        with self.assertRaises(dpapi.DpapiError):
            dpapi.unprotect(foreign)

    @control(120)
    def test_duplicate_provisioning_rotates_deliberately(self):
        dpapi_or_skip()
        first = self.provision()
        second_secret = fake_secret()
        second = self.provision(second_secret)
        self.assertNotEqual(first.credential_id, second.credential_id)
        self.assertTrue(second.detail.get("rotated"))
        self.assertGreater(second.rotated_at, 0.0)
        self.assertEqual(second.created_at, first.created_at,
                         "created_at should record first provisioning, rotated_at the latest")
        got, _ = secret_store.load_transient(self.dir)
        self.assertEqual(bytes(got).decode(), second_secret,
                         "rotation must replace, never leave two active credentials")
        secret_store.wipe_secret(got)
        self.assertEqual(len([n for n in os.listdir(self.dir)
                              if n.endswith(".dpapi")]), 1)

    @control(121)
    def test_a_deleted_credential_yields_owner_required(self):
        dpapi_or_skip()
        self.provision()
        out = secret_store.delete(self.dir)
        self.assertEqual(out["state_now"], secret_store.ABSENT)
        st = secret_store.status(self.dir, deep=True)
        self.assertEqual(st.state, secret_store.ABSENT)
        self.assertFalse(st.usable)
        det = credentials.detect(env={}, seed_present=False, broker_available=st.usable)
        ok, why = credentials.admit_for_mode(det, unattended=True)
        self.assertFalse(ok)
        self.assertIn("no credential provider", why)

    @control(122)
    def test_status_reports_state_without_secret_derived_material(self):
        dpapi_or_skip()
        absent = secret_store.status(self.dir)
        self.assertEqual(absent.state, secret_store.ABSENT)
        self.provision()
        present = secret_store.status(self.dir, deep=True)
        self.assertEqual(present.state, secret_store.PRESENT)
        secret_store.mark_validated(self.dir)
        validated = secret_store.status(self.dir)
        self.assertEqual(validated.state, secret_store.VALIDATED)
        for st in (absent, present, validated):
            blob = json.dumps(st.to_dict())
            self.assertNotIn(self.secret, blob)
            self.assertNotIn(self.secret[:8], blob)

    @control(122)
    def test_a_wrong_provider_or_schema_refuses(self):
        dpapi_or_skip()
        self.provision()
        meta = read_json(self.meta_path())
        meta["provider"] = "SOMETHING_ELSE"
        write_json(self.meta_path(), meta)
        self.assertEqual(secret_store.status(self.dir).state, secret_store.WRONG_PROVIDER)
        meta["provider"] = secret_store.PROVIDER_CLAUDE_OAUTH
        meta["schema_version"] = 99
        write_json(self.meta_path(), meta)
        self.assertEqual(secret_store.status(self.dir).state, secret_store.UNSUPPORTED_SCHEMA)


# =============================================================================================
# 123-130 -- leakage
# =============================================================================================
class TestLeakage(BrokerBase):
    @control(123)
    def test_the_secret_never_enters_command_line_arguments(self):
        profile = cp.ContainerProfile(profile_id="t", image_ref="img",
                                      image_digest="sha256:" + "a" * 64, mounts=())
        argv = profile.docker_create_args("n", ["python3", "-c", "pass"],
                                          env={"SAFE": "value"},
                                          env_passthrough=[secret_store.ENV_VAR])
        joined = "\x00".join(argv)
        self.assertNotIn(self.secret, joined)
        self.assertIn(secret_store.ENV_VAR, argv, "the NAME must be present")
        self.assertNotIn("%s=%s" % (secret_store.ENV_VAR, self.secret), argv)
        for a in argv:
            self.assertFalse(a.startswith(secret_store.ENV_VAR + "="),
                             "name=value form would place the secret in the process table")

    @control(123)
    def test_the_value_travels_in_the_process_environment_instead(self):
        env = secret_store.env_for_child(bytearray(self.secret.encode()))
        self.assertEqual(env, {secret_store.ENV_VAR: self.secret})
        self.assertEqual(list(env), [secret_store.ENV_VAR])

    @control(124)
    def test_the_secret_never_enters_the_durable_store(self):
        from tests import support
        sb = support.Sandbox()
        self.addCleanup(sb.close)
        sb.store.append_event("credential.used", detail={
            "provider": secret_store.PROVIDER_CLAUDE_OAUTH,
            "credential_id": "some-random-id",
            "env": credentials.redact_env({secret_store.ENV_VAR: self.secret})})
        sb.store.add_owner_grant("git_push", note="unrelated")
        raw = read_bytes(sb.db)
        self.assertNotIn(self.secret.encode(), raw)
        rows = sb.store._all("SELECT detail_json FROM event")
        self.assertGreater(len(rows), 0, "the scan inspected zero rows")
        self.assertNotIn(self.secret, "".join(str(r["detail_json"] or "") for r in rows))
        self.assertIn(credentials.REDACTED, "".join(str(r["detail_json"] or "") for r in rows))

    @control(125)
    def test_the_secret_never_enters_json_evidence_or_receipts(self):
        record = {
            "credential": secret_store.status(self.dir).to_dict(),
            "provider": credentials.broker_provider(available=True,
                                                    credential_id="abc").to_dict(),
            "env": credentials.redact_env({secret_store.ENV_VAR: self.secret,
                                           "PATH": "/usr/bin"}),
        }
        blob = json.dumps(record, sort_keys=True)
        self.assertNotIn(self.secret, blob)
        self.assertNotIn(self.secret[:12], blob)
        self.assertIn(credentials.REDACTED, blob)
        self.assertEqual(credentials.scan_for_secrets(blob, {secret_store.ENV_VAR: self.secret}),
                         [])

    @control(126)
    def test_the_secret_never_enters_stdout_or_stderr(self):
        dpapi_or_skip()
        self.provision()
        p = subprocess.run([sys.executable, "-m", CLI_MODULE, "credential", "status",
                            "--deep", "--secret-dir", self.dir],
                           cwd=ROOT, capture_output=True, shell=False, timeout=120,
                           env=cli_env())
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        self.assertNotIn(self.secret, out)
        self.assertNotIn(self.secret[:12], out)
        self.assertIn(secret_store.PRESENT, out)

    @control(127)
    def test_the_secret_never_appears_in_an_exception_string(self):
        dpapi_or_skip()
        with self.assertRaises(dpapi.DpapiError) as ctx:
            dpapi.unprotect(b"not-a-valid-dpapi-blob-at-all")
        self.assertNotIn(self.secret, str(ctx.exception))
        # And a decrypt failure on a REAL blob names the failure, not the payload.
        self.provision()
        foreign = dpapi.protect(bytearray(self.secret.encode()), entropy=b"other")
        with self.assertRaises(dpapi.DpapiError) as ctx2:
            dpapi.unprotect(foreign)
        self.assertNotIn(self.secret, str(ctx2.exception))
        self.assertIn("CryptUnprotectData failed", str(ctx2.exception))

    @control(128)
    def test_retained_container_records_carry_no_secret(self):
        """What the bridge KEEPS from a container must not include the value."""
        profile = cp.ContainerProfile(profile_id="t", image_ref="img",
                                      image_digest="sha256:" + "a" * 64, mounts=())
        argv = profile.docker_create_args("n", ["true"],
                                          env_passthrough=[secret_store.ENV_VAR])
        retained = {"argv": argv, "profile": profile.to_dict()}
        blob = json.dumps(retained)
        self.assertNotIn(self.secret, blob)
        self.assertIn(secret_store.ENV_VAR, blob)

    @control(126)
    def test_the_leakage_scanner_actually_finds_a_planted_value(self):
        """CONTROL ON THE CONTROL. A scanner that finds nothing may be finding nothing.

        The live P4.5 validation run reported `leaked_names: []` beside `scanned_bytes: 975`
        while comparing against an EMPTY needle -- zero comparisons, dressed as a clean result.
        These assertions are the reason that cannot recur silently.
        """
        planted = json.dumps({"stdout": "prefix " + self.secret + " suffix"})
        hit = credentials.scan_value(planted, self.secret)
        self.assertTrue(hit["found"])
        self.assertEqual(hit["compared"], 1)
        self.assertFalse(hit["vacuous"])

        clean = credentials.scan_value(json.dumps({"stdout": "nothing here"}), self.secret)
        self.assertFalse(clean["found"])
        self.assertEqual(clean["compared"], 1)
        self.assertFalse(clean["vacuous"])

        # It scans a wipeable buffer too, so the caller need not make a str copy to check.
        self.assertTrue(credentials.scan_value(planted, bytearray(self.secret.encode()))["found"])

    @control(126)
    def test_an_unscannable_needle_is_vacuous_never_clean(self):
        for needle in ("", "short", b"", bytearray(b"abc")):
            out = credentials.scan_value("some artifact text", needle)
            self.assertTrue(out["vacuous"], repr(needle))
            self.assertEqual(out["compared"], 0)
            self.assertFalse(out["found"])
            self.assertIn("no comparison was made", out["reason"])

    @control(122)
    def test_no_scan_or_probe_result_reports_the_credential_length(self):
        """A length is a property of the credential; the owner forbade partial reveal.

        Asserted on the SHAPE of what leaves these functions, not on a promise in a comment.
        """
        out = credentials.scan_value("x" * 50, self.secret)
        self.assertNotIn("needle_length", out)
        self.assertEqual(set(out) - {"found", "compared", "vacuous", "scannable",
                                     "scanned_bytes", "reason"}, set())
        src = read_text(os.path.join(ROOT, *SRC["credential_validate.py"]))
        self.assertNotIn("token_env_length", src)
        self.assertIn("token_env_present", src)

    @control(126)
    def test_validation_refuses_on_a_vacuous_or_failed_leakage_scan(self):
        """The verdict must not be reachable without a real comparison."""
        src = read_text(os.path.join(ROOT, *SRC["credential_validate.py"]))
        self.assertIn('leak["compared"] > 0', src)
        self.assertIn('argv_leak["compared"] > 0', src)
        self.assertIn("and leak_ok", src)
        self.assertIn("CREDENTIAL_LEAKED_INTO_RETAINED_ARTIFACT", src)
        # It scans the SECRET, not a placeholder.
        self.assertIn("credentials.scan_value(retained_blob, secret)", src)
        self.assertNotIn('{secret_store.ENV_VAR: ""}', src)

    @control(129)
    def test_the_secret_appears_in_no_repository_file(self):
        """Scan the whole project -- tracked, untracked AND var/ evidence -- for the fake value.

        Non-vacuous by construction: the credential is really provisioned and the CLI really runs
        against it first, so the scan inspects artifacts that a leaking implementation would
        actually have written, not an untouched tree.
        """
        dpapi_or_skip()
        self.provision()
        subprocess.run([sys.executable, "-m", CLI_MODULE, "credential", "status",
                        "--deep", "--secret-dir", self.dir],
                       cwd=ROOT, capture_output=True, shell=False, timeout=120,
                           env=cli_env())
        hits, scanned = [], 0
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for n in files:
                p = os.path.join(base, n)
                try:
                    with open(p, "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                scanned += 1
                if self.secret.encode() in data:
                    hits.append(os.path.relpath(p, ROOT))
        self.assertGreater(scanned, 30, "the scan inspected %d files" % scanned)
        self.assertEqual(hits, [])

    @control(130)
    def test_no_temporary_file_retains_the_secret_after_cleanup(self):
        dpapi_or_skip()
        self.provision()
        secret_store.delete(self.dir)
        leftovers = [n for base, _dirs, files in os.walk(self.dir) for n in files
                     if self.secret.encode() in read_bytes(os.path.join(base, n))]
        self.assertEqual(leftovers, [])
        self.assertEqual([n for n in os.listdir(self.dir)], [],
                         "delete should leave no residue in the store directory")


# =============================================================================================
# 131-135 -- fail-closed validation
# =============================================================================================
class TestValidationRefusals(BrokerBase):
    @control(131)
    def test_an_api_key_present_refuses_validation(self):
        out = credential_validate.validate(image_ref=support.test_image("p3"), directory=self.dir,
                                           host_env={"ANTHROPIC_API_KEY": "sk-ant-whatever"})
        self.assertEqual(out["verdict"], credential_validate.REFUSED)
        self.assertEqual(out["reason"], "CONFLICTING_CREDENTIAL_ENV")
        self.assertIn("ANTHROPIC_API_KEY", out["conflicting_vars"])

    @control(132)
    def test_provider_routing_refuses_validation(self):
        for var in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
                    "CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            out = credential_validate.validate(image_ref=support.test_image("p3"), directory=self.dir,
                                               host_env={var: "1"})
            self.assertEqual(out["verdict"], credential_validate.REFUSED, var)
            self.assertIn(var, out["conflicting_vars"])

    @control(131)
    def test_a_missing_credential_yields_owner_required(self):
        out = credential_validate.validate(image_ref=support.test_image("p3"), directory=self.dir,
                                           host_env={})
        self.assertEqual(out["verdict"], credential_validate.OWNER_REQUIRED)
        self.assertEqual(out["reason"], secret_store.ABSENT)

    @control(133)
    def test_a_non_subscription_classification_refuses(self):
        for status, expected in (
                ({"loggedIn": True, "authMethod": "console", "apiProvider": "firstParty"},
                 pf.API_CONSOLE),
                ({"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "bedrock",
                  "subscriptionType": "max"}, pf.THIRD_PARTY),
                ({"loggedIn": False}, pf.LOGGED_OUT),
                (None, pf.UNVERIFIED)):
            cls, _ = pf.classify_auth(status)
            self.assertEqual(cls, expected)
            self.assertNotEqual(cls, pf.SUBSCRIPTION)

    @control(133)
    def test_the_brokered_token_shape_classifies_as_subscription(self):
        """The record a real brokered token produces, and the shapes next to it that must not.

        Fixture bytes copied from the CLI's own output (2.1.185), not constructed to fit the
        classifier -- the whole point of the branch under test is that a real credential produced
        a field this project had never seen.
        """
        real = {"apiProvider": "firstParty", "authMethod": "oauth_token", "loggedIn": True}
        cls, detail = pf.classify_auth(real)
        self.assertEqual(cls, pf.SUBSCRIPTION, detail)

        # DISCRIMINATING NEGATIVES -- the branch must not have become a blanket accept.
        for status, expected in (
                # Provider must be stated. Absent != first-party.
                ({"authMethod": "oauth_token", "loggedIn": True}, pf.UNVERIFIED),
                ({"apiProvider": "", "authMethod": "oauth_token", "loggedIn": True},
                 pf.UNVERIFIED),
                # Third-party routing still wins, regardless of method.
                ({"apiProvider": "bedrock", "authMethod": "oauth_token", "loggedIn": True},
                 pf.THIRD_PARTY),
                ({"apiProvider": "vertex", "authMethod": "oauth_token", "loggedIn": True},
                 pf.THIRD_PARTY),
                # Logged out still wins.
                ({"apiProvider": "firstParty", "authMethod": "oauth_token", "loggedIn": False},
                 pf.LOGGED_OUT),
                # An API key with the SAME provider is still refused -- the gate's whole purpose.
                ({"apiProvider": "firstParty", "authMethod": "console", "loggedIn": True},
                 pf.API_CONSOLE),
                ({"apiProvider": "firstParty", "authMethod": "apiKey", "loggedIn": True},
                 pf.API_CONSOLE),
                # An unknown future method is still UNVERIFIED: the branch is by name, not by
                # "anything first-party".
                ({"apiProvider": "firstParty", "authMethod": "something_new", "loggedIn": True},
                 pf.UNVERIFIED)):
            got, why = pf.classify_auth(status)
            self.assertEqual(got, expected, "%r -> %s (%s)" % (status, got, why))

    @control(134)
    def test_the_recorded_live_verdict_still_holds(self):
        """Replay the REAL run's evidence through the current classifier and gate.

        The fixture was written by a live validation against the owner-provisioned credential;
        `auth_record` inside it came from the Claude CLI, not from this project. If a later edit
        to `classify_auth` would change the answer for the credential actually in use, this fails
        here rather than in production.
        """
        ev = read_json(os.path.join(ROOT, "tests", "fixtures", "p45_credential_evidence.json"))
        self.assertEqual(ev["verdict"], "PASS")

        cls, _ = pf.classify_auth(ev["auth_record"])
        self.assertEqual(cls, pf.SUBSCRIPTION)
        self.assertTrue(pf.decide(env={}, auth_status=ev["auth_record"],
                                  provider_injected=[secret_store.ENV_VAR]).accepted)

        # The recorded leakage scan must be NON-VACUOUS, or the recorded PASS means nothing.
        for surface in ("retained_artifacts", "argv"):
            s = ev["leakage_scan"][surface]
            self.assertEqual(s["compared"], 1, surface)
            self.assertFalse(s["vacuous"], surface)
            self.assertFalse(s["found"], surface)
            self.assertGreater(s["scanned_bytes"], 100, surface)

        # The environment the verdict binds to, stated in the verdict itself.
        self.assertIn("2.1.185", ev["claude_version"])
        self.assertEqual(ev["container"]["actual_verdict"], "CONTAINER_POLICY_OK")
        self.assertTrue(ev["ephemeral_home"])
        self.assertFalse(ev["auth_seed_mounted"])
        self.assertTrue(ev["token_env_present_in_child"])
        self.assertFalse(any(ev["conflicts_in_child"].values()))
        # The known, measured exposure is RECORDED rather than claimed closed.
        self.assertTrue(ev["daemon_env_exposure"]["value_readable_via_docker_inspect"])

    @control(133)
    def test_the_validation_evidence_names_the_fields_it_saw(self):
        """A refusal that cannot say WHICH fields were present is not actionable.

        This is the instrument defect the live run exposed: `redact_auth` is an allowlist, so a
        field it has never heard of vanishes from the record that explains the refusal.
        """
        src = read_text(os.path.join(ROOT, *SRC["credential_validate.py"]))
        self.assertIn("auth_status_keys", src)
        self.assertIn("sorted(status.keys())", src)
        # NAMES only -- a values dump would put identity fields into evidence.
        self.assertNotIn("json.dumps(status)", src)

    @control(133)
    def test_a_subscription_classification_is_accepted_with_the_injected_token(self):
        """Control on the control: the gate must be openable by the intended credential."""
        d = pf.decide(env={secret_store.ENV_VAR: "x"},
                      auth_status={"loggedIn": True, "authMethod": "claude.ai",
                                   "apiProvider": "firstParty", "subscriptionType": "max"},
                      provider_injected=[secret_store.ENV_VAR])
        self.assertTrue(d.accepted, d.reason)
        self.assertEqual(d.auth_class, pf.SUBSCRIPTION)

    @control(134)
    def test_the_validation_profile_is_ephemeral_and_seedless(self):
        profile = credential_validate.validation_profile("sha256:" + "a" * 64,
                                                         image_ref="img", network="bridge")
        targets = {m.container_path: m for m in profile.mounts}
        self.assertIn("/home/claude", targets)
        self.assertEqual(targets["/home/claude"].kind, cp.TMPFS)
        # The CURRENT seed path. Asserting the absence of the pre-extraction one was vacuous:
        # nothing in the platform can emit it any more, so the assertion could not fail.
        self.assertNotIn(credentials.seed_provider("v").mount_path, targets)
        self.assertNotIn("/workspace", targets)
        self.assertTrue(profile.read_only_rootfs)
        self.assertEqual(profile.cap_drop, ("ALL",))
        for m in profile.mounts:
            self.assertEqual(m.kind, cp.TMPFS, "the validation child binds no host path at all")

    @control(135)
    def test_transient_plaintext_is_wiped(self):
        buf = bytearray(self.secret.encode())
        self.assertIn(b"FAKE-oat-", bytes(buf))
        secret_store.wipe_secret(buf)
        self.assertEqual(bytes(buf), b"\x00" * len(buf))
        self.assertNotIn(b"FAKE-oat-", bytes(buf))

    @control(135)
    def test_load_transient_returns_a_wipeable_buffer_not_a_string(self):
        dpapi_or_skip()
        self.provision()
        got, _ = secret_store.load_transient(self.dir)
        self.assertIsInstance(got, bytearray, "a str could not be wiped by any caller")
        secret_store.wipe_secret(got)
        self.assertEqual(bytes(got), b"\x00" * len(got))


# =============================================================================================
# 136 -- provider precedence
# =============================================================================================
class TestProviderPrecedence(unittest.TestCase):
    @control(136)
    def test_the_broker_outranks_the_legacy_seed(self):
        det = credentials.detect(env={}, seed_volume="quaestor-claude-auth-seed",
                                 seed_present=True, broker_available=True,
                                 broker_credential_id="cid-123")
        self.assertEqual(det["selected"], credentials.EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN)
        self.assertTrue(det["unattended_production_ready"])
        ok, _ = credentials.admit_for_mode(det, unattended=True)
        self.assertTrue(ok)

    @control(136)
    def test_the_seed_alone_still_refuses_unattended_production(self):
        det = credentials.detect(env={}, seed_volume="v", seed_present=True,
                                 broker_available=False)
        self.assertEqual(det["selected"], credentials.READ_ONLY_CREDENTIAL_SEED)
        self.assertFalse(det["unattended_production_ready"])
        ok, why = credentials.admit_for_mode(det, unattended=True)
        self.assertFalse(ok)
        self.assertIn("OWNER_REQUIRED", why)

    @control(136)
    def test_the_broker_provider_description_names_no_secret(self):
        p = credentials.broker_provider(available=True, credential_id="cid-123")
        blob = json.dumps(p.to_dict())
        self.assertIn("cid-123", blob)
        self.assertIn(secret_store.ENV_VAR, blob)
        self.assertEqual(p.persistence, "DPAPI blob, transient injection")
        self.assertTrue(p.unattended_production_ready)


if __name__ == "__main__":
    unittest.main()

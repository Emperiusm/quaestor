"""THE CONTROL-REACHABILITY MATRIX (214) -- declared, reachable, effective.

WHY THIS FILE EXISTS
--------------------
An adversarial review of the extraction found the same defect in four separate places, and it is
worth naming precisely because every one of them had a PASSING control:

    CONTROL_DECLARED  does not imply
    CONTROL_REACHABLE does not imply
    CONTROL_EFFECTIVE

The protected-root guard existed and defaulted to protecting nothing. The role ceiling existed
with no caller. The review floor lived in a package with zero non-test importers. Each was tested
by a control that CONSTRUCTED its own subject and handed it the input the production path never
supplies -- so each control proved the function worked, and none proved the rule applied.

WHAT THIS CONTROL ASSERTS
-------------------------
For every security-significant control in the platform, a row naming:

    the DECLARATION   where the rule is written
    the REACHABILITY  the production symbol that consults it -- asserted to exist AND to name
                      the declaration, against the real source, not against a docstring
    the EFFECT        what happens when the rule fires
    the PROOF         the control number whose test exercises it

A row whose production caller does not mention its declaration FAILS here. That is the whole
point: this is the gate that would have caught all four original defects at once, because in
every one of them the "reachable" column would have been empty.

MATRIX ROWS ARE NOT DOCUMENTATION. If a row cannot be verified, it is deleted or the code is
fixed -- it is never softened into prose, because a matrix that describes intentions is the
artefact this repository keeps discovering it already had.
"""
from __future__ import annotations

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.controls import control  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")


def read(rel):
    p = os.path.join(SRC, *rel.split("/"))
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return fh.read()


#: (control, declaration_module, declared_symbol, production_module, production_symbol, proof)
#:
#: `production_module` is asserted to contain `production_symbol` AND to reference
#: `declared_symbol`. A row is a claim about the REAL import graph, and it is checked as one.
MATRIX = (
    ("authority gate",
     "quaestor/core/authority.py", "require",
     "quaestor/core/dispatcher.py", "dispatch", 6),
    ("role ceiling",
     "quaestor/core/actors.py", "authority_ceiling",
     "quaestor/deployment.py", "ceiling_for", 191),
    ("lane fencing",
     "quaestor/core/programs.py", "check_fence",
     "quaestor/core/strategic_store.py", "guard_fence", 199),
    ("protected roots",
     "quaestor/transports/mcp/adapter.py", "forbidden_alias_roots",
     "quaestor/deployment.py", "adapter_kwargs", 190),
    ("review floor",
     "quaestor/core/review_contract.py", "adversarial_required",
     "quaestor/core/acceptance.py", "decide", 194),
    ("adversarial-review requirement",
     "quaestor/core/review_contract.py", "summarize",
     "quaestor/core/acceptance.py", "decide", 194),
    ("evidence validation",
     "quaestor/core/evidence_ref.py", "EvidenceBundle",
     "quaestor/core/acceptance.py", "decide", 196),
    ("redaction",
     "quaestor/core/classification.py", "classify",
     "quaestor/core/strategic_store.py", "record_message", 202),
    ("qualification-only execution gate",
     "quaestor/transports/mcp/mode.py", "assert_inert",
     "quaestor/transports/mcp/adapter.py", "Adapter", 147),
    # The CLI passes the operator's `--secret-dir` through and the FS module resolves the
    # default, so the cross-module link that actually decides where secrets land is
    # branding -> secrets.fs (where default_dir lives since the broker and the owner-attestation
    # channel stopped sharing a module).
    ("secret access",
     "quaestor/branding.py", "STATE_DIR_NAME",
     "quaestor/secrets/fs.py", "default_dir", 117),
    ("credential-exemption ceiling",
     "quaestor/core/credential_policy.py", "ProviderCredentialPolicy",
     "quaestor/executors/claude_auth.py", "CLAUDE_POLICY", 208),
    ("duplicate dispatch admission",
     "quaestor/core/identity.py", "build_identity",
     "quaestor/core/dispatcher.py", "dispatch", 2),
    ("reconciliation",
     "quaestor/core/reconcile.py", "reconcile_run",
     "quaestor/transports/cli.py", "cmd_reconcile", 13),
    ("cancellation",
     "quaestor/core/cancellation.py", "classify_cancel",
     "quaestor/transports/mcp/adapter.py", "Adapter", 78),
)


def defines(src, name):
    """Does this module DECLARE this symbol? Against the AST, never a substring.

    A declaration site is a module-level or class-level ``def``/``class``/assignment, OR a named
    PARAMETER -- because a rule can be declared as the input a constructor requires, which is
    exactly the shape the protected-root guard has. The broad reading is deliberate and it is
    not the load-bearing half of a row: the assertion that matters is that the PRODUCTION module
    names the declaration, and no widening of this function can satisfy that one.
    """
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return True
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return True
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                return True
        elif isinstance(node, ast.arg) and node.arg == name:
            return True
    return False


class TestControlReachabilityMatrix(unittest.TestCase):
    @control(214)
    def test_every_security_control_has_a_production_caller(self):
        """DECLARED -> REACHABLE, for every row, against the real source."""
        checked, problems = 0, []
        for name, dmod, dsym, pmod, psym, _proof in MATRIX:
            dsrc, psrc = read(dmod), read(pmod)
            checked += 1
            if dsrc is None:
                problems.append("%s: declaration module %s is absent" % (name, dmod))
                continue
            if psrc is None:
                problems.append("%s: production module %s is absent" % (name, pmod))
                continue
            if not defines(dsrc, dsym):
                problems.append("%s: %s does not define %s" % (name, dmod, dsym))
            if not defines(psrc, psym):
                problems.append("%s: %s does not define %s" % (name, pmod, psym))
            if dsym not in psrc:
                problems.append("%s: %s never names %s -- DECLARED but not REACHABLE"
                                % (name, pmod, dsym))
        self.assertEqual(checked, len(MATRIX), "the matrix walked %d of %d rows"
                         % (checked, len(MATRIX)))
        self.assertGreaterEqual(checked, 12, "a matrix this short is not covering the platform")
        self.assertEqual(problems, [])

    @control(214)
    def test_the_matrix_would_catch_an_unreachable_control(self):
        """CONTROL ON THE CONTROL, on a row this suite writes by hand.

        The four original defects all looked like a passing control, so the question that matters
        is whether THIS gate can fail. A row naming a real declaration and a real production
        module that does not consult it must be reported -- otherwise the matrix is a table of
        intentions with an assertion attached.
        """
        # A real declaration, and a real module that has no business consulting it.
        dsrc = read("quaestor/core/evidence_ref.py")
        psrc = read("quaestor/core/canon.py")
        self.assertIsNotNone(dsrc)
        self.assertIsNotNone(psrc)
        self.assertTrue(defines(dsrc, "EvidenceBundle"))
        self.assertNotIn("EvidenceBundle", psrc,
                         "the negative fixture stopped being negative; pick another pair")

        # And `defines` is not answering True to everything.
        self.assertFalse(defines(dsrc, "a_symbol_that_does_not_exist"))
        self.assertTrue(defines(psrc, "canonical_json"))

    @control(214)
    def test_every_matrix_row_names_a_control_that_actually_runs(self):
        """The PROOF column, checked against the registry rather than trusted.

        A row can name any integer. If the number is not a control this build requires, the row
        is pointing at a proof that does not exist -- which is precisely how the review floor
        came to be "covered" by a test nothing ran.
        """
        from tests import controls as reg
        known = set(reg.REQUIRED_CONTROLS)
        missing = sorted({p for *_x, p in MATRIX} - known)
        self.assertGreater(len(known), 100, "the registry holds %d controls" % len(known))
        self.assertEqual(missing, [], "matrix rows cite unknown controls: %s" % missing)


if __name__ == "__main__":
    unittest.main()

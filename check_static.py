#!/usr/bin/env python3
"""check_static.py -- syntax, unused imports, and this project's OWN hard invariants.

No third-party linter is installed and none is added: a control plane that exists to avoid
supply-chain surface should not acquire a dependency to check itself. `ast` is enough for what
actually matters here, and the last four checks are things no general-purpose linter knows to
look for:

  * ``shell=True``            -- never, anywhere. Argument arrays only.
  * ``text=True`` on subprocess -- decodes with the locale codepage on Windows (cp1252 here), so
                                 every non-ASCII byte comes back mojibake. It was measured that this
                                 corrupting its ledger. Decode UTF-8 explicitly.
  * permission-bypass flags   -- may appear ONLY in the FORBIDDEN_FLAGS declaration and in tests.
  * bare ``except:``          -- swallows KeyboardInterrupt and SystemExit.

It emits a COUNT OF WHAT IT INSPECTED and refuses to pass over an empty file set, for the same
reason every other gate in this project does.
"""
from __future__ import annotations

import ast
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
MIN_FILES = 15

BYPASS_FLAGS = ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "--bare")
#: Files permitted to MENTION a bypass flag, because each one reasons about it rather than using
#: it: the adapter that refuses the flags, the checker itself, the docs that explain them, and the
#: tests that ASSERT their absence. Everything else naming one is a finding. The allowlist is
#: per-file and deliberately short -- widening it is how this check would quietly stop mattering.
BYPASS_ALLOWED_IN = ("src/quaestor/executors/claude_code.py",
                     "src/quaestor/executors/container.py",
                     "tests/test_units.py", "tests/test_p25_controls.py", "check_static.py",
                     "docs/DESIGN.md", "docs/RUNBOOK.md", "docs/ARCHITECTURE.md")


def python_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in ("var", "__pycache__", ".git", "fixtures")]
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(base, f)


def rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def unused_imports(tree, source):
    """Module-level imported names never referenced elsewhere in the file."""
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                name = (a.asname or a.name).split(".")[0]
                imported[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            # `from __future__ import annotations` binds a name that is never referenced BY
            # DESIGN -- it is a compiler directive, not a value. Flagging it would train the
            # reader to ignore this check's output, which is how a linter becomes decorative.
            if node.module == "__future__":
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                imported[a.asname or a.name] = node.lineno

    used = set()
    # A name listed in ``__all__`` is a DELIBERATE re-export: the module exists partly to publish
    # it, and the only reference is the export list itself. Without this the check punishes the
    # correct way to declare a public surface, which is how a linter gets switched off.
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)):
            for el in ast.walk(node.value):
                if isinstance(el, ast.Constant) and isinstance(el.value, str):
                    used.add(el.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name):
                used.add(n.id)
    # A name mentioned in a docstring/annotation string still counts as used.
    return [(n, ln) for n, ln in sorted(imported.items())
            if n not in used and ('"%s"' % n) not in source and ("'%s'" % n) not in source]


def main() -> int:
    findings = []
    inspected = 0

    for path in python_files():
        inspected += 1
        r = rel(path)
        with open(path, "rb") as fh:
            source = fh.read().decode("utf-8")
        try:
            tree = ast.parse(source, filename=r)
        except SyntaxError as exc:
            findings.append({"file": r, "line": exc.lineno, "kind": "SYNTAX_ERROR",
                             "detail": str(exc)})
            continue

        for name, line in unused_imports(tree, source):
            findings.append({"file": r, "line": line, "kind": "UNUSED_IMPORT", "detail": name})

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append({"file": r, "line": node.lineno, "kind": "BARE_EXCEPT",
                                 "detail": "bare except swallows KeyboardInterrupt/SystemExit"})
            if isinstance(node, ast.keyword) and node.arg in ("shell", "text"):
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    findings.append({
                        "file": r, "line": getattr(node.value, "lineno", 0),
                        "kind": "SHELL_TRUE" if node.arg == "shell" else "SUBPROCESS_TEXT_TRUE",
                        "detail": "%s=True" % node.arg})

        if r not in BYPASS_ALLOWED_IN:
            for flag in BYPASS_FLAGS:
                if flag in source:
                    findings.append({"file": r, "line": 0, "kind": "PERMISSION_BYPASS_FLAG",
                                     "detail": flag})

    problems = list(findings)
    if inspected < MIN_FILES:
        problems.append({"file": "-", "line": 0, "kind": "VACUOUS",
                         "detail": "inspected %d files, floor is %d" % (inspected, MIN_FILES)})

    report = {"verdict": "PASS" if not problems else "FAIL",
              "inspected_files": inspected, "floor": MIN_FILES,
              "findings": problems, "finding_count": len(problems)}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())

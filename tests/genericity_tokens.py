"""genericity_tokens -- the ONE file permitted to spell the origin's names.

A denylist has to name what it denies. That single fact makes the file holding it unscannable by
its own rule, and the tempting fix -- exempting whichever file the scan happens to live in -- is
how the previous version of this control came to certify only the directory that had already been
cleaned.

So the declaration is isolated here, this file alone is exempt, and it contains NOTHING else. Any
occurrence of these tokens in any other file, including the control that imports them and
including the platform source, is a failure.
"""
from __future__ import annotations

#: The private repository this platform was extracted from, the operator's account, and the
#: machine layout. None of them may appear anywhere else in the tree.
FORBIDDEN_TOKENS = ("aegis", "slabl", "emperiusm")

#: FROZEN WIRE VALUES, exempt BY VALUE wherever they appear. One salts every dispatch key; the
#: other is a protocol marker already written into artifacts. Renaming either would change
#: identities that already exist, so they are history rather than branding.
FROZEN_LITERALS = ("AEGIS_ORCHESTRATOR_DISPATCH_KEY_v1", "AEGIS_ORCHESTRATOR_HANDOFF")

#: This module's own path, relative to the repository root, as the scan will see it.
DECLARATION_FILE = "tests/genericity_tokens.py"

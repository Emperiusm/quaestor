"""The test package. Importing it points the suite at THIS checkout and quiets it on Windows.

WHICH ``quaestor`` A TARGETED RUN IMPORTS
-----------------------------------------
An editable install writes a ``.pth`` naming ONE checkout's ``src``, and a lane is normally
developed in a git worktree -- a different checkout of the same repository. Nothing else puts the
running checkout's ``src`` ahead of that ``.pth``, so ``python -m unittest tests.whatever`` from a
worktree imports the OTHER tree's product and reports a verdict about code this tree does not
contain: a false failure for a lane that adds a symbol, and the far worse case for a lane that
only adds tests to an existing module -- a GREEN run against the wrong source. ``run_tests.py``
fixes its own ``sys.path`` and cannot fix anyone else's, and the argument below about the runner
applies here word for word: the package every test module imports is the one place that cannot be
bypassed.

WHY THE CONSOLE FIX IS HERE AND NOT IN THE RUNNER
-------------------------------------------------
This suite refuses to mock the things that matter, so it makes a few hundred real subprocess
calls: git, python import probes, detached Cores, container controls. On Windows every one of
them is a console application, and Windows gives a console application its own window -- so a
full run throws a window on the operator's screen every few seconds for the length of the run,
on top of whatever they are actually doing.

That is not cosmetic. A gate people avoid running is a gate that stops catching things, and the
first place this was fixed -- inside ``run_tests.py``'s ``main`` -- covered the gate and left
``python -m unittest tests.test_whatever`` as noisy as before, which is how the suite is
actually run while working. The package every test module imports is the one place that cannot
be bypassed.

ADDITIVE, AND ONLY WHERE THE CALLER EXPRESSED NO OPINION. A call that already sets
``creationflags`` -- ``core.proc.spawn_detached_kwargs`` above all -- passes through exactly as
written, so nothing the suite measures about how the product detaches a process is altered by
the act of measuring it. Set ``QUAESTOR_TEST_CONSOLES=1`` to watch the windows again.
"""
from __future__ import annotations

import os
import sys

#: This checkout's own ``src``, ahead of any editable-install ``.pth`` pointing at another one.
#: Prepended at IMPORT of the test package, before any module in it has imported ``quaestor``.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "src"))

#: Windows CREATE_NO_WINDOW. Named rather than repeated as a magic number.
CREATE_NO_WINDOW = 0x08000000


def quiet_consoles() -> bool:
    """Suppress the console window Windows gives each child. Impure. NEVER raises. Idempotent."""
    if os.name != "nt" or os.environ.get("QUAESTOR_TEST_CONSOLES"):
        return False
    import subprocess
    if getattr(subprocess.Popen, "_quaestor_quiet", False):
        return True
    original = subprocess.Popen.__init__

    def __init__(self, *args, **kwargs):
        if not kwargs.get("creationflags"):
            kwargs["creationflags"] = CREATE_NO_WINDOW
        return original(self, *args, **kwargs)

    __init__._quaestor_quiet = True                      # noqa: B010
    subprocess.Popen.__init__ = __init__
    subprocess.Popen._quaestor_quiet = True              # noqa: B010
    return True


QUIETED = quiet_consoles()

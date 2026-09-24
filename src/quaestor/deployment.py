"""deployment -- the production path that WIRES the platform's controls to a project.

WHY THIS MODULE EXISTS
----------------------
An adversarial review of the extraction found the same defect in four places, and it is worth
naming precisely because it is the most expensive kind:

    CONTROL_DECLARED  does not imply
    CONTROL_REACHABLE does not imply
    CONTROL_EFFECTIVE

The protected-root guard existed and defaulted to protecting nothing, with the configuration that
was supposed to supply it parsed and never read. The role ceiling existed with no caller. The
review floor existed in a package nothing imported. Every one of them had a passing control,
because each control constructed the object it was testing and handed it the input the production
path never supplies.

This module is the production path. It builds a deployment FROM a project manifest, and it is the
thing transports and drivers are supposed to construct. If a control is not reachable from here,
it is not protecting anything.

FAIL-CLOSED, DELIBERATELY
-------------------------
If the manifest cannot establish a safety boundary, this refuses to build. A deployment that
silently degrades to "protect nothing" is worse than one that will not start, because the first is
discovered after the damage and the second before it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Sequence

from quaestor.core import actors as actors_mod
from quaestor.projects import config as proj_cfg
from quaestor.core import review_contract as review_mod

DEPLOYMENT_INSTRUMENT = "deployment/1"

# Refusal reasons
NO_CONFIG = "DEPLOYMENT_NO_PROJECT_CONFIG"
UNSAFE_ROOTS = "DEPLOYMENT_UNSAFE_PROTECTED_ROOTS"
UNSAFE_REPOSITORY = "DEPLOYMENT_UNSAFE_REPOSITORY"

#: A protected-root entry that is obviously a placeholder rather than a real boundary. Shipping
#: examples contain these on purpose; a REAL deployment that still names one has not been
#: configured, and treating it as protection would be a lie the platform tells itself.
PLACEHOLDER_MARKERS = ("/path/to/", "<", "example.com", "changeme", "TODO")


@dataclass(frozen=True)
class Deployment:
    """A project, resolved into the concrete inputs every control actually needs."""

    project: proj_cfg.ProjectConfig
    protected_roots: tuple
    repo_table: Mapping
    strict: bool = True
    instrument: str = DEPLOYMENT_INSTRUMENT

    def to_dict(self) -> dict:
        return {"project": self.project.name, "repository": self.project.repository,
                "protected_roots": list(self.protected_roots),
                "repo_aliases": sorted(self.repo_table),
                "strict": self.strict, "instrument": self.instrument}

    # -- the wiring the controls were missing ---------------------------------------------------
    def adapter_kwargs(self) -> dict:
        """Exactly what ``transports.mcp.adapter.Adapter`` needs to be SAFE.

        The transport's protected-root guard is only as good as what it is handed, and nothing
        was handing it anything. This is that thing.
        """
        return {"repo_table": dict(self.repo_table),
                "forbidden_alias_roots": tuple(self.protected_roots)}

    def ceiling_for(self, actor: actors_mod.Actor, requested: Sequence[str]) -> tuple:
        """Apply the role ceiling. The production caller ``authority_ceiling`` never had."""
        return actors_mod.authority_ceiling(actor, requested)

    def review_required(self, change_classes: Sequence[str]) -> tuple:
        """(required, matched). The floor, widened by project config, never narrowed by it."""
        policy = {"required_for": self.project.adversarial_required_for}
        return review_mod.adversarial_required(change_classes, policy)


def _looks_like_placeholder(p: str) -> bool:
    low = str(p).lower()
    return any(m.lower() in low for m in PLACEHOLDER_MARKERS)


def build(config_path: str = "", *, start: str = ".", strict: bool = True,
          allow_unprotected: bool = False) -> tuple:
    """(Deployment|None, reason). Impure (reads the manifest). NEVER raises.

    ``strict`` is the default and means: refuse rather than degrade. ``allow_unprotected`` is the
    single, explicit, named way to run a deployment that protects no root -- appropriate for a
    synthetic fixture, never for a real repository, and it has to be TYPED by a human rather than
    arrived at by omission.
    """
    cfg, reason = (proj_cfg.load(config_path) if config_path
                   else proj_cfg.load_nearest(start))
    if cfg is None:
        return None, "%s: %s" % (NO_CONFIG, reason)

    roots, placeholders = [], []
    for p in cfg.protected_roots:
        if _looks_like_placeholder(p):
            placeholders.append(p)
            continue
        roots.append(os.path.abspath(p).replace("\\", "/").rstrip("/"))

    if strict and placeholders:
        return None, ("%s: %s names placeholder protected root(s) %s. A placeholder is not a "
                      "boundary; replace it or pass allow_unprotected=True deliberately."
                      % (UNSAFE_ROOTS, cfg.source_path, placeholders))
    if strict and not roots and not allow_unprotected:
        return None, ("%s: %s declares no protected roots. The platform cannot know which "
                      "repositories must never be exposed, and defaulting to 'none' would make "
                      "the transport's guard vacuous. Declare security.protected_roots, or pass "
                      "allow_unprotected=True for a disposable fixture."
                      % (UNSAFE_ROOTS, cfg.source_path))

    repo = cfg.repository.replace("\\", "/").rstrip("/")
    if not repo:
        return None, "%s: project.repository is empty" % UNSAFE_REPOSITORY
    for r in roots:
        if repo.lower() == r.lower() or repo.lower().startswith(r.lower() + "/"):
            return None, ("%s: the project's own repository %s lies inside protected root %s, so "
                          "no alias could ever be built for it. Protected roots name what this "
                          "deployment must NOT reach." % (UNSAFE_REPOSITORY, repo, r))

    alias = "".join(c if (c.isalnum() or c in "-_") else "-" for c in cfg.name).strip("-") or "repo"
    return Deployment(project=cfg, protected_roots=tuple(roots),
                      repo_table={alias: repo}, strict=strict), ""

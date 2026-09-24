"""projects -- how a repository tells the platform about itself.

THE RULE THIS FILE ENFORCES
---------------------------
The core knows no project. Everything a project needs to say -- where it is, how to test it, what
authority it will tolerate, what must be reviewed, which roots must never be exposed -- arrives
through this manifest. If the core ever needs a new fact about a project, the fact belongs here,
not in an ``if project == ...``.

SMALL, WITH DEFAULTS THAT ARE SAFE RATHER THAN CONVENIENT
---------------------------------------------------------
A manifest that must be filled in completely before anything works is a manifest nobody writes.
So every key has a default, and the defaults are the RESTRICTIVE ones: read-only authority,
adversarial review on, no protected-root exemptions. A project opens things up deliberately, and
that opening is a diff someone can review.

NO YAML DEPENDENCY
------------------
The parser accepts a small, explicit subset of YAML and also plain JSON. Standard library only is
a deliberate constraint of this platform, and a config format is not worth a dependency -- but a
subset parser must be honest about being one, so it REFUSES what it does not understand instead of
guessing. A silently mis-parsed authority list is exactly the wrong thing to be relaxed about.

TOML IS THE PRIMARY FORMAT (PRD.md §47.1)
-----------------------------------------
PRD.md §47.1: "TOML is preferred as a simple standard primary format where practical; YAML may
remain a compatibility input if existing deployments need it." So ``quaestor.toml`` now
WINS discovery over ``quaestor.yaml`` (precedence lives in CONFIG_NAMES' order), and a ``.toml``
path is parsed with ``tomllib`` into the SAME mapping shape the YAML subset produces -- one
semantic model, two syntaxes, proven equal by the parity controls. During the one-release
compatibility window both must behave identically for equivalent documents; when the window
closes, the YAML subset parser is deletable without touching anything else.

tomllib errors name line/column and semantic refusals below name the offending key; either way
a manifest that will not parse says WHICH of its words is the problem.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Mapping

from quaestor.adapters import registry as cap_registry
from quaestor.core import authority as authority_mod

PROJECT_INSTRUMENT = "projects/1"

CONFIG_NAMES = ("quaestor.toml", "quaestor.yaml", "quaestor.yml", "quaestor.json",
                ".quaestor.yaml")
# PRD.md §47.1: TOML is the PRIMARY format, so it must also win DISCOVERY when both exist --
# otherwise a repository migrated to quaestor.toml would silently keep running on a stale
# quaestor.yaml and the two would drift apart unnoticed. First match in this tuple wins.

# Refusal reasons
CONFIG_MISSING = "PROJECT_CONFIG_MISSING"
CONFIG_MALFORMED = "PROJECT_CONFIG_MALFORMED"
CONFIG_REFUSED = "PROJECT_CONFIG_REFUSED"

# PRD.md §7.1 (the Role x Provider matrix): the seats assignable to any capable
# provider via ``executors.roles``. THE DECLARATION LIVES IN adapters.registry AND IS ALIASED
# HERE -- it used to be retyped, and the two copies disagreed the moment STRATEGIST was added:
# this file parsed the seat and the router then refused it as non-existent. Importing costs
# nothing (that module holds provider DATA and loads no vendor code) and makes the disagreement
# unrepresentable rather than merely tested for.
#
# OWNER is absent from it, so a manifest naming ``executors.roles.owner`` is refused at parse
# time rather than silently becoming an executable seat.
ASSIGNABLE_ROLES = cap_registry.ASSIGNABLE_SEATS


@dataclass(frozen=True)
class ProjectConfig:
    name: str
    repository: str
    executor: str = "fake"
    #: PRD.md §7: per-seat executor pins from ``executors.roles`` -- ONLY the
    #: roles the manifest actually pins. A seat absent here resolves to ``executor`` at
    #: dispatch time (see orchestrator._resolve_executor), which is what keeps the fallback
    #: observable and the provenance source ("roles-config" vs "default-config") decidable.
    role_executor: Mapping[str, str] = field(default_factory=dict)
    #: PRD.md §7.3 / P2.7 (PAI-Bus): per-seat ORDERED provider chains -- preferred
    #: first, fallbacks after, so a quota wall or outage does not stop the program. Failover
    #: itself is reconciliation-aware and lives in adapters.registry.chain_next; this field
    #: only carries the configured order. A seat absent here has no chain.
    role_chains: Mapping[str, tuple] = field(default_factory=dict)
    #: Per-seat failover policy. Today exactly one value exists, "availability_only": never
    #: switch across an AMBIGUOUS write. Anything else is REFUSED at parse time rather than
    #: silently meaning something weaker.
    role_fallback_policy: Mapping[str, str] = field(default_factory=dict)
    #: PRD.md §7.2 pairing policy (epistemic independence). Pairwise form: role pairs that never
    # share a provider family (INCLUDING via chain fallback). Risk-class form: candidates
    #: touching these classes escalate distinct-provider from policy preference to an
    #: admission REQUIREMENT. Enforcement is adapters.registry.check_pairing at admission,
    #: over MEASURED run.provenance seats -- parsing only carries the policy.
    independence_pairs: tuple = ()
    independence_risk_classes: tuple = ()
    #: PRD.md §7.5 seat policy, from ``executors.policy``. Declared by the operator and
    #: ENFORCED AT DISPATCH (orchestrator._seat_spec via adapters.registry.constraint_refusals).
    #: It existed as a resolver argument with no manifest surface and no production caller, so a
    #: deployment could not actually require, say, subscription-billed seats -- which two modules'
    #: docstrings nonetheless promised it could.
    seat_policy: Mapping[str, tuple] = field(default_factory=dict)
    workspace_provider: str = "git-worktree"
    sandbox_provider: str = "none"
    test_commands: tuple = ()
    default_authority: tuple = (authority_mod.READ_ONLY,)
    adversarial_review: bool = True
    adversarial_required_for: tuple = ()
    required_evidence: tuple = ("git_head", "git_status", "test_results")
    #: Roots this deployment refuses to expose through any transport alias. The platform ships
    #: with NONE -- it cannot know your machine -- so a project that wants protection says so.
    protected_roots: tuple = ()
    source_path: str = ""
    instrument: str = PROJECT_INSTRUMENT

    def to_dict(self) -> dict:
        return {"name": self.name, "repository": self.repository, "executor": self.executor,
                "role_executor": dict(self.role_executor),
                "role_chains": {k: list(v) for k, v in self.role_chains.items()},
                "role_fallback_policy": dict(self.role_fallback_policy),
                "independence_pairs": [list(p) for p in self.independence_pairs],
                "independence_risk_classes": list(self.independence_risk_classes),
                "seat_policy": {k: list(v) for k, v in dict(self.seat_policy).items()},
                "workspace_provider": self.workspace_provider,
                "sandbox_provider": self.sandbox_provider,
                "test_commands": list(self.test_commands),
                "default_authority": list(self.default_authority),
                "adversarial_review": self.adversarial_review,
                "adversarial_required_for": list(self.adversarial_required_for),
                "required_evidence": list(self.required_evidence),
                "protected_roots": list(self.protected_roots),
                "source_path": self.source_path, "instrument": self.instrument}


def _parse_mini_yaml(text: str) -> dict:
    """A SUBSET of YAML: nested mappings and ``- `` lists. Raises ValueError on anything else.

    ARBITRARY NESTING, VIA AN INDENT STACK. The first version of this parser handled exactly two
    levels and SILENTLY FLATTENED anything deeper. That is not a limitation, it is a defect of the
    worst kind: ``review.adversarial.enabled: true`` was hoisted to ``review.enabled``, so
    ``review.adversarial`` read back as an empty list, and the loader turned that into
    ``adversarial_review = False``. A manifest that asked for adversarial review on every
    security-sensitive change silently got none, and every field it did parse looked right.

    Refusing is the whole point of a subset parser. A config parser that quietly ignores a line it
    does not understand will one day quietly ignore an authority restriction -- so an ambiguous
    indent, a tab, or a line that is not ``key: value`` / ``- item`` raises instead of guessing.
    """
    root: dict = {}
    # (indent, container, key_in_parent, parent). The container at the top owns the next deeper
    # line. `key_in_parent` is carried so a block opened as a mapping can be CONVERTED to a list
    # when its first child turns out to be a "- " item -- YAML does not say which it is until
    # then, and guessing wrong silently attaches the list to the wrong owner.
    stack = [(-1, root, None, None)]
    last_key = None

    for lineno, raw in enumerate(text.split("\n"), 1):
        # A BOM (or any zero-width prefix) silently becomes part of the FIRST KEY otherwise --
        # measured: "\ufeffproject" parsed as a key named after an invisible character, and
        # project.name read back as missing. Windows editors emit BOMs routinely, so a parser
        # that does not eat one is a parser that fails on this platform's own output.
        line = raw.lstrip("﻿").rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            raise ValueError("line %d: tab in indentation; use spaces" % lineno)
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if stripped.startswith("- "):
            if last_key is None:
                raise ValueError("line %d: list item with no key: %r" % (lineno, raw))
            while len(stack) > 1 and stack[-1][0] >= indent:
                stack.pop()
            _ind, container, key_in_parent, parent = stack[-1]
            item = _scalar(stripped[2:].strip(), lineno)
            if isinstance(container, list):
                container.append(item)
            elif container == {} and parent is not None and key_in_parent is not None:
                # The block was opened as a mapping; its first child is a list item, so it IS a
                # list. Convert it in the PARENT and replace the stack entry.
                lst: list = [item]
                parent[key_in_parent] = lst
                stack[-1] = (_ind, lst, key_in_parent, parent)
            else:
                raise ValueError("line %d: list item inside a mapping that already has keys: %r"
                                 % (lineno, raw))
            continue

        if ":" not in stripped:
            raise ValueError("line %d: unparseable (this parser accepts 'key: value' and "
                             "'- item' only): %r" % (lineno, raw))

        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        owner = stack[-1][1]
        if not isinstance(owner, dict):
            raise ValueError("line %d: mapping key inside a list block: %r" % (lineno, raw))

        key, _, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        if not key:
            raise ValueError("line %d: empty key" % lineno)

        if value == "":
            # A block: either a nested mapping or a list. Which one is not decided until the
            # next line, so it starts as a mapping and a "- " item converts it.
            child: dict = {}
            owner[key] = child
            stack.append((indent, child, key, owner))
        else:
            owner[key] = _scalar(value, lineno)
        last_key = key
    return root


def _strip_trailing_comment(s: str) -> str:
    """Cut the first whitespace-delimited ``#`` outside quotes. PURE."""
    quote = ""
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in (" ", "\t")):
            return s[:i].rstrip()
    return s


def _scalar(v: str, lineno: int = 0):
    """One scalar, or an inline ``[a, b]`` list. PURE.

    Strips only a MATCHED pair of surrounding quotes. The previous version chained
    ``.strip('"').strip("'")``, which removes quote characters from either end independently --
    so ``python -m unittest -p "test_*.py"`` lost its closing quote and became a command that no
    shell would run correctly. Silent corruption of a configured command is exactly the class of
    defect a "small subset" parser is supposed to avoid by being simple.

    Inline lists are supported because the generated manifest writes ``protected_roots: []`` --
    an empty list that used to parse as the STRING "[]" and then fail placeholder validation
    downstream, which looked like a platform refusal rather than a parser gap.

    TRAILING COMMENTS ARE STRIPPED, PER THE YAML RULE (a comment opens at a ``#`` preceded by
    whitespace, outside quotes). Measured defect this fixed: ``quaestor init``'s own starter
    manifest wrote ``- READ_ONLY            # raise deliberately...``, the comment rode INTO
    the parsed value, and the loader refused init's output with "unknown authority profile"
    -- the platform refusing its own conservative default (§6 semantic parity means both
    syntaxes must read back what their author wrote). A quoted ``"#tag"`` or ``foo#bar`` is
    untouched: only whitespace-delimited comments are comments.
    """
    s = _strip_trailing_comment(v.strip())
    if s == "[]":
        return []
    if len(s) >= 2 and s[0] == "[" and s[-1] == "]":
        inner = s[1:-1].strip()
        return [_scalar(x) for x in inner.split(",")] if inner else []
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


#: Named refusals for the seat writer.
SEATS_UNKNOWN_ROLE = "SEATS_UNKNOWN_ROLE"
SEATS_UNKNOWN_KIND = "SEATS_UNKNOWN_KIND"
SEATS_NO_MANIFEST = "SEATS_NO_MANIFEST"
SEATS_WOULD_NOT_PARSE = "SEATS_WOULD_NOT_PARSE"
SEATS_UNSUPPORTED_FORMAT = "SEATS_UNSUPPORTED_FORMAT"


#: The seat shapes the parser accepts, and therefore the ONLY shapes this writer will re-emit.
#: A seat outside them is REFUSED rather than rewritten: silently flattening a structure this
#: emitter does not understand is exactly how the previous version destroyed providers.chain.
SEAT_SCALAR = "scalar"
SEAT_MAPPING = "mapping"


def _seat_shape(value):
    """(shape, normalised) for one seat entry, or (None, why). PURE."""
    if isinstance(value, str):
        return (SEAT_SCALAR, value.strip()) if value.strip() else (None, "empty kind")
    if isinstance(value, Mapping):
        unknown = sorted(str(k) for k in value if str(k) not in ("kind", "providers"))
        if unknown:
            return None, "unsupported key(s) %s" % unknown
        providers = value.get("providers") or {}
        if providers and not isinstance(providers, Mapping):
            return None, "providers must be a mapping"
        p_unknown = sorted(str(k) for k in providers
                           if str(k) not in ("chain", "fallback_policy"))
        if p_unknown:
            return None, "unsupported providers key(s) %s" % p_unknown
        return SEAT_MAPPING, value
    return None, "seat must be a kind or a {kind, providers} mapping"


def _emit_seat(role: str, value, shape: str) -> list:
    """One seat as YAML lines, in the shape it was written in. PURE."""
    if shape == SEAT_SCALAR:
        return ["    %s: %s" % (role, value)]
    lines = ["    %s:" % role]
    kind = str(value.get("kind") or "").strip()
    if kind:
        lines.append("      kind: %s" % kind)
    providers = value.get("providers") or {}
    if providers:
        lines.append("      providers:")
        chain = providers.get("chain") or ()
        if chain:
            lines.append("        chain: [%s]" % ", ".join(str(c) for c in chain))
        policy = str(providers.get("fallback_policy") or "").strip()
        if policy:
            lines.append("        fallback_policy: %s" % policy)
    return lines


def _emit_executors_block(block: Mapping) -> tuple:
    """(lines, refusal) for a whole ``executors:`` mapping. PURE.

    Re-emits what is THERE, merged -- it does not regenerate from the roles map. That
    distinction is the whole fix: regenerating drops every key the caller did not mention,
    and the keys a caller does not mention are exactly the ones they configured once and
    expect to keep (``default``, another seat's failover chain).
    """
    lines = ["executors:"]
    default = str(block.get("default") or "").strip()
    if default:
        lines.append("  default: %s" % default)
    roles = block.get("roles") or {}
    if not isinstance(roles, Mapping):
        return [], "executors.roles must be a mapping"
    emitted = []
    for role in ASSIGNABLE_ROLES:                # stable order, never dict order
        if role not in roles:
            continue
        shape, value = _seat_shape(roles[role])
        if shape is None:
            return [], "seat %r cannot be rewritten safely: %s" % (role, value)
        emitted.extend(_emit_seat(role, value, shape))
    leftover = sorted(str(r) for r in roles if str(r) not in ASSIGNABLE_ROLES)
    if leftover:
        return [], ("manifest names non-assignable seat(s) %s; refusing to rewrite a block "
                    "this writer would have to drop them from" % leftover)
    if emitted:
        lines.append("  roles:")
        lines.extend(emitted)
    return (lines if (default or emitted) else []), ""


def write_role_assignments(path: str, roles: Mapping) -> dict:
    """MERGE ``executors.roles`` into an existing manifest, preserving everything else. Impure.

    A TARGETED EDIT, NOT A RE-SERIALISATION OF THE DOCUMENT. The file is hand-reviewed -- the
    starter manifest ships with comments telling an operator which lines matter, and `init`
    tells them to read it -- so every line outside the ``executors:`` block is carried through
    byte-for-byte.

    THE BLOCK ITSELF IS MERGED, NOT REGENERATED. An earlier version rebuilt it from the roles
    argument alone, which silently deleted ``executors.default`` and any seat the caller did not
    mention, failover chains included. So the existing block is PARSED, the requested seats are
    merged into it, and the result is re-emitted in the shapes the parser accepts. A shape this
    emitter does not understand is REFUSED, never flattened: dropping structure nobody asked to
    change is the failure this function exists to avoid.

    THE RESULT IS PARSED BEFORE IT REPLACES ANYTHING. The edit goes to a uniquely-named temp
    file, is loaded through the ordinary ``load``, and is promoted only on success -- so a
    manifest that parsed before this call still parses after it, whatever the writer got wrong.
    """
    from quaestor.adapters import registry as cap_registry
    target = str(path or "")
    if os.path.isdir(target):
        target = find_config(target)
    if not target or not os.path.isfile(target):
        return {"ok": False, "reason": SEATS_NO_MANIFEST,
                "detail": "no project manifest at %r; write one with init first" % path}
    if not target.endswith((".yaml", ".yml")):
        return {"ok": False, "reason": SEATS_UNSUPPORTED_FORMAT,
                "detail": ("this writer edits YAML manifests only -- the product writes YAML "
                           "and accepts a quaestor.toml as INPUT only (discovery prefers it), "
                           "so a TOML manifest must be edited by hand; %s is not a YAML "
                           "manifest" % target)}

    wanted = {}
    for role, kind in dict(roles or {}).items():
        role, kind = str(role), str(kind or "").strip()
        if not kind:
            continue
        if role not in ASSIGNABLE_ROLES:
            return {"ok": False, "reason": SEATS_UNKNOWN_ROLE, "role": role,
                    "assignable": list(ASSIGNABLE_ROLES),
                    "detail": ("%r is not an assignable seat; OWNER in particular is always "
                               "human, never configurable, never delegated" % role)}
        if not cap_registry.is_declared(kind):
            return {"ok": False, "reason": SEATS_UNKNOWN_KIND, "kind": kind,
                    "detail": ("%r has no capability declaration; refusing rather than pinning "
                               "a seat to a provider nothing can route" % kind)}
        wanted[role] = kind

    # newline="" DISABLES universal-newline translation, which is the only way to SEE what the
    # file actually uses. Reading with translation on turns every CRLF into LF before the check
    # below runs, so the detection silently always says LF and rewrites the whole file.
    with open(target, encoding="utf-8", newline="") as fh:
        original = fh.read()
    # NEWLINES ARE PRESERVED. Rewriting a CRLF manifest with LF endings would show every line
    # as changed in a diff -- a claim of "one block edited" that the diff contradicts.
    newline = "\r\n" if "\r\n" in original else "\n"
    flat = original.replace("\r\n", "\n")

    try:
        doc = _parse_mini_yaml(flat)
    except (ValueError, OSError) as exc:
        return {"ok": False, "reason": SEATS_WOULD_NOT_PARSE,
                "detail": "the manifest does not parse as it stands: %s" % exc,
                "note": "the manifest on disk was NOT touched"}
    existing = doc.get("executors") if isinstance(doc, Mapping) else None
    if existing is not None and not isinstance(existing, Mapping):
        return {"ok": False, "reason": SEATS_WOULD_NOT_PARSE,
                "detail": "executors must be a mapping of {default, roles}",
                "note": "the manifest on disk was NOT touched"}
    block = {k: v for k, v in dict(existing or {}).items()}
    merged_roles = dict(block.get("roles") or {})
    merged_roles.update(wanted)                  # MERGE -- untouched seats survive verbatim
    block["roles"] = merged_roles

    lines, refusal = _emit_executors_block(block)
    if refusal:
        return {"ok": False, "reason": SEATS_UNSUPPORTED_FORMAT, "detail": refusal,
                "note": "the manifest on disk was NOT touched"}

    kept = []
    skipping = False
    for line in flat.split("\n"):
        # ANCHORED AT COLUMN 0. An `executors:` key nested under another mapping is a different
        # key; starting the skip there would delete the rest of its parent.
        if not skipping and line.startswith("executors:"):
            skipping = True
            continue
        if skipping:
            if line.strip() and not line[:1].isspace():
                skipping = False
            else:
                continue
        kept.append(line)
    body = "\n".join(kept).rstrip("\n")
    updated = (body + "\n\n" + "\n".join(lines) + "\n") if lines else (body + "\n")
    if newline != "\n":
        updated = updated.replace("\n", newline)

    # A UNIQUE probe name: the dashboard is a ThreadingHTTPServer, so two seat writes can be in
    # flight at once and a fixed name would have them clobber each other's probe.
    probe = "%s.seats-probe.%d.%d" % (target, os.getpid(), _next_probe_seq())
    try:
        with open(probe, "w", encoding="utf-8", newline="") as fh:
            fh.write(updated)
        cfg, reason = load(probe)
        if cfg is None:
            return {"ok": False, "reason": SEATS_WOULD_NOT_PARSE, "detail": reason,
                    "note": "the manifest on disk was NOT touched"}
        os.replace(probe, target)
    finally:
        if os.path.exists(probe):
            try:
                os.remove(probe)
            except OSError:
                pass
    return {"ok": True, "manifest": target, "roles": dict(cfg.role_executor),
            "preserved_default": str(block.get("default") or ""),
            "note": ("executors.roles merged: executors.default, every seat you did not name "
                     "(failover chains included) and every line OUTSIDE the executors block are "
                     "unchanged. Comments written INSIDE the executors block do not survive, "
                     "because that block is re-emitted rather than patched line-wise.")}


_PROBE_SEQ = [0]


def _next_probe_seq() -> int:
    """A per-process counter so concurrent writes cannot share a probe path. Impure."""
    _PROBE_SEQ[0] += 1
    return _PROBE_SEQ[0]


def find_config(start: str) -> str:
    """The nearest project config at or above ``start``. Impure. Returns "" if none."""
    cur = os.path.abspath(start)
    while True:
        for name in CONFIG_NAMES:
            candidate = os.path.join(cur, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            return ""
        cur = parent


def load(path: str) -> tuple:
    """(ProjectConfig|None, reason). Impure. NEVER raises.

    An unknown authority profile is REFUSED rather than dropped: silently ignoring a profile name
    would let a typo downgrade a project to the default envelope without anyone noticing.
    """
    if not path or not os.path.isfile(path):
        return None, "%s: no project config at %r" % (CONFIG_MISSING, path)
    try:
        if path.endswith(".toml"):
            # PRD.md §47.1: the primary format rides the stdlib parser (3.11+). tomllib demands
            # a BINARY handle, and its TOMLDecodeError is a ValueError, so it lands in the same
            # honest-refusal channel below -- with line/column in the message, i.e. the error
            # names where the manifest stopped being parseable.
            import tomllib
            with open(path, "rb") as fh:
                doc = tomllib.load(fh)
        else:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            doc = json.loads(text) if path.endswith(".json") else _parse_mini_yaml(text)
    except (OSError, ValueError) as exc:
        return None, "%s: %s" % (CONFIG_MALFORMED, exc)
    if not isinstance(doc, Mapping):
        return None, "%s: top level must be a mapping" % CONFIG_MALFORMED

    project = doc.get("project") or {}
    if not isinstance(project, Mapping) or not project.get("name"):
        return None, "%s: project.name is required" % CONFIG_MALFORMED

    # ABSENCE IS NOT A TEST DOUBLE. This defaulted to "fake", so a manifest that named no
    # executor produced a seat that runs, writes nothing, and reports PASS -- the cold-start
    # failure, at its root. An undeclared executor is now empty and refused by name at
    # dispatch, which is what "fail closed" means here.
    executor = (doc.get("executor") or {}).get("default", "")

    # PRD.md §7 matrix grammar: an optional ``executors:`` block naming the project default and
    # per-seat pins. Refusals here are the point: a typo'd role key must not quietly become
    # "no pin" (the authority-profile rule again), and OWNER is refused BY NAME because a
    # manifest that assigns the human seat has misunderstood the governance, not misspelled it.
    executors_doc = doc.get("executors")
    seat_policy: dict = {}
    role_pins: dict = {}
    role_chains: dict = {}
    role_fallback: dict = {}
    if executors_doc is not None:
        if not isinstance(executors_doc, Mapping):
            return None, "%s: executors must be a mapping of {default, roles}" % CONFIG_MALFORMED
        exec_default = str(executors_doc.get("default") or "").strip()
        if exec_default:
            executor = exec_default
        # SEAT POLICY (PRD.md §7.5). Declared here, evaluated by ONE function
        # (adapters.registry.constraint_refusals), enforced at dispatch. Unknown keys and unknown
        # values are NAMED refusals rather than ignored: a policy silently dropped is a policy
        # the operator believes is protecting them.
        seat_policy: dict = {}
        policy_doc = executors_doc.get("policy")
        if policy_doc is not None:
            if not isinstance(policy_doc, Mapping):
                return None, ("%s: executors.policy must be a mapping of "
                              "{credential_modes, local_or_remote}" % CONFIG_MALFORMED)
            unknown_policy = sorted(str(k) for k in policy_doc
                                    if str(k) not in ("credential_modes", "local_or_remote"))
            if unknown_policy:
                return None, ("%s: unknown executors.policy key(s) %s; supported are "
                              "['credential_modes', 'local_or_remote']"
                              % (CONFIG_REFUSED, unknown_policy))
            modes = policy_doc.get("credential_modes")
            if modes is not None:
                if isinstance(modes, str) or not isinstance(modes, (list, tuple)):
                    return None, ("%s: executors.policy.credential_modes must be a list"
                                  % CONFIG_MALFORMED)
                known_modes = ("subscription", "api")
                bad = sorted(str(m) for m in modes if str(m) not in known_modes)
                if bad:
                    return None, ("%s: unknown credential mode(s) %s; known are %s"
                                  % (CONFIG_REFUSED, bad, list(known_modes)))
                if modes:
                    seat_policy["credential_modes"] = tuple(str(m) for m in modes)
            loc = policy_doc.get("local_or_remote")
            if loc is not None:
                if str(loc) not in ("local", "remote"):
                    return None, ("%s: executors.policy.local_or_remote must be 'local' or "
                                  "'remote', not %r" % (CONFIG_REFUSED, loc))
                seat_policy["local_or_remote"] = str(loc)

        roles_doc = executors_doc.get("roles")
        if roles_doc is not None:
            if not isinstance(roles_doc, Mapping):
                return None, ("%s: executors.roles must map role -> executor kind"
                              % CONFIG_MALFORMED)
            if "owner" in roles_doc:
                return None, (
                    "%s: executors.roles.owner refuses assignment: OWNER is always human, "
                    "never configurable, never delegated (PRD.md section 7.1)"
                    % CONFIG_REFUSED)
            unknown = sorted(str(k) for k in roles_doc if str(k) not in ASSIGNABLE_ROLES)
            if unknown:
                return None, ("%s: unknown executor role(s) %s; assignable seats are %s "
                              "(every other seat, including OWNER, is not assignable)"
                              % (CONFIG_REFUSED, unknown, list(ASSIGNABLE_ROLES)))
            # Each seat's value is EITHER a bare kind ("planner: gpt-plan") OR a mapping
            # carrying kind + an ordered providers.chain (PRD.md §7.3). The chain is
            # where quota/outage resilience lives -- and where the refusal rules bite hardest:
            # a one-member chain has no fallback to give, a non-list chain is a typo wearing
            # a config shape, and an unknown fallback_policy would silently mean something
            # weaker than availability_only. All three refuse by name.
            role_pins = {}
            role_chains = {}
            role_fallback = {}
            for seat, raw in roles_doc.items():
                seat = str(seat)
                if isinstance(raw, Mapping):
                    kind = str(raw.get("kind") or "").strip()
                    if not kind:
                        return None, ("%s: executors.roles.%s names no executor kind"
                                      % (CONFIG_REFUSED, seat))
                    providers = raw.get("providers")
                    if providers is not None:
                        if not isinstance(providers, Mapping):
                            return None, ("%s: executors.roles.%s.providers must be a "
                                          "mapping of {chain, fallback_policy}"
                                          % (CONFIG_REFUSED, seat))
                        chain = providers.get("chain")
                        if chain is not None:
                            if not isinstance(chain, (list, tuple)) or \
                                    any(not str(k).strip() for k in chain):
                                return None, (
                                    "%s: executors.roles.%s.providers.chain must be a "
                                    "non-empty list of executor kinds" % (CONFIG_REFUSED, seat))
                            kinds_chain = tuple(str(k).strip() for k in chain)
                            if len(kinds_chain) < 2:
                                return None, (
                                    "%s: executors.roles.%s.providers.chain needs at least "
                                    "two candidate kinds; a one-member chain has no fallback "
                                    "to give" % (CONFIG_REFUSED, seat))
                            if len(set(kinds_chain)) != len(kinds_chain):
                                return None, (
                                    "%s: executors.roles.%s.providers.chain repeats a kind; "
                                    "a repeated member is not a fallback" % (CONFIG_REFUSED,
                                                                             seat))
                            role_chains[seat] = kinds_chain
                        policy = str(providers.get("fallback_policy") or "").strip()
                        if policy:
                            if policy != "availability_only":
                                return None, (
                                    "%s: executors.roles.%s.providers.fallback_policy %r is "
                                    "unknown; the only supported policy is "
                                    "'availability_only' (never switches across an AMBIGUOUS "
                                    "write)" % (CONFIG_REFUSED, seat, policy))
                            role_fallback[seat] = policy
                else:
                    kind = str(raw or "").strip()
                    if not kind:
                        return None, ("%s: executors.roles.%s names no executor kind"
                                      % (CONFIG_REFUSED, seat))
                role_pins[seat] = kind


    workspace = (doc.get("workspace") or {}).get("provider", "git-worktree")
    sandbox = (doc.get("sandbox") or {}).get("provider", "none")
    commands = (doc.get("commands") or {}).get("test", []) or []
    auth = (doc.get("authority") or {}).get("default", [authority_mod.READ_ONLY]) or []
    if isinstance(auth, str):
        auth = [auth]
    unknown = [a for a in auth if a not in authority_mod.PROFILES]
    if unknown:
        return None, ("%s: unknown authority profile(s) %s; known are %s"
                      % (CONFIG_REFUSED, unknown, sorted(authority_mod.PROFILES)))

    review = doc.get("review") or {}
    adversarial = review.get("adversarial", True)
    if isinstance(adversarial, Mapping):
        required_for = tuple(adversarial.get("required_for") or ())
        adversarial_on = bool(adversarial.get("enabled", True))
    else:
        required_for, adversarial_on = (), bool(adversarial)

    # PRD.md §7.2 pairing policy, epistemic independence. The typo rule again, twice over: a pair
    # naming a seat that does not exist would silently protect nothing, and a pair naming
    # OWNER has misunderstood who the human is. Both refuse by name. Risk classes validate
    # against the platform's existing change-class vocabulary (review_contract's
    # ADVERSARIAL_REQUIRED_FLOOR plus the classifier's data_migration) so a misspelled class
    # cannot quietly exempt itself from admission.
    indep_pairs: tuple = ()
    indep_classes: tuple = ()
    if isinstance(review, Mapping):
        indep = review.get("epistemic_independence")
        if indep is not None:
            if not isinstance(indep, Mapping):
                return None, ("%s: review.epistemic_independence must be a mapping of "
                              "{require_distinct_provider_between, "
                              "require_distinct_provider_for}" % CONFIG_MALFORMED)
            pairs_raw = indep.get("require_distinct_provider_between") or ()
            if not isinstance(pairs_raw, (list, tuple)):
                return None, ("%s: require_distinct_provider_between must be a list of "
                              "[role, role] pairs" % CONFIG_MALFORMED)
            for p in pairs_raw:
                if not isinstance(p, (list, tuple)) or len(p) != 2 or \
                        any(not str(r).strip() for r in p):
                    return None, ("%s: require_distinct_provider_between entries must each "
                                  "name exactly two roles: %r" % (CONFIG_MALFORMED, p))
                bad = [str(r) for r in p if str(r) not in ASSIGNABLE_ROLES]
                if "owner" in [str(r) for r in p]:
                    return None, ("%s: epistemic independence names OWNER; the human seat "
                                  "has no provider and no pairing policy applies to it"
                                  % CONFIG_REFUSED)
                if bad:
                    return None, ("%s: unknown role(s) %s in require_distinct_provider_"
                                  "between; assignable seats are %s"
                                  % (CONFIG_REFUSED, bad, list(ASSIGNABLE_ROLES)))
                pair = tuple(str(r) for r in p)
                if pair[0] == pair[1]:
                    return None, ("%s: require_distinct_provider_between pair %s names one "
                                  "seat twice" % (CONFIG_REFUSED, list(pair)))
                indep_pairs += (pair,)
            classes_raw = indep.get("require_distinct_provider_for") or ()
            if not isinstance(classes_raw, (list, tuple)):
                return None, ("%s: require_distinct_provider_for must be a list of risk "
                              "classes" % CONFIG_MALFORMED)
            # THE vocabulary, not a copy of it. This list and review_contract's had already
            # drifted apart once.
            from quaestor.core import review_contract as _rc
            known_classes = _rc.RISK_CLASSES
            unknown_classes = sorted({str(c) for c in classes_raw} - set(known_classes))
            if unknown_classes:
                return None, ("%s: unknown risk class(es) %s in require_distinct_provider_"
                              "for; known classes are %s"
                              % (CONFIG_REFUSED, unknown_classes, list(known_classes)))
            indep_classes = tuple(str(c) for c in classes_raw)

    evidence = (doc.get("evidence") or {}).get("require",
                                               ["git_head", "git_status", "test_results"]) or []
    protected = (doc.get("security") or {}).get("protected_roots", []) or []

    repo = str(project.get("repository") or ".")
    if not os.path.isabs(repo):
        repo = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(path)), repo))

    return ProjectConfig(
        name=str(project["name"]), repository=repo.replace("\\", "/"),
        executor=str(executor), role_executor=role_pins,
        role_chains={k: tuple(v) for k, v in role_chains.items()},
        seat_policy=seat_policy,
        role_fallback_policy=dict(role_fallback),
        independence_pairs=indep_pairs,
        independence_risk_classes=indep_classes,
        workspace_provider=str(workspace), sandbox_provider=str(sandbox),
        test_commands=tuple(str(c) for c in commands),
        default_authority=tuple(str(a) for a in auth),
        adversarial_review=adversarial_on,
        adversarial_required_for=tuple(str(c) for c in required_for),
        required_evidence=tuple(str(e) for e in evidence),
        protected_roots=tuple(str(p).replace("\\", "/") for p in protected),
        source_path=os.path.abspath(path).replace("\\", "/")), ""


def load_nearest(start: str = ".") -> tuple:
    return load(find_config(start))

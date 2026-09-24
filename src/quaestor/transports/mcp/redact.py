"""transport_redact -- what the remote caller is allowed to see.

TWO RECEIPTS, DELIBERATELY DIFFERENT SIZES
------------------------------------------
The LOCAL audit receipt stays rich: host paths, container ids, full evidence. The REMOTE object
is intentionally smaller. They are not two views of one record -- they are two records, and the
remote one is built by ALLOWLIST from named fields, never by deleting keys from the local one.

That direction matters. A denylist ("strip anything called token") silently ships every field a
future version adds, and the fields a future version adds are exactly the ones nobody has decided
are safe yet. This is the same argument ``preflight.redact_auth`` makes, applied to the transport.

HOST PATHS BECOME LOGICAL IDENTIFIERS
-------------------------------------
``/path/to/the/governed/repository`` tells a remote caller the operator's username, their
directory layout, and that a path traversal has somewhere to aim. It is replaced by an alias the
server already knows. A path that matches no alias is not passed through with the username
scrubbed -- it is replaced wholesale by ``<path-withheld>``, because partial redaction of a path
is a guessing game and the guess only has to be wrong once.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

REDACT_INSTRUMENT = "transport_redact/1"

WITHHELD_PATH = "<path-withheld>"
WITHHELD = "<withheld>"

#: Keys never emitted remotely, at any depth, whatever their value. The allowlist below is the
#: mechanism; this is the tripwire for a future edit that widens an allowlist carelessly.
NEVER_REMOTE = frozenset({
    "claude_code_oauth_token", "anthropic_api_key", "anthropic_auth_token", "token", "secret",
    "password", "credential", "credentials", "cipher", "blob", "dpapi", "env", "environment",
    "config_env", "container_env", "inspect", "inspect_before", "inspect_after", "prompt",
    "handoff_json", "stdout", "stderr", "argv", "command", "claude_path", "db_path", "lock_path",
    "stdout_path", "stderr_path", "run_dir", "worktree_path", "cwd", "repo_root", "secret_dir",
})

#: Host-path shapes. Broader than "drive letter or /home" because a redactor that only knows the
#: shapes its author happened to think of is a redactor whose gaps are exactly the interesting
#: cases: an extended-length prefix, a UNC share, a device path, a file:// URL, an unexpanded
#: environment reference, or a traversal that walks OUT of an aliased repository.
_PATH_RE = re.compile(
    r"(?:"
    r"\\\\\?\\[^\s\"']*"                        # \\?\C:\... extended-length
    r"|\\\\\.\\[^\s\"']*"                       # \\.\ device
    r"|\\\\[A-Za-z0-9._-]+\\[^\s\"']*"          # \\server\share
    r"|[A-Za-z]:[\\/][^\s\"']*"                 # C:\... or C:/...
    r"|file://[^\s\"']*"                        # file:// URL
    r"|%[A-Za-z_]+%[\\/][^\s\"']*"              # %USERPROFILE%\...
    r"|\$(?:HOME|USERPROFILE)[\\/][^\s\"']*"    # $HOME/...
    r"|/(?:home|Users|mnt|c|root|var|etc|tmp)/[^\s\"']*"
    r")")

#: A traversal segment surviving ALIAS substitution. `repo:x/../../protected-root` is no longer path-shaped
#: to the regex above -- aliasing destroyed the anchor the regex needed -- so it is caught here.
_TRAVERSAL_RE = re.compile(r"(?:^|[\s\"'/\\]|repo:[A-Za-z0-9_-]+[/\\])\.\.[/\\]")


def scrub_text(text: Any, *, alias_of=None) -> Any:
    """Replace host paths in free text. PURE.

    Free text -- a refusal reason, a drift message -- legitimately names a worktree. The alias
    table gets first refusal; anything else path-shaped is withheld entirely.
    """
    if not isinstance(text, str) or not text:
        return text
    out = text
    if alias_of:
        for host, alias in sorted(alias_of.items(), key=lambda kv: -len(kv[0])):
            for variant in {host, host.replace("/", "\\"), host.replace("\\", "/")}:
                if variant:
                    out = out.replace(variant, "repo:%s" % alias)
    out = _PATH_RE.sub(WITHHELD_PATH, out)
    # AFTER aliasing, because aliasing is what creates this case: `<host>/../../elsewhere`
    # becomes `repo:x/../../elsewhere`, which no longer looks like a host path to the regex but
    # still names a location outside the alias.
    return _TRAVERSAL_RE.sub(WITHHELD_PATH, out)


def alias_map(repo_table: Mapping[str, str] | None) -> dict:
    """host path -> alias, normalised both slash directions."""
    out = {}
    for alias, host in (repo_table or {}).items():
        h = str(host)
        out[h] = alias
        out[h.replace("\\", "/")] = alias
        out[h.replace("/", "\\")] = alias
    return out


def remote_run(run: Mapping | None, *, alias_of=None) -> dict | None:
    """The ChatGPT-facing view of a run row. ALLOWLIST."""
    if not run:
        return None
    keep = ("run_id", "execution_state", "is_write", "title", "created_at", "updated_at",
            "workflow_id", "step_id", "attempt", "reason")
    out = {k: run[k] for k in keep if k in run}
    # BOTH free-text fields are scrubbed. `title` is caller-supplied and echoed back, so leaving
    # it raw let a caller round-trip a host path through the remote payload -- found by review,
    # not by reading this code.
    for field in ("reason", "title"):
        if field in out:
            out[field] = scrub_text(out.get(field), alias_of=alias_of)
    return out


def remote_worker(worker: Mapping | None) -> dict | None:
    """Liveness, not process forensics. A pid is a local operational fact, not remote evidence."""
    if not worker:
        return None
    return {"liveness": worker.get("liveness"), "started_at": worker.get("started_at"),
            "heartbeat_at": worker.get("heartbeat_at"),
            "worker_present": bool(worker.get("spawn_pid"))}


def remote_result(result: Mapping | None, *, alias_of=None) -> dict | None:
    if not result:
        return None
    keep = ("run_id", "prompt_disposition", "program_verdict", "exit_code", "duration_s",
            "summary")
    out = {k: result[k] for k in keep if k in result}
    out["summary"] = scrub_text(out.get("summary"), alias_of=alias_of)
    return out


def remote_evidence(evidence: Mapping | None, *, alias_of=None) -> dict | None:
    """Counts and verdicts. Never the bytes that produced them."""
    if not evidence:
        return None
    keep = ("run_id", "tests_run", "tests_passed", "tests_failed", "inspected_count",
            "verdict", "instrument", "collected_at")
    out = {k: evidence[k] for k in keep if k in evidence}
    return out


def remote_lease(lease: Mapping | None) -> dict | None:
    if not lease:
        return None
    return {"held": True, "expected_branch": lease.get("expected_branch"),
            "expected_head": str(lease.get("expected_head") or "")[:12],
            "acquired_at": lease.get("acquired_at")}


def remote_handoff(handoff: Mapping | None, *, alias_of=None) -> dict | None:
    """The child's report, trimmed. Its free text is scrubbed and stays DATA."""
    if not handoff:
        return None
    # THE REAL FIELD NAMES, from handoff._REQUIRED_FIELDS. An earlier allowlist named fields the
    # handoff schema does not define ("next_actions", "blockers", "tests"), so this function
    # silently returned three of seventeen fields and `orchestrator_result` was nearly empty --
    # an allowlist is only safe if it matches the thing it filters. `run_nonce` is deliberately
    # ABSENT: it is the token that proves a result belongs to a run, and a remote caller has no
    # use for it that is not forgery.
    keep = ("protocol", "protocol_version", "workflow_id", "step_id",
            "prompt_disposition", "program_verdict", "acceptance_state",
            "authorized_scope_exhausted", "continuation_allowed", "next_authority",
            "owner_decision_required", "smallest_blocker", "next_action", "summary",
            "claimed_files_changed")
    out = {}
    for k in keep:
        if k not in handoff:
            continue
        v = handoff[k]
        if isinstance(v, str):
            v = scrub_text(v, alias_of=alias_of)
        elif isinstance(v, list):
            v = [scrub_text(x, alias_of=alias_of) if isinstance(x, str) else x for x in v]
        out[k] = v
    return out


def host_secret_values(env: Mapping[str, str] | None = None) -> list:
    """The VALUES of credential-shaped variables present on this host. Impure (reads env).

    Exists so the adapter's last-line scan has a real needle set. Without one the secret dimension
    compares nothing and reports no leaks -- which is the P4.5 empty-needle defect, and it came
    back here in new code until an adversarial reviewer caught it.

    Values never leave this process: they are compared, and only PATHS are reported.
    """
    import os as _os
    env = _os.environ if env is None else env
    names = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
             "AWS_BEARER_TOKEN_BEDROCK", "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY",
             "OPENAI_ADMIN_KEY", "CONTROL_PLANE_API_KEY")
    return [v for v in (str(env.get(n) or "") for n in names) if len(v) >= 8]


def assert_clean(obj: Any, *, secrets=(), inspected=None) -> dict:
    """Walk a remote payload and report violations. PURE. EMITS ITS INSPECTION COUNT.

    Used by controls AND by the adapter itself as a last line before a response leaves. A payload
    that inspected zero nodes is VACUOUS, never clean -- the defect P4.5 shipped and had to fix.

    THE SECRET DIMENSION REPORTS ITS OWN VACUITY SEPARATELY. Structural checks (forbidden keys,
    host paths) are non-vacuous as soon as one node exists, but "no secret leaked" is meaningless
    when zero needles were supplied. ``secret_scan_vacuous`` says which of those two situations
    produced the empty ``leaked_secrets`` list, instead of letting them look identical.
    """
    counts = {"nodes": 0, "strings": 0}
    bad_keys, bad_paths, leaked = [], [], []

    def check_string(text, path):
        counts["strings"] += 1
        if _PATH_RE.search(text) or _TRAVERSAL_RE.search(text):
            bad_paths.append(path)
        for s in secrets:
            if s and len(str(s)) >= 8 and str(s) in text:
                leaked.append(path)

    def walk(node, path="$"):
        counts["nodes"] += 1
        if isinstance(node, Mapping):
            for k, v in node.items():
                here = "%s.%s" % (path, k)
                if str(k).lower() in NEVER_REMOTE:
                    bad_keys.append(here)
                # KEYS ARE STRINGS TOO. Only their exact lowercase form was compared against the
                # denylist, so a KEY containing a host path or a secret was never examined at all.
                check_string(str(k), here + "<key>")
                walk(v, here)
        elif isinstance(node, (list, tuple, set)):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))
        elif isinstance(node, str):
            check_string(node, path)
        elif isinstance(node, (bytes, bytearray)):
            # A bytes leaf is serialized by json.dumps(default=str) as its repr, which carries
            # the payload. Declaring it inert would be a scanner that disagrees with the
            # serializer that writes the wire bytes.
            check_string(repr(bytes(node)), path)

    walk(obj)
    compared = len([s for s in secrets if s and len(str(s)) >= 8])
    return {"clean": not (bad_keys or bad_paths or leaked),
            "forbidden_keys": sorted(set(bad_keys)), "host_paths": sorted(set(bad_paths)),
            "leaked_secrets": sorted(set(leaked)),
            "inspected_nodes": counts["nodes"], "inspected_strings": counts["strings"],
            # VACUOUS MEANS "NOTHING A LEAK COULD HIDE IN WAS EXAMINED". Keying it on node count
            # made it dead code -- every object, including {}, counts as one node, so it could
            # never be True and the guard that depended on it never fired.
            "vacuous": counts["strings"] == 0,
            "secrets_compared": compared,
            "secret_scan_vacuous": compared == 0,
            "instrument": REDACT_INSTRUMENT}

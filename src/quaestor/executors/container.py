"""container_executor -- run the real Claude child INSIDE the validated confinement boundary.

Same ``Executor`` interface as the native adapter, so the worker, handoff validation, evidence
and reconciliation all work unchanged. What differs is where the process lives:

    ClaudeCliExecutor        claude -p, native, host filesystem in reach
    ClaudeContainerExecutor  claude -p, inside a container whose ACTUAL mounts and security
                             config the daemon has confirmed match a validated profile

The command itself is built by the SAME pure ``cli_executor.build_command``, so the argv the
child receives is subject to the same invariants (no permission-bypass flags, no `--bare`, the
prompt is one argv element, variadic options can never swallow it). This executor only supplies
``container_confined=True`` -- which it is entitled to do because ``run_confined`` refuses to
start a container whose inspected state disagrees with the profile.
"""
from __future__ import annotations

import os
from dataclasses import replace
from typing import Mapping, Sequence

from quaestor.sandbox import profile as cp
from quaestor.sandbox import docker as da
from quaestor.executors.claude_code import build_command
from quaestor.core.executor_contract import (EXIT_NONZERO, EXIT_OK, EXIT_SPAWN_FAILED, EXIT_TIMEOUT, ExecOutcome,
                       ExecRequest, Executor)


class ClaudeContainerExecutor(Executor):
    """Launch ``claude -p`` inside an ephemeral, policy-validated container."""

    name = "claude-container"

    def __init__(self, profile: cp.ContainerProfile, *, container_name: str,
                 forbidden_host_paths: Sequence[str] = (),
                 expected_rw_hosts: Sequence[str] = (),
                 workspace_container_path: str = "/workspace",
                 container_env: Mapping[str, str] | None = None,
                 permitted_exact_paths: Sequence[str] = (),
                 never_exempt: Sequence[str] = (),
                 remove: bool = True):
        self.profile = profile
        self.container_name = container_name
        self.forbidden_host_paths = tuple(forbidden_host_paths)
        self.expected_rw_hosts = tuple(expected_rw_hosts)
        #: The narrow, exact-path exemptions the DISPATCHER validated. They must travel to the
        #: detached worker: without them the worker re-validates the same profile against a
        #: policy that forbids everything under the project root and refuses to create the
        #: container -- correct behaviour from an under-informed check, and a silent WORKER_FAILED.
        self.permitted_exact_paths = tuple(permitted_exact_paths)
        self.never_exempt = tuple(never_exempt)
        self.workspace_container_path = workspace_container_path
        #: Environment handed to the CONTAINER (not to the host process). This is how the child
        #: learns where its egress gateway is. Omitting it is not a soft failure: on an
        #: --internal network with no direct route, a child with no proxy configuration simply
        #: cannot reach the API, and the symptom is a 3-minute hang ending in
        #: "Unable to connect to API (ConnectionRefused)" -- measured, on the first attempt.
        self.container_env = dict(container_env or {})
        self.remove = remove
        self.last: da.RunOutcome | None = None

    def execute(self, req: ExecRequest) -> ExecOutcome:
        # The child's cwd is the CONTAINER path, never the host path: passing a Windows path to a
        # Linux process would fail in a way that could be mistaken for confinement working.
        container_req = replace(req, cwd=self.workspace_container_path, container_confined=True,
                                claude_path="claude")
        try:
            argv = build_command(container_req)
        except Exception as exc:  # noqa: BLE001 - UnsafeCommand or anything else: never launch
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED,
                               error="command construction refused: %s: %s"
                                     % (type(exc).__name__, exc))

        outcome = da.run_confined(
            self.profile, argv, name=self.container_name, env=self.container_env,
            forbidden_host_paths=self.forbidden_host_paths,
            expected_rw_hosts=self.expected_rw_hosts,
            permitted_exact_paths=self.permitted_exact_paths,
            never_exempt=self.never_exempt, remove=self.remove)
        self.last = outcome

        _write(req.stdout_path, outcome.stdout)
        _write(req.stderr_path, outcome.stderr)
        _write_json(os.path.join(req.run_dir, "container.json"), {
            "container": outcome.summary(),
            "profile": self.profile.to_dict(),
            "profile_digest": self.profile.digest(),
            "argv_head": [a for a in argv[:-1]],
            "argv_len": len(argv),
            "prompt_bytes": len(str(req.prompt).encode("utf-8")),
            "actual_mounts": ((outcome.actual_verdict.checks or {}).get("actual_mounts")
                              if outcome.actual_verdict else None),
        })

        if not outcome.created:
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error=outcome.error)
        if not outcome.started:
            # Created but refused before start: the confinement check caught something. This is a
            # SECURITY refusal, not a Claude failure, and the error text says which.
            return ExecOutcome(False, None, EXIT_SPAWN_FAILED, error=outcome.error)
        if outcome.timed_out:
            return ExecOutcome(True, None, EXIT_TIMEOUT, error=outcome.error or "container timed out")
        rc = outcome.exit_code
        return ExecOutcome(True, rc, EXIT_OK if rc == 0 else EXIT_NONZERO,
                           child_pid=None, child_create_time=outcome.container_id[:12] or None,
                           note="executed inside container %s" % outcome.container_id[:12])


def _write(path: str, text: str) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text or "")


def _write_json(path: str, obj) -> None:
    import json
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=str)
    os.replace(tmp, path)


def container_env_preflight(profile: cp.ContainerProfile, *, name: str,
                            forbidden_host_paths: Sequence[str] = (),
                            expected_rw_hosts: Sequence[str] = ()) -> dict:
    """Measure credential overrides and auth class INSIDE the container. Impure. NEVER raises.

    The host preflight says nothing about the child's environment: the container has its own env,
    built from the image plus an explicit allowlist. So the same question -- is any provider or
    API override present, and is this subscription-backed -- is asked again, in the place it
    actually applies.
    """
    import json as _json
    from quaestor.executors import claude_auth as pf

    script = (
        "import json,os,subprocess,sys\n"
        "names=%r\n"
        "env={n:(os.environ.get(n) is not None) for n in names}\n"
        "lens={n:(len(os.environ.get(n) or '')) for n in names}\n"
        "try:\n"
        "    p=subprocess.run(['claude','auth','status'],capture_output=True,timeout=120)\n"
        "    raw=p.stdout.decode('utf-8','replace'); rc=p.returncode\n"
        "except Exception as e:\n"
        "    raw=''; rc=-1\n"
        "try:\n"
        "    status=json.loads(raw)\n"
        "except Exception:\n"
        "    status=None\n"
        "try:\n"
        "    v=subprocess.run(['claude','--version'],capture_output=True,timeout=120)\n"
        "    ver=v.stdout.decode('utf-8','replace').strip()\n"
        "except Exception:\n"
        "    ver=''\n"
        "sys.stdout.write(json.dumps({'env_present':env,'env_len':lens,'auth_rc':rc,"
        "'auth_status':status,'claude_version':ver}))\n"
    ) % (list(pf.OVERRIDE_VARS),)

    outcome = da.run_confined(profile, ["python3", "-c", script], name=name,
                              forbidden_host_paths=forbidden_host_paths,
                              expected_rw_hosts=expected_rw_hosts, remove=True)
    if not outcome.started:
        return {"ok": False, "reason": "CONTAINER_PREFLIGHT_UNAVAILABLE",
                "detail": outcome.error, "run": outcome.summary()}
    try:
        text = outcome.stdout.strip()
        doc = _json.loads(text[text.find("{"):]) if "{" in text else {}
    except ValueError as exc:
        return {"ok": False, "reason": "CONTAINER_PREFLIGHT_UNPARSEABLE", "detail": str(exc),
                "run": outcome.summary()}

    offenders = sorted(k for k, v in (doc.get("env_present") or {}).items() if v)
    decision = pf.decide(env={k: "x" for k in offenders}, auth_status=doc.get("auth_status"))
    return {
        "ok": decision.accepted,
        "reason": decision.reason or "",
        "detail": decision.detail,
        "auth_class": decision.auth_class,
        "offending_vars": offenders,
        "claude_version": doc.get("claude_version"),
        "auth_record": pf.redact_auth(doc.get("auth_status")),
        "env_present": doc.get("env_present"),
        "run": outcome.summary(),
        "note": ("measured INSIDE the container: the host's environment says nothing about the "
                 "child's, and the child's is what decides the billing path"),
    }

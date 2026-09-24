"""docker_adapter -- talk to Docker with argument arrays, and never trust the request over the report.

THE LIFECYCLE THIS MODULE ENFORCES
----------------------------------
    create  ->  INSPECT  ->  validate ACTUAL against the profile  ->  start  ->  wait  ->  logs
            ->  inspect again  ->  remove

The inspect-BEFORE-start step is the whole point. Creating a container materialises the daemon's
interpretation of our request without running anything, so the mount table and security config
can be checked against the profile while the container is still inert. If they disagree, the
container is removed and nothing ever executes inside it.

`shell=False` and argv arrays throughout. Bytes decoded explicitly as UTF-8 -- never `text=True`,
which decodes with the locale codepage on Windows and mojibakes anything non-ASCII.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor.sandbox import profile as cp

DOCKER_TIMEOUT_S = 300.0
ADAPTER_INSTRUMENT = "docker_adapter/1"

ENGINE_OK = "ENGINE_OK"
ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
ENGINE_WRONG_TYPE = "ENGINE_WRONG_TYPE"


@dataclass(frozen=True)
class DockerResult:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def docker(args: Sequence[str], *, timeout: float = DOCKER_TIMEOUT_S,
           stdin_bytes: bytes | None = None,
           process_env: Mapping[str, str] | None = None) -> DockerResult:
    """Run `docker ...`. Impure. NEVER raises.

    ``process_env`` supplies values for NAME-ONLY ``--env NAME`` passthrough. It is merged over
    the inherited environment for this one child process and is never logged: the whole point is
    that a secret reaches Docker without ever appearing in ``args``.
    """
    env = None
    if process_env:
        env = dict(os.environ)
        env.update({str(k): str(v) for k, v in process_env.items()})
    try:
        p = subprocess.run(["docker", *[str(a) for a in args]], capture_output=True, shell=False,
                           timeout=timeout, env=env,
                           input=stdin_bytes if stdin_bytes is not None else None,
                           stdin=None if stdin_bytes is not None else subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return DockerResult(127, "", "%s: %s" % (type(exc).__name__, exc))
    return DockerResult(p.returncode, p.stdout.decode("utf-8", "replace"),
                        p.stderr.decode("utf-8", "replace"))


@dataclass(frozen=True)
class EngineStatus:
    state: str
    os_type: str = ""
    server_version: str = ""
    client_version: str = ""
    compose_version: str = ""
    cgroup_version: str = ""
    security_options: tuple = ()
    error: str = ""
    detail: Mapping = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.state == ENGINE_OK


def engine_status() -> EngineStatus:
    """Is a LINUX Docker engine actually usable? Impure. NEVER raises.

    "Docker Desktop is installed" and "a Linux engine will run my container" are different
    claims. This asks the daemon, and a Windows-container engine is ENGINE_WRONG_TYPE rather
    than a confusing failure later -- there is no native-Windows fallback for confinement, so
    the refusal must be legible at the top.
    """
    ver = docker(["version", "--format", "{{json .}}"], timeout=90)
    if not ver.ok:
        return EngineStatus(ENGINE_UNAVAILABLE, error="docker version failed: %s"
                                                      % (ver.err.strip()[:300] or ver.out[:300]))
    try:
        vjson = json.loads(ver.out)
    except ValueError as exc:
        return EngineStatus(ENGINE_UNAVAILABLE, error="docker version output unparseable: %s" % exc)

    info = docker(["info", "--format", "{{json .}}"], timeout=120)
    if not info.ok:
        return EngineStatus(ENGINE_UNAVAILABLE, error="docker info failed: %s"
                                                      % info.err.strip()[:300])
    try:
        ijson = json.loads(info.out)
    except ValueError as exc:
        return EngineStatus(ENGINE_UNAVAILABLE, error="docker info output unparseable: %s" % exc)

    os_type = str(ijson.get("OSType") or "")
    comp = docker(["compose", "version", "--short"], timeout=90)
    server = (vjson.get("Server") or {})
    client = (vjson.get("Client") or {})
    status = EngineStatus(
        ENGINE_OK if os_type == "linux" else ENGINE_WRONG_TYPE,
        os_type=os_type,
        server_version=str(server.get("Version") or ijson.get("ServerVersion") or ""),
        client_version=str(client.get("Version") or ""),
        compose_version=comp.out.strip() if comp.ok else "",
        cgroup_version=str(ijson.get("CgroupVersion") or ""),
        security_options=tuple(ijson.get("SecurityOptions") or ()),
        error="" if os_type == "linux" else "engine OSType=%r; Linux containers are required and "
                                            "there is no native-Windows fallback" % os_type,
        detail={"architecture": ijson.get("Architecture"),
                "driver": ijson.get("Driver"),
                "containers_running_counter": ijson.get("ContainersRunning"),
                "kernel": ijson.get("KernelVersion")})
    return status


def image_digest(reference: str) -> tuple:
    """(digest|"" , detail). The immutable identity of a local image. Impure."""
    r = docker(["image", "inspect", reference, "--format", "{{.Id}}"], timeout=120)
    if not r.ok:
        return "", {"ok": False, "error": r.err.strip()[:300]}
    return r.out.strip(), {"ok": True, "reference": reference}


def volume_exists(name: str) -> bool:
    return docker(["volume", "inspect", name], timeout=60).ok


def create_volume(name: str, labels: Mapping[str, str] | None = None) -> DockerResult:
    args = ["volume", "create"]
    for k, v in sorted((labels or {}).items()):
        args += ["--label", "%s=%s" % (k, v)]
    args.append(name)
    return docker(args, timeout=90)


def inspect_container(cid: str) -> tuple:
    """(inspect_dict|None, error). Impure. NEVER raises."""
    r = docker(["inspect", cid], timeout=120)
    if not r.ok:
        return None, r.err.strip()[:300]
    try:
        doc = json.loads(r.out)
    except ValueError as exc:
        return None, "inspect output unparseable: %s" % exc
    if not isinstance(doc, list) or not doc:
        return None, "inspect returned no object"
    return doc[0], ""


@dataclass
class RunOutcome:
    """What actually happened. Every field is observed, none is assumed."""

    created: bool = False
    started: bool = False
    container_id: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    profile_verdict: cp.ProfileVerdict | None = None
    actual_verdict: cp.ProfileVerdict | None = None
    inspect_before: Mapping = field(default_factory=dict)
    inspect_after: Mapping = field(default_factory=dict)
    error: str = ""
    removed: bool = False

    @property
    def confinement_ok(self) -> bool:
        return bool(self.actual_verdict is not None and self.actual_verdict.ok)

    def summary(self) -> dict:
        return {"created": self.created, "started": self.started,
                "container_id": self.container_id[:12], "exit_code": self.exit_code,
                "timed_out": self.timed_out, "removed": self.removed,
                "profile_verdict": (self.profile_verdict.verdict if self.profile_verdict else None),
                "actual_verdict": (self.actual_verdict.verdict if self.actual_verdict else None),
                "actual_reasons": (list(self.actual_verdict.reasons) if self.actual_verdict else []),
                "error": self.error}


def run_confined(profile: cp.ContainerProfile, argv: Sequence[str], *, name: str,
                 env: Mapping[str, str] | None = None,
                 forbidden_host_paths: Sequence[str] = (),
                 expected_rw_hosts: Sequence[str] = (),
                 permitted_exact_paths: Sequence[str] = (),
                 never_exempt: Sequence[str] = (),
                 env_passthrough: Sequence[str] = (),
                 process_env: Mapping[str, str] | None = None,
                 remove: bool = True) -> RunOutcome:
    """Create, verify, start, wait, collect, remove. Impure. NEVER raises.

    Refuses in three distinct places, and the ORDER is the safety argument:
      1. the profile is impermissible          -> nothing is created
      2. the created container disagrees       -> nothing is started, container removed
      3. only then does anything execute
    """
    out = RunOutcome()

    verdict = cp.validate_profile(profile, forbidden_host_paths=forbidden_host_paths,
                                  expected_rw_hosts=expected_rw_hosts,
                                  permitted_exact_paths=permitted_exact_paths,
                                  never_exempt=never_exempt)
    out.profile_verdict = verdict
    if not verdict.ok:
        out.error = "profile refused: %s" % "; ".join(verdict.reasons)
        return out

    created = docker(profile.docker_create_args(name, argv, env, env_passthrough),
                     timeout=300, process_env=process_env)
    if not created.ok:
        out.error = "docker create failed: %s" % (created.err.strip()[:500] or created.out[:500])
        return out
    out.created = True
    out.container_id = created.out.strip()

    try:
        insp, err = inspect_container(out.container_id)
        if insp is None:
            out.error = "could not inspect the created container: %s" % err
            return out
        out.inspect_before = insp

        actual = cp.validate_actual(profile, insp, forbidden_host_paths=forbidden_host_paths,
                                    expected_rw_hosts=expected_rw_hosts,
                                    permitted_exact_paths=permitted_exact_paths,
                                    never_exempt=never_exempt)
        out.actual_verdict = actual
        if not actual.ok:
            out.error = ("SECURITY_BOUNDARY_FAIL before start -- the created container does not "
                         "match the validated profile: %s" % "; ".join(actual.reasons))
            return out

        started = docker(["start", out.container_id], timeout=120)
        if not started.ok:
            out.error = "docker start failed: %s" % started.err.strip()[:500]
            return out
        out.started = True

        waited = docker(["wait", out.container_id], timeout=max(60.0, profile.timeout_s + 60))
        if waited.ok:
            try:
                out.exit_code = int(waited.out.strip().splitlines()[-1])
            except (ValueError, IndexError):
                out.exit_code = None
        else:
            out.timed_out = True
            docker(["kill", out.container_id], timeout=90)

        logs = docker(["logs", out.container_id], timeout=180)
        out.stdout, out.stderr = logs.out, logs.err

        after, _ = inspect_container(out.container_id)
        out.inspect_after = after or {}
        return out
    finally:
        if remove and out.container_id:
            rm = docker(["rm", "-f", out.container_id], timeout=180)
            out.removed = rm.ok


def list_project_containers(label: str) -> list:
    r = docker(["ps", "-a", "--filter", "label=%s" % label,
                "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"], timeout=90)
    return [l for l in r.out.splitlines() if l.strip()] if r.ok else []


def container_exists(name_or_id: str) -> bool:
    return docker(["inspect", "--type", "container", name_or_id], timeout=60).ok

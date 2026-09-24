"""container_profile -- the container execution profile as MACHINE POLICY, validated before launch.

WHY A PROFILE OBJECT AND NOT A COMMAND STRING
---------------------------------------------
"Do not launch and then hope the child behaves." A `docker run` command line is prose: it can be
extended by anyone, it has no schema, and nothing about it refuses. This module makes the
security-relevant configuration a typed, frozen object that is VALIDATED before a container is
created, and that renders its own argv so the argv cannot drift from the thing that was checked.

TWO VALIDATIONS, AND THE SECOND ONE IS THE IMPORTANT ONE
--------------------------------------------------------
  1. ``validate_profile``    -- is what we are ABOUT to ask for permissible?
  2. ``validate_actual``     -- does the ENGINE'S OWN REPORT of the created container match?

Only the second is evidence. instrument doctrine, clause 2: a control that consumes only
your own output tests serialization, not verification. Checking the argv we just built proves we
can read our own variable; checking `docker inspect` proves what the daemon actually did. A
container whose declared profile is safe while its running mount table differs is
``SECURITY_BOUNDARY_FAIL`` -- exactly the case the specification calls out.

PURE module. Nothing here talks to Docker; ``docker_adapter`` does that and calls back in here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor.core.canon import canonical_json, canonical_path, sha256_text

PROFILE_INSTRUMENT = "container_profile/1"

# Verdicts
POLICY_OK = "CONTAINER_POLICY_OK"
POLICY_REFUSED = "CONTAINER_POLICY_REFUSED"
SECURITY_BOUNDARY_FAIL = "SECURITY_BOUNDARY_FAIL"

RW = "rw"
RO = "ro"
BIND = "bind"
VOLUME = "volume"
TMPFS = "tmpfs"

#: Host paths (or path prefixes) that must NEVER be bind-mounted into a Claude child, in any
#: mode. Each entry is here for a specific reason, not for tidiness:
#:   - the control plane decides whether Claude may act; Claude must not be able to edit it
#:   - the project's primary checkout is never an orchestrated write target
#:   - a user-profile root drags in every credential store at once
#:   - the docker socket/pipe IS the escape: whoever reaches it owns the host's containers
FORBIDDEN_HOST_PREFIXES_DEFAULT = (
    "/var/run/docker.sock",
    "//./pipe/docker_engine",
    "//./pipe/dockerdesktoplinuxengine",
    "/run/docker.sock",
)

FORBIDDEN_LEAF_NAMES = (".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker",
                        ".config/gcloud", ".git-credentials")

#: Namespace/privilege settings that are always refused.
FORBIDDEN_NETWORK = ("host",)
FORBIDDEN_PID = ("host",)
FORBIDDEN_IPC = ("host",)


@dataclass(frozen=True)
class Mount:
    host_path: str          # for VOLUME this is the volume name; for TMPFS it is ""
    container_path: str
    mode: str = RO
    kind: str = BIND
    #: tmpfs options only. Explicit rather than hardcoded because the EPHEMERAL HOME needs
    #: uid/gid/mode of its own -- a tmpfs owned by root is not writable by the unprivileged child,
    #: and "the home directory silently isn't writable" is a failure that looks like many others.
    options: str = ""

    @property
    def readonly(self) -> bool:
        return self.mode == RO

    def to_dict(self) -> dict:
        return {"host_path": self.host_path, "container_path": self.container_path,
                "mode": self.mode, "kind": self.kind, "options": self.options}

    @staticmethod
    def from_dict(d: Mapping) -> "Mount":
        return Mount(str(d.get("host_path") or ""), str(d.get("container_path") or ""),
                     str(d.get("mode") or RO), str(d.get("kind") or BIND),
                     str(d.get("options") or ""))

    def docker_args(self) -> list:
        if self.kind == TMPFS:
            opts = self.options or "rw,nosuid,size=256m"
            return ["--tmpfs", "%s:%s" % (self.container_path, opts)]
        if self.kind == VOLUME:
            return ["--mount", "type=volume,source=%s,target=%s%s"
                    % (self.host_path, self.container_path, ",readonly" if self.readonly else "")]
        return ["--mount", "type=bind,source=%s,target=%s%s"
                % (self.host_path, self.container_path, ",readonly" if self.readonly else "")]


@dataclass(frozen=True)
class ContainerProfile:
    """Every security-relevant knob, in one frozen object with a stable digest."""

    profile_id: str
    image_ref: str
    image_digest: str
    user: str = "1001:1001"
    workdir: str = "/workspace"
    mounts: tuple = ()
    network: str = "bridge"
    cap_drop: tuple = ("ALL",)
    cap_add: tuple = ()
    privileged: bool = False
    pid_mode: str = ""
    ipc_mode: str = ""
    read_only_rootfs: bool = True
    security_opt: tuple = ("no-new-privileges",)
    env_allowlist: tuple = ()
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 512
    timeout_s: float = 900.0
    claude_authority_profile: str = "READ_ONLY"
    autoremove: bool = False
    instrument: str = PROFILE_INSTRUMENT

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in (
            "profile_id", "image_ref", "image_digest", "user", "workdir", "network", "cap_drop",
            "cap_add", "privileged", "pid_mode", "ipc_mode", "read_only_rootfs", "security_opt",
            "env_allowlist", "memory", "cpus", "pids_limit", "timeout_s",
            "claude_authority_profile", "autoremove", "instrument")}
        d["cap_drop"] = list(self.cap_drop)
        d["cap_add"] = list(self.cap_add)
        d["security_opt"] = list(self.security_opt)
        d["env_allowlist"] = list(self.env_allowlist)
        d["mounts"] = [m.to_dict() for m in self.mounts]
        return d

    def digest(self) -> str:
        return sha256_text(canonical_json(self.to_dict()))

    @staticmethod
    def from_dict(d: Mapping) -> "ContainerProfile":
        """Rebuild a profile from its serialised form. PURE.

        The profile is written into the durable ``request.json`` so the WORKER -- a separate,
        detached process -- executes the same object the dispatcher validated, rather than
        rebuilding one from configuration that may since have changed. It is also, in itself,
        evidence: the run record states the exact security envelope that was used.
        """
        d = dict(d)
        return ContainerProfile(
            profile_id=str(d.get("profile_id") or ""),
            image_ref=str(d.get("image_ref") or ""),
            image_digest=str(d.get("image_digest") or ""),
            user=str(d.get("user") or "1001:1001"),
            workdir=str(d.get("workdir") or "/workspace"),
            mounts=tuple(Mount.from_dict(m) for m in (d.get("mounts") or ())),
            network=str(d.get("network") or "bridge"),
            cap_drop=tuple(d.get("cap_drop") or ("ALL",)),
            cap_add=tuple(d.get("cap_add") or ()),
            privileged=bool(d.get("privileged")),
            pid_mode=str(d.get("pid_mode") or ""),
            ipc_mode=str(d.get("ipc_mode") or ""),
            read_only_rootfs=bool(d.get("read_only_rootfs", True)),
            security_opt=tuple(d.get("security_opt") or ()),
            env_allowlist=tuple(d.get("env_allowlist") or ()),
            memory=str(d.get("memory") or ""), cpus=str(d.get("cpus") or ""),
            pids_limit=int(d.get("pids_limit") or 0),
            timeout_s=float(d.get("timeout_s") or 900.0),
            claude_authority_profile=str(d.get("claude_authority_profile") or "READ_ONLY"),
            autoremove=bool(d.get("autoremove")))

    def rw_bind_hosts(self) -> tuple:
        return tuple(m.host_path for m in self.mounts
                     if m.kind == BIND and m.mode == RW)

    def docker_create_args(self, name: str, argv: Sequence[str],
                           env: Mapping[str, str] | None = None,
                           env_passthrough: Sequence[str] = ()) -> list:
        """The exact argv for `docker create`. PURE.

        Rendered FROM the validated object, so the command cannot say something the profile did
        not. ``--pull=never`` matters: a run must not silently fetch a different image than the
        digest that was checked.
        """
        args = ["create", "--name", name, "--user", self.user, "--workdir", self.workdir,
                "--network", self.network, "--pull=never"]
        for c in self.cap_drop:
            args += ["--cap-drop", c]
        for c in self.cap_add:
            args += ["--cap-add", c]
        for s in self.security_opt:
            args += ["--security-opt", s]
        if self.read_only_rootfs:
            args.append("--read-only")
        if self.memory:
            args += ["--memory", self.memory]
        if self.cpus:
            args += ["--cpus", str(self.cpus)]
        if self.pids_limit:
            args += ["--pids-limit", str(self.pids_limit)]
        for m in self.mounts:
            args += m.docker_args()
        for k, v in sorted((env or {}).items()):
            args += ["--env", "%s=%s" % (k, v)]
        # SECRET-BEARING VARIABLES USE NAME-ONLY PASSTHROUGH.
        # `--env NAME=VALUE` puts the value in the docker CLI's COMMAND LINE, where any process
        # listing on the box can read it -- `tasklist`, Process Explorer, another container with
        # host PID (which we forbid, but the argv is still world-visible to the local user).
        # `--env NAME` tells Docker to copy the value from the docker process's OWN environment,
        # which the caller supplies via subprocess env=. Same delivery, no argv exposure.
        for k in sorted({str(n) for n in (env_passthrough or ())}):
            args += ["--env", k]
        args.append(self.image_digest if self.image_digest.startswith("sha256:")
                    else self.image_ref)
        args += [str(a) for a in argv]
        return args


@dataclass(frozen=True)
class ProfileVerdict:
    verdict: str
    reasons: tuple = ()
    checks: Mapping = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.verdict == POLICY_OK


def path_is_within(child: str, parent: str) -> bool:
    """Is ``child`` the same as, or beneath, ``parent``? PURE.

    Compares on a SEPARATOR BOUNDARY, so ``C:/repo-other`` is not "within" ``C:/repo``. A naive
    prefix test would make a sibling directory look contained, and a containment check that is
    wrong in the permissive direction is not a check.
    """
    c, p = canonical_path(child), canonical_path(parent)
    if not c or not p:
        return False
    return c == p or c.startswith(p.rstrip("/") + "/")


def _os_sensitive_roots() -> tuple:
    """Host roots that are sensitive on THIS operating system. Impure (reads the environment).

    Previously two Windows paths were hard-coded here, which meant the confinement policy silently
    protected nothing on Linux or macOS -- a control that is correct only on its author's machine.
    Derived from the environment instead, so the same policy is meaningful wherever it runs.
    """
    roots = []
    if os.name == "nt":
        systemdrive = (os.environ.get("SystemDrive") or "C:").rstrip("\\/")
        roots += [systemdrive + "/Users", os.environ.get("SystemRoot") or systemdrive + "/Windows",
                  os.environ.get("ProgramData") or systemdrive + "/ProgramData"]
    else:
        roots += ["/home", "/root", "/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc"]
    return tuple(r.replace("\\", "/") for r in roots if r)


#: Paths that can NEVER be exempted, whatever a caller passes in ``permitted_exact_paths``.
#: A working-tree root or a credential store is not made safe by naming it explicitly, and an
#: exemption mechanism whose escape hatch is unbounded is not an exemption mechanism.
def never_exemptible(platform_root: str, project_root: str) -> tuple:
    """Paths ``permitted_exact_paths`` may never open. NOT PURE -- reads HOME and the OS.

    Deliberately machine-derived: the credential stores live under the RUNNING user's home, so a
    constant would name somebody else's. See ``default_forbidden_paths`` for the full argument.
    """
    home = os.path.expanduser("~").replace("\\", "/")
    return tuple(canonical_path(p) for p in (
        platform_root, project_root, home, *_os_sensitive_roots(),
        home + "/.ssh", home + "/.aws", home + "/.azure", home + "/.config/gcloud",
        home + "/.claude", "/var/run/docker.sock"))


def validate_profile(profile: ContainerProfile, *,
                     forbidden_host_paths: Sequence[str] = (),
                     expected_rw_hosts: Sequence[str] = (),
                     permitted_exact_paths: Sequence[str] = (),
                     never_exempt: Sequence[str] = (),
                     require_digest: bool = True) -> ProfileVerdict:
    """Validate a profile.

    ``permitted_exact_paths`` exists for exactly one situation: P4 must expose a NARROW slice of
    the project's Git metadata (``<primary>/.git`` read-only, and the P4 worktree's own private admin
    directory) while the project root as a whole stays forbidden. Without it the blanket
    containment rule refuses every path under the repository, including the ones a linked
    worktree provably requires.

    Three properties keep it from becoming a hole:

      * EXACT MATCH ONLY. A permitted path exempts that path and nothing beneath or above it, so
        permitting ``<project>/.git`` does not permit ``<project>`` or ``<project>/.git/../src``.
      * ``never_exempt`` OVERRIDES IT. A working-tree root or credential store cannot be exempted
        by naming it, so the escape hatch cannot be opened onto the thing it exists to protect.
      * The read-WRITE allowlist is unaffected: an exempted path may still only be mounted
        read-write if it is also in ``expected_rw_hosts``.

    ``expected_rw_hosts`` is an ALLOWLIST. Any read-write bind not on it is refused as an unknown
    RW mount -- the denylist alone would silently admit every host path nobody thought to forbid,
    and the set of paths nobody thought of is exactly where the dangerous one lives.

    PURE. NEVER raises.
    """
    reasons = []
    checks = {}

    checks["not_privileged"] = profile.privileged is False
    if profile.privileged is not False:
        reasons.append("privileged=true is never permitted")

    checks["no_host_pid"] = str(profile.pid_mode or "").lower() not in FORBIDDEN_PID
    if not checks["no_host_pid"]:
        reasons.append("pid_mode=%r shares the host PID namespace" % profile.pid_mode)

    checks["no_host_ipc"] = str(profile.ipc_mode or "").lower() not in FORBIDDEN_IPC
    if not checks["no_host_ipc"]:
        reasons.append("ipc_mode=%r shares the host IPC namespace" % profile.ipc_mode)

    checks["no_host_network"] = str(profile.network or "").lower() not in FORBIDDEN_NETWORK
    if not checks["no_host_network"]:
        reasons.append("network=%r is host networking" % profile.network)

    checks["non_root_user"] = str(profile.user).split(":")[0] not in ("0", "root", "")
    if not checks["non_root_user"]:
        reasons.append("user=%r runs the child as root" % profile.user)

    checks["caps_dropped"] = "ALL" in {str(c).upper() for c in profile.cap_drop}
    if not checks["caps_dropped"]:
        reasons.append("cap_drop must include ALL; inheriting Docker's defaults is not a policy")
    if profile.cap_add:
        reasons.append("cap_add=%s: capabilities may only be added with a measured requirement"
                       % list(profile.cap_add))
    checks["no_caps_added"] = not profile.cap_add

    checks["image_pinned_by_digest"] = bool(
        profile.image_digest and profile.image_digest.startswith("sha256:"))
    if require_digest and not checks["image_pinned_by_digest"]:
        reasons.append("image is not pinned by digest; a tag is mutable, so the run record would "
                       "not say which bytes executed")

    forbidden = list(FORBIDDEN_HOST_PREFIXES_DEFAULT) + list(forbidden_host_paths or ())
    allow = [canonical_path(p) for p in (expected_rw_hosts or ())]
    permitted_exact = {canonical_path(p) for p in (permitted_exact_paths or ())}
    never_exempt_set = {canonical_path(p) for p in (never_exempt or ())}
    checks["permitted_exact_paths"] = sorted(permitted_exact)
    checks["never_exemptible"] = sorted(never_exempt_set)

    mount_checks = []
    seen_targets = {}
    for m in profile.mounts:
        entry = {"mount": m.to_dict(), "problems": []}

        if m.container_path in seen_targets:
            entry["problems"].append("duplicate container target %s (conflicts with %s)"
                                     % (m.container_path, seen_targets[m.container_path]))
        seen_targets[m.container_path] = m.host_path

        if m.kind == BIND:
            hp = canonical_path(m.host_path)
            raw = str(m.host_path).replace("\\", "/").lower()
            exempt = (hp in permitted_exact and hp not in never_exempt_set)
            if hp in permitted_exact and hp in never_exempt_set:
                entry["problems"].append(
                    "host path %s was offered as a permitted exception but is on the "
                    "never-exemptible list; naming a working tree or credential store does not "
                    "make it safe" % m.host_path)
            if not exempt:
                for f in forbidden:
                    fl = str(f).replace("\\", "/").lower()
                    if raw == fl or raw.startswith(fl.rstrip("/") + "/") or path_is_within(hp, f):
                        entry["problems"].append("host path %s is forbidden (matches %s)"
                                                 % (m.host_path, f))
            else:
                entry["exempted"] = "explicitly permitted exact path"
            for leaf in FORBIDDEN_LEAF_NAMES:
                if raw.endswith("/" + leaf) or ("/" + leaf + "/") in raw:
                    entry["problems"].append("host path %s exposes credential store %s"
                                             % (m.host_path, leaf))
            if m.mode == RW and allow and not any(path_is_within(hp, a) for a in allow):
                entry["problems"].append(
                    "UNKNOWN read-write bind %s: not in the expected-writable allowlist"
                    % m.host_path)
            if m.mode not in (RO, RW):
                entry["problems"].append("mount mode %r is neither ro nor rw" % m.mode)
        elif m.kind not in (VOLUME, TMPFS):
            entry["problems"].append("unknown mount kind %r" % m.kind)

        if entry["problems"]:
            reasons.extend(entry["problems"])
        mount_checks.append(entry)

    checks["mounts"] = mount_checks
    checks["docker_socket_absent"] = not any(
        "docker.sock" in str(m.host_path).lower() or "docker_engine" in str(m.host_path).lower()
        or "dockerdesktop" in str(m.host_path).lower()
        for m in profile.mounts)

    return ProfileVerdict(POLICY_OK if not reasons else POLICY_REFUSED, tuple(reasons), checks)


# ---------------------------------------------------------------------------------------------
# THE EVIDENCE HALF: does the ENGINE agree with the profile?
# ---------------------------------------------------------------------------------------------
def validate_actual(profile: ContainerProfile, inspect: Mapping, *,
                    forbidden_host_paths: Sequence[str] = (),
                    expected_rw_hosts: Sequence[str] = (),
                    permitted_exact_paths: Sequence[str] = (),
                    never_exempt: Sequence[str] = ()) -> ProfileVerdict:
    """Compare `docker inspect` output against the profile. PURE. NEVER raises.

    This is the control that cannot be satisfied by our own bookkeeping: every field here comes
    from the daemon's description of a container that actually exists. A declared-safe profile
    whose real mount table differs is SECURITY_BOUNDARY_FAIL, not a warning.
    """
    reasons, checks = [], {}
    host_cfg = dict(inspect.get("HostConfig") or {})
    cfg = dict(inspect.get("Config") or {})
    mounts = list(inspect.get("Mounts") or [])

    def bad(cond, msg, key):
        checks[key] = not cond
        if cond:
            reasons.append(msg)

    bad(host_cfg.get("Privileged") is True, "ACTUAL container is privileged", "not_privileged")
    bad(str(host_cfg.get("PidMode") or "").lower() in FORBIDDEN_PID,
        "ACTUAL container uses host PID namespace", "no_host_pid")
    bad(str(host_cfg.get("IpcMode") or "").lower() in FORBIDDEN_IPC,
        "ACTUAL container uses host IPC namespace", "no_host_ipc")
    bad(str(host_cfg.get("NetworkMode") or "").lower() in FORBIDDEN_NETWORK,
        "ACTUAL container uses host networking", "no_host_network")

    user = str(cfg.get("User") or "")
    checks["non_root_user"] = user.split(":")[0] not in ("0", "root", "")
    if not checks["non_root_user"]:
        reasons.append("ACTUAL container user is %r" % user)

    cap_drop = {str(c).upper() for c in (host_cfg.get("CapDrop") or [])}
    checks["caps_dropped"] = "ALL" in cap_drop
    if not checks["caps_dropped"]:
        reasons.append("ACTUAL CapDrop=%s does not drop ALL" % sorted(cap_drop))
    cap_add = [str(c) for c in (host_cfg.get("CapAdd") or [])]
    checks["no_caps_added"] = not cap_add
    if cap_add:
        reasons.append("ACTUAL CapAdd=%s" % cap_add)

    checks["read_only_rootfs"] = bool(host_cfg.get("ReadonlyRootfs")) or not profile.read_only_rootfs
    if profile.read_only_rootfs and not host_cfg.get("ReadonlyRootfs"):
        reasons.append("profile requires a read-only rootfs but the ACTUAL container has none")

    forbidden = list(FORBIDDEN_HOST_PREFIXES_DEFAULT) + list(forbidden_host_paths or ())
    allow = [canonical_path(p) for p in (expected_rw_hosts or ())]
    permitted_exact = {canonical_path(p) for p in (permitted_exact_paths or ())}
    never_exempt_set = {canonical_path(p) for p in (never_exempt or ())}

    declared = {(canonical_path(m.host_path) if m.kind == BIND else str(m.host_path),
                 m.container_path, m.mode, m.kind) for m in profile.mounts if m.kind != TMPFS}
    actual = set()
    actual_rows = []
    for m in mounts:
        mtype = str(m.get("Type") or "")
        src = str(m.get("Source") or "")
        name = str(m.get("Name") or "")
        dst = str(m.get("Destination") or "")
        mode = RW if m.get("RW") is True else RO
        key_src = canonical_path(src) if mtype == "bind" else (name or src)
        actual.add((key_src, dst, mode, "bind" if mtype == "bind" else "volume"))
        actual_rows.append({"type": mtype, "source": src, "name": name, "destination": dst,
                            "mode": mode})
        if mtype == "bind":
            raw = src.replace("\\", "/").lower()
            exempt = (key_src in permitted_exact and key_src not in never_exempt_set)
            if not exempt:
                for f in forbidden:
                    fl = str(f).replace("\\", "/").lower()
                    if raw == fl or raw.startswith(fl.rstrip("/") + "/"):
                        reasons.append("ACTUAL container binds forbidden host path %s" % src)
            if mode == RW and allow and not any(path_is_within(key_src, a) for a in allow):
                reasons.append("ACTUAL container has an UNKNOWN read-write bind: %s -> %s"
                               % (src, dst))

    checks["actual_mounts"] = actual_rows
    checks["mount_set_matches_profile"] = (declared == actual)
    if declared != actual:
        reasons.append("ACTUAL mount table differs from the validated profile: "
                       "only-in-profile=%s only-in-container=%s"
                       % (sorted(declared - actual), sorted(actual - declared)))

    checks["docker_socket_absent"] = not any(
        "docker.sock" in str(r["source"]).lower() or "docker_engine" in str(r["source"]).lower()
        for r in actual_rows)
    if not checks["docker_socket_absent"]:
        reasons.append("ACTUAL container mounts a Docker control interface")

    image = str(inspect.get("Image") or "")
    checks["image_matches_profile_digest"] = (
        not profile.image_digest or image == profile.image_digest)
    if profile.image_digest and image != profile.image_digest:
        reasons.append("ACTUAL container image %s is not the validated digest %s"
                       % (image, profile.image_digest))

    return ProfileVerdict(POLICY_OK if not reasons else SECURITY_BOUNDARY_FAIL,
                          tuple(reasons), checks)


def default_forbidden_paths(platform_root: str, project_root: str) -> tuple:
    """The host paths this project must never expose.

    NOT PURE, and the docstring used to say it was. It reads ``HOME``/``USERPROFILE`` and the
    running OS, so the answer differs per machine -- which is the POINT: a constant list would
    protect one developer's home directory and silently protect nothing on every other box, the
    same defect as the ``"C:/Users"`` literals this replaced. An environment-dependent verdict is
    correct here; an environment-dependent verdict that CLAIMS to be pure is what gets a reader
    to cache it, share it between machines, or assert it as a fixture.
    """
    home = os.path.expanduser("~").replace("\\", "/")
    return (
        platform_root,
        project_root,
        os.path.dirname(project_root.rstrip("/")),      # the parent, hence sibling repos
        home,                                           # the whole user profile
        home + "/.ssh", home + "/.aws", home + "/.azure", home + "/.config/gcloud",
        home + "/.claude",
        *_os_sensitive_roots(), "/var/run/docker.sock",
    )

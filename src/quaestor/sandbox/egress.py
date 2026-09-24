"""egress -- the outbound network policy, its lifecycle, and the evidence that it holds.

THE ARCHITECTURE, AND WHY THE INTERNAL NETWORK IS THE LOAD-BEARING PART
-----------------------------------------------------------------------
                    ┌──────────────────────────────┐
                    │ egress gateway (dual-homed)  │
    internal ───────┤ CONNECT allowlist + ledger   ├─────── bridge ─── internet
    (no route)      └──────────────────────────────┘
        │
    ┌───┴────────────────┐
    │ Claude child       │   attached ONLY to the internal network
    │ HTTPS_PROXY=gateway│   → ignoring the proxy yields NO egress, not direct egress
    └────────────────────┘

Docker's ``--internal`` network has no external route. That is what makes this a boundary rather
than a configuration: a child that unsets ``HTTPS_PROXY`` does not fall back to the internet, it
falls back to nothing. A proxy setting with a working direct route beside it would be
``EGRESS_POLICY_FAIL`` -- correct-looking and worthless.

DERIVING THE ALLOWLIST
----------------------
Never from memory. ``observe`` mode runs once with everything allowed and every CONNECT logged;
the allowlist is then built from what the pinned Claude version ACTUALLY contacted, and each
entry records why it is there. Because the image and the Claude version are pinned, installer and
updater endpoints are NOT pre-allowed merely because generic installations sometimes use them --
if this build never contacts them, they do not belong in the policy.

PURE decision core (``classify_destination``, ``build_policy``); the Docker lifecycle at the
bottom is the only I/O.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.sandbox import docker as da
from quaestor.core.canon import canonical_json, sha256_text

EGRESS_INSTRUMENT = "egress/1"

OBSERVE = "observe"
ENFORCE = "enforce"

# Destination classes
CORE_REQUIRED = "CORE_REQUIRED"
OPTIONAL_NONESSENTIAL = "OPTIONAL_NONESSENTIAL"
TASK_INITIATED = "TASK_INITIATED"
UNEXPLAINED = "UNEXPLAINED"

# Verdicts
EGRESS_PASS = "PASS"
EGRESS_FAIL = "EGRESS_POLICY_FAIL"
EGRESS_BLOCKED = "EGRESS_ENFORCEMENT_BLOCKED"

NETWORK_NAME = branding.resource("egress", "internal")
GATEWAY_NAME = branding.resource("egress", "gateway")
GATEWAY_PORT = 8080

#: Hostname substrings that identify first-party Anthropic inference/auth traffic. Used only to
#: CLASSIFY observed destinations, never to pre-authorise them: a host is allowed because it was
#: measured, and this table explains why it appeared.
_CORE_HINTS = ("api.anthropic.com", "statsig.anthropic.com", "console.anthropic.com",
               "claude.ai", "anthropic.com")
_OPTIONAL_HINTS = ("sentry.io", "statsig.com", "segment.io", "google-analytics",
                   "registry.npmjs.org", "nodejs.org", "github.com", "githubusercontent.com")


@dataclass(frozen=True)
class EgressPolicy:
    policy_version: str
    allow: tuple = ()
    mode: str = ENFORCE
    claude_version: str = ""
    image_digest: str = ""
    derived_at: float = 0.0
    derivation: Mapping = field(default_factory=dict)
    instrument: str = EGRESS_INSTRUMENT

    def to_dict(self) -> dict:
        return {"policy_version": self.policy_version, "allow": list(self.allow),
                "mode": self.mode, "claude_version": self.claude_version,
                "image_digest": self.image_digest, "derived_at": self.derived_at,
                "derivation": dict(self.derivation), "instrument": self.instrument}

    def digest(self) -> str:
        return sha256_text(canonical_json(self.to_dict()))


def match_rule(host: str, port: int, allow) -> tuple:
    """(allowed, rule). PURE.

    A rule is ``"host:port"``. ``*.example.com`` matches any SUBDOMAIN of example.com and NOT
    example.com itself -- a wildcard that also matched the parent would silently widen every rule
    written for a CDN. Matching is case-insensitive; the port must match exactly, because "the
    right host on the wrong port" is a different destination.

    THIS FUNCTION IS MIRRORED VERBATIM in ``docker/egress_proxy.py``, because the proxy runs
    inside a container where this package is not mounted and importing it would mean mounting the
    control plane into the child -- exactly what the confinement boundary forbids. Duplication is
    the lesser evil, and ``test_p3_controls`` asserts the two sources are byte-identical so they
    cannot drift apart: the copy under test must be the copy that enforces.
    """
    h = str(host or "").strip().lower().rstrip(".")
    for rule in allow or ():
        try:
            r_host, _, r_port = str(rule).rpartition(":")
            if not r_host or int(r_port) != int(port):
                continue
        except (TypeError, ValueError):
            continue
        r_host = r_host.strip().lower()
        if r_host.startswith("*."):
            if h.endswith(r_host[1:]) and h != r_host[2:]:
                return True, rule
        elif h == r_host:
            return True, rule
    return False, ""


def classify_destination(host: str) -> str:
    """Why did this hostname appear? PURE.

    UNEXPLAINED is the default and is deliberately loud: a destination nobody can account for is
    the single most interesting line in an egress ledger.
    """
    h = str(host or "").strip().lower()
    if not h:
        return UNEXPLAINED
    for hint in _CORE_HINTS:
        if h == hint or h.endswith("." + hint):
            return CORE_REQUIRED
    for hint in _OPTIONAL_HINTS:
        if h == hint or h.endswith("." + hint):
            return OPTIONAL_NONESSENTIAL
    return UNEXPLAINED


def parse_ledger(text: str) -> list:
    """Decision records from the gateway's stdout. PURE. NEVER raises."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def observed_destinations(ledger: Sequence[Mapping]) -> dict:
    """host -> {ports, count, class, decisions}. PURE."""
    seen: dict = {}
    for row in ledger or ():
        if row.get("event") != "connect":
            continue
        host = str(row.get("host") or "")
        if not host:
            continue
        e = seen.setdefault(host, {"ports": set(), "count": 0, "decisions": set(),
                                   "class": classify_destination(host)})
        e["ports"].add(int(row.get("port") or 0))
        e["count"] += 1
        e["decisions"].add(str(row.get("decision") or ""))
    return {h: {"ports": sorted(v["ports"]), "count": v["count"],
                "class": v["class"], "decisions": sorted(v["decisions"])}
            for h, v in sorted(seen.items())}


def build_policy(observed: Mapping, *, policy_version: str, claude_version: str,
                 image_digest: str, derived_at: float = 0.0,
                 include_classes: Sequence[str] = (CORE_REQUIRED,)) -> EgressPolicy:
    """Derive an allowlist from MEASURED destinations. PURE.

    Only classes in ``include_classes`` are admitted -- CORE_REQUIRED by default. An optional or
    unexplained destination is recorded in the derivation but NOT allowed: adding a telemetry
    domain so that a failure stops appearing in a log is how an allowlist quietly becomes a
    formality.
    """
    allow = []
    for host, info in sorted((observed or {}).items()):
        if info.get("class") in include_classes:
            for port in info.get("ports") or ():
                allow.append("%s:%d" % (host, int(port)))
    return EgressPolicy(
        policy_version=policy_version, allow=tuple(sorted(set(allow))), mode=ENFORCE,
        claude_version=claude_version, image_digest=image_digest, derived_at=derived_at,
        derivation={"observed": dict(observed), "included_classes": list(include_classes),
                    "excluded": {h: i for h, i in (observed or {}).items()
                                 if i.get("class") not in include_classes},
                    "note": ("derived from a measured observe-mode run of THIS pinned image and "
                             "Claude version; installer/updater endpoints are not pre-allowed")})


def evaluate(*, ledger: Sequence[Mapping], required_ok: bool, denied_controls: Mapping,
             direct_route_available: bool | None) -> dict:
    """The egress verdict. PURE. NEVER raises.

    ``direct_route_available`` is tri-state and decisive: True is an outright FAIL regardless of
    how well the proxy behaved, because the proxy is then decoration. None (never measured) also
    refuses -- an unmeasured bypass is not an absent one.
    """
    failures = []
    if direct_route_available is True:
        failures.append("a DIRECT external route exists beside the proxy; the allowlist is "
                        "advisory, not enforced")
    if direct_route_available is None:
        failures.append("direct-route bypass was never measured; an unmeasured bypass is not an "
                        "absent one")
    if not required_ok:
        failures.append("the required Claude endpoint was not reachable through the gateway")
    for name, passed in sorted((denied_controls or {}).items()):
        if passed is not True:
            failures.append("negative control did not deny as required: %s" % name)

    rows = list(ledger or ())
    allowed = [r for r in rows if r.get("decision") == "ALLOW" and r.get("event") == "connect"]
    denied = [r for r in rows if r.get("decision") == "DENY"]
    return {
        "verdict": EGRESS_PASS if not failures else EGRESS_FAIL,
        "failures": failures,
        "inspected_decisions": len([r for r in rows if r.get("decision") in ("ALLOW", "DENY")]),
        "allowed_count": len(allowed),
        "denied_count": len(denied),
        "rules_used": sorted({str(r.get("rule") or "") for r in allowed}),
        "deny_rules": sorted({str(r.get("rule") or "") for r in denied}),
    }


# ---------------------------------------------------------------------------------------------
# Docker lifecycle
# ---------------------------------------------------------------------------------------------
def ensure_internal_network(name: str = NETWORK_NAME) -> dict:
    """Create the --internal network if absent. Impure. NEVER raises.

    ``--internal`` is the whole point: Docker attaches no default gateway, so containers on it
    have no route off the host. Verified after creation rather than assumed.
    """
    exists = da.docker(["network", "inspect", name], timeout=60)
    if not exists.ok:
        created = da.docker(["network", "create", "--internal", "--label", branding.label("component") + "=egress",
                             name], timeout=120)
        if not created.ok:
            return {"ok": False, "error": created.err.strip()[:300]}
    got = da.docker(["network", "inspect", name, "--format", "{{.Internal}}\t{{.Driver}}"],
                    timeout=60)
    internal = got.out.strip().split("\t")[0].lower() == "true" if got.ok else False
    return {"ok": internal, "name": name, "internal": internal,
            "detail": got.out.strip(),
            "error": "" if internal else "network exists but is NOT --internal"}


def start_gateway(*, image: str, mode: str, allow: Sequence[str], policy_version: str,
                  proxy_script_host_path: str, name: str = GATEWAY_NAME,
                  network: str = NETWORK_NAME) -> dict:
    """Start the dual-homed gateway. Impure. NEVER raises.

    Attached to the DEFAULT BRIDGE first (so it has an external route) and then connected to the
    internal network, which is the only way to be dual-homed in Docker. The proxy script is bind
    mounted READ-ONLY: the gateway must not be able to rewrite its own policy engine.
    """
    stop_gateway(name)
    # --entrypoint OVERRIDES the image's auth bootstrap. The gateway is NOT a Claude child: it
    # needs no credential, and running the bootstrap made it abort on the read-only rootfs
    # (`mkdir /home/claude/.claude` fails, `set -e` exits) so the container died instantly. The
    # gateway was silently dead through an entire measurement attempt, and the only symptom was
    # Claude reporting an API error -- which, taken at face value, would have "measured" that
    # Claude needs no egress at all. A dead instrument that produces a plausible reading is worse
    # than one that produces none.
    args = ["run", "-d", "--name", name, "--label", branding.label("component") + "=egress",
            "--entrypoint", "python3",
            "--user", "1001:1001", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=32m",
            "--memory", "512m", "--pids-limit", "128",
            "--env", branding.env_var("egress", "mode") + "=%s" % mode,
            "--env", branding.env_var("egress", "allow") + "=%s" % json.dumps(list(allow)),
            "--env", branding.env_var("egress", "policy", "version") + "=%s" % policy_version,
            "--mount", "type=bind,source=%s,target=/opt/egress_proxy.py,readonly"
                       % proxy_script_host_path,
            image, "/opt/egress_proxy.py"]
    r = da.docker(args, timeout=180)
    if not r.ok:
        return {"ok": False, "error": r.err.strip()[:400]}
    cid = r.out.strip()
    conn = da.docker(["network", "connect", network, cid], timeout=120)
    if not conn.ok:
        return {"ok": False, "container_id": cid,
                "error": "could not attach the gateway to %s: %s" % (network,
                                                                     conn.err.strip()[:300])}
    # VERIFY IT IS ACTUALLY LISTENING before returning ok. "docker run -d exited 0" means the
    # daemon accepted the request, not that the process inside survived -- the distinction that
    # cost a measurement run. Poll for the proxy's own startup line in its ledger.
    import time as _t
    deadline = _t.time() + 30
    while _t.time() < deadline:
        running = da.docker(["inspect", "-f", "{{.State.Running}}", cid], timeout=60)
        logs = gateway_logs(name)
        if running.ok and running.out.strip() == "true" and '"event": "startup"' in logs:
            return {"ok": True, "container_id": cid, "name": name, "mode": mode,
                    "allow": list(allow), "policy_version": policy_version,
                    "startup_confirmed": True}
        _t.sleep(1.0)
    return {"ok": False, "container_id": cid, "name": name,
            "error": "gateway did not report startup within 30s; logs: %s"
                     % gateway_logs(name)[-300:]}


def gateway_logs(name: str = GATEWAY_NAME) -> str:
    r = da.docker(["logs", name], timeout=120)
    return (r.out or "") + (r.err or "")


def stop_gateway(name: str = GATEWAY_NAME) -> bool:
    return da.docker(["rm", "-f", name], timeout=120).ok


def remove_network(name: str = NETWORK_NAME) -> bool:
    return da.docker(["network", "rm", name], timeout=120).ok


def gateway_host(name: str = GATEWAY_NAME) -> str:
    return name


def proxy_env(name: str = GATEWAY_NAME, port: int = GATEWAY_PORT) -> dict:
    url = "http://%s:%d" % (name, port)
    return {"HTTPS_PROXY": url, "HTTP_PROXY": url, "https_proxy": url, "http_proxy": url,
            "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"}

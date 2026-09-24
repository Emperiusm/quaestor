"""tunnel -- the owner-operated bridge from chatgpt.com to this machine's loopback server.

WHY THIS EXISTS
---------------
ChatGPT cannot reach ``127.0.0.1`` -- no cloud client can, by design. A Plus-tier account's
custom-connector path needs a PUBLIC HTTPS endpoint speaking Streamable HTTP. This module is the
supported way to get one without surrendering the local-first posture:

    ChatGPT (Plus, read-only)  ->  public tunnel URL  ->  cloudflared (outbound-only)
        ->  loopback HTTP server  ->  adapter  ->  ledger, stores, worktrees

THE CAPABILITY CEILING IS THE TOKEN, NOT A PROMISE
--------------------------------------------------
``tunnel serve`` provisions the REMOTE transport token and hands ONLY that token toward the
public URL. The remote token authenticates the ``HTTP_REMOTE_BEARER`` channel, and that channel
is read-only at the adapter -- writes are refused BY CHANNEL and ledgered. The write-capable
loopback token never leaves the machine, so "ChatGPT can read" never becomes "ChatGPT can
dispatch": the ceiling travels with which secret was shared.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
No browser automation, no scraping of any chat product, no credential reuse: a Claude credential
is refused by name as transport auth (see transports.mcp.auth), and driving a chat UI with a
scripted browser is between the owner and their provider's terms -- this platform wants no part
of it. Writes stay where the attestation is: the local owner channel.

cloudflared QUICK TUNNELS
-------------------------
The default path needs NO account: ``cloudflared tunnel --url <loopback>`` prints a fresh
``https://<random>.trycloudflare.com`` URL. It is ephemeral (a new URL most restarts), which for
a single-owner deployment is a feature: the public name rotates with the session. Pass
``--cloudflared`` to point at a specific binary; any tunnel that forwards HTTPS to the loopback
port works -- the server neither knows nor cares which.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Mapping

from quaestor import branding
from quaestor.transports.mcp import auth as transport_auth
from quaestor.transports.mcp import schemas as ts

TUNNEL_INSTRUMENT = "tunnel/1"

#: cloudflared announces the quick-tunnel URL on stderr. ONE regex, stated once.
TUNNEL_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)

#: How long to wait for the tunnel to announce its public URL before declaring failure.
URL_TIMEOUT_S = 60.0


def cloudflared_args(port: int, *, cloudflared: str = "cloudflared") -> list:
    """The quick-tunnel command. PURE. Loopback target only -- the tunnel is a bridge, not a
    second listener: nothing on this machine serves anything but 127.0.0.1."""
    return [str(cloudflared), "tunnel", "--no-autoupdate",
            "--url", "http://127.0.0.1:%d" % int(port)]


def parse_tunnel_url(text: str) -> str:
    """The first trycloudflare URL in tunnel output, or "". PURE."""
    m = TUNNEL_URL_RE.search(str(text or ""))
    return m.group(0) if m else ""


def _remote_token(directory: str | None = None) -> dict:
    """The remote token, provisioning one if absent. Impure. The VALUE travels once, printed to
    the owner who ran ``tunnel serve`` -- the same once-only discipline as provisioning."""
    digest, token_id = transport_auth.load_digest(directory, remote=True)
    if digest:
        return {"token_id": token_id, "value": "",
                "note": ("existing remote token in use; its value was shown when it was "
                         "provisioned. Rotate with '%s' to get a fresh one."
                         % branding.command("tunnel", "token"))}
    out = transport_auth.provision(directory, remote=True)
    return {"token_id": out["token_id"], "value": out["value_returned_once"], "note": ""}


def serve(home: str, *, repo_table: Mapping[str, str], port: int = 0,
          cloudflared: str = "cloudflared", auth_dir: str | None = None,
          forbidden_alias_roots: tuple = (), stdout=None) -> int:
    """Run the loopback MCP server behind a quick tunnel until interrupted. Impure. Blocking.

    Returns a process exit code. The public URL and the remote token (when freshly provisioned)
    are printed ONCE, as setup JSON, before the process settles into serving.
    """
    stdout = stdout or __import__("sys").stdout
    token_doc = _remote_token(auth_dir)
    try:
        from quaestor.transports.mcp.adapter import Adapter
        from quaestor.transports.mcp import server as mcp_server
        adapter = Adapter(home, repo_table=dict(repo_table),
                          forbidden_alias_roots=tuple(forbidden_alias_roots))
        srv = mcp_server.MCPServer(adapter, auth_dir=auth_dir)
        httpd, bound = mcp_server.build_http_server(srv, host="127.0.0.1", port=int(port))
    except Exception as exc:  # noqa: BLE001 - a tunnel that cannot start must say why and stop
        stdout.write(json.dumps({"error": "TUNNEL_START_FAILED",
                                 "detail": "%s: %s" % (type(exc).__name__, exc),
                                 "instrument": TUNNEL_INSTRUMENT}) + "\n")
        return 2

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    proc = subprocess.Popen(cloudflared_args(bound, cloudflared=cloudflared),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace")
    url = ""
    deadline = time.time() + URL_TIMEOUT_S

    def _read_url() -> None:
        nonlocal url
        assert proc.stdout is not None
        for line in proc.stdout:
            if url:
                continue
            url = parse_tunnel_url(line)
            if url:
                break

    reader = threading.Thread(target=_read_url, daemon=True)
    reader.start()
    while time.time() < deadline and not url and proc.poll() is None:
        time.sleep(0.2)

    if not url:
        proc.terminate()
        httpd.shutdown()
        adapter.close()
        stdout.write(json.dumps({
            "error": "NO_TUNNEL_URL",
            "detail": ("no public URL appeared within %ds. Is the %s binary on PATH and is "
                       "outbound HTTPS permitted? Any tunnel forwarding HTTPS to 127.0.0.1:%d "
                       "works; this binary is not a hard dependency."
                       % (int(URL_TIMEOUT_S), cloudflared, bound)),
            "instrument": TUNNEL_INSTRUMENT}) + "\n")
        return 3

    setup = {
        "instrument": TUNNEL_INSTRUMENT,
        "connector_url": url + "/mcp",
        "health": url + "/healthz",
        "surface": "read-only (remote channel)",
        "transport_execution_mode": adapter.mode,
        "remote_token": token_doc,
        "setup": ("ChatGPT (web) -> Settings -> Apps & Connectors -> advanced settings -> "
                  "developer mode ON -> create a connector with connector_url. Authentication: "
                  "bearer/token, pasting remote_token.value when it is non-empty. Every tool "
                  "advertised there is read-only; state changes happen through the local "
                  "owner channel, which is where the attestation is."),
        "note": ("the quick-tunnel hostname is EPHEMERAL. A new run may publish a new URL; "
                 "update the connector when it changes. Revoke remote access with '%s'."
                 % branding.command("tunnel", "revoke")),
    }
    stdout.write(json.dumps(setup, indent=2, default=str) + "\n")
    stdout.flush()
    try:
        while proc.poll() is None:
            time.sleep(0.5)
        code = int(proc.returncode or 0)
    except KeyboardInterrupt:
        code = 0
    finally:
        if proc.poll() is None:
            proc.terminate()
        httpd.shutdown()
        adapter.close()
    return 0


def doctor(url: str, *, token: str = "", timeout: float = 20.0) -> dict:
    """Measure a deployed tunnel endpoint from OUTSIDE. Impure. NEVER raises.

    The checks are the ones a connector will silently fail on: reachable health, a bearer-enforced
    MCP route, a read-only advertised surface, and no OAuth metadata fiction. Findings carry
    PASS/FAIL and what each FAIL costs the connector.
    """
    base = str(url or "").rstrip("/")
    findings: list = []

    def _get(path: str) -> tuple:
        try:
            with urllib.request.urlopen(base + path, timeout=timeout) as r:
                return r.status, dict(r.headers).get("Content-Type", ""), r.read().decode(
                    "utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers).get("Content-Type", ""), e.read().decode(
                "utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - a doctor reports; it does not crash
            return 0, "", "%s: %s" % (type(exc).__name__, exc)

    def _post(body: Mapping, tok: str = "") -> tuple:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(base + "/mcp", data=data,
                                     headers={"Content-Type": "application/json"})
        if tok:
            req.add_header("Authorization", "Bearer " + tok)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, "", r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, "", e.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return 0, "", "%s: %s" % (type(exc).__name__, exc)

    code, _ct, _body = _get("/healthz")
    findings.append({"check": "health", "ok": code == 200,
                     "cost": "the connector cannot reach this deployment at all"})

    code, _ct, _body = _post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    findings.append({"check": "mcp_bearer_enforced", "ok": code == 401,
                     "cost": "an unauthenticated caller can use the transport"})

    listed = []
    if token:
        code, _ct, body = _post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token)
        try:
            listed = [t.get("name") for t in
                      (json.loads(body).get("result") or {}).get("tools") or []]
        except ValueError:
            listed = []
        read_only = ts.READ_ONLY_TOOLS
        findings.append({"check": "token_accepted", "ok": code == 200 and bool(listed),
                         "cost": "the connector will authenticate-fail on every call"})
        findings.append({"check": "surface_read_only",
                         "ok": bool(listed) and all(n in read_only for n in listed),
                         "advertised": sorted(n for n in listed if n),
                         "cost": "a write tool advertised to a channel that must refuse it"})

    for path in ("/.well-known/oauth-protected-resource",
                 "/.well-known/oauth-authorization-server"):
        code, ctype, body = _get(path)
        findings.append({"check": "no_oauth_fiction", "path": path,
                         "ok": code == 404 and "json" not in ctype.lower(),
                         "cost": "metadata that parses but lies is worse than absence"})

    return {"instrument": TUNNEL_INSTRUMENT, "url": base,
            "ok": all(f.get("ok") for f in findings), "findings": findings}

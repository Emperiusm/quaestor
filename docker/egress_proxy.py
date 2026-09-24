#!/usr/bin/env python3
"""egress_proxy -- a CONNECT-only allowlist gateway with a decision ledger.

WHY THIS EXISTS
---------------
P2.5 proved network NAMESPACE isolation (no host networking, no published ports) but left the
default Docker bridge's outbound route wide open. A confined child could still reach any host on
the internet. This closes that, and the closure has to be structural rather than advisory:

    the child attaches ONLY to an --internal Docker network, which has no external route at all.

So a child that ignores HTTPS_PROXY does not get direct egress -- it gets nothing. That property
is what makes this a boundary instead of a setting. A syntactically correct proxy configuration
with a working direct route beside it is EGRESS_POLICY_FAIL, not a pass.

WHAT IT ENFORCES
----------------
CONNECT host:port against an explicit allowlist, with the matching RULE recorded for every
decision so an operator can see which line made the call. Plain (non-CONNECT) HTTP is refused:
Claude Code speaks TLS, so an unencrypted request through this proxy is either a mistake or
something worth noticing.

NO TLS INTERCEPTION. The proxy never terminates TLS, so it cannot read traffic and does not need
to hold a CA. Hostname+port enforcement gives a meaningful destination allowlist, which is the
stated bar for this stage; interception would add a decryption capability nobody has justified.

MODES
-----
    observe   allow everything, log everything -- used ONCE to MEASURE what Claude actually
              needs, because deriving an allowlist from memory is how you end up allowing
              endpoints that are not used and blocking ones that are.
    enforce   allow only what the policy names.

Stdlib only, and it runs inside the same pinned image as the child -- no new dependency, no new
image, no third-party proxy whose configuration language becomes another thing to get wrong.
"""
from __future__ import annotations

import json
import os
import select
import socket
import sys
import threading
import time

LISTEN_HOST = os.environ.get("QUAESTOR_EGRESS_LISTEN", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("QUAESTOR_EGRESS_PORT", "8080"))
MODE = os.environ.get("QUAESTOR_EGRESS_MODE", "enforce").strip().lower()
POLICY_VERSION = os.environ.get("QUAESTOR_EGRESS_POLICY_VERSION", "unversioned")
try:
    ALLOW = json.loads(os.environ.get("QUAESTOR_EGRESS_ALLOW", "[]"))
except ValueError:
    ALLOW = []

_lock = threading.Lock()


def log(**kw):
    kw["ts"] = time.time()
    kw["policy_version"] = POLICY_VERSION
    kw["mode"] = MODE
    with _lock:
        sys.stdout.write(json.dumps(kw, sort_keys=True) + "\n")
        sys.stdout.flush()


def match_rule(host: str, port: int, allow) -> tuple:
    """(allowed, rule). PURE.

    A rule is ``"host:port"``. ``*.example.com`` matches any SUBDOMAIN of example.com and NOT
    example.com itself -- a wildcard that also matched the parent would silently widen every rule
    written for a CDN. Matching is case-insensitive; the port must match exactly, because "the
    right host on the wrong port" is a different destination.
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


def pump(a: socket.socket, b: socket.socket) -> int:
    total = 0
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 120)
            if x or not r:
                break
            for s in r:
                try:
                    data = s.recv(65536)
                except OSError:
                    return total
                if not data:
                    return total
                total += len(data)
                dst = b if s is a else a
                try:
                    dst.sendall(data)
                except OSError:
                    return total
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    return total


def handle(conn: socket.socket, peer):
    conn.settimeout(120)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        if len(parts) < 2:
            log(event="malformed", peer=str(peer), decision="DENY", rule="malformed-request")
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        method, target = parts[0].upper(), parts[1]
        if method != "CONNECT":
            log(event="non_connect", peer=str(peer), method=method, target=target,
                decision="DENY", rule="connect-only")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nthis gateway forwards CONNECT only\r\n")
            return

        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            log(event="bad_port", peer=str(peer), target=target, decision="DENY",
                rule="unparseable-port")
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        allowed, rule = (True, "observe-mode") if MODE == "observe" else match_rule(host, port,
                                                                                    ALLOW)
        if not allowed:
            log(event="connect", peer=str(peer), host=host, port=port, decision="DENY",
                rule="no-matching-allow-rule")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\negress policy: destination not allowed\r\n")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            log(event="connect", peer=str(peer), host=host, port=port, decision="ALLOW",
                rule=rule, upstream="FAILED", error="%s: %s" % (type(exc).__name__, exc))
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        log(event="connect", peer=str(peer), host=host, port=port, decision="ALLOW", rule=rule,
            upstream="ESTABLISHED")
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        pump(conn, upstream)
    except (OSError, socket.timeout):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(64)
    log(event="startup", listen="%s:%d" % (LISTEN_HOST, LISTEN_PORT), allow=ALLOW,
        decision="N/A", rule="startup")
    while True:
        try:
            conn, peer = srv.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())

"""websocket_client -- a minimal RFC 6455 client. Stdlib only.

WHY THIS EXISTS RATHER THAN A DEPENDENCY
-----------------------------------------
This platform has no third-party dependencies at all, and the one place it needed a facility the
stdlib lacks -- the clipboard -- it shelled out to PowerShell rather than take a library. The
Chrome DevTools Protocol needs a WebSocket, the stdlib has no client, and adding the project's
first dependency for its most fragile feature is a poor trade. So: ~200 lines, fully testable
against a socket double, and the browser transport that uses it stays optional either way.

SCOPE, DELIBERATELY SMALL
-------------------------
It speaks exactly as much of RFC 6455 as one local CDP connection needs:

    * the opening handshake, with the Sec-WebSocket-Accept digest VERIFIED (see below);
    * client->server TEXT frames, always masked, with 7 / 16 / 64-bit payload lengths;
    * server->client TEXT and BINARY frames, continuation frames reassembled;
    * PING answered with PONG, PONG ignored, CLOSE answered and surfaced as a clean EOF.

It does NOT implement: permessage-deflate, extensions, subprotocol negotiation, or fragmenting
outbound messages. A CDP command is a short JSON document, and inventing capability nobody
exercises is how a "minimal" client becomes an unaudited one.

TWO THINGS THAT ARE NOT OPTIONAL
---------------------------------
THE ACCEPT DIGEST IS VERIFIED. It is the only evidence that what answered is a WebSocket
endpoint and not an HTTP server (or a captive portal) echoing a 101. Skipping it is the classic
shortcut, and it turns "connected" into "connected to something".

CLIENT FRAMES ARE ALWAYS MASKED, with keys from ``secrets``. RFC 6455 requires it of clients and
conforming servers hang up without it; the mask is anti-cache-poisoning, not secrecy, so a
predictable one would be worse than useless -- it would look like a mask.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import struct
import urllib.parse

WEBSOCKET_INSTRUMENT = "websocket_client/1"

#: RFC 6455 section 1.3. Concatenated with the client key to derive the accept digest.
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

#: Largest inbound message accepted. A page's text can be long; a multi-gigabyte frame is a
#: pathology we NAME rather than allocate for. Same discipline as the webui's response bound.
MAX_MESSAGE_BYTES = 16 << 20


class WebSocketError(RuntimeError):
    """Any protocol-level failure. Named so callers can refuse rather than crash."""


class WebSocketClosed(WebSocketError):
    """The peer closed the connection. A clean EOF, not a fault."""


def _accept_digest(key: str) -> str:
    """The Sec-WebSocket-Accept value a conforming server must return. PURE."""
    return base64.b64encode(
        hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")  # noqa: S324


def _mask(payload: bytes, key: bytes) -> bytes:
    """RFC 6455 masking. PURE and self-inverse."""
    return bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def encode_frame(payload: bytes, *, opcode: int = OP_TEXT, mask_key: bytes | None = None) -> bytes:
    """One masked client frame. PURE when ``mask_key`` is supplied (controls supply one).

    FIN is always set: outbound CDP commands are short JSON documents and there is no reason to
    fragment one, so the fragmenting path is absent rather than untested.
    """
    key = mask_key if mask_key is not None else secrets.token_bytes(4)
    if len(key) != 4:
        raise WebSocketError("a mask key is exactly 4 bytes")
    header = bytearray([0x80 | (opcode & 0x0F)])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < (1 << 16):
        header.append(0x80 | 126)
        header += struct.pack("!H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", length)
    return bytes(header) + key + _mask(payload, key)


class WebSocket:
    """One client connection. Not thread-safe: one CDP session, one caller."""

    def __init__(self, sock, *, timeout: float = 30.0):
        self._sock = sock
        self._buf = b""
        self._closed = False
        self._sock.settimeout(float(timeout))

    # -- construction --------------------------------------------------------------------------
    @classmethod
    def connect(cls, url: str, *, timeout: float = 30.0, opener=None) -> "WebSocket":
        """Open and handshake. Impure. ``opener`` is the socket seam controls substitute."""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise WebSocketError("unsupported scheme %r; this client speaks ws:// only"
                                 % parts.scheme)
        if parts.scheme == "wss":
            # DELIBERATE: no TLS. This client exists for a LOOPBACK CDP port. A wss:// URL means
            # the caller is pointing it somewhere it was never audited to go.
            raise WebSocketError(
                "wss:// is not supported: this client exists for a loopback debug port and has "
                "no TLS path; refusing rather than appearing to secure the connection")
        host = parts.hostname or "127.0.0.1"
        port = int(parts.port or 80)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query

        sock = (opener or socket.create_connection)((host, port), timeout)
        ws = cls(sock, timeout=timeout)
        try:
            ws._handshake(host, port, target)
        except BaseException:
            # A FAILED HANDSHAKE STILL OPENED A SOCKET. Dropping the reference leaves the fd to
            # socket.__del__, and a seat that retries against a stale devtools URL leaks one per
            # attempt -- on a long unattended run that is a file-descriptor exhaustion nobody
            # would trace back to a handshake that failed hours earlier.
            ws.close()
            raise
        return ws

    def _handshake(self, host: str, port: int, target: str) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n" % (target, host, port, key))
        self._sock.sendall(request.encode("ascii"))

        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during the opening handshake")
            head += chunk
            if len(head) > 64 << 10:
                raise WebSocketError("handshake response exceeded 64KiB")
        raw_head, _, rest = head.partition(b"\r\n\r\n")
        self._buf = rest

        lines = raw_head.decode("latin-1").split("\r\n")
        status = lines[0] if lines else ""
        if " 101" not in status:
            raise WebSocketError("server refused the upgrade: %s" % status[:120])
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if headers.get("upgrade", "").lower() != "websocket":
            raise WebSocketError("server did not upgrade to websocket")
        # THE DIGEST CHECK. Without it, "connected" only means "something answered 101".
        expected = _accept_digest(key)
        if headers.get("sec-websocket-accept", "") != expected:
            raise WebSocketError(
                "Sec-WebSocket-Accept did not match: what answered is not a WebSocket endpoint")

    # -- io ------------------------------------------------------------------------------------
    def _recv_exactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise WebSocketClosed("peer closed the connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _read_frame(self) -> tuple:
        """(fin, opcode, payload) for ONE frame. Server frames are never masked in practice,
        but a masked one is handled rather than silently mis-parsed."""
        b0, b1 = self._recv_exactly(2)
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exactly(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exactly(8))[0]
        if length > MAX_MESSAGE_BYTES:
            raise WebSocketError("inbound frame of %d bytes exceeds the %d-byte bound"
                                 % (length, MAX_MESSAGE_BYTES))
        key = self._recv_exactly(4) if masked else b""
        payload = self._recv_exactly(length) if length else b""
        if masked:
            payload = _mask(payload, key)
        return fin, opcode, payload

    def send(self, text: str) -> None:
        if self._closed:
            raise WebSocketClosed("send on a closed websocket")
        self._sock.sendall(encode_frame(str(text).encode("utf-8"), opcode=OP_TEXT))

    def recv(self) -> str:
        """The next complete TEXT message. Control frames are handled and skipped.

        Continuation frames are reassembled, because a long page-evaluation result is exactly
        the case a server would fragment and exactly the case this client exists to read.
        """
        if self._closed:
            raise WebSocketClosed("recv on a closed websocket")
        chunks: list = []
        total = 0
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == OP_PING:
                self._sock.sendall(encode_frame(payload, opcode=OP_PONG))
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                self._closed = True
                try:
                    self._sock.sendall(encode_frame(b"", opcode=OP_CLOSE))
                except OSError:
                    pass
                raise WebSocketClosed("peer sent CLOSE")
            if opcode in (OP_TEXT, OP_BINARY, OP_CONTINUATION):
                chunks.append(payload)
                total += len(payload)
                if total > MAX_MESSAGE_BYTES:
                    raise WebSocketError("reassembled message exceeded the byte bound")
                if fin:
                    return b"".join(chunks).decode("utf-8", "replace")
                continue
            raise WebSocketError("unknown opcode 0x%X" % opcode)

    def send_json(self, obj) -> None:
        self.send(json.dumps(obj))

    def recv_json(self):
        return json.loads(self.recv())

    def close(self) -> None:
        """Best effort. NEVER raises: closing is cleanup, and cleanup that throws loses the
        original error that caused it."""
        if not self._closed:
            try:
                self._sock.sendall(encode_frame(b"", opcode=OP_CLOSE))
            except OSError:
                pass
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


# Re-exported for controls that build frames without a socket.
__all__ = ["WebSocket", "WebSocketError", "WebSocketClosed", "encode_frame",
           "OP_TEXT", "OP_BINARY", "OP_CLOSE", "OP_PING", "OP_PONG", "OP_CONTINUATION",
           "MAX_MESSAGE_BYTES", "WEBSOCKET_INSTRUMENT"]

"""test_browser_transport -- CONTROLS for the zero-dependency browser transport.

NO TEST HERE OPENS A SOCKET, A BROWSER, OR THE NETWORK. Every control drives a socket double or
a fake transport. A suite that needed a running Chrome is a suite nobody runs.

WHAT IS BEING DEFENDED
----------------------
This is the first hand-rolled network protocol on the platform, written instead of taking the
project's first third-party dependency. That trade is only sound if the implementation is
actually correct, so these controls check it against RFC 6455's own worked example and against
the specific shortcuts a "minimal" WebSocket client is usually guilty of:

    * not verifying Sec-WebSocket-Accept (turns "connected" into "connected to something");
    * not masking client frames (RFC-required; conforming servers hang up);
    * mishandling 16/64-bit lengths, continuation frames, or control frames interleaved
      mid-message -- all of which appear the moment a page evaluation returns real text.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from quaestor.executors import browser_transport as bt  # noqa: E402
from quaestor.executors import chatgpt_web_page as cw  # noqa: E402
from quaestor.executors import websocket_client as wsc  # noqa: E402


def server_frame(payload: bytes, *, opcode: int = wsc.OP_TEXT, fin: bool = True) -> bytes:
    """An UNMASKED server->client frame, built independently of the module under test.

    Deliberately a second implementation: a control that framed its input with the subject's own
    encoder would prove the encoder is self-consistent, not that it is correct.
    """
    import struct
    head = bytearray([(0x80 if fin else 0x00) | (opcode & 0x0F)])
    n = len(payload)
    if n < 126:
        head.append(n)
    elif n < (1 << 16):
        head.append(126)
        head += struct.pack("!H", n)
    else:
        head.append(127)
        head += struct.pack("!Q", n)
    return bytes(head) + payload


class FakeSocket:
    """A socket double. ``script`` is the byte stream the peer will send."""

    def __init__(self, script=b"", *, accept_key_from=None):
        self.sent = b""
        self._script = script
        self._accept_from = accept_key_from
        self.closed = False
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        self.sent += data
        # A cooperative peer completes the handshake using the key the client actually sent.
        if self._accept_from is not None and b"Sec-WebSocket-Key:" in data and not self._script:
            key = ""
            for line in data.decode("latin-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            digest = self._accept_from(key)
            self._script = ("HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n\r\n" % digest).encode("ascii")

    def recv(self, n):
        if not self._script:
            return b""
        out, self._script = self._script[:n], self._script[n:]
        return out

    def close(self):
        self.closed = True

    def feed(self, data: bytes):
        self._script += data


class TestFrameEncoding(unittest.TestCase):
    def test_the_accept_digest_matches_the_rfc_worked_example(self):
        """RFC 6455 section 1.3 publishes this exact pair. If it matches, the handshake maths
        is right rather than merely self-consistent."""
        self.assertEqual(wsc._accept_digest("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_client_frames_are_always_masked(self):
        """RFC-required of clients; conforming servers hang up without it."""
        frame = wsc.encode_frame(b"hi")
        self.assertTrue(frame[1] & 0x80, "the MASK bit was not set on a client frame")

    def test_masking_is_self_inverse_and_uses_the_supplied_key(self):
        key = b"\x01\x02\x03\x04"
        frame = wsc.encode_frame(b"hello", mask_key=key)
        self.assertEqual(frame[2:6], key)
        self.assertEqual(wsc._mask(frame[6:], key), b"hello")

    def test_length_encoding_covers_all_three_widths(self):
        key = b"\x00\x00\x00\x00"
        short = wsc.encode_frame(b"x" * 5, mask_key=key)
        self.assertEqual(short[1] & 0x7F, 5)
        medium = wsc.encode_frame(b"x" * 300, mask_key=key)
        self.assertEqual(medium[1] & 0x7F, 126)
        self.assertEqual(int.from_bytes(medium[2:4], "big"), 300)
        large = wsc.encode_frame(b"x" * (1 << 16), mask_key=key)
        self.assertEqual(large[1] & 0x7F, 127)
        self.assertEqual(int.from_bytes(large[2:10], "big"), 1 << 16)

    def test_a_bad_mask_key_is_refused(self):
        for bad in (b"", b"abc", b"abcde"):
            with self.assertRaises(wsc.WebSocketError):
                wsc.encode_frame(b"x", mask_key=bad)


class TestHandshake(unittest.TestCase):
    def _connect(self, sock):
        return wsc.WebSocket.connect("ws://127.0.0.1:9222/devtools/page/ABC",
                                     opener=lambda *_a, **_k: sock)

    def test_a_good_handshake_connects_and_sends_the_required_headers(self):
        sock = FakeSocket(accept_key_from=wsc._accept_digest)
        ws = self._connect(sock)
        request = sock.sent.decode("latin-1")
        self.assertIn("GET /devtools/page/ABC HTTP/1.1", request)
        self.assertIn("Upgrade: websocket", request)
        self.assertIn("Sec-WebSocket-Version: 13", request)
        self.assertIn("Sec-WebSocket-Key:", request)
        ws.close()

    def test_a_WRONG_accept_digest_is_refused(self):
        """THE SHORTCUT THIS CONTROL EXISTS FOR. Without the digest check, anything answering
        101 -- an HTTP server, a captive portal -- would be treated as a WebSocket peer."""
        sock = FakeSocket(b"HTTP/1.1 101 Switching Protocols\r\n"
                          b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          b"Sec-WebSocket-Accept: totallywrongvalue=\r\n\r\n")
        with self.assertRaises(wsc.WebSocketError) as caught:
            self._connect(sock)
        self.assertIn("not a WebSocket endpoint", str(caught.exception))

    def test_a_non_101_response_is_refused(self):
        sock = FakeSocket(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        with self.assertRaises(wsc.WebSocketError):
            self._connect(sock)

    def test_a_101_without_the_upgrade_header_is_refused(self):
        sock = FakeSocket(b"HTTP/1.1 101 Switching Protocols\r\n"
                          b"Sec-WebSocket-Accept: x\r\n\r\n")
        with self.assertRaises(wsc.WebSocketError):
            self._connect(sock)

    def test_a_closed_connection_mid_handshake_is_named_not_hung(self):
        sock = FakeSocket(b"HTTP/1.1 101 Switch")
        with self.assertRaises(wsc.WebSocketError):
            self._connect(sock)

    def test_wss_is_refused_rather_than_silently_unencrypted(self):
        """This client has no TLS. Accepting wss:// would appear to secure a connection it
        cannot secure -- worse than refusing."""
        with self.assertRaises(wsc.WebSocketError) as caught:
            wsc.WebSocket.connect("wss://example.com/socket",
                                  opener=lambda *_a, **_k: FakeSocket())
        self.assertIn("wss://", str(caught.exception))


class TestMessageIO(unittest.TestCase):
    def _connected(self, *frames):
        sock = FakeSocket(accept_key_from=wsc._accept_digest)
        ws = wsc.WebSocket.connect("ws://127.0.0.1:9222/x", opener=lambda *_a, **_k: sock)
        for f in frames:
            sock.feed(f)
        return ws, sock

    def test_a_simple_text_message_round_trips(self):
        ws, sock = self._connected(server_frame(b'{"id":1,"result":{}}'))
        self.assertEqual(ws.recv_json(), {"id": 1, "result": {}})
        before = len(sock.sent)
        ws.send_json({"id": 2, "method": "Runtime.evaluate"})
        # The outbound bytes are MASKED, so the plaintext cannot appear on the wire. Decoding
        # the frame the way a server would re-proves the mask is genuinely applied.
        frame = sock.sent[before:]
        self.assertTrue(frame[1] & 0x80, "the outbound frame was not masked")
        key, body = frame[2:6], frame[6:]
        self.assertEqual(json.loads(wsc._mask(body, key).decode("utf-8")),
                         {"id": 2, "method": "Runtime.evaluate"})


    def test_continuation_frames_are_reassembled(self):
        """A long page-evaluation result is exactly what a server fragments, and exactly what
        this client exists to read."""
        ws, _s = self._connected(
            server_frame(b'{"id":1,"res', fin=False),
            server_frame(b'ult":"ok"}', opcode=wsc.OP_CONTINUATION, fin=True))
        self.assertEqual(ws.recv_json(), {"id": 1, "result": "ok"})

    def test_a_ping_mid_message_is_answered_and_does_not_corrupt_the_stream(self):
        ws, sock = self._connected(
            server_frame(b"beat", opcode=wsc.OP_PING),
            server_frame(b'{"ok":true}'))
        before = len(sock.sent)
        self.assertEqual(ws.recv_json(), {"ok": True})
        self.assertGreater(len(sock.sent), before, "the PING was not answered with a PONG")

    def test_a_pong_is_ignored(self):
        ws, _s = self._connected(server_frame(b"", opcode=wsc.OP_PONG),
                                 server_frame(b'{"ok":1}'))
        self.assertEqual(ws.recv_json(), {"ok": 1})

    def test_a_close_frame_is_a_clean_eof_not_a_fault(self):
        ws, _s = self._connected(server_frame(b"", opcode=wsc.OP_CLOSE))
        with self.assertRaises(wsc.WebSocketClosed):
            ws.recv()

    def test_a_16_bit_length_message_reads(self):
        payload = json.dumps({"data": "y" * 400}).encode("utf-8")
        ws, _s = self._connected(server_frame(payload))
        self.assertEqual(len(ws.recv_json()["data"]), 400)

    def test_an_oversized_frame_is_named_not_allocated(self):
        import struct
        huge = bytes([0x81, 127]) + struct.pack("!Q", wsc.MAX_MESSAGE_BYTES + 1)
        ws, _s = self._connected(huge)
        with self.assertRaises(wsc.WebSocketError) as caught:
            ws.recv()
        self.assertIn("exceeds", str(caught.exception))

    def test_an_unknown_opcode_is_refused(self):
        ws, _s = self._connected(server_frame(b"?", opcode=0x7))
        with self.assertRaises(wsc.WebSocketError):
            ws.recv()

    def test_close_never_raises_even_on_a_dead_socket(self):
        ws, sock = self._connected()

        def _boom(_data):
            raise OSError("gone")

        sock.sendall = _boom
        ws.close()      # must not raise: cleanup that throws loses the original error
        self.assertTrue(sock.closed)

    def test_use_after_close_is_named(self):
        ws, _s = self._connected()
        ws.close()
        with self.assertRaises(wsc.WebSocketClosed):
            ws.send("x")
        with self.assertRaises(wsc.WebSocketClosed):
            ws.recv()


class FakeWs:
    """A CDP peer. ``replies`` maps method -> result (or a callable taking params)."""

    def __init__(self, replies=None, *, events=0):
        self.replies = dict(replies or {})
        self.sent = []
        self._queue = []
        self._events = events
        self.closed = False

    def send_json(self, obj):
        self.sent.append(obj)
        # Unsolicited events first: CDP interleaves them, and a client that reads the next
        # message rather than the matching id will hand back an event as an answer.
        for _ in range(self._events):
            self._queue.append({"method": "Page.frameNavigated", "params": {}})
        reply = self.replies.get(obj.get("method"), {})
        if callable(reply):
            reply = reply(obj.get("params") or {})
        if isinstance(reply, dict) and "error" in reply:
            self._queue.append({"id": obj["id"], "error": reply["error"]})
        else:
            self._queue.append({"id": obj["id"], "result": reply})

    def recv_json(self):
        if not self._queue:
            raise AssertionError("client read more messages than the peer produced")
        return self._queue.pop(0)

    def close(self):
        self.closed = True


def _value(v):
    return {"result": {"value": v}}


TARGETS = [{"type": "background_page", "url": "chrome-extension://x", "webSocketDebuggerUrl": "ws://x"},
           {"type": "page", "url": "https://example.com/", "webSocketDebuggerUrl": "ws://a"},
           {"type": "page", "url": "https://chatgpt.com/c/abc", "webSocketDebuggerUrl": "ws://b"}]


class TestCdpTransport(unittest.TestCase):
    def _attach(self, ws, *, targets=None, match=""):
        return bt.CdpTransport.attach(
            match=match,
            http_json=lambda *_a, **_k: TARGETS if targets is None else targets,
            connect=lambda *_a, **_k: ws)

    def test_evaluate_returns_the_page_value(self):
        ws = FakeWs({"Runtime.evaluate": _value("hello")})
        t = self._attach(ws)
        self.assertEqual(t.evaluate("1+1"), "hello")
        sent = ws.sent[0]
        self.assertEqual(sent["method"], "Runtime.evaluate")
        self.assertTrue(sent["params"]["returnByValue"])
        self.assertTrue(sent["params"]["awaitPromise"],
                        "a promise-returning expression must be awaited, not handed back raw")

    def test_interleaved_events_do_not_become_the_answer(self):
        """CDP interleaves unsolicited events with replies. A client reading the NEXT message
        instead of the MATCHING id hands an event back as a result."""
        ws = FakeWs({"Runtime.evaluate": _value(42)}, events=3)
        t = self._attach(ws)
        self.assertEqual(t.evaluate("x"), 42)

    def test_a_protocol_error_is_named_not_returned_as_a_value(self):
        ws = FakeWs({"Runtime.evaluate": {"error": {"code": -32000, "message": "nope"}}})
        t = self._attach(ws)
        with self.assertRaises(bt.BrowserUnavailable) as caught:
            t.evaluate("boom")
        self.assertEqual(caught.exception.reason, bt.BROWSER_EVAL_FAILED)

    def test_a_page_exception_is_named_not_silently_none(self):
        """A thrown expression returns no value. Passing that back as None would make a broken
        selector indistinguishable from an empty page."""
        ws = FakeWs({"Runtime.evaluate": {"exceptionDetails": {"text": "ReferenceError"},
                                          "result": {}}})
        t = self._attach(ws)
        with self.assertRaises(bt.BrowserUnavailable):
            t.evaluate("missing.thing")

    def test_goto_navigates(self):
        ws = FakeWs({"Page.navigate": {"frameId": "1"}})
        t = self._attach(ws)
        t.goto("https://chatgpt.com/")
        self.assertEqual(ws.sent[0]["method"], "Page.navigate")
        self.assertEqual(ws.sent[0]["params"]["url"], "https://chatgpt.com/")

    def test_attach_prefers_a_page_matching_the_hint(self):
        """The operator may have many tabs open. Grabbing an arbitrary one would type a
        strategist packet into whatever they happened to be reading."""
        captured = {}

        def _connect(url, **_k):
            captured["url"] = url
            return FakeWs()

        bt.CdpTransport.attach(match="chatgpt.com",
                               http_json=lambda *_a, **_k: TARGETS, connect=_connect)
        self.assertEqual(captured["url"], "ws://b")

    def test_attach_with_no_debuggable_browser_is_named_with_the_fix(self):
        def _dead(*_a, **_k):
            raise bt.BrowserUnavailable(bt.BROWSER_NOT_ATTACHED, "connection refused")
        with self.assertRaises(bt.BrowserUnavailable) as caught:
            bt.CdpTransport.attach(http_json=_dead, connect=lambda *_a, **_k: FakeWs())
        self.assertEqual(caught.exception.reason, bt.BROWSER_NOT_ATTACHED)

    def test_a_browser_with_no_page_tab_is_a_different_named_refusal(self):
        with self.assertRaises(bt.BrowserUnavailable) as caught:
            self._attach(FakeWs(), targets=[])
        self.assertEqual(caught.exception.reason, bt.BROWSER_NO_PAGE)
        self.assertIn("remote-debugging-port", str(caught.exception))

    def test_close_never_raises(self):
        class _Angry(FakeWs):
            def close(self):
                raise OSError("gone")
        t = self._attach(_Angry())
        t.close()      # cleanup that throws loses the original error


class TestTransportSelection(unittest.TestCase):
    def test_auto_prefers_playwright_when_importable(self):
        calls = []
        t, why = bt.open_transport(
            prefer=bt.PREFER_AUTO,
            playwright_attach=lambda **_k: calls.append("pw") or "PW",
            cdp_attach=lambda **_k: calls.append("cdp") or "CDP")
        if bt.PlaywrightTransport.available():
            self.assertEqual(t, "PW")
            self.assertIn("playwright", why)
        else:
            self.assertEqual(t, "CDP")
            self.assertIn("cdp", why)

    def test_auto_falls_through_to_cdp_when_playwright_cannot_attach(self):
        """REWRITTEN: the previous version injected a failing playwright seam that was NEVER
        CALLED -- open_transport only reaches it inside `if PlaywrightTransport.available()`,
        and in the shipping configuration playwright is not importable, so the test passed by
        taking a path that had nothing to do with its claim.

        The availability probe is now stubbed too, so the fall-through is actually exercised."""
        calls = []

        def _pw_fails(**_k):
            calls.append("pw")
            raise bt.BrowserUnavailable(bt.BROWSER_NOT_ATTACHED, "importable but not attachable")

        original = bt.PlaywrightTransport.available
        bt.PlaywrightTransport.available = classmethod(lambda cls: True)
        try:
            t, why = bt.open_transport(prefer=bt.PREFER_AUTO, playwright_attach=_pw_fails,
                                       cdp_attach=lambda **_k: "CDP")
        finally:
            bt.PlaywrightTransport.available = original
        self.assertEqual(calls, ["pw"],
                         "the playwright seam was never called, so no fall-through happened")
        self.assertEqual(t, "CDP")
        self.assertIn("cdp", why)

    def test_an_explicit_preference_is_honoured_both_ways(self):
        t, why = bt.open_transport(prefer=bt.PREFER_CDP,
                                   playwright_attach=lambda **_k: "PW",
                                   cdp_attach=lambda **_k: "CDP")
        self.assertEqual((t, "cdp" in why), ("CDP", True))
        t, why = bt.open_transport(prefer=bt.PREFER_PLAYWRIGHT,
                                   playwright_attach=lambda **_k: "PW",
                                   cdp_attach=lambda **_k: "CDP")
        self.assertEqual((t, "playwright" in why), ("PW", True))

    def test_an_unknown_preference_is_refused_not_defaulted(self):
        with self.assertRaises(ValueError):
            bt.open_transport(prefer="telepathy")

    def test_the_choice_is_always_reported(self):
        """A seat that silently changed how it reached the browser is a seat whose failures
        cannot be compared across runs."""
        _t, why = bt.open_transport(prefer=bt.PREFER_CDP, cdp_attach=lambda **_k: "CDP")
        self.assertTrue(why and isinstance(why, str))

    def test_both_transports_satisfy_the_same_interface(self):
        """The interface is four methods precisely so the fragile page logic exists once."""
        for cls in (bt.CdpTransport, bt.PlaywrightTransport):
            for method in ("goto", "evaluate", "url", "close"):
                self.assertTrue(callable(getattr(cls, method, None)),
                                "%s lacks %s" % (cls.__name__, method))

    def test_playwright_availability_never_raises(self):
        self.assertIn(bt.PlaywrightTransport.available(), (True, False))


def code_without_prose(path: str) -> str:
    """The module's CODE with every docstring and comment removed. PURE-ish (reads a file).

    A grep for "captcha" cannot tell an implementation from a sentence explaining that there is
    no implementation -- and the honest explanation is exactly what a reviewer wants written
    down. This platform already settled that argument for its no-transcript control: check by
    STRUCTURE, not by searching prose, or the control has to be deleted the first time someone
    improves the documentation.

    ``ast.unparse`` drops comments for free; docstrings are stripped explicitly.
    """
    import ast
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


class TestNoEvasionMachinery(unittest.TestCase):
    """Automating the operator's own signed-in session is the feature. Defeating a service's
    controls is a different thing, and it is what turns a flagged account into a banned one.

    These controls read the CODE, never the prose -- see ``code_without_prose``.
    """

    EXECUTORS = os.path.join(os.path.dirname(__file__), "..", "src", "quaestor", "executors")

    #: Names that only appear in code when someone is defeating bot detection.
    EVASION = ("stealth", "undetected", "webdriver", "setuseragentoverride",
               "user_agent_override", "captcha", "2captcha", "anticaptcha",
               "proxy_rotat", "spoof")

    def test_the_transport_code_contains_no_detection_evasion(self):
        for name in ("browser_transport.py", "websocket_client.py"):
            code = code_without_prose(os.path.join(self.EXECUTORS, name)).lower()
            for needle in self.EVASION:
                self.assertNotIn(needle, code, "%s implements %r" % (name, needle))

    def test_the_control_would_actually_catch_a_reintroduction(self):
        """A control on the control. A scanner that strips prose could just as easily strip
        everything, and a check that cannot fail proves nothing."""
        import tempfile
        probe = os.path.join(tempfile.mkdtemp(), "probe.py")
        with open(probe, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('"""A docstring mentioning captcha, which is fine."""\n'
                     'def go(page):\n'
                     '    page.evaluate("navigator.webdriver = false")\n')
        code = code_without_prose(probe).lower()
        self.assertNotIn("a docstring mentioning", code, "prose was not stripped")
        self.assertIn("webdriver", code, "the scanner cannot see real code")

    def test_neither_transport_launches_a_browser_or_holds_a_credential(self):
        code = code_without_prose(os.path.join(self.EXECUTORS, "browser_transport.py"))
        self.assertNotIn(".launch(", code,
                         "a transport that launches a browser owns a profile, and a profile is "
                         "where the credential lives")
        for secret in ("password", "openai_api_key", "session_token", "cookie"):
            self.assertNotIn(secret, code.lower(), secret)


class StreamingPage:
    """A fake ChatGPT page that STREAMS, because the bug this defends against only exists
    while text is still arriving. Each ``evaluate`` of the probe advances one tick.

    ``script`` is the sequence of (stop_present, text) the page shows, tick by tick.
    """

    def __init__(self, script, *, baseline=0, count=None, composer=True, login=False,
                 href="https://chatgpt.com/c/abc123"):
        self.script = list(script)
        self.tick = 0
        self.baseline = baseline
        # What the PAGE reports. Distinct from ``baseline`` on purpose: baseline is what existed
        # before the submit, and a page that reports the SAME number is a page where no new
        # answer ever appeared -- the case that must never read as complete.
        self.count = baseline + 1 if count is None else count
        self.composer = composer
        self.login = login
        self.href = href
        self.filled = None
        self.sent = 0

    def evaluate(self, expression):
        if "dispatchEvent" in expression:
            self.filled = expression
            return "OK"
        if "btn.click()" in expression:
            self.sent += 1
            return "OK"
        # the probe
        if self.tick < len(self.script):
            stop, text = self.script[self.tick]
        else:
            stop, text = self.script[-1] if self.script else (False, "")
        self.tick += 1
        return {"href": self.href, "composer": self.composer, "send": True,
                "stop": bool(stop), "login": self.login, "count": self.count, "text": text}

    def goto(self, url):
        self.href = url

    def url(self):
        return self.href

    def close(self):
        pass


def instant(page, *, timeout_s=1000.0, baseline=0, stable_polls=3):
    """Run await_completion with a virtual clock: no test waits on wall time."""
    ticks = {"n": 0}

    def _clock():
        return ticks["n"] * 1.0

    def _sleep(_s):
        ticks["n"] += 1

    return cw.await_completion(page, baseline=baseline, timeout_s=timeout_s,
                               poll_s=1.0, stable_polls=stable_polls,
                               clock=_clock, sleep=_sleep)


class TestPageClassification(unittest.TestCase):
    def test_logged_out_is_checked_before_the_missing_composer(self):
        """A signed-out page has no composer either. Reporting the downstream symptom sends an
        operator hunting a selector change that never happened."""
        self.assertEqual(cw.classify({"login": True, "composer": False}), cw.STATE_LOGGED_OUT)
        self.assertEqual(cw.classify({"href": "https://chatgpt.com/auth/login",
                                      "composer": True}), cw.STATE_LOGGED_OUT)

    def test_a_missing_composer_is_its_own_state(self):
        self.assertEqual(cw.classify({"composer": False}), cw.STATE_NO_COMPOSER)

    def test_the_stop_button_means_generating(self):
        self.assertEqual(cw.classify({"composer": True, "stop": True}), cw.STATE_GENERATING)
        self.assertEqual(cw.classify({"composer": True, "stop": False}), cw.STATE_COMPLETE)

    def test_classify_is_total_on_junk(self):
        for junk in ({}, None, "text", [], 7):
            self.assertIn(cw.classify(junk),
                          (cw.STATE_LOGGED_OUT, cw.STATE_NO_COMPOSER,
                           cw.STATE_GENERATING, cw.STATE_COMPLETE))

    def test_the_probe_reads_every_fact_in_one_evaluation(self):
        """Reading facts one at a time lets the page change between reads and produces a
        snapshot that never existed -- a stop button from before the last token and text from
        after it, which is exactly the combination that reads as complete."""
        page = StreamingPage([(False, "done")])
        calls = []
        original = page.evaluate
        page.evaluate = lambda e: (calls.append(e), original(e))[1]
        snap = cw.probe(page)
        self.assertEqual(len(calls), 1, "the probe made more than one round trip")
        for key in ("href", "composer", "stop", "login", "count", "text"):
            self.assertIn(key, snap)


class TestCompletionDetection(unittest.TestCase):
    """THE CONTROLS THAT MATTER MOST. Capturing a half-streamed answer puts a truncated
    directive into a ledger later runs read as binding, and does it silently."""

    def test_a_streaming_answer_is_never_captured_early(self):
        page = StreamingPage([
            (True, "Raise"),                 # generating
            (True, "Raise Value"),
            (True, "Raise ValueError."),     # text complete but STILL generating
            (False, "Raise ValueError."),    # stop gone, stability 1
            (False, "Raise ValueError."),    # 2
            (False, "Raise ValueError."),    # 3 -> complete
        ])
        out = instant(page)
        self.assertEqual(out["state"], cw.STATE_COMPLETE)
        self.assertEqual(out["text"], "Raise ValueError.")

    def test_text_briefly_stable_MID_STREAM_does_not_complete(self):
        """A slow chunk makes text identical across polls while the stop button is still
        present. Requiring the affordance to be gone is what catches it."""
        page = StreamingPage([
            (True, "Raise"), (True, "Raise"), (True, "Raise"), (True, "Raise"),
            (True, "Raise ValueError on zero."),
            (False, "Raise ValueError on zero."),
            (False, "Raise ValueError on zero."),
            (False, "Raise ValueError on zero."),
        ])
        out = instant(page)
        self.assertEqual(out["state"], cw.STATE_COMPLETE)
        self.assertEqual(out["text"], "Raise ValueError on zero.",
                         "an early, stable-looking prefix was captured as the answer")

    def test_the_stop_button_flickering_between_tokens_does_not_complete(self):
        """Some builds drop the stop affordance between tokens. Text stability is what covers
        that gap -- neither fact is sufficient alone."""
        page = StreamingPage([
            (False, "Rai"),                  # flicker: no stop, but text keeps changing
            (True, "Raise"),
            (False, "Raise Value"),          # flicker again
            (True, "Raise ValueError."),
            (False, "Raise ValueError."),
            (False, "Raise ValueError."),
            (False, "Raise ValueError."),
        ])
        out = instant(page)
        self.assertEqual(out["state"], cw.STATE_COMPLETE)
        self.assertEqual(out["text"], "Raise ValueError.")

    def test_a_message_that_never_exceeds_the_baseline_never_completes(self):
        """An assistant element appears the instant generation STARTS, so 'a message exists'
        must be measured against what was there before the submit."""
        # The page still shows the SAME five messages: nothing new arrived.
        page = StreamingPage([(False, "old answer")] * 10, baseline=5, count=5)
        out = instant(page, timeout_s=6.0, baseline=5)
        self.assertIn(out["state"], (cw.STATE_TIMEOUT, cw.STATE_NO_ANSWER))
        self.assertEqual(out["text"], "")

    def test_a_timeout_returns_no_text_but_reports_the_partial(self):
        """A partial capture is never returned as a RESULT. It is reported separately so an
        operator can see what was on screen without anything downstream mistaking it."""
        page = StreamingPage([(True, "half an ans")] * 20)
        out = instant(page, timeout_s=5.0)
        self.assertEqual(out["state"], cw.STATE_TIMEOUT)
        self.assertEqual(out["text"], "")
        self.assertEqual(out["partial"], "half an ans")

    def test_logging_out_mid_generation_stops_immediately(self):
        page = StreamingPage([(True, "start")], login=True)
        out = instant(page)
        self.assertEqual(out["state"], cw.STATE_LOGGED_OUT)
        self.assertEqual(out["text"], "")

    def test_the_composer_vanishing_mid_generation_stops_immediately(self):
        page = StreamingPage([(True, "start")], composer=False)
        out = instant(page)
        self.assertEqual(out["state"], cw.STATE_NO_COMPOSER)

    def test_stability_requires_the_configured_number_of_polls(self):
        """A single identical pair proves nothing; the bound is what makes it evidence."""
        script = [(False, "answer")] * 10
        out = instant(StreamingPage(script), stable_polls=5)
        self.assertEqual(out["state"], cw.STATE_COMPLETE)
        self.assertGreaterEqual(out["polls"], 5)

    def test_an_empty_answer_is_never_reported_complete(self):
        page = StreamingPage([(False, "")] * 10)
        out = instant(page, timeout_s=6.0)
        self.assertNotEqual(out["state"], cw.STATE_COMPLETE)


class TestSubmit(unittest.TestCase):
    def test_submit_captures_the_baseline_before_sending(self):
        """'A new message appeared' is only meaningful relative to what was there first."""
        page = StreamingPage([(False, "prior")], baseline=3, count=3)
        ok, reason, baseline = cw.submit(page, "hello")
        self.assertTrue(ok, reason)
        self.assertEqual(baseline, 3, "the pre-submit count was not the one captured")
        self.assertEqual(page.sent, 1)

    def test_submit_refuses_when_logged_out_and_sends_nothing(self):
        page = StreamingPage([(False, "")], login=True)
        ok, reason, _b = cw.submit(page, "hello")
        self.assertFalse(ok)
        self.assertEqual(reason, cw.STATE_LOGGED_OUT)
        self.assertEqual(page.sent, 0, "a packet was typed into a signed-out page")

    def test_submit_refuses_when_the_composer_is_gone(self):
        page = StreamingPage([(False, "")], composer=False)
        ok, reason, _b = cw.submit(page, "hello")
        self.assertFalse(ok)
        self.assertEqual(reason, cw.STATE_NO_COMPOSER)
        self.assertEqual(page.sent, 0)

    def test_the_composer_is_filled_through_the_native_setter(self):
        """A framework-controlled input ignores a plain value assignment: React tracks the
        previous value and swallows the synthetic event, so send stays disabled and the turn
        silently does nothing."""
        page = StreamingPage([(False, "")])
        cw.submit(page, "the packet")
        self.assertIn("getOwnPropertyDescriptor", page.filled)
        self.assertIn('"value"', page.filled)
        self.assertIn("dispatchEvent", page.filled)

    def test_the_prompt_is_json_encoded_into_the_expression(self):
        """A packet contains quotes, newlines and backslashes. Naive interpolation would break
        the expression or, worse, change what it evaluates."""
        page = StreamingPage([(False, "")])
        nasty = 'he said "hi"\nand \\ then; alert(1)'
        cw.fill_composer(page, nasty)
        self.assertIn(json.dumps(nasty), page.filled)


class TestConversationBinding(unittest.TestCase):
    def test_the_conversation_id_is_read_from_the_url(self):
        self.assertEqual(cw.conversation_id("https://chatgpt.com/c/abc-123"), "abc-123")
        self.assertEqual(cw.conversation_id("https://chatgpt.com/c/abc-123?model=x"), "abc-123")
        self.assertEqual(cw.conversation_id("https://chatgpt.com/c/abc-123#frag"), "abc-123")

    def test_a_url_with_no_conversation_is_empty_not_an_error(self):
        """The thread does not exist until the first message; that is a legitimate state."""
        for href in ("https://chatgpt.com/", "", None, "https://chatgpt.com/auth/login"):
            self.assertEqual(cw.conversation_id(href), "")


class TestSelectorHygiene(unittest.TestCase):
    def test_every_selector_lives_in_one_table(self):
        """REWRITTEN: the previous version split on "\n}" against ast.unparse output, which
        emits dict literals on ONE line -- so the split never matched, `rest` was always empty,
        and its enforcing assertion ran against nothing. It could not fail.

        This walks the AST instead: every selector-shaped string constant in the module must be
        inside the SELECTORS assignment, not merely somewhere after it in the text."""
        import ast
        path = os.path.join(os.path.dirname(__file__), "..", "src", "quaestor", "executors",
                            "chatgpt_web_page.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())

        selectors_node = None
        for node in tree.body:
            if (isinstance(node, ast.Assign) and node.targets
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "SELECTORS"):
                selectors_node = node
        self.assertIsNotNone(selectors_node, "SELECTORS is no longer a module-level assignment")

        inside = {id(n) for n in ast.walk(selectors_node)}
        marks = ("data-testid", "data-message-author-role", "#prompt-textarea",
                 "aria-label", "contenteditable", "role='alert'")
        leaked, seen_inside = [], 0
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if not any(m in node.value for m in marks):
                continue
            if id(node) in inside:
                seen_inside += 1
            else:
                leaked.append((getattr(node, "lineno", "?"), node.value[:60]))
        self.assertGreater(seen_inside, 4,
                           "the scanner found almost nothing inside SELECTORS -- it is probably "
                           "broken, and a control that cannot fail proves nothing")
        self.assertEqual(leaked, [],
                         "selector-shaped strings live outside the SELECTORS table: %s" % leaked)

    def test_each_selector_has_more_than_one_candidate_where_it_matters(self):
        """The page ships variants; a single selector is a single point of rot."""
        for name in ("composer", "send", "stop", "login"):
            self.assertGreater(len(cw.SELECTORS[name]), 1, name)

    def test_the_page_module_contains_no_detection_evasion(self):
        code = code_without_prose(os.path.join(
            os.path.dirname(__file__), "..", "src", "quaestor", "executors",
            "chatgpt_web_page.py")).lower()
        for needle in ("stealth", "undetected", "webdriver", "captcha", "spoof",
                       "user_agent", "useragent"):
            self.assertNotIn(needle, code, needle)


class TestTransportContractIsHonoured(unittest.TestCase):
    """The interface DECLARES 'Raises BrowserUnavailable' and callers depend on it:
    chatgpt_web._drive catches exactly that to turn a lost browser into a NAMED run outcome. A
    raw WebSocketClosed -- what an operator closing the tab produces -- sailed past that handler
    and surfaced as an unhandled crash instead of a recorded refusal."""

    class _Dies:
        def send_json(self, _o):
            pass

        def recv_json(self):
            raise wsc.WebSocketClosed("peer sent CLOSE")

        def close(self):
            pass

    def _transport(self):
        return bt.CdpTransport.attach(
            http_json=lambda *_a, **_k: [{"type": "page", "url": "https://chatgpt.com/",
                                          "webSocketDebuggerUrl": "ws://x"}],
            connect=lambda *_a, **_k: self._Dies())

    def test_a_closed_socket_becomes_BrowserUnavailable_on_evaluate(self):
        t = self._transport()
        with self.assertRaises(bt.BrowserUnavailable) as caught:
            t.evaluate("1+1")
        self.assertEqual(caught.exception.reason, bt.BROWSER_NOT_ATTACHED)
        self.assertIn("remote-debugging-port", str(caught.exception))

    def test_a_closed_socket_becomes_BrowserUnavailable_on_goto(self):
        t = self._transport()
        with self.assertRaises(bt.BrowserUnavailable):
            t.goto("https://chatgpt.com/")

    def test_a_protocol_refusal_keeps_its_own_named_reason(self):
        """The wrapper must not relabel a CDP-level refusal as 'not attached' -- they are
        different faults and send an operator to different places."""
        class _Refuses(self._Dies.__class__ if False else object):
            def __init__(self):
                self.sent = []

            def send_json(self, o):
                self.sent.append(o)

            def recv_json(self):
                return {"id": self.sent[-1]["id"],
                        "error": {"code": -32000, "message": "nope"}}

            def close(self):
                pass

        t = bt.CdpTransport.attach(
            http_json=lambda *_a, **_k: [{"type": "page", "url": "u",
                                          "webSocketDebuggerUrl": "ws://x"}],
            connect=lambda *_a, **_k: _Refuses())
        with self.assertRaises(bt.BrowserUnavailable) as caught:
            t.evaluate("boom")
        self.assertEqual(caught.exception.reason, bt.BROWSER_EVAL_FAILED)


class TestHandshakeFailureClosesTheSocket(unittest.TestCase):
    def test_every_handshake_failure_path_closes_the_socket(self):
        """A seat retrying against a stale devtools URL leaked one fd per attempt; on a long
        unattended run that is exhaustion nobody would trace back to a handshake hours earlier."""
        scripts = [b"HTTP/1.1 403 Forbidden\r\n\r\n",
                   b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                   b"Sec-WebSocket-Accept: wrong\r\n\r\n",
                   b"HTTP/1.1 101 Switch"]
        for script in scripts:
            sock = FakeSocket(script)
            with self.assertRaises(wsc.WebSocketError):
                wsc.WebSocket.connect("ws://127.0.0.1:9222/x",
                                      opener=lambda *_a, **_k: sock)
            self.assertTrue(sock.closed,
                            "the socket survived a failed handshake: %r" % script[:24])

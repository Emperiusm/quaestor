"""browser_transport -- how Quaestor reaches a browser, behind one very small interface.

THE INTERFACE IS FOUR METHODS, ON PURPOSE
------------------------------------------
``goto`` / ``evaluate`` / ``url`` / ``close``. Everything a chat UI needs -- typing into a
composer, reading the last message, detecting that generation stopped -- expresses as JavaScript
evaluated in the page, and both available transports support that natively.

That size is the design. The fragile, vendor-specific half of this feature is the selector and
completion-detection logic, and it must exist ONCE. A fatter interface would let that logic seep
into each transport, where the two copies would drift and the one nobody exercised would be the
one that broke.

TWO TRANSPORTS, AND WHY BOTH
-----------------------------
    CDP        the DEFAULT. Stdlib only: urllib to discover the debug target, and this package's
               own RFC 6455 client to drive it. This project has zero third-party dependencies
               and the one facility the stdlib lacked -- the clipboard -- it got by shelling out
               rather than by taking a library. Keeping that property for the browser too means
               the feature installs with nothing.

    PLAYWRIGHT the OPTIONAL upgrade, used when it is importable. Its waiting primitives are
               genuinely better than anything reasonable to hand-roll, which matters because
               completion detection is the highest-risk part of this feature.

Selection is explicit and reported: ``open_transport`` names which one it used and why, because
"it worked on my machine" is usually a transport difference nobody was told about.

WHAT NEITHER TRANSPORT DOES
----------------------------
Neither launches a browser, and neither handles a credential. They ATTACH to a browser the
operator started and is already signed into. There is deliberately no fingerprint spoofing, no
user-agent override, no CAPTCHA handling and no retry-on-block: automating your own authenticated
session is the feature, and defeating a service's controls is a different thing that turns a
flagged account into a banned one. A control greps this module for that machinery.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

BROWSER_TRANSPORT_INSTRUMENT = "browser_transport/1"

#: Where a Chrome started with --remote-debugging-port listens, by default.
DEFAULT_CDP_ENDPOINT = "http://127.0.0.1:9222"

# ---- named refusals ---------------------------------------------------------------------------
BROWSER_NOT_ATTACHED = "BROWSER_NOT_ATTACHED"
BROWSER_NO_PAGE = "BROWSER_NO_PAGE"
BROWSER_EVAL_FAILED = "BROWSER_EVAL_FAILED"
BROWSER_TRANSPORT_UNAVAILABLE = "BROWSER_TRANSPORT_UNAVAILABLE"

#: How an operator starts a browser this module can attach to. Quoted verbatim in refusals so the
#: fix travels with the error rather than living in documentation nobody has open.
ATTACH_HINT = (
    'start Chrome with a debug port and your normal profile, e.g.  '
    'chrome.exe --remote-debugging-port=9222 --user-data-dir="%LOCALAPPDATA%\\Chrome-Quaestor"  '
    '(sign in once in that window; Quaestor never handles the credential)')


class BrowserUnavailable(RuntimeError):
    """No transport could attach. Carries a NAMED reason and the attach hint."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = str(reason)
        self.detail = str(detail)
        super().__init__("%s: %s" % (reason, detail or ATTACH_HINT))


class BrowserTransport:
    """The interface. Four methods; see the module docstring for why it is this small."""

    name = "abstract"

    def goto(self, url: str) -> None:
        raise NotImplementedError

    def evaluate(self, expression: str):
        """Evaluate JS in the page and return its JSON-able value. Raises BrowserUnavailable."""
        raise NotImplementedError

    def url(self) -> str:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


# ---------------------------------------------------------------------------------------------
# CDP: the zero-dependency default
# ---------------------------------------------------------------------------------------------
def _http_json(url: str, timeout: float = 10.0):
    """GET a CDP discovery endpoint. Impure. Raises BrowserUnavailable, never urllib errors."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:   # noqa: S310 - loopback only
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise BrowserUnavailable(
            BROWSER_NOT_ATTACHED,
            "no debuggable browser at %s (%s: %s). %s"
            % (url, type(exc).__name__, exc, ATTACH_HINT)) from exc


class CdpTransport(BrowserTransport):
    """Chrome DevTools Protocol over this package's own WebSocket client. Stdlib only."""

    name = "cdp"

    def __init__(self, ws, *, endpoint: str = DEFAULT_CDP_ENDPOINT, timeout: float = 30.0):
        self._ws = ws
        self._endpoint = endpoint
        self._timeout = float(timeout)
        self._next_id = 0

    # -- attach ---------------------------------------------------------------------------------
    @classmethod
    def attach(cls, *, endpoint: str = DEFAULT_CDP_ENDPOINT, match: str = "",
               timeout: float = 30.0, http_json=None, connect=None) -> "CdpTransport":
        """Attach to an existing page target. Impure. ``http_json``/``connect`` are the seams
        controls substitute, so no test opens a socket.

        Prefers a page whose URL contains ``match`` -- the operator may have many tabs open, and
        grabbing an arbitrary one would type a strategist packet into whatever they were reading.
        """
        get = http_json or _http_json
        targets = get(endpoint.rstrip("/") + "/json", timeout)
        if not isinstance(targets, list):
            raise BrowserUnavailable(BROWSER_NO_PAGE,
                                     "the debug endpoint returned no target list")
        pages = [t for t in targets
                 if isinstance(t, dict) and t.get("type") == "page"
                 and t.get("webSocketDebuggerUrl")]
        if not pages:
            raise BrowserUnavailable(
                BROWSER_NO_PAGE,
                "the browser is attached but has no debuggable page tab open. %s" % ATTACH_HINT)
        chosen = next((p for p in pages if match and match in str(p.get("url") or "")), pages[0])
        from quaestor.executors import websocket_client as wsc
        opener = connect or wsc.WebSocket.connect
        try:
            ws = opener(str(chosen["webSocketDebuggerUrl"]), timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - any failure here is "cannot attach"
            raise BrowserUnavailable(
                BROWSER_NOT_ATTACHED,
                "could not open the devtools socket (%s: %s)" % (type(exc).__name__, exc)
            ) from exc
        return cls(ws, endpoint=endpoint, timeout=timeout)

    # -- protocol -------------------------------------------------------------------------------
    def _command(self, method: str, params=None):
        """One CDP command/response pair. EVENTS ARE SKIPPED: the protocol interleaves
        unsolicited events with responses, and matching on id is the only way to read the answer
        to the question actually asked."""
        self._next_id += 1
        want = self._next_id
        # EVERY WEBSOCKET-LEVEL FAILURE BECOMES BrowserUnavailable. The interface declares that
        # contract and callers depend on it: chatgpt_web._drive catches BrowserUnavailable to
        # turn a lost browser into a NAMED run outcome. A raw WebSocketClosed -- which is
        # exactly what an operator closing the tab produces -- sailed past that handler, escaped
        # execute(), and surfaced as an unhandled crash in the worker instead of a recorded
        # refusal an operator could act on.
        try:
            return self._exchange(want, method, params)
        except BrowserUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailable(
                BROWSER_NOT_ATTACHED,
                "the devtools connection failed during %s (%s: %s). %s"
                % (method, type(exc).__name__, exc, ATTACH_HINT)) from exc

    def _exchange(self, want: int, method: str, params):
        """One command/reply pair on the wire. Raises whatever the socket raises; the caller
        translates. Split out so the translation above cannot accidentally swallow a
        BrowserUnavailable this method itself raised for a protocol-level refusal."""
        self._ws.send_json({"id": want, "method": method, "params": dict(params or {})})
        for _ in range(200):          # bounded: a reply that never arrives must not hang a seat
            message = self._ws.recv_json()
            if not isinstance(message, dict):
                continue
            if message.get("id") != want:
                continue              # an event, or a stale reply
            if "error" in message:
                err = message["error"]
                raise BrowserUnavailable(
                    BROWSER_EVAL_FAILED,
                    "%s refused: %s" % (method, json.dumps(err)[:300]))
            return message.get("result") or {}
        raise BrowserUnavailable(BROWSER_EVAL_FAILED,
                                 "no reply to %s within the message bound" % method)

    def goto(self, url: str) -> None:
        self._command("Page.navigate", {"url": str(url)})

    def evaluate(self, expression: str):
        result = self._command("Runtime.evaluate", {
            "expression": str(expression), "returnByValue": True, "awaitPromise": True})
        if result.get("exceptionDetails"):
            raise BrowserUnavailable(
                BROWSER_EVAL_FAILED,
                "page evaluation threw: %s"
                % json.dumps(result["exceptionDetails"])[:300])
        return (result.get("result") or {}).get("value")

    def url(self) -> str:
        return str(self.evaluate("location.href") or "")

    def close(self) -> None:
        try:
            self._ws.close()
        except Exception:  # noqa: BLE001 - cleanup that throws loses the original error
            pass


# ---------------------------------------------------------------------------------------------
# Playwright: the optional upgrade
# ---------------------------------------------------------------------------------------------
class PlaywrightTransport(BrowserTransport):
    """Playwright attached to a RUNNING browser over CDP. Never launches one, never downloads
    a browser: ``connect_over_cdp`` uses the Chrome the operator already signed into."""

    name = "playwright"

    def __init__(self, page, *, pw=None, browser=None):
        self._page = page
        self._pw = pw
        self._browser = browser

    @classmethod
    def available(cls) -> bool:
        try:
            import playwright.sync_api  # noqa: F401
        except Exception:  # noqa: BLE001 - absent, broken, or wrong Python: all "unavailable"
            return False
        return True

    @classmethod
    def attach(cls, *, endpoint: str = DEFAULT_CDP_ENDPOINT, match: str = "",
               timeout: float = 30.0) -> "PlaywrightTransport":
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailable(
                BROWSER_TRANSPORT_UNAVAILABLE,
                "playwright is not importable (%s); the CDP transport needs no install"
                % exc) from exc
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.connect_over_cdp(endpoint, timeout=timeout * 1000)
        except Exception as exc:  # noqa: BLE001
            pw.stop()
            raise BrowserUnavailable(
                BROWSER_NOT_ATTACHED,
                "playwright could not attach at %s (%s). %s"
                % (endpoint, exc, ATTACH_HINT)) from exc
        pages = [p for ctx in browser.contexts for p in ctx.pages]
        if not pages:
            browser.close()
            pw.stop()
            raise BrowserUnavailable(BROWSER_NO_PAGE, "the browser has no page open")
        page = next((p for p in pages if match and match in str(p.url)), pages[0])
        return cls(page, pw=pw, browser=browser)

    def goto(self, url: str) -> None:
        self._page.goto(str(url))

    def evaluate(self, expression: str):
        try:
            return self._page.evaluate(str(expression))
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailable(BROWSER_EVAL_FAILED,
                                     "page evaluation threw: %s" % exc) from exc

    def url(self) -> str:
        return str(self._page.url)

    def close(self) -> None:
        # The BROWSER is not closed: it is the operator's, it was already open, and closing it
        # would shut a window they were using.
        for shut in (self._browser, self._pw):
            try:
                (shut.close if hasattr(shut, "close") else shut.stop)()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------------------------
PREFER_PLAYWRIGHT = "playwright"
PREFER_CDP = "cdp"
PREFER_AUTO = "auto"


def open_transport(*, endpoint: str = DEFAULT_CDP_ENDPOINT, match: str = "",
                   prefer: str = PREFER_AUTO, timeout: float = 30.0,
                   cdp_attach=None, playwright_attach=None) -> tuple:
    """(transport, why) -- attach with the best available transport. Impure.

    Returns the REASON alongside, and the caller records it: "it worked on my machine" is
    usually a transport difference nobody was told about, and a seat that silently changed how
    it reached the browser is a seat whose failures cannot be compared across runs.
    """
    prefer = str(prefer or PREFER_AUTO)
    if prefer not in (PREFER_AUTO, PREFER_CDP, PREFER_PLAYWRIGHT):
        raise ValueError("unknown transport preference %r; known are %s"
                         % (prefer, [PREFER_AUTO, PREFER_CDP, PREFER_PLAYWRIGHT]))
    pw_attach = playwright_attach or PlaywrightTransport.attach
    cdp = cdp_attach or CdpTransport.attach

    if prefer == PREFER_CDP:
        return cdp(endpoint=endpoint, match=match, timeout=timeout), \
            "cdp: explicitly preferred (stdlib only)"
    if prefer == PREFER_PLAYWRIGHT:
        return pw_attach(endpoint=endpoint, match=match, timeout=timeout), \
            "playwright: explicitly preferred"
    if PlaywrightTransport.available():
        try:
            return pw_attach(endpoint=endpoint, match=match, timeout=timeout), \
                "playwright: importable, and its waiting primitives beat hand-rolled polling"
        except BrowserUnavailable:
            # FALL THROUGH, not fail. Playwright being importable says nothing about whether it
            # can attach; the stdlib path may still work and is what this project ships with.
            pass
    return cdp(endpoint=endpoint, match=match, timeout=timeout), \
        "cdp: stdlib transport (playwright not importable or could not attach)"

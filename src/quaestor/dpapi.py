"""dpapi -- Windows DPAPI (CryptProtectData/CryptUnprotectData), via ctypes. No dependencies.

WHY DPAPI AND NOT A PASSPHRASE
------------------------------
The owner should not have to remember or re-enter a second secret to unlock the first one. DPAPI
CurrentUser keys the ciphertext to the logged-on Windows account: another local account, and a
copy of the blob carried to another machine, cannot decrypt it. That is the cryptographic
boundary this broker relies on -- file ACLs are defence in depth on top, never the mechanism.

ADDITIONAL ENTROPY IS APPLICATION-SCOPED, NOT SECRET
----------------------------------------------------
``ENTROPY`` is a fixed, public, application-specific byte string. It is not a key and adds no
secrecy; what it adds is that a naive ``CryptUnprotectData(blob)`` by some other tool running as
the same user fails. Binding the ciphertext to this application is cheap, so it is done -- but it
is documented as scoping, not as strength, because a reader who mistook it for a key would draw
the wrong conclusion about what protects the token.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
It never accepts or returns ``str``. Plaintext crosses this boundary as ``bytearray`` so the
caller can overwrite it; Python cannot guarantee erasure of an immutable ``str``, and pretending
otherwise would be the kind of confident-but-false claim this project keeps refusing to make.
See ``secret_store.wipe`` for the honest statement of that limit.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

from quaestor import branding, compat

#: Public, application-scoped. NOT a key -- see the module docstring.
#: Application-scoped, and therefore INSTALLATION-scoped: a blob sealed under one value
#: cannot be opened under another. Changing it invalidates every credential this
#: installation has already stored, so treat it as frozen once anything is provisioned.
ENTROPY = compat.CREDENTIAL_ENTROPY

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class DpapiError(RuntimeError):
    """DPAPI refused. Carries the Windows error code, never any plaintext."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def available() -> bool:
    """Is DPAPI usable on this platform? Impure. NEVER raises."""
    if os.name != "nt":
        return False
    try:
        blob = protect(bytearray(b"probe"))
        out = unprotect(blob)
        ok = bytes(out) == b"probe"
        wipe(out)
        return ok
    except Exception:  # noqa: BLE001
        return False


def _blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _take(blob: _DATA_BLOB) -> bytearray:
    """Copy a DATA_BLOB into a bytearray and free the LocalAlloc'd buffer."""
    try:
        out = bytearray(blob.cbData)
        ctypes.memmove((ctypes.c_char * blob.cbData).from_buffer(out), blob.pbData, blob.cbData)
        return out
    finally:
        if blob.pbData:
            ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect(plaintext: bytearray, *, entropy: bytes = ENTROPY,
            description: str = branding.PRODUCT_TITLE + " credential") -> bytes:
    """Encrypt to the CURRENT USER. Impure. Raises DpapiError.

    ``CRYPTPROTECT_UI_FORBIDDEN`` because this must never pop a dialog: an unattended dispatch
    that silently waits on a UI prompt is a hang with no diagnosis.
    """
    if os.name != "nt":
        raise DpapiError("DPAPI is only available on Windows (os.name=%r)" % os.name)
    crypt32 = ctypes.windll.crypt32
    din = _blob(bytes(plaintext))
    dent = _blob(entropy)
    dout = _DATA_BLOB()
    ok = crypt32.CryptProtectData(ctypes.byref(din), wintypes.LPCWSTR(description),
                                  ctypes.byref(dent), None, None,
                                  CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(dout))
    if not ok:
        raise DpapiError("CryptProtectData failed (winerror %d)" % ctypes.GetLastError())
    return bytes(_take(dout))


def unprotect(ciphertext: bytes, *, entropy: bytes = ENTROPY) -> bytearray:
    """Decrypt. Impure. Raises DpapiError. Returns a MUTABLE bytearray so it can be wiped.

    A failure here is a REFUSAL, not a fallback: a blob that will not decrypt under this user is
    either corrupt or belongs to somebody else, and both mean the credential is unusable.
    """
    if os.name != "nt":
        raise DpapiError("DPAPI is only available on Windows (os.name=%r)" % os.name)
    crypt32 = ctypes.windll.crypt32
    din = _blob(bytes(ciphertext))
    dent = _blob(entropy)
    dout = _DATA_BLOB()
    ok = crypt32.CryptUnprotectData(ctypes.byref(din), None, ctypes.byref(dent), None, None,
                                    CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(dout))
    if not ok:
        raise DpapiError("CryptUnprotectData failed (winerror %d) -- the blob is corrupt, was "
                         "protected with different entropy, or belongs to another user"
                         % ctypes.GetLastError())
    return _take(dout)


def wipe(buf) -> None:
    """Overwrite a mutable buffer in place. Impure. NEVER raises.

    HONEST LIMIT: this zeroes the bytes of a ``bytearray`` we control. It cannot erase copies the
    interpreter may have made -- an immutable ``str``, an interned literal, a buffer freed by the
    allocator, or anything paged to disk. So the broker keeps plaintext in ``bytearray`` from
    decrypt to injection and wipes it immediately, and this docstring is the honest statement of
    what that does and does not achieve.
    """
    try:
        for i in range(len(buf)):
            buf[i] = 0
    except (TypeError, IndexError):
        pass

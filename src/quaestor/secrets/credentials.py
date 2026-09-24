"""credentials -- how a child obtains authentication, as an explicit provider abstraction.

TWO PROVIDER CLASSES, AND THEY ARE NOT INTERCHANGEABLE
-------------------------------------------------------
    READ_ONLY_CREDENTIAL_SEED          proven in P3. A read-only volume holding exactly one
                                       credential artifact, copied into an ephemeral tmpfs home
                                       by the image's bootstrap. Sufficient for QUALIFICATION.
    EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN  an owner-provisioned automation credential supplied from
                                       an external secret source and injected into the ephemeral
                                       child as CLAUDE_CODE_OAUTH_TOKEN. NOT implemented as a
                                       generator: nothing here mints a token, and there is no
                                       `setup-token` call anywhere in this project.

WHY THE SEED IS NOT A PRODUCTION ANSWER
---------------------------------------
P3 measured Claude refreshing its credential and writing the new material back. Against a
read-only seed that write-back fails. Short runs are unaffected; an unattended transport that
runs for weeks is not. So the seed is explicitly marked as qualification-grade, and
``unattended_production_ready`` is False for it -- a fact recorded in the run rather than
discovered later.

THE ONE ENVIRONMENT VARIABLE THAT MAY EVER BE INJECTED
-------------------------------------------------------
``preflight`` refuses ANY credential/provider override found in the environment, because such a
variable silently decides the billing path. The external-OAuth provider needs exactly one
exception, and it is granted by NAME, not by trust in the caller:

    EXEMPTIBLE = {"CLAUDE_CODE_OAUTH_TOKEN"}

``ANTHROPIC_API_KEY`` can never be exempted by any provider, so "inject a credential" can never
become "switch to API billing". That distinction is the whole point of §12's requirement that an
OAuth token be admitted *without* being treated as an API key.

NOTHING HERE EVER RETURNS OR RECORDS A SECRET VALUE. Providers describe themselves; the value
reaches the container through Docker's env and is never written to SQLite, run JSON, logs, the
image, or Git. ``redact_env`` is the only shape that leaves this module.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Sequence

from quaestor import branding
from quaestor.executors import claude_auth

PROVIDER_INSTRUMENT = "credentials/1"

READ_ONLY_CREDENTIAL_SEED = "READ_ONLY_CREDENTIAL_SEED"
EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN = "EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN"
NONE_AVAILABLE = "NONE_AVAILABLE"

#: The ONLY environment variable this broker may ever inject past the preflight's
#: override rule. Deliberately a frozenset of one, and it is not merely CONVENTION that
#: ANTHROPIC_API_KEY is absent: `credential_policy.forbids_exemption` refuses any
#: API-key-shaped name structurally, so the provider policy this is read from could not
#: have been CONSTRUCTED with one. Injecting a credential can therefore never become
#: switching to API billing.
EXEMPTIBLE_ENV = claude_auth.CLAUDE_POLICY.exemptible_env

#: Environment variable names whose VALUES must never appear in any artifact.
SECRET_ENV_NAMES = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                    "AWS_BEARER_TOKEN_BEDROCK", "GITHUB_TOKEN", "GH_TOKEN")

REDACTED = "<REDACTED>"


@dataclass(frozen=True)
class CredentialProvider:
    """A description of HOW a child authenticates. Never carries the secret itself."""

    kind: str
    persistence: str                      # "read-only volume" | "ephemeral env injection" | "none"
    artifact: str = ""                    # the artifact NAME, never its content
    volume: str = ""
    mount_path: str = ""
    env_var: str = ""
    unattended_production_ready: bool = False
    available: bool = False
    note: str = ""
    instrument: str = PROVIDER_INSTRUMENT

    def to_dict(self) -> dict:
        """Persistable description. Contains no secret by construction -- there is no field for
        one, which is a stronger guarantee than remembering to strip it."""
        return {"kind": self.kind, "persistence": self.persistence, "artifact": self.artifact,
                "volume": self.volume, "mount_path": self.mount_path, "env_var": self.env_var,
                "unattended_production_ready": self.unattended_production_ready,
                "available": self.available, "note": self.note, "instrument": self.instrument}


def seed_provider(volume: str, mount_path: str = "/run/%s-auth-seed" % branding.PRODUCT_NAME, *,
                  available: bool = True) -> CredentialProvider:
    return CredentialProvider(
        kind=READ_ONLY_CREDENTIAL_SEED, persistence="read-only volume",
        artifact=".credentials.json", volume=volume, mount_path=mount_path,
        unattended_production_ready=False, available=available,
        note=("qualification-grade. Claude refreshes credentials and writes back; a read-only "
              "seed forbids that, so long-running unattended use needs a broker, not this."))


def external_oauth_provider(*, available: bool) -> CredentialProvider:
    return CredentialProvider(
        kind=EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN, persistence="ephemeral env injection",
        artifact="", env_var="CLAUDE_CODE_OAUTH_TOKEN",
        unattended_production_ready=True, available=available,
        note=("owner-provisioned automation credential from an external secret source. This "
              "project never mints one: there is no setup-token invocation anywhere, and none "
              "may be added without owner instruction."))


def broker_provider(*, available: bool, credential_id: str = "") -> CredentialProvider:
    """The P4.5 owner broker: DPAPI-protected, injected transiently, no persistent Claude home."""
    return CredentialProvider(
        kind=EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN, persistence="DPAPI blob, transient injection",
        artifact="claude-oauth.dpapi", env_var="CLAUDE_CODE_OAUTH_TOKEN",
        unattended_production_ready=True, available=available,
        note=("owner-provisioned via the local credential broker; decrypted only immediately "
              "before dispatch and injected through the docker process environment, never argv. "
              "credential_id=%s" % (credential_id or "-")))


def detect(env: Mapping[str, str] | None = None, *, seed_volume: str = "",
           seed_present: bool = False, broker_available: bool = False,
           broker_credential_id: str = "") -> dict:
    """Which providers exist right now? Impure only in reading env NAMES. NEVER returns a value.

    Presence of the OAuth variable is reported as a boolean. Its content is never read, never
    logged, and never returned.
    """
    env = os.environ if env is None else env
    oauth_present = bool(str(env.get("CLAUDE_CODE_OAUTH_TOKEN") or "").strip())
    external_available = bool(broker_available or oauth_present)
    providers = {
        READ_ONLY_CREDENTIAL_SEED: seed_provider(seed_volume, available=bool(seed_present)),
        EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN: (
            broker_provider(available=True, credential_id=broker_credential_id)
            if broker_available else external_oauth_provider(available=oauth_present)),
    }
    # THE BROKER OUTRANKS THE SEED once it holds a credential. The seed is retained only for
    # historical P0-P4 regression fixtures; it is not the production source, and leaving it as a
    # silent fallback is how a qualified mechanism gets bypassed by an unqualified one.
    chosen = (EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN if external_available
              else (READ_ONLY_CREDENTIAL_SEED if seed_present else NONE_AVAILABLE))
    return {"providers": {k: v.to_dict() for k, v in providers.items()},
            "selected": chosen,
            "selected_provider": (providers[chosen].to_dict() if chosen in providers else None),
            "unattended_production_ready": bool(
                chosen in providers and providers[chosen].unattended_production_ready)}


def admit_for_mode(detection: Mapping, *, unattended: bool) -> tuple:
    """(ok, reason). PURE.

    Attended qualification runs may use the seed. UNATTENDED production may not: the provider
    must be one whose refresh lifecycle is solved, and none is provisioned, so the answer is
    OWNER_REQUIRED rather than a quiet downgrade to the seed.
    """
    chosen = str(detection.get("selected") or NONE_AVAILABLE)
    if chosen == NONE_AVAILABLE:
        return False, ("no credential provider is available; a child cannot authenticate and the "
                       "run is refused rather than started unauthenticated")
    if unattended and not detection.get("unattended_production_ready"):
        return False, ("provider %s is qualification-grade only: its credential refresh cannot be "
                       "persisted, so unattended production requires an owner-provisioned "
                       "external token. OWNER_REQUIRED." % chosen)
    return True, ""


def env_for(provider: CredentialProvider, secret_value: str | None) -> dict:
    """The env a container receives for this provider. Impure only in the caller's hands.

    The secret is passed through and never retained: this function returns the mapping and keeps
    no copy, and every persisted record of a run uses ``redact_env`` instead.
    """
    if provider.kind == EXTERNAL_SUBSCRIPTION_OAUTH_TOKEN and secret_value:
        return {provider.env_var: secret_value}
    return {}


def redact_env(env: Mapping[str, str], extra_secret_names: Sequence[str] = ()) -> dict:
    """Evidence-safe view of an environment. PURE.

    Secret-named variables are reported as PRESENT with a LENGTH and the literal ``<REDACTED>``;
    the value never appears. the rule, applied here: presence and shape are evidence, the
    value is not.
    """
    names = set(SECRET_ENV_NAMES) | {str(n) for n in (extra_secret_names or ())}
    out = {}
    for k, v in sorted((env or {}).items()):
        if k in names:
            out[k] = {"present": v is not None, "length": len(str(v or "")), "value": REDACTED}
        else:
            out[k] = v
    return out


#: A needle shorter than this cannot be scanned for: short strings collide with ordinary text and
#: a "no match" would be meaningless. Below it the scan is VACUOUS, never clean.
MIN_NEEDLE = 8


def scan_value(blob: str, value) -> dict:
    """Does ``blob`` contain this exact secret VALUE? Impure only in reading bytes. PURE.

    EMITS ITS COMPARISON COUNT, and reports ``vacuous`` when it could not perform one. A scan
    that silently skips its only needle and returns "no leaks" is the exact instrument defect this
    project keeps finding -- it happened HERE, in the live P4.5 validation run, which passed an
    empty value and reported a clean result beside a 975-byte ``scanned_bytes`` figure.

    Takes ``bytes``/``bytearray`` as well as ``str`` so the caller can scan while the plaintext is
    still in a wipeable buffer, instead of making a ``str`` copy just to check for leaks.
    """
    text = blob or ""
    if isinstance(value, (bytes, bytearray)):
        needle = bytes(value).decode("utf-8", "replace")
    else:
        needle = str(value or "")
    # NOTE THE ABSENT FIELD: the needle's LENGTH is not reported. Elsewhere this project records
    # presence-and-length as evidence, but the owner's P4.5 instruction forbids partial reveal of
    # the credential and a length is a property of it. `compared`/`vacuous` carry the whole
    # diagnostic signal without it, so nothing is lost by leaving it out.
    if len(needle) < MIN_NEEDLE:
        return {"found": False, "compared": 0, "vacuous": True, "scannable": False,
                "scanned_bytes": len(text),
                "reason": "needle shorter than %d characters; no comparison was made"
                          % MIN_NEEDLE}
    return {"found": needle in text, "compared": 1, "vacuous": False, "scannable": True,
            "scanned_bytes": len(text), "reason": ""}


def scan_for_secrets(blob: str, env: Mapping[str, str] | None = None) -> list:
    """Names of secret variables whose VALUES appear in ``blob``. PURE.

    Used by controls to prove no artifact contains credential material. It compares against the
    live values so it catches a leak even when the leaking code never names the variable.
    """
    env = os.environ if env is None else env
    hits = []
    for name in SECRET_ENV_NAMES:
        val = str((env or {}).get(name) or "")
        if len(val) >= 8 and val in (blob or ""):
            hits.append(name)
    return hits

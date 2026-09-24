"""credential_validate -- prove a brokered credential authenticates, without ever seeing it.

THE VALIDATION CHILD DOES NO REPOSITORY WORK. It mounts no workspace, gets no Git metadata, and
runs exactly one command: ``claude auth status``. Its only job is to answer "does this token
produce subscription-backed authentication inside the confined image".

WHERE THE SECRET GOES, AND WHERE IT DOES NOT
--------------------------------------------
    DPAPI blob -> bytearray -> subprocess env -> `docker create --env NAME` -> container
                     |
                     +-- wiped immediately after the container is created

It never enters argv, never enters the run record, never enters the returned dict. The container
gets an EPHEMERAL tmpfs home and NO auth-seed volume, so nothing about this run leaves persistent
Claude state behind -- which is also the point: it proves the broker alone is sufficient.
"""
from __future__ import annotations

import json
import uuid
from typing import Mapping

from quaestor import branding
from quaestor.sandbox import profile as cp
from quaestor.secrets import credentials
from quaestor.sandbox import docker as da
from quaestor.executors import claude_auth as pf
from quaestor.secrets import store as secret_store

VALIDATE_INSTRUMENT = "credential_validate/1"

PASS = "PASS"
REFUSED = "AUTH_PREFLIGHT_REFUSED"
OWNER_REQUIRED = "OWNER_REQUIRED"
UNAVAILABLE = "VALIDATION_UNAVAILABLE"

#: Environment overrides that must NOT be present on the host when brokering an OAuth token.
#: ANTHROPIC_API_KEY is the important one: it takes precedence in non-interactive mode, so a run
#: that "used the broker" could silently have billed the API instead.
CONFLICTING = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
               "ANTHROPIC_API_URL", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
               "CLAUDE_CODE_USE_FOUNDRY", "AWS_BEARER_TOKEN_BEDROCK")

AUTH_PROBE = (
    "import json,subprocess,sys\n"
    "p=subprocess.run(['claude','auth','status'],capture_output=True,timeout=120)\n"
    "raw=p.stdout.decode('utf-8','replace')\n"
    "try: status=json.loads(raw)\n"
    "except Exception: status=None\n"
    "v=subprocess.run(['claude','--version'],capture_output=True,timeout=120)\n"
    "import os\n"
    "names=%r\n"
    # KEY NAMES, never values. When classify_auth refuses because it does not recognise a field,
    # the operator's next question is "which fields were there?" -- and an allowlisted record
    # cannot answer it. Names are shape, not identity, so they are safe to carry into evidence.
    "keys=sorted(status.keys()) if isinstance(status,dict) else []\n"
    "sys.stdout.write(json.dumps({'auth_status':status,'rc':p.returncode,"
    "'auth_status_keys':keys,"
    "'claude_version':v.stdout.decode('utf-8','replace').strip(),"
    # PRESENCE ONLY. An earlier version also reported the token's LENGTH; a length is a property
    # of the credential, and the owner's instruction forbids partial reveal. Presence answers the
    # only question this probe needs to answer -- did the injection arrive.
    "'token_env_present':bool(os.environ.get('CLAUDE_CODE_OAUTH_TOKEN')),"
    "'conflicts_present':{n:(os.environ.get(n) is not None) for n in names}}))\n"
) % (list(CONFLICTING),)


def validation_profile(image_digest: str, *, image_ref: str, network: str) -> cp.ContainerProfile:
    """No workspace, no Git metadata, no auth seed. Ephemeral home only."""
    return cp.ContainerProfile(
        profile_id="credential-validation", image_ref=image_ref, image_digest=image_digest,
        user="1001:1001", workdir="/home/claude",
        mounts=(cp.Mount("", "/home/claude", cp.RW, cp.TMPFS,
                         options="rw,nosuid,size=256m,uid=1001,gid=1001,mode=0700"),
                cp.Mount("", "/tmp", cp.RW, cp.TMPFS,
                         options="rw,nosuid,size=64m,uid=1001,gid=1001")),
        network=network, cap_drop=("ALL",), cap_add=(), privileged=False,
        pid_mode="", ipc_mode="", read_only_rootfs=True,
        security_opt=("no-new-privileges",), memory="1g", cpus="1", pids_limit=256,
        timeout_s=300.0, claude_authority_profile="READ_ONLY")


def validate(*, image_ref: str, network: str = "bridge", directory: str | None = None,
             host_env: Mapping[str, str] | None = None,
             proxy_env: Mapping[str, str] | None = None) -> dict:
    """Run the confined validation child. Impure. NEVER raises. NEVER returns the secret."""
    import os as _os
    host_env = _os.environ if host_env is None else host_env

    conflicts = sorted(n for n in CONFLICTING if host_env.get(n) is not None)
    if conflicts:
        return {"verdict": REFUSED, "reason": "CONFLICTING_CREDENTIAL_ENV",
                "conflicting_vars": conflicts,
                "detail": ("refusing to validate a brokered OAuth token while an API/provider "
                           "override is present: it would take precedence and the run would not "
                           "be testing the broker at all"),
                "instrument": VALIDATE_INSTRUMENT}

    st = secret_store.status(directory, deep=True)
    if not st.usable:
        return {"verdict": OWNER_REQUIRED if st.state == secret_store.ABSENT else REFUSED,
                "reason": st.state, "detail": st.reason, "credential": st.to_dict(),
                "instrument": VALIDATE_INSTRUMENT}

    digest, ddet = da.image_digest(image_ref)
    if not digest:
        return {"verdict": UNAVAILABLE, "reason": "IMAGE_ABSENT", "detail": ddet,
                "instrument": VALIDATE_INSTRUMENT}

    secret, st2 = secret_store.load_transient(directory)
    if secret is None:
        return {"verdict": REFUSED, "reason": st2.state, "detail": st2.reason,
                "credential": st2.to_dict(), "instrument": VALIDATE_INSTRUMENT}

    profile = validation_profile(digest, image_ref=image_ref, network=network)
    name = branding.resource("credential-validate", uuid.uuid4().hex[:8])
    try:
        env = dict(proxy_env or {})
        process_env = secret_store.env_for_child(secret)
        outcome = da.run_confined(
            profile, ["python3", "-c", AUTH_PROBE], name=name, env=env,
            env_passthrough=[secret_store.ENV_VAR], process_env=process_env, remove=True)
        # THE LEAKAGE SCAN RUNS HERE, WHILE THE REAL VALUE IS STILL IN THE BUFFER -- and it uses
        # the real value, not a placeholder. The previous version scanned against "" and reported
        # a clean result having made ZERO comparisons, beside a `scanned_bytes` figure that made
        # it look thorough. `scan_value` emits its comparison count so that can never recur.
        argv_rendered = profile.docker_create_args(name, ["python3", "-c", AUTH_PROBE], env,
                                                   [secret_store.ENV_VAR])
        retained_blob = json.dumps({"argv": argv_rendered, "stdout": outcome.stdout,
                                    "stderr": outcome.stderr, "summary": outcome.summary()})
        leak = credentials.scan_value(retained_blob, secret)
        argv_leak = credentials.scan_value(json.dumps(argv_rendered), secret)
        # MEASURED, NOT CLAIMED: `docker inspect` reports Config.Env WITH VALUES, so anyone who
        # can query the daemon can read an injected variable. That is inherent to --env and is
        # NOT something this project can close; what it can do is measure it and say so, rather
        # than let "no leaks found" imply a containment that does not exist. Nothing here
        # persists the inspect blobs -- `summary()` carries verdicts and ids, never Config.
        daemon_leak = credentials.scan_value(
            json.dumps({"before": outcome.inspect_before, "after": outcome.inspect_after},
                       default=str), secret)
    finally:
        # Wipe the moment the container exists. `process_env` still holds a str copy Python
        # cannot erase -- stated plainly rather than papered over; it is function-local and dies
        # with the frame.
        secret_store.wipe_secret(secret)

    if not outcome.started:
        return {"verdict": UNAVAILABLE, "reason": "CONTAINER_DID_NOT_START",
                "detail": outcome.error, "container": outcome.summary(),
                "instrument": VALIDATE_INSTRUMENT}

    probe = {}
    text = (outcome.stdout or "").strip()
    i = text.find("{")
    if i >= 0:
        try:
            probe = json.loads(text[i:])
        except ValueError:
            probe = {}

    auth = probe.get("auth_status")
    auth_class, detail = pf.classify_auth(auth)
    decision = pf.decide(env={}, auth_status=auth,
                         provider_injected=[secret_store.ENV_VAR])

    # A VACUOUS SCAN IS NOT A CLEAN ONE. If the comparison could not be made, this refuses --
    # authentication succeeding is not permission to skip the containment question.
    leak_ok = (leak["compared"] > 0 and not leak["found"]
               and argv_leak["compared"] > 0 and not argv_leak["found"])
    ok = (auth_class == pf.SUBSCRIPTION) and decision.accepted and leak_ok

    if ok:
        secret_store.mark_validated(directory)

    return {
        "verdict": PASS if ok else REFUSED,
        "reason": ("" if ok else
                   ("CREDENTIAL_LEAKED_INTO_RETAINED_ARTIFACT" if not leak_ok
                    else (decision.reason or auth_class))),
        "auth_class": auth_class,
        "auth_detail": detail,
        "auth_record": pf.redact_auth(auth),
        "auth_status_keys": probe.get("auth_status_keys"),
        "claude_version": probe.get("claude_version"),
        "token_env_present_in_child": probe.get("token_env_present"),
        "conflicts_in_child": probe.get("conflicts_present"),
        "container": outcome.summary(),
        "credential": secret_store.status(directory).to_dict(),
        "leakage_scan": {"retained_artifacts": leak, "argv": argv_leak,
                         "scanned_against": "the real credential value, in-process, before wipe"},
        "daemon_env_exposure": {
            "value_readable_via_docker_inspect": daemon_leak["found"],
            "compared": daemon_leak["compared"],
            "note": ("inherent to `docker --env`: the daemon records Config.Env with values, so "
                     "any local caller who can query it can read an injected variable. This "
                     "project persists no inspect blob; the exposure is stated, not claimed "
                     "closed. Closing it needs a secrets mount, which is out of P4.5 scope.")},
        "ephemeral_home": True,
        "auth_seed_mounted": False,
        "instrument": VALIDATE_INSTRUMENT,
        "note": ("the child received the token ONLY through the docker process environment via "
                 "name-only --env passthrough; it never appeared in any command line"),
    }

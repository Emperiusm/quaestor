"""controls -- the REQUIRED mutation controls, and the registry that counts which ones ran.

WHY A REGISTRY AT ALL
---------------------
Instrument doctrine clause 1: *a gate emits a count of what it inspected, and a run that
inspected nothing is VACUOUS, never PASS.* A test suite is a gate. A suite that silently stopped
executing half its controls -- because a module failed to import, because a name was renamed,
because someone ran it with a filter -- reports green over an unexamined tree, which is precisely
the ``unresolved 0 over zero files`` defect wearing a unittest costume.

So this file holds the CONTRACT (which controls must exist), the decorator records EXECUTION, and
``run_tests.py`` asserts both coverage numbers after the suite finishes:

    declared controls  == REQUIRED_CONTROLS      (static: they exist)
    executed controls  == REQUIRED_CONTROLS      (dynamic: they actually ran)

Either number short is a failure, and the failure names the missing ids.
"""
from __future__ import annotations

import functools

#: id -> what the control must prove. Numbering follows the specification's TASK 13 list, so a
#: reader can check the suite against the contract line by line.
REQUIRED_CONTROLS = {
    1: "identical dispatch submitted twice spawns exactly one execution",
    2: "the same worktree requested by two mutable runs rejects the second",
    3: "expected HEAD drift fails before execution",
    4: "expected branch drift fails before execution",
    5: "a worker that crashes before producing a result is classified, not retried",
    6: "a malformed JSON result becomes RESULT_INVALID",
    7: "a schema-valid result carrying the wrong run identity is refused",
    8: "a missing structured handoff becomes RESULT_INVALID",
    9: "an unsupported handoff protocol version is refused",
    10: "prompt_disposition=COMPLETE with program_verdict=FAIL is a VALID handoff",
    11: "a capability outside the envelope yields OWNER_REQUIRED",
    12: "a restarted dispatcher rediscovers a live worker or classifies the uncertainty",
    13: "an uncertain write execution does not auto-retry",
    14: "the executor claims no file change while the fixture changed -> disagreement",
    15: "the executor claims a file change while the fixture did not -> disagreement",
    16: "a stale result artifact from a prior run is refused",
    17: "a conflicting API/provider credential environment refuses at preflight",
    18: "zero inspected evidence cannot be reported as a successful validated execution",

    # ---- P2: the consuming project's real-repository bindings. Numbering continues the contract; the required P2
    # negative controls that an existing P0/P1 control ALREADY proves are mapped in
    # P2_REUSED_CONTROLS below rather than duplicated here.
    19: "a child that ran in the wrong cwd fails the execution-location proof",
    20: "a child answer disagreeing with the independent measurement is rejected",
    21: "an inspected count below the derived floor is VACUOUS, never PASS",
    22: "the evidence floor is derived from the revision, not from the checkout it polices",
    23: "a READ_ONLY run that mutates a tracked file is caught by measurement",
    24: "a READ_ONLY run that creates an untracked file is caught by measurement",
    25: "P2-attributable primary-checkout drift is flagged, foreign churn is attributed",
    26: "foreign worktree or branch interference is flagged",
    27: "an ownership stamp naming a different path is refused as FOREIGN",
    28: "an unattributable or mismatched session stamp is refused",
    29: "retirement refuses when a safety proof fails or cannot be evaluated",
    30: "the control-fact anchors must be unique, or the measurement refuses",
}

REQUIRED_CONTROLS.update({
    # ---- P2.5: Docker confinement + control-plane hardening. The 34 required negative controls
    # from the specification's matrix, in order.
    31: "Docker engine unavailable -> BLOCKED, with no native-Windows fallback",
    32: "native (unconfined) STANDARD_EDIT_CONFINED is refused before launch",
    33: "a privileged container profile is refused",
    34: "a host-PID-namespace profile is refused",
    35: "a host-network profile is refused",
    36: "a mounted Docker socket is refused",
    37: "an arbitrary user-profile bind is refused",
    38: "the project's primary checkout mounted RW is refused",
    39: "the orchestrator source mounted RW is refused",
    40: "an unknown read-write host mount is refused",
    41: "an allowed /workspace write succeeds (executed evidence)",
    42: "read-only mount mutation by a direct process fails (executed evidence)",
    43: "read-only mount mutation by a real Claude built-in tool fails (executed evidence)",
    44: "read-only mount mutation via Bash fails (executed evidence)",
    45: "an unmounted forbidden host target is unreachable (executed evidence)",
    46: "path traversal yields no host filesystem access (executed evidence)",
    47: "symlink escape yields no host write (executed evidence)",
    48: "the Docker daemon/control plane is unavailable to the child (executed evidence)",
    49: "a wrong host->container mapping is refused",
    50: "challenge bytes that disagree refuse the run",
    51: "an API/provider credential override inside the container refuses at preflight",
    52: "a forged SQLite owner grant still yields OWNER_REQUIRED",
    53: "an unchanged status fingerprint while bytes change is caught by the content class",
    54: "a silently lowered evidence floor is refused",
    55: "a missing floor derivation is refused",
    56: "a forged test PASS claim loses to the independent collector",
    57: "a zero-test suite is VACUOUS, never PASS",
    58: "a test timeout is not recorded as PASS",
    59: "cancellation after a measured write is not a clean CANCELLED",
    60: "duplicate cancel is idempotent and non-destructive",
    61: "the real-child concurrency ceiling refuses a second child",
    62: "a container whose ACTUAL mounts differ from the profile is SECURITY_BOUNDARY_FAIL",
    63: "a forbidden sentinel that changed makes the run SECURITY_BOUNDARY_FAIL",
    64: "a Claude handoff claiming PASS loses to failing confinement evidence",
})

REQUIRED_CONTROLS.update({
    # ---- P3: the full confined WRITE pipeline, egress, and the Git-metadata model.
    65: "the persistent auth seed cannot be modified by the child",
    66: "arbitrary child home state does not survive into the next container",
    67: "a fresh container can still bootstrap authentication from the same seed",
    68: "execution image identity is bound by digest, not by tag",
    69: "the meaningful fixture genuinely starts in a failing state",
    70: "the real child edits only the authorized fixture workspace",
    71: "the independent collector observes PASS after the fix",
    72: "a Claude PASS claim against a collector FAIL resolves to FAIL",
    73: "replaying an identical completed dispatch spawns no second child",
    74: "a container that dies after a write, before a terminal result, is reconciled honestly",
    75: "no automatic redispatch follows an ambiguous write execution",
    76: "a dispatcher restart with live worker/container state reconciles rather than duplicates",
    77: "the child's egress was measured, not assumed",
    78: "non-allowlisted egress destinations are denied",
    79: "a direct egress bypass around the gateway is impossible",
    80: "worktree-only mount Git behaviour was measured rather than assumed",
    81: "the chosen Git metadata model resolves the exact HEAD",
    82: "the chosen Git metadata model observes a workspace edit",
    83: "the chosen Git metadata model cannot mutate host refs",
    84: "the chosen Git metadata model cannot mutate host config",
    85: "the chosen Git metadata model cannot commit, stash or tag",
    86: "no project primary working-tree content is exposed to a child",
    87: "no sibling worktree content is exposed to a child",
    88: "no arbitrary child state persists through the authentication mechanism",
})

REQUIRED_CONTROLS.update({
    # ---- P4: the consuming project's containerized worktree qualification.
    89: "the project's canonical helper is invoked through a VERIFIED MSYS Git Bash",
    90: "an invalid or foreign ownership stamp blocks dispatch",
    91: "a worktree HEAD differing from the admitted base is refused",
    92: "sibling worktree private metadata is hidden from the child",
    93: "the P4 worktree's own private metadata remains visible",
    94: "primary working-tree content is absent from the child",
    95: "Git metadata write attempts are denied",
    96: "credential-bearing Git config would refuse the metadata mount",
    97: "the narrowed egress policy denies arbitrary hosts",
    98: "the real READ_ONLY answer independently agrees with the bridge",
    99: "a READ_ONLY child that changed the workspace fails",
    100: "a write child that modified a tracked path fails",
    101: "a write child that created a second untracked path fails",
    102: "a smoke artifact digest mismatch fails",
    103: "a smoke artifact observed-HEAD mismatch fails",
    104: "a smoke artifact tracked-file digest mismatch fails",
    105: "cleanup refuses a non-owned or replaced smoke artifact",
    106: "retirement refuses a dirty P4 worktree",
    107: "exact worktree removal is verified on disk AND in the git registry",
    108: "branch retirement refuses a branch carrying unique commits",
    109: "foreign worktree mutation is attributed and rejected",
    110: "an external OAuth provider's secret is redacted everywhere",
    111: "an absent credential for unattended production yields OWNER_REQUIRED",
    112: "the real container's ACTUAL mounts equal the admitted mounts",
})

REQUIRED_CONTROLS.update({
    # ---- P4.5: the owner credential broker.
    113: "the credential is accepted only from a hidden interactive prompt, never an argument",
    114: "provisioning refuses when stdin is not an interactive terminal",
    115: "nothing is stored in plaintext at rest",
    116: "persisted metadata carries no secret-derived material",
    117: "the credential store lives outside both repositories",
    118: "a corrupt DPAPI blob refuses rather than degrading",
    119: "a blob protected in a different context cannot be used",
    120: "duplicate provisioning rotates deliberately with a new credential id",
    121: "a deleted credential yields OWNER_REQUIRED",
    122: "status reports PRESENT/ABSENT/VALIDATED without secret-derived material",
    123: "the secret never appears in process command-line arguments",
    124: "the secret never appears in the durable SQLite store",
    125: "the secret never appears in JSON evidence, manifests, receipts or handoffs",
    126: "the secret never appears in stdout or stderr",
    127: "the secret never appears in an exception string",
    128: "the secret never appears in retained docker inspect output",
    129: "the secret never appears in any repository file, tracked or untracked",
    130: "no temporary file retains the secret after cleanup",
    131: "an ANTHROPIC_API_KEY present refuses validation",
    132: "provider routing (Bedrock/Vertex/Foundry) refuses validation",
    133: "a non-subscription auth classification refuses",
    134: "the validation child uses an ephemeral home and mounts no auth seed",
    135: "transient plaintext is wiped after injection",
    136: "the broker outranks the legacy seed as the production credential source",
})

# ---- P5-A: the ChatGPT/MCP transport envelope. The transport is an ADAPTER, not a second
# orchestrator, and every control below either proves it decides nothing or proves it refuses.
REQUIRED_CONTROLS.update({
    137: "the MCP surface is exactly five governed verbs; no shell/exec/fs/docker/git/sql tool",
    138: "tool mutability annotations match what each tool can actually cause",
    139: "an unknown tool name refuses without revealing whether any run exists",
    140: "an unknown request field refuses; the schema is closed, not lenient",
    141: "an unsupported schema version refuses as PROTOCOL_REFUSED",
    142: "no caller-supplied filesystem path is ever accepted; a repo is named by server alias",
    143: "an authority profile outside the transport allowlist refuses at the edge",
    144: "qualification-mode dispatch cannot spawn a worker, so no executor is constructible",
    145: "no executor, credential-broker or docker module is reachable from the transport",
    146: "an adapter aliasing the governed repository cannot be constructed",
    147: "absent or malformed transport auth refuses before any orchestrator invocation",
    148: "the Claude OAuth credential is refused as transport authentication",
    149: "auth failure is indistinguishable from a nonexistent run",
    150: "duplicate transport dispatch resolves to one dispatch key and one run",
    151: "duplicate status/result/cancel/reconcile preserve their own semantics",
    152: "a transport timeout never causes a blind redispatch",
    153: "the transport request identity never replaces the orchestrator dispatch key",
    154: "remote payloads carry no secret, no raw environment and no absolute host path",
    155: "the redaction scan is non-vacuous and a failed scan withholds the response",
    156: "policy-injection text in any caller field remains inert data",
    157: "owner-approval prose in a request cannot create owner authority",
    158: "reconcile never starts an execution",
    159: "the HTTP transport binds loopback only and cannot be configured otherwise",
    160: "durable transport and orchestrator state survive a server restart",
    161: "the MCP protocol layer negotiates versions and never answers a notification",
    162: "the transport ledger records what it inspected and can prove its own idempotency",
    163: "the server is dual-era: legacy initialize AND modern per-request metadata conform",
    164: "transport verbs reach only runs the transport itself created",
    165: "a pre-adapter HTTP refusal is still ledgered, and is bounded before it is read",
    166: "the child processes a dispatch really spawns are counted, and are read-only git only",
    167: "no GET falls through to the MCP POST-only route; OAuth discovery is absent, not malformed",
    168: "the tool-surface refresh marker is deterministic, observable, and cannot alter behaviour",
})

#: P2 required negative controls that are ALREADY proven by an executed P0/P1 control. Listed so
#: the mapping is explicit and auditable rather than assumed -- and so nobody re-proves them by
#: writing a redundant test that spends time without adding coverage.
P2_REUSED_CONTROLS = {
    "wrong expected HEAD": 3,
    "wrong branch": 4,
    "wrong handoff run identity": 7,
    "stale result artifact from a prior run": 16,
    "zero inspected files": 18,
}


# ---- P5-X: the extraction's own contract. Genericity, and the primitives the extraction added.
REQUIRED_CONTROLS.update({
    169: "the platform source names no project, user or machine (frozen constants excepted)",
    170: "no absolute host path is compiled into the platform",
    171: "the core never imports transports, executors, sandbox, review or projects",
    172: "the product name lives in exactly one module",
    173: "an actor role confers no authority, and an unknown role is refused",
    174: "review roles can never hold a mutating capability; the ceiling never widens",
    175: "the two-way protocol has a closed, routable message vocabulary",
    176: "an AUTHORITY_REQUEST records a request and grants nothing",
    177: "message persistence is idempotent by content digest",
    178: "open questions persist until answered; a malformed envelope is refused",
    179: "a decision records who was entitled to make it",
    180: "decisions are superseded, never overwritten, and never without a rationale",
    181: "the event vocabulary is closed, and requests are distinguishable from effects",
    182: "one active strategic writer per lane, fenced against a superseded writer",
    183: "two writable lanes cannot share a workspace",
    184: "run/lane/program outcomes do not collapse into one boolean; waiting is not failure",
    185: "a new strategist session can resume from durable state without a transcript",
    186: "review is independent by construction, and two projects share one unchanged core",
    187: "the child-prompt contract is pinned, so re-keying dispatch is never silent",
    188: "every %-format string in the platform has matching specifier and argument counts",
    189: "the lane fence is enforced on writes, and concurrent claims cannot both acquire",
})


# ---- P5-XQ: control reachability. CONTROL_DECLARED != CONTROL_REACHABLE != CONTROL_EFFECTIVE.
# Adversarial review found four security-significant controls that existed only as unreachable
# code, each with a PASSING control that constructed its own subject. These test the production
# path, not the function.
REQUIRED_CONTROLS.update({
    190: "a deployment refuses to build when no protected root can be established",
    191: "the deployment hands protected roots to the transport; the wiring is not dead",
    192: "path policy is constructed for every platform, not only the one it runs on",
    193: "a change requiring adversarial review cannot be accepted without one",
    194: "a reviewer's self-declared outcome is recomputed, never trusted",
    195: "only an owner waiver passes the review floor, and it must be recorded",
    196: "model-constructed evidence is never accepted as measurement",
    197: "the role ceiling has a production caller and covers every outward capability",
    198: "the executor registry refuses an absent or unknown kind rather than defaulting",
    199: "a store written under other identity semantics is refused, not migrated",
    200: "execution identity depends only on declared inputs",
    201: "the content classifier recognises credential shapes and keeps engineering prose",
    202: "no secret or host path reaches durable strategic storage",
    203: "concurrent claims and writes are correct under real threads",
    204: "no message content can grant capability, mutate the objective, or bypass ownership",
    205: "a reviewer finding is not a verified fact and cannot reach a program verdict",
    206: "a provider secret is redacted everywhere, detected by value not by name",
    207: "an absent credential for unattended production yields OWNER_REQUIRED",
    208: "the API key can never be exempted, and the mount escape hatch stays bounded",
    209: "the egress environment contract is symmetric across the container boundary",
    210: "the image and the host agree on the auth-seed path",
    211: "every example project is constructible, and a third needs no core change",
    212: "every import-graph walk resolves relative imports, proven on foreign bytes",
    213: "the credential policy is provider-neutral and the vendor lives in executors",
    214: "every security-significant control has a verified production caller",
})


# ---- P6: the remote read-only surface. A Plus-tier ChatGPT reaches this transport only through
# the tunnel channel, and the feature IS its ceiling: the remote token authenticates read-only,
# writes are refused by channel, and the retrieval verbs actually retrieve.
REQUIRED_CONTROLS.update({
    215: "the remote token authenticates a distinct channel, and the class follows the secret",
    216: "a remote caller is advertised exactly the read-only surface, nothing else",
    217: "every remote write is refused by channel, ledgered, and unreachable by argument shape",
    218: "revoking or rotating the remote token closes remote access at once, loopback untouched",
    219: "search and fetch retrieve this transport's own records, scoped and honestly labelled",
    220: "the tunnel seams are measured: loopback-only command, URL parsing, a live doctor run",
})


# ---- P7: adapter assurance (§5.3, §5.12, §5.13). ADAPTER ASSURANCE IS MEASURED, NOT
# SELF-DECLARED: every control below proves Quaestor COMPUTES a level from probe evidence and
# refuses claims above proof -- CONTROL_DECLARED != CONTROL_EFFECTIVE is barred at the adapter
# edge rather than audited after the fact.
REQUIRED_CONTROLS.update({
    221: "each assurance level's full probe set computes exactly that level",
    222: "every over-claim refusal names the probes it is missing",
    223: "a claim at proof is clean, and evidence below OBSERVED refuses even OBSERVED",
    224: "the prompt-transport leak check fails ARGV and passes STDIN/PIPE (§5.13)",
    225: "send/receive round-trips and message ids survive; dropped ids are detected",
    226: "cancel actually cancels and lifecycle hooks work; a decorative cancel is detected",
    227: "read-only stays read-only under provocation; a violated read-only is detected",
    228: "no write outside the claimed workspace succeeds; an escape is detected",
    229: "resume after reconnect holds, and the durable record carries computed<=claimed with refusals",
    230: "the adapter registry feeds `doctor` and an empty registry renders []",
})


# ---- P8: reference adapters (direction §5.2 Tiers 0-1, §5.6, §5.7). Three concrete agent-ends on
# the §5.1 contract. The file lane exists to keep "file contents != authority" (§5.6) structural;
# the command/clipboard lanes must not leak prompts through argv (§5.13); the transcript lane must
# be unable to mutate anything it watches. As everywhere: assurance is computed from probes, never
# self-declared.
REQUIRED_CONTROLS.update({
    231: "a filebox task is answered in the outbox, received exactly once, and marked consumed",
    232: "an outbox response lacking its completion marker is never received (loud-not-partial)",
    233: "authority-shaped outbox fields surface verbatim yet are refused by the apply step",
    234: "command turns carry the prompt on stdin only; argv leaks nothing (§5.13)",
    235: "a timed-out command turn is killed, not orphaned, and fails loudly",
    236: "clipboard dialogue round-trips where Windows PowerShell supports it (manual mode)",
    237: "the transcript observer is read-only by surface: it observes and cannot send",
    238: "every reference adapter measures exactly its registered assurance level from probes",
    239: "every declared kind is buildable or refused by name at admission; no seat can be "
         "routed to a kind that dies in build() (bd quaestor-ubg)",
    240: "a manifest can pin a seat to a user-supplied command and hold a real run end to "
         "end, with an explicit preflight branch (bd quaestor-cjj)",
    241: "the file-inbox reference adapter is dispatchable as an executor kind end to end "
         "(bd quaestor-ru1.19)",
    242: "the shipped surfaces run the probes and show the COMPUTED assurance level from "
         "durable records, not a declaration (bd quaestor-ru1.18)",
    243: "class-level and constructor capability channels must agree or construction refuses "
         "by name; the surface cannot advertise an unbacked capability (bd quaestor-ru1.21)",
    244: "run.provenance carries role, provider, model_family (derived from the kind) and "
         "model on a real dispatch (bd quaestor-kaz.11)",
    245: "docs and the seat-writer refusal both state plainly that the product writes YAML "
         "and TOML is accepted input only (bd quaestor-ru1.20)",

    # ---- RELAY MODE (bd quaestor-pr4). The relay's whole reason to exist is that a
    # conversation survives a restart without saying anything twice, so the controls below are
    # weighted toward the ledger, reconciliation and the governance boundary rather than toward
    # the happy path -- the happy path is proven LIVE, and a mock may never stand in for that.
    246: "a relay drives multi-turn exchange over persistent endpoints without Program Mode: "
         "no run, no lane, no seat, no Executor.execute (bd quaestor-pr4.1)",
    247: "a relay killed mid-delivery re-delivers nothing the endpoint already holds, and "
         "re-delivers exactly once what it does not (bd quaestor-pr4.5)",
    248: "an endpoint that cannot answer 'do you already hold this?' stops the relay instead "
         "of guessing between duplicating work and dropping it (bd quaestor-pr4.5)",
    249: "a turn already in the durable record is never treated as new work (bd quaestor-pr4.1)",
    250: "a partial or truncated endpoint turn is never forwarded as completed work "
         "(bd quaestor-pr4.1)",
    251: "repetition, exchange-count and duration ceilings each stop the relay by name "
         "(bd quaestor-pr4.1)",
    252: "orchestrator prose asserting authority grants nothing; only profile plus owner "
         "channel decide (bd quaestor-pr4.6)",
    253: "a declared owner-gated effect request creates an owner hold and the directive is "
         "recorded but NOT delivered (bd quaestor-pr4.6)",
    254: "an effect class this build does not model is refused, never ignored "
         "(bd quaestor-pr4.6)",
    255: "an owner-gated effect OBSERVED in the repository holds the relay even though no "
         "directive requested it (bd quaestor-pr4.6)",
    256: "binding a repo-mutating execution end under a profile that does not grant repo_write "
         "is refused at start, before any message moves (bd quaestor-pr4.6)",
    257: "the relay kernel imports no provider: the endpoint layer is reachable only through "
         "the registry, and an unknown kind is a named refusal (bd quaestor-pr4.1)",
    258: "capability and assurance are separate facts: an unconfined but repo-writing execution "
         "end participates with can_mutate_repo true and confinement unproven "
         "(bd quaestor-pr4.8)",
    259: "the repository reading the orchestrator is shown is taken by this process, not by the "
         "execution agent's own transport (bd quaestor-pr4.4)",
    260: "an endpoint that cannot resume reports RESUME_UNSUPPORTED and the relay records that "
         "rather than claiming continuity it does not have (bd quaestor-pr4.5)",
    # REGRESSION, from the first live restart qualification (2026-08-29). The relay was killed
    # where a relay actually spends most of its life -- WAITING for a slow agent turn -- and
    # resumed with an empty delivery queue, so it stopped for NO_PROGRESS while the agent's
    # finished work sat uncollected. The delivery ledger alone was not enough.
    261: "a relay killed while awaiting a reply resumes into the RECEIVE phase, collecting the "
         "outstanding turn without re-delivering the message (bd quaestor-pr4.5)",
    262: "a transport failure while asking an endpoint 'do you already hold this?' is never "
         "reported as 'no': it propagates and the relay stops (bd quaestor-pr4.5)",
    263: "credential-shaped spans in an agent turn are removed before that turn crosses to a "
         "remote orchestrator, and the surrounding engineering prose survives "
         "(bd quaestor-pr4.4)",

    # ---- CHATGPT WEB AS A RELAY ORCHESTRATOR (bd quaestor-pr4.11). Four of these encode
    # defects that only a REAL signed-in page could expose; the unit suite had been feeding
    # ``classify`` synthetic booleans and could not have found any of them.
    264: "the chatgpt-web orchestrator end satisfies the RelayEnd contract and the relay kernel "
         "stays provider-neutral: no relay core module mentions a browser (bd quaestor-pr4.11)",
    265: "an always-present EMPTY aria live region is not an error affordance: only non-empty "
         "error text is, so a healthy signed-in page does not classify as STREAM_ERROR "
         "(bd quaestor-pr4.11)",
    266: "the optimistic client-side conversation id the page shows before the server assigns "
         "one is never bound as the relay's conversation identity (bd quaestor-pr4.11)",
    267: "resume refuses to call landing on a different or new conversation a resumed one "
         "(bd quaestor-pr4.11)",
    268: "the receive anchor carries the pre-submit baseline through the relay ledger, so a "
         "restarted relay asks the same 'newer than what?' and cannot re-read an older answer "
         "as new (bd quaestor-pr4.11)",
    269: "a still-generating or timed-out chatgpt turn is returned incomplete with a named "
         "error and its partial text is never the message text (bd quaestor-pr4.11)",
    270: "signed-out, no-composer, and browser-gone are each distinct named endpoint states, "
         "and none of them raises out of open/status/receive (bd quaestor-pr4.11)",
    271: "chatgpt holds() answers from the LIVE conversation and REFUSES rather than guessing "
         "when the page is unreadable or the thread outruns the rendered window "
         "(bd quaestor-pr4.11)",
    272: "the in-page content key and its Python twin agree on every input, including astral "
         "characters, so a turn that matches is not missed (bd quaestor-pr4.11)",
    273: "an endpoint whose conversation does not exist until the first message has its "
         "identity recorded once it becomes knowable, so a restart can still re-bind "
         "(bd quaestor-pr4.11)",
    274: "a new answer is recognised on a VIRTUALISED thread, where the rendered message count "
         "plateaus and can never exceed the pre-send baseline (bd quaestor-pr4.11)",
    275: "holds() refuses when the page is showing a WINDOW of the thread rather than all of "
         "this relay's deliveries, instead of reading a scrolled-out turn as absent "
         "(bd quaestor-pr4.11)",
    # ---- FROM ADVERSARIAL REVIEW (bd quaestor-pr4.21). Six lenses raised 38 candidates and
    # per-finding refutation confirmed 14; these pin the distinct defects behind them.
    276: "receive refuses to read another conversation's answer as the reply, and never "
         "silently rebinds the endpoint to a thread the anchor did not name "
         "(bd quaestor-pr4.21)",
    277: "the reply is located from the relay's OWN user turn, so a turn interleaved into the "
         "same thread by anyone else is never returned as the answer (bd quaestor-pr4.21)",
    278: "an assistant turn already judged incomplete is not accepted later unchanged, because "
         "a dead stream satisfies every completion check (bd quaestor-pr4.21)",
    279: "a lost, unreadable or never-configured delivery record makes holds() REFUSE rather "
         "than report the message as never sent (bd quaestor-pr4.21)",
    280: "holds() reads the conversation the delivery went to, navigating there first, and "
         "refuses if the browser cannot be brought to it (bd quaestor-pr4.21)",
    281: "the two whitespace normalisers agree on every code point, including the ones only "
         "one language's \\\\s matches, so a landed turn always hashes alike "
         "(bd quaestor-pr4.21)",
    282: "the reply is anchored to the page's OWN id for the turn the relay submitted, so a "
         "message the renderer rewrites -- any message carrying markdown -- is still found "
         "(bd quaestor-pr4.22)",
    283: "send waits for a user-turn id that DIFFERS from the one present before the submit, so "
         "an exchange is never anchored to somebody else's message (bd quaestor-pr4.22)",

    # -- completion corroboration: a claim is measured, not believed (bd quaestor-pr4.16) ------
    284: "a completion claim that independent measurement REFUTES does not stop the relay as "
         "OBJECTIVE_COMPLETE (bd quaestor-pr4.16)",
    285: "a refuted completion claim rides back to the Orchestrator as a blocker carrying WHICH "
         "check failed and its measured output (bd quaestor-pr4.16)",
    286: "repeated refuted completion claims stop the relay as COMPLETION_UNCORROBORATED, a "
         "different outcome from OBJECTIVE_COMPLETE, under a bound (bd quaestor-pr4.16)",
    287: "with no corroboration configured the claim is recorded UNCONFIGURED -- honest that "
         "nothing measured it -- and never as corroborated (bd quaestor-pr4.16)",
    288: "a check that could not be RUN is UNMEASURABLE and is never read as a passing check "
         "(bd quaestor-pr4.16)",
    289: "the refusal bound is counted from the durable event log, so a relay cannot forget its "
         "refusals by restarting (bd quaestor-pr4.16)",
    290: "corroboration runs the project's own commands in THIS process, never asking the agent "
         "whether the agent's work is correct (bd quaestor-pr4.16)",

    # -- bounded recovery from an incomplete turn (bd quaestor-nmq) ----------------------------
    291: "a still-usable endpoint that returns one INCOMPLETE turn is retried and the relay "
         "continues; one bad turn does not end a healthy slice (bd quaestor-nmq)",
    292: "only the RECEIVE is retried -- the send is never repeated -- so bounded recovery "
         "cannot duplicate a delivery (bd quaestor-nmq)",
    293: "an endpoint that is no longer usable is NOT retried; endpoint death and an unfinished "
         "sentence stop by different names (bd quaestor-nmq)",
    294: "incomplete-turn retries are bounded and exhaustion stops as *_INCOMPLETE, with the "
         "partial never forwarded on any attempt (bd quaestor-nmq)",
    295: "a quoted check argument survives splitting, so a check that must FAIL really fails; "
         "the first splitter handed the quotes to the interpreter and a failing check exited "
         "zero (bd quaestor-pr4.16)",

    # -- found by adversarial review of PR #8 --------------------------------------------------
    296: "an INCOMPLETE turn is never written into the orchestrator transcript, so a retry "
         "re-asks the same question instead of being answered as a CONTINUATION (bd quaestor-nmq)",
    297: "a truncated directive never reaches the agent as its tail alone: the head, which may "
         "carry the guardrail, is not silently discarded (bd quaestor-nmq)",
    298: "the completion marker counts only as the LAST line of a turn, so an Orchestrator that "
         "explicitly DENIES completion does not end the relay (bd quaestor-pr4.16)",
    299: "repository movement is the FIRST reading compared with the LAST, so a tree that was "
         "already dirty before the relay started does not corroborate a completion claim "
         "(bd quaestor-pr4.16)",
    300: "verification output is redacted at the source, so a credential printed by a failing "
         "check reaches neither the durable record nor the remote Orchestrator (bd quaestor-pr4.16)",
    301: "resume RE-GATES an owner-held directive instead of delivering it: resuming is not "
         "approving, and a refused directive is not in the delivery queue (bd quaestor-pr4.6)",
    302: "a real owner grant DOES release a held directive and discharges the hold, so the gate "
         "is a boundary rather than a wall (bd quaestor-pr4.6)",
    303: "the completion policy is persisted with the relay, so resume cannot silently switch "
         "corroboration off and accept a claim it had just refused (bd quaestor-pr4.16)",

    # -- the model-exercising preflight (bd quaestor-nmq) ---------------------------------------
    304: "an unusable MODEL is refused at start, by its own name, not discovered at exchange 1 "
         "and blamed on the endpoint (bd quaestor-nmq)",
    305: "an orchestrator whose provider is down stops as *_MODEL_UNUSABLE, distinct from a "
         "disconnect (bd quaestor-nmq)",
    306: "PROBE_UNSUPPORTED is honest and never passing: it neither blocks a start nor claims "
         "the provider path was measured (bd quaestor-nmq)",
    307: "the browser end DECLINES to be probed rather than posting into the operator's own "
         "conversation (bd quaestor-nmq)",
    308: "a probe that raises is REFUSED, never allowed through (bd quaestor-nmq)",
    309: "--no-probe skips the probe, and a relay that skipped it never claims it passed "
         "(bd quaestor-nmq)",
    310: "a PERMANENT provider refusal stops at once and names the provider, a TRANSIENT "
         "upstream fault is still retried, and a DEAD endpoint is a disconnect (bd quaestor-nmq)",
    311: "a probe detail is redacted at construction, so a provider error body echoing a "
         "credential never reaches the durable record or a CLI surface (bd quaestor-nmq)",
    312: "the probe policy is persisted with the relay, so a resume cannot silently turn "
         "probing back on after the operator opted out (bd quaestor-nmq)",
    313: "probing never writes over a recorded conversation: registry.probe closes nothing it "
         "did not open, because close() SAVES (bd quaestor-nmq)",
    314: "the probe sends the SHAPE the real turn sends, so a model that rejects a parameter "
         "the relay never sets cannot block startup (bd quaestor-nmq)",
    315: "relay doctor does not report ready for a configuration relay start would refuse, and "
         "a DECLINED probe is not a failed one (bd quaestor-nmq)",

    # -- Quaestor Core: the authenticated local service boundary (bd quaestor-0fe.1) -----------
    316: "an unauthenticated caller reaches liveness and nothing else, and absent/malformed/"
         "unknown/revoked all get the SAME refusal (bd quaestor-0fe.1)",
    317: "a client token scoped to one project cannot reach another, and cannot learn that "
         "another exists (bd quaestor-0fe.1)",
    318: "an empty scope reaches no project, and there is no wildcard that could widen one "
         "(bd quaestor-0fe.1)",
    319: "the Core API exposes named operations only -- no execute, no file read/write -- and "
         "the module reaches no shell (bd quaestor-0fe.1)",
    320: "a filesystem path from a caller never selects a project; projects are named by id "
         "(bd quaestor-0fe.1)",
    321: "a revoked client is refused immediately, with no Core restart, and its record is kept "
         "(bd quaestor-0fe.1)",
    322: "a protocol-version mismatch and an oversized body each fail clearly (bd quaestor-0fe.1)",
    323: "a second Core cannot race the first: the lock is the mutual exclusion "
         "(bd quaestor-0fe.1)",
    324: "a stale endpoint file left by a killed Core is reported, never believed "
         "(bd quaestor-0fe.1)",
    325: "device identity and project authorizations survive a restart, and the identity "
         "carries no secret (bd quaestor-0fe.1)",
    326: "Core never shuts down on an idle timer while a relay is live or an owner hold stands "
         "(bd quaestor-0fe.1)",
    327: "project authorization has four verdicts and only AUTHORIZED is a yes; authorising is "
         "an operator act no Core operation performs (bd quaestor-0fe.1)",

    # -- found by an adversarial review of the Core boundary (bd quaestor-0fe.1) ---------------
    328: "serving one project runs NO git and touches no other project's working tree: the "
         "grant is applied before the work, not to the result (bd quaestor-0fe.1)",
    329: "a negative Content-Length does not walk past the body bound (bd quaestor-0fe.1)",
    330: "a malformed request always gets an ANSWER; nothing before the credential check may "
         "raise (bd quaestor-0fe.1)",
    331: "a credential embedded in a git remote never becomes a project identity, and is never "
         "written to the registry or served (bd quaestor-0fe.1)",
    332: "a STALE authorization is refused at the boundary: authorised once is not authorised "
         "now (bd quaestor-0fe.1)",
    333: "core.status does not hand a client the absolute state-home path or the OS account "
         "name (bd quaestor-0fe.1)",
    334: "an unreadable relay ledger is an OBLIGATION, not an absence, so the idle watchdog "
         "cannot shut down over an owner hold (bd quaestor-0fe.1)",

    # -- Core OWNS the relay's process lifetime (bd quaestor-0fe.1) ----------------------------
    335: "a client NAMES a registered relay shape and never describes one: nothing a client "
         "sends reaches the relay's command line (bd quaestor-0fe.1)",
    336: "an unauthorised project performs ZERO work -- no profile read, no spawn, no relay -- "
         "because the grant is checked before anything is done (bd quaestor-0fe.1)",
    337: "a retried start returns the SAME relay and spawns exactly once: the request identity "
         "is reserved BEFORE the relay is spawned (bd quaestor-0fe.1)",
    338: "a request identity is hashed and scoped to the client and project that chose it, so "
         "two ids cannot collide into one relay (bd quaestor-0fe.1)",
    339: "one logical relay is one process: a second holder is refused by the OS lock, and a "
         "running relay cannot be resumed into a second (bd quaestor-0fe.1)",
    340: "a relay whose durable state says RUNNING while no process holds its lock is reported "
         "ORPHANED by every listing, never as running (bd quaestor-0fe.1)",
    341: "stop is a governed durable request and not a kill: it applies only to a RUNNING relay "
         "and never overwrites the reason an ended relay ended (bd quaestor-0fe.1)",
    342: "a resumed relay's policy comes from its durable record, INCLUDING a deliberate zero, "
         "and never from a flag default (bd quaestor-0fe.1)",
    343: "Core resumes a relay with NO policy on the command line at all, so no profile can be "
         "imposed on a relay that already has one (bd quaestor-0fe.1)",
    344: "an owner hold survives Core: a resume through Core reports the hold standing rather "
         "than a resume that did not happen (bd quaestor-0fe.1)",
    345: "the idle watchdog is obligated by a held lock and by an owner hold, and is not pinned "
         "forever by an orphaned row (bd quaestor-0fe.1)",
    346: "the objective is the one string a client contributes to a command line, and it is "
         "bounded and refused unless it is one line of prose (bd quaestor-0fe.1)",

    # -- the QUALIFICATION HARNESS, which leaked processes and mismeasured a kill --------------
    347: "the qualification harness ends ONE process and never a tree: no /T, no negative pid "
         "(bd quaestor-0fe.1)",
    348: "the qualification harness cleans up on the FAILURE path, not only the passing one, "
         "and reports what it terminated (bd quaestor-0fe.1)",
    349: "the qualification harness has a real wall-clock ceiling that raises into its own "
         "cleanup instead of spawning on in the background (bd quaestor-0fe.1)",
    350: "the qualification harness ends only what it created, never what merely resembles it, "
         "and a second run cannot inherit the first's home (bd quaestor-0fe.1)",
    351: "a client starts Core ON DEMAND and gets one answer whether it started one or found "
         "one; liveness is measured by the lock, never read from a file (bd quaestor-0fe.1)",
    352: "a relay records WHERE its ends are, so a resume carrying no flags rebuilds the same "
         "endpoints -- and records references to credentials, never a credential "
         "(bd quaestor-0fe.1)",

    # -- an OWNER_HOLD is a durable authority requirement (bd quaestor-7ze) --------------------
    353: "an owner hold raised by ANY gate is outstanding until an owner decides, and an "
         "authenticated channel with no decision is not a decision (bd quaestor-7ze)",
    354: "only a matching, unrevoked, unexpired owner decision through an authenticated channel "
         "discharges a hold (bd quaestor-7ze)",
    355: "a decision cannot cross to another relay: scope selects which grants a relay sees, "
         "and the hold identity distinguishes relays (bd quaestor-7ze)",
    356: "a discharge is recorded once and survives a restart, and so does an undischarged "
         "hold (bd quaestor-7ze)",
    357: "an old decision does not cover a new hold: identity is the effect and the "
         "capabilities, not the relay alone (bd quaestor-7ze)",
    358: "authority uncertainty fails CLOSED -- a hold whose requirement cannot be identified, "
         "and an unreadable ledger, are not approvals (bd quaestor-7ze)",
    359: "discharging a hold grants authority and performs no effect: the directive goes back "
         "to the governed delivery path (bd quaestor-7ze)",
    360: "the status surface names the capability an owner must decide, so a hold is actionable "
         "without reading the event log (bd quaestor-7ze)",
    361: "an EXPIRED owner grant is not a decision; --expires was written and never consulted "
         "(bd quaestor-7ze)",
    362: "denial is real: an ungranted hold is not worn down by repetition, and ending a held "
         "relay is not approving it (bd quaestor-7ze)",
    363: "a discharge settles ONE raising, not an identity forever: the same requirement raised "
         "again is outstanding again, and a directive decision does not discharge an observed "
         "effect (bd quaestor-7ze)",
    365: "an OBSERVED ungranted effect is an AUTHORITY requirement, not a measurement "
         "failure: the durable hold is decided by whether the gate names missing capabilities, "
         "not by an allowlist of hold names a new gate can fall outside of (bd quaestor-7rh)",
    364: "UNREADABLE IS NOT EMPTY: a relay ledger that cannot be read blocks rather than "
         "discharging every outstanding hold at once, and an unreadable event log alone does "
         "not invent a hold on a relay that was never held (bd quaestor-7ze)",

    # -- Core answers only to its own authority (bd quaestor-d47) ------------------------------
    376: "a rebound Host is refused on EVERY route and method, /health included, on the SECOND "
         "request of a reused connection, and before any credential is read -- terminally, and "
         "with a declared body drained so the refusal survives -- while the loopback forms a "
         "real client sends still work (bd quaestor-d47)",
    372: "a PRESENT foreign Origin is refused -- by authority AND by scheme -- and an ABSENT "
         "one is not, so a page cannot be answered and the CLI is not locked out "
         "(bd quaestor-d47)",
    373: "the authority refusal identifies nobody: no Server banner, no instrument, no "
         "allowlist, so the 403 that covered /health is not that probe wearing a new status "
         "code (bd quaestor-d47)",
    374: "importing the test package makes `quaestor` resolve to THIS checkout's src even with "
         "another quaestor earlier on sys.path, so a targeted run in a worktree cannot report a "
         "verdict about a different tree (bd quaestor-d47)",
    375: "the body of a refused request is consumed EXACTLY and only up to the same limit a "
         "trusted body gets, driven directly because this platform was measured not to show the "
         "RST the draining defends against (bd quaestor-d47)",
    # -- a resume does not destroy the diagnosis (bd quaestor-1fr) -----------------------------
    377: "a resume keeps the previous stop reason through everything that has not superseded "
         "it: reconciliation is asked while the row still carries it, a stop reconciliation "
         "ITSELF takes names it, an operator stop landing inside that window keeps its own "
         "reason instead of being blanked, and the supersession reaches the event log BEFORE "
         "the row is cleared (bd quaestor-1fr)",
    378: "the diagnosis is cleared only once the resume has earned it: a proceeding resume "
         "leaves a RUNNING row with no stale reason, the row is still parked at the instant "
         "the ceiling is consulted, every stop the resume takes on the way -- an owner hold "
         "that still stands, the ceiling, a dead endpoint -- names what it replaced, and a "
         "resume that superseded nothing records nothing (bd quaestor-1fr)",
    # ---- PROVIDER-AUTHORED STRINGS ON THE RELAY CONTRACT (bd quaestor-32q). The class was
    # closed once at EndProbe and reopened by the field nobody looked at twice. These two are
    # deliberately a PAIR: 370 also pins ``text`` as RAW, which is the premise 263 reads.
    370: "a provider-authored error is classified at the contract IN BOTH DIRECTIONS, so it "
         "never crosses to the remote orchestrator or into the delivery ledger -- while the "
         "endpoint URL inside it SURVIVES, and the agent TEXT is left raw for the kernel to "
         "sanitise, which is what control 263 measures (bd quaestor-32q)",
    371: "the delivery refusal and the endpoint status detail carry provider bodies into the "
         "same durable event log by the same route and are classified by the same rule -- a "
         "host path goes, the provider URL stays readable, and endpoint-native identity "
         "survives byte for byte even when it is itself path-shaped (bd quaestor-32q)",
    # 366-369 are RETIRED, not renumbered: they measured a disk preflight for a self-hosted runner
    # fleet, and CI now runs on GitHub-hosted runners where that preflight has no disk to guard.

    # -- a grant names a PROJECT, not a place (bd quaestor-lmh) --------------------------------
    379: "a token scoped to one project cannot reach a repository that merely SITS WHERE that "
         "project used to: two registry records naming one root make classify answer AUTHORIZED "
         "for the other record, and every project-naming operation refuses without naming what "
         "is there -- relay.start included, proven to refuse BEFORE reserve_request and before "
         "_spawn_relay by a sentinel on each call, because a failed spawn releases the request "
         "identity again and leaves the ledger looking untouched either way (bd quaestor-lmh)",
    380: "the gate turns on IDENTITY and nothing else, in BOTH directions. The ordinary "
         "single-record project still answers on every operation, and THE SAME ROOT is "
         "reachable by the token that names what is actually there -- so the refusal above is "
         "the mismatch, not the fixture. And the successor gets no more than that: a relay row "
         "recorded at a root two records claim is served to NEITHER project and relabelled for "
         "neither, so it cannot be listed, stopped or resumed across the grant (bd quaestor-lmh)",
    # -- a completion claim is an utterance, not a suffix (bd quaestor-9lq) --------------------
    385: "a turn that does not CLAIM the marker never stops the relay, however it ends on it: "
         "the plain denial (\"the objective is not X\", \"I cannot write X\"), the DEFERRAL that "
         "carries no negative word at all (\"when CI is green I will emit X\"), the DISTANCING "
         "built from innocent words (\"far from X\", \"I stop short of X\"), the same denials "
         "with the marker moved onto a line of its own, a marker glued to a preceding word, and "
         "a turn that merely MENTIONS the token -- a question, a strikethrough, the protocol "
         "line quoted back; end to end the relay neither stops OBJECTIVE_COMPLETE nor even "
         "reaches the corroboration the claim would have bypassed (bd quaestor-9lq)",
    386: "the paired positive, without which refusing everything would pass 385 and burn every "
         "run to MAX_EXCHANGES: every form a real Orchestrator emits -- the bare line, the "
         "marker after prose, markdown, a terminal stop, a negation in an already-closed "
         "sentence, and above all the two shapes ordinary SUCCESS takes, an absence (\"with no "
         "failures, so X\") and identifier evidence (\"test_not_found now passes, X\") -- still "
         "ends the relay through the real kernel, while the three deliberate limits hold: case "
         "is NOT folded, a WORD after the marker still refuses, and a QUESTION is not a claim "
         "(bd quaestor-9lq)",
    # -- The opencode provider probe is EXECUTED, not read (bd quaestor-7z1) ---------------
    383: "the opencode probe really asks the configured model and the verdict follows the "
         "ANSWER, driven against the listing the server really returns: a healthy reply "
         "passes, an APIError on the assistant turn is REFUSED even when text sits beside "
         "it, and neither the probe's OWN prompt echoed back nor an assistant turn that has "
         "not spoken yet counts as an answer -- silence, an echo and a server that will not "
         "open a session are UPSTREAM_FAILED, a prompt the server rejects is REFUSED, and a "
         "probe that could not even make a scratch directory reports UNSUPPORTED rather than "
         "health, with the 60s ceiling pinned to its literal and to the polls it admits (bd "
         "quaestor-7z1)",
    384: "the opencode probe costs nothing it should not: it runs in a THROWAWAY session in "
         "a scratch directory it removes afterwards, never in the bound session or the "
         "authorised project, and it refuses a bare model name rather than spending an "
         "inference on a fabricated vendor (bd quaestor-7z1)",

    # ---- UNCERTAIN IS NOT DEAD (bd quaestor-9ap). reap guarded on `== ALIVE` and
    # recovered on everything else, so proc's UNKNOWN -- which its own docstring forbids
    # callers from converting to DEAD -- failed live workers and retried their lanes.
    391: "an UNPROBEABLE worker lock -- probe_lock's real open() failure, no mocking -- "
         "leaves a LIVE worker's run, lease and lane exactly as they were, even though "
         "its worktree is clean and at base: reap never reaches the recovery path at "
         "all, records the uncertainty instead of acting on it, and writes ONLY its own "
         "marker key, so what that live worker writes in the same window survives "
         "(bd quaestor-9ap)",
    392: "a worker whose liveness is PERMANENTLY unreadable is held for a bounded number "
         "of reap passes and then escalated to the owner as a BLOCKER on a "
         "WAITING_FOR_OWNER lane -- exactly once, however many passes follow -- and is "
         "never retried and never has its lease taken; the once is scoped to the RUN, so "
         "a later run on the same lane is not silenced by the earlier one's spent "
         "marker (bd quaestor-9ap)",
    393: "reap decides a dead-worker recovery on a FRESH liveness reading taken before it "
         "transitions the run, and releases the lease only THROUGH lease.may_reclaim: a "
         "reaper that loses its probe inside that window recovers nothing, leaves the run "
         "ACTIVE with its lease standing, and completes the recovery on a later pass "
         "instead of stranding it -- while an ordinary dead worker with a clean tree is "
         "still reclaimed, and the guard on collecting reap's own child refuses a pid "
         "whose recorded creation time no longer matches (bd quaestor-9ap)",
    399: "the durable escalated marker is written AFTER the escalation it describes, never "
         "before: a reaper that dies parking the lane -- a real store failure, not a skipped "
         "call -- leaves no marker claiming an escalation that did not happen, and the NEXT "
         "pass still reaches the owner with a WAITING_FOR_OWNER lane and a blocker, instead of "
         "reading a spent flag and stranding the lane holding its lease for ever with nothing "
         "on any desk (bd quaestor-9ap)",
    400: "reap REACHES its own child-collection arm rather than merely defining it: on the "
         "UNKNOWN arm the arm sits on, the call is observed and is made with THIS run's worker "
         "pid, so an uncollected corpse cannot keep answering probes and turn an ordinary "
         "crashed worker into an UNKNOWN one that is held and escalated instead of retried; "
         "deleting the call site is otherwise an undetected one-line change (bd quaestor-9ap)",

    # -- lock uncertainty is resolved against proceeding, on BOTH sides (bd quaestor-lag) ------
    381: "NO failure inside probe_lock -- not the open, not the lock call -- is ever reported "
         "as LOCK_FREE or LOCK_ABSENT, the two verdicts that mean nobody is there and that "
         "classify_liveness turns into a positive DEAD when the pid is also gone. Driven over "
         "all four branches of the probe: real contention (LOCK_HELD, measured by provoking it "
         "on whichever platform is running), a real open failure (LOCK_UNKNOWN, from a "
         "directory -- this is the arm LOCK_UNKNOWN actually comes from), free, and absent, "
         "plus nine injected errnos. It deliberately does NOT pin the lock-call arm to "
         "LOCK_HELD: that collapse is over-reporting whose cost is PERMANENT on a "
         "lock-incapable filesystem (ENOSYS/EOPNOTSUPP), and bd quaestor-lag's remaining work "
         "replaces it with an errno split now that bd quaestor-9ap has fixed orchestrator.reap "
         "-- which used to be the sole consumer that converted UNKNOWN into dead-worker "
         "recovery and no longer does. The module reads errno nowhere, so the injected loop is "
         "one branch nine times and the inspection count counts BRANCHES (bd quaestor-lag; its "
         "blocker has landed, so the split is unblocked follow-up work rather than a hazard "
         "this control forbids)",
    382: "a process that cannot PROVE it took the lock does not run: WorkerLock.acquire refuses "
         "on BOTH of its arms -- the makedirs+open guard, driven for real via a parent that is "
         "a regular file and a path that is a directory, and the lock call across every errno "
         "family -- records no handle on either, and the handle it opened before refusing is "
         "asserted .closed on the stub's own reference rather than inferred from the file "
         "being re-takeable (bd quaestor-lag)",
    # -- a documented READ does not write the operator's ledger (bd quaestor-mpp) ----------
    397: "answering a READ leaves the ledger byte-identical, asserted on the FILESYSTEM and "
         "not on the call returning: a store that is not in WAL mode keeps its journal mode "
         "and its exact bytes -- where the old open rewrote the database header to convert "
         "it -- and a WAL store a live relay is holding open survives repeated reads with "
         "no byte, no mtime and no sidecar changed. Before any relay has ever run the "
         "surfaces still ANSWER without the read creating the ledger it is reading, and the "
         "ban is SQLite's: ALTER, UPDATE, DELETE and INSERT are all refused on the "
         "connection itself (bd quaestor-mpp)",
    398: "a read will not migrate, so it REFUSES a store older than the build rather than "
         "answering from it -- naming the columns it lacks, leaving its schema and bytes "
         "untouched where the old open ran ALTER TABLE unattended once a second -- and the "
         "refusal REACHES the idle watchdog as unmeasured rather than as 'no relays', which "
         "is what shuts Core down on top of a standing owner hold; with the paired positive "
         "that the store's OWNER may still migrate it and the same read then answers, so "
         "what was refused is the staleness and not the fixture (bd quaestor-mpp)",
    401: "the read-only URI survives the path shapes a home can actually have, which is the "
         "whole mechanism -- mode=ro is the only thing making the connection read-only. A home "
         "holding '?', '#' or '%' keeps the parameter rather than ending the URI early and "
         "silently becoming read-WRITE, proven against a REAL database at that punctuated path "
         "by asserting SQLite still refuses a CREATE TABLE on it; and an AUTHORITY-ROOTED path "
         "-- a UNC share on Windows, a //host/... path on POSIX, spelled per platform because a "
         "UNC spelling on POSIX is an ordinary filename with backslashes and measures nothing "
         "-- carries an EMPTY authority (file:////server/share/...) rather than putting the "
         "host where the authority goes, where SQLite answers 'invalid uri authority' and every "
         "Core read surface fails permanently on a store the writing open reads fine, with the "
         "paired negative that a drive path does NOT gain those slashes. Asserted on the URI "
         "the code builds, never on one the test rebuilds (bd quaestor-mpp)",
    # -- crash windows in the delivery ledger (bd quaestor-cjx) --------------------------------
    394: "reconciliation's verdicts survive the resume that reached them. A CONFIRMED delivery "
         "is a delivery that SUCCEEDED, so it leaves the same outstanding turn one does -- "
         "adopted BEFORE the row is confirmed, proven by reading the row at the instant of the "
         "confirming write and by killing the process between the two, which costs one exchange "
         "and no turn -- instead of emptying the queue and stopping the relay NO_PROGRESS for "
         "ever while the endpoint holds a reply nobody will collect. And UNRECONCILABLE is an "
         "OPEN question, not a settled one: the next resume asks it again and stops by its own "
         "name rather than blanking it and re-stopping generically, while an endpoint that can "
         "answer still settles it (bd quaestor-cjx)",
    395: "the awaited-turn marker outlives the reply it names. Killed where the clear used to "
         "have already run -- a sanitiser and two gates before the reply was durable -- the "
         "record still names what was outstanding and the turn is collected by the next relay; "
         "at the moment the marker DOES come off, the reply it names is already a row; and a "
         "kill at the far edge, reply recorded and marker still standing, is recognised and "
         "closed rather than re-asked and refused by the stale-replay guard (bd quaestor-cjx)",
    396: "a delivery is CLAIMED, not assumed. The claim is a compare-and-swap over exactly the "
         "states the queue hands out -- proven state by state, so the queue and the claim cannot "
         "disagree -- and a second writer that takes the row in the window between reading the "
         "queue and claiming it makes the first LOSE: it does not send, it does not overwrite "
         "the winner's claim, it does not announce a delivery, and it stops by its own name "
         "rather than blaming an endpoint it never spoke to (bd quaestor-cjx)",
})


# =============================================================================================
# PLATFORM vs PROJECT-INTEGRATION CONTROLS
# =============================================================================================
# The extraction moved the PLATFORM here and left the project integration behind. Two control
# ranges tested the original consuming repository specifically -- its real worktrees, its branch
# and ownership conventions, its checkout on one machine -- so they are not platform controls and
# cannot run here.
#
# They are NOT deleted from the record. Listing them keeps the equivalence matrix honest: a reader
# can see exactly which controls the platform inherited and which remain the integration's
# responsibility, instead of finding a registry that quietly went from 168 entries to 132.
#: 110 and 111 are deliberately ABSENT from this range. Adversarial review read their bodies and
#: found them fully synthetic -- platform controls lost to a RANGE-BASED split rather than to a
#: judgement about each control, which is precisely the failure mode a range has. They are
#: restored above as 206 and 207. This note is what keeps the reclassification visible instead of
#: looking like the registry quietly changed size again.
PROJECT_INTEGRATION_CONTROLS = {
    n: REQUIRED_CONTROLS[n]
    for n in list(range(19, 31)) + [c for c in range(89, 113) if c not in (110, 111)]
    if n in REQUIRED_CONTROLS
}

#: 110 and 111 were neither platform-generic-in-place nor project-specific: adversarial review
#: found their tests fully synthetic, so they were PLATFORM controls lost to a range-based split.
#: They are restored above under new ids, and recorded here as superseded so the registry shows
#: what happened to them instead of appearing to have quietly shrunk twice.
SUPERSEDED_CONTROLS = {
    110: "superseded by 206 (a provider secret is redacted everywhere)",
    111: "superseded by 207 (an absent credential yields OWNER_REQUIRED)",
}

#: The platform's own contract. Everything the extracted core must keep proving.
for _n in list(PROJECT_INTEGRATION_CONTROLS) + list(SUPERSEDED_CONTROLS):
    REQUIRED_CONTROLS.pop(_n, None)

#: Populated at RUN time by the decorator. Never pre-seeded.
EXECUTED: set = set()

#: Populated at IMPORT time by the decorator. Static declaration.
DECLARED: dict = {}


def control(number: int):
    """Mark a test as proving REQUIRED_CONTROLS[number]. Records declaration and execution."""
    if number not in REQUIRED_CONTROLS:
        raise KeyError("control %r is not in the required contract" % (number,))

    def deco(fn):
        DECLARED.setdefault(number, []).append("%s.%s" % (fn.__qualname__, fn.__name__))

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            out = fn(*args, **kwargs)
            EXECUTED.add(number)          # recorded only on a PASS -- an exception skips this
            return out

        wrapper.__control__ = number
        return wrapper

    return deco


def coverage_report() -> dict:
    declared = set(DECLARED)
    executed = set(EXECUTED)
    required = set(REQUIRED_CONTROLS)
    return {
        "required": sorted(required),
        "declared": sorted(declared),
        "executed": sorted(executed),
        "missing_declaration": sorted(required - declared),
        "missing_execution": sorted(required - executed),
        "counts": {"required": len(required), "declared": len(declared),
                   "executed": len(executed)},
    }

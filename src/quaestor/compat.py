"""compat -- FROZEN WIRE CONSTANTS. Values that are history, not branding.

READ THIS BEFORE "TIDYING" ANYTHING IN HERE.

These strings still carry the name of the private repository this platform was extracted from.
That is deliberate, and each one is frozen for a specific, measured reason:

``DISPATCH_KEY_SALT``
    It is an input to the dispatch-identity digest. Changing it changes EVERY dispatch key, which
    silently breaks the platform's central guarantee -- at-most-one active execution per logical
    dispatch identity -- for any store that already holds runs. A rename here is not a rename; it
    is a data migration, and an invisible one.

``HANDOFF_PROTOCOL``
    It appears in a CAPTURED executor output kept as a test fixture. That fixture is the only test
    input this project did not generate itself, which is precisely what makes it evidence: a
    parser tested solely against bytes it also produced tests serialization, not verification.
    Renaming the protocol would force editing the fixture, destroying the one control that proves
    the envelope parser works against reality.

So: the product name is in ``quaestor.branding`` and is free to change. These are not that. If a
future version genuinely needs a new protocol name, it must be introduced as a NEW versioned
constant that is accepted ALONGSIDE this one, with its own captured fixture -- never by editing
the value here.
"""
from __future__ import annotations

#: Salt for the dispatch-identity digest. FROZEN -- see the module docstring.
DISPATCH_KEY_SALT = "AEGIS_ORCHESTRATOR_DISPATCH_KEY_v1"

#: Structured-handoff protocol discriminator. FROZEN -- see the module docstring.
HANDOFF_PROTOCOL = "AEGIS_ORCHESTRATOR_HANDOFF"

#: DPAPI ADDITIONAL ENTROPY -- an ON-DISK CRYPTOGRAPHIC PARAMETER, not branding.
#:
#: A blob sealed under one entropy value cannot be opened under another. It was briefly derived
#: from ``branding.PRODUCT_TITLE``, which ``branding`` explicitly licenses as free to rename --
#: so renaming the product would have silently made every stored credential unreadable, and the
#: failure would have surfaced as "the credential is corrupt" rather than "you renamed something".
#: It belongs here, with the other values that may not move.
CREDENTIAL_ENTROPY = b"Quaestor/credential-broker/v1"

#: THE CHILD-PROMPT CONTRACT VERSION.
#:
#: The prompt handed to an executor is an INPUT to the dispatch identity, so its bytes are part of
#: the deduplication join. The extraction changed one line of its boilerplate -- the old text named
#: the private project this platform came from, and shipping that into every executor's context in
#: a project-agnostic tool was not an option.
#:
#: The consequence, measured rather than assumed: for otherwise identical inputs,
#:     v1 (branded)  -> dispatch key 054ab896450a4821c60700bf3040313c705e4885a1f4af7743a9f93fa2cb016b
#:     v2 (generic)  -> dispatch key 19bb3d7fe050ad08653a562a9156c02b0413b0e36664ca2a91830c336b64b0b3
#: The ALGORITHM and the SALT are unchanged -- a fixed prompt string hashes identically in both --
#: so this is not a change of identity semantics. It is a change of one input's value.
#:
#: What that means in practice: a store written by the pre-extraction implementation is NOT
#: interchangeable with one written here. Previously-completed work would re-admit as new, which
#: is the kind of migration that is invisible until it has already happened. Do not point this
#: platform at an existing store; start a new one, or write an explicit key mapping.
#:
#: A control pins the prompt's first line to this version, so any future edit to the boilerplate
#: is a deliberate, visible diff instead of a silent re-keying.
CHILD_PROMPT_CONTRACT = "v2-generic"

#: Why each value may not move, quoted by the control that enforces it.
FROZEN_REASONS = {
    "DISPATCH_KEY_SALT": ("participates in the dispatch identity digest; changing it changes "
                          "every dispatch key and breaks at-most-one-active-execution for any "
                          "existing store"),
    "HANDOFF_PROTOCOL": ("appears in a captured real-executor fixture; changing it would force "
                         "editing the only test input this project did not generate"),
    "CREDENTIAL_ENTROPY": ("seals every stored credential blob; changing it makes existing "
                           "credentials permanently unreadable, and the symptom looks like "
                           "corruption rather than like a rename"),
}

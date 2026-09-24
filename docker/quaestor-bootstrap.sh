#!/bin/sh
# quaestor-bootstrap -- seed an EPHEMERAL home from a READ-ONLY auth seed, then exec the child.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# P2.5 mounted a persistent read-write volume at /home/claude so authentication would survive
# between runs. It worked, and it was too broad: measured after four runs that volume held 69
# entries / 560 KB -- a 35 KB .claude.json with five backups, session-env directories for four
# distinct sessions, shell snapshots, an nodejs cache, and a probe file written days earlier.
# One 581-byte file of that was authentication. Everything else was arbitrary child state that
# outlived the child and would have been visible to the next one.
#
# So the two concepts are now separate:
#
#     PERSISTENT AUTH SEED   /run/quaestor-auth-seed   read-only volume, credential ONLY
#     EPHEMERAL CHILD HOME   /home/claude           tmpfs, destroyed with the container
#
# This script copies exactly ONE artifact across that boundary. It does not copy settings, hooks,
# shell startup files, history, project instructions, MCP configuration, plugins, caches, or
# anything else that happens to live under $HOME. Nothing is ever copied BACK: the seed is
# mounted read-only, so a child that refreshes its token cannot promote that change to persistent
# state. (Credential refresh WAS observed in P2.5 -- see docs/DESIGN.md section 19. Making it
# durable needs a credential broker, not a writable home.)
#
# The script lives on the read-only rootfs and is owned by root, so the unprivileged child cannot
# edit the thing that bootstraps it.
set -eu

SEED="${QUAESTOR_AUTH_SEED:-/run/quaestor-auth-seed}"
HOME_DIR="${HOME:-/home/claude}"
CRED="${QUAESTOR_AUTH_ARTIFACT:-.credentials.json}"

mkdir -p "$HOME_DIR/.claude"

if [ -f "$SEED/$CRED" ]; then
    # cp, not a bind: the child gets a private copy in tmpfs. A bind would give the child a
    # handle on the seed itself and make "read-only" the only thing standing between it and the
    # persistent material.
    cp "$SEED/$CRED" "$HOME_DIR/.claude/$CRED"
    chmod 600 "$HOME_DIR/.claude/$CRED"
else
    # FAIL LEGIBLY, NOT SILENTLY. Proceeding without credentials makes `claude auth status`
    # report logged-out, which the auth preflight refuses -- a clear refusal beats a run that
    # mysteriously cannot reach the model.
    echo "quaestor-bootstrap: no auth artifact at $SEED/$CRED -- the child will be unauthenticated" >&2
fi

exec "$@"

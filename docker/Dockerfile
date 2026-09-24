# Ephemeral Claude execution container -- the OUTER confinement boundary.
#
# WHAT THIS IMAGE IS FOR
# ----------------------
# A STANDARD_EDIT_CONFINED Claude child must not rely on prompt compliance, project layout, or
# native-Windows Claude permissions as its containment boundary. Docker filesystem/namespace
# isolation is the PRIMARY boundary; Claude's own tool permissions are the SECONDARY one. This
# image is the primary boundary's payload, and it is deliberately small.
#
# WHAT IS DELIBERATELY ABSENT, AND WHY
# ------------------------------------
#   docker CLI / daemon   -- the child must not be able to reach a control plane that could
#                            escape it. The socket is never mounted; not installing the client
#                            removes even the convenient path.
#   kubectl, cloud CLIs   -- an unattended child with cloud credentials in reach is the paid /
#                            external-write hazard the authority policy exists to prevent.
#   sshd, ssh client keys -- no inbound service, no credential material.
#   build toolchains      -- "might be useful someday" is how a minimal boundary becomes a
#                            general-purpose machine.
#
# python3 IS present, and only because the TEST_EXECUTION collector runs bridge-owned test
# profiles inside this container. That is a measured requirement, not a convenience.
#
# BASE PINNED BY DIGEST (P3). P2.5 referenced `node:22-bookworm-slim` by tag and merely RECORDED
# the resulting digest after the fact -- which describes a build rather than constraining one. A
# tag is mutable, so two builds a week apart could differ while both claiming the same base. The
# digest below was measured from the P2.5 build and is now the input, not the output.
FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

# Pinned to the host's installed Claude Code so container and host behaviour are comparable.
# A floating version would make every re-run a different experiment.
ARG CLAUDE_VERSION=2.1.185
ARG CLAUDE_UID=1001
ARG CLAUDE_GID=1001

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         git \
         ca-certificates \
         python3 \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_VERSION}" \
    && npm cache clean --force

# NON-ROOT by construction. The container also runs with --cap-drop=ALL and
# --security-opt=no-new-privileges; this is the third, independent layer, so a profile bug that
# forgot a flag still does not yield a root child.
RUN groupadd --gid "${CLAUDE_GID}" claude \
    && useradd --uid "${CLAUDE_UID}" --gid "${CLAUDE_GID}" --create-home --shell /bin/bash claude \
    && mkdir -p /workspace /evidence-readonly /run/quaestor-auth-seed \
    && chown "${CLAUDE_UID}:${CLAUDE_GID}" /workspace /home/claude

# The mount points are created empty and owned appropriately so that a MISSING bind shows up as
# an empty directory rather than as a permission error that could be mistaken for confinement.
# An empty /workspace must fail the challenge-byte check, not look like a denied write.

# The bootstrap is root-owned on a read-only rootfs: the unprivileged child cannot edit the thing
# that bootstraps it.
COPY quaestor-bootstrap.sh /usr/local/bin/quaestor-bootstrap
RUN chmod 0755 /usr/local/bin/quaestor-bootstrap \
    && chown root:root /usr/local/bin/quaestor-bootstrap

USER claude
WORKDIR /workspace

ENV CLAUDE_CODE_ENTRYPOINT=quaestor-container \
    HOME=/home/claude \
    QUAESTOR_AUTH_SEED=/run/quaestor-auth-seed \
    npm_config_update_notifier=false \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_ERROR_REPORTING=1 \
    DISABLE_BUG_COMMAND=1

# ENTRYPOINT is the bootstrap and nothing else; the orchestrator supplies the exact argv for
# every execution, so nothing about WHAT runs is baked in where a reader of the run record could
# not see it.
ENTRYPOINT ["/usr/local/bin/quaestor-bootstrap"]
CMD ["/bin/bash", "-lc", "claude --version"]

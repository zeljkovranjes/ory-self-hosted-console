# syntax=docker/dockerfile:1
#
# Multi-stage build for the Ory Console backend skeleton.
#
# Stage 1 (builder): compile a release binary with cached dependency layers.
# Stage 2 (runtime): a minimal distroless image carrying ONLY the binary —
# no shell, no package manager, runs as non-root (T-02-image-bloat /
# T-02-secrets-in-image mitigations). No secrets are COPY'd into any layer;
# the bind address (and future config) come from env at runtime.

# ---- Stage 1: builder ----
# Toolchain floor is set by the deps: salvo 0.93 needs rustc >= 1.92, and
# sqlx 0.9.0 (Phase 2 persistence) raises that to rustc >= 1.94. Pin the builder
# to 1.95 (matches the host toolchain) so the --locked build resolves cleanly.
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app

# WR-01: the FLAG-01 keystone probe route (`/api/features/_probe`) is gated behind
# the OFF-BY-DEFAULT `test-probe` cargo feature so a normal production image carries
# NO dead, saml-toggleable probe. The live acceptance harness
# (scripts/verify/phase12-acceptance.sh) sets TEST_PROBE=1 to build an image that
# DOES expose the probe so it can anchor FLAG-01 end-to-end. Any non-empty value
# enables it; the default empty value ships the hardened production binary.
ARG TEST_PROBE=

# SQLX_OFFLINE: the sqlx `query!`/`query_as!` macros verify SQL at compile time
# against a live DB unless offline metadata is present. The build stage has NO
# database, so we force offline mode and ship the committed `.sqlx` metadata
# (Pitfall 2). Set BEFORE any cargo build so both invocations honor it.
ENV SQLX_OFFLINE=true

# WORKSPACE LAYOUT (Phase 19): the repo root is now a Cargo workspace
# (console-core + backend + cli). This Dockerfile's BUILD CONTEXT must therefore
# be the REPO ROOT (not backend/), because a `--locked` build needs the workspace
# root Cargo.toml + the single root Cargo.lock + the console-core crate the
# backend depends on. The `cli` member is NOT copied — building `-p
# ory-console-backend` never compiles it, so clap/the CLI never enter this image
# (the leanness invariant; verified by `cargo tree -p ory-console-backend` having
# no clap). Plan 04 updates docker-compose's backend `build.context`/`build.dockerfile`
# to match (see the SUMMARY note).
#
# Pre-cache dependencies: copy the workspace manifests + the committed lockfile,
# create dummy sources for EVERY workspace member cargo will resolve, and build
# only `-p ory-console-backend` so the dependency layer is reused when only
# backend/src changes.
# --locked: resolve EXACTLY the versions pinned in Cargo.lock (CR-04). Without the
# lockfile + --locked the build resolves transitive versions fresh from the
# Cargo.toml ranges, defeating supply-chain reproducibility (INFRA-04).
# The backend crate has BOTH a lib and a bin target, and console-core is a lib —
# the dep-cache stub must provide a placeholder source for each member cargo
# parses (the root resolves ALL members even when building only the backend), or
# cargo fails target resolution before any dependency is built.
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml ./backend/Cargo.toml
COPY console-core/Cargo.toml ./console-core/Cargo.toml
COPY cli/Cargo.toml ./cli/Cargo.toml
RUN mkdir -p backend/src console-core/src cli/src \
    && echo '// dependency cache build' > backend/src/lib.rs \
    && echo 'fn main() { println!("dependency cache build"); }' > backend/src/main.rs \
    && echo '// dependency cache build' > console-core/src/lib.rs \
    && echo 'fn main() {}' > cli/src/main.rs \
    && cargo build --release --locked -p ory-console-backend \
    && rm -rf backend/src console-core/src cli/src

# Copy the committed sqlx offline metadata and the migrations BEFORE the real
# build so the query macros resolve with no DB, and `sqlx::migrate!()` finds the
# embedded migration source. These live UNDER backend/ in the workspace layout,
# and `sqlx::migrate!()` / `include_str!` resolve relative to the backend crate's
# CARGO_MANIFEST_DIR (=/app/backend), so they MUST land at /app/backend/.sqlx,
# /app/backend/migrations and /app/backend/config.
COPY backend/.sqlx ./backend/.sqlx
COPY backend/migrations ./backend/migrations

# Now copy real sources and build the actual binary (still --locked, offline).
# console-core is a build-time dependency of the backend, so its real source must
# be present too.
COPY console-core/src ./console-core/src
COPY backend/src ./backend/src
# Phase 4 (config-edit) embeds the four Ory service config schemas + the five
# `ory://` sub-schemas at compile time via `include_str!("../../config/schemas/…")`
# (relative to backend/src/config_edit -> /app/backend/config/schemas/…). They
# MUST be present before the real build or the lib fails to compile (os error 2:
# no such file). The dep-cache stub above does not need them (empty lib.rs).
COPY backend/config ./backend/config
# Bust the cached dummy artifacts so BOTH the real backend lib and bin (and
# console-core) are recompiled (the bin depends on the lib + console-core, so a
# stale stub would break it).
# WR-01: the shell-form `${TEST_PROBE:+--features test-probe}` expands to nothing
# for a production build (no probe) and to `--features test-probe` when the
# TEST_PROBE build-arg was set (the acceptance image). Done here in the RUN (sh -c)
# because Dockerfile `ENV` does NOT support `${VAR:+...}` substitution.
# `-p ory-console-backend` keeps the image lean: only the backend bin + its
# console-core dep compile; the cli member (and clap) are never built.
RUN touch backend/src/lib.rs backend/src/main.rs console-core/src/lib.rs \
    && cargo build --release --locked -p ory-console-backend ${TEST_PROBE:+--features test-probe}

# ---- curl stage ----
# The distroless runtime ships no curl. We vendor a single STATICALLY-LINKED
# curl binary so the backend can (a) self-healthcheck its own /health and
# (b) serve as the internal probe source for the Phase 1 acceptance harness
# (it curls kratos:4434/health/ready and the restart-broker over the internal
# network). This keeps the distroless hardening (no shell, no package manager,
# non-root) while satisfying the harness contract.
#
# NOTE: curlimages/curl ships a *dynamically*-linked musl curl that cannot run
# in glibc distroless (it needs the Alpine loader + many .so files). We instead
# use ghcr.io/tarampampam/curl, a scratch image whose /bin/curl is fully static
# (verified: runs in `scratch` with no loader), so the single copied binary runs
# unmodified in distroless/cc.
FROM ghcr.io/tarampampam/curl:8.11.1@sha256:8f09f048304280e0e50cc82a1f4ead45971e6e0f260011ab143576e7bf982493 AS curlbin

# ---- Stage 2: runtime ----
# Distroless CC base: provides the minimal glibc runtime the binary needs,
# no shell, runs as the built-in nonroot user.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

# Static curl lives at /bin/curl in the tarampampam image.
COPY --from=curlbin /bin/curl /usr/local/bin/curl

# Workspace builds emit artifacts to the WORKSPACE-ROOT target dir
# (/app/target/release/), so the bin path is unchanged from the pre-workspace
# single-crate layout — only its inputs (the workspace manifests) moved.
COPY --from=builder /app/target/release/ory-console-backend /usr/local/bin/ory-console-backend

# Documented default; overridable via env at runtime (Plan 04).
ENV BACKEND_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

USER nonroot

ENTRYPOINT ["/usr/local/bin/ory-console-backend"]

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

# SQLX_OFFLINE: the sqlx `query!`/`query_as!` macros verify SQL at compile time
# against a live DB unless offline metadata is present. The build stage has NO
# database, so we force offline mode and ship the committed `.sqlx` metadata
# (Pitfall 2). Set BEFORE any cargo build so both invocations honor it.
ENV SQLX_OFFLINE=true

# Pre-cache dependencies: copy the manifest AND the committed lockfile, create a
# dummy source, and build so the dependency layer is reused when only src/ changes.
# --locked: resolve EXACTLY the versions pinned in Cargo.lock (CR-04). Without the
# lockfile + --locked the build resolves transitive versions fresh from the
# Cargo.toml ranges, defeating supply-chain reproducibility (INFRA-04).
# The crate now has BOTH a lib and a bin target, so the dep-cache stub must
# provide a placeholder for each (an empty lib.rs + a dummy main.rs) or cargo
# fails target resolution before any dependency is built.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo '// dependency cache build' > src/lib.rs \
    && echo 'fn main() { println!("dependency cache build"); }' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Copy the committed sqlx offline metadata and the migrations BEFORE the real
# build so the query macros resolve with no DB, and `sqlx::migrate!()` finds the
# embedded migration source.
COPY .sqlx ./.sqlx
COPY migrations ./migrations

# Now copy real sources and build the actual binary (still --locked, offline).
COPY src ./src
# Phase 4 (config-edit) embeds the four Ory service config schemas + the five
# `ory://` sub-schemas at compile time via `include_str!("../../config/schemas/…")`
# (resolves to /app/config/schemas/…). They MUST be present before the real
# build or the lib fails to compile (os error 2: no such file). The dep-cache
# stub above does not need them (it builds an empty lib.rs).
COPY config ./config
# Bust the cached dummy artifacts so BOTH the real lib and bin are recompiled
# (the bin depends on the lib crate, so a stale stub lib.rs would break it).
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked

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

COPY --from=builder /app/target/release/ory-console-backend /usr/local/bin/ory-console-backend

# Documented default; overridable via env at runtime (Plan 04).
ENV BACKEND_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

USER nonroot

ENTRYPOINT ["/usr/local/bin/ory-console-backend"]

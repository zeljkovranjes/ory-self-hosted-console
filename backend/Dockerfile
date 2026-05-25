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
# salvo 0.93 (and its time/* transitive deps) require rustc >= 1.92, so the
# builder toolchain is pinned to 1.92 (rust:1.85 fails to compile salvo_core).
FROM rust:1.92-slim-bookworm AS builder

WORKDIR /app

# Pre-cache dependencies: copy the manifest AND the committed lockfile, create a
# dummy source, and build so the dependency layer is reused when only src/ changes.
# --locked: resolve EXACTLY the versions pinned in Cargo.lock (CR-04). Without the
# lockfile + --locked the build resolves transitive versions fresh from the
# Cargo.toml ranges, defeating supply-chain reproducibility (INFRA-04).
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() { println!("dependency cache build"); }' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Now copy real sources and build the actual binary (still --locked).
COPY src ./src
# Bust the cached dummy-main artifact so the real main.rs is compiled.
RUN touch src/main.rs \
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

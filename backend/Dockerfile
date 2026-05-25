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
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app

# Pre-cache dependencies: copy only the manifest, create a dummy source, and
# build so the dependency layer is reused when only src/ changes.
COPY Cargo.toml ./
RUN mkdir -p src \
    && echo 'fn main() { println!("dependency cache build"); }' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Now copy real sources and build the actual binary.
COPY src ./src
# Bust the cached dummy-main artifact so the real main.rs is compiled.
RUN touch src/main.rs \
    && cargo build --release

# ---- Stage 2: runtime ----
# Distroless CC base: provides the minimal glibc runtime the binary needs,
# no shell, runs as the built-in nonroot user.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=builder /app/target/release/ory-console-backend /usr/local/bin/ory-console-backend

# Documented default; overridable via env at runtime (Plan 04).
ENV BACKEND_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

USER nonroot

ENTRYPOINT ["/usr/local/bin/ory-console-backend"]

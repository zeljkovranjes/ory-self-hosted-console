# syntax=docker/dockerfile:1
#
# Multi-stage build for the OPTIONAL Ory Console operator CLI (`console-cli`).
#
# This is a SEPARATE image from backend/Dockerfile by design (LOCKED constraint):
# the backend runtime image must stay lean and carry NO clap/CLI code, so the CLI
# is built into its own tiny image and run via `docker compose run --rm cli ...`.
#
# Build context is the REPO ROOT (same as the backend) because a `--locked` build
# needs the workspace-root Cargo.toml + the single root Cargo.lock + the
# console-core crate the cli depends on. Only `-p ory-console-cli` is built.
#
# FEATURE POSTURE (T-19-SC / no-second-writer): the DEFAULT build does NOT enable
# `offline-admin`, so the image carries NO sqlx and NO DB writer — the ONLINE
# commands are pure HTTP clients of the backend routes (never a second writer).
# An operator who explicitly wants the offline DB-direct admin path can rebuild
# with `--features offline-admin` (documented in README); the shipped image does
# not.

# ---- Stage 1: builder ----
# Same toolchain floor as the backend (sqlx 0.9 / salvo 0.93 raise rustc; the cli
# itself only needs clap+reqwest, but the workspace resolves under one toolchain).
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app

# WORKSPACE LAYOUT (Phase 19): repo-root context. Copy the workspace manifests +
# the committed lockfile, create dummy sources for EVERY workspace member cargo
# resolves (the root resolves ALL members even when building only the cli), and
# build only `-p ory-console-cli` so the dependency layer is cached when only
# cli/src changes. --locked pins EXACTLY the versions in Cargo.lock (CR-04).
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml ./backend/Cargo.toml
COPY console-core/Cargo.toml ./console-core/Cargo.toml
COPY cli/Cargo.toml ./cli/Cargo.toml
RUN mkdir -p backend/src console-core/src cli/src \
    && echo '// dependency cache build' > backend/src/lib.rs \
    && echo 'fn main() { println!("dependency cache build"); }' > backend/src/main.rs \
    && echo '// dependency cache build' > console-core/src/lib.rs \
    && echo '// dependency cache build' > cli/src/lib.rs \
    && echo 'fn main() {}' > cli/src/main.rs \
    && cargo build --release --locked -p ory-console-cli \
    && rm -rf backend/src console-core/src cli/src

# Real sources for the cli + its console-core dep, then the real build. The
# backend crate is NOT built here (`-p ory-console-cli` only), so its source is
# never copied — keeping this image to the cli + console-core graph.
COPY console-core/src ./console-core/src
COPY cli/src ./cli/src
# Bust the cached dummy artifacts so the real cli bin + lib (and console-core)
# recompile.
RUN touch cli/src/lib.rs cli/src/main.rs console-core/src/lib.rs \
    && cargo build --release --locked -p ory-console-cli

# ---- Stage 2: runtime ----
# Distroless CC base: minimal glibc runtime, no shell, no package manager, runs
# as the built-in nonroot user. The cli image carries ONLY the cli binary; it has
# NO Docker socket, NO host port, and (default features) NO sqlx/DB writer.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /work

# Workspace builds emit to the workspace-root target dir; the bin name is
# `ory-console` (lib `console_cli`), per 19-03-SUMMARY.
COPY --from=builder /app/target/release/ory-console /usr/local/bin/ory-console

USER nonroot

# No ENTRYPOINT process loop — the cli is a one-shot invoked as
# `docker compose run --rm cli <subcommand>`. ENTRYPOINT is the binary so the
# compose `command:`/run args are the cli subcommand+flags.
ENTRYPOINT ["/usr/local/bin/ory-console"]

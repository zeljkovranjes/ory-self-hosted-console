# syntax=docker/dockerfile:1
#
# Thin wrapper that vendors a single statically-linked curl binary into an Ory
# distroless image so the SERVICE CONTAINER ITSELF can carry an in-image
# HEALTHCHECK (no shell, no package manager — distroless hardening preserved).
#
# WHY: the Ory `-distroless` images (gcr.io/distroless/static) ship no shell and
# no curl, and — unlike Kratos (`kratos remote status`) — Hydra has no in-image
# health subcommand. The Phase 1 acceptance harness asserts each long-lived
# service CONTAINER reports `healthy` (`assert_healthy hydra|keto|oathkeeper`),
# which requires the healthcheck to live on the service container, not on a
# separate sidecar. We therefore copy a static curl (from ghcr.io/tarampampam/curl,
# whose /bin/curl runs in `scratch` with no loader) and let docker-compose define
# the per-service HEALTHCHECK against the service's own /health endpoint over
# loopback. One static binary, no extra runtime surface.
#
# BASE_IMAGE is passed per service (oryd/hydra|keto|oathkeeper:v26.2.0-distroless).
# The exact tag pins live in docker-compose.yml; this Dockerfile only layers curl.

ARG BASE_IMAGE

FROM ghcr.io/tarampampam/curl:8.11.1@sha256:8f09f048304280e0e50cc82a1f4ead45971e6e0f260011ab143576e7bf982493 AS curlbin

FROM ${BASE_IMAGE}
# Static curl — runs unmodified on distroless/static (verified: no loader needed).
COPY --from=curlbin /bin/curl /usr/local/bin/curl

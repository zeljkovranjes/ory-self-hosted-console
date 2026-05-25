# syntax=docker/dockerfile:1
#
# Multi-stage build for the Ory Console frontend skeleton (Next.js 16 standalone).
#
# Stage 1 (deps):    install node_modules from the lockfile only (cache-friendly).
# Stage 2 (builder): `next build` -> emits .next/standalone (self-contained server).
# Stage 3 (runtime): minimal node image carrying only the standalone output +
#                    static assets, running as a non-root user on port 3000.
# No secrets enter any layer (T-02-secrets-in-image); runtime config via env.

ARG NODE_VERSION=24-slim

# ---- Stage 1: dependencies ----
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# The package.json `postinstall` hook runs `node scripts/copy-monaco.mjs` (it
# syncs monaco-editor/min/vs -> public/monaco/vs so the editor loads same-origin,
# never from a CDN — FE-04 / MONACO.md). npm runs it after install, so the script
# MUST be present in this layer or `npm ci` exits 1. Copy it before install.
COPY scripts ./scripts
# Use a clean, reproducible install when a lockfile exists; fall back to install otherwise.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# ---- Stage 2: builder ----
FROM node:${NODE_VERSION} AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ---- Stage 3: runtime ----
FROM node:${NODE_VERSION} AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Run as the built-in non-root `node` user.
USER node

# Standalone output: server.js + a pruned node_modules. Copy static + public too.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

EXPOSE 3000

CMD ["node", "server.js"]

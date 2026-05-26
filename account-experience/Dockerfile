# syntax=docker/dockerfile:1
#
# Multi-stage build for the Account Experience (AX) Next.js 16 service.
# Cloned from frontend/Dockerfile, MINUS the Monaco postinstall copy step (the AX
# has no Monaco editor). Standalone output; non-root; port 3000; zero CDN egress
# (the font is a vendored local woff2 under public/fonts/, the Elements theme CSS
# is a package import — no remote fetch at build or runtime).
#
# Stage 1 (deps):    install node_modules from the lockfile only (cache-friendly).
# Stage 2 (builder): `next build` -> emits .next/standalone (self-contained server).
# Stage 3 (runtime): minimal node image carrying only the standalone output +
#                    static + public assets, running as a non-root user on port 3000.
# No secrets enter any layer; runtime config (ORY_SDK_URL) via env.

ARG NODE_VERSION=24-slim

# ---- Stage 1: dependencies ----
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
# Clean, reproducible install from the committed lockfile. No postinstall hook
# (unlike frontend/, which copies monaco) — AX has no such step.
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

# Multi-stage build producing two targets: `gateway` and `web`.
FROM node:20-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
# nmap enables deep fingerprinting; the engine still works without it.
RUN apt-get update && apt-get install -y --no-install-recommends nmap iproute2 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app

FROM base AS deps
COPY pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages ./packages
COPY services ./services
COPY apps ./apps
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @netscanner/inventory db:generate

# --- Gateway: runs all backend services in one process ---
FROM deps AS gateway
EXPOSE 4000
CMD ["sh", "-c", "pnpm --filter @netscanner/inventory db:push && pnpm --filter @netscanner/gateway start"]

# --- Web: Next.js dashboard ---
FROM deps AS web
RUN pnpm --filter @netscanner/web build
EXPOSE 3000
CMD ["pnpm", "--filter", "@netscanner/web", "start"]

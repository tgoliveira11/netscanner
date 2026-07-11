FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iproute2 iputils-ping arp-scan ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./
COPY packages ./packages
COPY services ./services
COPY apps/web ./apps/web
COPY scripts ./scripts

RUN pnpm install --frozen-lockfile
RUN pnpm --filter @netscanner/inventory db:generate
ENV BUILD_STATIC=1
RUN pnpm --filter @netscanner/web build || true

RUN mkdir -p /var/lib/netscanner
ENV NETSCANNER_HOME=/var/lib/netscanner
ENV NODE_ENV=production
ENV GATEWAY_HOST=0.0.0.0
ENV GATEWAY_PORT=4000
ENV CLUSTER_ENABLED=true
ENV CLUSTER_DEDICATED=true
ENV CLUSTER_PREFER_LEADER=true
ENV MDNS_ENABLED=true

EXPOSE 4000/tcp 4010/udp
WORKDIR /app/services/gateway
CMD ["pnpm", "exec", "tsx", "src/main.ts"]

FROM node:22-bookworm-slim
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/contracts ./packages/contracts
COPY packages/logger ./packages/logger
COPY packages/config ./packages/config
COPY services/cloud ./services/cloud
RUN pnpm install --frozen-lockfile --filter @netscanner/cloud...
WORKDIR /app/services/cloud
ENV CLOUD_PORT=8080
ENV CLOUD_DATA_DIR=/data
EXPOSE 8080
CMD ["pnpm", "exec", "tsx", "src/main.ts"]

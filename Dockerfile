# ---------- Builder stage ----------
FROM oven/bun:1.3.5-alpine AS builder

WORKDIR /app

# Copy lockfiles & package.json
COPY package*.json ./
COPY bun.lockb* ./
COPY yarn.lock* ./
COPY pnpm-lock.yaml* ./

# Install dependencies (cached)
RUN --mount=type=cache,target=/root/.bun bun install

# Copy source
COPY . .

# Build app (RSBuild output -> dist)
RUN bun run build


# ---------- Production stage ----------
FROM oven/bun:1.3.5-alpine AS production

WORKDIR /app

# Copy built files
COPY --from=builder /app/public ./public
COPY --from=builder /app/main ./main
ENV NODE_ENV=production
# Expose port
EXPOSE 3000

# Optional health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/ || exit 1

# Run Bun with fallback install (auto resolves missing deps)
CMD [ "bun", "--bun", "main" ]
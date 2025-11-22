# Backstage Dockerfile
FROM node:18-bookworm-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 g++ build-essential && \
    yarn config set python /usr/bin/python3 && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy root package files
COPY package.json yarn.lock ./
COPY .yarnrc.yml ./
COPY .yarn ./.yarn

# Copy all workspace packages
COPY packages ./packages
COPY plugins ./plugins

# Install dependencies
RUN yarn install --frozen-lockfile

# Build backend
RUN yarn build:backend

# Production stage
FROM node:18-bookworm-slim

WORKDIR /app

# Copy built application
COPY --from=0 /app/node_modules ./node_modules
COPY --from=0 /app/packages ./packages
COPY --from=0 /app/plugins ./plugins
COPY --from=0 /app/package.json ./package.json
COPY --from=0 /app/yarn.lock ./yarn.lock

# Expose port
EXPOSE 7007

# Start the app
CMD ["node", "packages/backend", "--config", "app-config.production.yaml"]

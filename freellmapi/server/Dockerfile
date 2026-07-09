FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy root package.json and lockfile
COPY package.json package-lock.json ./

# Copy workspace packages to install dependencies first (for caching)
COPY server/package.json server/
COPY client/package.json client/
COPY shared/package.json shared/

# Install dependencies using npm ci for deterministic builds
RUN npm ci

# Copy the rest of the monorepo source code
COPY . .

# Build both server and client (if needed) or just the server
RUN npm run build

# Create data directory with appropriate permissions for SQLite
RUN mkdir -p /app/server/data

# Expose port
EXPOSE 3001

# Start the server
CMD ["node", "server/dist/index.js"]

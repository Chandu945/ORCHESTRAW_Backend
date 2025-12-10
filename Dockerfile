# --- STAGE 1: BUILD ---
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files and install ALL dependencies (including dev deps for building)
COPY package*.json ./
COPY prisma ./prisma/
COPY prisma.config.ts ./

ARG DATABASE_URL="postgresql://postgres:password@postgres:5432/auth_db?schema=public"
ENV DATABASE_URL=${DATABASE_URL}

# Install dependencies
RUN npm install

# Generate Prisma Client
RUN npx prisma generate

# Copy source code
COPY . .

# Build the application
RUN npm run build

# --- STAGE 2: PRODUCTION RUNNER ---
FROM node:22-alpine

WORKDIR /app

# Copy only necessary files from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./

# Expose the port
EXPOSE 8080

# Command to start the app
# We migrate the DB first, then start the app
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/src/main.js"]


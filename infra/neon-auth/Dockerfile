# vibe-neon-auth: Neon-Auth-compatible auth service (self-hosted Better Auth).
# Build:  docker build -t vibe-neon-auth:v1 infra/neon-auth
# One container per project that chose auth_backend=neon-auth; config via env
# (see server.mjs header). No secrets are baked into the image.
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.mjs verify-jwt.mjs ./
USER node
EXPOSE 3000
CMD ["node", "server.mjs"]

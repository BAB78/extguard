FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
RUN npm prune --omit=dev

FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN groupadd --system --gid 1001 extguard \
    && useradd --system --uid 1001 --gid extguard --home-dir /app extguard
COPY --from=build --chown=extguard:extguard /app/package.json /app/package-lock.json ./
COPY --from=build --chown=extguard:extguard /app/node_modules ./node_modules
COPY --from=build --chown=extguard:extguard /app/dist ./dist
COPY --chown=extguard:extguard migrations ./migrations
USER extguard
EXPOSE 3000
CMD ["sh", "-c", "node dist/migrate.js && exec node dist/server.js"]

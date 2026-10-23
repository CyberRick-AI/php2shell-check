# Self-host PHP2Shell Check in a container. Zero npm dependencies, so nothing to install.
#   docker compose up -d          (see compose.yaml)
#   docker build -t php2shell-check . && docker run --rm -p 127.0.0.1:3000:3000 php2shell-check
FROM node:22-alpine
WORKDIR /app
COPY package.json server.js local-audit.js ./
COPY src ./src
COPY advisories ./advisories
COPY public ./public
# Files stay root-owned (read-only for the app user); make sure they are world-readable whatever the host perms were.
RUN chmod -R a+rX /app
ENV HOST=0.0.0.0 PORT=3000 IN_DOCKER=1 NODE_ENV=production
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1
CMD ["node", "server.js"]

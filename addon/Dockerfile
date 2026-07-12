ARG BUILD_FROM
FROM node:22.17.1-alpine3.22 AS build
WORKDIR /build
RUN corepack enable && corepack prepare pnpm@11.7.0 --activate
COPY app/package.json app/pnpm-lock.yaml app/pnpm-workspace.yaml app/tsconfig.json app/tsconfig.build.json ./
COPY app/src ./src
RUN pnpm install --frozen-lockfile && pnpm build && pnpm prune --prod

FROM ${BUILD_FROM}
RUN apk add --no-cache nodejs openssl
WORKDIR /app
COPY --from=build build/dist ./dist
COPY --from=build build/node_modules ./node_modules
COPY --from=build build/package.json ./package.json
COPY run.sh /run.sh
RUN chmod 0755 /run.sh && mkdir -p /data/tls && chmod 0700 /data/tls
CMD ["/run.sh"]

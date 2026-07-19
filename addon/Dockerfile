ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base:3.22@sha256:b530091383543737310fd0b3512123de3e3b5165f221f244d0171b858528d963
# amd64 development override: --build-arg NODE_BUILD_FROM=node:22.17.1-alpine3.22@sha256:99351363debf40f3495cb7fc657a777334c3b21143e594dbfcc7de187439633c
ARG NODE_BUILD_FROM=node:22.17.1-alpine3.22@sha256:5539840ce9d013fa13e3b9814c9353024be7ac75aca5db6d039504a56c04ea59
FROM ${NODE_BUILD_FROM} AS build
WORKDIR /build
RUN apk add --no-cache \
    build-base=0.5-r3 \
    gcc=14.2.0-r6 \
    binutils=2.44-r3 \
    file=5.46-r2 \
    linux-headers=6.14.2-r0 \
    musl-dev=1.2.5-r12
RUN corepack enable && corepack prepare pnpm@11.7.0 --activate
COPY app/package.json app/pnpm-lock.yaml app/pnpm-workspace.yaml app/tsconfig.json app/tsconfig.build.json ./
COPY app/src ./src
RUN pnpm install --frozen-lockfile && pnpm build && pnpm prune --prod
ARG NATIVE_CFLAGS="-std=c11 -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Werror -Wformat=2 -Wformat-security"
ARG NATIVE_LDFLAGS="-pie -Wl,-z,relro,-z,now,-z,noexecstack"
RUN set -eux; \
    mkdir -p /build/native; \
    cc ${NATIVE_CFLAGS} src/security/native/openat2-read.c ${NATIVE_LDFLAGS} -o /build/native/openat2-read; \
    cc ${NATIVE_CFLAGS} src/repository/native/openat2-list.c ${NATIVE_LDFLAGS} -o /build/native/openat2-list; \
    cc ${NATIVE_CFLAGS} src/git/native/git-broker.c ${NATIVE_LDFLAGS} -o /build/native/git-broker; \
    file /build/native/openat2-read /build/native/openat2-list /build/native/git-broker

FROM ${BUILD_FROM}
RUN apk add --no-cache git=2.49.1-r0 nodejs=22.23.0-r0 openssl=3.5.7-r0
WORKDIR /app
COPY --from=build build/dist ./dist
COPY --from=build build/node_modules ./node_modules
COPY --from=build build/package.json ./package.json
COPY --from=build --chown=0:0 --chmod=0555 /build/native/ /app/native/
COPY run.sh /run.sh
RUN chmod 0755 /run.sh && mkdir -p /data/tls && chmod 0700 /data/tls
CMD ["/run.sh"]

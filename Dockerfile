# syntax=docker/dockerfile:1
# Base images are pinned by tag and digest so rebuilds are reproducible;
# bump them deliberately (e.g. via Dependabot's docker ecosystem).

# Builder stage: compile the txwatch binary
FROM rust:1.99.1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS builder
WORKDIR /build
# .dockerignore excludes .git/, so build.rs cannot run `git rev-parse` here.
# Pass the SHA and timestamp in as build args so `txwatch --version` reports
# the real commit and a reproducible build time instead of "(unknown built ...)".
ARG TXWATCH_GIT_SHA=unknown
ARG SOURCE_DATE_EPOCH
# Features compiled into the binary. Defaults to `metrics` so published images
# expose --metrics-addr, /healthz and /readyz; pass --build-arg FEATURES= to
# build the minimal image.
ARG FEATURES=metrics
ENV TXWATCH_GIT_SHA=${TXWATCH_GIT_SHA} \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# reqwest's default TLS is rustls with the aws-lc-rs crypto provider (no
# OpenSSL); its C sources need a C toolchain and cmake to build against musl.
RUN apk add --no-cache musl-dev build-base cmake perl
COPY . .
# --locked: build exactly the audited Cargo.lock that cargo-deny/cargo-audit check.
# The cache mounts keep downloaded crates and compiled dependencies between
# builds, so a source change only recompiles the workspace crates.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p txwatch --features "${FEATURES}" && \
    cp target/release/txwatch /usr/local/bin/txwatch

# Runtime stage: minimal image with only the binary
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# rustls-platform-verifier loads trust roots from the system CA store.
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 txwatch && \
    adduser -S -D -H -u 10001 -G txwatch txwatch && \
    mkdir /data && chown txwatch:txwatch /data
COPY --from=builder /usr/local/bin/txwatch /usr/local/bin/txwatch
# Mount your config here, or point TXWATCH_CONFIG / --config elsewhere.
ENV TXWATCH_CONFIG=/config/txwatch.toml

# Run unprivileged. /data is the writable working directory: point
# cursor_file there (e.g. cursor_file = "/data/cursors.json") and mount the
# config read-only (e.g. -v ./txwatch.toml:/config/txwatch.toml:ro).
USER txwatch
WORKDIR /data

# The default image is built with `--features metrics`, so /healthz is served
# once the process runs as `watch --metrics-addr ...` (e.g. 0.0.0.0:9090).
# busybox wget ships with alpine, so no extra package is needed. Images built
# with `--build-arg FEATURES=` (no metrics) never listen on 9090 and will
# report unhealthy; override or disable the check for those.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["txwatch"]

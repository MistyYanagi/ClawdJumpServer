# syntax=docker/dockerfile:1
#
# ClawdJumpServer bastion server (cjs-server) container image.
#
#   docker build -t cjs-server .
#   docker run --rm -v cjs-data:/var/lib/cjs-server cjs-server init --hostname jump.example.com
#   docker run -d --name cjs -p 8443:8443 -v cjs-data:/var/lib/cjs-server cjs-server
#
# See docs/deployment.md for TLS certificates, the first administrators,
# pinning the audit key and backups.

# The workspace declares rust-version 1.85, but the locked dependency set
# (icu_*, time, sha2 0.11) needs 1.88; `--locked` keeps Cargo.lock as is.
ARG RUST_VERSION=1.88

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
# Every workspace member is needed to resolve the workspace.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p cjs-server --locked \
    && install -m 0755 target/release/cjs-server /usr/local/bin/cjs-server

FROM debian:bookworm-slim
# ca-certificates: outbound TLS of the egress proxy; curl: health check.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 cjs \
    && useradd --system --uid 10001 --gid cjs --home-dir /var/lib/cjs-server --shell /usr/sbin/nologin cjs \
    && install -d -o cjs -g cjs -m 0700 /var/lib/cjs-server
COPY --from=build /usr/local/bin/cjs-server /usr/local/bin/cjs-server

ENV CJS_DATA=/var/lib/cjs-server \
    CJS_LISTEN=0.0.0.0:8443
USER 10001:10001
VOLUME ["/var/lib/cjs-server"]
EXPOSE 8443

# /api/v1/openapi.json is the only unauthenticated API route. The
# certificate is usually self-signed or issued for the public name, hence -k
# (this only checks liveness). Falls back to plain HTTP for --no-tls.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsk -o /dev/null https://127.0.0.1:8443/api/v1/openapi.json \
     || curl -fs -o /dev/null http://127.0.0.1:8443/api/v1/openapi.json \
     || exit 1

ENTRYPOINT ["cjs-server"]
CMD ["run"]

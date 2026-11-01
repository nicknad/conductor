# Buildable conductor image for DAST. The scan runs the real release binary,
# the real TLS-only listener, and the real startup/trust-store path.

FROM rust:slim-bookworm AS build
WORKDIR /build
# rusqlite's bundled SQLite needs a C toolchain; the slim Rust image does
# not ship one.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin conductor \
    && mkdir -p /data /tls /etc/conductor \
    && chown -R conductor:conductor /data

COPY --from=build /build/target/release/conductor /usr/local/bin/conductor

USER conductor
ENV CONDUCTOR_CONFIG=/etc/conductor/config.json
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/conductor"]

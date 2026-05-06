# syntax=docker/dockerfile:1.7

FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN mkdir -p migrations \
    && cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /app/target/release/umamoe-ingest /usr/local/bin/umamoe-ingest

ENV HOST=0.0.0.0 \
    PORT=3003

EXPOSE 3003

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-3003}/health" >/dev/null || exit 1

USER appuser

CMD ["umamoe-ingest"]
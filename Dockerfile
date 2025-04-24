FROM lukemathwalker/cargo-chef:latest-rust-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM ghcr.io/foundry-rs/foundry:latest AS foundry

FROM chef AS app-builder
COPY . .

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil

RUN cargo build --release --all

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && \
    apt-get install -y libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=app-builder /app/target/release/blockchain-rpc-bin /usr/local/bin

LABEL org.opencontainers.image.authors="Drew Stone <drewstone329@gmail.com>"
LABEL org.opencontainers.image.description="A Tangle Blueprint for arbitrary containerized RPC hosting"
LABEL org.opencontainers.image.source="https://github.com/tangle-network/blockchain-rpc"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV RUST_LOG="gadget=info"
ENV BIND_ADDR="0.0.0.0"
ENV BIND_PORT=9632
ENV BLUEPRINT_ID=0
ENV SERVICE_ID=0
ENV CHAIN="testnet"
ENV KEYSTORE_URI="./keystore"

ENTRYPOINT ["/usr/local/bin/blockchain-rpc-bin", "run"]
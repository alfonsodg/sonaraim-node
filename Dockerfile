# Syntax: multi-stage Dockerfile for sonaraim-node
ARG RUST_IMAGE=rust:slim-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY src ./src
COPY tests ./tests

RUN cargo test --release && cargo build --release --bin sonaraim-node

FROM ${RUNTIME_IMAGE} AS runtime
RUN groupadd --gid 10001 sonaraim \
    && useradd --uid 10001 --gid sonaraim --shell /sbin/nologin --create-home sonaraim

WORKDIR /app
COPY --from=builder /app/target/release/sonaraim-node /usr/local/bin/sonaraim-node

USER sonaraim:sonaraim
ENTRYPOINT ["/usr/local/bin/sonaraim-node"]

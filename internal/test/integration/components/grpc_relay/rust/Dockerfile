FROM rust:1.87@sha256:51c04d7a2b38418ba23ecbfb373c40d3bd493dec1ddfae00ab5669527320195e AS builder

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY internal/test/integration/components/grpc_relay/relay.proto .
COPY internal/test/integration/components/grpc_relay/rust/Cargo.toml internal/test/integration/components/grpc_relay/rust/Cargo.lock ./
COPY internal/test/integration/components/grpc_relay/rust/build.rs .
COPY internal/test/integration/components/grpc_relay/rust/src ./src

RUN cargo build --locked --release

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /build/target/release/grpc-relay /grpc-relay

ENTRYPOINT ["/grpc-relay"]

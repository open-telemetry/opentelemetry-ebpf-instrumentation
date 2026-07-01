# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4 AS builder

WORKDIR /src
COPY internal/test/integration/components/custom_span_rust/Cargo.toml ./Cargo.toml
COPY internal/test/integration/components/custom_span_rust/Cargo.lock ./Cargo.lock
COPY internal/test/integration/components/custom_span_rust/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /src/target/release/custom_span_rust /custom_span_rust
EXPOSE 8398
ENTRYPOINT ["/custom_span_rust"]

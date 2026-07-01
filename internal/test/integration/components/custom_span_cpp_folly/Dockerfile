# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY internal/test/integration/components/custom_span_cpp_folly/include/ ./include/
COPY internal/test/integration/components/custom_span_cpp_folly/app.cpp ./app.cpp
# -no-pie keeps the .note.stapsdt addresses resolvable without ASLR offset
# arithmetic. -static drops the libc loader path so the binary advertises
# probes from itself.
RUN g++ -O2 -no-pie -static -std=c++17 -Iinclude -o custom_span_cpp app.cpp

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /src/custom_span_cpp /custom_span_cpp
EXPOSE 8397
ENTRYPOINT ["/custom_span_cpp"]

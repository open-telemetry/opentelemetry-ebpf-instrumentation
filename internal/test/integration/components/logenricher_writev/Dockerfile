# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM gcc:16.1.0-trixie@sha256:af4cbf4b5789035f6fad5221e1c3e2dc5c2a419b32c83640c6ef27b4af4a5854 AS builder

WORKDIR /src
COPY internal/test/integration/components/logenricher_writev/multiseg_writev.c .
RUN gcc -O2 -static -o multiseg_writev multiseg_writev.c

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /src/multiseg_writev /multiseg_writev
EXPOSE 8388
ENTRYPOINT ["/multiseg_writev"]

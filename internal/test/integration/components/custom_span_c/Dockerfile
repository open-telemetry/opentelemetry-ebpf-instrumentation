# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        systemtap-sdt-dev \
        libc6-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY internal/test/integration/components/custom_span_c/app.c .
# `-no-pie` keeps the .note.stapsdt locations resolvable without ASLR
# adjustment. Static link removes the libc dynamic-loader path so the
# binary advertises probes from the exe itself.
RUN gcc -O2 -no-pie -static -o custom_span_c app.c

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /src/custom_span_c /custom_span_c
EXPOSE 8390
ENTRYPOINT ["/custom_span_c"]

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM gcc:16.1.0-trixie@sha256:47c649664b62db94d186b16936e203bb07ab1d10a0ef860cee198e594f636757 AS builder

WORKDIR /src
COPY internal/test/integration/components/logenricher_writev/multiseg_writev.c .
RUN gcc -O2 -static -o multiseg_writev multiseg_writev.c

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

COPY --from=builder /src/multiseg_writev /multiseg_writev
EXPOSE 8388
ENTRYPOINT ["/multiseg_writev"]

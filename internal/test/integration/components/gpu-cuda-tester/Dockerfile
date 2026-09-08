# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Builds a self-contained target that exercises OBI's CUDA instrumentation with
# NO GPU and NO NVIDIA driver: a stub libcudart.so exporting the CUDA Runtime
# API symbols OBI's gpuevent uprobes attach to, plus a caller that invokes them
# in a loop with realistic arguments. OBI attaches its uprobes by symbol name to
# any mapped library whose path contains "/libcudart.so", so each call fires the
# probe and emits gpu.cuda.* metrics exactly as a real CUDA app would.
#
# Docker command must be invoked from the project root directory.
FROM gcc:14.4.0-trixie@sha256:df8990c2f53aa9ef57808e755aa8f580dd86b9b34c6233715de23e89f7e06b65 AS builder

WORKDIR /src
COPY internal/test/integration/components/gpu-cuda-tester/ .

# Build the stub shared library (unversioned SONAME so its mapped path is
# exactly ".../libcudart.so") and the caller linked against it. -O0 keeps every
# CUDA call going through the PLT so OBI's uprobes have a symbol to attach to.
RUN gcc -O0 -fPIC -shared -Wl,-soname,libcudart.so -o libcudart.so libcudart-stub.c && \
    gcc -O0 -o gpu-cuda-tester main.c -L. -lcudart -Wl,-rpath,/app

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /app
COPY --from=builder /src/libcudart.so /app/libcudart.so
COPY --from=builder /src/gpu-cuda-tester /app/gpu-cuda-tester
ENV LD_LIBRARY_PATH=/app
USER 0:0

CMD ["/app/gpu-cuda-tester"]

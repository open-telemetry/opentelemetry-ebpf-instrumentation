# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Builds a self-contained target that exercises OBI's CUDA instrumentation with
# NO GPU and NO NVIDIA driver: stub libcudart.so / libcuda.so.1 libraries
# exporting the CUDA Runtime and Driver API symbols OBI's gpuevent uprobes
# attach to, plus callers that invoke them in a loop with realistic arguments.
# OBI attaches its uprobes by symbol name to any mapped library whose path
# contains "/libcudart.so" or "/libcuda.so", so each call fires the probe and
# emits gpu.cuda.* metrics exactly as a real CUDA app would.
#
# Docker command must be invoked from the project root directory.
FROM gcc:14.4.0-trixie@sha256:df8990c2f53aa9ef57808e755aa8f580dd86b9b34c6233715de23e89f7e06b65 AS builder

WORKDIR /src
COPY internal/test/integration/components/gpu-cuda-tester/ .

# Build the stub shared libraries and the callers linked against them. The
# runtime stub uses an unversioned SONAME so its mapped path is exactly
# ".../libcudart.so"; the driver stub keeps the real "libcuda.so.1" SONAME and
# is linked through a "libcuda.so" symlink. -O0 keeps every CUDA call going
# through the PLT so OBI's uprobes have a symbol to attach to.
RUN gcc -O0 -fPIC -shared -Wl,-soname,libcudart.so -o libcudart.so libcudart-stub.c && \
    gcc -O0 -fPIC -shared -Wl,-soname,libcuda.so.1 -o libcuda.so.1 libcuda-stub.c && \
    ln -sf libcuda.so.1 libcuda.so && \
    gcc -O0 -o gpu-cuda-tester main.c -L. -lcudart -Wl,-rpath,/app && \
    gcc -O0 -o gpu-cuda-setdevice-tester setdevice_main.c -L. -lcudart -Wl,-rpath,/app && \
    gcc -O0 -o gpu-cuda-driver-tester driver_main.c -L. -lcuda -Wl,-rpath,/app && \
    gcc -O0 -o gpu-cuda-driver-ctx-tester driver_ctx_main.c -L. -lcuda -Wl,-rpath,/app

FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /app
COPY --from=builder /src/libcudart.so /app/libcudart.so
COPY --from=builder /src/libcuda.so.1 /app/libcuda.so.1
COPY --from=builder /src/gpu-cuda-tester /app/gpu-cuda-tester
COPY --from=builder /src/gpu-cuda-setdevice-tester /app/gpu-cuda-setdevice-tester
COPY --from=builder /src/gpu-cuda-driver-tester /app/gpu-cuda-driver-tester
COPY --from=builder /src/gpu-cuda-driver-ctx-tester /app/gpu-cuda-driver-ctx-tester
ENV LD_LIBRARY_PATH=/app
USER 0:0

CMD ["/app/gpu-cuda-tester"]

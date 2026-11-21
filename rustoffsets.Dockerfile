# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS toolchain

ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) cross_cc=gcc-aarch64-linux-gnu; cross_libc=libc6-dev-arm64-cross ;; \
      arm64) cross_cc=gcc-x86-64-linux-gnu; cross_libc=libc6-dev-amd64-cross ;; \
      *) echo "Unsupported build architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    apt-get update && \
    apt-get install -y --no-install-recommends python3 cmake "$cross_cc" "$cross_libc" && \
    rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh && \
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain none --no-modify-path && \
    rm /tmp/rustup-init.sh

FROM toolchain AS updater
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/rustexec/ internal/rustexec/
COPY scripts/rust-offsets/ scripts/rust-offsets/
COPY scripts/rust_context.py scripts/update-rust-offsets.py scripts/
COPY internal/test/integration/components/rustcontext/ internal/test/integration/components/rustcontext/
COPY configs/offsets/rust_versions.json configs/offsets/rust_versions.json
COPY pkg/internal/ebpf/generictracer/rust_offsets.json pkg/internal/ebpf/generictracer/rust_offsets.json

ARG TARGETARCH
# Make varies this argument to refresh release discovery without clearing cache mounts.
ARG RUST_OFFSETS_RUN
ARG RUST_OFFSETS_FLAGS
RUN --mount=type=cache,id=rust-offsets-rustup-${TARGETARCH},target=/usr/local/rustup,sharing=locked \
    --mount=type=cache,id=rust-offsets-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=rust-offsets-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=rust-offsets-go-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    --mount=type=cache,id=rust-offsets-work-${TARGETARCH},target=/work,sharing=locked \
    python3 scripts/update-rust-offsets.py --work-dir /work ${RUST_OFFSETS_FLAGS}

FROM scratch AS export
COPY --from=updater /src/configs/offsets/rust_versions.json /configs/offsets/rust_versions.json
COPY --from=updater /src/pkg/internal/ebpf/generictracer/rust_offsets.json /pkg/internal/ebpf/generictracer/rust_offsets.json

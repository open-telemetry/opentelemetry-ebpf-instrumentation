# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.25.3 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY internal/test/integration/components/ebpf-instrument/ebpf_instrument_wrapper_minimal.sh /ebpf_instrument_wrapper_minimal.sh

# Build
RUN make compile-for-coverage

# Create final image from minimal + built binary
FROM ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

COPY --from=builder /src/bin/ebpf-instrument /ebpf-instrument
# Wrap the executable in a script that waits for the processes to end
# in order to avoid issues when tearing down the container on kernels 6.14+.
# https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/781
COPY --from=builder /ebpf_instrument_wrapper_minimal.sh /ebpf_instrument_wrapper_minimal.sh
RUN chmod +x /ebpf_instrument_wrapper_minimal.sh

ENTRYPOINT [ "/ebpf_instrument_wrapper_minimal.sh" ]

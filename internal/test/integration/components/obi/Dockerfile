# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS builder

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
COPY internal/test/integration/components/obi/ebpf_instrument_wrapper_minimal.sh /ebpf_instrument_wrapper_minimal.sh

# Build
RUN make compile-for-coverage

# Create final image from minimal + built binary
FROM ubuntu@sha256:cd1dba651b3080c3686ecf4e3c4220f026b521fb76978881737d24f200828b2b

COPY --from=builder /src/bin/obi /obi
# Wrap the executable in a script that waits for the processes to end
# in order to avoid issues when tearing down the container on kernels 6.14+.
# https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/781
COPY --from=builder /ebpf_instrument_wrapper_minimal.sh /ebpf_instrument_wrapper_minimal.sh
RUN chmod +x /ebpf_instrument_wrapper_minimal.sh

ENTRYPOINT [ "/ebpf_instrument_wrapper_minimal.sh" ]

# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Download modules before copying sources, so source changes reuse the cached
# module layer instead of re-downloading everything
COPY go.mod go.sum ./
RUN go mod download

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/goabi/ internal/goabi/
COPY internal/goversion/ internal/goversion/
COPY internal/config/ internal/config/
COPY pkg/ pkg/
COPY Makefile Makefile

# Build
RUN make compile-for-coverage

# inspects OBI's BPF maps and restricts its syscalls in the integration tests
COPY internal/test/integration/components/obi/testtool/ internal/test/integration/components/obi/testtool/
RUN go build -buildvcs=false -o bin/obitesttool ./internal/test/integration/components/obi/testtool/

# Create final image from minimal + built binary
FROM ubuntu@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9

COPY --from=builder /src/bin/obi /obi
COPY --from=builder /src/bin/obitesttool /obitesttool

ENTRYPOINT [ "/obi" ]

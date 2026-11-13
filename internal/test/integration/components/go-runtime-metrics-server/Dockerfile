# Build the testserver binary
# Docker command must be invoked from the project root directory
ARG RUNTIME_METRICS_TESTSERVER_GO_IMAGE=golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1
FROM ${RUNTIME_METRICS_TESTSERVER_GO_IMAGE} AS builder

ARG TARGETARCH
ARG RUNTIME_METRICS_TESTSERVER_LDFLAGS

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/go-runtime-metrics-server/ .

# Build
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go mod download && go build -ldflags="${RUNTIME_METRICS_TESTSERVER_LDFLAGS}" -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]

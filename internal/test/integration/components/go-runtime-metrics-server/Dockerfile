# Build the testserver binary
# Docker command must be invoked from the project root directory
ARG RUNTIME_METRICS_TESTSERVER_GO_IMAGE=golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1
FROM ${RUNTIME_METRICS_TESTSERVER_GO_IMAGE} AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/go-runtime-metrics-server/ .

# Build
RUN go mod download && go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]

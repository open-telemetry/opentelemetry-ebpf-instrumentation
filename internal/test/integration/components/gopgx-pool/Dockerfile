# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gopgx-pool.go gopgx-pool.go

# Build
RUN go mod download
RUN go build -o gopgx-pool gopgx-pool.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/gopgx-pool .
USER 0:0

CMD [ "/gopgx-pool" ]

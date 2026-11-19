# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gopgx-stdlib.go gopgx-stdlib.go

# Build
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go mod download
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go build -o gopgx-stdlib gopgx-stdlib.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/gopgx-stdlib .
USER 0:0

CMD [ "/gopgx-stdlib" ]

# Build the testserver binary
# Docker command must be invoked from the projec root directory
# Make sure that the Go version here is a minor number less than in the Dockerfile_latest file
# in this same folder.
# This way we make sure that we support any internal compiler changes in newer Go versions
FROM golang:1.25.9@sha256:8a7adc288b77e9b787cd2695029eb54d10ae80571b21d44fed68d067ad0a9c96 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o pingclient ./internal/test/integration/components/pingclient/pingclient.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421

WORKDIR /
COPY --from=builder /src/pingclient .
USER 0:0

CMD [ "/pingclient" ]

# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25@sha256:d7098379b7da665ab25b99795465ec320b1ca9d4addb9f77409c4827dc904211 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY test/ test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o pingclient ./test/integration/components/pingclient/pingclient.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0

WORKDIR /
COPY --from=builder /src/pingclient .
USER 0:0

CMD [ "/pingclient" ]

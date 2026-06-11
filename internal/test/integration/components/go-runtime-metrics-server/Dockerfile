# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.26.3@sha256:efaccb5b497e90df3ebe5216cc25cd9f98e73874e2d638b56e38d4a3f098c41c AS builder

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

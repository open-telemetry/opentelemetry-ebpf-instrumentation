# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.7@sha256:85c0ab0b73087fda36bf8692efe2cf67c54a06d7ca3b49c489bbff98c9954d64 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/gokafka/ .

# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver", "-brokers=kafka:9092", "-version=3.3.0" ]
FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# Copy the entire repository as it's needed for the 'replace' directive in go.mod
COPY . .

# Build the collector
WORKDIR /app/examples/otel-collector/otelcol-dev
RUN go build -o otelcol-dev .

# Final stage
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates
# Note: libc6-compat is not needed since the binary is statically linked

WORKDIR /
COPY --from=builder /app/examples/otel-collector/otelcol-dev/otelcol-dev /otelcol
COPY examples/otel-collector/config.yaml /etc/otelcol/config.yaml

# The OBI receiver might need to open ports and load eBPF programs.
# Ports used in config.yaml: 8000, 4317
EXPOSE 8000 4317

ENTRYPOINT ["/otelcol"]
CMD ["--config", "/etc/otelcol/config.yaml"]

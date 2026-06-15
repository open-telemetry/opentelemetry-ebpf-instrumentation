FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# Copy the entire repository as it's needed for the 'replace' directive in go.mod
COPY . .

# Build the collector
WORKDIR /app/examples/otel-collector/otelcol-dev
RUN go build -o otelcol-dev .

# Final stage
FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
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

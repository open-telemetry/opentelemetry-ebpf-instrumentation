FROM golang:1.25.6-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# Copy the entire repository as it's needed for the 'replace' directive in go.mod
COPY . .

# Build the collector
WORKDIR /app/examples/otel-collector/otelcol-dev
RUN go build -o otelcol-dev .

# Final stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates

WORKDIR /
COPY --from=builder /app/examples/otel-collector/otelcol-dev/otelcol-dev /otelcol
COPY examples/otel-collector/config.yaml /etc/otelcol/config.yaml

# The OBI receiver might need to open ports and load eBPF programs.
# Ports used in config.yaml: 8000, 4317
EXPOSE 8000 4317

ENTRYPOINT ["/otelcol"]
CMD ["--config", "/etc/otelcol/config.yaml"]

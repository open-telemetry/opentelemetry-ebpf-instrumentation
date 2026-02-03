FROM golang:1.25.6-alpine@sha256:98e6cffc31ccc44c7c15d83df1d69891efee8115a5bb7ede2bf30a38af3e3c92 AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# Copy the entire repository as it's needed for the 'replace' directive in go.mod
COPY . .

# Build the collector
WORKDIR /app/examples/otel-collector/otelcol-dev
RUN go build -o otelcol-dev .

# Final stage
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
RUN apk add --no-cache ca-certificates

WORKDIR /
COPY --from=builder /app/examples/otel-collector/otelcol-dev/otelcol-dev /otelcol
COPY examples/otel-collector/config.yaml /etc/otelcol/config.yaml

# The OBI receiver might need to open ports and load eBPF programs.
# Ports used in config.yaml: 8000, 4317
EXPOSE 8000 4317

ENTRYPOINT ["/otelcol"]
CMD ["--config", "/etc/otelcol/config.yaml"]

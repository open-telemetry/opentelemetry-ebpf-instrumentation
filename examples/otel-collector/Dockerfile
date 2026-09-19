FROM golang:1.27.1-alpine@sha256:4cb7ac979db5fcc41cae44b2227ba5ab8a51e8807f40d9ba4dee20a0ad960b5b AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# Copy the entire repository as it's needed for the 'replace' directive in go.mod
COPY . .

# Build the collector
WORKDIR /app/examples/otel-collector/otelcol-dev
RUN go build -o otelcol-dev .

# Final stage
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
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

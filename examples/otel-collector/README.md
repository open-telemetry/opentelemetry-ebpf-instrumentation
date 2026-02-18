# OBI As OpenTelemetry Collector Receiver Example

This example demonstrates how to build and run the OpenTelemetry Collector with OBI as a receiver component for zero-code eBPF instrumentation.

## Prerequisites

- Go 1.25 or later
- [OTel Collector Builder (`ocb`)](https://opentelemetry.io/docs/collector/extend/ocb/) installed
- Docker (for generating eBPF files) or a C compiler, clang, and eBPF headers
- Linux system with elevated privileges (sudo) to run the collector

## Quick Start

1. Generate eBPF files (required for OBI):

   ```bash
   cd ../..
   make docker-generate
   # or if you have build tools installed locally:
   # make generate
   cd examples/otel-collector
   ```

2. Generate the collector distribution with the OBI receiver using OCB:

   ```bash
   ocb --config ./builder-config.yaml
   ```

   This creates a custom collector binary in `./otelcol-dev/otelcol-dev`.

3. Run the collector with elevated privileges:

   ```bash
   pushd otelcol-dev
   sudo go run . --config ../config.yaml
   popd
   ```

The collector requires `sudo` to attach eBPF probes to processes.

## Testing the Collector

Once the collector is running, you can generate some test traces:

1. In a new terminal, start a simple HTTP server:

   ```bash
   python3 -m http.server 8000
   ```

2. Make an HTTP request to generate tracing data:

   ```bash
   curl http://localhost:8000
   ```

3. Check the collector logs for received traces. The debug exporter will print traces to the logs:

   ```
   2026-01-05T23:18:08.379+0200    info    ResourceSpans #0
   Resource SchemaURL: 
   Resource attributes:
        -> service.name: Str(python3.12)
        -> telemetry.sdk.language: Str(python)
        -> telemetry.sdk.name: Str(opentelemetry-ebpf-instrumentation)
        -> telemetry.sdk.version: Str(unset)
        -> host.name: Str(lima-coralogix-vm-24)
        -> host.id: Str(a998876e9a2642d8a1a9b8a0030c786e)
        -> os.type: Str(linux)
        -> service.instance.id: Str(lima-coralogix-vm-24:295419)
        -> otel.scope.name: Str(go.opentelemetry.io/obi)
   ScopeSpans #0
   ScopeSpans SchemaURL: 
   InstrumentationScope  
   Span #0
       Trace ID       : 8c28f3b6817dfc2e629612dc39952fef
       Parent ID      : 9adcce7d3501ea15
       ID             : 511fc600e31636db
       Name           : in queue
       Kind           : Internal
       Start time     : 2026-01-05 21:17:58.465955692 +0000 UTC
       End time       : 2026-01-05 21:17:58.468910267 +0000 UTC
       Status code    : Unset
       Status message : 
       DroppedAttributesCount: 0
       DroppedEventsCount: 0
       DroppedLinksCount: 0
   Span #1
       Trace ID       : 8c28f3b6817dfc2e629612dc39952fef
       Parent ID      : 9adcce7d3501ea15
       ID             : 302aa18decfd48f3
       Name           : processing
       Kind           : Internal
       Start time     : 2026-01-05 21:17:58.468910267 +0000 UTC
       End time       : 2026-01-05 21:17:58.496701454 +0000 UTC
       Status code    : Unset
       Status message : 
       DroppedAttributesCount: 0
       DroppedEventsCount: 0
       DroppedLinksCount: 0
   Span #2
       Trace ID       : 8c28f3b6817dfc2e629612dc39952fef
       Parent ID      : 
       ID             : 9adcce7d3501ea15
       Name           : GET /
       Kind           : Server
       Start time     : 2026-01-05 21:17:58.465955692 +0000 UTC
       End time       : 2026-01-05 21:17:58.496701454 +0000 UTC
       Status code    : Unset
       Status message : 
       DroppedAttributesCount: 0
       DroppedEventsCount: 0
       DroppedLinksCount: 0
   Attributes:
        -> http.request.method: Str(GET)
        -> http.response.status_code: Int(200)
        -> url.path: Str(/)
        -> client.address: Str(127.0.0.1)
        -> server.address: Str(python3.12)
        -> server.port: Int(8000)
        -> http.request.body.size: Int(77)
        -> http.response.body.size: Int(11187)
        -> http.route: Str(/)
           {"resource": {"service.instance.id": "7e92d7ee-5866-4d53-8025-75c0d250e8cf", "service.name": "otelcol-dev", "service.version": ""}, "otelcol.component.id": "debug", "otelcol.component.kind": "exporter", "otelcol.signal": "traces"}
   
   ```

## Configuration

The `config.yaml` file defines:

- **OBI receiver**: Listens on port 8000 for HTTP traffic and automatically instruments services
- **OTLP receiver**: Accepts spans from manually instrumented applications
- **Batch processor**: Groups spans for efficient export
- **Debug exporter**: Prints spans to logs (useful for debugging)
- **OTLP exporter**: Sends spans to a Jaeger backend (requires Jaeger to be running)

You can modify `config.yaml` to:

- Add more exporters for different backends
- Configure service discovery filters
- Enable additional OBI features (metrics, logs)

## Troubleshooting

### Error: "Required system capabilities not present"

The collector requires elevated privileges to attach eBPF probes. You have two options:

#### Option 1: Run with sudo (simplest)

```bash
sudo go run . --config ../config.yaml
```

#### Option 2: Grant capabilities to the binary (more secure)

Set capabilities on the compiled binary to allow it to run without sudo:

```bash
# After building with OCB
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_dac_read_search,cap_net_raw,cap_perfmon,cap_bpf,cap_checkpoint_restore=ep ./otelcol-dev/otelcol-dev

# Then run without sudo
./otelcol-dev/otelcol-dev --config ../config.yaml
```

Verify the capabilities were set:

```bash
getcap ./otelcol-dev/otelcol-dev
```

### Error: "cannot unmarshal the configuration"

Your `config.yaml` may have YAML syntax errors or reference processors/exporters that aren't in the builder config. Ensure all referenced components are defined in `builder-config.yaml`.

### No traces appearing in logs

1. Verify the collector started successfully (check for startup messages)
2. Confirm your test application is actually making HTTP requests
3. Check that the OBI receiver configuration matches your port (`8000` in this example)

## Building a Docker Image

Once you have a working collector locally, you'll likely want to deploy it to your infrastructure. Containerizing the collector makes it easy to deploy across multiple nodes or into Kubernetes clusters.

The included `Dockerfile` builds the collector from source within the container. To build and push the image to your registry:

```bash
cd ../..
make docker-generate  # Generate eBPF files first
cd examples/otel-collector

docker build -t my-registry/otelcol-obi:v0.5.0 .
docker push my-registry/otelcol-obi:v0.5.0
```

This image can then be deployed as a DaemonSet in Kubernetes, or used in any container orchestration platform.

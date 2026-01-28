# OBI As otel collector receiver

We can follow the guide from opentelemetry.io on [Running and debugging the receiver](https://opentelemetry.io/docs/collector/extend/custom-component/receiver/#running-and-debugging-the-receiver)

1. First we need to [download the otel collector builder](https://opentelemetry.io/docs/collector/extend/ocb/#step-1---install-the-builder)
2. Generate the collector distribution with the OBI receiver:

```bash
./ocb --config ./builder-config.yaml
```

1. Run the collector with the generated distribution:

```bash
pushd otelcol-dev
sudo go run . --config ../config.yaml
popd
```

1. Setup a test server on port 8000

```bash
python3 -m http.server 8000
```

1. Perform an HTTP request to generate some tracing data

```bash
curl http://localhost:8000
```

1. Check the collector logs to see the received traces

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

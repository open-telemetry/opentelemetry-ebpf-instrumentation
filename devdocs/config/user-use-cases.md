# OBI User-Centric Configuration Use Cases

Status: Draft for discussion  
Audience: OBI maintainers and contributors  
Scope: top-priority user journeys and simple user intent statements

## Top user expectation

Users expect OBI to provide useful, low-friction observability for running services (without code changes), with clear controls for scope, cost, and operational safety.

## Grouped user journeys

### Onboard and activate

1. A user wants to instrument all services running on platform `<X>`.
    - Linux hosts (amd64/arm64)
    - Kubernetes workloads
    - Collector receiver deployments
2. A user wants to get useful default telemetry quickly, without deep OBI knowledge.
3. A user wants to enable network observability in addition to application observability.

### Target and scope

1. A user wants to instrument only `<Y>` services and exclude everything else.
    - process identity (executable path, PID)
    - network identity (open ports)
    - language identity (programming language)
    - Kubernetes/container identity (metadata, labels/annotations, containers-only)
2. A user wants to combine multiple target rules to scope instrumentation and control telemetry volume/cost.
3. A user wants to avoid instrumenting services that are already instrumented.

### Export and integrate

1. A user wants to send telemetry to an OTLP backend.
2. A user wants to expose Prometheus metrics when needed.
3. A user wants to leverage Collector processing and exporting pipelines when running OBI as a receiver.

### Enrich and optimize

1. A user wants to enable Kubernetes metadata enrichment for all instrumented services.
2. A user wants to enable protocol-specific parsing only for selected sources (for example HTTP payload extraction).
3. A user wants controls to limit cardinality and data growth.

### Operate in production

1. A user wants safe production operations with clear logging, profiling, and shutdown controls.
2. A user wants troubleshooting workflows for "no data", partial data, or unexpected cardinality spikes.
3. A user wants clear visibility into effective/resolved configuration before rollout.

### Validate and migrate

1. A user wants invalid or conflicting configuration to fail fast with actionable errors.
2. A user wants to migrate from legacy config keys to the new schema with minimal manual edits.
3. A user wants stable configuration patterns across environments with minimal duplication.
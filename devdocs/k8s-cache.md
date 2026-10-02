# Kubernetes metadata cache service (`k8s-cache`)

`k8s-cache` is an optional, standalone service that centralizes the Kubernetes
informer cache shared by multiple OBI instances. Instead of every OBI pod in the
cluster opening its own watch connections against the Kubernetes API server,
they all subscribe to this service over gRPC and receive the metadata events
they need to decorate traces, flows and metrics.

The source lives under:

- Entry point: [cmd/k8s-cache/main.go](../cmd/k8s-cache/main.go)
- Server + gRPC stream: [pkg/kube/kubecache/service](../pkg/kube/kubecache/service)
- Informers (watch loop): [pkg/kube/kubecache/meta](../pkg/kube/kubecache/meta)
- Wire protocol (protobuf): [pkg/kube/kubecache/informer](../pkg/kube/kubecache/informer)
- Configuration: [pkg/kube/kubecache/config.go](../pkg/kube/kubecache/config.go)
- Internal metrics: [pkg/kube/kubecache/instrument](../pkg/kube/kubecache/instrument)
- Client (inside OBI): [pkg/kube/cache_svc_client.go](../pkg/kube/cache_svc_client.go)
- Dockerfile: [k8scache.Dockerfile](../k8scache.Dockerfile)
- Published image: `otel/opentelemetry-ebpf-k8s-cache` (also on `ghcr.io`).

## Table Of Contents

- [Summary](#summary)
- [When to use](#when-to-use)
- [How OBI communicates with the k8s-cache](#how-obi-communicates-with-the-k8s-cache)
- [How to deploy](#how-to-deploy)
- [Configuration reference](#configuration-reference)
- [Minimum RBAC permissions](#minimum-rbac-permissions)
- [Internal metrics](#internal-metrics)

## Summary

`k8s-cache` A tiny Go binary that does two things:

1. Runs Kubernetes informers (`Pod`, `Node`, `Service`) against the Kube API,
   keeping an in-memory view of the cluster metadata.
2. Exposes a gRPC streaming endpoint
   (`informer.EventStreamService/Subscribe`) that clients connect to. On
   subscription, the service replays the current snapshot and then keeps
   pushing add/update/delete events in real time. An explicit
   `SYNC_FINISHED` event marks the end of the initial replay, so the client
   knows when it is safe to start decorating telemetry.

By default the service listens for gRPC on port `50055` and can optionally
expose a pprof listener and a Prometheus `/metrics` endpoint for internal
telemetry.

## When to use

Anytime running large amount of OBI instances on the same cluster, be it large `Deployments`, running OBI as a
`DaemonSet` or running multiple OBI instances as `Sidecars`.
Centralizing the k8s metadata collection to a single source (k8s-cache) can help with:

- **Less load on the Kube API server.** Only the cache opens the long-running
  `LIST`/`WATCH` connections; OBI pods open a single gRPC stream each, which
  does not hit the API server at all.
- **Lower per-OBI memory footprint.** The cluster metadata snapshot is held
  once in the cache, not replicated on every node.
- **Faster OBI cold starts on big clusters.** OBI subscribes and receives the
  already-populated snapshot, so it does not have to wait for its own informer
  to list the whole cluster before it can start decorating.
- **Cheaper reconnects.** OBI passes the timestamp of its last event, so the
  snapshot replay on resubscribe can skip older entries. This reduces replay
  volume, but it is not a durable event log and reconnects can still replay
  entries from the same timestamp window.

If k8s cache address is not provided, OBI will initiate its own local in-process cache.
which is fine for small clusters but is exactly the scaling pattern this service exists
to avoid.

Note: As the name implies, `k8s-cache` is only useful when running OBI on a kubernetes cluster, in any other mode (
standalone,
docker) it does not make sense to use it.

## How OBI communicates with the k8s-cache

Inside OBI, the switch between "local informers" and "remote cache" is the
`attributes.kubernetes.meta_cache_address` field, also configurable via
the `OTEL_EBPF_KUBE_META_CACHE_ADDRESS` environment variable.

When set, OBI:

1. Opens a gRPC stream and calls `Subscribe` with the timestamp of the last
   event received in a previous connection (0 on first boot).
2. Blocks the rest of the pipeline until it sees `SYNC_FINISHED` or until
   `OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT` expires, so decoration does not
   start with partial metadata.
3. On disconnect, sleeps for `ReconnectInitialInterval` and retries.

The wire types are defined in
[proto/informer.proto](../proto/informer.proto). Any change to
the event schema must stay backwards-compatible with already-deployed OBI
instances that connect to a newer cache (and vice versa).

## How to deploy

### Helm

When using
the [OBI Helm chart](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-ebpf-instrumentation),
you just have to provide a non-zero value for the
`k8sCache.replicas` configuration option in `values.yaml`.

### Kubernetes

The recommended deployment pattern is a low replica `Deployment`, a `Service`
for the OBI `DaemonSet`, and a `NetworkPolicy` that limits which pods can
connect to the gRPC port. The example below assumes OBI pods have the
`instrumentation: obi` label in the same namespace. Adjust the selectors and
namespace scoping to match your OBI deployment.

Do not use this `podSelector` policy unchanged when OBI runs with
`hostNetwork: true`: network policy implementations commonly treat those
clients as node traffic instead of matching their pod labels. Use a
CNI-specific host policy, firewall rule, service-mesh mTLS policy, or another
authenticated proxy that permits OBI's node traffic before applying ingress
isolation to k8s-cache.

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: k8s-cache
spec:
  replicas: 1
  selector:
    matchLabels:
      app: k8s-cache
  template:
    metadata:
      labels:
        app: k8s-cache
    spec:
      serviceAccountName: obi # needs list/watch on pods, nodes, services
      containers:
        - name: k8s-cache
          image: otel/opentelemetry-ebpf-k8s-cache:latest
          env:
            - name: OTEL_EBPF_K8S_CACHE_PORT
              value: "50055"
          ports:
            - containerPort: 50055
              name: grpc
---
kind: Service
apiVersion: v1
metadata:
  name: k8s-cache
spec:
  selector:
    app: k8s-cache
  ports:
    - port: 50055
      name: grpc
      protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-cache-grpc-from-obi
spec:
  podSelector:
    matchLabels:
      app: k8s-cache
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              instrumentation: obi
      ports:
        - protocol: TCP
          port: 50055
```

This secured example leaves the optional internal Prometheus metrics endpoint
disabled. If you enable it on port `8999`, add a separate ingress rule that
allows only your metrics scraper to reach that port.

Then point OBI at it, either via YAML:

```yaml
attributes:
  kubernetes:
    enable: true
    meta_cache_address: k8s-cache:50055
```

or via environment variable on the OBI DaemonSet:

```yaml
env:
  - name: OTEL_EBPF_KUBE_METADATA_ENABLE
    value: "true"
  - name: OTEL_EBPF_KUBE_META_CACHE_ADDRESS
    value: "k8s-cache.default.svc:50055"
```

A single replica is usually enough: the service is stateless from the caller's
perspective and the bottleneck on large clusters is the Kube API watch, not
the fan-out to OBI clients. If you need HA, run multiple replicas behind the
same `Service` — each OBI instance connects to one of them and will reconnect
to another on failure.

By default, the k8s-cache gRPC endpoint uses plaintext gRPC without built-in
authentication or authorization. A subscriber receives the current Kubernetes
metadata snapshot and future updates, including pod, service, and node metadata
used by OBI for enrichment. Do not expose this `Service` to pods or namespaces
that are not trusted to read that metadata.

For encrypted connections, set `grpc.security_mode` on the cache service and
`attributes.kubernetes.meta_cache_grpc.security_mode` on OBI to `tls` or `mtls`.
Both sides must use the same mode. For example, with mutual TLS:

```yaml
# k8s-cache configuration
grpc:
  security_mode: mtls
  cert_file: /etc/k8s-cache/tls.crt
  key_file: /etc/k8s-cache/tls.key
  ca_file: /etc/k8s-cache/ca.crt
```

```yaml
# OBI configuration
attributes:
  kubernetes:
    meta_cache_address: k8s-cache.default.svc:50055
    meta_cache_grpc:
      security_mode: mtls
      server_name: k8s-cache.default.svc
      ca_file: /etc/obi/ca.crt
      cert_file: /etc/obi/tls.crt
      key_file: /etc/obi/tls.key
```

Mount the certificate, private key, and CA files into the corresponding pods.
The cache service certificate needs a SAN matching the client `server_name`
(or the hostname in `meta_cache_address` when `server_name` is omitted). In
`tls` mode, the cache service needs only `cert_file` and `key_file`; OBI
verifies its certificate using `ca_file` or the system trust store. In `mtls`
mode, the cache service additionally requires `ca_file` to verify client
certificates, and OBI requires its own `cert_file` and `key_file`. Restart the
cache service after rotating its certificate or CA. Network policy is still
recommended to limit which workloads can reach the endpoint. Use a dedicated
client CA for authorized OBI instances: every certificate with client-auth
usage issued by the configured CA is accepted, regardless of its subject or
SAN. mTLS here authenticates membership in that CA's trust domain, not an
individual client identity.

The same client settings are available in the v2 configuration at
`extensions.obi.enrich.enrichers.kubernetes.metadata_cache.grpc`. The service
accepts environment variables prefixed `OTEL_EBPF_K8S_CACHE_GRPC_`; OBI accepts
`OTEL_EBPF_KUBE_META_CACHE_GRPC_` (for example, `..._SECURITY_MODE` and
`..._CA_FILE`).

If your CNI does not enforce `NetworkPolicy` for the selected source pods, use
an equivalent CNI-specific host policy, firewall rule, service-mesh mTLS
policy, or another authenticated proxy in front of k8s-cache.

### Running locally for development

Compile and run the binary directly without Docker:

```bash
make compile-cache
./bin/k8s-cache --config ./my-config.yaml
```

The binary reuses your local kubeconfig (`$KUBECONFIG` or `~/.kube/config`)
when it is not running inside a cluster, which is handy when iterating on the
informer code.

## Configuration reference

Configuration is loaded in this order (later overrides earlier):

1. Defaults from `DefaultConfig` in
   [pkg/kube/kubecache/config.go](../pkg/kube/kubecache/config.go).
2. A YAML file passed via `--config` or `OTEL_EBPF_K8S_CACHE_CONFIG_PATH`.
3. Environment variables.

| YAML key                 | Env var                                                | Default        | Purpose                                                                   |
|--------------------------|--------------------------------------------------------|----------------|---------------------------------------------------------------------------|
| `log_level`              | `OTEL_EBPF_K8S_CACHE_LOG_LEVEL`                        | `info`         | `debug`/`info`/`warn`/`error`.                                            |
| `port`                   | `OTEL_EBPF_K8S_CACHE_PORT`                             | `50055`        | gRPC listen port.                                                         |
| `max_connections`        | `OTEL_EBPF_K8S_CACHE_MAX_CONNECTIONS`                  | `150`          | Per-transport HTTP/2 stream cap (wired into `grpc.MaxConcurrentStreams`). |
| `profile_port`           | `OTEL_EBPF_K8S_CACHE_PROFILE_PORT`                     | `0` (disabled) | If non-zero, starts a `net/http/pprof` listener.                          |
| `informer_resync_period` | `OTEL_EBPF_K8S_CACHE_INFORMER_RESYNC_PERIOD`           | `30m`          | Full informer resync interval. Increase to lower API load.                |
| `informer_send_timeout`  | `OTEL_EBPF_K8S_CACHE_INFORMER_SEND_TIMEOUT`            | `10s`          | Per-message send deadline before a slow subscriber connection is closed.  |
| `grpc.security_mode`     | `OTEL_EBPF_K8S_CACHE_GRPC_SECURITY_MODE`                | `insecure`     | `insecure`, `tls`, or `mtls`.                                              |
| `grpc.cert_file`         | `OTEL_EBPF_K8S_CACHE_GRPC_CERT_FILE`                    | unset          | Server certificate for `tls` and `mtls`.                                  |
| `grpc.key_file`          | `OTEL_EBPF_K8S_CACHE_GRPC_KEY_FILE`                     | unset          | Server private key for `tls` and `mtls`.                                  |
| `grpc.ca_file`           | `OTEL_EBPF_K8S_CACHE_GRPC_CA_FILE`                      | unset          | Trusted client CA, required for `mtls`.                                   |
| `internal_metrics.port`  | `OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PORT` | `0` (disabled) | If non-zero, serves Prometheus metrics.                                   |
| `internal_metrics.path`  | `OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PATH` | `/metrics`     | Metrics endpoint path.                                                    |

Also worth knowing:

- `OTEL_EBPF_K8S_CACHE_CONFIG_PATH` — alternative to the `--config` flag.
- `KUBECONFIG` — honored when running outside a cluster.

## Minimum RBAC permissions

The cache needs `list` and `watch` on the same resources OBI would otherwise
watch itself:

```yaml
rules:
  - apiGroups: [ "" ]
    resources: [ "pods", "services", "nodes" ]
    verbs: [ "list", "watch" ]
```

`services` and `nodes` are required for NetO11y and for cluster-name
discovery. If you disable those in your OBI config you can drop the
corresponding rules too.

On OpenShift, OBI can auto-detect the cluster name from the Infrastructure CR.
This requires an additional rule:

```yaml
  - apiGroups: ["config.openshift.io"]
    resources: ["infrastructures"]
    verbs: ["get"]
```

Without it, the fetcher fails gracefully and the next provider is tried.

## Internal metrics

When `OTEL_EBPF_K8S_CACHE_INTERNAL_METRICS_PROMETHEUS_PORT` is set, the
service exposes these Prometheus metrics (prefix defined by
[pkg/export/attributes/names](../pkg/export/attributes/names)):

- `*_kube_cache_informer_events_total{type=new|update|delete}` — events
  received from the Kube API.
- `*_kube_cache_connected_clients` — current number of subscribed OBI
  instances.
- `*_kube_cache_client_messages_total{status=submit|success|timeout|error}` —
  outcome of events forwarded to clients. Growing `timeout` means a slow
  subscriber hit `informer_send_timeout`; growing `error` means the stream
  failed during `Send`.
- `*_informer_receive_lag_seconds` — histogram of the delay between a Kube
  event happening and the cache forwarding it. Useful to spot informer
  backpressure.
- `*_kube_cache_internal_build_info` — build info gauge (value `1`).

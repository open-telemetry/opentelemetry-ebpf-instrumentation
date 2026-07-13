# OBI Store Demo

This example runs the Google Cloud Online Boutique application locally on
Kubernetes and instruments it with OBI through the OpenTelemetry eBPF
Instrumentation Helm chart.

The vendored application comes from
`GoogleCloudPlatform/microservices-demo` v0.10.5. The OBI-specific files live in
[`k8s`](./k8s) and provide:

- the `obi-store-demo` namespace
- the Online Boutique service manifests
- a Grafana LGTM backend for OTLP traces and metrics
- Helm values for the `opentelemetry-ebpf-instrumentation` chart

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the service topology (a Mermaid
service graph and a connection table). It is generated from the manifests by
[fix_architecture.py](./fix_architecture.py); after changing a manifest, run
`python3 examples/store-demo/fix_architecture.py` to regenerate it (CI checks
it with `--check`).

## Prerequisites

Install these tools before running the demo:

- Docker
- `kind`
- `kubectl`
- Helm

The Kubernetes flow assumes a local kind cluster. OBI runs as a privileged
DaemonSet so it can discover and instrument application processes on the node.

## Create The Cluster

```bash
export KIND_CLUSTER_NAME=obi-store-demo
kind create cluster --name "${KIND_CLUSTER_NAME}"
kubectl config use-context "kind-${KIND_CLUSTER_NAME}"
```

## Build And Load Images

Build each curated service image and load it into the kind cluster. The image
tags match the tags referenced by the Kubernetes manifests.

```bash
services=(
  "adservice:examples/store-demo/app/src/adservice"
  "cartservice:examples/store-demo/app/src/cartservice/src"
  "checkoutservice:examples/store-demo/app/src/checkoutservice"
  "currencyservice:examples/store-demo/app/src/currencyservice"
  "emailservice:examples/store-demo/app/src/emailservice"
  "frontend:examples/store-demo/app/src/frontend"
  "loadgenerator:examples/store-demo/app/src/loadgenerator"
  "paymentservice:examples/store-demo/app/src/paymentservice"
  "productcatalogservice:examples/store-demo/app/src/productcatalogservice"
  "recommendationservice:examples/store-demo/app/src/recommendationservice"
  "shippingservice:examples/store-demo/app/src/shippingservice"
)

for service_context in "${services[@]}"; do
  service="${service_context%%:*}"
  context="${service_context#*:}"
  image="obi-store-demo-${service}:local"

  docker build -t "${image}" "${context}"
  kind load docker-image "${image}" --name "${KIND_CLUSTER_NAME}"
done
```

## Deploy The Store And LGTM

Apply the Kubernetes manifests. This creates the namespace, the Online Boutique
services, the load generator, and the Grafana LGTM backend.

```bash
kubectl apply -k examples/store-demo/k8s
kubectl -n obi-store-demo wait --for=condition=Available deploy --all --timeout=5m
```

## Install OBI With Helm

Install the official OpenTelemetry eBPF Instrumentation chart with the store demo
values. The values file enables Kubernetes-aware discovery, instruments the store
deployments, and exports traces and metrics to the in-cluster LGTM service.

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm upgrade --install obi open-telemetry/opentelemetry-ebpf-instrumentation \
  --namespace obi-store-demo \
  -f examples/store-demo/k8s/03-obi-values.yaml
```

Wait for OBI to become ready:

```bash
kubectl -n obi-store-demo wait --for=condition=Ready pod \
  -l app.kubernetes.io/instance=obi \
  --timeout=120s
```

## Generate Traffic

The `loadgenerator` deployment starts sending traffic to the frontend
automatically. You can also port-forward the frontend and send a few manual
requests.

```bash
kubectl -n obi-store-demo port-forward svc/frontend 8080:80
```

In another terminal:

```bash
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/product/OLJCESPC7Z
curl http://127.0.0.1:8080/cart
```

## Validate OBI Telemetry

Run these checks after the store, LGTM, and OBI are running. They use the
Kubernetes service proxy for LGTM, so Grafana does not need to be port-forwarded.

Check the OBI Helm release and ready pod, frontend HTTP metrics with Kubernetes
deployment attributes, backend gRPC metrics, frontend traces, and backend gRPC
traces. The backend trace check accepts separate backend gRPC traces; current
OBI gRPC propagation does not guarantee a fully stitched checkout trace.

```bash
helm -n obi-store-demo list
kubectl -n obi-store-demo wait --for=condition=Ready pod \
  -l app.kubernetes.io/instance=obi \
  --timeout=120s
python3 -c "import json, subprocess; raw=subprocess.check_output(['kubectl','-n','obi-store-demo','get','--raw','/api/v1/namespaces/obi-store-demo/services/http:lgtm:3000/proxy/api/datasources/proxy/uid/prometheus/api/v1/query?query=http_server_request_duration_seconds_count'], text=True); data=json.loads(raw); assert any(item['metric'].get('service_name') == 'frontend' and item['metric'].get('k8s_deployment_name') == 'frontend' and item['metric'].get('http_route') in {'/','/product/{id}','/cart','/cart/checkout'} for item in data['data']['result'])"
python3 -c "import json, subprocess; raw=subprocess.check_output(['kubectl','-n','obi-store-demo','get','--raw','/api/v1/namespaces/obi-store-demo/services/http:lgtm:3000/proxy/api/datasources/proxy/uid/prometheus/api/v1/query?query=rpc_server_duration_seconds_count'], text=True); data=json.loads(raw); assert any(item['metric'].get('rpc_system') == 'grpc' and item['metric'].get('k8s_namespace_name') == 'obi-store-demo' and item['metric'].get('service_name') in {'checkoutservice','productcatalogservice','shippingservice','emailservice','cartservice','currencyservice','adservice'} for item in data['data']['result'])"
python3 -c "import json, subprocess; raw=subprocess.check_output(['kubectl','-n','obi-store-demo','get','--raw','/api/v1/namespaces/obi-store-demo/services/http:lgtm:3000/proxy/api/datasources/proxy/uid/tempo/api/search?tags=service.name%3Dfrontend&limit=10'], text=True); data=json.loads(raw); assert any(trace.get('rootServiceName') == 'frontend' for trace in data.get('traces', []))"
python3 -c "import json, subprocess; services={'adservice','cartservice','checkoutservice','currencyservice','emailservice','productcatalogservice','shippingservice'}; url='/api/v1/namespaces/obi-store-demo/services/http:lgtm:3000/proxy/api/datasources/proxy/uid/tempo/api/search?tags=service.name%3D{}&limit=10'; assert any(trace.get('rootServiceName') == service and trace.get('rootTraceName','').startswith('/') for service in services for trace in json.loads(subprocess.check_output(['kubectl','-n','obi-store-demo','get','--raw',url.format(service)], text=True)).get('traces', []))"
```

Check that the demo app deployments are not exporting telemetry through app SDK
OTLP settings:

```bash
python3 -c "import json, subprocess; apps={'adservice','cartservice','checkoutservice','currencyservice','emailservice','frontend','paymentservice','productcatalogservice','recommendationservice','shippingservice'}; data=json.loads(subprocess.check_output(['kubectl','-n','obi-store-demo','get','deploy','-o','json'], text=True)); bad=[]; [bad.append((dep['metadata']['name'], env.get('name'))) for dep in data['items'] if dep['metadata']['name'] in apps for container in dep['spec']['template']['spec'].get('containers', []) for env in container.get('env', []) if env.get('name','').startswith('OTEL_EXPORTER_OTLP') or env.get('name','') in {'OTEL_TRACES_EXPORTER','OTEL_METRICS_EXPORTER','OTEL_EXPORTER_OTLP_ENDPOINT'}]; assert not bad, bad"
```

## Explore Telemetry In Grafana

Port-forward Grafana from the LGTM service:

```bash
kubectl -n obi-store-demo port-forward svc/lgtm 3000:3000
```

Then open `http://localhost:3000` and sign in with `admin` / `admin`.

In Grafana Explore:

- select the traces data source to inspect requests across the store services
- select the metrics data source to inspect HTTP metrics grouped by route,
  status code, and Kubernetes workload metadata

The OBI Helm values define low-cardinality route patterns for common frontend
paths such as `/`, `/product/:product_id`, `/cart`, and `/cart/checkout`.

## Expected OBI Visibility And Current Gaps

Use these expectations when deciding whether the demo is healthy:

- Service discovery should find the store deployments listed in
  [`03-obi-values.yaml`](./k8s/03-obi-values.yaml) and attach Kubernetes
  workload metadata to their telemetry.
- Frontend HTTP traffic should produce traces and metrics for requests such as
  `/`, `/product/:product_id`, `/cart`, and `/cart/checkout`.
- Metrics should be available in Grafana for the discovered services, with HTTP
  metrics grouped by route, status code, and Kubernetes workload metadata.
- The service graph should show the frontend and the backend services OBI can
  observe from the generated traffic. Some backend edges can be missing while
  the demo is still working.
- Expect partial backend gRPC visibility. Online Boutique uses gRPC for most
  service-to-service calls, and OBI can report supported gRPC spans and metrics,
  but not every backend RPC is guaranteed to appear with a complete method name
  or matching client/server pair.
- Current gRPC propagation does not guarantee a fully stitched checkout trace.
  The trace may not continue through frontend, checkoutservice, cartservice,
  currencyservice, paymentservice, emailservice, and shippingservice. Separate
  backend gRPC traces or incomplete service-graph edges are expected OBI
  visibility gaps, not store-demo failures.

## Cleanup

```bash
helm uninstall obi --namespace obi-store-demo
kubectl delete -k examples/store-demo/k8s
kind delete cluster --name "${KIND_CLUSTER_NAME}"
```

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

## Cleanup

```bash
helm uninstall obi --namespace obi-store-demo
kubectl delete -k examples/store-demo/k8s
kind delete cluster --name "${KIND_CLUSTER_NAME}"
```

# Apache Example

This example highlights the Apache HTTP Server behaviors that OBI can observe:

- direct Apache route handling with `2xx`, `3xx`, `4xx`, and `5xx` responses
- Apache acting as a reverse proxy, including a chained proxy hop between multiple Apache processes

The scenario is framed as a small demo storefront:

- `edge-apache` is the public web edge for a shop landing page and a few user-facing routes
- `recommendations-v1` is the legacy recommendations API
- `recommendations-v2` is the next recommendations tier, which still forwards some traffic to `v1` during rollout

That keeps the Apache example aligned with the nginx example so you can compare how OBI behaves across both web servers.

You can run the example in three ways:

- Docker Compose for the fastest local setup
- Kubernetes with `kind`, manifests, and the Helm-installed OBI chart
- a dedicated Linux host or VM where Apache and OBI run directly on the host

## Topology

The example uses three Apache instances:

- `edge-apache`: serves storefront pages and proxies recommendation API calls
- `recommendations-v1`: the legacy recommendations service
- `recommendations-v2`: the newer recommendations service, which still chains some calls through `recommendations-v1`

That gives us these flows:

- direct handling: client -> `edge-apache`
- single proxy hop: client -> `edge-apache` -> `recommendations-v1`
- chained proxy hop: client -> `edge-apache` -> `recommendations-v2` -> `recommendations-v1`

The Apache route logic lives in shared vhost files under [`examples/apache/shared`](./shared). Docker Compose and the dedicated-host flow use those files directly. The Kubernetes manifests use mirrored copies under [`examples/apache/k8s/shared`](./k8s/shared) so the config stays within the kustomize tree while preserving the same route behavior.

## Routes To Exercise

Use the bundled [`generate-traffic.sh`](./generate-traffic.sh) script, or call the routes manually. By default the script runs continuously until you stop it with `Ctrl+C`, prints periodic progress updates, and exercises the full route set concurrently at mixed rates. Use `--one-shot` if you only want a single pass.

Docker Compose and Kubernetes also start this traffic generator automatically in a dedicated container or pod, so the demo begins producing telemetry as soon as the environment is up. In the dedicated-host mode, you run the traffic script yourself.

- `/users/42/home` -> direct `200`
- `/campaigns/spring-2026/redirect` -> direct `302`
- `/support/articles/984404` -> direct `404`
- `/checkout/sessions/abc123xyz` -> direct `500`
- `/api/users/42/recommendations/v1/homepage-hero` -> proxied `200`
- `/api/users/314159/recommendations/v1/category-bundles` -> proxied `404`
- `/api/users/271828/recommendations/v2/style-refresh` -> proxied `302`
- `/api/users/42/recommendations/rollout/personalized-homepage` -> chained proxy `200`
- `/api/users/9001/recommendations/rollout/cart-recovery` -> chained proxy `503`

The OBI route config uses the same route patterns as the nginx demo:

```yaml
routes:
  patterns:
    - /users/:user_id/home
    - /campaigns/:campaign_id/redirect
    - /support/articles/:article_id
    - /checkout/sessions/:session_id
    - /api/users/:user_id/recommendations/v1/:experience
    - /api/users/:user_id/recommendations/v2/:experience
    - /api/users/:user_id/recommendations/rollout/:experience
  unmatched: path
```

That means OBI can group the Apache traffic into the same low-cardinality route families you see in the nginx example.

## Telemetry Pipeline

All deployment modes follow the same default pattern:

1. OBI exports traces and metrics over OTLP.
2. A Grafana LGTM stack receives OTLP in a single backend.
3. Grafana is prewired to its traces and metrics backends, so you can explore both signals from one UI.

The example is still backend-neutral. If you want to compare Apache behavior with another OTLP backend later, keep the same three-tier topology and swap the OTLP destination.

## Docker Compose

This mode is the fastest way to try the full stack locally on Linux.

```bash
docker compose up -d
```

That command builds and starts a dedicated `traffic-generator` container automatically. If you want to trigger an extra manual pass from your terminal, you can still run:

```bash
./generate-traffic.sh --one-shot --base-url http://127.0.0.1:8080
```

Useful endpoints:

- app: `http://localhost:8080`
- Grafana: `http://localhost:3000` (`admin` / `admin`)
- OTLP HTTP ingest: `http://localhost:4318`

To view telemetry in the UI:

1. Open `http://localhost:3000` in your browser and sign in with `admin` / `admin`.
2. Open Grafana Explore.
3. Pick the traces data source to inspect end-to-end Apache request traces.
4. Pick the metrics data source to inspect HTTP metrics grouped by route and status code.

Notes:

- The `obi` service runs privileged with host PID access so it can attach to the Apache worker processes started by Docker Compose.
- The compose file pins the topology and OTLP wiring, but you can override the OBI image with `OBI_IMAGE=...`.

## Kubernetes

The Kubernetes variant uses the official OpenTelemetry eBPF Instrumentation Helm chart:

- chart: <https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-ebpf-instrumentation>

The example still deploys the same three-tier Apache topology and LGTM backend with manifests, but OBI itself is installed through Helm so the example matches the supported Kubernetes installation path more closely.

```bash
docker build -t obi-apache-traffic:local -f examples/apache/traffic-runner/Dockerfile examples/apache
kind load docker-image obi-apache-traffic:local

kubectl apply -f examples/apache/k8s/00-namespace.yaml
kubectl apply -k examples/apache/k8s

helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm upgrade --install obi open-telemetry/opentelemetry-ebpf-instrumentation \
  --namespace obi-apache-example \
  -f examples/apache/k8s/03-obi-values.yaml
```

Port-forward the UIs. Use two separate terminal windows for this:

```bash
# Terminal 1
kubectl -n obi-apache-example port-forward svc/edge-apache 8080:8080
```

```bash
# Terminal 2
kubectl -n obi-apache-example port-forward svc/lgtm 3000:3000
```

Then open the UI:

1. Open `http://localhost:3000` in your browser.
2. Sign in with `admin` / `admin`.
3. Open Grafana Explore.
4. Use the traces data source to inspect the proxied Apache request chain.
5. Use the metrics data source to inspect route-grouped HTTP metrics.

Run an extra one-shot pass from your shell if you want:

```bash
./examples/apache/generate-traffic.sh --one-shot --base-url http://127.0.0.1:8080
```

The manifests also start a dedicated `traffic-generator` pod automatically, so the manual command above is optional.

## Dedicated Linux Host Or VM

This mode is meant for an EC2 instance or a local Linux machine where Apache and OBI run directly on the host.

1. Install Apache HTTP Server with `httpd` available on `PATH`, `obi`, and a recent Docker engine.
2. Make sure `obi` runs with sufficient privileges to attach to Apache processes. The example commands below use `sudo`.
3. Start the three host Apache instances:

```bash
./examples/apache/start-standalone.sh
```

1. Start the observability backend:

```bash
docker run -d --name lgtm --restart unless-stopped \
  -p 3000:3000 -p 4317:4317 -p 4318:4318 \
  grafana/otel-lgtm:0.23.0
```

1. Run OBI on the host:

```bash
sudo OTLP_ENDPOINT=http://127.0.0.1:4318 \
  obi --config="$PWD/examples/apache/standalone/obi-config.yaml"
```

1. Generate traffic:

```bash
./examples/apache/generate-traffic.sh --base-url http://127.0.0.1:8080
```

1. When you are done, stop the host Apache instances:

```bash
./examples/apache/stop-standalone.sh
docker rm -f lgtm
```

The host config discovers the three Apache processes by open port and keeps the OTLP target configurable through `OTLP_ENDPOINT`.

To view telemetry in the UI:

1. Open `http://localhost:3000` in your browser.
2. Sign in with `admin` / `admin`.
3. Open Grafana Explore.
4. Use the traces data source to inspect the multi-hop recommendation requests.
5. Use the metrics data source to inspect grouped route metrics and status-code breakdowns.

## What To Look For

In Grafana Explore:

- one server span per Apache hop
- child client spans for proxied recommendation requests
- shared trace IDs across `edge-apache`, `recommendations-v1`, and `recommendations-v2` during proxied flows

In Grafana metrics views:

- HTTP duration and request metrics split by `http.response.status_code`
- route aggregation for `/api/users/:user_id/recommendations/v1/:experience` and `/api/users/:user_id/recommendations/rollout/:experience`

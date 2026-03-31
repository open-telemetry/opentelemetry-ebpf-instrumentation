# NGINX Example

This example highlights the NGINX behaviors that OBI can observe:

- direct NGINX route handling with `2xx`, `3xx`, `4xx`, and `5xx` responses
- NGINX acting as a reverse proxy, including a chained proxy hop between multiple NGINX processes

The scenario is framed as a small demo storefront:

- `edge-nginx` is the public web edge for a shop landing page and a few user-facing routes
- `recommendations-v1` is the legacy recommendations API
- `recommendations-v2` is the next recommendations tier, which still forwards some traffic to `v1` during rollout

That makes the topology feel closer to a real migration story you might show in a talk: a stable public edge, a legacy backend, and a new version gradually introduced without losing trace continuity.

## Topology

The example uses three NGINX instances:

- `edge-nginx`: serves storefront pages and proxies recommendation API calls
- `recommendations-v1`: the legacy recommendations service
- `recommendations-v2`: the newer recommendations service, which still chains some calls through `recommendations-v1`

That gives us these flows:

- direct handling: client -> `edge-nginx`
- single proxy hop: client -> `edge-nginx` -> `recommendations-v1`
- chained proxy hop: client -> `edge-nginx` -> `recommendations-v2` -> `recommendations-v1`

The NGINX route logic now lives in shared include files under [`examples/nginx/k8s/shared`](./k8s/shared), and Docker, standalone, and Kubernetes all consume those same files. Each deployment mode only defines the thin wrapper needed for upstream addresses and mount paths, so the route behavior itself lives in one place.

## Routes To Exercise

Use the bundled [`generate-traffic.sh`](./generate-traffic.sh) script, or call the routes manually. By default the script runs continuously until you stop it with `Ctrl+C`, prints periodic progress updates, and exercises the full route set concurrently at mixed rates. Use `--one-shot` if you only want a single pass.

Docker Compose and Kubernetes also start this traffic generator automatically in a dedicated container or pod, so the demo begins producing telemetry as soon as the environment is up.

- `/users/42/home` -> direct `200`
- `/campaigns/spring-2026/redirect` -> direct `302`
- `/support/articles/984404` -> direct `404`
- `/checkout/sessions/abc123xyz` -> direct `500`
- `/api/users/42/recommendations/v1/homepage-hero` -> proxied `200`
- `/api/users/314159/recommendations/v1/category-bundles` -> proxied `404`
- `/api/users/271828/recommendations/v2/style-refresh` -> proxied `302`
- `/api/users/42/recommendations/rollout/personalized-homepage` -> chained proxy `200`
- `/api/users/9001/recommendations/rollout/cart-recovery` -> chained proxy `503`

The OBI route config groups those paths into low-cardinality route names so it is easy to compare direct and proxied spans.

For example, the shared OBI config includes these route patterns:

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

That means OBI can collapse paths such as `/api/users/42/recommendations/v1/homepage-hero` and `/api/users/314159/recommendations/v1/category-bundles` into the same low-cardinality route family, instead of letting user IDs explode span names and metric label values. The same normalization applies to the chained proxy calls as they move through `recommendations-v2` and `recommendations-v1`.

## Telemetry Pipeline

All deployment modes ship with the same default pattern:

1. OBI exports traces and metrics over OTLP.
2. A Grafana LGTM stack receives OTLP in a single container image.
3. Grafana is prewired to its traces and metrics backends, so you can explore both signals from one UI.

If you want to showcase a different backend later, keep the NGINX topology and swap the OTLP destination in the OBI or collector config. The example itself stays backend-neutral.

For this example, moving to LGTM does not drop any OBI telemetry that we currently demonstrate. We still have traces and metrics. What changes is the UX:

- you no longer get separate Jaeger and Prometheus UIs
- you use Grafana Explore for traces and metrics instead
- LGTM also includes logs and profiles, but OBI is only exercising traces and metrics in this example

## Docker Compose

This mode is the fastest way to try the full stack locally.

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
3. Pick the traces data source to inspect end-to-end recommendation traces.
4. Pick the metrics data source to inspect HTTP metrics grouped by route and status code.

Notes:

- The `obi` service runs privileged with host PID access so it can attach to the NGINX worker processes started by Docker Compose.
- The compose file pins the topology and OTLP wiring, but you can override the OBI image with `OBI_IMAGE=...`.

## Kubernetes

The Kubernetes variant uses the official OpenTelemetry eBPF Instrumentation Helm chart:

- chart: <https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-ebpf-instrumentation>

The example still deploys the same three-tier NGINX topology and observability backends with manifests, but OBI itself is installed through Helm so the example matches the supported Kubernetes installation path more closely.

```bash
docker build -t obi-nginx-traffic:local -f examples/nginx/traffic-runner/Dockerfile examples/nginx
kind load docker-image obi-nginx-traffic:local

kubectl apply -f examples/nginx/k8s/00-namespace.yaml
kubectl apply -k examples/nginx/k8s

helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm upgrade --install obi open-telemetry/opentelemetry-ebpf-instrumentation \
  --namespace obi-nginx-example \
  -f examples/nginx/k8s/03-obi-values.yaml
```

Port-forward the UIs. Use two separate terminal windows for this: each `kubectl port-forward` command keeps running in the foreground, so the second command will not start if you paste both into the same terminal.

```bash
# Terminal 1
kubectl -n obi-nginx-example port-forward svc/edge-nginx 8080:8080
```

```bash
# Terminal 2
kubectl -n obi-nginx-example port-forward svc/lgtm 3000:3000
```

Then open the UI:

1. Open `http://localhost:3000` in your browser.
2. Sign in with `admin` / `admin`.
3. Open Grafana Explore.
4. Use the traces data source to inspect the proxied NGINX request chain.
5. Use the metrics data source to inspect route-grouped HTTP metrics.

Then run:

```bash
./examples/nginx/generate-traffic.sh --one-shot --base-url http://127.0.0.1:8080
```

The Kubernetes manifests also start a dedicated `traffic-generator` pod automatically, so the manual command above is only needed if you want an extra one-shot sweep on demand.

The Helm values in [`examples/nginx/k8s/03-obi-values.yaml`](./k8s/03-obi-values.yaml) configure OBI with Kubernetes-aware discovery and the same grouped route patterns used by the Docker Compose and dedicated-host variants.

## Dedicated Linux Host Or VM

This mode is meant for an EC2 instance or a local Linux machine where NGINX and OBI run directly on the host.

1. Install `nginx`, `obi`, and a recent Docker engine.
2. Start the three host NGINX instances with the provided configs:

```bash
mkdir -p "$PWD/examples/nginx/standalone/edge/logs"
mkdir -p "$PWD/examples/nginx/standalone/recommendations-v1/logs"
mkdir -p "$PWD/examples/nginx/standalone/recommendations-v2/logs"
nginx -p "$PWD/examples/nginx" -c standalone/edge/nginx.conf
nginx -p "$PWD/examples/nginx" -c standalone/recommendations-v1/nginx.conf
nginx -p "$PWD/examples/nginx" -c standalone/recommendations-v2/nginx.conf
```

1. Start the observability backend:

```bash
docker run -d --name lgtm --restart unless-stopped \
  -p 3000:3000 -p 4317:4317 -p 4318:4318 \
  grafana/otel-lgtm:0.22.1
```

1. Run OBI on the host:

```bash
sudo OTLP_ENDPOINT=http://127.0.0.1:4318 \
  obi --config="$PWD/examples/nginx/standalone/obi-config.yaml"
```

1. Generate traffic:

```bash
./examples/nginx/generate-traffic.sh --base-url http://127.0.0.1:8080
```

The provided host config discovers the three NGINX processes by open port and keeps the OTLP target configurable through `OTLP_ENDPOINT`.

To view telemetry in the UI:

1. Open `http://localhost:3000` in your browser.
2. Sign in with `admin` / `admin`.
3. Open Grafana Explore.
4. Use the traces data source to inspect the multi-hop recommendation requests.
5. Use the metrics data source to inspect grouped route metrics and status-code breakdowns.

## What To Look For

In Grafana Explore:

- one server span per NGINX hop
- child client spans for proxied recommendation requests
- shared trace IDs across `edge-nginx`, `recommendations-v1`, and `recommendations-v2` during proxied flows

In Grafana metrics views:

- HTTP duration and request metrics split by `http.response.status_code`
- route aggregation for `/api/users/:user_id/recommendations/v1/:experience` and `/api/users/:user_id/recommendations/rollout/:experience`

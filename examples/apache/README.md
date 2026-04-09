# Apache Example

This example shows Apache HTTP Server support in OBI with a small three-tier topology that covers direct request handling, reverse proxying, chained proxy hops, and route normalization.

It covers:

- direct Apache route handling with `2xx`, `3xx`, `4xx`, and `5xx` responses
- Apache acting as a reverse proxy
- a chained proxy hop across multiple Apache processes
- low-cardinality route grouping in OBI
- traces and HTTP RED metrics exported to Grafana LGTM over OTLP

The demo uses three Apache instances:

- `edge-apache`: the public storefront edge
- `recommendations-v1`: the legacy recommendations backend
- `recommendations-v2`: the newer recommendations backend, which still forwards some rollout traffic to `v1`

That gives us these flows:

- direct handling: client -> `edge-apache`
- single proxy hop: client -> `edge-apache` -> `recommendations-v1`
- chained proxy hop: client -> `edge-apache` -> `recommendations-v2` -> `recommendations-v1`

## Routes To Exercise

Use the bundled [`generate-traffic.sh`](./generate-traffic.sh) script, or call the routes manually. By default the script runs continuously until you stop it with `Ctrl+C`, prints periodic progress updates, and exercises the full route set concurrently at mixed rates. Use `--one-shot` if you only want a single pass.

Docker Compose also starts this traffic generator automatically in a dedicated container, so the demo begins producing telemetry as soon as the environment is up.

- `/users/42/home` -> direct `200`
- `/campaigns/spring-2026/redirect` -> direct `302`
- `/support/articles/984404` -> direct `404`
- `/checkout/sessions/abc123xyz` -> direct `500`
- `/api/users/42/recommendations/v1/homepage-hero` -> proxied `200`
- `/api/users/314159/recommendations/v1/category-bundles` -> proxied `404`
- `/api/users/271828/recommendations/v2/style-refresh` -> proxied `302`
- `/api/users/42/recommendations/rollout/personalized-homepage` -> chained proxy `200`
- `/api/users/9001/recommendations/rollout/cart-recovery` -> chained proxy `503`

The OBI config uses the same route patterns as the nginx demo:

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

That keeps user IDs and experience names out of low-cardinality route labels and span names.

## Docker Compose

This example uses a single Docker Compose setup for Linux.

```bash
docker compose up -d
```

If you want to trigger an extra manual pass from your terminal, run:

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
3. Pick the traces data source to inspect end-to-end request traces.
4. Pick the metrics data source to inspect HTTP metrics grouped by route and status code.

Notes:

- The `obi` service runs privileged with host PID access so it can attach to the Apache worker processes.
- You can override the OBI image with `OBI_IMAGE=...`.

## What To Look For

In Grafana Explore:

- server spans for Apache-handled requests
- trace continuity for proxied recommendation requests when Apache forwards traffic downstream
- shared route grouping across direct, single-hop, and chained-hop traffic

In Grafana metrics views:

- HTTP duration and request metrics split by `http.response.status_code`
- route aggregation for `/api/users/:user_id/recommendations/v1/:experience` and `/api/users/:user_id/recommendations/rollout/:experience`

# Go Channel Links Example

This example demonstrates Go span linking across a user-space channel handoff.

The app exposes two HTTP endpoints, `/receive` and `/dispatch`. Each cycle:

- serves `GET /receive`, which blocks waiting on an unbuffered Go `chan`
- serves `GET /dispatch`, which sends work into that same `chan`
- creates a channel handoff between two separate HTTP handler goroutines

OBI observes the `runtime.chansend1` and `runtime.chanrecv1`/`runtime.chanrecv2` handoff and emits link metadata for the active OBI spans involved in that handoff. In this example those are ordinary OBI HTTP server spans for `/dispatch` and `/receive`.

## Topology

- `channel-links-app`: small Go HTTP service with `/receive` and `/dispatch`
- `traffic-generator`: repeatedly opens a waiting `/receive` request and then triggers `/dispatch`
- `obi`: instruments the Go service and exports traces and metrics over OTLP
- `lgtm`: Grafana LGTM stack for viewing telemetry

## Run

```bash
cd examples/go-channel-links
docker compose up -d --build
```

By default, the compose file builds the `obi` image from your current workspace and tags it as `obi-go-channel-links:local`.

If the stack is already running and you changed the app, OBI config, or OBI source, recreate the app and OBI containers:

```bash
docker compose up -d --build --force-recreate channel-links-app obi
```

Useful endpoints:

- app receive: `http://localhost:8080/receive`
- app dispatch: `http://localhost:8080/dispatch`
- Grafana: `http://localhost:3000` (`admin` / `admin`)

If you want to trigger the handoff manually:

```bash
curl http://localhost:8080/receive &
sleep 1
curl http://localhost:8080/dispatch
wait
```

## View The Links

1. Open `http://localhost:3000` and sign in with `admin` / `admin`.
2. Open Grafana Explore.
3. Select the `Tempo` data source.
4. Trigger the `/receive` then `/dispatch` pair a few times, or let the traffic generator run.
5. Open recent traces produced by `channel-links-app` and inspect the top-level HTTP server spans for `/receive` and `/dispatch`.

What to look for:

- the `GET /receive` server span has a `Links` section
- the `GET /dispatch` server span has a `Links` section
- each link points to the peer trace's `processing` span created by OBI
- the two requests remain separate traces; the relationship is expressed with links, not parent-child edges

## Notes

- The compose stack uses the same privileged OBI + LGTM pattern as the NGINX example.
- You can still override the OBI image explicitly with `OBI_IMAGE=... docker compose up -d`.
- The example intentionally uses a plain blocking receive (`item := <-workCh`). `select`-based channel receive paths are not covered by this probe set.

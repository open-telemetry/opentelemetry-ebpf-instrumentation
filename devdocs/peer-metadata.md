# Peer metadata

Peer metadata exchanges service identities between OBI agents on directly
routable hosts. It is disabled by default and bypassed when
Kubernetes enrichment is enabled. Run one agent per host and use the same
metadata port, authentication, and TLS settings across peers.

Enable it in a standalone Config v2 document:

```yaml
extensions:
  obi:
    version: "2.0"
    enrich:
      enrichers:
        peer_metadata:
          enabled: true
          caller_ttl: 60s
          peer_cidrs: ["10.0.0.0/8"]
          token: ${env:OBI_PEER_METADATA_TOKEN}
```

This is a configuration fragment, retain the capture rules and exporters from your existing
configuration. Omit `peer_cidrs` to use automatic private blocks. Reference
environment variables explicitly using `${env:VARIABLE}` in the corresponding
setting. The bearer token is optional and is redacted when OBI logs its effective
configuration.

## Resolution

Each agent inventories all selected, instrumented services, including services
with no recent requests. It polls live processes for TCP listening sockets and
removes terminated or reused process IDs. Inventory refreshes use
`refresh_interval`. Newly instrumented listeners may be absent until the next
refresh. UDP listener attribution is not supported.

For a client span, the destination IP and listening port identify the remote
service. Multiple processes sharing the same service name and namespace count
as one service. Zero or multiple matching service identities use the remote
hostname. For IPv4 destinations, IPv4 listeners take precedence. If none match,
`::` listeners are tried as possible dual-stack sockets. The inventory does not
distinguish IPv6-only sockets.

For a server span, the remote agent supplies services recently observed calling
that server's destination IP and port. One service identity supplies its name
and namespace. Zero or multiple identities use the caller host's hostname with
an empty service namespace. Observations expire after `caller_ttl`. No ephemeral
ports or per-connection identities are stored. This deliberately permits
occasional incorrect attribution when observations or inventories are stale.

Enrichment runs after name resolution and before filtering and export. Known
peer service identities and hostname fallbacks replace the corresponding
resolved peer name. A cached hostname does not prevent later service resolution.
Cold or expired caches keep the existing DNS or unresolved name and schedule a
background request.

For a resolved service that exports graph metrics, the client agent leaves the
request-total increment to the server agent. Both agents still report their own
latency histograms. Participation respects per-service export settings and dynamic
app-metrics PID selection. Selection changes take effect as inventories and peer
caches refresh.

## Network and lifecycle

An empty `peer_cidrs` list enables automatic eligibility. For each active local
private address, the agent allows its entire private block: `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, or `fc00::/7`. Explicit CIDRs replace automatic
eligibility. Only peers seen in spans are queried.
Loopback and local addresses resolve from the local inventory without HTTP.
Link-local, multicast, and unspecified remote addresses are excluded.

Only active peers refresh. Requests are coalesced per peer, use jitter, and back
off on failure. Metadata expires after `cache_ttl` without a successful refresh.
Remote failures leave telemetry running. Local bind errors or invalid TLS files
abort pipeline startup. Cancellation closes the listener and background workers.

The endpoint accepts a shared bearer token when `token` is configured. TLS uses
normal certificate verification: configure a CA file for a private CA and
certificate IP SANs, or a common `server_name`. Without a token, the endpoint
allows unauthenticated reads. CIDRs govern outgoing queries, but they do not restrict
incoming requests. This protocol assumes trusted peers and does not account for
NAT, proxies, or load balancers.

## Settings

All settings are under `extensions.obi.enrich.enrichers.peer_metadata`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Enable serving and querying peer metadata. |
| `listen_address` | `""` | Bind IP; empty binds all local interfaces. |
| `port` | `8998` | Shared metadata port. |
| `peer_cidrs` | `[]` | Automatic private blocks, or explicit eligible ranges. |
| `refresh_interval` | `10s` | Peer and listener inventory refresh interval. |
| `caller_ttl` | `60s` | Observation retention. |
| `cache_ttl` | `60s` | Remote metadata expiry and peer inactivity retention. |
| `request_timeout` | `2s` | HTTP request and server I/O timeout. |
| `max_peers` | `1024` | Maximum cached hosts. |
| `max_concurrent` | `8` | Maximum concurrent outgoing HTTP requests. |
| `max_caller_entries` | `16384` | Maximum service-to-destination observations. |
| `max_response_bytes` | `1048576` | Encoded response limit in both directions. |
| `max_cache_bytes` | `67108864` | Cached encoded response byte budget. |
| `token` | `""` | Shared bearer token; supports declarative substitution. |
| `tls.enabled` | `false` | Serve and query over HTTPS. |
| `tls.cert_file` | `""` | Server certificate PEM file. |
| `tls.key_file` | `""` | Server private key PEM file. |
| `tls.ca_file` | `""` | Peer CA PEM file; empty uses system roots. |
| `tls.server_name` | `""` | Override the certificate name verified for peers. |

Durations must be at least 1ms and size limits must be positive.
`max_cache_bytes` must be at least `max_response_bytes`. When local caller
observations overflow, caller attribution falls back to hostnames until the
potentially missing observations expire. Responses over the configured size
limit fail instead of returning a partial inventory.

## Protocol

`GET /v1/metadata` returns protocol `version`, `hostname`, `services`, TCP
`listeners`, and recent `callers`. Services contain `name`, `namespace`, and an
optional `service_graph` flag indicating whether the service exports graph metrics;
listeners contain an `endpoint` with `ip` and `port`, plus `service`.

Use optional `port` and `ip` query parameters to filter listener inventory.
Without filters, the response contains all instrumented services, including
services without listeners. Repeated `target` parameters select the destination
IPs for caller observations. Without them, the requester IP is used. Agents
request observations only for their own local IPs.

Each caller record has a `destination` and a list of services with
`remaining_ms`. Lifetimes are relative to the snapshot, avoiding a requirement
for synchronized host clocks. Receivers subtract time since the request began
and cap remote lifetimes to their own `caller_ttl`. `caller_ambiguity_ms` marks
observation overflow conservatively.

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
          tls:
            enabled: true
            cert_file: /etc/obi/peer/cert.pem
            key_file: /etc/obi/peer/key.pem
            ca_file: /etc/obi/peer/ca.pem
```

This is a configuration fragment, retain the capture rules and exporters from your existing
configuration. Omit `peer_cidrs` to use automatic private blocks. Reference
environment variables explicitly using `${env:VARIABLE}` in the corresponding
setting. The bearer token is optional. Peer metadata settings are omitted when
OBI logs its runtime configuration.

## Resolution

Each agent inventories all selected, instrumented services, including services
with no recent requests. It polls live processes for TCP listening sockets and
removes terminated or reused process IDs. Inventory refreshes at startup, after
process events, and periodically using `refresh_interval`. Event bursts are
coalesced. Listeners opened later are discovered by periodic refreshes. UDP
listener attribution is not supported.

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
request-total increment to the server agent only after that agent acknowledges
cached caller observations matching the client service and destination. Until
then, including when metadata exchange works in only one direction, the client
keeps its request count. Participation also requires the server's protocol metrics
selection to include the request's protocol. Disabling HTTP metrics while keeping
HTTP traces enabled therefore retains the client count and trace enrichment.
For eligible protocols, both agents report their own latency histograms.
Participation respects per-service export settings and dynamic app-metrics PID
selection. When only the hostname can be resolved and the protocol is eligible,
the client request total remains suppressed conservatively until a listener
matches. A matched service with graph metrics disabled retains normal client
counting. Failed connection attempts are excluded from this suppression. Selection
changes take effect as inventories and peer caches refresh.

## Network and lifecycle

An empty `peer_cidrs` list enables automatic eligibility. For each active local
private address, the agent allows its entire private block: `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, or `fc00::/7`. Explicit CIDRs replace automatic
eligibility. The same CIDRs restrict incoming requests using the TCP source IP;
requests outside them return HTTP 403. Only peers seen in spans are queried.
Loopback and local addresses resolve from the local inventory without HTTP.
Link-local, multicast, and unspecified remote addresses are excluded.

Only active peers refresh. Requests are coalesced per peer, use jitter, and back
off on failure. Responsive peers take refresh priority. When both refreshes and
probes are due, one discovery or failed-peer probe is scheduled after at most
`max_concurrent` prioritized refreshes. Each group keeps fetch-deadline order, so
silent peers cannot monopolize refreshes and new peers still make progress.
Remote failures leave telemetry running. Local bind errors or invalid TLS files
abort pipeline startup. Cancellation closes the listener and background workers.

A configured bearer `token` requires TLS; token-over-HTTP configurations fail
validation. Peer certificates are verified before the token is sent. Configure a
CA trusted to issue certificates to peer agents, with certificate IP SANs or a
common `server_name`. Without a token, HTTP is allowed and permitted source IPs
can read inventory without authentication. CIDRs restrict incoming requests and
outgoing queries; they do not authenticate peers. Forwarded headers are ignored.
This protocol assumes trusted peers and does not account for NAT, proxies, or load
balancers. Local HTTP diagnostics require an explicit loopback CIDR when it is
outside the permitted ranges.

## Settings

All settings are under `extensions.obi.enrich.enrichers.peer_metadata`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Enable serving and querying peer metadata. |
| `listen_address` | `""` | Bind IP; empty binds all local interfaces. |
| `port` | `8998` | Shared metadata port. |
| `peer_cidrs` | `[]` | Allowed incoming and outgoing peer networks; empty selects private blocks. |
| `refresh_interval` | `10s` | Peer and listener inventory refresh interval. |
| `caller_ttl` | `60s` | Observation retention. |
| `cache_ttl` | `60s` | Remote metadata expiry and peer inactivity retention. |
| `request_timeout` | `2s` | HTTP request and server I/O timeout. |
| `max_peers` | `1024` | Maximum cached hosts. |
| `max_concurrent` | `8` | Maximum concurrent outgoing HTTP requests. |
| `max_caller_entries` | `16384` | Maximum service-to-destination observations. |
| `max_response_bytes` | `1048576` | Encoded response limit in both directions. |
| `max_cache_bytes` | `67108864` | Cached encoded response byte budget. |
| `token` | `""` | Shared bearer token; requires TLS and supports declarative substitution. |
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
optional `service_graph` flag indicating per-service graph participation;
listeners contain an `endpoint` with `ip` and `port`, plus `service`.

`metric_protocols` carries the agent-wide unsigned 64-bit
[`InstrumentationSelection`](../pkg/export/instrumentations/instr_options.go)
mask used by the protocol metrics gate. Zero explicitly disables all mapped
protocols; agents without a protocol restriction advertise the all-protocol mask.
Agents without a metrics exporter omit this eligibility, retaining client-side
request counts even for hostname fallbacks. Missing eligibility on older peers
also retains client-side request counts.

Use optional `port` and `ip` query parameters to filter listener inventory.
Without filters, the response contains all instrumented services, including
services without listeners. Caller observations are limited to the TCP source IP
of the requester. Optional `target` parameters must all match that address after
IP normalization; other targets return HTTP 400. Agents omit `target` and use the
source address observed by the peer. On multihomed hosts, observations for other
local IPs are not returned by that connection.

Each caller record has a `destination` and a list of services with
`remaining_ms`. Optional `known_callers` records acknowledge the requester's
observations already cached by the responding agent. They expire with those
observations or the cache, whichever comes first. They are omitted when the
cached caller set is globally ambiguous. Older peers without acknowledgements
retain client-side request counts for matched services.

Lifetimes are relative to the snapshot, avoiding a requirement
for synchronized host clocks. Receivers subtract time since the request began
and cap remote lifetimes to their own `caller_ttl`. `caller_ambiguity_ms` marks
observation overflow conservatively.

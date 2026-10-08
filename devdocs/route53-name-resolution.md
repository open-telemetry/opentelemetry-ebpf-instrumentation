# Route53 name resolution

The opt-in `route53` name resolver maps endpoint IPs to fully qualified DNS names
from selected AWS Route53 hosted zones on detected EC2 hosts.
Configure Route53 in Config v2:

```yaml
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    enrich:
      enrichers:
        cloud:
          refresh_interval: 30s
          route53:
            refresh_interval: 5m
            hosted_zone_ids: [Z0123456789EXAMPLE]
      service_name:
        sources: [k8s, ecs, route53]
```

Use the AWS SDK's standard credentials configuration. Grant
`route53:ListResourceRecordSets` on the configured hosted zones; listing all zones
is not required. Zone IDs can include the `/hostedzone/` prefix. Select zones
appropriate to the monitored network, since different private networks can reuse
IP addresses.

Literal A and AAAA records contribute IP mappings. Names are lowercase, retain
all domain labels, and omit the trailing dot. Aliases, CNAMEs, and wildcard records
are excluded. If multiple names map to the same IP, the lexicographically smallest
name wins, independently of API response order.

Kubernetes and ECS names take precedence over Route53 names. Route53 takes
precedence over captured DNS responses and reverse DNS. Route53 decorates endpoint
names; ECS container identity remains responsible for local process naming.

Route53 polls independently of ECS, with a default interval of five minutes.
Initial discovery is delayed randomly between zero and one interval to spread
startup traffic. Later polls wait between 80% and 120% of the interval after the
previous fetch completes. Names remain unresolved until initial discovery succeeds.

Each source retains its last successful snapshot. Successful refreshes remove
deleted records; a failed Route53 fetch preserves its mappings and does not block
ECS refreshes. Repeated throttling doubles the Route53 polling interval up to
eight times the configured interval, with the same jitter. A successful fetch
restores the configured interval. SDK retries still apply within each fetch.

A longer interval reduces average API traffic; jitter spreads bursts. Each OBI
instance still lists every configured zone, including all pages. Size the interval
for the number of instances and zones sharing the account, leaving capacity for
other API clients. There is no coordination between instances.

Hosted zones and the refresh interval can reference deployment-specific variables
through Config v2 substitution, for example:

```yaml
route53:
  refresh_interval: ${ROUTE53_REFRESH_INTERVAL:-5m}
  hosted_zone_ids: ["${ROUTE53_HOSTED_ZONE_ID}"]
```

For legacy Config v1, enable the source and configure the same settings under
`cloud_metadata.route53`:

```yaml
name_resolver:
  sources: [k8s, ecs, route53]
cloud_metadata:
  route53:
    refresh_interval: 5m
    hosted_zone_ids: [Z0123456789EXAMPLE]
```

Config v1 also accepts these environment variables, which override YAML values:

- `OTEL_EBPF_NAME_RESOLVER_SOURCES`: comma-separated resolver sources.
- `OTEL_EBPF_NAME_RESOLVER_ROUTE53_HOSTED_ZONE_IDS`: comma-separated hosted zone IDs.
- `OTEL_EBPF_NAME_RESOLVER_ROUTE53_REFRESH_INTERVAL`: polling interval (default `5m`).

The hosted zone IDs are required when the `route53` source is enabled.
`obi config migrate` preserves these settings when converting Config v1 to v2.

The Route53 client region, which selects the AWS partition, is
`extensions.obi.enrich.enrichers.cloud.region` (or `cloud_metadata.region` in
Config v1) if set, otherwise the detected
cloud region. Without either, the AWS SDK's region configuration applies,
falling back to `us-east-1`.
For local tests, its endpoint override is `AWS_ENDPOINT_URL_ROUTE_53`.

## Integration tests

`TestRoute53ServiceResolution` starts a digest-pinned Floci container, creates a
hosted zone and a record pointing at a backend container, and checks the exported
HTTP client metric's explicitly enabled `server` label. It uses a one-second Route53 interval and
replaces the record to verify periodic refreshes. Existing EC2/ECS metadata containers and the ECS API failure mock remain unchanged.

```sh
go test -v -run '^TestRoute53ServiceResolution$' -timeout 10m ./internal/test/integration/
```

Unit tests additionally cover pagination, IPv6, duplicate IPs, record exclusions,
snapshot retention on failure, record deletion, resolver precedence, and recovery
from an initial API error.

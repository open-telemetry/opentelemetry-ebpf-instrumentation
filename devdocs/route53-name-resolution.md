# Route53 name resolution

The `route53` name resolver is enabled by default and maps endpoint IPs to fully
qualified DNS names from AWS Route53 hosted zones on detected EC2 hosts.
Each refresh discovers public zones in the current AWS account and private zones
associated with the host's VPC, identified through its primary network interface
in EC2 instance metadata. If the VPC or region is unknown, only public zones are
eligible. Optional `hosted_zone_ids` narrow this selection without bypassing the
VPC or address filters.

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
`route53:ListResourceRecordSets` on the hosted zones. Zone discovery also
requires `route53:ListHostedZones` and, when the VPC and region are known,
`route53:ListHostedZonesByVPC` on `*`, including when explicit zone IDs are configured.
Zone IDs can include the `/hostedzone/` prefix. Use explicit IDs to select zones
appropriate to the monitored network, since different private networks can reuse
IP addresses.

Literal A and AAAA records contribute IP mappings. Names are lowercase, retain
all domain labels, and omit the trailing dot. Aliases, CNAMEs, and wildcard records
are excluded.

Public zones can contain IPs reused across networks, so their records need
additional filtering:

| Address type | Treatment in public zones |
| --- | --- |
| Private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 (`fc00::/7`) | Excluded |
| Shared address space (`100.64.0.0/10`) | Excluded |
| Loopback, link-local, multicast, and unspecified addresses | Excluded |
| Non-public special-purpose ranges, including documentation, benchmarking, and reserved addresses | Excluded |
| Reachable exceptions within special-purpose ranges | Retained |

The prefix tables follow the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries
and are maintained in code. Teredo and 6to4, which carry IPv6 over IPv4, are
retained because their reachability depends on the underlying IPv4 network.
OBI does not probe addresses to check reachability.

This can omit a valid mapping such as `database.example.com -> 100.64.0.2` in a
public zone: the IP alone cannot identify which network the record describes.
If no eligible private zone or other resolver supplies a name, the endpoint
remains unresolved. Publishing the record in a private zone associated with the
monitored VPC makes it eligible. Explicit zone IDs cannot override these rules.

Eligible private zones retain all valid A/AAAA addresses. OBI checks the zone's
VPC association, not whether each IP belongs to a VPC subnet; a zone may name
endpoints in connected networks. Private-zone names override public-zone names
for the same IP. Within either scope, the alphabetically smallest name wins,
regardless of API response order. The IP-only map cannot determine which of
several names an application used.

Zones associated only through Route 53 Profiles are excluded because
`ListHostedZonesByVPC` does not discover them, even with explicit zone IDs.
Associated zones owned by another account or AWS service are eligible if readable.
If any record page returns `AccessDenied`, OBI discards that zone's records and
continues with readable zones. Skipped zones are checked on later refreshes;
each successful refresh contains only records from currently readable zones.

Kubernetes and ECS names take precedence over Route53 names. Route53 takes
precedence over captured DNS responses and reverse DNS. Route53 decorates endpoint
names; ECS container identity remains responsible for local process naming.

Route53 polls independently of ECS, with a default interval of five minutes.
Initial discovery is delayed randomly between zero and one interval to spread
startup traffic. Later polls wait between 80% and 120% of the interval after the
previous fetch completes. Names remain unresolved until initial discovery succeeds.

Before the first successful refresh, `AccessDenied` during discovery or from
every selected zone disables Route53 polling. OBI logs one warning with the
required permissions. Grant them and restart OBI to enable the source.
Transient failures still retry. After a successful refresh, discovery failures
or denial by every selected zone preserve the last snapshot and keep retrying.

Each source retains its last successful snapshot. Successful refreshes remove
deleted records; a failed Route53 fetch preserves its mappings and does not block
ECS refreshes. Repeated throttling doubles the Route53 polling interval up to
eight times the configured interval, with the same jitter. A successful fetch
restores the configured interval. SDK retries still apply within each fetch.

A longer interval reduces average API traffic; jitter spreads bursts. Each OBI
instance reads all record pages of each selected zone. Size the interval
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

Hosted zone IDs are optional. To disable Route53, set service name sources
explicitly, for example `[k8s, ecs]`.
`obi config migrate` preserves Route53 settings present in the Config v1 YAML;
legacy environment overrides must be materialized or explicitly rewired for Config v2.

The Route53 client region, which selects the AWS partition, is
`extensions.obi.enrich.enrichers.cloud.region` (or `cloud_metadata.region` in
Config v1) if set, otherwise the detected
cloud region. Without either, the AWS SDK's region configuration applies,
falling back to `us-east-1`.
For local tests, its endpoint override is `AWS_ENDPOINT_URL_ROUTE_53`.

## Integration tests

`TestRoute53ServiceResolution` starts a digest-pinned Floci container, creates a
private hosted zone associated with the mock host's VPC and a record pointing
at a backend container, discovers the zone automatically, and checks the exported
HTTP client metric's explicitly enabled `server` label. Conflicting records in a
public zone and an unrelated VPC must not replace the local private name. The
test uses a one-second Route53 interval and replaces the record to verify
periodic refreshes.

```sh
go test -v -run '^TestRoute53ServiceResolution$' -timeout 10m ./internal/test/integration/
```

Unit tests additionally cover pagination, IPv6, duplicate IPs, record exclusions,
snapshot retention on failure, record deletion, resolver precedence, and recovery
from an initial API error.

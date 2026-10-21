# Route53 name resolution

The `route53` name resolver is enabled by default and maps endpoint IPs to fully
qualified DNS names from AWS Route53 hosted zones on detected EC2 hosts.
Without `hosted_zone_ids`, each refresh discovers public zones in the current
AWS account and private zones associated with the detected VPC. The VPC is
identified through the primary network interface in EC2 instance metadata.
If the VPC or its region cannot be detected, only public zones are discovered.
Explicit `hosted_zone_ids` narrow this selection; they do not bypass VPC or
address filtering.
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

Zone discovery applies two separate rules to avoid importing names from
unrelated networks:

- **Zone selection:** public zones in the current account and private zones
  associated with the detected VPC are eligible. Private zones without that VPC
  association are excluded entirely.
- **Public-zone address filtering:** private IPv4 ranges (`10.0.0.0/8`,
  `172.16.0.0/12`, and `192.168.0.0/16`), IPv6 unique-local addresses (`fc00::/7`),
  and shared address space (`100.64.0.0/10`) are excluded, along with addresses
  that are not global unicast, such as loopback and link-local addresses.
  Non-public special-purpose allocations are also excluded, including
  documentation, benchmarking, reserved IPv4 space, local IPv6 translation,
  discard-only, and SRv6 SID prefixes. The filter follows the
  [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
  [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) registries,
  preserving more-specific globally reachable exceptions. Conditional transition
  mechanisms such as Teredo and 6to4 are retained; this is not a live reachability
  check. The prefix tables are maintained in the code, not downloaded at runtime.
  A public
  DNS zone can contain addresses reused across networks; its visibility does not
  make those addresses globally unique.

Filtering can omit valid IP-to-hostname mappings. For example, a public zone may
intentionally publish `database.example.com -> 100.64.0.2` for clients on an
internal network. OBI ignores that public-zone record because the IP alone does
not identify which network it belongs to. If no eligible private-zone mapping or
other name resolver supplies a name, Route53 leaves the endpoint unresolved.
Publishing the mapping in a private zone associated with the monitored VPC makes
it eligible. Explicit zone IDs cannot override the filter.

Records from eligible private zones retain these addresses. OBI checks the
**zone's VPC association**, not whether each record's IP belongs to a VPC subnet.
An associated zone can legitimately name endpoints in connected networks.
Consequently, this does not discard every private IP outside the detected VPC.

Private-zone names take precedence over public-zone names for the same IP.
Precedence alone does not prevent mislabeling: if no private-zone record exists
for `100.64.0.2`, an unrelated name for that address in a public zone would
otherwise be used. Public-zone address filtering prevents that fallback.
Within each scope, the lexicographically smallest name wins, independently of
API response order. Multiple names can still refer to the same IP within a VPC;
the IP-only map cannot determine which name an application used.

Explicitly configured `hosted_zone_ids` act as an allowlist of discovered zones.
They cannot include private zones unrelated to the detected VPC or bypass
public-zone address filtering. If the VPC or region is unknown, configured private
zones are excluded as well.

Private zones associated through Route 53 Profiles are not discovered by `ListHostedZonesByVPC` and are
excluded even when explicitly configured. Associated zones owned by another
account or AWS service are included when their records are readable. A zone whose records
return `AccessDenied` is skipped without blocking readable zones. If a later
page is denied, all records from that zone are discarded. Skipped zones are
checked again on subsequent refreshes, allowing newly granted access to take
effect. A successful refresh contains only records from currently readable zones.

Kubernetes and ECS names take precedence over Route53 names. Route53 takes
precedence over captured DNS responses and reverse DNS. Route53 decorates endpoint
names; ECS container identity remains responsible for local process naming.

Route53 polls independently of ECS, with a default interval of five minutes.
Initial discovery is delayed randomly between zero and one interval to spread
startup traffic. Later polls wait between 80% and 120% of the interval after the
previous fetch completes. Names remain unresolved until initial discovery succeeds.

If zone discovery returns `AccessDenied`, or all selected zones deny record
access, before the first successful refresh, OBI marks the source unavailable,
logs one warning listing the required permissions, and stops polling it. Grant the permissions and restart OBI to enable it.
Transient startup failures still retry. After a successful refresh, discovery
denials or denial by all selected zones preserve the last snapshot and continue
retrying, allowing recovery when access is restored.

Each source retains its last successful snapshot. Successful refreshes remove
deleted records; a failed Route53 fetch preserves its mappings and does not block
ECS refreshes. Repeated throttling doubles the Route53 polling interval up to
eight times the configured interval, with the same jitter. A successful fetch
restores the configured interval. SDK retries still apply within each fetch.

A longer interval reduces average API traffic; jitter spreads bursts. Each OBI
instance lists every discovered or configured zone, including all pages. Size the interval
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

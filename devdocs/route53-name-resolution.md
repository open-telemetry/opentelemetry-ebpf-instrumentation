# Route53 name resolution

The opt-in `route53` name resolver maps endpoint IPs to fully qualified DNS names
from selected AWS Route53 hosted zones on detected EC2 hosts:

```yaml
name_resolver:
  sources: [k8s, ecs, route53]
cloud_metadata:
  refresh_interval: 30s
  route53:
    hosted_zone_ids: [Z0123456789EXAMPLE]
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

Refreshes replace the shared cloud inventory after all enabled sources succeed.
Successful refreshes remove deleted records; a failure retains the previous
inventory until the next interval. An initial failure leaves the inventory empty
until a refresh succeeds.

The corresponding environment variables are:

- `OTEL_EBPF_NAME_RESOLVER_SOURCES=route53`
- `OTEL_EBPF_NAME_RESOLVER_ROUTE53_HOSTED_ZONE_IDS=Z0123456789EXAMPLE`
- `OTEL_EBPF_CLOUD_META_REFRESH_INTERVAL=30s`

The AWS SDK uses the configured region, falling back to `us-east-1` for Route53.
For local tests, its endpoint override is `AWS_ENDPOINT_URL_ROUTE_53`.

## Integration tests

`TestRoute53ServiceResolution` starts a digest-pinned Floci container, creates a
hosted zone and a record pointing at a backend container, and checks the exported
service-graph name. It replaces the record to verify periodic refreshes. Existing
EC2/ECS metadata containers and the ECS API failure mock remain unchanged.

```sh
go test -v -run '^TestRoute53ServiceResolution$' -timeout 10m ./internal/test/integration/
```

Unit tests additionally cover pagination, IPv6, duplicate IPs, record exclusions,
snapshot retention on failure, record deletion, resolver precedence, and recovery
from an initial API error.

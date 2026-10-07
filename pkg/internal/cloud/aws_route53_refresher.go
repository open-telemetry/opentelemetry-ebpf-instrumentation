// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/internal/cloud"

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// route53EscapedWildcard is the octal escape that Route53 returns for a "*" wildcard label.
const route53EscapedWildcard = `\052`

type Route53Client interface {
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type Route53Inventory struct {
	client        Route53Client
	hostedZoneIDs []string
}

func NewRoute53Inventory(client Route53Client, hostedZoneIDs []string) *Route53Inventory {
	return &Route53Inventory{
		client:        client,
		hostedZoneIDs: slices.Clone(hostedZoneIDs),
	}
}

func (i *Route53Inventory) Name() string { return "route53" }

func (i *Route53Inventory) Refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	for _, zone := range i.hostedZoneIDs {
		pages := route53.NewListResourceRecordSetsPaginator(i.client, &route53.ListResourceRecordSetsInput{HostedZoneId: &zone})
		for pages.HasMorePages() {
			out, err := pages.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("listing Route53 records for hosted zone %q: %w", zone, err)
			}
			for _, record := range out.ResourceRecordSets {
				addRoute53Record(snapshot.ServiceByIP, record)
			}
		}
	}
	return nil
}

func addRoute53Record(next map[string]string, record types.ResourceRecordSet) {
	if record.Type != types.RRTypeA && record.Type != types.RRTypeAaaa {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(aws.ToString(record.Name)), ".")
	if name == "" || strings.Contains(name, "*") || strings.Contains(name, route53EscapedWildcard) {
		return
	}
	for _, resource := range record.ResourceRecords {
		addr, err := netip.ParseAddr(aws.ToString(resource.Value))
		if err != nil || (record.Type == types.RRTypeA) != addr.Is4() {
			continue
		}
		ip := addr.Unmap().String()
		// DNS names need not be unique per IP; keep selection independent of API order.
		if previous, ok := next[ip]; !ok || name < previous {
			next[ip] = name
		}
	}
}

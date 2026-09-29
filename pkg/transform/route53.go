// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"go.opentelemetry.io/obi/pkg/internal/cloud"
)

// Route53MetadataConfig maps A/AAAA records to fully qualified names.
// Aliases, CNAMEs, and wildcard records are excluded. ECS names take precedence.
type Route53MetadataConfig struct {
	// HostedZoneIDs restricts discovery to these hosted zones. Required when route53 is enabled.
	HostedZoneIDs []string `yaml:"hosted_zone_ids" env:"OTEL_EBPF_NAME_RESOLVER_ROUTE53_HOSTED_ZONE_IDS" envSeparator:","`
}

func route53InventoryRefresher(
	ctx context.Context,
	cloudCfg CloudMetadataConfig,
) (cloud.MetadataRefresher, error) {
	if cloudCfg.RefreshInterval <= 0 {
		return nil, errors.New("initializing Route53 name resolver: a positive refresh interval is required")
	}
	if len(cloudCfg.Route53.HostedZoneIDs) == 0 {
		return nil, errors.New("initializing Route53 name resolver: hosted_zone_ids is required")
	}
	for _, id := range cloudCfg.Route53.HostedZoneIDs {
		if strings.TrimSpace(strings.TrimPrefix(id, "/hostedzone/")) == "" {
			return nil, errors.New("initializing Route53 name resolver: hosted zone IDs must not be empty")
		}
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithDefaultRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration for Route53 name resolver: %w", err)
	}
	return cloud.NewRoute53Inventory(route53.NewFromConfig(awsCfg), cloudCfg.Route53.HostedZoneIDs), nil
}

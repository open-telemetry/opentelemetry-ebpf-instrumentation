// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"

	"go.opentelemetry.io/obi/pkg/internal/ecs"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// ECSInventoryProvider initializes the shared inventory before its consumers and
// runs periodic refreshes for the lifetime of the application pipeline.
func ECSInventoryProvider(ctxInfo *global.ContextInfo, cfg *NameResolverConfig) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if cfg == nil || !resolverSources(cfg.Sources).Has(ResolverECS) {
			return swarm.EmptyRunFunc()
		}
		if cfg.ECS.Cluster == "" || cfg.ECS.Region == "" || cfg.ECS.RefreshInterval <= 0 {
			return nil, errors.New("initializing ECS name resolver: cluster, region, and a positive refresh interval are required")
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.ECS.Region))
		if err != nil {
			return nil, fmt.Errorf("loading AWS configuration for ECS name resolver: %w", err)
		}
		inventory := ecs.NewInventory(awsecs.NewFromConfig(awsCfg), cfg.ECS.Cluster)
		if err := inventory.Refresh(ctx); err != nil {
			nrlog().Warn("can't load initial ECS task inventory; will retry", "error", err)
		}
		ctxInfo.AppO11y.ECSInventory = inventory
		return func(ctx context.Context) {
			inventory.Run(ctx, cfg.ECS.RefreshInterval)
		}, nil
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configwatch // import "go.opentelemetry.io/obi/cmd/obi/internal/configwatch"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const configWatchInterval = time.Second

// Watch refreshes discovery criteria for an initialized application pipeline
// when the configuration file changes from the contents loaded at startup.
func Watch(ctx context.Context, path string, initial []byte, refresh func(context.Context, *obi.Config) error) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFile(ctx, path, initial, refresh, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the path on every poll also handles atomic file replacements and ConfigMap symlinks.
func watchConfigFile(ctx context.Context, path string, previous []byte, refresh func(context.Context, *obi.Config) error, log *slog.Logger, ticks <-chan time.Time) {
	var readError string
	var rejected []byte
	var refreshError string
	for {
		data, err := os.ReadFile(path)
		switch {
		case err != nil:
			if readError != err.Error() {
				log.Error("can't read configuration for refresh; continuing with the running configuration", "path", path, "error", err)
				readError = err.Error()
			}
		default:
			readError = ""
			if bytes.Equal(previous, data) {
				rejected = nil
				refreshError = ""
				break
			}

			if err := refreshConfig(ctx, data, refresh); err != nil {
				if ctx.Err() != nil {
					return
				}
				if !bytes.Equal(rejected, data) || refreshError != err.Error() {
					log.Error("can't refresh configuration; continuing with the running configuration and retrying", "path", path, "error", err)
					rejected = data
					refreshError = err.Error()
				}
			} else {
				previous = data
				rejected = nil
				refreshError = ""
				log.Info("discovery criteria refreshed", "path", path)
			}
		}
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
		}
	}
}

func refreshConfig(ctx context.Context, data []byte, refresh func(context.Context, *obi.Config) error) error {
	cfg, err := loadConfig(data)
	if err != nil {
		return err
	}
	return refresh(ctx, cfg)
}

func loadConfig(data []byte) (*obi.Config, error) {
	doc, _, err := schema.ParseStandaloneYAML(obicfg.ReplaceEnv(data))
	if err != nil {
		if _, ok := errors.AsType[*schema.NotV2Error](err); ok {
			return nil, errors.New("configuration version changed; restart OBI to apply this configuration")
		}
		return nil, fmt.Errorf("loading config v2: %w", err)
	}

	cfg, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return nil, fmt.Errorf("loading config v2: %w", err)
	}
	if err := cfg.ValidateStaticForApplicationRefresh(); err != nil {
		return nil, err
	}
	return cfg, nil
}

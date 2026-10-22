// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/obi/pkg/obi"
)

const configWatchInterval = time.Second

func watchConfig(ctx context.Context, path string, refresh func(context.Context, *obi.Config) error) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFile(ctx, path, refresh, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the path on every poll also handles atomic file replacements and ConfigMap symlinks.
func watchConfigFile(ctx context.Context, path string, refresh func(context.Context, *obi.Config) error, log *slog.Logger, ticks <-chan time.Time) {
	var previous []byte
	var seen bool
	var readError string
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
			if seen && bytes.Equal(previous, data) {
				break
			}

			seen = true
			previous = data
			if err := refreshConfig(ctx, data, refresh); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Error("can't refresh configuration; restart OBI to apply this config", "path", path, "error", err)
			} else {
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
	cfg, version, err := loadConfigReader(bytes.NewReader(data))
	if err != nil {
		return err
	}

	if version != configVersionV2 {
		return errors.New("configuration version changed; restart OBI to apply this configuration")
	}

	if err := cfg.ValidateStatic(); err != nil {
		return err
	}

	return refresh(ctx, cfg)
}

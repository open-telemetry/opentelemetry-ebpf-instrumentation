// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configwatch // import "go.opentelemetry.io/obi/cmd/obi/internal/configwatch"

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"time"

	"go.opentelemetry.io/obi/cmd/obi/internal/configload"
	"go.opentelemetry.io/obi/pkg/obi"
)

const configWatchInterval = time.Second

// Watch refreshes discovery criteria for an initialized application pipeline
// when any configuration file changes from the contents loaded at startup.
func Watch(ctx context.Context, initial []configload.Source, refresh func(context.Context, *obi.Config) error) {
	ticker := time.NewTicker(configWatchInterval)
	defer ticker.Stop()
	watchConfigFiles(ctx, initial, refresh, slog.With("component", "config.Watcher"), ticker.C)
}

// Reading the paths on every poll also handles atomic file replacements and ConfigMap symlinks.
func watchConfigFiles(ctx context.Context, previous []configload.Source, refresh func(context.Context, *obi.Config) error, log *slog.Logger, ticks <-chan time.Time) {
	paths := sourcePaths(previous)
	lastRead := previous
	var readError string
	var loaded *loadedContents
	var rejected []configload.Source
	var refreshError string
	for {
		sources, err := readSources(paths)
		switch {
		case err != nil:
			if readError != err.Error() {
				log.Error("can't read configuration for refresh; continuing with the running configuration", "paths", paths, "error", err)
				readError = err.Error()
			}
		default:
			readError = ""
			unchangedSinceLastRead := equalContents(lastRead, sources)
			lastRead = sources
			if equalContents(previous, sources) {
				loaded = nil
				rejected = nil
				refreshError = ""
				break
			}

			// A poll can land in the middle of an in-place write, so contents apply
			// only once two consecutive polls read them unchanged.
			if !unchangedSinceLastRead {
				break
			}

			if loaded == nil || !equalContents(loaded.sources, sources) {
				cfg, err := loadConfig(sources)
				loaded = &loadedContents{sources: sources, cfg: cfg, err: err}
			}
			if err := refreshConfig(ctx, loaded, refresh); err != nil {
				if ctx.Err() != nil {
					return
				}
				if !equalContents(rejected, sources) || refreshError != err.Error() {
					log.Error("can't refresh configuration; continuing with the running configuration and retrying", "paths", paths, "error", err)
					rejected = sources
					refreshError = err.Error()
				}
			} else {
				previous = sources
				loaded = nil
				rejected = nil
				refreshError = ""
				log.Info("discovery criteria refreshed", "paths", paths)
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

// loadedContents keeps the result of loading one version of the files. Retrying the same
// contents reuses it, so validation and its warnings run once per change. Environment
// variables are fixed for the process, so identical contents always load the same way.
type loadedContents struct {
	sources []configload.Source
	cfg     *obi.Config
	err     error
}

func refreshConfig(ctx context.Context, loaded *loadedContents, refresh func(context.Context, *obi.Config) error) error {
	if loaded.err != nil {
		return loaded.err
	}
	return refresh(ctx, loaded.cfg)
}

func loadConfig(sources []configload.Source) (*obi.Config, error) {
	cfg, version, err := configload.LoadSources(sources)
	if err != nil {
		return nil, err
	}
	if version != configload.VersionV2 {
		return nil, errors.New("configuration version changed; restart OBI to apply this configuration")
	}
	if err := cfg.ValidateStaticForApplicationRefresh(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func readSources(paths []string) ([]configload.Source, error) {
	sources := make([]configload.Source, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sources = append(sources, configload.Source{Path: path, Data: data})
	}
	return sources, nil
}

func sourcePaths(sources []configload.Source) []string {
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		paths = append(paths, source.Path)
	}
	return paths
}

func equalContents(a, b []configload.Source) bool {
	return slices.EqualFunc(a, b, func(x, y configload.Source) bool {
		return x.Path == y.Path && bytes.Equal(x.Data, y.Data)
	})
}

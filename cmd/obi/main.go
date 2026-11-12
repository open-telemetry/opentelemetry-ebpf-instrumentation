// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	otelsdk "go.opentelemetry.io/otel/sdk"

	"go.opentelemetry.io/obi/cmd/obi/internal/configcmd"
	"go.opentelemetry.io/obi/cmd/obi/internal/configload"
	"go.opentelemetry.io/obi/cmd/obi/internal/configwatch"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/kube/klogbridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	configVersionV1 = configload.VersionV1
	configVersionV2 = configload.VersionV2
)

// configPathEnv holds a comma-separated list of configuration files with higher priority than
// the -config flags.
const configPathEnv = "OTEL_EBPF_CONFIG_PATH"

// configPaths collects the paths of the repeatable -config flag.
type configPaths []string

func (p *configPaths) String() string {
	return strings.Join(*p, ",")
}

func (p *configPaths) Set(path string) error {
	*p = append(*p, path)
	return nil
}

// configFilePaths returns the configuration files in increasing order of priority.
func configFilePaths(flagPaths []string, envPaths string) []string {
	paths := slices.Clone(flagPaths)
	for path := range strings.SplitSeq(envPaths, ",") {
		if path = strings.TrimSpace(path); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func loadConfig(paths []string) (*obi.Config, string, []configload.Source) {
	sources := make([]configload.Source, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("can't open "+path, "error", err)
			os.Exit(-1)
		}
		sources = append(sources, configload.Source{Path: path, Data: data})
	}

	config, version, err := configload.LoadSources(sources)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}
	return config, version, sources
}

func main() {
	if handled, exitCode := configcmd.MaybeRun(os.Args[1:], os.Stdout, os.Stderr); handled {
		if exitCode != configcmd.ExitSuccess {
			os.Exit(exitCode)
		}
		return
	}

	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)

	var flagPaths configPaths
	flag.Var(&flagPaths, "config", "path to a configuration file; repeat it to override the previous files")
	flag.Parse()

	config, configVersion, configSources := loadConfig(configFilePaths(flagPaths, os.Getenv(configPathEnv)))
	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}

	var logHandler slog.Handler
	switch obi.LogFormat(strings.ToLower(string(config.LogFormat))) {
	default:
		slog.Warn("unknown log format specified, defaulting to text", "format", config.LogFormat)
		fallthrough
	case obi.LogFormatText:
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: &lvl,
		})
	case obi.LogFormatJSON:
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: &lvl,
		})
	}
	slog.SetDefault(slog.New(logHandler))
	klogbridge.Install()

	slog.Info("OpenTelemetry eBPF Instrumentation", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())
	slog.Info("configuration loaded", "version", configVersion)

	if err := obi.CheckOSSupport(); err != nil {
		slog.Error("can't start OpenTelemetry eBPF Instrumentation", "error", err)
		os.Exit(-1)
	}

	if err := config.Validate(); err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}

	if err := obi.CheckOSCapabilities(config); err != nil {
		if config.EnforceSysCaps {
			slog.Error("can't start OpenTelemetry eBPF Instrumentation", "error", err)
			os.Exit(-1)
		}

		slog.Warn("Required system capabilities not present, OpenTelemetry eBPF Instrumentation may malfunction", "error", err)
	}

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", "error", err)
		}()
	}

	config.Log()

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	var opts []instrumenter.Option
	if configVersion == configVersionV2 && len(configSources) > 0 && config.Enabled(obi.FeatureAppO11y) {
		updater := discover.NewCriteriaUpdater(config)
		opts = append(opts, instrumenter.WithCriteriaUpdater(updater))
		go configwatch.Watch(ctx, configSources, updater.Update)
	}
	var runErr error
	if configVersion == configVersionV2 {
		selection := instrumentations.NewInstrumentationSelection(config.OTELMetrics.Instrumentations)
		runErr = instrumenter.RunWithProtocolMetricSelection(ctx, config, nil, &selection, opts...)
	} else {
		runErr = instrumenter.Run(ctx, config)
	}

	if err := runErr; err != nil {
		slog.Error("OpenTelemetry eBPF Instrumentation ran with errors", "error", err)
		os.Exit(-1)
	}
	slog.Info("OpenTelemetry eBPF Instrumentation successfully exiting")
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	otelsdk "go.opentelemetry.io/otel/sdk"

	"go.opentelemetry.io/obi/cmd/obi/internal/configcmd"
	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/kube/klogbridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	configVersionV1 = "v1"
	configVersionV2 = "v2"
)

func loadConfig(configPath *string) (*obi.Config, string) {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}

	config, version, err := loadConfigReader(configReader)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		//nolint:gocritic
		os.Exit(-1)
	}
	return config, version
}

func loadConfigReader(file io.Reader) (*obi.Config, string, error) {
	var data []byte
	fileProvided := file != nil
	if fileProvided {
		var err error
		data, err = io.ReadAll(file)
		if err != nil {
			return nil, "", fmt.Errorf("reading configuration: %w", err)
		}
	}

	doc, _, err := schema.ParseStandaloneYAML(obicfg.ReplaceEnv(data))
	if err == nil {
		config, err := convert.DocumentToRuntime(doc)
		if err != nil {
			return nil, "", fmt.Errorf("loading config v2: %w", err)
		}
		return config, configVersionV2, nil
	}

	var notV2 *schema.NotV2Error
	if !errors.As(err, &notV2) {
		return nil, "", fmt.Errorf("loading config v2: %w", err)
	}

	var legacyReader io.Reader
	if fileProvided {
		legacyReader = bytes.NewReader(data)
	}
	config, err := obi.LoadConfig(legacyReader)
	if err != nil {
		return nil, "", fmt.Errorf("loading config v1: %w", err)
	}
	return config, configVersionV1, nil
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

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	if cfg := os.Getenv("OTEL_EBPF_CONFIG_PATH"); cfg != "" {
		configPath = &cfg
	}
	config, configVersion := loadConfig(configPath)
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

	if err := instrumenter.Run(ctx, config); err != nil {
		slog.Error("OpenTelemetry eBPF Instrumentation ran with errors", "error", err)
		os.Exit(-1)
	}
	slog.Info("OpenTelemetry eBPF Instrumentation successfully exiting")
}

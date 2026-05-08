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

	obiconfigv2 "go.opentelemetry.io/obi/internal/obiconfigv2"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/instrumenter"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func main() {
	if maybeRunConfigCommand(os.Args[1:]) {
		return
	}

	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	if cfg := os.Getenv("OTEL_EBPF_CONFIG_PATH"); cfg != "" {
		configPath = &cfg
	}
	config := loadConfig(configPath)
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

	slog.Info("OpenTelemetry eBPF Instrumentation", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())

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

func loadConfig(configPath *string) *obi.Config {
	var configReader io.ReadCloser
	var configBytes []byte
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
		defer configReader.Close()
		configBytes, err = io.ReadAll(configReader)
		if err != nil {
			slog.Error("can't read "+*configPath, "error", err)
			os.Exit(-1)
		}
	}

	if len(configBytes) > 0 {
		if doc, _, err := obiv2.ParseYAML(configBytes, obiv2.DeploymentModeStandalone); err == nil {
			config, adaptErr := obiconfigv2.StandaloneToRuntime(doc)
			if adaptErr != nil {
				slog.Error("wrong configuration", "error", adaptErr)
				os.Exit(-1)
			}
			return config
		} else {
			var notV2 *obiv2.NotV2Error
			if !errors.As(err, &notV2) {
				slog.Error("wrong configuration", "error", err)
				os.Exit(-1)
			}
		}
	}

	config, err := obi.LoadConfig(bytesReader(configBytes))
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		//nolint:gocritic
		os.Exit(-1)
	}
	return config
}

func bytesReader(data []byte) io.Reader {
	if len(data) == 0 {
		return nil
	}
	return bytes.NewReader(data)
}

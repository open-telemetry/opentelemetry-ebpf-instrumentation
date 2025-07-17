package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	otelsdk "go.opentelemetry.io/otel/sdk"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/buildinfo"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/instrumenter"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
)

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	slog.Info("OpenTelemetry eBPF Instrumentation", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())

	if err := obi.CheckOSSupport(); err != nil {
		slog.Error("can't start OpenTelemetry eBPF Instrumentation", "error", err)
		os.Exit(-1)
	}

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	if cfg := os.Getenv("OTEL_EBPF_CONFIG_PATH"); cfg != "" {
		configPath = &cfg
	}

	config := loadConfig(configPath)
	if err := config.Validate(); err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}

	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
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

	if config.LogConfig {
		configYaml, err := yaml.Marshal(config)
		if err != nil {
			slog.Warn("can't marshal configuration to YAML", "error", err)
		}
		slog.Info("Running OpenTelemetry eBPF Instrumentation with configuration")
		fmt.Println(string(configYaml))
	}

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	if err := instrumenter.Run(ctx, config); err != nil {
		slog.Error("OpenTelemetry eBPF Instrumentation ran with errors", "error", err)
		os.Exit(-1)
	}

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}

func loadConfig(configPath *string) *obi.Config {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}
	config, err := obi.LoadConfig(configReader)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		//nolint:gocritic
		os.Exit(-1)
	}
	return config
}

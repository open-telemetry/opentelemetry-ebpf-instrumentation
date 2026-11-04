// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
)

// main code of the central metadata service, which collects the metadata published by
// each OBI instance and serves it to the instances that look it up.

func main() {
	lvl := slog.LevelVar{}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &lvl})))

	slog.Info("OBI's central metadata service", "Version", buildinfo.Version, "Revision", buildinfo.Revision)

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if path := os.Getenv("OTEL_EBPF_METADATA_SERVICE_CONFIG_PATH"); path != "" {
		configPath = &path
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}

	if err := lvl.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}

	if err := run(&cfg); err != nil {
		slog.Error("running metadata service", "error", err)
		os.Exit(-1)
	}

	slog.Info("service stopped. Exiting now")
}

func run(cfg *peer.CentralServerConfig) error {
	server, err := peer.NewCentralServer(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.Run(ctx)
}

func loadConfig(path string) (peer.CentralServerConfig, error) {
	var file io.Reader
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return peer.CentralServerConfig{}, err
		}
		defer f.Close()
		file = f
	}

	return peer.LoadCentralServerConfig(file)
}

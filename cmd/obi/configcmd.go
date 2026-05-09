// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"gopkg.in/yaml.v3"

	obiconfigv2 "go.opentelemetry.io/obi/internal/obiconfigv2"
	"go.opentelemetry.io/obi/pkg/obi"
	obiv2 "go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

func maybeRunConfigCommand(args []string) bool {
	if len(args) == 0 || args[0] != "config" {
		return false
	}

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: obi config <validate|migrate> ...")
		os.Exit(2)
	}

	switch args[1] {
	case "validate":
		runConfigValidate(args[2:])
	case "migrate":
		runConfigMigrate(args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand %q\n", args[1])
		os.Exit(2)
	}

	return true
}

func runConfigValidate(args []string) {
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	mode := fs.String("mode", string(obiv2.DeploymentModeStandalone), "validation mode: standalone or receiver")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: obi config validate [--mode=standalone|receiver] <path>")
		os.Exit(2)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch obiv2.DeploymentMode(*mode) {
	case obiv2.DeploymentModeStandalone:
		if err := validateStandaloneConfig(data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case obiv2.DeploymentModeReceiver:
		if err := validateReceiverConfig(data); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "invalid mode %q\n", *mode)
		os.Exit(2)
	}
}

func validateStandaloneConfig(data []byte) error {
	doc, _, err := obiv2.ParseYAML(data, obiv2.DeploymentModeStandalone)
	if err == nil {
		cfg, err := obiconfigv2.StandaloneToRuntime(doc)
		if err != nil {
			return err
		}
		return cfg.Validate()
	}

	var notV2 *obiv2.NotV2Error
	if !errors.As(err, &notV2) {
		return err
	}

	cfg, err := obi.LoadConfig(bytesReader(data))
	if err != nil {
		return err
	}
	cfg.Traces.TracesConsumer = consumertest.NewNop()
	cfg.OTELMetrics.MetricsConsumer = consumertest.NewNop()
	return cfg.Validate()
}

func validateReceiverConfig(data []byte) error {
	_, ext, err := obiv2.ParseYAML(data, obiv2.DeploymentModeReceiver)
	if err == nil {
		cfg, err := obiconfigv2.ConfigToRuntime(ext, obiv2.DeploymentModeReceiver)
		if err != nil {
			return err
		}
		return cfg.Validate()
	}

	var notV2 *obiv2.NotV2Error
	if !errors.As(err, &notV2) {
		return err
	}

	cfg, err := obi.LoadConfig(bytesReader(data))
	if err != nil {
		return err
	}
	cfg.Traces.TracesConsumer = consumertest.NewNop()
	cfg.OTELMetrics.MetricsConsumer = consumertest.NewNop()
	return cfg.Validate()
}

func runConfigMigrate(args []string) {
	fs := flag.NewFlagSet("config migrate", flag.ExitOnError)
	from := fs.String("from", "v1", "source config version")
	to := fs.String("to", "v2", "destination config version")
	fs.Parse(args)

	if *from != "v1" || *to != "v2" {
		fmt.Fprintln(os.Stderr, "only --from v1 --to v2 is currently supported")
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: obi config migrate --from v1 --to v2 <path>")
		os.Exit(2)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	encoded, report, err := migrateConfigData(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if report != "" {
		fmt.Fprint(os.Stderr, report)
	}
	fmt.Fprint(os.Stdout, encoded)
}

func marshalCanonicalV2(doc *obiv2.Document) (string, error) {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func migrateConfigData(data []byte) (string, string, error) {
	if doc, _, err := obiv2.ParseYAML(data, obiv2.DeploymentModeStandalone); err == nil {
		encoded, encodeErr := marshalCanonicalV2(doc)
		return encoded, "", encodeErr
	}

	cfg, err := obi.LoadConfig(bytesReader(data))
	if err != nil {
		return "", "", err
	}

	doc, err := obiconfigv2.RuntimeToDocument(cfg)
	if err != nil {
		return "", "", err
	}
	encoded, err := marshalCanonicalV2(doc)
	if err != nil {
		return "", "", err
	}

	report := "" +
		"migrated v1 config to canonical v2\n" +
		"mapping report:\n" +
		"- legacy runtime config parsed through pkg/obi.Config\n" +
		"- OTel pipeline sections emitted at top level: tracer_provider, meter_provider\n" +
		"- OBI-owned capture, enrich, correlation, and daemon settings emitted under extensions.obi\n" +
		"- application and network attribute filters fanned out to signal-scoped v2 filter blocks\n" +
		"- discovery.skip_go_specific_tracers inverted into capture.runtimes.go.enabled\n"

	return encoded, report, nil
}

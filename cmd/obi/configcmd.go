// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"go.opentelemetry.io/obi/internal/config/convert"
	configschema "go.opentelemetry.io/obi/internal/config/schema"
)

const (
	configCommandExitSuccess = 0
	configCommandExitFailure = 1
	configCommandExitUsage   = 2
)

type configValidationMode string

const (
	configValidationModeStandalone configValidationMode = "standalone"
	configValidationModeReceiver   configValidationMode = "receiver"
)

func runConfigCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || args[0] != "config" {
		return false, configCommandExitSuccess
	}

	if len(args) < 2 {
		configCommandUsage(stderr)
		return true, configCommandExitUsage
	}

	switch args[1] {
	case "help", "-h", "--help":
		configCommandUsage(stdout)
		return true, configCommandExitSuccess
	case "validate":
		return true, runConfigValidate(args[2:], stdout, stderr)
	case "migrate":
		return true, runConfigMigrate(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config subcommand %q\n", args[1])
		configCommandUsage(stderr)
		return true, configCommandExitUsage
	}
}

func configCommandUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: obi config <validate|migrate> ...")
}

func runConfigValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: obi config validate [--mode=standalone|receiver] <path>")
	}
	mode := flags.String("mode", string(configValidationModeStandalone), "validation mode: standalone or receiver")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return configCommandExitSuccess
		}
		return configCommandExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return configCommandExitUsage
	}

	validationMode := configValidationMode(*mode)
	if validationMode != configValidationModeStandalone && validationMode != configValidationModeReceiver {
		fmt.Fprintf(stderr, "invalid validation mode %q: expected standalone or receiver\n", *mode)
		return configCommandExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "read configuration: %v\n", err)
		return configCommandExitFailure
	}
	if err := validateConfigData(data, validationMode); err != nil {
		fmt.Fprintf(stderr, "invalid configuration: %v\n", err)
		return configCommandExitFailure
	}

	fmt.Fprintln(stdout, "configuration is valid")
	return configCommandExitSuccess
}

func validateConfigData(data []byte, mode configValidationMode) error {
	switch mode {
	case configValidationModeStandalone:
		doc, _, err := configschema.ParseStandaloneYAML(data)
		if err != nil {
			return err
		}
		if _, err := convert.DocumentToRuntime(doc); err != nil {
			return err
		}
	case configValidationModeReceiver:
		ext, err := configschema.ParseReceiverYAML(data)
		if err != nil {
			return err
		}
		if _, err := convert.V2ToRuntime(ext); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid validation mode %q", mode)
	}
	return nil
}

func runConfigMigrate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: obi config migrate [--from=v1] [--to=v2] <path>")
	}
	from := flags.String("from", "v1", "source configuration version")
	to := flags.String("to", "v2", "destination configuration version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return configCommandExitSuccess
		}
		return configCommandExitUsage
	}
	if *from != "v1" || *to != "v2" {
		fmt.Fprintln(stderr, "only migration from v1 to v2 is supported")
		return configCommandExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return configCommandExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "read configuration: %v\n", err)
		return configCommandExitFailure
	}
	encoded, report, err := migrateConfigData(data)
	if err != nil {
		fmt.Fprintf(stderr, "migrate configuration: %v\n", err)
		return configCommandExitFailure
	}

	if report != "" {
		fmt.Fprint(stderr, report)
	}
	fmt.Fprint(stdout, encoded)
	return configCommandExitSuccess
}

func migrateConfigData(data []byte) (string, string, error) {
	encoded, notices, err := convert.MigrateV1YAML(data)
	if err != nil {
		return "", "", err
	}

	var report strings.Builder
	report.WriteString("migrated v1 configuration to config v2\n")
	report.WriteString("mapping report:\n")
	if len(notices) == 0 {
		report.WriteString("- no non-trivial structural rewrites detected\n")
	} else {
		for _, notice := range notices {
			fmt.Fprintf(&report, "- %s: %s\n", notice.Source, notice.Message)
		}
	}
	return string(encoded), report.String(), nil
}

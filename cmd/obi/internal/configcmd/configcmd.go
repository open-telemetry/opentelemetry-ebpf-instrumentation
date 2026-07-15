// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configcmd // import "go.opentelemetry.io/obi/cmd/obi/internal/configcmd"

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	featureexport "go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	ExitSuccess = 0
	ExitError   = 1
	ExitUsage   = 2
)

type validationMode string

const (
	validationModeStandalone validationMode = "standalone"
	validationModeReceiver   validationMode = "receiver"
)

// MaybeRun handles an obi config command and reports whether args selected the
// config command group.
func MaybeRun(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || args[0] != "config" {
		return false, ExitSuccess
	}
	return true, run(args[1:], stdout, stderr)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: obi config <validate|migrate> ...")
		return ExitUsage
	}

	switch args[0] {
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "migrate":
		return runMigrate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config subcommand %q\n", args[0])
		return ExitUsage
	}
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: obi config validate [--mode=standalone|receiver] <path>")
		flags.PrintDefaults()
	}
	mode := flags.String("mode", string(validationModeStandalone), "validation mode: standalone or receiver")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitUsage
	}
	selectedMode := validationMode(*mode)
	if selectedMode != validationModeStandalone && selectedMode != validationModeReceiver {
		fmt.Fprintf(stderr, "invalid validation mode %q; expected standalone or receiver\n", *mode)
		return ExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "validation failed: read %s: %v\n", flags.Arg(0), err)
		return ExitError
	}
	if err := validateConfig(data, selectedMode); err != nil {
		fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return ExitError
	}

	fmt.Fprintln(stdout, "configuration is valid")
	return ExitSuccess
}

var errInvalidMode = errors.New("invalid validation mode")

func validateConfig(data []byte, mode validationMode) error {
	data = obiconfig.ReplaceEnv(data)

	var cfg *obi.Config
	var err error
	switch mode {
	case validationModeStandalone:
		var doc *schema.Document
		doc, _, err = schema.ParseStandaloneYAML(data)
		if err == nil {
			cfg, err = convert.DocumentToRuntime(doc)
		}
	case validationModeReceiver:
		var ext *schema.Extension
		ext, err = schema.ParseReceiverYAML(data)
		if err == nil {
			cfg, err = convert.V2ToRuntime(ext)
		}
	default:
		return fmt.Errorf("%w %q; expected standalone or receiver", errInvalidMode, mode)
	}
	if err != nil {
		return err
	}
	if mode == validationModeReceiver {
		err = cfg.ValidateForReceiver()
	} else {
		err = cfg.Validate()
	}
	if err != nil {
		return fmt.Errorf("runtime configuration: %w", err)
	}
	return nil
}

func runMigrate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("obi config migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: obi config migrate [--from=v1] [--to=v2] <path>")
		flags.PrintDefaults()
	}
	from := flags.String("from", "v1", "source config version")
	to := flags.String("to", "v2", "destination config version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
		return ExitUsage
	}
	if *from != "v1" || *to != "v2" {
		fmt.Fprintln(stderr, "only --from=v1 --to=v2 is supported")
		return ExitUsage
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return ExitUsage
	}

	data, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "migration failed: read %s: %v\n", flags.Arg(0), err)
		return ExitError
	}
	output, report, err := migrateConfig(data)
	if err != nil {
		fmt.Fprintf(stderr, "migration failed: %v\n", err)
		return ExitError
	}
	if _, err := stdout.Write(output); err != nil {
		fmt.Fprintf(stderr, "migration failed: write output: %v\n", err)
		return ExitError
	}
	if report != "" {
		fmt.Fprint(stderr, report)
	}
	return ExitSuccess
}

func migrateConfig(data []byte) ([]byte, string, error) {
	replaced := obiconfig.ReplaceEnv(data)
	if _, _, err := schema.ParseStandaloneYAML(replaced); err == nil {
		return nil, "", errors.New("input is already a standalone OBI config v2 document")
	} else {
		var notV2 *schema.NotV2Error
		if !errors.As(err, &notV2) {
			return nil, "", fmt.Errorf("source is not supported v1 YAML: %w", err)
		}
	}
	cfg, err := loadV1Config(replaced)
	if err != nil {
		return nil, "", err
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("v1 runtime configuration: %w", err)
	}

	doc, _ := convert.RuntimeToV2(cfg)
	output, err := yaml.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("encode config v2 YAML: %w", err)
	}
	if err := validateConfig(output, validationModeStandalone); err != nil {
		return nil, "", fmt.Errorf("migrated config v2 did not validate: %w", err)
	}

	roundTripped, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return nil, "", fmt.Errorf("verify migrated config v2: %w", err)
	}
	unsupported, err := changedInputFields(replaced, cfg, roundTripped)
	if err != nil {
		return nil, "", fmt.Errorf("verify migrated fields: %w", err)
	}
	if len(unsupported) != 0 {
		return nil, "", fmt.Errorf(
			"fields are outside the supported v1-to-v2 migration contract: %s",
			strings.Join(unsupported, ", "),
		)
	}

	return output, migrationReport(replaced), nil
}

func loadV1Config(data []byte) (*obi.Config, error) {
	cfg := obi.DefaultConfig
	if cfg.Routes != nil {
		routes := *cfg.Routes
		cfg.Routes = &routes
	}
	if cfg.NameResolver != nil {
		nameResolver := *cfg.NameResolver
		cfg.NameResolver = &nameResolver
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &cfg, nil
	}
	decoder := legacyyaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode v1 YAML fields: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("v1 YAML must contain exactly one document")
		}
		return nil, fmt.Errorf("decode trailing v1 YAML: %w", err)
	}

	cfg.Attributes.Select.Normalize()
	if cfg.OTELMetrics.EndpointEnabled() && cfg.OTELMetrics.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.OTELMetrics.DeprFeatures
	} else if cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.DeprFeatures != 0 {
		cfg.Metrics.Features = cfg.Prometheus.DeprFeatures
	}
	if cfg.NetworkFlows.Enable {
		cfg.Metrics.Features |= featureexport.FeatureNetwork
	}

	return &cfg, nil
}

type yamlPath []any

func changedInputFields(data []byte, before, after *obi.Config) ([]string, error) {
	var source any
	if len(bytes.TrimSpace(data)) != 0 {
		if err := yaml.Unmarshal(data, &source); err != nil {
			return nil, err
		}
	}
	beforeMap, err := configMap(before)
	if err != nil {
		return nil, err
	}
	afterMap, err := configMap(after)
	if err != nil {
		return nil, err
	}

	var changed []string
	for _, path := range leafPaths(source, nil) {
		name := formatPath(path)
		if migrationAlias(name) {
			continue
		}
		beforeValue, beforeOK := valueAtPath(beforeMap, path)
		afterValue, afterOK := valueAtPath(afterMap, path)
		if beforeOK != afterOK || !reflect.DeepEqual(beforeValue, afterValue) {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

func configMap(cfg *obi.Config) (any, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func leafPaths(value any, prefix yamlPath) []yamlPath {
	switch value := value.(type) {
	case map[string]any:
		if len(value) == 0 {
			return []yamlPath{prefix}
		}
		var paths []yamlPath
		for key, child := range value {
			paths = append(paths, leafPaths(child, appendPath(prefix, key))...)
		}
		return paths
	case []any:
		if len(value) == 0 {
			return []yamlPath{prefix}
		}
		var paths []yamlPath
		for index, child := range value {
			paths = append(paths, leafPaths(child, appendPath(prefix, index))...)
		}
		return paths
	default:
		return []yamlPath{prefix}
	}
}

func appendPath(prefix yamlPath, part any) yamlPath {
	out := make(yamlPath, len(prefix), len(prefix)+1)
	copy(out, prefix)
	return append(out, part)
}

func valueAtPath(value any, path yamlPath) (any, bool) {
	for _, part := range path {
		switch part := part.(type) {
		case string:
			mapping, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			value, ok = mapping[part]
			if !ok {
				return nil, false
			}
		case int:
			sequence, ok := value.([]any)
			if !ok || part >= len(sequence) {
				return nil, false
			}
			value = sequence[part]
		}
	}
	return value, true
}

func formatPath(path yamlPath) string {
	var out strings.Builder
	for _, part := range path {
		switch part := part.(type) {
		case string:
			if out.Len() != 0 {
				out.WriteByte('.')
			}
			out.WriteString(part)
		case int:
			fmt.Fprintf(&out, "[%d]", part)
		}
	}
	return out.String()
}

func migrationAlias(path string) bool {
	for _, prefix := range []string{
		"executable_path",
		"open_port",
		"target_pids",
		"network.enable",
		"otel_metrics_export.features",
		"prometheus_export.features",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"[") {
			return true
		}
	}
	return false
}

func migrationReport(data []byte) string {
	var root map[string]any
	_ = yaml.Unmarshal(data, &root)

	lines := []string{"migrated v1 config to OBI config v2"}
	if hasAnyPath(root, "filter.application", "filter.network", "filter.stats") {
		lines = append(lines, "- fanned out v1 attribute filters to signal-scoped v2 filters")
	}
	if hasAnyPath(root, "discovery.instrument", "discovery.services", "discovery.exclude_instrument", "discovery.exclude_services") {
		lines = append(lines, "- reshaped effective discovery selectors into capture.rules")
	}
	if hasAnyPath(root, "discovery.skip_go_specific_tracers") {
		lines = append(lines, "- inverted discovery.skip_go_specific_tracers into capture.runtimes.go.enabled")
	}
	if hasAnyPath(root, "otel_traces_export", "otel_metrics_export", "prometheus_export") {
		lines = append(lines, "- moved exporter configuration into top-level OpenTelemetry providers")
	}
	return strings.Join(lines, "\n") + "\n"
}

func hasAnyPath(root map[string]any, paths ...string) bool {
	for _, path := range paths {
		var current any = root
		found := true
		for _, part := range strings.Split(path, ".") {
			mapping, ok := current.(map[string]any)
			if !ok {
				found = false
				break
			}
			current, ok = mapping[part]
			if !ok {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

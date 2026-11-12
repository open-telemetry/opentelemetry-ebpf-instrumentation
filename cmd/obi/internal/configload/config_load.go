// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload // import "go.opentelemetry.io/obi/cmd/obi/internal/configload"

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

// minimalV2Document produces the v2 defaults when converted.
var minimalV2Document = fmt.Appendf(nil, "file_format: %q\nextensions:\n  obi:\n    version: %q\n",
	schema.SupportedFileFormat, schema.SupportedVersion)

// Source is the contents of one configuration file.
type Source struct {
	Path string
	Data []byte
}

// LoadV2 expands environment variables and converts a standalone v2 document.
// Runtime validation is left to the startup or refresh caller.
func LoadV2(data []byte) (*obi.Config, error) {
	doc, _, err := schema.ParseStandaloneYAML(obicfg.ReplaceEnv(data))
	if err != nil {
		return nil, fmt.Errorf("loading config v2: %w", err)
	}
	cfg, err := convert.DocumentToRuntime(doc)
	if err != nil {
		return nil, fmt.Errorf("loading config v2: %w", err)
	}
	return cfg, nil
}

// Load converts a v2 document, or a v1 document when the data is not v2.
// Empty data loads the v1 defaults.
func Load(data []byte) (*obi.Config, string, error) {
	config, err := LoadV2(data)
	if err == nil {
		return config, VersionV2, nil
	}

	if _, ok := errors.AsType[*schema.NotV2Error](err); !ok {
		return nil, "", err
	}

	config, err = obi.LoadConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("loading config v1: %w", err)
	}
	return config, VersionV1, nil
}

// LoadSources loads the sources in increasing order of priority. Each source after the first
// overrides the settings whose value differs from the defaults of its own version, so a later
// source cannot reset a setting back to its default value.
// The result has the version of the first source, whose defaults it starts from.
// Without sources, it loads the v1 defaults.
func LoadSources(sources []Source) (*obi.Config, string, error) {
	if len(sources) == 0 {
		return Load(nil)
	}

	config, version, err := loadSource(sources[0])
	if err != nil {
		return nil, "", err
	}

	for _, source := range sources[1:] {
		if err := overrideWithSource(config, source); err != nil {
			return nil, "", err
		}
	}
	return config, version, nil
}

func overrideWithSource(config *obi.Config, source Source) error {
	layer, version, err := loadSource(source)
	if err != nil {
		return err
	}

	defaults, err := versionDefaults(version)
	if err != nil {
		return err
	}

	override(reflect.ValueOf(config).Elem(), reflect.ValueOf(layer).Elem(), reflect.ValueOf(defaults).Elem())
	return nil
}

func loadSource(source Source) (*obi.Config, string, error) {
	config, version, err := Load(source.Data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", source.Path, err)
	}
	return config, version, nil
}

// versionDefaults returns the configuration that a version produces from a document without settings.
func versionDefaults(version string) (*obi.Config, error) {
	if version == VersionV2 {
		return LoadV2(minimalV2Document)
	}
	return obi.LoadConfig(nil)
}

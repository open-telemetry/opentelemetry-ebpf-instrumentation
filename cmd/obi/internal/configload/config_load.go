// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package configload // import "go.opentelemetry.io/obi/cmd/obi/internal/configload"

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

// Source is the contents of one configuration file.
type Source struct {
	Path string
	Data []byte
}

// LoadV2 expands environment variables and converts a standalone v2 document.
// Runtime validation is left to the startup or refresh caller.
func LoadV2(data []byte) (*obi.Config, error) {
	return loadV2Expanded(obicfg.ReplaceEnv(data))
}

func loadV2Expanded(data []byte) (*obi.Config, error) {
	doc, _, err := schema.ParseStandaloneYAML(data)
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
	return loadExpanded(obicfg.ReplaceEnv(data))
}

func loadExpanded(data []byte) (*obi.Config, string, error) {
	config, err := loadV2Expanded(data)
	if err == nil {
		return config, VersionV2, nil
	}

	if _, ok := errors.AsType[*schema.NotV2Error](err); !ok {
		return nil, "", err
	}

	config, err = obi.LoadConfigYAML(data)
	if err != nil {
		return nil, "", fmt.Errorf("loading config v1: %w", err)
	}
	return config, VersionV1, nil
}

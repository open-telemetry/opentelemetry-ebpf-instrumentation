// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer/consumertest"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

type receiverConfig struct {
	runtime *obi.Config
}

func (c *receiverConfig) Unmarshal(component *confmap.Conf) error {
	if component == nil {
		return nil
	}

	data, err := yaml.Marshal(component.ToStringMap())
	if err != nil {
		return fmt.Errorf("marshal OBI receiver config: %w", err)
	}

	extension, err := schema.ParseReceiverYAML(data)
	if err != nil {
		var notV2 *schema.NotV2Error
		if !errors.As(err, &notV2) {
			return fmt.Errorf("parse OBI receiver config v2: %w", err)
		}

		cfg := defaultRuntimeConfig()
		if err := cfg.Unmarshal(component); err != nil {
			return fmt.Errorf("parse legacy OBI receiver config: %w", err)
		}
		c.runtime = cfg
		return nil
	}

	cfg, err := convert.V2ToRuntime(extension)
	if err != nil {
		return fmt.Errorf("convert OBI receiver config v2: %w", err)
	}
	setReceiverConsumers(cfg)
	c.runtime = cfg
	return nil
}

func (c *receiverConfig) Validate() error {
	if c == nil || c.runtime == nil {
		return errInvalidConfig
	}
	return c.runtime.Validate()
}

func defaultRuntimeConfig() *obi.Config {
	cfg := obi.DefaultConfig
	setReceiverConsumers(&cfg)
	return &cfg
}

func setReceiverConsumers(cfg *obi.Config) {
	cfg.Traces.TracesConsumer = consumertest.NewNop()
	cfg.OTELMetrics.MetricsConsumer = consumertest.NewNop()
}

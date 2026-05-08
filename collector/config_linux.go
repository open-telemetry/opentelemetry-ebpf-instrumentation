// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/collector/confmap"

	obiconfigv2 "go.opentelemetry.io/obi/internal/obiconfigv2"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/obiconfig/v2"
)

type receiverConfig struct {
	runtime *obi.Config
}

func newReceiverConfig() *receiverConfig {
	cfg := obi.DefaultConfig
	return &receiverConfig{runtime: &cfg}
}

func (c *receiverConfig) Unmarshal(component *confmap.Conf) error {
	if component == nil {
		return nil
	}

	raw := component.ToStringMap()
	_, ext, err := v2.ParseMap(raw, v2.DeploymentModeReceiver)
	if err == nil {
		runtime, adaptErr := obiconfigv2.ConfigToRuntime(ext, v2.DeploymentModeReceiver)
		if adaptErr != nil {
			return adaptErr
		}
		c.runtime = runtime
		return nil
	}

	var notV2 *v2.NotV2Error
	if !errors.As(err, &notV2) {
		return err
	}

	cfg := obi.DefaultConfig
	if err := cfg.Unmarshal(component); err != nil {
		return fmt.Errorf("decoding legacy receiver config: %w", err)
	}
	cfg.NormalizeForLoad()
	c.runtime = &cfg
	return nil
}

func (c *receiverConfig) Validate() error {
	if c == nil || c.runtime == nil {
		return errInvalidConfig
	}
	return c.runtime.Validate()
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestJobTracesEnabledByDefault(t *testing.T) {
	off := &services.JobTracesConfig{Enabled: false}
	allOff := services.GlobDefinitionCriteria{{Path: services.NewGlob("*"), JobTraces: off}}

	for _, tc := range []struct {
		name    string
		set     func(*Config)
		enabled bool
	}{
		{name: "nothing selected", set: func(*Config) {}, enabled: false},
		{name: "instrument selector", set: func(c *Config) {
			c.Discovery.Instrument = services.GlobDefinitionCriteria{{Path: services.NewGlob("*")}}
		}, enabled: true},
		{name: "services selector", set: func(c *Config) {
			c.Discovery.Services = services.RegexDefinitionCriteria{{Path: services.NewRegexp(".*")}}
		}, enabled: true},
		{name: "every selector turned off", set: func(c *Config) {
			c.Discovery.Instrument = allOff
		}, enabled: false},
		{name: "target executable", set: func(c *Config) {
			c.Discovery.Instrument = allOff
			c.AutoTargetExe = services.NewGlob("*/worker")
		}, enabled: true},
		{name: "target PIDs", set: func(c *Config) {
			c.Discovery.Instrument = allOff
			c.TargetPIDs = services.IntEnum{Ranges: []services.IntRange{{Start: 1234}}}
		}, enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig
			tc.set(&cfg)
			require.Equal(t, tc.enabled, cfg.JobTracesEnabled())
		})
	}
}

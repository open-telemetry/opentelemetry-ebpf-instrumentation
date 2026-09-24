// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDaphneOptions(t *testing.T) {
	const application = "orders.asgi:application"
	optionsWithValues := []string{
		"-p", "--port", "-b", "--bind", "--websocket_timeout", "--websocket_connect_timeout", "-u",
		"--unix-socket", "--fd", "-e", "--endpoint", "-v", "--verbosity", "-t", "--http-timeout",
		"--access-log", "--log-fmt", "--ping-interval", "--ping-timeout", "--websocket-max-message-size",
		"--websocket-max-frame-size", "--application-close-timeout", "--root-path", "--proxy-headers-host",
		"--proxy-headers-port", "-s", "--server-name",
	}
	assert.Equal(t, optionSet(optionsWithValues...), daphneOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseDaphne([]string{option, "env:prod", application})

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	optionsWithoutValues := []string{"--proxy-headers", "--no-server-name", "-h", "--help"}
	assert.Equal(t, optionSet(optionsWithoutValues...), daphneOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseDaphne([]string{option, application})

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseDaphneFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.asgi:application"
	tests := map[string][]string{
		"long option":               {"--future-option", "env:prod", application},
		"attached long option":      {"--future-option=env:prod", application},
		"short option":              {"-Z", "env:prod", application},
		"short option cluster":      {"-hZ", application},
		"after application":         {application, "--future-option", "env:prod"},
		"value on flag":             {"--proxy-headers=true", application},
		"missing value":             {application, "--port"},
		"unknown option as value":   {"--access-log", "--future-option", "env:prod", application},
		"removed proxy header name": {"--proxy-forwarded-address-header", "X-Forwarded-For", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseDaphne(args))
		})
	}
}

func TestParseDaphneAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.asgi:application"
	tests := map[string][]string{
		"stdout access log":        {"--access-log", "-", application},
		"attached stdout log":      {"--access-log=-", application},
		"attached long value":      {"--port=8000", application},
		"attached short value":     {"-p8000", application},
		"short value with equals":  {"-p=8000", application},
		"negative timeout":         {"--websocket_timeout", "-1", application},
		"option after application": {application, "--ping-interval", "30"},
		"after terminator":         {"--", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseDaphne(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

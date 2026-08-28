// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHypercornOptions(t *testing.T) {
	const application = "orders.asgi:app"
	optionsWithValues := []string{
		"--access-log", "--access-logfile", "--access-logformat", "--backlog", "-b", "--bind", "--ca-certs",
		"--certfile", "--cert-reqs", "--ciphers", "-c", "--config", "--error-log", "--error-logfile", "--log-file",
		"--graceful-timeout", "--read-timeout", "--max-requests", "--max-requests-jitter", "-g", "--group", "-k",
		"--worker-class", "--keep-alive", "--keyfile", "--keyfile-password", "--insecure-bind", "--log-config",
		"--log-level", "-p", "--pid", "--quic-bind", "--root-path", "--server-name", "--statsd-host",
		"--statsd-prefix", "-m", "--umask", "-u", "--user", "--verify-mode", "--websocket-ping-interval", "-w",
		"--workers",
	}
	assert.Equal(t, optionSet(optionsWithValues...), hypercornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseHypercorn([]string{option, "env:prod", application})

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	optionsWithoutValues := []string{"-D", "--daemon", "--debug", "--reload", "-h", "--help"}
	assert.Equal(t, optionSet(optionsWithoutValues...), hypercornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseHypercorn([]string{option, application})

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseHypercornApplicationForms(t *testing.T) {
	tests := []struct {
		name        string
		application string
		target      string
		kind        TargetKind
	}{
		{name: "default app object", application: "company.orders.api", target: "company.orders.api", kind: TargetModule},
		{name: "explicit app object", application: "company.orders.api:app", target: "company.orders.api:app", kind: TargetModule},
		{name: "file app", application: "src/api.py:app", target: "src/api.py:app", kind: TargetFile},
		{name: "asgi mode", application: "asgi:company.orders.api:app", target: "company.orders.api:app", kind: TargetModule},
		{name: "wsgi file mode", application: "wsgi:src/api.py:app", target: "src/api.py:app", kind: TargetFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := ParseHypercorn([]string{"--workers", "4", tt.application})

			assert.Equal(t, tt.target, launch.Target)
			assert.Equal(t, tt.kind, launch.TargetKind)
			assert.Equal(t, []string{"."}, launch.SearchPaths)
		})
	}
}

func TestParseHypercornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.asgi:app"
	tests := map[string][]string{
		"long option":                {"--future-option", "env:prod", application},
		"attached long option":       {"--future-option=env:prod", application},
		"short option":               {"-Z", "env:prod", application},
		"short option cluster":       {"-DZ", application},
		"after application":          {application, "--future-option", "env:prod"},
		"value on flag":              {"--reload=true", application},
		"missing value":              {application, "--workers"},
		"unknown option as value":    {"--access-logfile", "--future-option", "env:prod", application},
		"invalid cipher option":      {"--cipher", "env:prod", application},
		"unsupported paste option":   {"--paste", "config:prod", application},
		"unsupported version option": {"--version", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseHypercorn(args))
		})
	}
}

func TestParseHypercornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.asgi:app"
	tests := map[string][]string{
		"stdout access log":        {"--access-logfile", "-", application},
		"attached stdout log":      {"--access-logfile=-", application},
		"python config":            {"--config", "python:settings", application},
		"attached python config":   {"--config=python:settings", application},
		"attached long value":      {"--workers=4", application},
		"attached short value":     {"-w4", application},
		"short value with equals":  {"-w=4", application},
		"short option cluster":     {"-Dw4", application},
		"negative long value":      {"--read-timeout", "-1", application},
		"negative short value":     {"-w", "-1", application},
		"option after application": {application, "--access-logfile", "-"},
		"after terminator":         {"--", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseHypercorn(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

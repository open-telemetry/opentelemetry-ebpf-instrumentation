// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUvicornOptions(t *testing.T) {
	const application = "orders.api:app"
	optionsWithValues := []string{
		"--host", "--port", "--uds", "--fd", "--reload-dir", "--reload-include", "--reload-exclude",
		"--reload-delay", "--workers", "--loop", "--http", "--ws", "--ws-max-size", "--ws-max-queue",
		"--ws-ping-interval", "--ws-ping-timeout", "--ws-per-message-deflate", "--lifespan", "--interface",
		"--env-file", "--log-config", "--log-level", "--forwarded-allow-ips", "--root-path",
		"--limit-concurrency", "--backlog", "--limit-max-requests", "--limit-max-requests-jitter",
		"--timeout-keep-alive", "--timeout-graceful-shutdown", "--timeout-worker-healthcheck", "--ssl-keyfile",
		"--ssl-certfile", "--ssl-keyfile-password", "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs",
		"--ssl-ciphers", "--header", "--app-dir", "--h11-max-incomplete-event-size",
	}
	assert.Equal(t, optionSet(optionsWithValues...), uvicornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseUvicorn([]string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	optionsWithoutValues := []string{
		"--reload", "--access-log", "--no-access-log", "--use-colors", "--no-use-colors", "--proxy-headers",
		"--no-proxy-headers", "--server-header", "--no-server-header", "--date-header", "--no-date-header",
		"--version", "--reset-contextvars", "--factory", "--help",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), uvicornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseUvicorn([]string{option, application}, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseUvicornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.api:app"
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "long option", args: []string{"--future-option", "env:prod", application}},
		{name: "attached long option", args: []string{"--future-option=env:prod", application}},
		{name: "short option", args: []string{"-Z", "env:prod", application}},
		{name: "after application", args: []string{application, "--future-option", "env:prod"}},
		{name: "value on flag", args: []string{"--reload=true", application}},
		{name: "missing value", args: []string{application, "--workers"}},
		{
			name: "environment application",
			args: []string{"--future-option", "env:prod"},
			env:  map[string]string{"UVICORN_APP": application},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseUvicorn(tt.args, tt.env))
		})
	}
}

func TestParseUvicornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.api:app"
	tests := []struct {
		name        string
		args        []string
		env         map[string]string
		searchPaths []string
	}{
		{name: "attached value", args: []string{"--host=0.0.0.0", application}, searchPaths: []string{"."}},
		{name: "option after application", args: []string{application, "--port", "8000"}, searchPaths: []string{"."}},
		{name: "after terminator", args: []string{"--", application, "--future-option", "env:prod"}, searchPaths: []string{"."}},
		{name: "separated app directory", args: []string{"--app-dir", "/srv", application}, searchPaths: []string{"/srv"}},
		{name: "attached app directory", args: []string{"--app-dir=/srv", application}, searchPaths: []string{"/srv"}},
		{
			name:        "app directory after terminator",
			args:        []string{application, "--", "--app-dir", "/wrong"},
			env:         map[string]string{"UVICORN_APP_DIR": "/srv"},
			searchPaths: []string{"/srv"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := ParseUvicorn(tt.args, tt.env)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
			assert.Equal(t, tt.searchPaths, launch.SearchPaths)
		})
	}
}

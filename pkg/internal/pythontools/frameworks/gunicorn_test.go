// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGunicornOptions(t *testing.T) {
	const application = "orders.wsgi:application"

	optionsWithValues := []string{
		"-c", "--config", "-b", "--bind", "--backlog", "-w", "--workers", "-k", "--worker-class", "--threads",
		"--worker-connections", "--max-requests", "--max-requests-jitter", "-t", "--timeout", "--graceful-timeout",
		"--keep-alive", "--limit-request-line", "--limit-request-fields", "--limit-request-field_size",
		"--reload-engine", "--reload-extra-file", "--chdir", "-e", "--env", "-p", "--pid", "--worker-tmp-dir",
		"-u", "--user", "-g", "--group", "-m", "--umask", "--forwarded-allow-ips", "--access-logfile",
		"--access-logformat", "--error-logfile", "--log-file", "--log-level", "--logger-class", "--log-config",
		"--log-config-json", "--log-syslog-to", "--log-syslog-prefix", "--log-syslog-facility", "--statsd-host",
		"--dogstatsd-tags", "--statsd-prefix", "-n", "--name", "--pythonpath", "--paste", "--paster",
		"--proxy-allow-from", "--protocol", "--uwsgi-allow-from", "--keyfile", "--certfile", "--ssl-version",
		"--cert-reqs", "--ca-certs", "--ciphers", "--http-protocols", "--http2-cleartext",
		"--http2-max-concurrent-streams", "--http2-initial-window-size", "--http2-max-frame-size",
		"--http2-max-header-list-size", "--paste-global", "--forwarder-headers", "--header-map", "--asgi-loop",
		"--asgi-lifespan", "--asgi-disconnect-grace-period", "--http-parser", "--root-path", "--dirty-app",
		"--dirty-workers", "--dirty-timeout", "--dirty-threads", "--dirty-graceful-timeout", "--control-socket",
		"--control-socket-mode",
	}
	assert.Equal(t, optionSet(optionsWithValues...), gunicornOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseGunicorn([]string{option, "env:prod", application}, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	optionsWithoutValues := []string{
		"--reload", "--spew", "--check-config", "--print-config", "--preload", "--no-sendfile", "--reuse-port",
		"-D", "--daemon", "--initgroups", "--disable-redirect-access-to-syslog", "--capture-output",
		"--log-syslog", "-R", "--enable-stdio-inheritance", "--enable-backlog-metric", "--suppress-ragged-eofs",
		"--do-handshake-on-connect", "--permit-obsolete-folding", "--strip-header-spaces",
		"--permit-unconventional-http-method", "--permit-unconventional-http-version", "--casefold-http-method",
		"--no-control-socket", "-h", "--help", "-v", "--version", "--proxy-protocol",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), gunicornOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseGunicorn([]string{option, application}, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseGunicornApplicationForms(t *testing.T) {
	tests := map[string]string{
		"default application object":  "company.orders.wsgi",
		"explicit application object": "company.orders.wsgi:application",
		"factory application object":  "company.orders.wsgi:create_app()",
	}
	for name, application := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseGunicorn([]string{"--workers", "4", application}, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseGunicornFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "long option", args: []string{"--future-option", "env:prod", application}},
		{name: "attached long option", args: []string{"--future-option=env:prod", application}},
		{name: "short option", args: []string{"-Z", "env:prod", application}},
		{name: "short option cluster", args: []string{"-DZ", application}},
		{name: "after application", args: []string{application, "--future-option", "env:prod"}},
		{name: "before known flag", args: []string{"--future-option", "--capture-output", application}},
		{
			name: "environment option",
			args: []string{application},
			env:  map[string]string{"GUNICORN_CMD_ARGS": "--future-option env:prod"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseGunicorn(tt.args, tt.env))
		})
	}
}

func TestParseGunicornAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"attached short value":    {"-w4", application},
		"short value with equals": {"-w=4", application},
		"attached long value":     {"--workers=4", application},
		"attached tags":           {"--dogstatsd-tags=env:prod", application},
		"short flag cluster":      {"-DR", application},
		"after terminator":        {"--", application, "--future-option", "env:prod"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseGunicorn(args, nil)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	launch := ParseGunicorn([]string{"main:app", "--", "--name", "wrong"}, nil)
	assert.Empty(t, launch.FallbackName)

	for _, option := range []string{"-Dnorders", "-Dn=orders"} {
		launch := ParseGunicorn([]string{option, "main:app"}, nil)
		assert.Equal(t, "orders", launch.FallbackName)
	}
}

func TestParseGunicornProxyProtocolOption(t *testing.T) {
	const application = "orders.wsgi:application"

	tests := map[string][]string{
		"separated off value":    {"--proxy-protocol", "off", application},
		"separated v1 value":     {"--proxy-protocol", "v1", application},
		"separated v2 value":     {"--proxy-protocol", "v2", application},
		"separated auto value":   {"--proxy-protocol", "auto", application},
		"attached value":         {"--proxy-protocol=v1", application},
		"legacy bare flag":       {"--proxy-protocol", application},
		"bare before module app": {"--proxy-protocol", "company.orders.wsgi"},
		"bare before an option":  {"--proxy-protocol", "--dogstatsd-tags", "env:prod", application},
		"bare after application": {application, "--proxy-protocol"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseGunicorn(args, nil)

			expected := application
			if name == "bare before module app" {
				expected = "company.orders.wsgi"
			}
			assert.Equal(t, expected, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	assert.Equal(t, PythonLaunch{}, ParseGunicorn([]string{"--proxy-protocol=invalid", application}, nil))
}

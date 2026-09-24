// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWaitressOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	optionsWithValues := []string{
		"--host", "--port", "--listen", "--threads", "--trusted-proxy", "--trusted-proxy-count",
		"--trusted-proxy-headers", "--url-scheme", "--url-prefix", "--backlog", "--recv-bytes",
		"--send-bytes", "--outbuf-overflow", "--outbuf-high-watermark", "--inbuf-overflow",
		"--connection-limit", "--cleanup-interval", "--channel-timeout", "--max-request-header-size",
		"--max-request-body-size", "--ident", "--asyncore-loop-timeout", "--unix-socket",
		"--unix-socket-perms", "--sockets", "--channel-request-lookahead", "--server-name", "--app",
	}
	assert.Equal(t, optionSet(optionsWithValues...), waitressOptionsWithValues)

	for _, option := range optionsWithValues {
		t.Run(option, func(t *testing.T) {
			args := []string{option, "env:prod", application}
			if option == "--app" {
				args = []string{option, application}
			}
			launch := ParseWaitress(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}

	optionsWithoutValues := []string{
		"--help", "--call", "--ipv4", "--no-ipv4", "--ipv6", "--no-ipv6",
		"--log-untrusted-proxy-headers", "--no-log-untrusted-proxy-headers",
		"--clear-untrusted-proxy-headers", "--no-clear-untrusted-proxy-headers", "--log-socket-errors",
		"--no-log-socket-errors", "--expose-tracebacks", "--no-expose-tracebacks", "--asyncore-use-poll",
		"--no-asyncore-use-poll",
	}
	assert.Equal(t, optionSet(optionsWithoutValues...), waitressOptionsWithoutValues)

	for _, option := range optionsWithoutValues {
		t.Run(option, func(t *testing.T) {
			launch := ParseWaitress([]string{option, application})

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseWaitressFailsClosedOnUnknownOptions(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"long option":                 {"--future-option", "env:prod", application},
		"attached long option":        {"--future-option=env:prod", application},
		"short option":                {"-Z", "env:prod", application},
		"after application":           {application, "--future-option", "env:prod"},
		"known option after app":      {application, "--threads", "4"},
		"value on flag":               {"--asyncore-use-poll=true", application},
		"missing value":               {"--threads"},
		"unknown option as value":     {"--ident", "--future-option", "env:prod", application},
		"multiple applications":       {application, "other.wsgi:application"},
		"explicit and positional app": {"--app", application, "other.wsgi:application"},
		"abbreviated option":          {"--thre=4", application},
		"invalid adjustment option":   {"--adj", "env:prod", application},
		"unsupported version option":  {"--version", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseWaitress(args))
		})
	}
}

func TestParseWaitressAcceptsKnownOptionForms(t *testing.T) {
	const application = "orders.wsgi:application"
	tests := map[string][]string{
		"separated value":           {"--threads", "4", application},
		"attached value":            {"--threads=4", application},
		"negative value":            {"--asyncore-loop-timeout", "-1", application},
		"lone dash value":           {"--ident", "-", application},
		"attached dashed value":     {"--ident=--private", application},
		"repeated option":           {"--listen", "*:8000", "--listen=[::1]:8000", application},
		"explicit application":      {"--app", application},
		"attached application":      {"--app=" + application},
		"call application":          {"--call", application},
		"option after explicit app": {"--app", application, "--threads", "4"},
		"after terminator":          {"--", application},
		"negative boolean":          {"--no-expose-tracebacks", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseWaitress(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
		})
	}
}

func TestParseWaitressDottedApplication(t *testing.T) {
	const application = "company.orders.wsgi.create_app"
	for name, args := range map[string][]string{
		"positional":   {"--call", application},
		"explicit app": {"--call", "--app=" + application},
	} {
		t.Run(name, func(t *testing.T) {
			launch := ParseWaitress(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetDottedReference, launch.TargetKind)
		})
	}

	assert.Equal(t, PythonLaunch{}, ParseWaitress([]string{
		"company.orders.wsgi:create_app()",
	}))
	assert.Equal(t, PythonLaunch{}, ParseWaitress([]string{
		" company.orders.wsgi:app ",
	}))
}

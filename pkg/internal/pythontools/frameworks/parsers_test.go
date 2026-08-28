// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	parserOptionsWithValues = optionSet(
		"-p", "-b",
		"--port", "--bind",
	)
	parserOptionsWithoutValues = optionSet(
		"-h", "-v",
		"--help",
	)
)

func TestArgparseShortOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		consumes bool
		known    bool
	}{
		{"short option with value", "-p", true, true},
		{"attached short value", "-p8000", false, true},
		{"short option without value", "-h", false, true},
		{"cluster ending in value option", "-hp", true, true},
		{"cluster value option not last", "-ph", false, true},
		{"unknown short option", "-Z", false, false},
		{"cluster with unknown option", "-hZ", false, false},
		{"cluster starting unknown", "-Zp", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			consumes, known := argparseShortOption(test.arg, parserOptionsWithValues, parserOptionsWithoutValues)

			assert.Equal(t, test.consumes, consumes)
			assert.Equal(t, test.known, known)
		})
	}
}

func TestArgparsePositionals(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
		ok   bool
	}{
		{"single positional", []string{"app:server"}, []string{"app:server"}, true},
		{"no positionals", []string{}, nil, true},
		{"long option attached value", []string{"--port=8000", "app:server"}, []string{"app:server"}, true},
		{"long option separated value", []string{"--port", "8000", "app:server"}, []string{"app:server"}, true},
		{"long option value dash", []string{"--bind", "-", "app:server"}, []string{"app:server"}, true},
		{"long option negative value", []string{"--port", "-1", "app:server"}, []string{"app:server"}, true},
		{"long option decimal value", []string{"--port", "1.5", "app:server"}, []string{"app:server"}, true},
		{"short option separated value", []string{"-p", "8000", "app:server"}, []string{"app:server"}, true},
		{"short option attached value", []string{"-p8000", "app:server"}, []string{"app:server"}, true},
		{"short flag", []string{"-h", "app:server"}, []string{"app:server"}, true},
		{"cluster flag then value option", []string{"-hp", "8000", "app:server"}, []string{"app:server"}, true},
		{"bare dash is positional", []string{"-", "app:server"}, []string{"-", "app:server"}, true},
		{"terminator collects rest as positionals", []string{"--", "-p", "-Z", "app:server"}, []string{"-p", "-Z", "app:server"}, true},
		{"terminator at end", []string{"--"}, nil, true},
		{"long option missing value", []string{"app:server", "--port"}, nil, false},
		{"long option value looks like option", []string{"--port", "--help", "app:server"}, nil, false},
		{"long option neg value trailing dot", []string{"--port", "-1.", "app:server"}, nil, false},
		{"plain value with trailing dot ok", []string{"--port", "1.", "app:server"}, []string{"app:server"}, true},
		{"flag with attached value", []string{"--help=true", "app:server"}, nil, false},
		{"unknown long option", []string{"--future", "app:server"}, nil, false},
		{"unknown long option attached", []string{"--future=x", "app:server"}, nil, false},
		{"unknown short option", []string{"-Z", "app:server"}, nil, false},
		{"short option missing value", []string{"-p"}, nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values, ok := argparsePositionals(test.args, parserOptionsWithValues, parserOptionsWithoutValues)

			assert.Equal(t, test.ok, ok)
			if test.ok {
				assert.Equal(t, test.want, values)
			} else {
				assert.Nil(t, values)
			}
		})
	}
}

func TestParseArgparseApplication(t *testing.T) {
	t.Run("parses first application reference", func(t *testing.T) {
		launch := parseArgparseApplication(
			[]string{"--port", "8000", "notaref", "orders.api:app", "inventory.wsgi:application"},
			parserOptionsWithValues,
			parserOptionsWithoutValues,
		)

		assert.Equal(t, PythonLaunch{
			Target:      "orders.api:app",
			TargetKind:  TargetModule,
			SearchPaths: []string{"."},
		}, launch)
	})

	t.Run("no arguments", func(t *testing.T) {
		assert.Equal(t, PythonLaunch{}, parseArgparseApplication(nil, parserOptionsWithValues, parserOptionsWithoutValues))
	})

	t.Run("positionals without application reference", func(t *testing.T) {
		assert.Equal(t, PythonLaunch{}, parseArgparseApplication(
			[]string{"orders", "--port", "8000"},
			parserOptionsWithValues,
			parserOptionsWithoutValues,
		))
	})

	t.Run("invalid options fail", func(t *testing.T) {
		assert.Equal(t, PythonLaunch{}, parseArgparseApplication(
			[]string{"--port"},
			parserOptionsWithValues,
			parserOptionsWithoutValues,
		))
	})
}

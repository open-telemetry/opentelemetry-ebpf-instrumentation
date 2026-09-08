// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frameworks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFastAPIEntrypoint(t *testing.T) {
	const application = "company.orders.api:app"
	tests := map[string][]string{
		"long option":           {"run", "--entrypoint", application},
		"attached long option":  {"run", "--entrypoint=" + application},
		"short option":          {"dev", "-e", application},
		"attached short option": {"dev", "-e" + application},
		"short cluster":         {"run", "-ve" + application},
		"short cluster value":   {"run", "-ve", application},
		"last option wins":      {"run", "--entrypoint", "other.api:app", "--entrypoint", application},
		"after flag":            {"run", "--proxy-headers", "--entrypoint", application},
		"after negative flag":   {"run", "--no-proxy-headers", "--entrypoint", application},
		"after global option":   {"--verbose", "run", "--entrypoint", application},
		"after negative global": {"--no-verbose", "run", "--entrypoint", application},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			launch := ParseFastAPI(args)

			assert.Equal(t, application, launch.Target)
			assert.Equal(t, TargetModule, launch.TargetKind)
			assert.False(t, launch.FastAPIAuto)
		})
	}

	for name, args := range map[string][]string{
		"missing value":               {"run", "--entrypoint"},
		"empty value":                 {"run", "--entrypoint="},
		"with path":                   {"run", "main.py", "--entrypoint", application},
		"with app option":             {"run", "--app", "api", "--entrypoint", application},
		"app without path":            {"run", "--app", "api"},
		"invalid import string":       {"run", "--entrypoint", "company.orders.api"},
		"factory call":                {"run", "--entrypoint", "company.orders.api:create_app()"},
		"padded entrypoint":           {"run", "--entrypoint", " " + application + " "},
		"unknown option":              {"run", "--future-option", "env:prod", "main.py"},
		"unknown attached":            {"run", "--future-option=env:prod", "main.py"},
		"unknown short":               {"run", "-Z", "env:prod", "main.py"},
		"unknown after path":          {"run", "main.py", "--future-option"},
		"value on flag":               {"run", "--proxy-headers=true", "main.py"},
		"multiple paths":              {"run", "env:prod", "main.py"},
		"unknown before command":      {"--future-option", "run", "main.py"},
		"global option after command": {"run", "--no-verbose", "main.py"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{}, ParseFastAPI(args))
		})
	}

	for name, args := range map[string][]string{
		"long entrypoint is another option value":  {"run", "--root-path", "--entrypoint=" + application},
		"short entrypoint is another option value": {"run", "--root-path", "-e" + application},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, PythonLaunch{FastAPIAuto: true}, ParseFastAPI(args))
		})
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnettools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDotnetLaunch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		entryPoint string
		depsFile   string
	}{
		{name: "direct DLL", args: []string{"Orders.Api.dll"}, entryPoint: "Orders.Api.dll"},
		{name: "absolute DLL", args: []string{"/app/Orders.Api.dll"}, entryPoint: "/app/Orders.Api.dll"},
		{name: "exec", args: []string{"exec", "Orders.Api.dll"}, entryPoint: "Orders.Api.dll"},
		{
			name:       "exec options",
			args:       []string{"exec", "--runtimeconfig", "app.runtimeconfig.json", "--fx-version", "8.0.0", "Orders.Api.dll"},
			entryPoint: "Orders.Api.dll",
		},
		{
			name:       "legacy roll forward option",
			args:       []string{"--roll-forward-on-no-candidate-fx", "2", "Orders.Api.dll"},
			entryPoint: "Orders.Api.dll",
		},
		{
			name:       "deps file",
			args:       []string{"exec", "--depsfile", "metadata/Orders.deps.json", "Orders.Api.dll"},
			entryPoint: "Orders.Api.dll",
			depsFile:   "metadata/Orders.deps.json",
		},
		{
			name:       "attached deps file",
			args:       []string{"exec", "--depsfile=metadata/Orders.deps.json", "Orders.Api.dll"},
			entryPoint: "Orders.Api.dll",
			depsFile:   "metadata/Orders.deps.json",
		},
		{name: "option terminator", args: []string{"--", "Orders.Api.dll"}, entryPoint: "Orders.Api.dll"},
		{name: "application arguments", args: []string{"Orders.Api.dll", "Other.dll"}, entryPoint: "Orders.Api.dll"},
		{name: "CLI command", args: []string{"run", "--project", "Orders.Api.csproj"}},
		{name: "CLI command before DLL", args: []string{"test", "Tests.dll"}},
		{name: "non-DLL application", args: []string{"Orders.Api.exe"}},
		{name: "missing application", args: []string{"exec", "--runtimeconfig", "app.runtimeconfig.json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launch := parseDotnetLaunch(tt.args)

			assert.Equal(t, tt.entryPoint, launch.EntryPoint)
			assert.Equal(t, tt.depsFile, launch.DepsFile)
		})
	}
}

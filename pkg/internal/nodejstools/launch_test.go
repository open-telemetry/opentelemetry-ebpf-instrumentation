// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNodeLaunch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		entryPoint string
	}{
		{name: "entrypoint", args: []string{"app.js"}, entryPoint: "app.js"},
		{name: "ES module entrypoint", args: []string{"app.mjs"}, entryPoint: "app.mjs"},
		{name: "CommonJS entrypoint", args: []string{"app.cjs"}, entryPoint: "app.cjs"},
		{name: "absolute entrypoint", args: []string{"/app/dist/main.js"}, entryPoint: "/app/dist/main.js"},
		{name: "boolean option", args: []string{"--inspect", "app.js"}, entryPoint: "app.js"},
		{name: "require", args: []string{"--require", "./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "short require", args: []string{"-r", "./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "import", args: []string{"--import", "./otel.mjs", "app.js"}, entryPoint: "app.js"},
		{name: "loader", args: []string{"--loader", "tsx", "app.ts"}, entryPoint: "app.ts"},
		{name: "experimental loader", args: []string{"--experimental-loader", "tsx", "app.ts"}, entryPoint: "app.ts"},
		{name: "attached experimental loader", args: []string{"--experimental-loader=./loader.mjs", "app.ts"}, entryPoint: "app.ts"},
		{name: "attached option value", args: []string{"--require=./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "attached short require", args: []string{"-r./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "attached short condition", args: []string{"-Cdevelopment", "app.js"}, entryPoint: "app.js"},
		{name: "multiple options", args: []string{"--no-warnings", "--import", "./otel.mjs", "app.js"}, entryPoint: "app.js"},
		{
			name: "other options with values",
			args: []string{
				"--inspect-port", "9230",
				"--title", "orders",
				"--watch-path", "src",
				"app.js",
			},
			entryPoint: "app.js",
		},
		{name: "underscore option", args: []string{"--inspect_port", "9230", "app.js"}, entryPoint: "app.js"},
		{name: "option terminator", args: []string{"--", "--app.js"}, entryPoint: "--app.js"},
		{name: "arguments after entrypoint", args: []string{"app.js", "--require", "not-a-preload"}, entryPoint: "app.js"},
		{name: "inspect entrypoint", args: []string{"inspect", "app.js"}, entryPoint: "app.js"},
		{name: "inspect after options", args: []string{"--no-warnings", "inspect", "app.js"}, entryPoint: "app.js"},
		{name: "inspect host and port", args: []string{"inspect", "localhost:9229"}},
		{name: "inspect port", args: []string{"inspect", "9229"}},
		{name: "file entry URL", args: []string{"--entry-url", "file:///app/main.js"}},
		{name: "data entry URL", args: []string{"--entry-url", "data:text/javascript,setInterval(() => {}, 1000)"}},
		{name: "eval", args: []string{"-e", "app.js"}},
		{name: "input type with eval", args: []string{"--input-type", "module", "-e", "await main()"}},
		{name: "attached short eval", args: []string{"-econsole.log('hello')"}},
		{name: "attached eval", args: []string{"--eval=console.log('hello')"}},
		{name: "print", args: []string{"--print", "app.js"}},
		{name: "run package script", args: []string{"--run", "build.js"}},
		{name: "stdin", args: []string{"-"}},
		{name: "repl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.entryPoint, ParseNodeLaunch(tt.args).EntryPoint)
		})
	}
}

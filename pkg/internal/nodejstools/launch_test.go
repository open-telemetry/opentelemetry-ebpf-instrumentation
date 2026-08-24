// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejstools

import (
	"bytes"
	"log/slog"
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
		{name: "extensionless entrypoint", args: []string{"app"}, entryPoint: "app"},
		{name: "ES module entrypoint", args: []string{"app.mjs"}, entryPoint: "app.mjs"},
		{name: "CommonJS entrypoint", args: []string{"app.cjs"}, entryPoint: "app.cjs"},
		{name: "absolute entrypoint", args: []string{"/app/dist/main.js"}, entryPoint: "/app/dist/main.js"},
		{name: "boolean option", args: []string{"--inspect", "app.js"}, entryPoint: "app.js"},
		// this is going to find a wrong entrypoint 4096, but ResolveServiceMetadata will discard it if there's
		// no local file 4096.js/.mjs/.cjs/.ts.
		{name: "max old space size", args: []string{"--max-old-space-size", "4096", "app.js"}, entryPoint: "4096"},
		{name: "require", args: []string{"--require", "./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "short require", args: []string{"-r", "./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "import", args: []string{"--import", "./otel.mjs", "app.js"}, entryPoint: "app.js"},
		{name: "loader", args: []string{"--loader", "tsx", "app.ts"}, entryPoint: "app.ts"},
		{name: "experimental loader", args: []string{"--experimental-loader", "tsx", "app.ts"}, entryPoint: "app.ts"},
		{name: "attached experimental loader", args: []string{"--experimental-loader=./loader.mjs", "app.ts"}, entryPoint: "app.ts"},
		{name: "extensionless entrypoint after option", args: []string{"--require", "./otel.js", "app"}, entryPoint: "app"},
		{name: "attached option value", args: []string{"--require=./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "diagnostic directory with attached value", args: []string{"--diagnostic-dir=/tmp", "app"}, entryPoint: "app"},
		{name: "short require", args: []string{"-r", "./otel.js", "app.js"}, entryPoint: "app.js"},
		{name: "short condition", args: []string{"-C", "development", "app.js"}, entryPoint: "app.js"},
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
		{name: "V8 option with attached value", args: []string{"--stack-trace-limit=20", "app"}, entryPoint: "app"},
		{name: "attached config file", args: []string{"--experimental-config-file=node.config.json", "app"}, entryPoint: "app"},
		{name: "separate config file", args: []string{"--experimental-config-file", "config", "server.js"}, entryPoint: "server.js"},
		{name: "removed Node 16 option", args: []string{"--experimental-fetch", "app"}, entryPoint: "app"},
		{name: "current compatibility option", args: []string{"--experimental-detect-module", "app"}, entryPoint: "app"},
		{name: "removed option with value", args: []string{"--experimental-policy", "policy.json", "app"}, entryPoint: "app"},
		{name: "unknown long option", args: []string{"--future-option", "worker.js", "app.js"}},
		{name: "unknown short option", args: []string{"-x", "worker.js", "app.js"}},
		{name: "unknown short option starting with eval", args: []string{"-evil", "worker.js", "app.js"}},
		{name: "unknown attached option", args: []string{"--future-option=value", "app.js"}},
		{name: "option terminator", args: []string{"--", "--app.js"}, entryPoint: "--app.js"},
		{name: "arguments after entrypoint", args: []string{"app.js", "--require", "not-a-preload"}, entryPoint: "app.js"},
		{name: "inspect entrypoint", args: []string{"inspect", "app.js"}, entryPoint: "app.js"},
		{name: "inspect after options", args: []string{"--no-warnings", "inspect", "app.js"}, entryPoint: "app.js"},
		{name: "inspect host and port", args: []string{"inspect", "localhost:9229"}},
		{name: "inspect port", args: []string{"inspect", "9229"}},
		{name: "file entry URL", args: []string{"--entry-url", "file:///app/main.js"}, entryPoint: "/app/main.js"},
		{name: "data entry URL", args: []string{"--entry-url", "data:text/javascript,setInterval(() => {}, 1000)"}},
		{name: "eval", args: []string{"-e", "app.js"}},
		{name: "input type with eval", args: []string{"--input-type", "module", "-e", "await main()"}},
		{name: "print and eval", args: []string{"-pe", "console.log('hello')"}},
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

func TestParseNodeLaunchLogsUnknownOption(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	launch := ParseNodeLaunch([]string{"--future-option=secret", "app.js"})

	assert.Empty(t, launch.EntryPoint)
	assert.Contains(t, logs.String(), "unknown option")
	assert.Contains(t, logs.String(), "--future-option")
	assert.NotContains(t, logs.String(), "secret")
}

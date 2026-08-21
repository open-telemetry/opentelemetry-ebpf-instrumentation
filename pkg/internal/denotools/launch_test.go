// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package denotools

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDenoLaunch(t *testing.T) {
	projectOnly := DenoLaunch{DiscoverProject: true}
	tests := []struct {
		name string
		args []string
		want DenoLaunch
	}{
		{name: "default repl", want: projectOnly},
		{name: "direct shorthand", args: []string{"main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true, direct: true}},
		{name: "extensionless shorthand", args: []string{"server"}, want: DenoLaunch{EntryPoint: "server", DiscoverProject: true, direct: true}},
		{name: "file URL shorthand", args: []string{"file:///opt/orders/main.ts"}, want: DenoLaunch{EntryPoint: "file:///opt/orders/main.ts", DiscoverProject: true, direct: true}},
		{name: "JSR shorthand", args: []string{"jsr:@acme/orders/server"}, want: DenoLaunch{EntryPoint: "jsr:@acme/orders/server", DiscoverProject: true, direct: true}},
		{name: "npm shorthand", args: []string{"npm:@acme/orders@1.2.3"}, want: DenoLaunch{EntryPoint: "npm:@acme/orders@1.2.3", DiscoverProject: true, direct: true}},
		{name: "HTTP shorthand", args: []string{"https://example.com/main.ts"}, want: DenoLaunch{EntryPoint: "https://example.com/main.ts", DiscoverProject: true, direct: true}},
		{name: "run", args: []string{"run", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "serve", args: []string{"serve", "server.ts"}, want: DenoLaunch{EntryPoint: "server.ts", DiscoverProject: true}},
		{name: "watch", args: []string{"watch", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "root config", args: []string{"--config", "root.json", "run", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", ConfigPath: "root.json", DiscoverProject: true}},
		{name: "run config", args: []string{"run", "--config", "deno.json", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "attached config", args: []string{"run", "--config=deno.jsonc", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", ConfigPath: "deno.jsonc", DiscoverProject: true}},
		{name: "attached short config", args: []string{"run", "-cdeno.json", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "no config", args: []string{"run", "--no-config", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", NoConfig: true, DiscoverProject: true}},
		{name: "root log level", args: []string{"--log-level", "debug", "run", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "attached short log level", args: []string{"-Ldebug", "run", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "bare permissions", args: []string{"run", "--allow-read", "--allow-net", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "scoped permissions", args: []string{"run", "--allow-read=/tmp", "--deny-net=example.com", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "combined permissions", args: []string{"watch", "-RN", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "bare watch option", args: []string{"run", "--watch", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "attached watch paths", args: []string{"run", "--watch=src,templates", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "attached reload", args: []string{"run", "--reload=jsr:@std/http", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "bare reload", args: []string{"run", "--reload", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "bare env file", args: []string{"run", "--env-file", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "attached env file", args: []string{"run", "--env-file=.env.production", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "bare inspector", args: []string{"run", "--inspect", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "conditions", args: []string{"run", "--conditions", "development", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "preload", args: []string{"run", "--preload", "otel.ts", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "require", args: []string{"run", "--require", "otel.cjs", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "preload import alias", args: []string{"run", "--import", "otel.ts", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "lock with attached value", args: []string{"run", "--lock=deno.lock", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "lock with separate value", args: []string{"run", "--lock", "deno.lock", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "lock consumes possible entrypoint", args: []string{"run", "--lock", "main.ts"}, want: projectOnly},
		{name: "serve options", args: []string{"serve", "--host", "127.0.0.1", "--port=8080", "--parallel", "server.ts"}, want: DenoLaunch{EntryPoint: "server.ts", DiscoverProject: true}},
		{name: "serve profiling", args: []string{"serve", "--cpu-prof-dir", "profiles", "server.ts"}, want: DenoLaunch{EntryPoint: "server.ts", DiscoverProject: true}},
		{name: "watch run options", args: []string{"watch", "--coverage", "--watch-exclude=dist", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "Deno 1 import map alias", args: []string{"run", "--importmap", "imports.json", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "Deno 1 plugin permission", args: []string{"run", "--allow-plugin", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "integration flags", args: []string{"run", "--unstable-detect-cjs", "-A", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "current unstable flag", args: []string{"run", "--unstable-lazy-dynamic-imports", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "transient node conditions flag", args: []string{"run", "--unstable-node-conditions", "development", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "unstable lockfile flag", args: []string{"run", "--unstable-lockfile-v5", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "unstable subdomain wildcard flag", args: []string{"run", "--unstable-subdomain-wildcards", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "unstable vsock flag", args: []string{"run", "--unstable-vsock", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "stable unsafe proto", args: []string{"run", "--unsafe-proto", "app.js"}, want: DenoLaunch{EntryPoint: "app.js", DiscoverProject: true}},
		{name: "ignored read permission", args: []string{"run", "--ignore-read", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "ignored environment variable", args: []string{"run", "--ignore-env=TOKEN", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "inspector publish UID", args: []string{"run", "--inspect-publish-uid=stderr", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "disable environment proxy", args: []string{"run", "--no-use-env-proxy", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "minimum dependency age alias", args: []string{"run", "--min-dep-age", "60", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "node modules linker alias", args: []string{"run", "--linker=hoisted", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "option terminator", args: []string{"run", "--", "--main.ts"}, want: DenoLaunch{EntryPoint: "--main.ts", DiscoverProject: true}},
		{name: "direct option terminator", args: []string{"--", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true, direct: true}},
		{name: "application arguments ignored", args: []string{"run", "main.ts", "--config", "worker.json"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "empty argument ignored", args: []string{"", "run", "", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "stdin shorthand", args: []string{"-"}, want: projectOnly},
		{name: "run stdin", args: []string{"run", "-"}, want: projectOnly},
		{name: "eval", args: []string{"eval", "console.log('hello')"}, want: projectOnly},
		{name: "Deno 1 eval TypeScript flag", args: []string{"eval", "--ts", "console.log('hello')"}, want: projectOnly},
		{name: "eval print alias", args: []string{"eval", "-p", "console.log('hello')"}, want: projectOnly},
		{name: "eval config", args: []string{"eval", "--config", "deno.json", "console.log('hello')"}, want: DenoLaunch{ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "eval config after code", args: []string{"eval", "console.log('hello')", "--config", "deno.json"}, want: DenoLaunch{ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "Deno 1 eval compatibility mode", args: []string{"eval", "--unstable", "--compat", "console.log('hello')", "--config", "deno.json"}, want: DenoLaunch{ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "eval arguments after terminator", args: []string{"eval", "console.log('hello')", "--", "--config", "worker.json"}, want: projectOnly},
		{name: "repl", args: []string{"repl"}, want: projectOnly},
		{name: "repl setup before config", args: []string{"repl", "--eval", "setup()", "--config", "deno.json"}, want: DenoLaunch{ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "repl config after eval files", args: []string{"repl", "--eval-file", "a.ts", "b.ts", "--config", "deno.json"}, want: DenoLaunch{ConfigPath: "deno.json", DiscoverProject: true}},
		{name: "repl arguments after terminator", args: []string{"repl", "--", "--config", "worker.json"}, want: projectOnly},
		{name: "repl no config", args: []string{"repl", "--no-config"}, want: DenoLaunch{NoConfig: true, DiscoverProject: true}},
		{name: "unknown option", args: []string{"run", "--future-option", "worker.ts", "main.ts"}, want: projectOnly},
		{name: "unknown attached option", args: []string{"run", "--future-option=value", "main.ts"}, want: projectOnly},
		{name: "unknown option before another option", args: []string{"run", "--future-option", "--allow-net", "main.ts"}, want: DenoLaunch{EntryPoint: "main.ts", DiscoverProject: true}},
		{name: "run rejects serve option", args: []string{"run", "--port", "8080", "main.ts"}, want: projectOnly},
		{name: "help", args: []string{"--help"}},
		{name: "version", args: []string{"-V"}},
		{name: "task", args: []string{"task", "start"}},
		{name: "task with config", args: []string{"--config", "deno.json", "task", "start"}},
		{name: "test", args: []string{"test", "main_test.ts"}},
		{name: "x", args: []string{"x", "jsr:@std/http/file-server"}},
		{name: "current tooling command", args: []string{"pack"}},
		{name: "install shorthand", args: []string{"i", "jsr:@std/http"}},
		{name: "approve builds", args: []string{"approve-builds"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseDenoLaunch(tt.args))
		})
	}
}

func TestParseDenoLaunchLogsSanitizedUnknownOption(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	launch := ParseDenoLaunch([]string{"run", "--future-option=secret", "main.ts"})

	assert.Empty(t, launch.EntryPoint)
	assert.Contains(t, logs.String(), "unknown option")
	assert.Contains(t, logs.String(), "--future-option")
	assert.NotContains(t, logs.String(), "secret")
}

func TestSanitizedOptionName(t *testing.T) {
	assert.Equal(t, "--future-option", sanitizedOptionName("--future-option=secret"))
	assert.Equal(t, "-x", sanitizedOptionName("-xsecret"))
}

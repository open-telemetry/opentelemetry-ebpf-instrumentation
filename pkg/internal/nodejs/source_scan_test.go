// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasSIGUSR1Reference(t *testing.T, dir string) bool {
	t.Helper()
	result := dirSIGUSR1Reference(dir)
	if result == sourceScanUnavailable {
		t.Fatal("expected the application directory to be scannable")
	}
	return result == sourceScanFound
}

func TestSourceScan_DoubleQuoted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
const signals = ["SIGINT", "SIGTERM", "SIGUSR1"];
signals.forEach((sig) => process.on(sig, () => shutdown()));
`)
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected (double quotes)")
	}
}

func TestSourceScan_SingleQuoted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
process.on('SIGUSR1', () => {
  console.log('reloading config');
});
`)
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected (single quotes)")
	}
}

func TestSourceScan_BacktickQuoted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.ts", "const sig = `SIGUSR1`;\nprocess.on(sig, handler);\n")
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected (backtick)")
	}
}

func TestSourceScan_NoReference(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
const http = require('http');
const server = http.createServer((req, res) => res.end('ok'));
server.listen(3000);
`)
	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected no SIGUSR1 reference")
	}
}

func TestSourceScan_CommentIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
// process.on("SIGUSR1", handler);
/* "SIGUSR1" is handled elsewhere */
const server = require('http').createServer();
`)
	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 in comments to be ignored")
	}
}

func TestSourceScan_UnquotedIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
// This app does not handle SIGUSR1
console.log("Starting server");
`)
	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected unquoted SIGUSR1 to be ignored")
	}
}

func TestSourceScan_MultiLineBlockComment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
const http = require('http');
/*
  We used to handle SIGUSR1 for config reload:
  process.on("SIGUSR1", () => reloadConfig());
  But this was removed in v2.0
*/
const server = http.createServer();
`)
	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 in multi-line block comment to be ignored")
	}
}

func TestSourceScan_ArrayPattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `
[
  "SIGINT",
  "SIGTERM",
  "SIGUSR1",
  "SIGUSR2",
  "SIGQUIT",
  "beforeExit",
].forEach((signal) => {
  process.on(signal, async () => {
    log.info("shutting down");
    await this.shutdown(0);
  });
});
`)
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in array pattern")
	}
}

func TestSourceScan_TypeScriptFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.ts", `
import { createServer } from 'http';
process.on('SIGUSR1', () => console.log('debug'));
`)
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in .ts file")
	}
}

func TestSourceScan_SkipsNonEntryPointDependencyFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const server = require('http').createServer();`)
	writeFile(t, dir, "node_modules/some-lib/package.json", `{"main": "index.js"}`)
	writeFile(t, dir, "node_modules/some-lib/index.js", `module.exports = {};`)
	writeFile(t, dir, "node_modules/some-lib/internal/deep.js", `process.on("SIGUSR1", handler);`)

	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 outside a dependency entry point to be skipped")
	}
}

func TestSourceScan_CompiledOutputDist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"main": "dist/main.js"}`)
	writeFile(t, dir, "dist/main.js", `process.on("SIGUSR1", () => reloadConfig());`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in compiled output under dist")
	}
}

func TestSourceScan_CompiledOutputBuild(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "build/server.js", `process.on('SIGUSR1', handler);`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in compiled output under build")
	}
}

// A minified bundle is one line, routinely past bufio.Scanner's 64KB default.
func TestSourceScan_MinifiedSingleLineBundle(t *testing.T) {
	dir := t.TempDir()
	padding := strings.Repeat("a", 4*bufio.MaxScanTokenSize)
	writeFile(t, dir, "dist/main.js", `var x="`+padding+`";process.on("SIGUSR1",function(){r()});`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in a minified single-line bundle")
	}
}

func TestSourceScan_OverlongLineIsUnscannable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dist/main.js", "var x=\""+strings.Repeat("a", harvest.MaxJSLineScanBytes+1)+"\";")

	if got := dirSIGUSR1Reference(dir); got != sourceScanUnavailable {
		t.Errorf("expected sourceScanUnavailable for a line over the scan limit, got %d", got)
	}
}

func TestSourceScan_SkipsSystemDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const server = require('http').createServer();`)
	writeFile(t, dir, "proc/self/fake.js", `process.on("SIGUSR1", handler);`)
	writeFile(t, dir, "usr/lib/node/fake.js", `process.on("SIGUSR1", handler);`)

	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected system directories to be skipped when the app dir resolves to a filesystem root")
	}
}

func TestSourceScan_HandlerInDependencyEntryPoint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('heapdump');`)
	writeFile(t, dir, "node_modules/heapdump/index.js", `process.on("SIGUSR1", () => writeSnapshot());`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in a dependency entry point")
	}
}

func TestSourceScan_HandlerInScopedDependencyMain(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('@acme/agent');`)
	writeFile(t, dir, "node_modules/@acme/agent/package.json", `{"main": "lib/agent.js"}`)
	writeFile(t, dir, "node_modules/@acme/agent/lib/agent.js", `process.on('SIGUSR1', reload);`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in a scoped dependency main")
	}
}

func TestSourceScan_DependencyWithoutHandlerStaysClean(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('lodash');`)
	writeFile(t, dir, "node_modules/lodash/package.json", `{"main": "lodash.js"}`)
	writeFile(t, dir, "node_modules/lodash/lodash.js", `module.exports = {};`)

	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected a dependency without a handler to stay clean")
	}
}

func TestSourceScan_NextJSOutput(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".next/server/app.js", `process.on("SIGUSR1", () => reload());`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in .next output")
	}
}

func TestSourceScan_SymlinkedSourceFile(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()
	writeFile(t, shared, "signals.js", `process.on("SIGUSR1", reload);`)

	if err := os.Symlink(filepath.Join(shared, "signals.js"), filepath.Join(dir, "signals.js")); err != nil {
		t.Fatal(err)
	}

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected through a symlinked source file")
	}
}

func TestSourceScan_SymlinkedSourceDirectory(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()
	writeFile(t, shared, "handlers/signals.js", `process.on("SIGUSR1", reload);`)

	if err := os.Symlink(filepath.Join(shared, "handlers"), filepath.Join(dir, "src")); err != nil {
		t.Fatal(err)
	}

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected through a symlinked source directory")
	}
}

func TestSourceScan_SymlinkCycleTerminates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "nested/app.js", `const x = 1;`)

	if err := os.Symlink(dir, filepath.Join(dir, "nested", "loop")); err != nil {
		t.Fatal(err)
	}

	done := make(chan sourceScanResult, 1)
	go func() { done <- dirSIGUSR1Reference(dir) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("expected the scan to terminate on a symlink cycle")
	}
}

func TestSourceScan_ScansFromPackageRootAboveEntryPoint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"main": "dist/main.js"}`)
	writeFile(t, dir, "dist/main.js", `require('./bundle');`)
	writeFile(t, dir, "src/signals.js", `process.on("SIGUSR1", reload);`)

	if root := applicationRoot(filepath.Join(dir, "dist")); root != dir {
		t.Fatalf("expected the package root %s, got %s", dir, root)
	}
	if !hasSIGUSR1Reference(t, applicationRoot(filepath.Join(dir, "dist"))) {
		t.Error("expected sibling sources of the entry point directory to be scanned")
	}
}

func TestSourceScan_DependencyResolvedFromPackageRoot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"main": "dist/main.js"}`)
	writeFile(t, dir, "dist/main.js", `require('heapdump');`)
	writeFile(t, dir, "node_modules/heapdump/index.js", `process.on("SIGUSR1", () => writeSnapshot());`)

	if !hasSIGUSR1Reference(t, applicationRoot(filepath.Join(dir, "dist"))) {
		t.Error("expected node_modules at the package root to be scanned for a dist/ entry point")
	}
}

func TestApplicationRoot_StopsAtProcRootBoundary(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "root", "app", "dist")
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}

	if root := applicationRoot(entry); root != entry {
		t.Errorf("expected the climb to stop without a package root, got %s", root)
	}
}

func TestSourceScan_NestedSourceFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/handlers/signals.mjs", `
export function setup() {
  process.on("SIGUSR1", () => reloadConfig());
}
`)
	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in nested source file")
	}
}

func TestSourceScan_NonJSFileIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", `This app handles "SIGUSR1" for graceful reload.`)
	writeFile(t, dir, "config.json", `{"signal": "SIGUSR1"}`)
	writeFile(t, dir, "app.py", `import signal; signal.signal(signal.SIGUSR1, handler)`)

	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected non-JS files to be ignored")
	}
}

func TestSourceScan_NonRegularJSFileIgnored(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "pipe.js")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}

	result := make(chan sourceScanResult, 1)
	go func() {
		result <- dirSIGUSR1Reference(dir)
	}()

	select {
	case got := <-result:
		if got == sourceScanFound {
			t.Error("expected non-regular JS file to be ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("expected source scan to ignore FIFO without blocking")
	}
}

func TestSourceScan_OversizedJSFileIgnored(t *testing.T) {
	dir := t.TempDir()
	line := "const filler = 1;\n"
	content := strings.Repeat(line, int(harvest.MaxJSFileScanBytes/int64(len(line)))+1) +
		`process.on("SIGUSR1", handler);`
	writeFile(t, dir, "large.js", content)

	if got := dirSIGUSR1Reference(dir); got != sourceScanUnavailable {
		t.Errorf("expected sourceScanUnavailable for a file over the scan limit, got %d", got)
	}
}

func TestSourceScan_UnreadableDirectoryIsUnscannable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const server = require('http').createServer();`)
	blocked := filepath.Join(dir, "config")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	if got := dirSIGUSR1Reference(dir); got != sourceScanUnavailable {
		t.Errorf("expected sourceScanUnavailable for an unreadable directory, got %d", got)
	}
}

func TestSourceScan_UnreadableDirectoryDoesNotHideLaterHandler(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	dir := t.TempDir()
	blocked := filepath.Join(dir, "aaa-blocked")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	writeFile(t, dir, "zzz/handlers.js", `process.on("SIGUSR1", reload);`)

	if got := dirSIGUSR1Reference(dir); got != sourceScanFound {
		t.Errorf("expected the walk to continue past an unreadable directory and find the handler, got %d", got)
	}
}

func TestSourceScan_SymlinkedDependency(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('heapdump');`)
	writeFile(t, dir, "store/heapdump/index.js", `process.on("SIGUSR1", () => writeSnapshot());`)

	link := filepath.Join(dir, "node_modules", "heapdump")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "store", "heapdump"), link); err != nil {
		t.Fatal(err)
	}

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected in a symlinked (pnpm-style) dependency")
	}
}

func TestSourceScan_PlugNPlayIsUnscannable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('heapdump');`)
	writeFile(t, dir, ".pnp.cjs", `module.exports = {};`)

	if got := dirSIGUSR1Reference(dir); got != sourceScanUnavailable {
		t.Errorf("expected sourceScanUnavailable for a Plug'n'Play install, got %d", got)
	}
}

func TestSourceScan_DependencyExportsEntryPoint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `import 'agent';`)
	writeFile(t, dir, "node_modules/agent/package.json", `{"exports": {".": "./dist/index.js"}}`)
	writeFile(t, dir, "node_modules/agent/dist/index.js", `process.on("SIGUSR1", reload);`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected through an ESM exports entry point")
	}
}

func TestSourceScan_DependencyExtensionlessMain(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.js", `require('agent');`)
	writeFile(t, dir, "node_modules/agent/package.json", `{"main": "./lib/agent"}`)
	writeFile(t, dir, "node_modules/agent/lib/agent.js", `process.on("SIGUSR1", reload);`)

	if !hasSIGUSR1Reference(t, dir) {
		t.Error("expected SIGUSR1 to be detected through an extensionless main")
	}
}

func TestSourceScan_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if hasSIGUSR1Reference(t, dir) {
		t.Error("expected false for empty directory")
	}
}

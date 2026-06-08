// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
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

func TestSourceScan_DoubleQuoted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
const signals = ["SIGINT", "SIGTERM", "SIGUSR1"];
signals.forEach((sig) => process.on(sig, () => shutdown()));
`)
	if !dirHasSIGUSR1Reference(dir) {
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
	if !dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 to be detected (single quotes)")
	}
}

func TestSourceScan_BacktickQuoted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.ts", "const sig = `SIGUSR1`;\nprocess.on(sig, handler);\n")
	if !dirHasSIGUSR1Reference(dir) {
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
	if dirHasSIGUSR1Reference(dir) {
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
	if dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 in comments to be ignored")
	}
}

func TestSourceScan_UnquotedIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `
// This app does not handle SIGUSR1
console.log("Starting server");
`)
	if dirHasSIGUSR1Reference(dir) {
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
	if dirHasSIGUSR1Reference(dir) {
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
	if !dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 to be detected in array pattern")
	}
}

func TestSourceScan_TypeScriptFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "server.ts", `
import { createServer } from 'http';
process.on('SIGUSR1', () => console.log('debug'));
`)
	if !dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 to be detected in .ts file")
	}
}

func TestSourceScan_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.js", `const server = require('http').createServer();`)
	writeFile(t, dir, "node_modules/some-lib/index.js", `process.on("SIGUSR1", handler);`)

	if dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 in node_modules to be skipped")
	}
}

func TestSourceScan_NestedSourceFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "src/handlers/signals.mjs", `
export function setup() {
  process.on("SIGUSR1", () => reloadConfig());
}
`)
	if !dirHasSIGUSR1Reference(dir) {
		t.Error("expected SIGUSR1 to be detected in nested source file")
	}
}

func TestSourceScan_NonJSFileIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", `This app handles "SIGUSR1" for graceful reload.`)
	writeFile(t, dir, "config.json", `{"signal": "SIGUSR1"}`)
	writeFile(t, dir, "app.py", `import signal; signal.signal(signal.SIGUSR1, handler)`)

	if dirHasSIGUSR1Reference(dir) {
		t.Error("expected non-JS files to be ignored")
	}
}

func TestSourceScan_NonRegularJSFileIgnored(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "pipe.js")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}

	result := make(chan bool, 1)
	go func() {
		result <- dirHasSIGUSR1Reference(dir)
	}()

	select {
	case found := <-result:
		if found {
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

	if dirHasSIGUSR1Reference(dir) {
		t.Error("expected oversized JS file to be ignored")
	}
}

func TestSourceScan_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if dirHasSIGUSR1Reference(dir) {
		t.Error("expected false for empty directory")
	}
}

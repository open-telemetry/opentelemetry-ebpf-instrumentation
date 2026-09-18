// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"io"
	"regexp"

	"github.com/hashicorp/go-version"
)

// The agent constructs an AsyncLocalStorage, added in 13.10.0 and backported to
// 12.17.0, so the 13.x releases below 13.10 are a hole a single lower bound
// would let through.
//
// https://nodejs.org/api/async_context.html — "Added in: v13.10.0, v12.17.0"
var (
	minInjectableVersion = version.Must(version.NewVersion("12.17.0"))
	node13Series         = version.Must(version.NewVersion("13.0.0"))
	node13Backport       = version.Must(version.NewVersion("13.10.0"))
)

// supportsAsyncLocalStorage reports whether the runtime can run the injected
// agent at all: without the API the agent throws on evaluation.
func supportsAsyncLocalStorage(nodeVersion *version.Version) bool {
	if nodeVersion.LessThan(minInjectableVersion) {
		return false
	}

	return nodeVersion.LessThan(node13Series) || nodeVersion.GreaterThanOrEqual(node13Backport)
}

// Node.js builds its /json/version reply from the literal "node.js/" NODE_VERSION
// (src/inspector_socket_server.cc), so the concatenated string sits in .rodata and
// survives stripping. Components are bounded so versionLiteralMax is finite.
var nodeVersionPattern = regexp.MustCompile(`node\.js/v(\d{1,3}\.\d{1,3}\.\d{1,3})`)

// versionLiteralMax is the longest string nodeVersionPattern can match, so a
// chunked scan knows how much to carry across a read boundary.
const versionLiteralMax = len("node.js/v") + len("000.000.000")

// rodataChunkSize bounds how much of .rodata is held at once: it reaches tens of
// megabytes in current Node.js builds.
const rodataChunkSize = 1 << 20

// nodeVersionFromELF reads the runtime version out of the executable, without
// running anything in the target process.
func nodeVersionFromELF(elfFile *elf.File) (*version.Version, bool) {
	if elfFile == nil {
		return nil, false
	}

	rodata := elfFile.Section(".rodata")
	if rodata == nil || rodata.Type == elf.SHT_NOBITS {
		return nil, false
	}

	return scanNodeVersion(rodata.Open(), rodataChunkSize)
}

// scanNodeVersion holds at most chunkSize bytes at a time, keeping enough
// of each read to catch a match straddling two of them. chunkSize is a parameter
// so tests can exercise the boundary cheaply.
func scanNodeVersion(r io.Reader, chunkSize int) (*version.Version, bool) {
	// below one the carry fills the buffer, every read is empty and the loop
	// never advances
	buf := make([]byte, max(chunkSize, 1)+versionLiteralMax)
	held := 0

	for {
		n, err := io.ReadFull(r, buf[held:])
		end := held + n

		if nodeVersion, ok := nodeVersionFrom(buf[:end]); ok {
			return nodeVersion, true
		}

		if err != nil {
			return nil, false
		}

		held = min(versionLiteralMax, end)
		copy(buf, buf[end-held:end])
	}
}

// nodeVersionFrom takes the first match: stock builds carry the literal once, but
// an executable bundling that string of its own could shift the reading.
func nodeVersionFrom(rodata []byte) (*version.Version, bool) {
	match := nodeVersionPattern.FindSubmatch(rodata)
	if match == nil {
		return nil, false
	}

	nodeVersion, err := version.NewVersion(string(match[1]))
	if err != nil {
		return nil, false
	}

	return nodeVersion, true
}

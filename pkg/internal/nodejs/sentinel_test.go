// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// The agent signals the eBPF layer by calling into fs on a path that cannot
// resolve, so the call always fails. fs.existsSync reports that failure as a
// return value; the fs.accessSync it replaced built and threw a UVException,
// which costs several times the call itself — on the trace-context path, on
// every async callback in request scope.
//
// The check is on the throwing calls rather than on accessSync alone, since
// statSync, realpathSync and opendirSync would reintroduce the same cost. It
// matches a called identifier in any form, so a destructured or re-exported
// import is caught too; it cannot see a call assembled at runtime.
var (
	throwingProbe = regexp.MustCompile(`\b(accessSync|statSync|lstatSync|realpathSync|opendirSync|readlinkSync)\s*\(`)
	dynamicFS     = regexp.MustCompile(`\bfs\s*\[`)
	sentinelEmit  = regexp.MustCompile(`fs\.([A-Za-z0-9_]+)\s*\(\s*(?:` + "`" + `/dev/null/obi|'/dev/null/obi|"/dev/null/obi|SENTINEL_PREFIX)`)
)

func TestAgentScriptsUseNonThrowingSentinel(t *testing.T) {
	for name, code := range map[string]string{
		"fdextractor.js": _extractorCode,
		"spanbridge.js":  _spanBridgeCode,
	} {
		emits := sentinelEmit.FindAllStringSubmatch(code, -1)
		require.NotEmpty(t, emits, "%s: no sentinel emit found at all", name)

		for _, m := range emits {
			require.Equal(t, "existsSync", m[1],
				"%s: the sentinel is emitted with fs.%s, which throws", name, m[1])
		}

		require.NotRegexp(t, throwingProbe, code,
			"%s: a throwing fs probe is called; the sentinel path must use fs.existsSync", name)

		require.NotRegexp(t, dynamicFS, code,
			"%s: fs is indexed dynamically, so the call cannot be checked", name)
	}
}

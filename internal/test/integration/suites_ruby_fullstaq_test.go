// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestSuite_RailsFullstaqRuby348Postgres(t *testing.T) {
	// The pinned Fullstaq package is amd64; process emulation cannot validate its uprobes.
	if runtime.GOARCH != "amd64" {
		t.Skip("Fullstaq Ruby 3.4.8 requires a native amd64 Docker host")
	}

	compose, err := docker.ComposeSuite("docker-compose-fullstaq-ruby-3.4.8-postgres.yml", path.Join(pathOutput, "test-suite-fullstaq-ruby-3.4.8-postgres.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	compose.Env = append(compose.Env, `OTEL_EBPF_OPEN_PORT=3040`, `OTEL_EBPF_EXECUTABLE_PATH=`, `TEST_SERVICE_PORTS=3041:3040`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { runWeaverValidation(t) })

	assertFullstaqRuby348(t, compose)
	t.Run("Rails PostgreSQL traces", testHTTPTracesRailsPostgres)
	t.Run("Rails PostgreSQL prepared statement traces", testHTTPTracesRailsPostgresPrepared)
}

func assertFullstaqRuby348(t *testing.T, compose *docker.Compose) {
	t.Helper()
	const rubyRoot = "/usr/lib/fullstaq-ruby/versions/3.4.8-jemalloc"

	version, err := compose.ExecOutput("testserver", "ruby", "-e", "print RUBY_VERSION")
	require.NoError(t, err)
	require.Equal(t, "3.4.8", version)

	// Reproduce the stripped launcher and symbol-bearing interpreter without DWARF.
	launcher, err := compose.ExecOutput("testserver", "readelf", "-SW", rubyRoot+"/bin/ruby")
	require.NoError(t, err)
	require.NotContains(t, launcher, ".symtab")
	library, err := compose.ExecOutput("testserver", "readelf", "-SW", rubyRoot+"/lib/libruby.so.3.4.8")
	require.NoError(t, err)
	for _, section := range []string{".symtab", ".strtab", ".dynsym", ".note.gnu.build-id"} {
		require.Contains(t, library, section)
	}
	require.NotContains(t, library, ".debug_")
	require.NotContains(t, library, ".gnu_debuglink")

	// Check the running Puma process, including Fullstaq's linked jemalloc allocator.
	maps, err := compose.ExecOutput("testserver", "cat", "/proc/1/maps")
	require.NoError(t, err)
	require.Contains(t, maps, rubyRoot+"/bin/ruby")
	require.Contains(t, maps, rubyRoot+"/lib/libruby.so.3.4.8")
	require.Contains(t, maps, rubyRoot+"/lib/libjemalloc.so.1")
}

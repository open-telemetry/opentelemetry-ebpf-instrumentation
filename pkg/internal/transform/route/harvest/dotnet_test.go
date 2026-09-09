// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func TestDotnetRoute(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "relative route", raw: "api/customers/{id:int}", want: "/api/customers/{id:int}", ok: true},
		{name: "tilde route", raw: "~/api/customers/{id?}/", want: "/api/customers/{id?}", ok: true},
		{name: "root", raw: "/", want: "/", ok: true},
		{name: "whitespace", raw: "  /api/customers/  ", want: "/api/customers", ok: true},
		{name: "all slashes", raw: "///"},
		{name: "empty", raw: ""},
		{name: "blank", raw: " \t "},
		{name: "URL", raw: "https://example.com/path"},
		{name: "URL in route", raw: "/api://customers"},
		{name: "newline", raw: "/api\ncustomers"},
		{name: "NUL", raw: "/api\x00customers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dotnetRoute(tt.raw)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDotnetLen(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint32
		size int
		ok   bool
	}{
		{name: "one byte minimum", data: []byte{0}, want: 0, size: 1, ok: true},
		{name: "one byte maximum", data: []byte{0x7f}, want: 0x7f, size: 1, ok: true},
		{name: "two byte minimum", data: []byte{0x80, 0x80}, want: 0x80, size: 2, ok: true},
		{name: "two byte maximum", data: []byte{0xbf, 0xff}, want: 0x3fff, size: 2, ok: true},
		{name: "four byte minimum", data: []byte{0xc0, 0x00, 0x40, 0x00}, want: 0x4000, size: 4, ok: true},
		{name: "four byte maximum", data: []byte{0xdf, 0xff, 0xff, 0xff}, want: 0x1fffffff, size: 4, ok: true},
		{name: "following data", data: []byte{4, 9, 9}, want: 4, size: 1, ok: true},
		{name: "missing", data: nil},
		{name: "truncated two bytes", data: []byte{0x80}},
		{name: "truncated four bytes", data: []byte{0xc0, 0, 0}},
		{name: "invalid prefix", data: []byte{0xe0, 0, 0, 0}},
		{name: "invalid all ones prefix", data: []byte{0xff, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, size, ok := dotnetLen(tt.data)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.size, size)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestDotnetAdd(t *testing.T) {
	t.Run("adds normalised route", func(t *testing.T) {
		e := dotnetExtractor{rs: map[string]struct{}{}}
		e.add("api/customers/")
		e.add("/api/customers")

		assert.Equal(t, map[string]struct{}{`/api/customers`: {}}, e.rs)
	})

	t.Run("ignores invalid route", func(t *testing.T) {
		e := dotnetExtractor{rs: map[string]struct{}{}}
		e.add("https://example.com")

		assert.Empty(t, e.rs)
	})

	t.Run("caps route count", func(t *testing.T) {
		e := dotnetExtractor{rs: make(map[string]struct{}, maxDotnetRoutes)}
		for i := 0; i < maxDotnetRoutes; i++ {
			e.rs["/"+strconv.Itoa(i)] = struct{}{}
		}

		e.add("/not-added")

		assert.Len(t, e.rs, maxDotnetRoutes)
		assert.NotContains(t, e.rs, "/not-added")
	})
}

func TestExtractDotnetRoutes(t *testing.T) {
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result, err := ExtractDotnetRoutes(ctx, nil)

		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, result)
	})

	t.Run("missing file info", func(t *testing.T) {
		result, err := ExtractDotnetRoutes(context.Background(), nil)

		assert.EqualError(t, err, ".NET route harvesting requires process file info")
		assert.Nil(t, result)
	})

	t.Run("missing entry assembly", func(t *testing.T) {
		fi := exec.New(exec.Init{
			Pid:        app.PID(os.Getpid()),
			CmdExePath: filepath.Join(t.TempDir(), "routes"),
		})

		result, err := ExtractDotnetRoutes(context.Background(), fi)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid entry assembly", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "routes")
		require.NoError(t, os.WriteFile(path+".dll", []byte("not a PE file"), 0o600))
		fi := exec.New(exec.Init{Pid: app.PID(os.Getpid()), CmdExePath: path})

		result, err := ExtractDotnetRoutes(context.Background(), fi)

		assert.ErrorContains(t, err, "read .NET entry assembly")
		assert.Nil(t, result)
	})

	t.Run("harvests attribute and minimal routes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "routes")
		require.NoError(t, os.WriteFile(path+".dll", testBlobBytes(t), 0o600))
		fi := exec.New(exec.Init{Pid: app.PID(os.Getpid()), CmdExePath: path})

		result, err := ExtractDotnetRoutes(context.Background(), fi)

		require.NoError(t, err)
		assert.Equal(t, PartialRoutes, result.Kind)
		assert.Equal(t, []string{
			"/api/Products",
			"/minimal/{id}",
			"/Get/{id}",
			"/health",
			"/items",
		}, result.Routes)
	})
}

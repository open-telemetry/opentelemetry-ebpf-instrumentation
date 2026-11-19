// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanSinatraRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   []string
	}{
		{"classic style", "get '/users/:id' do\n  'ok'\nend", []string{"/users/:id"}},
		{"double quotes", `get "/users/:id" do`, []string{"/users/:id"}},
		{"all verbs", "get '/a' do\nend\npost '/a' do\nend\nput '/a' do\nend\npatch '/a' do\nend\ndelete '/a' do\nend\nhead '/a' do\nend\noptions '/a' do\nend", []string{"/a"}},
		{"parenthesized", "get('/users/:id') do\nend", []string{"/users/:id"}},
		{"block syntax", "get '/users/:id' do |id|\n  id\nend", []string{"/users/:id"}},
		{"modular app", "class App < Sinatra::Base\n  get '/users/:id' do\n  end\nend", []string{"/users/:id"}},
		{"root route", "get '/' do\nend", []string{"/"}},
		{"multiple routes", "get '/users' do\nend\nget '/users/:id' do\nend\npost '/users' do\nend", []string{"/users", "/users/:id"}},
		{"comments", "# get '/ignored'\n=begin\nget '/ignored'\n=end\nget '/health' do # comment\nend", []string{"/health"}},
		{"optional trailing slash", "get '/posts/?' do\nend", []string{"/posts"}},
		{"optional parameter", "get '/posts/:id?' do\nend", []string{"/posts/:id"}},
		{"optional slash and parameter", "get '/posts/?:id?' do\nend", []string{"/posts/:id"}},
		{"optional root slash", "get '/?' do\nend", []string{"/"}},
		{"optional literal character", "get '/colou?r' do\nend", nil},
		{"unsupported patterns", "get '/users(/:id)' do\nend\nget '/files/*path' do\nend", nil},
		{"status symbol", "get '/health' do\n  head :ok\nend\nhead :ok\nhead(:no_content)", []string{"/health"}},
		{"padrino named routes", "get :index do\nend\nget :show, :with => :id do\nend\nget :edit, with: :id do\nend", nil},
		{"string with options", "get '/users', :provides => :json do\nend\nget '/admin', agent: /Firefox/ do\nend", []string{"/users", "/admin"}},
		{"string concatenation", "get '/users' + suffix do\nend", nil},
		{"not a route declaration", "get_logger.info('/users')\nputs '/users'", nil},
		{"dynamic path", "get \"/users/#{id}\" do\nend", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, err := scanSinatraRoutes(t.Context(), strings.NewReader(tc.source))
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, routes)
		})
	}
}

func TestScanSinatraRoutesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := scanSinatraRoutes(ctx, strings.NewReader(`get '/users' do`))
	require.ErrorIs(t, err, context.Canceled)
}

// extractRailsRoutes falls back to scanning for Sinatra routes when no Rails
// config/routes.rb is found anywhere between cwd and the application root.
func TestExtractRailsRoutesSinatraFallback(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "controllers"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "Gemfile"), []byte(
		"source 'https://rubygems.org'\n\ngem 'sinatra'\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "app.rb"), []byte(
		"require 'sinatra'\n\nget '/users/:id' do\n  'ok'\nend\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "controllers", "admin.rb"), []byte(
		"get '/admin' do\nend\n"), 0o644))

	result, err := extractRailsRoutes(t.Context(), root, "/app")
	require.NoError(t, err)
	assert.Equal(t, PartialRoutes, result.Kind)
	assert.ElementsMatch(t, []string{"/users/:id", "/admin"}, result.Routes)
}

// A server may start below the application root; the Gemfile is then found in
// a parent of the working directory.
func TestExtractRailsRoutesSinatraFallbackParentGemfile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "web"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "Gemfile.lock"), []byte(
		"GEM\n  remote: https://rubygems.org/\n  specs:\n    sinatra (4.1.1)\n\nDEPENDENCIES\n  sinatra\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "web", "app.rb"), []byte(
		"get '/users/:id' do\nend\n"), 0o644))

	result, err := extractRailsRoutes(t.Context(), root, "/app/web")
	require.NoError(t, err)
	assert.Equal(t, []string{"/users/:id"}, result.Routes)
}

// Other Ruby frameworks use the same bare verb declarations: without Sinatra
// among the application's gems, nothing is harvested.
func TestExtractRailsRoutesSinatraFallbackRequiresSinatra(t *testing.T) {
	const grapeAPI = "class API < Grape::API\n  resource :users do\n    get ':id' do\n    end\n    get '/all' do\n    end\n  end\nend\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"no manifest", nil},
		{"grape gemfile", map[string]string{"Gemfile": "source 'https://rubygems.org'\n\ngem 'grape'\ngem 'puma'\n"}},
		{"grape lockfile", map[string]string{
			"Gemfile":      "gem 'grape'\n",
			"Gemfile.lock": "GEM\n  specs:\n    grape (2.2.0)\n      rack (>= 2)\n    rack (3.1.8)\n\nDEPENDENCIES\n  grape\n",
		}},
		{"commented out", map[string]string{"Gemfile": "# gem 'sinatra'\ngem 'grape'\n"}},
		{"other sinatra gems", map[string]string{"Gemfile": "gem 'sinatra-contrib-lookalike'\ngem 'grape'\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
			for name, content := range tc.files {
				require.NoError(t, os.WriteFile(filepath.Join(root, "app", name), []byte(content), 0o644))
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, "app", "api.rb"), []byte(grapeAPI), 0o644))

			result, err := extractRailsRoutes(t.Context(), root, "/app")
			require.NoError(t, err)
			assert.Equal(t, PartialRoutes, result.Kind)
			assert.Empty(t, result.Routes)
		})
	}
}

func TestDependsOnSinatra(t *testing.T) {
	for _, tc := range []struct {
		name, file, content string
		want                bool
	}{
		{"gemfile single quotes", "Gemfile", "gem 'sinatra'\n", true},
		{"gemfile double quotes and version", "Gemfile", "gem \"sinatra\", \"~> 4.0\"\n", true},
		{"gemfile parentheses", "Gemfile", "gem('sinatra', require: 'sinatra/base')\n", true},
		{"gemfile in group", "Gemfile", "group :web do\n  gem 'sinatra'\nend\n", true},
		{"gems.rb", "gems.rb", "gem 'sinatra'\n", true},
		{"gemfile other gem", "Gemfile", "gem 'sinatra-contrib'\ngem 'grape'\n", false},
		{"gemfile commented", "Gemfile", "# gem 'sinatra'\n", false},
		{"lockfile resolved", "Gemfile.lock", "GEM\n  specs:\n    sinatra (4.1.1)\n      rack (>= 3.0.0)\n", true},
		{"lockfile transitive", "Gemfile.lock", "GEM\n  specs:\n    padrino-core (0.16.0)\n      sinatra (>= 4)\n", true},
		{"lockfile direct", "Gemfile.lock", "DEPENDENCIES\n  sinatra\n", true},
		{"lockfile pinned source", "Gemfile.lock", "DEPENDENCIES\n  sinatra!\n", true},
		{"lockfile windows line endings", "Gemfile.lock", "DEPENDENCIES\r\n  sinatra\r\n", true},
		{"gems.locked", "gems.locked", "DEPENDENCIES\n  sinatra (~> 4.0)\n", true},
		{"lockfile other gems", "Gemfile.lock", "GEM\n  specs:\n    sinatra-contrib (4.1.1)\n    rack-sinatra (1.0)\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "app")
			require.NoError(t, os.MkdirAll(dir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o644))

			got, err := dependsOnSinatra(t.Context(), root, dir)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The nearest Bundler manifest describes the application; one further up
// belongs to something else.
func TestDependsOnSinatraUsesNearestManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "srv", "api")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "srv", "Gemfile"), []byte("gem 'sinatra'\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile"), []byte("gem 'grape'\n"), 0o644))

	got, err := dependsOnSinatra(t.Context(), root, dir)
	require.NoError(t, err)
	assert.False(t, got)
}

// When cwd cannot be narrowed down past the filesystem root, the Sinatra
// fallback must not scan the entire tree.
func TestExtractRailsRoutesSinatraFallbackSkipsFilesystemRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "app.rb"), []byte(
		"get '/users/:id' do\nend\n"), 0o644))

	result, err := extractRailsRoutes(t.Context(), root, "/")
	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestWalkRubyFilesSkipsIrrelevantDirs(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "vendor"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "spec"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "vendor", "ignored.rb"), []byte(`get '/ignored' do`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "spec", "ignored_spec.rb"), []byte(`get '/ignored' do`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app.rb"), []byte(`get '/kept' do`), 0o644))

	var visited []string
	err := walkRubyFiles(t.Context(), root, func(path string) error {
		visited = append(visited, path)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "app.rb")}, visited)
}

// Directories named like Linux system directories (lib, bin, opt...) or like
// Node.js build output are regular application directories in a Ruby app.
func TestWalkRubyFilesKeepsApplicationDirs(t *testing.T) {
	root := t.TempDir()
	var want []string
	for _, dir := range []string{"bin", "build", "lib", "opt", "srv"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
		path := filepath.Join(root, dir, "routes.rb")
		require.NoError(t, os.WriteFile(path, []byte(`get '/kept' do`), 0o644))
		want = append(want, path)
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".git", "ignored.rb"), []byte(`get '/ignored' do`), 0o644))

	var visited []string
	err := walkRubyFiles(t.Context(), root, func(path string) error {
		visited = append(visited, path)
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, want, visited)
}

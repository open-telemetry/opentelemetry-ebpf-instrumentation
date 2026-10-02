// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestScanRailsRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   []string
	}{
		{"resources", `resources :users`, []string{"/users", "/users/new", "/users/:id", "/users/:id/edit"}},
		{"multiple resources", `resources :posts, :comments`, []string{"/posts", "/posts/new", "/posts/:id", "/posts/:id/edit", "/comments", "/comments/new", "/comments/:id", "/comments/:id/edit"}},
		{"multiline options", "resources :users,\n  # public path\n  path: 'people',\n  only: [:index, :show]", []string{"/people", "/people/:id"}},
		{"limited actions", `resources :users, only: [:index, :show]`, []string{"/users", "/users/:id"}},
		{"hash rocket only", `resources :posts, :only => :show`, []string{"/posts/:id"}},
		{"hash rocket multiple resources", `resources :posts, :comments, :only => :show`, []string{"/posts/:id", "/comments/:id"}},
		{"action options stay local", "resources :users, only: :show\nresources :posts", []string{"/users/:id", "/posts", "/posts/new", "/posts/:id", "/posts/:id/edit"}},
		{"excluded actions", `resources :users, except: %i[new edit]`, []string{"/users", "/users/:id"}},
		{"hash rocket except", `resources :users, :except => %i[new edit]`, []string{"/users", "/users/:id"}},
		{"single action", `resource :profile, only: :show`, []string{"/profile"}},
		{"hash rocket path and parameter", `resources :users, :path => 'people', :param => :slug`, []string{"/people", "/people/new", "/people/:slug", "/people/:slug/edit"}},
		{"dynamic actions", `resources :users, only: actions`, nil},
		{"empty actions", `resources :users, only: []`, nil},
		{"singular resource", `resource :profile`, []string{"/profile", "/profile/new", "/profile/edit"}},
		{"multiple singular resources", `resource :profile, :account`, []string{"/profile", "/profile/new", "/profile/edit", "/account", "/account/new", "/account/edit"}},
		{"custom path and parameter", `resources :users, path: 'people', param: :slug`, []string{"/people", "/people/new", "/people/:slug", "/people/:slug/edit"}},
		{"literal routes", "get '/users/:id', to: 'users#show'\npost(\"users\", to: 'users#create')\nmatch 'health', via: :all\nget :preview", []string{"/users/:id", "/users", "/health", "/preview"}},
		{"scopes", "namespace :admin do\nscope path: '/api/v1' do\nget 'status', to: 'status#index'\nend\nend", []string{"/admin", "/api/v1", "/status"}},
		{"root", `root 'users#index'`, []string{"/"}},
		{"comments", "# get '/ignored'\n=begin\nget '/ignored'\n=end\nget '/health', to: 'health#show' # comment\nget '/health'", []string{"/health"}},
		{"dynamic paths", "get \"/users/#{name}\"\nget PREFIX + '/users'\nget '/users' + suffix\nresources :users, path: user_path\nresources :users, param: dynamic_param\nget /pattern/", nil},
		{"unsupported patterns", "get '/users(/:id)'\nget '/files/*path'", nil},
		// The comma-based continuation rule only joins lines while the previous
		// line ends in a trailing comma; an "only: [" opening its own line breaks
		// that chain. The declaration is then parsed with an unresolved "only:"
		// value, which safely drops the whole resource instead of guessing.
		{"multiline array without trailing comma on open bracket", "resources :users,\n  only: [\n    :index,\n    :show\n  ]", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, _, err := scanRailsRoutes(t.Context(), strings.NewReader(tc.source))
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, routes)
		})
	}
}

// A line longer than bufio.Scanner's default 64KiB token limit must not abort
// the scan; the scanner buffer is sized to the same budget as maxRailsFileBytes.
func TestScanRailsRoutesLongLine(t *testing.T) {
	padding := strings.Repeat(" ", 128*1024)
	source := fmt.Sprintf("# %s\nget '/health'", padding)
	routes, _, err := scanRailsRoutes(t.Context(), strings.NewReader(source))
	require.NoError(t, err)
	assert.Equal(t, []string{"/health"}, routes)
}

func TestRailsRouteMatcher(t *testing.T) {
	routes, _, err := scanRailsRoutes(t.Context(), strings.NewReader(`
Rails.application.routes.draw do
 namespace :admin do
  resources :users do
   resources :comments
  end
 end
end
`))
	require.NoError(t, err)
	matcher := RouteMatcherFromResult(RouteHarvesterResult{Routes: routes, Kind: PartialRoutes})
	for path, want := range map[string]string{
		"/admin/users/123":              "/admin/users/:id",
		"/admin/users/new":              "/admin/users/new",
		"/admin/users/123/edit":         "/admin/users/:id/edit",
		"/admin/users/123/comments/456": "/admin/users/:id/comments/:id",
		"/unknown/123":                  "",
	} {
		assert.Equal(t, want, matcher.Find(path), path)
	}
}

func TestExtractRailsRoutes(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "config"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "config", "routes.rb"), []byte(`get '/health'`), 0o644))
	for _, cwd := range []string{"/app", "/app/bin"} {
		result, err := extractRailsRoutes(t.Context(), root, cwd)
		require.NoError(t, err)
		assert.Equal(t, PartialRoutes, result.Kind)
		assert.Equal(t, []string{"/health"}, result.Routes)
	}
	result, err := extractRailsRoutes(t.Context(), root, "/")
	require.NoError(t, err)
	assert.Empty(t, result.Routes)
}

func TestReadRailsAPIOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   bool
	}{
		{"enabled", "config.api_only = true", true},
		{"enabled with comment", "config.api_only = true # generated API application", true},
		{"disabled", "config.api_only = false", false},
		{"commented", "# config.api_only = true", false},
		{"block commented", "=begin\nconfig.api_only = true\n=end", false},
		{"dynamic", "config.api_only = ENV.fetch('API_ONLY')", false},
		{"last assignment wins", "config.api_only = true\nconfig.api_only = false", false},
		{"last assignment enables", "config.api_only = false\nconfig.api_only = true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "application.rb")
			require.NoError(t, os.WriteFile(path, []byte(tc.source), 0o644))
			got, err := readRailsAPIOnly(t.Context(), path)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractRailsRoutesUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "oversized", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, "config"), 0o755))
			path := filepath.Join(root, "config", "routes.rb")
			switch kind {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "routes.rb")
				require.NoError(t, os.WriteFile(outside, []byte(`get '/outside'`), 0o644))
				require.NoError(t, os.Symlink(outside, path))
			case "oversized":
				require.NoError(t, os.WriteFile(path, []byte(strings.Repeat(" ", int(maxRailsFileBytes)+1)), 0o644))
			case "directory":
				require.NoError(t, os.Mkdir(path, 0o755))
			}
			result, err := extractRailsRoutes(t.Context(), root, "/")
			require.NoError(t, err)
			assert.Empty(t, result.Routes)
		})
	}
}

type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}

func TestScanRailsRoutesCancellationAndReadError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := scanRailsRoutes(ctx, strings.NewReader(`resources :users`))
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = scanRailsRoutes(t.Context(), erroringReader{})
	require.Error(t, err)
}

func TestHarvestRoutesRuby(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		var languages []services.RouteHarvesterLanguage
		if disabled {
			languages = append(languages, services.RouteHarvesterLanguageRuby)
		}
		h := NewRouteHarvester(&services.RouteHarvestingConfig{}, languages, time.Second)
		called := false
		h.rubyExtractRoutes = func(ctx context.Context, pid app.PID) (*RouteHarvesterResult, error) {
			called = true
			assert.Equal(t, app.PID(12345), pid)
			return successfulExtractRoutes(ctx, pid)
		}
		result, err := h.HarvestRoutes(createTestFileInfo(svc.InstrumentableRuby))
		require.NoError(t, err)
		assert.Equal(t, !disabled, called)
		if disabled {
			assert.Nil(t, result)
		} else {
			require.NotNil(t, result)
			assert.NotEmpty(t, result.Routes)
		}
	}
}

func TestHarvestRoutesRubyError(t *testing.T) {
	h := NewRouteHarvester(&services.RouteHarvestingConfig{}, nil, time.Second)
	want := errors.New("cannot read routes")
	h.rubyExtractRoutes = func(context.Context, app.PID) (*RouteHarvesterResult, error) {
		return nil, want
	}
	_, err := h.HarvestRoutes(createTestFileInfo(svc.InstrumentableRuby))
	require.ErrorIs(t, err, want)
}

// Checks the actual integration app so fixture changes cannot silently break route harvesting.
func TestRailsIntegrationFixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	require.NoError(t, err)
	result, err := extractRailsRoutes(t.Context(), root, "/internal/test/integration/components/rubytestserver/testapi")
	require.NoError(t, err)
	matcher := RouteMatcherFromResult(*result)
	for path, want := range map[string]string{
		"/graphql":                      "/graphql",
		"/graphql/alpha":                "/graphql/:tenant_id",
		"/graphql/beta":                 "/graphql/:tenant_id",
		"/harvest/engine/graphql/gamma": "/harvest/engine/graphql/:tenant_id",
		"/users/1":                      "/users/:id",
		"/users/new":                    "/users/:id",
		"/smoke":                        "/smoke",
		"/harvest/orders/alpha":         "/harvest/orders/:order_id",
		"/harvest/orders/beta":          "/harvest/orders/:order_id",
		"/harvest/api/widgets/first":    "/harvest/api/widgets/:widget_id",
	} {
		assert.Equal(t, want, matcher.Find(path), path)
	}
}

func TestRailsDrawReferences(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"config/routes.rb": `
get '/health'
draw :orders
draw("api/widgets")
draw :orders
# draw :unused
draw dynamic_name
draw "#{dynamic_name}"
draw '../outside'
draw '/outside'
draw :missing
draw :linked
draw :internal_link
`,
		"config/routes/orders.rb":      "get '/orders/:order_id'\ndraw :shared",
		"config/routes/api/widgets.rb": "get '/widgets/:widget_id'\ndraw :shared",
		"config/routes/shared.rb":      "get '/shared'\ndraw :orders",
		"config/routes/unused.rb":      "get '/unused'",
		"config/outside.rb":            "get '/outside'",
	}
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
	}
	outside := filepath.Join(t.TempDir(), "outside.rb")
	require.NoError(t, os.WriteFile(outside, []byte(`get '/linked'`), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "config", "routes", "linked.rb")))
	require.NoError(t, os.Symlink(filepath.Join(root, "config", "outside.rb"), filepath.Join(root, "config", "routes", "internal_link.rb")))
	result, err := extractRailsRoutes(t.Context(), root, "/")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"/health", "/orders/:order_id", "/widgets/:widget_id", "/shared"}, result.Routes)
}

func TestRailsDrawFileLimit(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "config", "routes"), 0o755))
	var main strings.Builder
	for i := range maxRailsRouteFiles + 1 {
		name := fmt.Sprintf("routes%d", i)
		fmt.Fprintf(&main, "draw :%s\n", name)
		require.NoError(t, os.WriteFile(filepath.Join(root, "config", "routes", name+".rb"), []byte(fmt.Sprintf("get '/%s'", name)), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "config", "routes.rb"), []byte(main.String()), 0o644))
	result, err := extractRailsRoutes(t.Context(), root, "/")
	require.NoError(t, err)
	assert.Len(t, result.Routes, maxRailsRouteFiles-1)
}

// Follows mounted engines and their own draws, including cyclic references,
// without importing routes from unmounted engines or the host's similarly named draw.
func TestRailsMountedEngines(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"config/routes.rb": `
Rails.application.routes.draw do
  mount Backend::Engine, at: '/'
  mount Backend::Engine => '/v2'
  mount Admin::Engine,
    at: '/admin'
  mount Missing::Engine, at: '/missing'
  mount Unused::Engine, at: dynamic_path
  # mount Unused::Engine, at: '/unused'
end`,
		"config/routes/shared.rb": `get '/wrong_draw'`,
		"components/backend_api/config/routes.rb": `Backend::Engine.routes.draw do
  post '/graphql', to: 'graphql#execute'
  resources :orders, only: [:show], param: :order_id
  draw :shared
  mount Admin::Engine, at: '/nested'
end`,
		"components/backend_api/config/routes/shared.rb": "get '/engine_draw/:key'\ndraw :shared",
		"engines/admin/config/routes.rb": `Admin::Engine.routes.draw do
  get '/reports/:report_id'
  mount Backend::Engine, at: '/backend'
end`,
		"components/unused/config/routes.rb": "Unused::Engine.routes.draw do\nget '/unused_route'\nend",
	}
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
	}
	result, err := extractRailsRoutes(t.Context(), root, "/")
	require.NoError(t, err)
	assert.NotContains(t, result.Routes, "/unused_route")
	assert.NotContains(t, result.Routes, "/wrong_draw")
	matcher := RouteMatcherFromResult(*result)
	for path, want := range map[string]string{
		"/graphql":            "/graphql",
		"/v2/graphql":         "/v2/graphql",
		"/orders/123":         "/orders/:order_id",
		"/admin/reports/123":  "/admin/reports/:report_id",
		"/nested/reports/123": "/nested/reports/:report_id",
		"/engine_draw/abc":    "/engine_draw/:key",
	} {
		assert.Equal(t, want, matcher.Find(path), path)
	}
}

// Accepts common mount spellings but rejects expressions that require Ruby evaluation.
func TestRailsMountLiterals(t *testing.T) {
	for _, source := range []string{
		`mount Backend::Engine, at: '/api'`,
		`mount(::Backend::Engine => '/api')`,
		`mount Backend::Engine, :at => '/api'`,
	} {
		name, path, ok := railsMountValue(source)
		require.True(t, ok, source)
		assert.Equal(t, "Backend::Engine", name)
		assert.Equal(t, "/api", path)
	}
	for _, source := range []string{
		`mount engine, at: '/api'`,
		`mount Backend::Engine, at: prefix`,
		`mount Backend::Engine, at: '/api' + suffix`,
		`mount Backend::Engine, at: "#{prefix}"`,
	} {
		_, _, ok := railsMountValue(source)
		assert.False(t, ok, source)
	}
}

// Avoids choosing between duplicate engine names or following links outside the app,
// and checks that cancellation stops discovery.
func TestRailsEngineIndexSafety(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for _, name := range []string{"one", "two"} {
		path := filepath.Join(root, "components", name, "config", "routes.rb")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("Duplicate::Engine.routes.draw do\nget '/ambiguous'\nend"), 0o644))
	}
	outside := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(outside, "config"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "config", "routes.rb"), []byte("Outside::Engine.routes.draw do\nget '/outside'\nend"), 0o644))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "components", "linked")))
	engines, err := findRailsEngines(t.Context(), root, root)
	require.NoError(t, err)
	require.Contains(t, engines, "Duplicate::Engine")
	assert.Empty(t, engines["Duplicate::Engine"])
	assert.NotContains(t, engines, "Outside::Engine")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = findRailsEngines(ctx, root, root)
	require.ErrorIs(t, err, context.Canceled)
}

// Finds the engine constant despite comments, while rejecting conditional declarations
// and the host application's route set.
func TestReadRailsEngineName(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"# frozen_string_literal: true\nBackend::Engine.routes.draw do # routes", "Backend::Engine"},
		{"=begin\nFake::Engine.routes.draw do\n=end\n::Backend::Engine.routes.draw do", "Backend::Engine"},
		{"if enabled\nBackend::Engine.routes.draw do", ""},
		{"Rails.application.routes.draw do", ""},
	} {
		path := filepath.Join(t.TempDir(), "routes.rb")
		require.NoError(t, os.WriteFile(path, []byte(tc.source), 0o644))
		name, err := readRailsEngineName(t.Context(), path)
		require.NoError(t, err)
		assert.Equal(t, tc.want, name)
	}
}

// Checks GraphQL routes across mount forms and nested engines. Named parameters must
// survive matching, and mounts that cannot be resolved must not contribute routes.
func TestRailsGraphQLMounts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		path   string
		route  string
	}{
		{"plain endpoint", `mount GraphqlAPI::Engine, at: '/'`, "/graphql", "/graphql"},
		{"nested engines", `mount Gateway::Engine, at: '/gateway'`, "/gateway/api/graphql/alpha", "/gateway/api/graphql/:tenant_id"},
		{"root", `mount GraphqlAPI::Engine, at: '/'`, "/graphql/alpha", "/graphql/:tenant_id"},
		{"prefix", `mount GraphqlAPI::Engine, at: '/api'`, "/api/graphql/alpha", "/api/graphql/:tenant_id"},
		{"hash rocket", `mount(GraphqlAPI::Engine => '/api')`, "/api/graphql/beta", "/api/graphql/:tenant_id"},
		{"scope", "scope '/v1' do\n mount GraphqlAPI::Engine, at: '/api'\nend", "/v1/api/graphql/alpha", "/v1/api/graphql/:tenant_id"},
		{"multiline", "mount GraphqlAPI::Engine,\n at: '/api'", "/api/graphql/alpha", "/api/graphql/:tenant_id"},
		{"repeated", "mount GraphqlAPI::Engine, at: '/'\nmount GraphqlAPI::Engine, at: '/api', as: :api", "/api/graphql/alpha", "/api/graphql/:tenant_id"},
		{"unmounted", `get '/health'`, "", ""},
		{"commented", `# mount GraphqlAPI::Engine, at: '/'`, "", ""},
		{"dynamic mount", `mount GraphqlAPI::Engine, at: ENV.fetch('PREFIX')`, "", ""},
		{"different engine", `mount Other::Engine, at: '/'`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, source := range map[string]string{
				"config/routes.rb":                            tc.source,
				"engines/gateway/config/routes.rb":            "Gateway::Engine.routes.draw do\n mount GraphqlAPI::Engine, at: '/api'\nend",
				"components/backend/config/routes.rb":         "GraphqlAPI::Engine.routes.draw do\n draw :graphql\nend",
				"components/backend/config/routes/graphql.rb": "post '/graphql', to: 'queries#execute'\npost '/graphql/:tenant_id', to: 'queries#execute'",
				"config/routes/graphql.rb":                    "post '/wrong_graphql'",
			} {
				path := filepath.Join(root, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
			}
			result, err := extractRailsRoutes(t.Context(), root, "/")
			require.NoError(t, err)
			// The host has a draw with the same name; the engine must use its own file.
			assert.NotContains(t, result.Routes, "/wrong_graphql")
			if tc.route == "" {
				assert.NotContains(t, result.Routes, "/graphql")
				assert.NotContains(t, result.Routes, "/graphql/:tenant_id")
				return
			}
			assert.Contains(t, result.Routes, "/graphql")
			assert.Contains(t, result.Routes, "/graphql/:tenant_id")
			matcher := RouteMatcherFromResult(*result)
			assert.Equal(t, tc.route, matcher.Find(tc.path))
		})
	}
}

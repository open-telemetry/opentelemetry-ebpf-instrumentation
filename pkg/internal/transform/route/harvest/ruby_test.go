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
		{"multiline options", "resources :users,\n  # public path\n  path: 'people',\n  only: [:index, :show]", []string{"/people", "/people/:id"}},
		{"limited actions", `resources :users, only: [:index, :show]`, []string{"/users", "/users/:id"}},
		{"excluded actions", `resources :users, except: %i[new edit]`, []string{"/users", "/users/:id"}},
		{"single action", `resource :profile, only: :show`, []string{"/profile"}},
		{"dynamic actions", `resources :users, only: actions`, nil},
		{"empty actions", `resources :users, only: []`, nil},
		{"singular resource", `resource :profile`, []string{"/profile", "/profile/new", "/profile/edit"}},
		{"custom path and parameter", `resources :users, path: 'people', param: :slug`, []string{"/people", "/people/new", "/people/:slug", "/people/:slug/edit"}},
		{"literal routes", "get '/users/:id', to: 'users#show'\npost(\"users\", to: 'users#create')\nmatch 'health', via: :all\nget :preview", []string{"/users/:id", "/users", "/health", "/preview"}},
		{"scopes", "namespace :admin do\nscope path: '/api/v1' do\nget 'status', to: 'status#index'\nend\nend", []string{"/admin", "/api/v1", "/status"}},
		{"root", `root 'users#index'`, []string{"/"}},
		{"comments", "# get '/ignored'\n=begin\nget '/ignored'\n=end\nget '/health', to: 'health#show' # comment\nget '/health'", []string{"/health"}},
		{"dynamic paths", "get \"/users/#{name}\"\nget PREFIX + '/users'\nget '/users' + suffix\nresources :users, path: user_path\nresources :users, param: dynamic_param\nget /pattern/", nil},
		{"unsupported patterns", "get '/users(/:id)'\nget '/files/*path'", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, _, err := scanRailsRoutes(t.Context(), strings.NewReader(tc.source))
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, routes)
		})
	}
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
				require.NoError(t, os.WriteFile(path, []byte(strings.Repeat(" ", int(maxRailsRoutesBytes)+1)), 0o644))
			case "directory":
				require.NoError(t, os.Mkdir(path, 0o755))
			}
			result, err := extractRailsRoutes(t.Context(), root, "/")
			require.NoError(t, err)
			assert.Empty(t, result.Routes)
		})
	}
}

func TestScanRailsRoutesCancellationAndReadError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := scanRailsRoutes(ctx, strings.NewReader(`resources :users`))
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = scanRailsRoutes(t.Context(), strings.NewReader(strings.Repeat("x", 128*1024)))
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

func TestRailsIntegrationFixture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	require.NoError(t, err)
	result, err := extractRailsRoutes(t.Context(), root, "/internal/test/integration/components/rubytestserver/testapi")
	require.NoError(t, err)
	matcher := RouteMatcherFromResult(*result)
	for path, want := range map[string]string{
		"/users/1":                   "/users/:id",
		"/smoke":                     "/smoke",
		"/harvest/orders/alpha":      "/harvest/orders/:order_id",
		"/harvest/orders/beta":       "/harvest/orders/:order_id",
		"/harvest/api/widgets/first": "/harvest/api/widgets/:widget_id",
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

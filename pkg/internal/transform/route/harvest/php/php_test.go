// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/transform/route"
	phpharvest "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"
)

func TestExtractRoutesFromLaravelProject(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "laravel", "basic"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/users/{user}"}, routes)
}

func TestExtractRoutesFromLaravelFeatures(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "laravel", "features"))

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/api/photos/{photo}/comments/create",
		"/api/comments/{comment}/edit",
		"/api/photos/{photo}/comments",
		"/api/v1/users/{user}",
		"/api/admin/audit",
		"/api/v1/status",
		"/api/v1/users",
		"/api/comments/{comment}",
		"/api/old",
	}, routes)
}

func TestExtractRoutesFromLaravelResourceVariants(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "laravel", "resource_variants"))

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/account/create",
		"/account/edit",
		"/profile/edit",
		"/posts/{post}",
		"/settings",
		"/account",
		"/profile",
	}, routes)
}

func TestExtractRoutesUsesOnlyStaticLaravelLiterals(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "laravel", "static_literals"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/double", "/single"}, routes)
}

func TestExtractRoutesFromModernSymfonyProject(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "symfony", "modern"))

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/library/public-books/{id}",
		`/api/orders/{id<\d+>}`,
		"/library/books/{id}",
		"/admin/users/{id}",
		"/api/health",
		"/from-php/{id}",
		"/status/{code}",
	}, routes)
}

func TestExtractRoutesFromLegacySymfonyProject(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "symfony", "legacy"))

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/legacy/status/{code}",
		"/legacy/orders/{id}",
		"/xml/admin/{id}",
		"/xml/health",
		"/xml/old",
		"/legacy-php/{id}",
	}, routes)
}

func TestExtractRoutesFromImportedSymfonyAttributes(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "symfony", "imported_attributes"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/api/orders/{id}"}, routes)
}

func TestExtractRoutesFromMappedSymfonyAttributes(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "symfony", "mapped_attributes"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/api/users/{id}"}, routes)
}

func TestExtractRoutesFromSlimFourProject(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "slim", "v4"))

	require.NoError(t, err)
	assert.Equal(t, []string{
		"/service/api/nested/echo/{value}",
		"/service/api/news/{*params}",
		"/service/api/users/{id}",
		"/service/api/news",
	}, routes)

	matcher := route.NewPartialRouteMatcher(routes)
	assert.Equal(t, "/service/api/users/{id}", matcher.Find("/service/api/users/1234"))
	assert.Equal(t, "/service/api/news/{*params}", matcher.Find("/service/api/news/2026/09/17"))
}

func TestExtractRoutesFromSlimThreeProject(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "slim", "v3"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/v3/things/{id}"}, routes)
}

func TestExtractRoutesSkipsUnconfirmedFrameworks(t *testing.T) {
	projects := []string{"malformed", "unsupported", "symfony_component"}
	for _, project := range projects {
		t.Run(project, func(t *testing.T) {
			routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "composer", project))

			require.NoError(t, err)
			assert.Nil(t, routes)
		})
	}
}

func TestExtractRoutesKeepsValidCallsAndSkipsExcludedPHPFiles(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "scanner", "project"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/broken", "/valid"}, routes)
}

func TestExtractRoutesMergesComposerConfirmedFrameworks(t *testing.T) {
	routes, err := phpharvest.ExtractRoutes(context.Background(), filepath.Join("testdata", "composer", "multiple"))

	require.NoError(t, err)
	assert.Equal(t, []string{"/laravel/{id}", "/symfony/{id}", "/slim/{id}"}, routes)
}

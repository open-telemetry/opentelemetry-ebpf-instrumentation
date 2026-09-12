// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyLegacyPHP(t *testing.T) {
	root := t.TempDir()
	validPath := filepath.Join(root, "app", "config", "routing.php")
	tokens := lexPHP([]byte(`
        use \Symfony\Component\Routing\Route;
		$routes[] = new Route('/users');
		$routes[] = new route('/lowercase');
		$routes[] = new Route;
		$routes[] = new Route($dynamic);
        $routes[] = new Other('/ignored');
    `))
	routes := newRouteSet()

	extractSymfonyLegacyPHP(validPath, root, tokens, routes)
	extractSymfonyLegacyPHP(filepath.Join(root, "src", "routing.php"), root, tokens, routes)
	extractSymfonyLegacyPHP(validPath, root, lexPHP([]byte(`new Route('/without-import');`)), routes)

	assert.Equal(t, routeSet{"/users": {}, "/lowercase": {}}, routes)
}

func TestImportsSymfonyRoute(t *testing.T) {
	for _, code := range []string{
		`use Symfony\Component\Routing\Route;`,
		`USE \symfony\component\routing\route;`,
	} {
		assert.True(t, importsSymfonyRoute(lexPHP([]byte(code))), code)
	}

	assert.False(t, importsSymfonyRoute(nil))
	assert.False(t, importsSymfonyRoute(lexPHP([]byte(`use Symfony\Component\Routing\RouteCollection;`))))
	assert.False(t, importsSymfonyRoute(lexPHP([]byte(`new \Symfony\Component\Routing\Route('/users');`))))
}

func TestIsLegacySymfonyConfig(t *testing.T) {
	root := t.TempDir()

	for _, relative := range []string{"app/config/routing.php", "app/config/routes/admin.php", "config/routes/legacy.php"} {
		assert.True(t, isLegacySymfonyConfig(filepath.Join(root, filepath.FromSlash(relative)), root), relative)
	}

	for _, relative := range []string{"app/configuration/routing.php", "config/routes.php", "src/routes.php"} {
		assert.False(t, isLegacySymfonyConfig(filepath.Join(root, filepath.FromSlash(relative)), root), relative)
	}
	assert.False(t, isLegacySymfonyConfig(filepath.Join(filepath.Dir(root), "app", "config", "routing.php"), root))
}

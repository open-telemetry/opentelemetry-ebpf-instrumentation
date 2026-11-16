// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanFalcon(t *testing.T) {
	routes := map[string]struct{}{}
	lines := []string{
		`app.add_route("/users/{user_id}", UserResource())`,
		`app.add_route('/items/{item_id:int}', ItemResource())`,
		`app.add_route('/orders/{order_id}', OrderResource(), suffix='order')`,
		`app.add_route('/files/{name}.{ext}', FileResource())`,
		`app.add_route('/dates/{ts:dt("%Y-%m-%d")}', DateResource())`,
		`app.add_route("/dates/{ts:dt(\"%Y-%m-%d\")}", DateResource())`,
		`app.add_route(uri_template="/users/{user_id}", resource=UserResource())`,
		`app.add_route(uri_template='/items/{item_id:int}', resource=ItemResource())`,
		`app.add_route('/files/{file_path:path}', FileResource())`,
	}
	for _, line := range lines {
		scanFalcon(line, routes)
	}

	assert.ElementsMatch(t, []string{
		"/users/{user_id}",
		"/items/{item_id}",
		"/orders/{order_id}",
		"/dates/{ts}",
		"/files/{file_path:path}",
	}, routeKeys(routes))
}

func TestScanFalconSkipsUnsupportedForms(t *testing.T) {
	routes := map[string]struct{}{}
	for _, line := range []string{
		`app.add_route(PATH, Resource())`,
		`app.add_route(f"/users/{user_id}", Resource())`,
		`app.add_route(`,
		`"/users/{user_id}")`,
		`app.add_route('/files/{name}.{ext}', Resource())`,
	} {
		scanFalcon(line, routes)
	}

	assert.Empty(t, routes)
}

func TestFalconImportPattern(t *testing.T) {
	for _, line := range []string{
		`import falcon`,
		`import falcon.asgi`,
		`import falcon as f`,
		`from falcon import App`,
		`from falcon import asgi`,
		`from falcon.asgi import App`,
	} {
		assert.True(t, falconImportPattern.MatchString(line), line)
	}

	assert.False(t, falconImportPattern.MatchString(`import flask`))
}

func TestStartsFalcon(t *testing.T) {
	assert.True(t, startsFalcon(`app.add_route("/users", Resource())`))
	assert.False(t, startsFalcon(`app.add_static_route("/static", "/tmp")`))
}

func TestScanFalconIgnoresNestedURIKeyword(t *testing.T) {
	routes := map[string]struct{}{}

	scanFalcon(
		`app.add_route(resource=Resource(uri_template="/wrong"), uri_template="/correct/{id}")`,
		routes,
	)

	assert.Equal(t, map[string]struct{}{
		"/correct/{id}": {},
	}, routes)
}

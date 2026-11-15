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
	}
	for _, line := range lines {
		scanFalcon(line, routes)
	}

	assert.ElementsMatch(t, []string{
		"/users/{user_id}",
		"/items/{item_id}",
		"/orders/{order_id}",
		"/dates/{ts}",
	}, routeKeys(routes))
}

func TestScanFalconSkipsUnsupportedForms(t *testing.T) {
	routes := map[string]struct{}{}
	for _, line := range []string{
		`app.add_route(PATH, Resource())`,
		`app.add_route(f"/users/{user_id}", Resource())`,
		`app.add_route(`,
		`"/users/{user_id}")`,
	} {
		scanFalcon(line, routes)
	}

	assert.Empty(t, routes)
}

func TestStartsFalcon(t *testing.T) {
	assert.True(t, startsFalcon(`app.add_route("/users", Resource())`))
	assert.False(t, startsFalcon(`app.add_static_route("/static", "/tmp")`))
}

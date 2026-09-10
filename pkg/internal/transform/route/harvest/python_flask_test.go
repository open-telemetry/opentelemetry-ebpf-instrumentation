// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanFlask(t *testing.T) {
	routes := map[string]struct{}{}
	lines := []string{
		`@app.route("/items/<int:item_id>")`,
		`@app.get(rule=r'/orders')`,
		`app.add_url_rule(u"/health", view_func=health)`,
		`app.add_url_rule(view_func=ready, rule="/ready")`,
		`bp = flask.Blueprint("users", __name__, url_prefix="/users")`,
		`app.register_blueprint(bp, url_prefix='/api')`,
	}
	for _, line := range lines {
		scanFlask(line, routes)
	}

	assert.ElementsMatch(t, []string{
		"/api", "/health", "/items/<int:item_id>", "/orders", "/ready", "/users",
	}, routeKeys(routes))
}

func TestScanFlaskSkipsUnsupportedForms(t *testing.T) {
	routes := map[string]struct{}{}
	for _, line := range []string{
		`@app.route(f"/{item_id}")`,
		`@app.route(PATH)`,
		`@app.route(`,
		`"/split")`,
	} {
		scanFlask(line, routes)
	}

	assert.Empty(t, routes)
}

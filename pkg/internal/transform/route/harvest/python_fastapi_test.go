// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanFastAPI(t *testing.T) {
	routes := map[string]struct{}{}
	lines := []string{
		`@app.get("/items/{item_id}")`,
		`@router.post(path=r'/orders')`,
		`app.add_api_route(u"/health", health)`,
		`app.add_api_route(endpoint=ready, path="/ready")`,
		`router = APIRouter(prefix="/users")`,
		`app.include_router(router, prefix='/api')`,
	}
	for _, line := range lines {
		scanFastAPI(line, routes)
	}

	assert.ElementsMatch(t, []string{
		"/api", "/health", "/items/{item_id}", "/orders", "/ready", "/users",
	}, routeKeys(routes))
}

func TestScanFastAPISkipsUnsupportedForms(t *testing.T) {
	routes := map[string]struct{}{}
	for _, line := range []string{
		`@app.get(f"/{item_id}")`,
		`@app.get(PATH)`,
		`@app.websocket("/socket")`,
		`@app.get(`,
		`"/split")`,
	} {
		scanFastAPI(line, routes)
	}

	assert.Empty(t, routes)
}

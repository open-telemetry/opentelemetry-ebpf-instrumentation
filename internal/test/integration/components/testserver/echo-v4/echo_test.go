// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package echov4

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRoutes(t *testing.T) {
	h := handler()
	for _, tc := range []struct {
		name, method, path, route string
		status                    int
	}{
		{"first ID", "GET", "/api/rolldice/4", "/api/rolldice/:id", 200},
		{"second ID", "GET", "/api/rolldice/42", "/api/rolldice/:id", 200},
		{"static", "GET", "/api/health", "/api/health", 200},
		{"wildcard", "GET", "/api/files/a/b", "/api/files/*", 200},
		{"auxiliary lookup", "GET", "/api/lookup/42", "/api/lookup/:id", 200},
		{"pre-routing lookup", "GET", "/api/prelookup/42", "/api/prelookup/:id", 200},
		{"request WithContext", "GET", "/api/with-context/42", "/api/with-context/:id", 200},
		{"request Clone", "GET", "/api/clone/42", "/api/clone/:id", 200},
		{"method mismatch", "POST", "/api/rolldice/42", "", 405},
		{"unmatched after match", "GET", "/missing", "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, tc.status, w.Code)
			if tc.route != "" {
				assert.Equal(t, tc.route, w.Body.String())
			}
			assert.Equal(t, tc.path, r.URL.Path)
		})
	}
}

func TestRouterContextReuse(t *testing.T) {
	e := echo.New()
	e.GET("/users/:id", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	c := e.AcquireContext()
	defer e.ReleaseContext(c)
	for _, tc := range []struct{ method, path, route string }{
		{"GET", "/users/1", "/users/:id"},
		{"GET", "/missing", ""},
		{"POST", "/users/2", "/users/:id"},
		{"GET", "/missing-again", ""},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			c.Reset(httptest.NewRequest(tc.method, tc.path, nil), httptest.NewRecorder())
			e.Router().Find(tc.method, tc.path, c)
			assert.Equal(t, tc.route, c.Path())
		})
	}
}

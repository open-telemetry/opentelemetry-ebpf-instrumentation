// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package echov4 // import "go.opentelemetry.io/obi/internal/test/integration/components/testserver/echo-v4"

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/labstack/echo/v4"
)

func handler() http.Handler {
	e := echo.New()
	auxiliary := echo.New()
	auxiliary.GET("/auxiliary/:key", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	lookup := func() {
		aux := auxiliary.NewContext(httptest.NewRequest(http.MethodGet, "/auxiliary/check", nil), httptest.NewRecorder())
		auxiliary.Router().Find(http.MethodGet, "/auxiliary/check", aux)
	}
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			switch {
			case strings.HasPrefix(c.Request().URL.Path, "/api/prelookup/"):
				lookup()
			case strings.HasPrefix(c.Request().URL.Path, "/api/with-context/"):
				c.SetRequest(c.Request().WithContext(c.Request().Context()))
			case strings.HasPrefix(c.Request().URL.Path, "/api/clone/"):
				c.SetRequest(c.Request().Clone(c.Request().Context()))
			}
			return next(c)
		}
	})
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { return next(c) }
	})
	respond := func(c echo.Context) error {
		return c.String(http.StatusOK, c.Path())
	}
	api := e.Group("/api")
	api.GET("/rolldice/:id", respond)
	api.GET("/health", respond)
	api.GET("/files/*", respond)
	api.GET("/prelookup/:id", respond)
	api.GET("/with-context/:id", respond)
	api.GET("/clone/:id", respond)
	api.GET("/lookup/:id", func(c echo.Context) error {
		lookup()
		return respond(c)
	})
	mux := http.NewServeMux()
	mux.Handle("/", e)
	return mux
}

func Setup(port int) {
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), handler())
	slog.Error("Echo v4 HTTP server stopped", "error", err)
}

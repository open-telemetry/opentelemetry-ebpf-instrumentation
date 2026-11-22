// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package echov4 // import "go.opentelemetry.io/obi/internal/test/integration/components/testserver/echo-v4"

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func handler() http.Handler {
	e := echo.New()
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { return next(c) }
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
	mux := http.NewServeMux()
	mux.Handle("/", e)
	return mux
}

func Setup(port int) {
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), handler())
	slog.Error("Echo v4 HTTP server stopped", "error", err)
}

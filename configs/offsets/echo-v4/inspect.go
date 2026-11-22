// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	e.GET("/api/users/:id", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Path())
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:8090", e))
}

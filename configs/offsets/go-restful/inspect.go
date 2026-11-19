// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"net/http"

	restful "github.com/emicklei/go-restful/v3"
)

func main() {
	ws := new(restful.WebService)
	ws.Path("/api")
	ws.Route(ws.GET("/users/{id}").To(func(_ *restful.Request, resp *restful.Response) {
		_, _ = resp.Write([]byte("ok"))
	}))

	container := restful.NewContainer()
	container.Add(ws)

	log.Fatal(http.ListenAndServe("127.0.0.1:8090", container))
}

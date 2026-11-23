// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package restful // import "go.opentelemetry.io/obi/internal/test/integration/components/testserver/go-restful"

import (
	"fmt"
	"log/slog"
	"net/http"

	restful "github.com/emicklei/go-restful/v3"
)

func Setup(port int) {
	log := slog.With("component", "restful.Server")

	ws := new(restful.WebService)
	ws.Path("/api").Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/rolldice/{id}").To(func(req *restful.Request, resp *restful.Response) {
		diceID := req.PathParameter("id")

		if err := resp.WriteEntity(map[string]string{"id": diceID}); err != nil {
			log.Error("error encoding json", "error", err)
		}
	}))

	container := restful.NewContainer()
	container.Add(ws)

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)

	err := http.ListenAndServe(address, container)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"go.opentelemetry.io/obi/internal/test/integration/components/testserver_1.17/arg"
)

func Setup(port int) {
	r := gin.Default()

	r.NoRoute(func(ctx *gin.Context) {
		fmt.Printf("received request with url %s\n", ctx.Request.RequestURI)
		status := arg.DefaultStatus
		if sstr := ctx.Query(arg.Status); sstr != "" {
			if s, err := strconv.Atoi(sstr); err != nil {
				fmt.Printf("wrong status value. Ignoring error %w\n", err)
			} else {
				status = s
			}
		}
		if dstr := ctx.Query(arg.Delay); dstr != "" {
			if d, err := time.ParseDuration(dstr); err != nil {
				fmt.Printf("wrong delay value. Ignoring error %w\n", err)
			} else {
				time.Sleep(d)
			}
		}
		ctx.String(status, "")
	})

	address := fmt.Sprintf(":%d", port)
	fmt.Printf("starting HTTP server at address %s\n", address)
	err := r.Run(address)
	fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
}

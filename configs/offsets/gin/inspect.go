// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func main() {
	log := slog.With("component", "gin.Server")
	r := gin.Default()

	r.GET("/api/users/:id/posts/:postID", func(c *gin.Context) {
		userID := c.Param("id")
		postID := c.Param("postID")
		c.JSON(200, gin.H{
			"user_id": userID,
			"post_id": postID,
		})
	})

	address := fmt.Sprintf(":%d", 8090)
	log.Info("starting HTTP server", "address", address)
	err := r.Run(address)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}

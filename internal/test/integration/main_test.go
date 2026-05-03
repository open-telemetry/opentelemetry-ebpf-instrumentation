// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/moby/moby/client"
	"github.com/ory/dockertest/v4"
)

var dockerPool dockertest.ClosablePool

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	ctx := context.Background()

	var err error
	dockerPool, err = dockertest.NewPool(ctx, "")
	if err != nil {
		fmt.Printf("could not create Docker pool: %v\n", err)
		os.Exit(1)
	}

	if _, err = dockerPool.Client().Ping(ctx, client.PingOptions{}); err != nil {
		fmt.Printf("could not connect to Docker daemon: %v\n", err)
		os.Exit(1)
	}

	if err = buildOBIImage(ctx); err != nil {
		fmt.Printf("failed to build OBI image: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err = dockerPool.Close(ctx); err != nil {
		fmt.Printf("could not close Docker pool: %v\n", err)
		os.Exit(1)
	}

	os.Exit(code)
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/ory/dockertest/v3"
)

var dockerPool *dockertest.Pool

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	var err error
	dockerPool, err = dockertest.NewPool("")
	if err != nil {
		fmt.Printf("could not create Docker pool: %v\n", err)
		os.Exit(1)
	}
	if err = dockerPool.Client.Ping(); err != nil {
		fmt.Printf("could not connect to Docker daemon: %v\n", err)
		os.Exit(1)
	}

	if err = buildOBIImage(); err != nil {
		fmt.Printf("failed to build OBI image: %v\n", err)
		os.Exit(1)
	}

	m.Run()
}

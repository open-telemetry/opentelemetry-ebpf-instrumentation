// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	cleanup, err := buildOBIImage()
	if err != nil {
		fmt.Printf("failed to build OBI image: %v\n", err)
		os.Exit(1)
	}

	m.Run()

	if err := cleanup(); err != nil {
		fmt.Printf("failed to remove OBI image: %v\n", err)
		os.Exit(1)
	}
}

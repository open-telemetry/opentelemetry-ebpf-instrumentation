// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const suiteName = "Yaml Suite"

func RunSpecs(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, suiteName)
}

func RegisterSuite() bool {
	return ginkgo.Describe("test case", ginkgo.Label("docker", "integration", "slow"), func() {
		base := os.Getenv("TESTCASE_BASE_PATH")
		if base != "" {
			ginkgo.It("runs OATS cases", func() {
				args, err := oatsArgs(base)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())

				cmd := exec.Command(oatsBinary(), args...)
				cmd.Stdout = ginkgo.GinkgoWriter
				cmd.Stderr = ginkgo.GinkgoWriter
				gomega.Expect(cmd.Run()).To(gomega.Succeed())
			})
		}
	})
}

func oatsBinary() string {
	if binary := os.Getenv("TESTCASE_OATS_BIN"); binary != "" {
		return binary
	}
	return "oats"
}

func oatsArgs(base string) ([]string, error) {
	timeout := os.Getenv("TESTCASE_TIMEOUT")
	if timeout == "" {
		timeout = (30 * time.Second).String()
	}
	if _, err := time.ParseDuration(timeout); err != nil {
		return nil, fmt.Errorf("parse TESTCASE_TIMEOUT: %w", err)
	}

	return []string{
		"--config", filepath.Join(base, "oats-config.yaml"),
		"--timeout", timeout,
		"--container-runtime", "docker",
		"--gcx-download", "auto",
		"--no-cache",
	}, nil
}

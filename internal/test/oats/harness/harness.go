// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"os"
	"testing"
	"time"

	"github.com/grafana/oats/model"
	"github.com/grafana/oats/yaml"
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
		cases, base := readTestCases()
		if base != "" {
			ginkgo.It("should have at least one test case", func() {
				gomega.Expect(cases).ToNot(gomega.BeEmpty(), "expected at least one test case in %s", base)
			})
		}

		yaml.VerboseLogging = true
		settings := testCaseSettings()

		for i := range cases {
			c := cases[i]
			ginkgo.It(c.Name, func() {
				yaml.RunTestCase(&c, settings)
			})
		}
	})
}

func readTestCases() ([]model.TestCase, string) {
	base := os.Getenv("TESTCASE_BASE_PATH")
	if base == "" {
		return nil, ""
	}

	cases, err := yaml.ReadTestCases([]string{base}, true)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	return cases, base
}

func testCaseSettings() model.Settings {
	timeout := 30 * time.Second
	if value := os.Getenv("TESTCASE_TIMEOUT"); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	}

	return model.Settings{
		Host:          "localhost",
		Timeout:       timeout,
		AbsentTimeout: 10 * time.Second,
		LgtmVersion:   "latest",
		LgtmLogSettings: map[string]bool{
			"ENABLE_LOGS_ALL":        false,
			"ENABLE_LOGS_GRAFANA":    false,
			"ENABLE_LOGS_PROMETHEUS": false,
			"ENABLE_LOGS_LOKI":       false,
			"ENABLE_LOGS_TEMPO":      false,
			"ENABLE_LOGS_PYROSCOPE":  false,
			"ENABLE_LOGS_OTELCOL":    false,
		},
		ManualDebug: os.Getenv("TESTCASE_MANUAL_DEBUG") == "true",
		LogLimit:    1000,
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oats

import (
	"fmt"
	"testing"
	"time"

	"github.com/grafana/oats/model"
	"github.com/grafana/oats/yaml"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestYaml(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Yaml Suite")
}

var _ = Describe("test case", Label("docker", "integration", "slow"), func() {
	fmt.Println("First test")
	cases, err := yaml.ReadTestCases([]string{"."}, true)
	Expect(err).ToNot(HaveOccurred())
	It("should have at least one test case", func() {
		Expect(cases).ToNot(BeEmpty(), "expected at least one test case")
	})

	yaml.VerboseLogging = true
	settings := model.Settings{
		Host:          "127.0.0.1",
		Timeout:       30 * time.Second,
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
		LogLimit: 1000,
	}

	for _, c := range cases {
		tc := c
		Describe(c.Name, Ordered, func() {
			yaml.RunTestCase(&tc, settings)
		})
	}
})

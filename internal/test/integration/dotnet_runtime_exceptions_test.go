// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func testDotnetExceptionMetrics(t *testing.T, client *http.Client, workload, runtimeVersion string, endpoints []string, reconnect func()) {
	t.Helper()
	previous := make([]map[string]float64, len(endpoints))
	for round := range 2 {
		if round > 0 {
			reconnect()
		}
		for index, endpoint := range endpoints {
			values, err := scrapeDotnetExceptions(client, endpoint)
			require.NoError(t, err)
			if previous[index] != nil {
				require.Equal(t, previous[index], values, "reconnect must preserve exception totals")
			}
			previous[index] = values
		}
		var reference struct {
			Before map[string]uint64 `json:"before"`
			After  map[string]uint64 `json:"after"`
		}
		response, err := client.Post(workload+"/exceptions-run", "application/json", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&reference))
		require.NoError(t, response.Body.Close())
		require.Len(t, reference.After, 7)
		if runtimeVersion != "8.0" {
			require.Never(t, func() bool {
				for _, endpoint := range endpoints {
					values, err := scrapeDotnetExceptions(client, endpoint)
					require.NoError(t, err)
					if len(values) != 0 {
						return true
					}
				}
				return false
			}, 3*time.Second, time.Second)
			return
		}
		for index, endpoint := range endpoints {
			want := make(map[string]float64)
			for name, after := range reference.After {
				delta := after - reference.Before[name]
				require.Positive(t, delta, name)
				want[name] = previous[index][name] + float64(delta)
			}
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				values, err := scrapeDotnetExceptions(client, endpoint)
				require.NoError(ct, err)
				require.Equal(ct, want, values)
			}, testTimeout, time.Second)
			previous[index] = want
			t.Logf("exception round %d %s: %v", round+1, endpoint, want)
		}
	}
}

func scrapeDotnetExceptions(client *http.Client, endpoint string) (map[string]float64, error) {
	response, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned %s", response.Status)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(response.Body)
	if err != nil {
		return nil, err
	}
	values := make(map[string]float64)
	family := families[attributes.DotnetExceptions.Prom]
	if family == nil {
		return values, nil // No controlled exceptions have been thrown yet.
	}
	if family.GetType() != dto.MetricType_COUNTER {
		return nil, errors.New("exceptions must be a counter")
	}
	for _, metric := range family.GetMetric() {
		labels := make(map[string]string)
		for _, pair := range metric.GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		name := labels["error_type"]
		if labels["service_name"] != "dotnet-runtime" || labels["service_namespace"] != "integration-test" || !strings.HasPrefix(name, "Pr5") {
			continue
		}
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate exception type %q", name)
		}
		values[name] = metric.GetCounter().GetValue()
	}
	return values, nil
}

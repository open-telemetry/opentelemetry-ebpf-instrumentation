// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

type dotnetCPUSnapshot struct {
	Count  int     `json:"cpuCount"`
	User   float64 `json:"cpuUser"`
	System float64 `json:"cpuSystem"`
}

func testDotnetCPUMetrics(t *testing.T, client *http.Client, workload string, endpoints []string, count int, reconnect func()) {
	t.Helper()
	readReference := func() (dotnetCPUSnapshot, error) {
		var snapshot dotnetCPUSnapshot
		response, err := client.Get(workload + "/snapshot")
		if err != nil {
			return snapshot, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return snapshot, fmt.Errorf("CPU reference endpoint returned %s", response.Status)
		}
		err = json.NewDecoder(response.Body).Decode(&snapshot)
		return snapshot, err
	}
	for round := range 2 {
		before, err := readReference()
		require.NoError(t, err)
		require.Equal(t, count, before.Count, "managed reference must reflect the configured CPU restriction")
		if round > 0 {
			reconnect()
		}
		for _, endpoint := range endpoints {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				values, err := scrapeDotnetCPU(client, endpoint)
				require.NoError(ct, err)
				latest, err := readReference()
				require.NoError(ct, err)
				require.Equal(ct, latest.Count, values.Count)
				// proc stat reports whole ticks; managed reference uses finer precision.
				require.GreaterOrEqual(ct, values.User, before.User-0.02)
				require.GreaterOrEqual(ct, values.System, before.System-0.02)
				require.LessOrEqual(ct, values.User, latest.User+0.02)
				require.LessOrEqual(ct, values.System, latest.System+0.02)
			}, testTimeout, time.Second)
		}
		var reference struct {
			Before dotnetCPUSnapshot `json:"before"`
			After  dotnetCPUSnapshot `json:"after"`
		}
		loadClient := &http.Client{Timeout: 30 * time.Second}
		response, err := loadClient.Post(workload+"/cpu-run", "application/json", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&reference))
		require.NoError(t, response.Body.Close())
		require.GreaterOrEqual(t, reference.After.User-reference.Before.User, 0.19)
		require.GreaterOrEqual(t, reference.After.System-reference.Before.System, 0.09)
		for _, endpoint := range endpoints {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				values, err := scrapeDotnetCPU(client, endpoint)
				require.NoError(ct, err)
				latest, err := readReference()
				require.NoError(ct, err)
				require.Equal(ct, count, values.Count)
				require.GreaterOrEqual(ct, values.User, reference.After.User-0.02)
				require.GreaterOrEqual(ct, values.System, reference.After.System-0.02)
				require.LessOrEqual(ct, values.User, latest.User+0.02)
				require.LessOrEqual(ct, values.System, latest.System+0.02)
			}, testTimeout, time.Second)
		}
		t.Logf("CPU round %d: count=%d, user delta=%.3fs, system delta=%.3fs", round+1, count,
			reference.After.User-reference.Before.User, reference.After.System-reference.Before.System)
	}
}

func scrapeDotnetCPU(client *http.Client, endpoint string) (dotnetCPUSnapshot, error) {
	var result dotnetCPUSnapshot
	response, err := client.Get(endpoint)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("CPU metrics endpoint returned %s", response.Status)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(response.Body)
	if err != nil {
		return result, err
	}
	seen := map[string]bool{}
	for _, name := range []string{attributes.DotnetProcessCPUCount.Prom, attributes.DotnetProcessCPUTime.Prom} {
		family := families[name]
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["service_name"] != "dotnet-runtime" || labels["service_namespace"] != "integration-test" {
				continue
			}
			key := name + labels["cpu_mode"]
			if seen[key] {
				return result, fmt.Errorf("duplicate CPU series %s", key)
			}
			seen[key] = true
			if name == attributes.DotnetProcessCPUCount.Prom {
				if family.GetType() != dto.MetricType_GAUGE || metric.Gauge == nil || labels["cpu_mode"] != "" {
					return result, errors.New("invalid CPU count series")
				}
				value := metric.GetGauge().GetValue()
				result.Count = int(value)
				if result.Count <= 0 || float64(result.Count) != value {
					return result, fmt.Errorf("invalid CPU count %v", value)
				}
				continue
			}
			if family.GetType() != dto.MetricType_COUNTER || metric.Counter == nil {
				return result, errors.New("invalid CPU time series")
			}
			switch labels["cpu_mode"] {
			case "user":
				result.User = metric.GetCounter().GetValue()
			case "system":
				result.System = metric.GetCounter().GetValue()
			default:
				return result, fmt.Errorf("unexpected CPU mode %q", labels["cpu_mode"])
			}
		}
	}
	if !seen[attributes.DotnetProcessCPUCount.Prom] || !seen[attributes.DotnetProcessCPUTime.Prom+"user"] || !seen[attributes.DotnetProcessCPUTime.Prom+"system"] {
		return result, fmt.Errorf("missing CPU series: %v", seen)
	}
	return result, nil
}

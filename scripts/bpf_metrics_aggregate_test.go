// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBPFMetricsAggregateRetainsEarlierSuites(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	dir := filepath.Join(t.TempDir(), "artifacts with spaces")
	for _, fixture := range []struct {
		artifact string
		shard    string
		peak     int
		suite    string
	}{
		{"bpf-metrics-1-42-1", "1", 100, "TestCompletedEarlier"},
		{"bpf-metrics-1-42-2", "1", 200, "TestRetried"},
		{"bpf-metrics-1-42-10", "1", 10, "TestRetried"},
		{"bpf-metrics-2-42-1", "2", 21, "TestOtherShard"},
		{"bpf-metrics-3-42-1", "3", 31, "TestCompletedShard"},
		{"bpf-metrics-3-42-2", "3", 0, ""},
	} {
		summary := map[string]any{
			"shard": fixture.shard,
			"peak": map[string]any{
				"total_bytes_memlock": fixture.peak, "maps": 1, "progs": 0,
				"maps_grouped": []map[string]any{{
					"name": "shared_map", "type": "hash", "total_memlock": fixture.peak,
					"count": 1, "max_entries": 16,
				}},
			},
			"suites": []map[string]any{{
				"name": fixture.suite, "peak_bytes": fixture.peak,
				"duration_s": 1, "snapshots_in_window": 1, "series": []int{fixture.peak},
				"result": "pass",
			}},
		}
		if fixture.suite == "" {
			summary["suites"] = []map[string]any{}
		}
		path := filepath.Join(dir, fixture.artifact)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "summary.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outputJSON := filepath.Join(dir, "aggregate.json")
	cmd := exec.CommandContext(t.Context(), "bash", "./bpf-metrics-aggregate.sh",
		"--in", dir, "--out-md", filepath.Join(dir, "aggregate.md"), "--out-json", outputJSON)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("aggregate failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outputJSON)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Shards int `json:"shards"`
		Suites []struct {
			Name      string `json:"name"`
			PeakBytes int    `json:"peak_bytes"`
		} `json:"suites"`
		PeakMaps []struct {
			MaxTotalMemlock  int `json:"max_total_memlock"`
			ObservedInShards int `json:"observed_in_shards"`
		} `json:"peak_maps"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Shards != 3 || len(result.Suites) != 4 || len(result.PeakMaps) != 1 {
		t.Fatalf("counted more than one attempt per shard: %s", data)
	}
	wantSuites := []string{"TestCompletedEarlier", "TestCompletedShard", "TestOtherShard", "TestRetried"}
	for i, name := range wantSuites {
		if result.Suites[i].Name != name {
			t.Fatalf("did not retain each suite's latest observation: %s", data)
		}
	}
	if result.Suites[3].PeakBytes != 10 {
		t.Fatalf("included stale metrics for a retried suite: %s", data)
	}
	if result.PeakMaps[0].MaxTotalMemlock != 21 || result.PeakMaps[0].ObservedInShards != 3 {
		t.Fatalf("included stale attempt peaks: %s", data)
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// gpuCounterMetricsExpected are the CUDA counter series OBI emits, in the
// Prometheus form the collector exports (OTLP dots -> underscores; monotonic
// sums get a _total suffix; the memory allocations counter carries a "By" unit
// so the collector appends _bytes). Each is driven by a distinct CUDA Runtime
// API call the target makes every loop iteration.
var gpuCounterMetricsExpected = []string{
	"gpu_cuda_kernel_launch_calls_total",      // cudaLaunchKernel
	"gpu_cuda_graph_launch_calls_total",       // cudaGraphLaunch
	"gpu_cuda_memory_allocations_bytes_total", // cudaMalloc (unit "By")
}

// gpuHistogramFamilyPrefixes are the CUDA histogram families. The collector
// explodes each OTLP histogram into _bucket/_sum/_count and, for the unit-"1"
// histograms, may insert a unit suffix (e.g. _ratio) before those — so we match
// the _count series with an optional-suffix regex rather than a fixed name.
var gpuHistogramFamilyPrefixes = []string{
	"gpu_cuda_kernel_grid_size",  // grid dims from cudaLaunchKernel
	"gpu_cuda_kernel_block_size", // block dims from cudaLaunchKernel
	"gpu_cuda_memory_copies",     // cudaMemcpy / cudaMemcpyAsync
}

// TestGPUCudaMetrics brings up a target that dynamically links a stub
// libcudart.so and calls the CUDA Runtime API in a loop. OBI (with CUDA
// instrumentation forced on) attaches its gpuevent uprobes to those symbols by
// name — needing no GPU or NVIDIA driver — so every call emits a gpu.cuda.*
// metric. The collector fans the OTLP stream out to a Prometheus exporter
// (asserted here) and to weaver, which live-checks the surface against the
// semantic-convention registry in enforce mode.
func TestGPUCudaMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-gpu.yml", path.Join(pathOutput, "test-suite-gpu.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	// Cleanups run LIFO: register compose.Close() first so it runs LAST, after
	// runWeaverValidation has /stopped the still-running weaver container.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("gpu.cuda.* metrics exported over OTLP", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, name := range gpuCounterMetricsExpected {
				results, err := pq.Query(name)
				if !assert.NoError(ct, err, "querying %s", name) {
					continue
				}
				assert.NotEmptyf(ct, results, "gpu metric %s should be present", name)
			}
			for _, prefix := range gpuHistogramFamilyPrefixes {
				q := `{__name__=~"` + prefix + `.*_count"}`
				results, err := pq.Query(q)
				if !assert.NoError(ct, err, "querying %s", q) {
					continue
				}
				assert.NotEmptyf(ct, results, "gpu histogram family %s should be present", prefix)
			}
		}, testTimeout, 500*time.Millisecond)

		// The cuda.memcpy.kind attribute is default-on for gpu.cuda.memory.copies
		// and the target cycles through every copy direction, so the label must be
		// populated with at least one recognized value.
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`{__name__=~"gpu_cuda_memory_copies.*_count"}`)
			if !assert.NoError(ct, err) {
				return
			}
			kinds := map[string]bool{}
			for _, r := range results {
				if k := r.Metric["cuda_memcpy_kind"]; k != "" {
					kinds[k] = true
				}
			}
			assert.NotEmpty(ct, kinds, "cuda_memcpy_kind label should be present on gpu_cuda_memory_copies")
		}, testTimeout, 500*time.Millisecond)

		// Diagnostic: log the full gpu_cuda_* surface actually observed, so the
		// exact collector-exported series names can be reconciled against what the
		// emitter really emits.
		if observed, err := pq.Query(`group by (__name__) ({__name__=~"gpu_cuda_.*"})`); err == nil {
			names := make([]string, 0, len(observed))
			for _, r := range observed {
				names = append(names, r.Metric["__name__"])
			}
			t.Logf("observed gpu_cuda_* metric series: %v", names)
		}
	})
}

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
	"gpu_cuda_memory_free_bytes_total",        // cudaFree (unit "By")
	"gpu_cuda_memset_bytes_total",             // cudaMemset (unit "By")
	"gpu_cuda_stream_create_calls_total",      // cudaStreamCreate*
	"gpu_cuda_stream_destroy_calls_total",     // cudaStreamDestroy
	"gpu_cuda_event_record_calls_total",       // cudaEventRecord*
	"gpu_cuda_event_synchronize_calls_total",  // cudaEventSynchronize
	"gpu_cuda_stream_synchronize_calls_total", // cudaStreamSynchronize
	"gpu_cuda_device_synchronize_calls_total", // cudaDeviceSynchronize
	"gpu_cuda_host_register_bytes_total",      // cudaHostRegister (unit "By")
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

// gpuDriverService is the service name OBI derives from the driver target's
// executable. Scoping queries to it proves the cu* uprobes fire for a process
// that maps libcuda.so.1 alone, without any libcudart.
const gpuDriverService = "gpu-cuda-driver-tester"

// gpuDriverCtxService is the service name OBI derives from the driver target
// that binds a nonzero context via cuCtxCreate/cuCtxPushCurrent. OBI does not
// instrument those calls, so its metrics must omit device identity labels.
const gpuDriverCtxService = "gpu-cuda-driver-ctx-tester"

// gpuSetDeviceService is the service name OBI derives from the target that
// explicitly calls cudaSetDevice(1). Its metrics must carry resolved device
// identity labels.
const gpuSetDeviceService = "gpu-cuda-setdevice-tester"

// TestGPUCudaMetrics brings up two targets: one that dynamically links a stub
// libcudart.so and calls the CUDA Runtime API in a loop, and one that links a
// stub libcuda.so.1 and calls the CUDA Driver API. OBI (with CUDA
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

	// The driver target maps libcuda.so.1 alone, so its series prove the cu*
	// uprobes fire independently of the libcudart target.
	t.Run("gpu.cuda.* metrics from the CUDA Driver API target", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, name := range []string{
				"gpu_cuda_kernel_launch_calls_total", // cuLaunchKernel / cuLaunchKernelEx
				"gpu_cuda_graph_launch_calls_total",  // cuGraphLaunch
			} {
				q := name + `{service_name="` + gpuDriverService + `"}`
				results, err := pq.Query(q)
				if !assert.NoError(ct, err, "querying %s", q) {
					continue
				}
				assert.NotEmptyf(ct, results, "driver API metric %s should be present", name)
			}
			// cuLaunchKernel / cuLaunchKernelEx must feed the same grid and
			// block-size histograms as the runtime API launches.
			for _, prefix := range []string{
				"gpu_cuda_kernel_grid_size",
				"gpu_cuda_kernel_block_size",
			} {
				q := `{__name__=~"` + prefix + `.*_count",service_name="` + gpuDriverService + `"}`
				results, err := pq.Query(q)
				if !assert.NoError(ct, err, "querying %s", q) {
					continue
				}
				assert.NotEmptyf(ct, results, "driver API histogram family %s should be present", prefix)
			}
		}, testTimeout, 500*time.Millisecond)
	})

	// Target that binds to device 1 and queries its properties. Every GPU metric
	// emitted by this service must carry the resolved device identity labels.
	t.Run("gpu.cuda.* metrics carry device identity for cudaSetDevice(1)", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			q := `gpu_cuda_kernel_launch_calls_total{service_name="` + gpuSetDeviceService + `"}`
			results, err := pq.Query(q)
			if !assert.NoError(ct, err, "querying %s", q) {
				return
			}
			assert.NotEmpty(ct, results, "kernel launch metric should be present for %s", gpuSetDeviceService)

			for _, r := range results {
				assert.Equal(ct, "1", r.Metric["cuda_device_index"], "expected device index 1")
				assert.Equal(ct, "00000000-0000-0000-0000-000000000001", r.Metric["cuda_device_uuid"], "expected device UUID for device 1")
				assert.Equal(ct, "OBI Test GPU A", r.Metric["cuda_device_model"], "expected device model for device 1")
			}
		}, testTimeout, 500*time.Millisecond)
	})

	// Driver API target never calls cudaSetDevice/cudaGetDevice, so its current
	// device is unknown and the device identity labels must be omitted.
	t.Run("gpu.cuda.* metrics omit device identity for unknown Driver API device", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			q := `gpu_cuda_kernel_launch_calls_total{service_name="` + gpuDriverService + `"}`
			results, err := pq.Query(q)
			if !assert.NoError(ct, err, "querying %s", q) {
				return
			}
			assert.NotEmpty(ct, results, "kernel launch metric should be present for %s", gpuDriverService)

			for _, r := range results {
				assert.Empty(ct, r.Metric["cuda_device_index"], "unknown device should not expose cuda_device_index")
				assert.Empty(ct, r.Metric["cuda_device_uuid"], "unknown device should not expose cuda_device_uuid")
				assert.Empty(ct, r.Metric["cuda_device_model"], "unknown device should not expose cuda_device_model")
			}
		}, testTimeout, 500*time.Millisecond)
	})

	// Driver API target that binds a nonzero context through cuCtxCreate +
	// cuCtxPushCurrent. OBI does not instrument those calls, so the device is
	// still unknown and the device identity labels must be omitted.
	t.Run("gpu.cuda.* metrics omit device identity for nonzero Driver API context", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			q := `gpu_cuda_kernel_launch_calls_total{service_name="` + gpuDriverCtxService + `"}`
			results, err := pq.Query(q)
			if !assert.NoError(ct, err, "querying %s", q) {
				return
			}
			assert.NotEmpty(ct, results, "kernel launch metric should be present for %s", gpuDriverCtxService)

			for _, r := range results {
				assert.Empty(ct, r.Metric["cuda_device_index"], "unobserved context binding should not expose cuda_device_index")
				assert.Empty(ct, r.Metric["cuda_device_uuid"], "unobserved context binding should not expose cuda_device_uuid")
				assert.Empty(ct, r.Metric["cuda_device_model"], "unobserved context binding should not expose cuda_device_model")
			}
		}, testTimeout, 500*time.Millisecond)
	})
}

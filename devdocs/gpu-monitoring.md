# GPU monitoring

OBI instruments the CUDA APIs an application uses to drive an NVIDIA GPU:
kernel launches, memory copies, allocations, stream and event operations, and
the introspection calls that reveal which device the work ran on. This is
execution telemetry about the application's GPU work.

Device telemetry such as utilization, memory, temperature, or power is a
separate, opt-in feature described under [Device metrics](#device-metrics).

## Enabling

GPU monitoring is off unless enabled through `ebpf.instrument_cuda`
(`OTEL_EBPF_INSTRUMENT_CUDA`):

| Value          | Behavior                                      |
|:---------------|:----------------------------------------------|
| `auto` (default) | Enabled when `nvidia-smi` is on the `PATH` of the OBI process. |
| `on`           | Always enabled.                               |
| `off`          | Always disabled.                              |

When enabled, `newCommonTracersGroup` in `pkg/appolly/discover/finder.go` adds
the gpuevent tracer to the common tracer set. The tracer is not required: if it
fails to load, the rest of the instrumentation still works.

## Where the code lives

| Piece                         | Location                                        |
|:------------------------------|:------------------------------------------------|
| eBPF programs and maps        | `bpf/gpuevent/cuda.c`                           |
| Event structs shared with Go  | `bpf/gpuevent/cuda.h`                           |
| Ring buffer definition        | `bpf/gpuevent/gpu_ringbuf.h`                    |
| Go tracer (probes, decoding)  | `pkg/internal/ebpf/gpuevent/gpuevent.go`        |
| Span types and fields         | `pkg/appolly/app/request/span.go`               |
| OTLP metric emitters          | `pkg/export/otel/metrics.go`                    |
| Prometheus metric emitters    | `pkg/export/prom/prom.go`                       |
| Schema registry               | `schemas/obi/groups/gpu/`                       |
| Integration test              | `internal/test/integration/gpu_metrics_test.go` |

The eBPF program is derived from the `gpuevent_snoop` program in
[strobelight](https://github.com/facebookincubator/strobelight); the header of
`bpf/gpuevent/cuda.c` records the upstream revision.

## Instrumented APIs

OBI attaches uprobes to the CUDA Runtime (`libcudart.so`) and the CUDA Driver
(`libcuda.so`). Calls whose arguments need to be correlated with a result use
entry and return probes; the rest use a single entry probe.

| Library     | Probes          | Symbols |
|:------------|:----------------|:--------|
| `libcudart` | entry + return  | cudaLaunchKernel, cudaGraphLaunch, cudaMalloc, cudaFree, cudaSetDevice, cudaGetDevice, cudaGetDeviceProperties, cudaGetDeviceProperties_v2 |
| `libcudart` | entry           | cudaMemcpy, cudaMemcpyAsync, cudaMemset, cudaStreamCreate, cudaStreamCreateWithFlags, cudaStreamCreateWithPriority, cudaStreamDestroy, cudaEventRecord, cudaEventRecordWithFlags, cudaEventSynchronize, cudaStreamSynchronize, cudaDeviceSynchronize, cudaHostRegister |
| `libcuda`   | entry + return  | cuDeviceGetUuid, cuDeviceGetUuid_v2, cuDeviceGetName |
| `libcuda`   | entry           | cuLaunchKernel, cuLaunchKernelEx, cuGraphLaunch |

Code built with the per-thread default stream (`nvcc --default-stream per-thread`
or `CUDA_API_PER_THREAD_DEFAULT_STREAM`) calls renamed symbols instead:
`cudaLaunchKernel_ptsz`, `cudaGraphLaunch_ptsz`, `cudaMemcpy_ptds`,
`cudaMemcpyAsync_ptsz`, `cudaMemset_ptds`, `cudaEventRecord_ptsz`,
`cudaEventRecordWithFlags_ptsz`, `cudaStreamSynchronize_ptsz`,
`cuLaunchKernel_ptsz`, `cuLaunchKernelEx_ptsz` and `cuGraphLaunch_ptsz`. They
take the same arguments as their base symbols, so each one is attached to the
same program as its base symbol.

Return probes exist where the outcome only becomes known after the call:
`cudaMalloc` reports the allocated pointer and size, `cudaFree` confirms the
release, `cudaSetDevice` confirms which device is now current, and the
introspection calls read the buffers that the callee filled in. Driver API
launches are entry-only because deduplication against the runtime API is done
with a per-thread marker, not with a return value.

## Events and the ring buffer

The eBPF programs push fixed-size events into `gpu_events`, a 64 KB ring
buffer. `processCudaEvent` in `pkg/internal/ebpf/gpuevent/gpuevent.go` decodes
them into spans.

| Event                        | Span type                             | Metric |
|:-----------------------------|:--------------------------------------|:-------|
| `k_event_kernel_launch`      | `EventTypeGPUCudaKernelLaunch`        | `gpu.cuda.kernel.launch.calls`, `gpu.cuda.kernel.grid.size`, `gpu.cuda.kernel.block.size` |
| `k_event_graph_launch`       | `EventTypeGPUCudaGraphLaunch`         | `gpu.cuda.graph.launch.calls` |
| `k_event_malloc`             | `EventTypeGPUCudaMalloc`              | `gpu.cuda.memory.allocations` |
| `k_event_memcpy`             | `EventTypeGPUCudaMemcpy`              | `gpu.cuda.memory.copies` |
| `k_event_free`               | `EventTypeGPUCudaFree`                | `gpu.cuda.memory.free.bytes` |
| `k_event_memset`             | `EventTypeGPUCudaMemset`              | `gpu.cuda.memset.bytes` |
| `k_event_stream_create`      | `EventTypeGPUCudaStreamCreate`        | `gpu.cuda.stream.create.calls` |
| `k_event_stream_destroy`     | `EventTypeGPUCudaStreamDestroy`       | `gpu.cuda.stream.destroy.calls` |
| `k_event_event_record`       | `EventTypeGPUCudaEventRecord`         | `gpu.cuda.event.record.calls` |
| `k_event_event_synchronize`  | `EventTypeGPUCudaEventSynchronize`    | `gpu.cuda.event.synchronize.calls` |
| `k_event_stream_synchronize` | `EventTypeGPUCudaStreamSynchronize`   | `gpu.cuda.stream.synchronize.calls` |
| `k_event_device_synchronize` | `EventTypeGPUCudaDeviceSynchronize`   | `gpu.cuda.device.synchronize.calls` |
| `k_event_host_register`      | `EventTypeGPUCudaHostRegister`        | `gpu.cuda.host.register.bytes` |
| `k_event_device_info`        | —                                     | — |

`k_event_device_info` carries the device UUID and model that an introspection
call revealed. It produces no span; the Go tracer only caches the pair for
labelling later events.

## Device attribution

Spans and metrics are labelled with the device the calling thread was bound to
when that binding was observed:

| Attribute           | Meaning |
|:--------------------|:--------|
| `cuda.device.index` | Process-local device index. Present when the thread selected or queried a device through `cudaSetDevice` or `cudaGetDevice`; omitted when no binding was observed. |
| `cuda.device.uuid`  | Bare device UUID, the `uuid` column of `nvidia-smi` with its `GPU-` prefix removed. Omitted until the process asked CUDA about the device. |
| `cuda.device.model` | Device name, for example `NVIDIA H20-3e`. Omitted until observed. |

The thread-to-device binding is learned from `cudaSetDevice` and `cudaGetDevice`
and kept per host thread, because CUDA's current device is per host thread. A
failed `cudaSetDevice` does not bind the thread, and a `cudaGetDevice` query does
not change it. Identity is cached per process, and partial observations merge:
an observation that reveals only the UUID or only the name does not clear the
other part.

Because `CUDA_VISIBLE_DEVICES` remaps indices, the same index can refer to
different physical GPUs in different processes; the UUID identifies the
physical device.

## Runtime and driver deduplication

`libcudart` implements the launch APIs by calling into `libcuda`, so a process
that maps both libraries would report the same launch twice. A per-thread
in-flight marker is set at the runtime entry probe and consumed by the driver
entry probes, which then report nothing. The runtime return probes clear the
marker for calls that never reach the driver.

## Byte-accurate free accounting

`cudaFree` is not told how large the freed block is, so frees are accounted
using the size recorded at allocation time. The `cudaMalloc` return probe
stores the returned pointer and size, keyed by process and device pointer. The
`cudaFree` probes look the size up and report it once the return probe confirms
the free.

## eBPF maps

Maps are pinned internal to OBI. The per-thread in-flight context maps are
regular hash maps: their matching return probes consume and delete entries
unconditionally, so a deselected or exiting target cannot leak them. The
long-lived state maps (`cuda_alloc_sizes`, `cuda_thread_device`,
`cuda_device_info`) are LRU hashes so entries for processes that exit without
cleaning up are evicted rather than growing without bound.

| Map                       | Type      | Key → value                | Entries | Purpose |
|:--------------------------|:----------|:---------------------------|--------:|:--------|
| `cuda_malloc_ctx`         | hash      | thread → malloc arguments  | 1024    | Correlate `cudaMalloc` arguments with its return value. |
| `cuda_free_ctx`           | hash      | thread → free arguments    | 1024    | Report a free only once its return code confirms it. |
| `cuda_alloc_sizes`        | LRU hash  | (process, pointer) → size  | 65536   | Size lookup for `cudaFree`. |
| `cuda_runtime_launch_ctx` | hash      | thread → marker            | 1024    | Suppress driver launches that a runtime call is proxying. |
| `cuda_thread_device`      | LRU hash  | thread → device index      | 8192    | Current device of each host thread. |
| `cuda_device_info`        | LRU hash  | (process, index) → identity | 4096   | UUID and name revealed by introspection. |
| `cuda_introspect_ctx`     | hash      | thread → context           | 1024    | Carry introspection arguments from entry to return. |
| `cuda_set_device_ctx`     | hash      | thread → context           | 1024    | Bind a thread only after `cudaSetDevice` succeeds. |

## Span fields

GPU span types reuse the generic `Span` fields instead of adding per-call data
to the span:

| Span                              | `ContentLength`          | `SubType`                  |
|:----------------------------------|:-------------------------|:---------------------------|
| kernel launch                     | grid.x × grid.y × grid.z | block.x × block.y × block.z |
| memcpy                            | bytes copied             | `cudaMemcpyKind`           |
| malloc, free, memset, host register | bytes                  | —                          |
| graph launch, stream/event/sync calls | —                    | —                          |

The spans expose these values as `gridSize`, `blockSize`, `size`, and `kind`
span attributes, built by `spanAttributes` in
`pkg/appolly/app/request/span.go`.

## Metrics

GPU metrics are `development` stability and declared in
`schemas/obi/groups/gpu/metrics.yaml`. They carry `cuda.device.index`,
`cuda.device.uuid`, and `cuda.device.model` when the device binding and identity
were observed; `gpu.cuda.memory.copies` also carries `cuda.memcpy.kind`. An em
dash in the unit column means the metric is declared without a unit, a pure
count.

| Metric                             | Instrument | Unit |
|:-----------------------------------|:-----------|:-----|
| `gpu.cuda.kernel.launch.calls`     | counter    | —    |
| `gpu.cuda.kernel.grid.size`        | histogram  | 1    |
| `gpu.cuda.kernel.block.size`       | histogram  | 1    |
| `gpu.cuda.graph.launch.calls`      | counter    | —    |
| `gpu.cuda.memory.allocations`      | counter    | By   |
| `gpu.cuda.memory.copies`           | histogram  | By   |
| `gpu.cuda.memory.free.bytes`       | counter    | By   |
| `gpu.cuda.memset.bytes`            | counter    | By   |
| `gpu.cuda.stream.create.calls`     | counter    | —    |
| `gpu.cuda.stream.destroy.calls`    | counter    | —    |
| `gpu.cuda.event.record.calls`      | counter    | —    |
| `gpu.cuda.event.synchronize.calls` | counter    | —    |
| `gpu.cuda.stream.synchronize.calls` | counter   | —    |
| `gpu.cuda.device.synchronize.calls` | counter   | —    |
| `gpu.cuda.host.register.bytes`     | counter    | By   |

The registry is checked against the emitting surface: the GPU integration test
runs weaver in enforce mode, so a metric that is emitted but not declared, or
declared but not emitted, fails the test.

The OTLP exporter emits these metrics in `pkg/export/otel/metrics.go`, and the
Prometheus exporter mirrors them in `pkg/export/prom/prom.go`, both gated by
the GPU instrumentation being enabled.

### Adding a new GPU metric

1. Add the value to the span in `pkg/appolly/app/request/span.go` (and a
   getter for it if the metric needs a new attribute value). If a new event is
   needed, add the C struct to `bpf/gpuevent/cuda.h`, the event to
   `bpf/gpuevent/cuda.c`, then regenerate the bpf2go bindings with
   `make generate` (or `make docker-generate` when not on a Linux host).
2. Declare the metric, and any new attribute, in
   `schemas/obi/groups/gpu/metrics.yaml` and
   `schemas/obi/groups/gpu/registry.yaml`.
3. Register the metric and its attributes in
   `pkg/export/attributes/metric.go` and
   `pkg/export/attributes/attr_defs.go`, adding new attribute names to
   `pkg/export/attributes/names/attrs.go`.
4. Emit it in `pkg/export/otel/metrics.go` and mirror the emitter in
   `pkg/export/prom/prom.go`.
5. Run `make generate-schema-docs` to refresh the reference docs under
   `site/docs/`.
6. If the change renames emitted telemetry, record the transformation in
   [telemetry-schema.md](telemetry-schema.md).

## Device metrics

OBI can also report the state of the NVIDIA GPUs of the host, the same numbers
that `nvidia-smi` shows. The GPU firmware computes them and the driver only
hands them out to a program that asks through the NVIDIA Management Library
(NVML), so eBPF cannot observe them. OBI polls NVML instead.

### Enabling

Device metrics are off by default and can only be enabled through Config v2:

```yaml
extensions:
  obi:
    version: "2.0"
    capture:
      instrumentation:
        gpu:
          device_metrics:
            enabled: true
            interval: 30s
```

`interval` is the time between two readings of the GPUs.

### How OBI reads NVML

NVML is a shared library, `libnvidia-ml.so.1`, that the NVIDIA driver installs
on the host. OBI is a statically linked binary and cannot load a shared
library, so the NVML code lives in a small helper program that is embedded in
the OBI binary:

1. `make compile` builds the helper in `pkg/internal/nvml/helper` into
   `pkg/internal/nvml/embedded`, and embeds it in OBI through the
   `obi_nvml_helper` build tag. The helper is built without cgo and calls NVML
   through [purego](https://github.com/ebitengine/purego). A build without the
   tag, such as `go build` or `go test`, has no helper and logs that GPU device
   metrics are unavailable when they are enabled.
2. When device metrics are enabled, OBI copies the helper to an anonymous
   in-memory file and runs it as a child process whose root directory is the
   root filesystem of the host, `/proc/1/root`. The helper therefore uses the
   loader, the C library and the NVIDIA library of the host, and nothing is
   written to the host.
3. Every `interval`, the helper prints one JSON line with the metric values of
   each GPU and of each process that uses it, already in the units of the
   metrics. The record is defined in `pkg/internal/nvml/sample`.
4. OBI keeps the values of the most recent sample, adds the Kubernetes
   attributes of each process, and reports the values each time the metrics are
   collected. The series of a GPU or a process that went away disappear at the
   next sample.

If the helper exits, for example because the driver is not installed yet, OBI
drops the readings and starts it again after one minute. The helper looks for
the library in the loader search path of the host and then under
`/run/nvidia/driver`, where the NVIDIA GPU Operator exposes the driver files.

### Requirements

- An NVIDIA driver with `libnvidia-ml.so.1` on a host that uses the GNU C
  library.
- OBI runs as root, shares the PID namespace of the host (`hostPID: true` in
  Kubernetes), and has the `SYS_CHROOT` and `SYS_PTRACE` capabilities, which
  it needs to use the host filesystem as the root of the helper. A privileged
  container has all of them.
- On hosts that use AppArmor, the default profile of the container runtime
  stops OBI from entering the host filesystem even with these capabilities, so
  a container that is not privileged needs the `unconfined` AppArmor profile
  (`appArmorProfile: {type: Unconfined}` in Kubernetes).

### Where the code lives

| Piece                                  | Location                         |
|:---------------------------------------|:---------------------------------|
| NVML helper program                    | `pkg/internal/nvml/helper/`      |
| Record the helper sends, and launcher  | `pkg/internal/nvml/`             |
| Metrics, readings and attributes       | `pkg/internal/gpuolly/`          |
| OTLP and Prometheus metric emitters    | `pkg/export/{otel,prom}/*_gpu.go` |
| Schema registry                        | `schemas/obi/groups/gpu/`        |

### Metrics

The device metrics are `development` stability. The `hw.*` metrics follow the
OpenTelemetry hardware semantic conventions and are imported from them in
`schemas/obi/groups/gpu/imports.yaml`. The `gpu.*` metrics have no upstream
definition and are declared in `schemas/obi/groups/gpu/metrics.yaml`.

| Metric                      | Instrument    | Unit      | Extra attribute |
|:----------------------------|:--------------|:----------|:----------------|
| `hw.gpu.utilization`        | gauge         | 1         | `hw.gpu.task`: `general`, `encoder`, `decoder` |
| `hw.gpu.memory.usage`       | updowncounter | By        | |
| `hw.gpu.memory.limit`       | updowncounter | By        | |
| `hw.gpu.memory.utilization` | gauge         | 1         | |
| `hw.power`                  | gauge         | W         | |
| `hw.energy`                 | counter       | J         | |
| `hw.temperature`            | gauge         | Cel       | `hw.sensor_location`: `gpu`, `memory` |
| `hw.temperature.limit`      | gauge         | Cel       | `hw.limit_type`: `high.degraded` (slowdown), `high.critical` (shutdown) |
| `hw.errors`                 | counter       | {error}   | `error.type`: `corrected`, `uncorrected` |
| `hw.status`                 | updowncounter | 1         | `hw.state`: `ok`, `predicted_failure`, `failed` |
| `gpu.clock.frequency`       | gauge         | Hz        | `gpu.clock.type`: `processor`, `memory` |
| `gpu.clock.throttled`       | updowncounter | 1         | `gpu.clock.throttle.reason` |
| `gpu.memory.remapped_rows`  | gauge         | {row}     | `error.type`: `corrected`, `uncorrected` |
| `gpu.memory.activity`       | gauge         | 1         | |
| `gpu.memory.reserved`       | updowncounter | By        | |
| `gpu.pcie.replays`          | counter       | {replay}  | |
| `gpu.xid.errors`            | counter       | {error}   | `gpu.xid.code` |
| `gpu.process.memory.usage`  | updowncounter | By        | process and Kubernetes attributes |
| `gpu.process.utilization`   | gauge         | 1         | `hw.gpu.task`: `general`, `encoder`, `decoder`; process and Kubernetes attributes |

Notes on what the values mean:

- `hw.energy`, `hw.errors` and `gpu.pcie.replays` report the totals that the
  driver keeps: energy and PCIe replays since the driver was loaded, and memory
  errors over the lifetime of the GPU.
- `gpu.memory.activity` is the fraction of the last sample period during which
  the GPU memory was being read or written, which `nvidia-smi` shows as memory
  utilization. `hw.gpu.memory.utilization` is the fraction of the memory in use.
- `hw.temperature` with `hw.sensor_location="memory"` is only reported by GPUs
  that measure their memory temperature, mostly those with HBM memory.
- `gpu.xid.errors` counts the Xid errors, the error reports of the NVIDIA
  driver, since OBI started reading the GPU.
- `hw.status` reports `1` for the state the GPU is in and `0` for the others. A
  GPU is `predicted_failure` while a memory row remapping is pending, and
  `failed` when it ran out of spare rows. There is one `ok` series per GPU, so
  counting them gives the number of GPUs.
- `gpu.clock.throttled` reports `1` for each reason that currently limits the
  clocks of the GPU and `0` for the others.
- A value that a GPU or a driver does not report is omitted.

Every metric carries `hw.id`, the NVML identifier of the GPU, such as
`GPU-4dd8a2f9-1c57-6a0b-9d3e-2f5b7c8e9a10`. It is the `uuid` column of
`nvidia-smi` and the identifier DCGM uses; the `cuda.device.uuid` attribute of
the CUDA metrics is the same value without the `GPU-` prefix. The `hw.gpu.*`
and `gpu.*` metrics also carry `hw.model`, and optionally `hw.vendor` and
`hw.driver_version`. The metrics that the semantic conventions define for any
hardware component (`hw.power`, `hw.energy`, `hw.errors`, `hw.status`) carry
`hw.type="gpu"` instead, and `hw.temperature` and `hw.temperature.limit` carry
only `hw.id`, as the conventions define them.

The process metrics carry `process.pid` and `process.executable.name`. In
Kubernetes they also carry the same Kubernetes attributes as the application
metrics, such as the namespace, pod, container and owner of the process, which
makes it possible to tell how much of a shared GPU each pod uses. The attributes of every metric can be changed through
`capture.attributes.select`. When a selection removes the attribute that tells
two readings apart, OBI reports them as one series: it adds up counters and
up-down counters, and keeps the highest value of gauges.

### Limitations

- Only compute processes are listed, not graphics processes.
- GPUs split with MIG are reported as whole devices.
- NVML does not report utilization per process on every GPU. Where it does
  not, `gpu.process.utilization` is omitted.
- The GPUs are listed when the helper starts. A GPU added later is reported
  after the helper restarts.
- The OpenTelemetry Collector receiver does not embed the helper yet.

## Testing without a GPU

`TestGPUCudaMetrics` in `internal/test/integration/gpu_metrics_test.go` runs
the whole pipeline without NVIDIA hardware. The test builds fake `libcudart.so`
and `libcuda.so.1` libraries from the stub sources in
`internal/test/integration/components/gpu-cuda-tester/`, and
`docker-compose-gpu.yml` forces `OTEL_EBPF_INSTRUMENT_CUDA=on` so the gpuevent
tracer loads.

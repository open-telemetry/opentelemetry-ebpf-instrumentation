// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Caller that binds the current thread to CUDA device 1, queries its
// properties, and then drives cudaLaunchKernel in a loop. OBI learns the device
// identity from cudaSetDevice and cudaGetDeviceProperties, so every
// gpu.cuda.kernel.launch.calls metric emitted by this target must carry
// cuda.device.index="1" and the matching UUID/model labels.
//
// OBI attaches one uprobe per symbol in nondeterministic order, and only the
// cudaSetDevice return probe records the binding. A launch observed before
// those probes are live would be attributed to an unknown device and leave an
// unlabeled series behind for the rest of the run, so the target starts with a
// launch-free warm-up that outlasts OBI's discovery and attach, and only then
// enters the launch loop.

#include <stdio.h>
#include <unistd.h>

#include "cuda_stub.h"

enum {
  iteration_ms = 50,
  warmup_iterations = 300, // 15s
};

static void bind_device(void) {
  cudaSetDevice(1);

  cudaDeviceProp prop = {};
  cudaGetDeviceProperties(&prop, 1);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-setdevice-tester started\n");

  for (unsigned i = 0; i < warmup_iterations; i++) {
    bind_device();
    usleep(iteration_ms * 1000);
  }

  for (;;) {
    bind_device();

    dim3 grid = {4, 2, 1};
    dim3 block = {32, 4, 1};
    cudaLaunchKernel((const void *)0xdeadbeef, grid, block, NULL, 0, NULL);

    usleep(iteration_ms * 1000);
  }

  return 0;
}

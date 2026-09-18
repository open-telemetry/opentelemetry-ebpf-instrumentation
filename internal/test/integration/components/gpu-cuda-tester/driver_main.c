// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Caller that drives the stub libcuda.so.1 in an endless loop, exercising the
// CUDA Driver API entry points OBI instruments. It runs continuously so OBI has
// time to discover the process and attach its uprobes before (and while) the
// calls fire. Each iteration:
//
//   - cuLaunchKernel     -> gpu.cuda.kernel.launch.calls + grid/block size
//   - cuLaunchKernelEx   -> gpu.cuda.kernel.launch.calls + grid/block size
//   - cuGraphLaunch      -> gpu.cuda.graph.launch.calls
//
// The binary deliberately links only libcuda: a process that maps both libcuda
// and libcudart would be skipped by OBI's conflicting-library gate to avoid
// double counting the same kernel launch, so this target maps libcuda alone to
// prove the driver path is instrumented on its own.

#include <stdio.h>
#include <unistd.h>

#include "cuda_driver_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-driver-tester started\n");

  for (;;) {
    cuLaunchKernel((CUfunction)0xdeadbeef, 4, 2, 1, 32, 4, 1, 0, NULL, NULL,
                   NULL);

    CUlaunchConfig config = {
        .gridDimX = 8,
        .gridDimY = 1,
        .gridDimZ = 1,
        .blockDimX = 64,
        .blockDimY = 2,
        .blockDimZ = 1,
        .sharedMemBytes = 0,
        .hStream = NULL,
    };
    cuLaunchKernelEx(&config, (CUfunction)0xfeedface, NULL, NULL);

    cuGraphLaunch((CUgraphExec)0xcafe, NULL);

    usleep(50 * 1000); // 50ms
  }

  return 0;
}

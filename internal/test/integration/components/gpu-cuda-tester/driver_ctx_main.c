// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Caller that binds a nonzero CUDA Driver API context (via cuCtxCreate +
// cuCtxPushCurrent) and then drives cuLaunchKernel in a loop. OBI does not
// instrument the context-management calls, so the current CUdevice is never
// observed and every gpu.cuda.kernel.launch.calls metric emitted by this
// target must omit the cuda.device.* labels.

#include <stdio.h>
#include <unistd.h>

#include "cuda_driver_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-driver-ctx-tester started\n");

  // Bind a nonzero context the way a real Driver API application would. OBI
  // does not observe these calls, so the device must remain unknown.
  CUcontext ctx = NULL;
  cuCtxCreate(&ctx, 0, 2);
  cuCtxPushCurrent(ctx);

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

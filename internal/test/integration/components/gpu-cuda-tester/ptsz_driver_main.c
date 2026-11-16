// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unistd.h>

#include "cuda_driver_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-ptsz-driver-tester started\n");

  for (;;) {
    cuLaunchKernel_ptsz((CUfunction)0xdeadbeef, 4, 2, 1, 32, 4, 1, 0, NULL,
                        NULL, NULL);

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
    cuLaunchKernelEx_ptsz(&config, (CUfunction)0xfeedface, NULL, NULL);

    cuGraphLaunch_ptsz((CUgraphExec)0xcafe, NULL);

    usleep(50 * 1000);
  }

  return 0;
}

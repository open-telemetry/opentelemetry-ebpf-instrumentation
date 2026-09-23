// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Caller that binds the current thread to CUDA device 1, queries its
// properties, and then drives cudaLaunchKernel in a loop. OBI learns the device
// identity from cudaSetDevice and cudaGetDeviceProperties, so every
// gpu.cuda.kernel.launch.calls metric emitted by this target must carry
// cuda.device.index="1" and the matching UUID/model labels.
//
// OBI only observes calls made after it discovers the process and attaches its
// uprobes, so the binding and property queries are re-issued every iteration:
// a one-shot call at startup races the attach and leaves the launches
// unlabeled.

#include <stdio.h>
#include <unistd.h>

#include "cuda_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-setdevice-tester started\n");

  for (;;) {
    cudaSetDevice(1);

    cudaDeviceProp prop = {};
    cudaGetDeviceProperties(&prop, 1);

    dim3 grid = {4, 2, 1};
    dim3 block = {32, 4, 1};
    cudaLaunchKernel((const void *)0xdeadbeef, grid, block, NULL, 0, NULL);

    usleep(50 * 1000); // 50ms
  }

  return 0;
}

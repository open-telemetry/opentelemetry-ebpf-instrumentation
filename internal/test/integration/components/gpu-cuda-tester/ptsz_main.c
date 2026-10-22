// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "cuda_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-ptsz-tester started\n");

  char hostbuf[256];
  void *devptr = (void *)0x1000;
  cudaEvent_t event = (cudaEvent_t)0xbeef;

  for (;;) {
    dim3 grid = {4, 2, 1};
    dim3 block = {32, 4, 1};
    cudaLaunchKernel_ptsz((const void *)0xdeadbeef, grid, block, NULL, 0, NULL);
    cudaGraphLaunch_ptsz((cudaGraphExec_t)0xcafe, NULL);

    cudaMemcpy_ptds(devptr, hostbuf, sizeof(hostbuf), cudaMemcpyHostToDevice);
    cudaMemcpyAsync_ptsz(hostbuf, devptr, sizeof(hostbuf),
                         cudaMemcpyDeviceToHost, NULL);
    cudaMemset_ptds(devptr, 0, sizeof(hostbuf));

    cudaEventRecord_ptsz(event, NULL);
    cudaEventRecordWithFlags_ptsz(event, NULL, 0);
    cudaStreamSynchronize_ptsz(NULL);

    usleep(50 * 1000);
  }

  return 0;
}

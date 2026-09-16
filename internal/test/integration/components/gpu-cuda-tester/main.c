// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Caller that drives the stub libcudart.so in an endless loop, exercising every
// CUDA Runtime API entry point OBI instruments. It runs continuously so OBI has
// time to discover the process and attach its uprobes before (and while) the
// calls fire. Each iteration:
//
//   - cudaMalloc                    -> gpu.cuda.memory.allocations
//   - cudaLaunchKernel              -> gpu.cuda.kernel.launch.calls + grid/block size
//   - cudaMemcpy                    -> gpu.cuda.memory.copies (+ cuda.memcpy.kind)
//   - cudaMemcpyAsync               -> gpu.cuda.memory.copies (+ cuda.memcpy.kind)
//   - cudaGraphLaunch               -> gpu.cuda.graph.launch.calls
//   - cudaFree                      -> gpu.cuda.memory.free.bytes
//   - cudaMemset                    -> gpu.cuda.memset.bytes
//   - cudaStreamCreate*             -> gpu.cuda.stream.create.calls
//   - cudaStreamDestroy             -> gpu.cuda.stream.destroy.calls
//   - cudaEventRecord*              -> gpu.cuda.event.record.calls
//   - cudaEventSynchronize          -> gpu.cuda.event.synchronize.calls
//   - cudaStreamSynchronize         -> gpu.cuda.stream.synchronize.calls
//   - cudaDeviceSynchronize         -> gpu.cuda.device.synchronize.calls
//   - cudaHostRegister              -> gpu.cuda.host.register.bytes
//
// The memcpy kind is cycled through all four directions so cuda.memcpy.kind is
// emitted with varied, semantically valid values.

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "cuda_stub.h"

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("gpu-cuda-tester started\n");

  const enum cudaMemcpyKind kinds[] = {
      cudaMemcpyHostToDevice,
      cudaMemcpyDeviceToHost,
      cudaMemcpyDeviceToDevice,
      cudaMemcpyHostToHost,
  };

  char hostbuf[256];
  void *devptr = NULL;
  cudaStream_t stream = NULL;
  cudaEvent_t event = (cudaEvent_t)0xbeef;
  unsigned long i = 0;

  for (;;) {
    cudaMalloc(&devptr, sizeof(hostbuf));

    dim3 grid = {4, 2, 1};
    dim3 block = {32, 4, 1};
    cudaLaunchKernel((const void *)0xdeadbeef, grid, block, NULL, 0, NULL);

    cudaMemcpy(devptr, hostbuf, sizeof(hostbuf), kinds[i % 4]);
    cudaMemcpyAsync(hostbuf, devptr, sizeof(hostbuf), kinds[(i + 1) % 4], NULL);

    cudaGraphLaunch((cudaGraphExec_t)0xcafe, NULL);

    cudaMemset(devptr, 0, sizeof(hostbuf));
    cudaHostRegister(hostbuf, sizeof(hostbuf), 0);

    cudaStreamCreate(&stream);
    cudaStreamCreateWithFlags(&stream, 0);
    cudaStreamCreateWithPriority(&stream, 0, 0);
    cudaStreamDestroy(stream);

    cudaEventRecord(event, NULL);
    cudaEventRecordWithFlags(event, NULL, 0);
    cudaEventSynchronize(event);
    cudaStreamSynchronize(stream);
    cudaDeviceSynchronize();

    cudaFree(devptr);

    i++;
    usleep(50 * 1000); // 50ms
  }

  return 0;
}

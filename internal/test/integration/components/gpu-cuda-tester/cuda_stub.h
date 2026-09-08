// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Minimal subset of the CUDA Runtime API surface that OBI's gpuevent uprobes
// attach to. The types and signatures mirror <cuda_runtime_api.h> closely
// enough that the SysV x86-64 / AArch64 calling convention places each argument
// in the register OBI's BPF programs read (see bpf/gpuevent/cuda.c):
//
//   cudaLaunchKernel(func, gridDim, blockDim, ...)  BPF reads gridDim/blockDim
//   cudaMalloc(devPtr, size)                         BPF reads size
//   cudaMemcpy(dst, src, count, kind)                BPF reads size + kind
//   cudaMemcpyAsync(dst, src, count, kind, stream)   BPF reads size + kind
//   cudaGraphLaunch(graphExec, stream)               BPF reads nothing
//
// dim3 is a 12-byte struct passed by value: the {x,y} pair occupies one
// eightbyte register and {z} the next, which is exactly how OBI decodes
// grid_xy/grid_z and block_xy/block_z.
#ifndef CUDA_STUB_H
#define CUDA_STUB_H

#include <stddef.h>

typedef int cudaError_t;
typedef void *cudaStream_t;
typedef void *cudaGraphExec_t;

typedef struct dim3 {
  unsigned int x;
  unsigned int y;
  unsigned int z;
} dim3;

enum cudaMemcpyKind {
  cudaMemcpyHostToHost = 0,
  cudaMemcpyHostToDevice = 1,
  cudaMemcpyDeviceToHost = 2,
  cudaMemcpyDeviceToDevice = 3,
  cudaMemcpyDefault = 4
};

cudaError_t cudaLaunchKernel(const void *func, dim3 gridDim, dim3 blockDim,
                             void **args, size_t sharedMem,
                             cudaStream_t stream);
cudaError_t cudaMalloc(void **devPtr, size_t size);
cudaError_t cudaMemcpy(void *dst, const void *src, size_t count,
                       enum cudaMemcpyKind kind);
cudaError_t cudaMemcpyAsync(void *dst, const void *src, size_t count,
                            enum cudaMemcpyKind kind, cudaStream_t stream);
cudaError_t cudaGraphLaunch(cudaGraphExec_t graphExec, cudaStream_t stream);

#endif // CUDA_STUB_H

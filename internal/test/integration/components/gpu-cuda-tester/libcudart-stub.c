// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Stub implementation of libcudart.so. It performs no GPU work and needs no
// NVIDIA driver: each function has a trivial body and returns success. Its only
// purpose is to export the CUDA Runtime API symbols by name so that, when the
// caller invokes them, OBI's uprobes (attached by symbol name to any mapped
// library whose path contains "/libcudart.so") fire with realistic register
// arguments and emit gpu.cuda.* metrics.
//
// Built into a shared object so the symbols land in .dynsym (where OBI's ELF
// symbol resolution finds them) and every call goes through the PLT (so the
// compiler cannot inline the calls away). Compiled with -O0 and a volatile sink
// for the same reason.

#include "cuda_stub.h"

static volatile unsigned long g_sink;

cudaError_t cudaLaunchKernel(const void *func, dim3 gridDim, dim3 blockDim,
                             void **args, size_t sharedMem,
                             cudaStream_t stream) {
  (void)func;
  (void)args;
  (void)sharedMem;
  (void)stream;
  g_sink += (unsigned long)gridDim.x * gridDim.y * gridDim.z;
  g_sink += (unsigned long)blockDim.x * blockDim.y * blockDim.z;
  return 0;
}

cudaError_t cudaMalloc(void **devPtr, size_t size) {
  if (devPtr != NULL) {
    // Hand back a non-NULL fake device pointer so the caller can pass it to
    // cudaMemcpy without tripping any of its own NULL checks.
    *devPtr = (void *)0x1000;
  }
  g_sink += size;
  return 0;
}

cudaError_t cudaMemcpy(void *dst, const void *src, size_t count,
                       enum cudaMemcpyKind kind) {
  (void)dst;
  (void)src;
  g_sink += count + (unsigned long)kind;
  return 0;
}

cudaError_t cudaMemcpyAsync(void *dst, const void *src, size_t count,
                            enum cudaMemcpyKind kind, cudaStream_t stream) {
  (void)dst;
  (void)src;
  (void)stream;
  g_sink += count + (unsigned long)kind;
  return 0;
}

cudaError_t cudaGraphLaunch(cudaGraphExec_t graphExec, cudaStream_t stream) {
  (void)graphExec;
  (void)stream;
  g_sink += 1;
  return 0;
}

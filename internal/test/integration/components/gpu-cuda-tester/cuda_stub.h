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
//   cudaFree(devPtr)                                 BPF reads tracked size
//   cudaMemset(devPtr, value, count)                 BPF reads count
//   cudaStreamCreate(stream)                         BPF reads nothing
//   cudaStreamCreateWithFlags(stream, flags)         BPF reads nothing
//   cudaStreamCreateWithPriority(stream, flags, priority) BPF reads nothing
//   cudaStreamDestroy(stream)                        BPF reads nothing
//   cudaEventRecord(event, stream)                   BPF reads nothing
//   cudaEventRecordWithFlags(event, stream, flags)   BPF reads nothing
//   cudaEventSynchronize(event)                      BPF reads nothing
//   cudaStreamSynchronize(stream)                    BPF reads nothing
//   cudaDeviceSynchronize()                          BPF reads nothing
//   cudaHostRegister(ptr, size, flags)               BPF reads size
//   cudaSetDevice(device)                            BPF reads device
//   cudaGetDeviceProperties(prop, device)            BPF reads prop + device
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
typedef void *cudaEvent_t;

typedef struct dim3 {
  unsigned int x;
  unsigned int y;
  unsigned int z;
} dim3;

// Minimal cudaDeviceProp: OBI reads name (offset 0) and uuid (offset 256).
typedef struct cudaDeviceProp {
  char name[256];
  unsigned char uuid[16];
} cudaDeviceProp;

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
cudaError_t cudaFree(void *devPtr);
cudaError_t cudaMemcpy(void *dst, const void *src, size_t count,
                       enum cudaMemcpyKind kind);
cudaError_t cudaMemcpyAsync(void *dst, const void *src, size_t count,
                            enum cudaMemcpyKind kind, cudaStream_t stream);
cudaError_t cudaGraphLaunch(cudaGraphExec_t graphExec, cudaStream_t stream);
cudaError_t cudaMemset(void *devPtr, int value, size_t count);
cudaError_t cudaStreamCreate(cudaStream_t *stream);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t *stream, unsigned int flags);
cudaError_t cudaStreamCreateWithPriority(cudaStream_t *stream,
                                         unsigned int flags, int priority);
cudaError_t cudaStreamDestroy(cudaStream_t stream);
cudaError_t cudaEventRecord(cudaEvent_t event, cudaStream_t stream);
cudaError_t cudaEventRecordWithFlags(cudaEvent_t event, cudaStream_t stream,
                                     unsigned int flags);
cudaError_t cudaEventSynchronize(cudaEvent_t event);
cudaError_t cudaStreamSynchronize(cudaStream_t stream);
cudaError_t cudaDeviceSynchronize(void);
cudaError_t cudaHostRegister(void *ptr, size_t size, unsigned int flags);
cudaError_t cudaSetDevice(int device);
cudaError_t cudaGetDeviceProperties(cudaDeviceProp *prop, int device);

#endif // CUDA_STUB_H

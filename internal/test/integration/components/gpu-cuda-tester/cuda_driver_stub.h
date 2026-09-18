// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Minimal subset of the CUDA Driver API surface that OBI's gpuevent uprobes
// attach to. The types and signatures mirror <cuda.h> closely enough that the
// SysV x86-64 / AArch64 calling convention places each argument in the register
// OBI's BPF programs read (see bpf/gpuevent/cuda.c):
//
//   cuLaunchKernel(f, gx, gy, gz, bx, by, bz, shared, stream, ...)
//       BPF reads grid/block dims; the seventh argument (blockDimZ) spills to
//       the stack on x86-64 and is passed in x6 on arm64.
//   cuLaunchKernelEx(config, f, ...)   BPF reads the CUlaunchConfig dims
//   cuGraphLaunch(graphExec, stream)   BPF reads nothing
//
// CUlaunchConfig mirrors the real struct: seven u32 grid/block/sharedMemBytes
// fields, four bytes of padding, then hStream at byte offset 32. The real
// struct carries trailing attribute fields that OBI does not read, so they are
// omitted.
#ifndef CUDA_DRIVER_STUB_H
#define CUDA_DRIVER_STUB_H

typedef int CUresult;
typedef void *CUfunction;
typedef void *CUstream;
typedef void *CUgraphExec;

typedef struct CUlaunchConfig {
  unsigned int gridDimX;
  unsigned int gridDimY;
  unsigned int gridDimZ;
  unsigned int blockDimX;
  unsigned int blockDimY;
  unsigned int blockDimZ;
  unsigned int sharedMemBytes;
  CUstream hStream;
} CUlaunchConfig;

CUresult cuLaunchKernel(CUfunction f, unsigned int gridDimX,
                        unsigned int gridDimY, unsigned int gridDimZ,
                        unsigned int blockDimX, unsigned int blockDimY,
                        unsigned int blockDimZ, unsigned int sharedMemBytes,
                        CUstream hStream, void **kernelParams, void **extra);
CUresult cuLaunchKernelEx(const CUlaunchConfig *config, CUfunction f,
                          void **kernelParams, void **extra);
CUresult cuGraphLaunch(CUgraphExec graphExec, CUstream hStream);

#endif // CUDA_DRIVER_STUB_H

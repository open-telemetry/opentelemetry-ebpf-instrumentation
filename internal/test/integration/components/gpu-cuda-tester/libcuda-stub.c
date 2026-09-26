// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Stub implementation of libcuda.so.1. It performs no GPU work and needs no
// NVIDIA driver: each function has a trivial body and returns success. Its only
// purpose is to export the CUDA Driver API symbols by name so that, when the
// caller invokes them, OBI's uprobes (attached by symbol name to any mapped
// library whose path contains "/libcuda.so") fire with realistic register
// arguments and emit gpu.cuda.* metrics.
//
// Built into a shared object so the symbols land in .dynsym (where OBI's ELF
// symbol resolution finds them) and every call goes through the PLT (so the
// compiler cannot inline the calls away). Compiled with -O0 and a volatile sink
// for the same reason.

#include <stddef.h>

#include "cuda_driver_stub.h"

static volatile unsigned long g_sink;

CUresult cuLaunchKernel(CUfunction f, unsigned int gridDimX,
                        unsigned int gridDimY, unsigned int gridDimZ,
                        unsigned int blockDimX, unsigned int blockDimY,
                        unsigned int blockDimZ, unsigned int sharedMemBytes,
                        CUstream hStream, void **kernelParams, void **extra) {
  (void)f;
  (void)sharedMemBytes;
  (void)hStream;
  (void)kernelParams;
  (void)extra;
  g_sink += (unsigned long)gridDimX * gridDimY * gridDimZ;
  g_sink += (unsigned long)blockDimX * blockDimY * blockDimZ;
  return 0;
}

CUresult cuLaunchKernelEx(const CUlaunchConfig *config, CUfunction f,
                          void **kernelParams, void **extra) {
  (void)f;
  (void)kernelParams;
  (void)extra;
  if (config != NULL) {
    g_sink +=
        (unsigned long)config->gridDimX * config->gridDimY * config->gridDimZ;
    g_sink += (unsigned long)config->blockDimX * config->blockDimY *
              config->blockDimZ;
  }
  return 0;
}

CUresult cuGraphLaunch(CUgraphExec graphExec, CUstream hStream) {
  (void)graphExec;
  (void)hStream;
  g_sink += 1;
  return 0;
}

// Minimal no-op context stubs. They never touch a real GPU; the nonzero device
// argument is recorded only so tests can prove OBI does not infer a device
// from these uninstrumented calls.
static CUcontext g_current_ctx = (CUcontext)0x1;

CUresult cuCtxCreate(CUcontext *pctx, unsigned int flags, int dev) {
  if (pctx != NULL) {
    *pctx = (CUcontext)(0x10 + (unsigned long)dev);
  }
  (void)flags;
  g_sink += (unsigned long)dev;
  return 0;
}

CUresult cuCtxSetCurrent(CUcontext ctx) {
  g_current_ctx = ctx;
  g_sink += (unsigned long)ctx;
  return 0;
}

CUresult cuCtxPushCurrent(CUcontext ctx) {
  g_current_ctx = ctx;
  g_sink += (unsigned long)ctx;
  return 0;
}

CUresult cuCtxPopCurrent(CUcontext *pctx) {
  if (pctx != NULL) {
    *pctx = g_current_ctx;
  }
  return 0;
}

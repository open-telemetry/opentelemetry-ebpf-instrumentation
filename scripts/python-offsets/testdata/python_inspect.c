// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "Python.h"
#include "internal/pycore_gc.h"
#include "internal/pycore_interp.h"
#include "internal/pycore_runtime.h"
#if PY_VERSION_HEX >= 0x030e0000
#include "internal/pycore_debug_offsets.h"
#endif

#include <stddef.h>
#include <stdio.h>

#ifdef Py_GIL_DISABLED
#error "free-threaded CPython is not supported"
#endif

_Static_assert(sizeof(void *) == 8, "non-LP64 pointer size");
_Static_assert(sizeof(Py_ssize_t) == 8, "non-LP64 Py_ssize_t");
_Static_assert(NUM_GENERATIONS == 3, "unexpected GC generation count");

#if PY_VERSION_HEX >= 0x030d0000
_Static_assert(offsetof(_PyRuntimeState, interpreters.main) ==
                   offsetof(_PyRuntimeState, interpreters.head) +
                       sizeof(void *),
               "main interpreter no longer follows head");
_Static_assert(offsetof(_Py_DebugOffsets, version) == 8 &&
                   offsetof(_Py_DebugOffsets, free_threaded) == 16 &&
                   offsetof(_Py_DebugOffsets, runtime_state.size) == 24 &&
                   offsetof(_Py_DebugOffsets, runtime_state.finalizing) == 32 &&
                   offsetof(_Py_DebugOffsets,
                            runtime_state.interpreters_head) == 40 &&
                   offsetof(_Py_DebugOffsets, interpreter_state.size) == 48 &&
                   offsetof(_Py_DebugOffsets, gc.collecting) ==
                       offsetof(_Py_DebugOffsets, gc) + 8,
               "unexpected debug offsets bootstrap layout");
#endif

_Static_assert(sizeof(struct gc_generation_stats) == 24,
               "unexpected inline GC record size");
_Static_assert(sizeof(((struct _gc_runtime_state *)0)->generation_stats) == 72,
               "unexpected inline GC payload size");
_Static_assert(offsetof(struct gc_generation_stats, collections) == 0,
               "unexpected collections offset");
_Static_assert(offsetof(struct gc_generation_stats, collected) == 8,
               "unexpected collected offset");
_Static_assert(offsetof(struct gc_generation_stats, uncollectable) == 16,
               "unexpected uncollectable offset");

#if PY_VERSION_HEX >= 0x030d0000
#define DEBUG_GC offsetof(_Py_DebugOffsets, gc)
#define DEBUG_INTERPRETER_GC offsetof(_Py_DebugOffsets, interpreter_state.gc)
#else
#define DEBUG_GC ((size_t)0)
#define DEBUG_INTERPRETER_GC ((size_t)0)
#endif

int main(void) {
  printf("{\"version\":\"%s\",\"finalizing\":%zu,\"main\":%zu,"
         "\"interpreter_gc\":%zu,\"generation_stats\":%zu,"
         "\"collecting\":%zu,\"debug_gc\":%zu,"
         "\"debug_interpreter_gc\":%zu}\n",
         PY_VERSION, offsetof(_PyRuntimeState, _finalizing),
         offsetof(_PyRuntimeState, interpreters.main),
         offsetof(PyInterpreterState, gc),
         offsetof(struct _gc_runtime_state, generation_stats),
         offsetof(struct _gc_runtime_state, collecting), DEBUG_GC,
         DEBUG_INTERPRETER_GC);
  return 0;
}

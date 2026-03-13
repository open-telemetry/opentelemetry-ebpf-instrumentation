# Python asyncio and uvloop Context Propagation

This document describes the architecture and implementation of Python async
context propagation for `asyncio` workloads, including applications running on
`uvloop`. It extends the existing context propagation mechanisms documented in
[context-propagation.md](context-propagation.md).

## Table of Contents

- [Current State](#current-state)
- [Architecture](#architecture)
- [Runtime Model](#runtime-model)
- [Probe Points](#probe-points)
- [Parent Lookup](#parent-lookup)
- [Implementation Details](#implementation-details)

## Current State

| Execution pattern | Python runtime behavior | OBI correlation path |
|-------------------|-------------------------|----------------------|
| `await` in the current task | The event-loop thread is executing a single `asyncio.Task` | `task_step` records `current_task`, and parent lookup resolves the request directly from that task |
| `asyncio.create_task()` / `asyncio.gather()` / nested tasks | Child tasks inherit execution context from the parent task | `_asyncio_Task___init__` records the parent chain and request ownership for the child task |
| `asyncio.to_thread()` | Python copies the current `Context` and runs it on a worker thread | `PyContext_CopyCurrent()` binds the copied `PyContext*` to the originating task, and `context_run` lets the worker thread resolve that context back to the task |
| `uvloop` event loop | The loop implementation changes, but `asyncio` task and `contextvars` semantics stay the same | The same task/context probes and lookup logic work without any `uvloop`-specific probe |

## Architecture

### Why thread-only correlation is not enough

OBI normally assumes that work running on the same thread belongs to the same
logical request. That assumption breaks down for Python async workloads:

- many requests interleave on one event-loop thread,
- child tasks can outlive the parent frame that created them,
- `asyncio.to_thread()` moves work onto a worker thread that is not running an
  `asyncio.Task`.

To recover the correct parent trace, the tracer needs the current logical Python
task rather than only the current OS thread.

### What the Python async implementation adds

The implementation introduces three pieces of Python-specific state:

1. **Per-thread state** in `python_thread_state`
   - tracks the current `TaskObj*`,
   - tracks the current `PyContext*`,
   - tracks an in-flight child task while `_asyncio_Task___init__` is running.

2. **Per-task state** in `python_task_state`
   - stores the parent task pointer,
   - stores an ephemeral partial connection key (`connection_info_part_t`) that identifies the server-side request owned by that task,
   - stores a monotonically increasing version for `TaskObj*` reuse protection.

3. **Context-to-task state** in `python_context_task`
   - binds a copied `PyContext*` to the task that owned it when the copy was
     created,
   - stores the task version captured at bind time.

The end result is a two-stage lookup:

1. resolve the current logical task,
2. walk task ancestry until finding the task that owns the server request
   connection.

That keeps Python async correlation aligned with the generic parent-trace flow
already used elsewhere in the tracer: once the owning request connection is
known, OBI resolves the parent span from `server_traces_aux`.

## Runtime Model

The design depends on three CPython behaviors:

1. creating an `asyncio.Task` copies the current `contextvars.Context` when no
   explicit context is supplied,
2. `Context.run()` makes a `Context` active on the current thread for the
   duration of the callback,
3. `asyncio.to_thread()` propagates the current `Context` to the worker thread.

Those are `asyncio` and `contextvars` semantics, not assumptions about the
default selector loop. `uvloop` replaces the event loop implementation, but it
still runs normal `asyncio.Task` and `contextvars` flows, so OBI can anchor the
feature on CPython `_asyncio` and `libpython` symbols rather than on `uvloop`
internals.

## Probe Points

The implementation is built around four probe families.

### `_asyncio_Task___init__`

Runs when a new `asyncio.Task` is created.

Responsibilities:

- capture the child `TaskObj*`,
- record the parent task from the current thread state,
- snapshot the request connection that currently belongs to that logical flow,
- mark the child as `inflight_task` so the copied context can be attributed
  before the child starts running.

This is where OBI builds the task lineage used later during parent lookup.

### `PyContext_CopyCurrent()` / `context_new_from_vars`

Runs when Python copies the active `Context`.

Responsibilities:

- during task creation, bind the copied context to the new child task,
- during `asyncio.to_thread()`, bind the copied context to the current
  event-loop task before execution moves to the worker thread.

The Docker test environment can expose `context_new_from_vars` instead of
`PyContext_CopyCurrent()` because the compiler applies Tail Recursion
Optimization (TRO) to `PyContext_CopyCurrent`, inlining it into
`context_new_from_vars`, so both symbols map to the same probe.

### `task_step`

Runs when `_asyncio` switches execution into a task.

Responsibilities:

- track which task is currently active on the event-loop thread,
- clear `current_task` when the step returns.

This is the direct task identity path for async client work that still runs on
the event loop.

### `context_run`

Runs when Python activates a `Context` on a thread.

Responsibilities:

- track which `PyContext*` is active on the current thread,
- preserve the rest of the thread snapshot while updating the current context.

This is the bridge for cases where there is no direct task identity on the
thread, most importantly `asyncio.to_thread()`.

## Parent Lookup

When a Python client request needs a trace parent, lookup happens in two phases.

### Phase 1: resolve the current logical task

`resolve_python_current_task()` checks:

1. `python_thread_state.current_task`
2. `python_thread_state.current_context`
3. `python_context_task[current_context]`
4. `resolve_python_context_task()` to reject stale task pointers whose version
   no longer matches

If the current thread is executing a normal task step, the first path wins. If
the current thread is a `to_thread` worker, the second path resolves the task
through the active copied context.

### Phase 2: walk task ancestry until a request owner is found

`find_python_parent_trace()` starts from the resolved task and walks up the
stored parent chain. For each task it checks whether `python_task_state.conn`
contains the request connection that owns the server span. When it does, parent
lookup continues through `server_traces_aux`, exactly like the other runtime
correlation mechanisms.

This means `asyncio.to_thread()` does not need a separate parent-discovery
algorithm. The worker thread only needs to recover the originating task from
the copied context; after that, normal task-parent traversal takes over.

## Implementation Details

### Request ownership is captured at task creation time

Task creation stores the request connection in `python_task_state` with a
parent-first rule. If the parent task already owns a request connection, the
child inherits that connection directly. Otherwise task creation falls back to
the current thread-local connection from `pid_tid_to_conn`.

This ordering matters because `python_task_state` is request-scoped, while
`pid_tid_to_conn` is only thread-scoped. Once child tasks start interleaving on
the same event-loop thread, the thread-local connection can already belong to a
different in-flight request. Preferring the parent keeps child tasks in the
same request lineage across concurrent `gather()` workloads.

### Task pointer reuse is versioned

CPython can eventually reuse the same `TaskObj*` address for a different task
instance. To prevent stale `PyContext* -> TaskObj*` mappings from resolving to
the wrong task, each task state carries a version counter. Context bindings
capture that version, and lookup rejects the mapping if the current task state
version no longer matches.

### Probe attachment is version-aware

The userspace tracer adapts probe attachment in three places:

- `_asyncio.task_step` uses one start probe for Python 3.9-3.11 and another for
  Python 3.12+ because the task argument moved from `PT_REGS_PARM1` to
  `PT_REGS_PARM2`,
- `context_run.lto_priv.0` is attached as an alternative symbol for Python 3.14
  builds with link-time optimization,
- `context_new_from_vars` is attached as an alternative return probe when
  `PyContext_CopyCurrent()` is optimized differently in container builds.

The `_asyncio` probe attachment itself is discovered dynamically from the
process's loaded libraries, so the tracer can attach to the actual
`.../lib-dynload/_asyncio` module in use.

### Why this works with `uvloop`

There is no `uvloop`-specific BPF state. The feature works because the
correlation points are defined by CPython task/context behavior:

- task execution still enters `_asyncio.task_step`,
- task creation still goes through `_asyncio_Task___init__`,
- copied contexts still come from `PyContext_CopyCurrent()`,
- worker-thread execution still activates a `Context` via `context_run`.

`uvloop` changes how readiness and callback scheduling are driven, but not the
logical contract OBI uses to reconstruct task lineage.

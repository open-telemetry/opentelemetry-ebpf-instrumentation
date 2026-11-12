// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/preempt_guard.h>

#include <generictracer/python_exception.h>
#include <pid/pid.h>

// Entry of _PyErr_SetObject(tstate, type, value), which every new raise passes
// through. User space attaches it only to processes that capture exceptions.
SEC("uprobe/python_err_set_object")
int GUARDED_PROG(obi_uprobe_python_err_set_object, struct pt_regs *, ctx) {
    if (!g_exceptions_enabled) {
        return 0;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);
    const u32 process_pid = obi_pid(id);
    const python_exception_proc_t *proc =
        bpf_map_lookup_elem(&python_exception_procs, &process_pid);
    if (!proc) {
        return 0;
    }

    const u64 type = (u64)PT_REGS_PARM2(ctx);
    if (python_exception_control_flow(proc, type)) {
        return 0;
    }

    tp_info_t tp = {};
    const enum exception_owner owner = python_exception_owner(id, &tp);
    if (owner == k_exception_owner_none) {
        return 0;
    }

    const u64 tstate = (u64)PT_REGS_PARM1(ctx);
    if (python_read_ptr(tstate + proc->tstate_interp) != proc->main_interp) {
        return 0;
    }

    python_exception_key_t key = {.pid = host_pid};
    __builtin_memcpy(key.span_id, tp.span_id, sizeof(key.span_id));

    python_exception_pending_t *pending = python_exception_pending_slot(&key);
    if (!pending) {
        return 0;
    }
    python_exception_keep(proc, tstate, pending);

    const u64 value = (u64)PT_REGS_PARM3(ctx);
    const u64 value_type = python_object_type(value);
    if (!python_exception_reraised(proc, &pending->latest, value, value_type)) {
        python_exception_capture(proc, tstate, type, value, value_type, &pending->latest);
        pending->latest.payload.obi_pid = process_pid;
        pending->latest.owner = owner;
    }

    return 0;
}

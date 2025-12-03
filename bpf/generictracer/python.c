// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/trace_common.h>

#include <pid/pid.h>

static __always_inline trace_key_t make_trace_key(void *context) {
    trace_key_t t_key = {};
    task_tid(&t_key.p_key);
    if (context) {
        t_key.extra_id = (u64)context;
    } else {
        t_key.extra_id = extra_runtime_id();
    }
    return t_key;
}

SEC("uprobe/libpython3.so:context_run")
int obi_uprobe_context_run(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    void *context = (void *)PT_REGS_PARM1(ctx);
    const trace_key_t t_key = make_trace_key(context);

    bpf_dbg_printk("context_run: tid=%d ctx=%llx", t_key.p_key.tid, context);
    bpf_map_update_elem(&python_thread_context, &t_key, &context, BPF_ANY);
    bpf_map_update_elem(&python_current_context, &id, &context, BPF_ANY);
    return 0;
}

SEC("uprobe/libpython3.so:context_new_from_vars_ret")
int obi_uprobe_context_new_from_vars_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    void *context = (void *)PT_REGS_RC(ctx);

    if (!context) {
        return 0;
    }

    const trace_key_t t_key = make_trace_key(0);

    bpf_dbg_printk(
        "context_new: tid=%d ctx=%llx extra=%llx", t_key.p_key.tid, context, t_key.extra_id);
    bpf_map_update_elem(&python_context_trace, &context, &t_key, BPF_ANY);
    return 0;
}

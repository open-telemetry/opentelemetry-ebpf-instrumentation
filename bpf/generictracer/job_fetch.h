// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/lw_thread.h>
#include <common/tp_info.h>

#include <generictracer/maps/job_fetch_waits.h>
#include <generictracer/redis_job_fetch.h>

#include <maps/java_vt_threads.h>
#include <maps/job_contexts.h>
#include <maps/python_thread_state.h>

#include <pid/pid_helpers.h>

// A thread that took a job off a queue runs it until its next fetch

static __always_inline void job_thread_key(pid_key_t *thread) {
    task_tid(thread);
    java_vt_translate_tid(thread);
}

static __always_inline bool job_fetch_same_conn(const pid_connection_info_t *a,
                                                const pid_connection_info_t *b) {
    if (a->pid != b->pid || a->conn.s_port != b->conn.s_port || a->conn.d_port != b->conn.d_port) {
        return false;
    }

    for (u8 i = 0; i < IP_V6_ADDR_LEN_WORDS; i++) {
        if (a->conn.s_ip[i] != b->conn.s_ip[i] || a->conn.d_ip[i] != b->conn.d_ip[i]) {
            return false;
        }
    }

    return true;
}

// The job fetch a client request starts; the thread's previous job ends with it
static __always_inline enum redis_job_fetch job_fetch_request(const unsigned char *buf,
                                                              const u32 len,
                                                              const u8 direction,
                                                              const bool is_server,
                                                              const lw_thread_t lw_thread) {
    // goroutines move between threads, so only real threads can run a job
    if (direction != TCP_SEND || is_server || lw_thread != k_lw_thread_none) {
        return k_redis_job_fetch_none;
    }

    const enum redis_job_fetch fetch = redis_job_fetch_request(buf, len);
    if (fetch == k_redis_job_fetch_none) {
        return fetch;
    }

    pid_key_t thread = {0};
    job_thread_key(&thread);
    const job_context_t *job = bpf_map_lookup_elem(&job_contexts, &thread);
    // a job that started no thread or process of its own was handed to a reused one, or run here
    if (job && !job->inherited && !job->children) {
        const u8 pooled = 1;
        bpf_map_update_elem(&job_pooled_owners, &thread, &pooled, BPF_ANY);
    }
    bpf_map_delete_elem(&job_contexts, &thread);

    return fetch;
}

// A fetch made while serving a request is one of its calls, not the start of a job
static __always_inline void job_fetch_wait(const pid_connection_info_t *conn,
                                           const enum redis_job_fetch fetch,
                                           const u8 parent_status) {
    if (fetch == k_redis_job_fetch_none || parent_status != k_parent_status_none) {
        return;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const job_fetch_wait_t wait = {.conn = *conn, .fetch = fetch};
    bpf_map_update_elem(&job_fetch_waits, &id, &wait, BPF_ANY);
}

// a thread serving other connections while the fetch is pending runs many jobs at once
static __always_inline void job_fetch_see_buffer(const pid_connection_info_t *conn,
                                                 const lw_thread_t lw_thread) {
    if (lw_thread != k_lw_thread_none) {
        return;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const job_fetch_wait_t *wait = bpf_map_lookup_elem(&job_fetch_waits, &id);
    if (wait && !job_fetch_same_conn(&wait->conn, conn)) {
        bpf_map_delete_elem(&job_fetch_waits, &id);
    }
}

static __always_inline bool python_asyncio_thread(const u64 id) {
    const python_thread_state_t *state = bpf_map_lookup_elem(&python_thread_state, &id);

    return state && (state->current_task || state->current_context);
}

static __always_inline void job_fetch_reply(const pid_connection_info_t *conn,
                                            const tp_info_t *fetch_tp,
                                            const unsigned char *reply,
                                            const u32 len) {
    const u64 id = bpf_get_current_pid_tgid();
    const job_fetch_wait_t *wait = bpf_map_lookup_elem(&job_fetch_waits, &id);
    if (!wait || !job_fetch_same_conn(&wait->conn, conn)) {
        return;
    }

    const enum redis_job_fetch fetch = wait->fetch;
    bpf_map_delete_elem(&job_fetch_waits, &id);

    // asyncio tasks share the thread, so a job can't be told apart from the tasks around it
    if (!redis_job_fetch_reply_has_job(fetch, reply, len) || python_asyncio_thread(id)) {
        return;
    }

    job_context_t job = {
        .tp =
            {
                .tp = *fetch_tp,
                .pid = pid_from_pid_tgid(id),
                .valid = 1,
            },
    };
    // the job starts with the reply: a blocking fetch may have waited longer than a job lasts
    job.tp.tp.ts = bpf_ktime_get_ns();
    job_thread_key(&job.owner);

    bpf_map_update_elem(&job_contexts, &job.owner, &job, BPF_ANY);
}

// A thread or process the job's own thread starts runs the job, unless that thread reuses them
static __always_inline void job_inherit(const struct task_struct *child) {
    pid_key_t parent = {0};
    job_thread_key(&parent);

    job_context_t *job = bpf_map_lookup_elem(&job_contexts, &parent);
    // a helper the job starts in turn may outlive the job and serve later ones
    if (!job || job->inherited || bpf_map_lookup_elem(&job_pooled_owners, &parent)) {
        return;
    }

    job->children++;
    job_context_t inherited = *job;
    inherited.inherited = 1;

    pid_key_t thread = {0};
    task_tid_of(child, &thread);
    bpf_map_update_elem(&job_contexts, &thread, &inherited, BPF_ANY);
}

static __always_inline void job_thread_end(const pid_key_t *thread, const u64 id) {
    bpf_map_delete_elem(&job_contexts, thread);
    bpf_map_delete_elem(&job_fetch_waits, &id);
}

// A child that runs another program doesn't show the job has threads or processes of its own
static __always_inline void job_exec(const pid_key_t *thread, const u64 id) {
    const job_context_t *job = bpf_map_lookup_elem(&job_contexts, thread);
    if (job && job->inherited) {
        job_context_t *owner = bpf_map_lookup_elem(&job_contexts, &job->owner);
        if (owner && !owner->inherited && owner->children &&
            !bpf_memcmp(owner->tp.tp.span_id, job->tp.tp.span_id, SPAN_ID_SIZE_BYTES)) {
            owner->children--;
        }
    }

    job_thread_end(thread, id);
}

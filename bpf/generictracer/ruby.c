// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/strings.h>

#include <generictracer/maps/pid_tid_to_conn.h>
#include <generictracer/maps/puma_tasks.h>

#include <generictracer/types/puma_task_id.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>

enum { k_comm_len = 12 };
enum { k_rb_ary_embedded_ptr_pos = 0x10, k_rb_ary_heap_ptr_pos = 0x20 };
const char PUMA_WORKER[] = "puma srv tp";
const char PUMA_SRV[] = "puma srv";
const char PUMA_SRV_THREAD[] = "puma srv th";

/**
Code to track the worker thread handoff for Puma used in Ruby on Rails and other Ruby based projects.
Puma architecture document: https://github.com/puma/puma/blob/main/docs/architecture.md

Basic concepts:
1. Server thread, which does all the accept(s) of the incoming requests, named "puma srv".
2. Worker threads, that do all the request handling, named "puma srv tp NNN"
3. Reactor thread, which takes over the reading of the incoming request if there are no worker
   threads available.
4. Other worker threads, named "puma srv thread NNN".

The "puma srv" thread adds the work when it's accepted, by sending a "client" object to
the "worker pool", called "pool" in the server.rb code: 
https://github.com/puma/puma/blob/731b97d2a5c7838c9d736462e259e629655b00a1/lib/puma/server.rb#L406

This is effectively an array push in ruby's world, handled by rb_ary_push.

The worker threads ("puma srv tp NNN") wait around for work to arrive, and when there's work ready, they take
the head of the work queue setup by the "puma srv" thread, by calling "shift" on the array, i.e. rb_ary_shift.
This is the call to "todo.shft": 
https://github.com/puma/puma/blob/731b97d2a5c7838c9d736462e259e629655b00a1/lib/puma/thread_pool.rb#L178

We can see that the << operator that "server.rb" calls, is essentially adding to the todo queue:
https://github.com/puma/puma/blob/731b97d2a5c7838c9d736462e259e629655b00a1/lib/puma/thread_pool.rb#L261


The approach we take to handle this is the follows:
1. Uprobe on "rb_obj_call_init_kw", where we match the name of the server thread. Initially, a probe on
   "rb_ary_push" was considered, but this proved to be very expensive. Instead we look for calls to
   object initializations by this thread. This thread may be initializing random objects, but we don't care, 
   since the LRU map will flush the unwanted items. The "puma srv" thread is a light allocator.
2. At the time the "push" probe runs, we looks to see if we have recorded info in the accept4 kprobe. If we have,
   then we record metadata so that the worker thread can find it. What we record is the item pointer. 
   Since Ruby GC (so far) doesn't move objects, this should work 100% of the
   time. Even if they decide to move and compact the objects, the chances of this new object from moving
   is very small. If the references ever move, we'll fail to correlate the server and client call in
   that instance.
3. Uprobe on "rb_ary_shift", where we match for the "puma srv tp" worker threads and we read the head
   of the todo array. We handle two cases, Ruby embedded arrays and Ruby heap arrays. Ruby frozen arrays
   don't matter, since we would be throwing an exception on shift if this array was frozen.
4. At the time of the "shift" probe, we take the item pointer and record it for the 
   current thread. 
5. find_parent_trace in trace_common.h, looks up the puma metadata for the current pid:tgid pair. It
   would find the metadata recorded by the "rb_ary_shft" uprobe, i.e. the "puma srv tp NNN" worker, which
   is the client thread. We take the returned "array:item" pair from the client and look up in the map
   setup by "puma srv" thread on "rb_array_push" for the connection information of the original server
   request that was accepted. We then use the connection information to hit "server_traces_aux" for the
   traceparent information, much like we do for "nginx".

In a sense, this design is very similar to what happens with nginx request tracking, except here we use
the array:item pair for the work, rather than the file descriptors.
 */

SEC("uprobe/ruby:rb_obj_call_init_kw")
int obi_rb_obj_call_init_kw(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    char buf[k_comm_len];
    if (bpf_get_current_comm(buf, k_comm_len)) {
        bpf_dbg_printk("can't get current command");
        return 0;
    }

    u64 item = (u64)PT_REGS_PARM1(ctx);

    if (!obi_bpf_memcmp(buf, PUMA_WORKER, sizeof(PUMA_WORKER) - 1) ||
        !obi_bpf_memcmp(buf, PUMA_SRV_THREAD, sizeof(PUMA_SRV_THREAD) - 1)) {
        //bpf_printk("rb_obj_call_init_kw <==> ary %llx, item %llx, thread %s", ary, item, buf);
        return 0;
    } else if (!obi_bpf_memcmp(buf, PUMA_SRV, sizeof(PUMA_SRV) - 1)) {
        ssl_pid_connection_info_t *info = bpf_map_lookup_elem(&pid_tid_to_conn, &id);
        if (!info) {
            bpf_dbg_printk("rb_obj_call_init_kw no connection info for id %lld", id);
            return 0;
        }

        bpf_dbg_printk("rb_obj_call_init_kw ==> item %llx, thread %s", item, buf);

        u32 host_pid = pid_from_pid_tgid(id);
        connection_info_part_t conn_part = {};
        populate_ephemeral_info(
            &conn_part, &info->p_conn.conn, info->orig_dport, host_pid, FD_SERVER);

        puma_task_id_t task_id = {
            .item = item,
            .pid = host_pid,
        };

        bpf_map_update_elem(&puma_task_connections, &task_id, &conn_part, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/ruby:rb_ary_shift")
int obi_rb_ary_shift(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 item_ptr = (u64)PT_REGS_PARM1(ctx);

    if (!item_ptr) {
        return 0;
    }

    u64 flags = 0;
    bpf_probe_read_user(&flags, sizeof(u64), (void *)(item_ptr));

    // See if the array is not embedded anymore and we have to
    // find the heap pointer. If the 0x2000 flag is set, the array
    // is embedded.
    const u16 embedded_arr = flags & 0x2000;

    u64 item = 0;
    bpf_probe_read_user(&item, sizeof(u64), (void *)(item_ptr + k_rb_ary_embedded_ptr_pos));

    bpf_dbg_printk("rb_ary_shift ret ==> slice %llx, item %llx, flags %x", item_ptr, item, flags);

    // If we don't have an embedded array, item is the current array length.
    // Zero length means we don't have elements in the array.
    if (item) {
        if (!embedded_arr) {
            u64 heap_arr_ptr = 0;
            bpf_probe_read_user(
                &heap_arr_ptr, sizeof(u64), (void *)(item_ptr + k_rb_ary_heap_ptr_pos));
            if (heap_arr_ptr) {
                bpf_probe_read_user(&item, sizeof(u64), (void *)(heap_arr_ptr));
                bpf_dbg_printk("heap %llx, value item %llx", heap_arr_ptr, item);
            } else {
                bpf_dbg_printk("empty heap pointer, 0 array length?");
                return 0;
            }
        }

        u32 host_pid = pid_from_pid_tgid(id);

        puma_task_id_t task_id = {
            .item = item,
            .pid = host_pid,
        };

        connection_info_part_t *conn_part = bpf_map_lookup_elem(&puma_task_connections, &task_id);
        if (conn_part) {
            bpf_dbg_printk("stored item to id correlation, id = %llx, item %llx", id, item);
            bpf_map_update_elem(&puma_worker_tasks, &id, &task_id, BPF_ANY);
        } else {
            bpf_dbg_printk("untracked item %llx, ignoring...", item);
        }
    }

    return 0;
}

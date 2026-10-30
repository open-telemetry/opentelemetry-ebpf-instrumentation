// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/exception_event.h>
#include <common/scratch_mem.h>

#include <maps/exception_events.h>

// Set from user space when any selected workload captures exceptions.
volatile const bool g_exceptions_enabled;

enum { k_exception_payload_max_len = 8192 };

typedef struct exception_record {
    exception_event_header_t hdr;
    unsigned char payload[k_exception_payload_max_len];
} exception_record_t;

SCRATCH_MEM(exception_record_t)

// Returns per-CPU scratch space with a zeroed header. The caller fills the
// header and payload, then calls exception_record_submit in the same program
// run. State kept across probes belongs in a keyed map.
static __always_inline exception_record_t *exception_record_start(void) {
    exception_record_t *record = exception_record_t_mem();
    if (!record) {
        return NULL;
    }

    __builtin_memset(&record->hdr, 0, sizeof(record->hdr));
    return record;
}

static __always_inline void exception_record_submit(const exception_record_t *record) {
    if (record->hdr.payload_len > sizeof(record->payload)) {
        return;
    }

    u64 size = sizeof(record->hdr) + record->hdr.payload_len;
    bpf_clamp_umax(size, sizeof(*record));

    exception_events_ringbuf_output((void *)record, size);
}

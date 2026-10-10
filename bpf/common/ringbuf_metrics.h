// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/ringbuf_types.h>

#include <bpfcore/bpf_helpers.h>

static __always_inline void
account_ringbuf_write(void *stats_map, bool metrics_enabled, bool failed) {
    if (!metrics_enabled) {
        return;
    }

    ringbuf_write_stats_t *stats = bpf_map_lookup_elem(stats_map, &(u32){0});
    if (!stats) {
        return;
    }

    stats->writes++;
    if (failed) {
        stats->failures++;
    }
}

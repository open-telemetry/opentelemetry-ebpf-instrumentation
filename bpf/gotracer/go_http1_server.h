// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>

#include <gotracer/go_common.h>
#include <gotracer/go_http1.h>
#include <gotracer/types/nethttp.h>

enum go_http_server_header_source : u8 {
    k_go_http_server_header_source_none = 0,
    k_go_http_server_header_source_http2 = 1,
};

enum go_http_server_parent_authority : u8 {
    k_go_http_server_parent_force_root = 0,
    k_go_http_server_parent_connection_fallback = 1,
    k_go_http_server_parent_traceparent = 2,
};

static __always_inline u8
go_http1_server_invocation_is_pending(const server_http_func_invocation_t *invocation) {
    return invocation && invocation->start_monotime_ns == 0;
}

static __always_inline u8 go_http1_begin_server_handoff(void *handoff_map,
                                                        const go_addr_key_t *key,
                                                        http1_server_handoff_t *fresh,
                                                        u8 is_tls) {
    if (!fresh) {
        return 0;
    }

    const u64 generation = key ? go_process_generation(key->pid) : 0;
    if (!generation) {
        return 0;
    }
    __builtin_memset(fresh, 0, sizeof(*fresh));
    fresh->generation = generation;
    fresh->traceparent_state = k_go_http1_traceparent_scan_unknown;
    fresh->parsing = 1;
    fresh->is_tls = is_tls;
    return bpf_map_update_elem(handoff_map, key, fresh, BPF_ANY) == 0;
}

static __always_inline u8 go_http1_server_handoff_is_current(const http1_server_handoff_t *handoff,
                                                             const go_addr_key_t *key) {
    return handoff && key && go_process_generation_matches(key->pid, handoff->generation);
}

static __always_inline http1_server_handoff_t *
go_http1_server_handoff_lookup_current(void *handoff_map, const go_addr_key_t *key) {
    if (!handoff_map || !key) {
        return NULL;
    }
    http1_server_handoff_t *handoff = bpf_map_lookup_elem(handoff_map, key);
    if (!handoff) {
        return NULL;
    }
    if (!go_http1_server_handoff_is_current(handoff, key)) {
        bpf_map_delete_elem(handoff_map, key);
        return NULL;
    }
    return handoff;
}

static __always_inline server_http_func_invocation_t *
go_http_server_invocation_lookup_current(void *invocation_map, const go_addr_key_t *key) {
    if (!invocation_map || !key) {
        return NULL;
    }
    server_http_func_invocation_t *invocation = bpf_map_lookup_elem(invocation_map, key);
    if (!invocation) {
        return NULL;
    }
    if (!go_process_generation_matches(key->pid, invocation->generation)) {
        bpf_map_delete_elem(invocation_map, key);
        return NULL;
    }
    return invocation;
}

static __always_inline void go_http1_finish_server_header_parsing(void *handoff_map,
                                                                  const go_addr_key_t *key) {
    http1_server_handoff_t *handoff = go_http1_server_handoff_lookup_current(handoff_map, key);
    if (handoff) {
        handoff->parsing = 0;
    }
}

static __always_inline void go_http1_close_server_handoff(void *handoff_map,
                                                          const go_addr_key_t *key) {
    bpf_map_delete_elem(handoff_map, key);
}

static __always_inline void go_http_server_close_prehandler_state(void *handoff_map,
                                                                  void *invocation_map,
                                                                  const go_addr_key_t *key) {
    bpf_map_delete_elem(handoff_map, key);
    bpf_map_delete_elem(invocation_map, key);
}

static __always_inline void
go_http_clear_unversioned_address_state(void *client_invocation_map,
                                        void *client_data_map,
                                        void *client_connection_map,
                                        void *framer_map,
                                        void *process_headers_map,
                                        void *handoff_map,
                                        void *server_invocation_map,
                                        void *reader_map,
                                        void *server_connection_map,
                                        const go_addr_key_t *key,
                                        const go_exact_process_addr_key_t *client_key) {
    if (client_key) {
        bpf_map_delete_elem(client_invocation_map, client_key);
        bpf_map_delete_elem(client_data_map, client_key);
        bpf_map_delete_elem(client_connection_map, client_key);
        bpf_map_delete_elem(process_headers_map, client_key);
    }
    bpf_map_delete_elem(framer_map, key);
    go_http_server_close_prehandler_state(handoff_map, server_invocation_map, key);
    bpf_map_delete_elem(reader_map, key);
    bpf_map_delete_elem(server_connection_map, key);
}

static __always_inline void go_http_server_retire_go_trace(const go_addr_key_t *key) {
    poison_and_revoke_go_trace(key);
}

static __always_inline http1_server_handoff_t *
go_http1_server_header_observation_eligible(void *handoff_map, const go_addr_key_t *key) {
    http1_server_handoff_t *handoff = go_http1_server_handoff_lookup_current(handoff_map, key);
    return handoff && handoff->parsing ? handoff : NULL;
}

static __always_inline u8
go_http1_server_handoff_has_parent(const http1_server_handoff_t *handoff) {
    return handoff && handoff->headers_complete &&
           handoff->traceparent_state == k_go_http1_traceparent_scan_found &&
           valid_trace(handoff->tp.trace_id) && valid_span(handoff->tp.span_id);
}

static __always_inline u8 go_http1_store_server_scan(http1_server_handoff_t *handoff,
                                                     enum go_http1_traceparent_scan_result result,
                                                     const go_http1_traceparent_t *traceparent) {
    if (!handoff || !handoff->parsing) {
        return 0;
    }

    handoff->headers_observed = 1;
    handoff->headers_complete = result != k_go_http1_traceparent_scan_unknown;
    handoff->observation_failed = result == k_go_http1_traceparent_scan_unknown;
    handoff->traceparent_observed = result == k_go_http1_traceparent_scan_found ||
                                    result == k_go_http1_traceparent_scan_present;

    if (result == k_go_http1_traceparent_scan_found && traceparent && traceparent->authoritative &&
        valid_trace(traceparent->tp.trace_id) && valid_span(traceparent->tp.span_id)) {
        handoff->tp = traceparent->tp;
        handoff->traceparent_state = k_go_http1_traceparent_scan_found;
    } else {
        __builtin_memset(&handoff->tp, 0, sizeof(handoff->tp));
        handoff->traceparent_state = result == k_go_http1_traceparent_scan_found
                                         ? k_go_http1_traceparent_scan_present
                                         : result;
    }

    return handoff->traceparent_state != k_go_http1_traceparent_scan_absent;
}

static __always_inline u8 go_http1_fail_server_header_observation(http1_server_handoff_t *handoff) {
    if (!handoff || !handoff->parsing) {
        return 0;
    }

    __builtin_memset(&handoff->tp, 0, sizeof(handoff->tp));
    handoff->traceparent_state = k_go_http1_traceparent_scan_unknown;
    handoff->headers_complete = 0;
    handoff->observation_failed = 1;
    return 1;
}

static __always_inline u8 go_http1_observe_legacy_server_header(http1_server_handoff_t *handoff,
                                                                const unsigned char *field,
                                                                u32 captured_len,
                                                                u64 field_len) {
    if (!handoff || !handoff->parsing || handoff->observation_failed) {
        return handoff && handoff->observation_failed;
    }

    handoff->headers_observed = 1;
    if (field_len == 0) {
        handoff->headers_complete = 1;
        if (!handoff->traceparent_observed) {
            __builtin_memset(&handoff->tp, 0, sizeof(handoff->tp));
            handoff->traceparent_state = k_go_http1_traceparent_scan_absent;
        }
        return handoff->traceparent_state != k_go_http1_traceparent_scan_absent;
    }

    if (!field || captured_len < k_go_http1_traceparent_name_field_len ||
        !is_traceparent_name(field)) {
        return 0;
    }

    if (handoff->traceparent_observed || field_len > captured_len) {
        __builtin_memset(&handoff->tp, 0, sizeof(handoff->tp));
        handoff->traceparent_observed = 1;
        handoff->traceparent_state = k_go_http1_traceparent_scan_present;
        return 1;
    }

    handoff->traceparent_observed = 1;
    handoff->traceparent_state = k_go_http1_traceparent_scan_absent;
    go_http1_observe_inbound_traceparent(
        &handoff->tp, &handoff->traceparent_state, field, captured_len);
    return 1;
}

static __always_inline u8 go_http1_pending_h2_sentinel(
    const server_http_func_invocation_t *invocation, const u64 current_generation) {
    return go_http1_server_invocation_is_pending(invocation) &&
           invocation->header_source == k_go_http_server_header_source_http2 &&
           process_incarnation_matches(invocation->generation, current_generation);
}

static __always_inline u8 go_http2_header_requires_parent_discard(u8 traceparent_state) {
    return traceparent_state != k_go_http1_traceparent_scan_absent;
}

static __always_inline enum go_http_server_parent_authority
go_http_server_parent_authority(const http1_server_handoff_t *http1,
                                const server_http_func_invocation_t *pending_h2,
                                const u64 current_generation) {
    if (http1) {
        if (!process_incarnation_matches(http1->generation, current_generation)) {
            return k_go_http_server_parent_force_root;
        }
        if (!http1->headers_complete) {
            return k_go_http_server_parent_force_root;
        }
        if (http1->traceparent_state == k_go_http1_traceparent_scan_absent) {
            return k_go_http_server_parent_connection_fallback;
        }
        if (go_http1_server_handoff_has_parent(http1)) {
            return k_go_http_server_parent_traceparent;
        }
        return k_go_http_server_parent_force_root;
    }

    if (!go_http1_pending_h2_sentinel(pending_h2, current_generation)) {
        return k_go_http_server_parent_force_root;
    }
    if (pending_h2->header_traceparent_state == k_go_http1_traceparent_scan_found &&
        valid_trace(pending_h2->tp.trace_id) && valid_span(pending_h2->tp.span_id)) {
        return k_go_http_server_parent_traceparent;
    }
    return k_go_http_server_parent_force_root;
}

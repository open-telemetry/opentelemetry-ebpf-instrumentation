// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/utils.h>

#include <common/h2_defs.h>

#ifndef OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
#define OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE 1
#endif

#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
#define OBI_HPACK_CACHE_HELPER __always_inline
#else
#define OBI_HPACK_CACHE_HELPER __noinline
#endif

enum hpack_traceparent_status : u8 {
    k_hpack_traceparent_absent,
    k_hpack_traceparent_found,
    k_hpack_traceparent_unknown,
};

enum hpack_server_parent_authority : u8 {
    k_hpack_server_parent_force_root,
    k_hpack_server_parent_connection_fallback,
    k_hpack_server_parent_traceparent,
};

static __always_inline enum hpack_server_parent_authority
hpack_server_parent_authority(u8 status, u8 decoded) {
    if (status == k_hpack_traceparent_absent) {
        return k_hpack_server_parent_connection_fallback;
    }
    if (status == k_hpack_traceparent_found && decoded) {
        return k_hpack_server_parent_traceparent;
    }
    return k_hpack_server_parent_force_root;
}

enum hpack_field_representation : u8 {
    k_hpack_representation_unknown,
    k_hpack_representation_indexed,
    k_hpack_representation_incremental,
    k_hpack_representation_without_indexing,
    k_hpack_representation_never_indexed,
};

enum hpack_name_classification : u8 {
    k_hpack_name_unknown,
    k_hpack_name_traceparent,
    k_hpack_name_non_traceparent,
};

enum {
    k_hpack_dynamic_entry_overhead = 32,
    k_hpack_default_dynamic_table_size = 4096,
    // RFC 7541 entries are at least 32 octets, so the default table can hold
    // at most 128 entries. Larger negotiated tables fail closed below.
    k_hpack_max_tracked_dynamic_entries =
        k_hpack_default_dynamic_table_size / k_hpack_dynamic_entry_overhead,
    k_hpack_dynamic_entry_mask = k_hpack_max_tracked_dynamic_entries - 1,
    k_hpack_dynamic_entry_size_bits = 13,
    k_hpack_dynamic_name_size_bits = 12,
    k_hpack_dynamic_entry_size_mask = (1U << k_hpack_dynamic_entry_size_bits) - 1,
    k_hpack_dynamic_name_size_mask = (1U << k_hpack_dynamic_name_size_bits) - 1,
    k_hpack_dynamic_name_size_shift = k_hpack_dynamic_entry_size_bits,
    k_hpack_dynamic_classification_shift =
        k_hpack_dynamic_entry_size_bits + k_hpack_dynamic_name_size_bits,
    // A valid v00 traceparent entry consumes 32 + 11 + 55 = 98 octets, so a
    // default 4096-byte table can retain at most 41. Keep one spare slot for
    // simple bounded allocation and future-version values can only be larger.
    k_hpack_max_cached_traceparents = 42,
    k_hpack_min_incremental_field_bytes = 2,
    // The shortest RFC 7541 Huffman symbol is five bits. A single decoded
    // string in a bounded fresh block therefore cannot exceed this size.
    k_hpack_max_ephemeral_decoded_string = (k_hpack_tp_max_scan * 8) / 5,
    k_hpack_max_cache_free_dynamic_entries =
        k_hpack_tp_max_scan / k_hpack_min_incremental_field_bytes,
    // A known dynamic name can be reused by every later two-byte insertion.
    // Bound each name by the largest fresh-block string, then add one shared
    // value-string allowance and the 32-byte overhead for every entry.
    k_hpack_max_cache_free_cumulative_size =
        k_hpack_max_cache_free_dynamic_entries *
            (k_hpack_dynamic_entry_overhead + k_hpack_max_ephemeral_decoded_string) +
        k_hpack_max_ephemeral_decoded_string,
};

_Static_assert((k_hpack_max_tracked_dynamic_entries & k_hpack_dynamic_entry_mask) == 0,
               "HPACK dynamic entry count must be a power of two");
_Static_assert(k_hpack_max_cached_traceparents <= 64,
               "HPACK traceparent cache bitmap must fit in u64");
_Static_assert(k_hpack_default_dynamic_table_size < (1U << 16),
               "HPACK cumulative entry sizes must be exact modulo u16");
// A deferred cache fill is completed after scanning one bounded block. Even
// the smallest incremental field needs an opener and value-length octet, so
// an insertion generation cannot wrap before that fill is validated.
_Static_assert(k_hpack_tp_max_scan / k_hpack_min_incremental_field_bytes < 256,
               "HPACK insertion generation can wrap within one scanned block");
_Static_assert(k_hpack_max_cache_free_cumulative_size < (1U << 16),
               "cache-free HPACK insertion history exceeds u16");

typedef struct hpack_traceparent_result {
    u32 value_offset;
    u32 encoded_value_len;
    unsigned char cached_trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char cached_parent_id[SPAN_ID_SIZE_BYTES];
    u8 status;
    u8 value_huffman;
    u8 representation;
    u8 value_cached;
    u8 cached_flags;
    u8 inserted_slot;
    u8 inserted_generation;
    u8 inserted_identity_valid;
    u8 value_cache_unavailable;
    u8 _pad[3];
} hpack_traceparent_result_t;

typedef struct hpack_traceparent_decode_result {
    u32 value_len;
    u8 valid;
    u8 version;
    u8 _pad[2];
} hpack_traceparent_decode_result_t;

static __always_inline u8
hpack_decode_integer(const unsigned char *data, u32 data_len, u32 *pos, u8 prefix_bits, u32 *out) {
    if (!data || !pos || !out || !prefix_bits || prefix_bits > 8) {
        return 0;
    }

    u32 current = *pos;
    if (current >= data_len) {
        return 0;
    }

    const u32 prefix_max = (1U << prefix_bits) - 1;
    u32 data_pos = current;
    bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
    u32 value = data[data_pos] & prefix_max;
    current++;
    if (value < prefix_max) {
        *pos = current;
        *out = value;
        return 1;
    }

#pragma unroll
    for (u8 shift = 0; shift <= 28; shift += 7) {
        if (current >= data_len) {
            return 0;
        }

        data_pos = current;
        bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
        const u8 byte = data[data_pos];
        current++;
        const u32 chunk = byte & 0x7f;
        if (shift == 28 && chunk > 0x0f) {
            return 0;
        }
        const u32 increment = chunk << shift;
        if (increment > ~(u32)0 - value) {
            return 0;
        }
        value += increment;
        if (!(byte & 0x80)) {
            *pos = current;
            *out = value;
            return 1;
        }
    }

    return 0;
}

static __always_inline u8 hpack_decode_string(const unsigned char *data,
                                              u32 data_len,
                                              u32 *pos,
                                              u32 *value_offset,
                                              u32 *value_len,
                                              u8 *huffman) {
    if (!data || !pos || !value_offset || !value_len || !huffman || *pos >= data_len) {
        return 0;
    }

    u32 current = *pos;
    u32 data_pos = current;
    bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
    *huffman = data[data_pos] & 0x80;
    u32 decoded_len = 0;
    if (!hpack_decode_integer(data, data_len, &current, 7, &decoded_len) || current > data_len ||
        decoded_len > data_len - current) {
        return 0;
    }

    u32 next = current + decoded_len;
    if (next > data_len) {
        return 0;
    }
    bpf_clamp_umax(current, k_hpack_tp_max_scan);
    bpf_clamp_umax(next, k_hpack_tp_max_scan);

    *value_offset = current;
    *value_len = decoded_len;
    *pos = next;
    return 1;
}

static __noinline u8 hpack_is_traceparent_huffman_name(const unsigned char *data, u32 offset) {
    u64 mismatch = 0;
    if (offset > k_hpack_tp_max_scan - k_hpack_tp_name_huffman_len) {
        return 0;
    }
    data += offset;
#pragma clang loop unroll(full)
    for (u32 i = 0; i < k_hpack_tp_name_huffman_len; i++) {
        mismatch |= (u64)(data[i] ^ k_hpack_tp_huffman[i]);
    }
    asm volatile("" : "+r"(mismatch));
    return mismatch == 0;
}

static __noinline u8 hpack_is_traceparent_raw_name(const unsigned char *data, u32 offset) {
    u64 mismatch = 0;
    if (offset > k_hpack_tp_max_scan - k_hpack_tp_name_len) {
        return 0;
    }
    data += offset;
#pragma clang loop unroll(full)
    for (u32 i = 0; i < k_hpack_tp_name_len; i++) {
        mismatch |= (u64)(data[i] ^ (u8)k_hpack_tp_name[i]);
    }
    asm volatile("" : "+r"(mismatch));
    return mismatch == 0;
}

typedef struct hpack_cached_traceparent {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u8 flags;
    // One-based dynamic-entry slot plus its insertion generation. Cache
    // records belonging to evicted entries are reclaimed lazily.
    u8 owner_entry_slot;
    u8 owner_generation;
} hpack_cached_traceparent_t;

typedef struct hpack_dynamic_entry {
    u32 encoded;
    // Total inserted entry bytes immediately before this entry. Subtraction
    // from cumulative_size gives the exact active suffix size modulo u16.
    u16 cumulative_start;
    u8 generation;
    // One-based cache slot; zero means that the value is not authoritative.
    u8 traceparent_slot;
} hpack_dynamic_entry_t;

typedef struct hpack_dynamic_name_state {
    // head is the newest entry and HPACK dynamic index one addresses it.
    hpack_dynamic_entry_t entries[k_hpack_max_tracked_dynamic_entries];
    u64 traceparent_slots_used;
    hpack_cached_traceparent_t traceparents[k_hpack_max_cached_traceparents];
    u16 table_size;
    u16 max_table_size;
    u8 head;
    u8 entry_count;
    u8 valid;
    u8 next_generation;
    u16 cumulative_size;
} hpack_dynamic_name_state_t;

static const u8 k_hpack_static_name_lengths[64] = {
    0, 10, 7,  7,  5,  5,  7,  7,  7,  7,  7,  7,  7, 7,  7,  14, 15, 15, 13, 6,  27,
    3, 5,  13, 13, 19, 16, 16, 14, 16, 13, 12, 6,  4, 4,  6,  7,  4,  4,  8,  17, 13,
    8, 19, 13, 4,  8,  12, 18, 19, 5,  7,  7,  11, 6, 10, 25, 17, 10, 4,  3,  16,
};

static __always_inline void hpack_dynamic_name_state_init(hpack_dynamic_name_state_t *state) {
    state->table_size = 0;
    state->max_table_size = k_hpack_default_dynamic_table_size;
    state->head = 0;
    state->entry_count = 0;
    state->valid = 1;
    state->next_generation = 0;
    state->cumulative_size = 0;
    state->traceparent_slots_used = 0;
}

static __always_inline void hpack_dynamic_name_state_clear(hpack_dynamic_name_state_t *state) {
    state->table_size = 0;
    state->head = 0;
    state->entry_count = 0;
    state->cumulative_size = 0;
    state->traceparent_slots_used = 0;
}

static __always_inline void hpack_dynamic_name_state_invalidate(hpack_dynamic_name_state_t *state) {
    hpack_dynamic_name_state_clear(state);
    state->valid = 0;
}

static __always_inline u8
hpack_dynamic_name_state_bounds_valid(const hpack_dynamic_name_state_t *state) {
    if (state->valid > 1 || state->max_table_size > k_hpack_default_dynamic_table_size) {
        return 0;
    }
    if (!state->valid) {
        // An unresolved reference clears the mirror but retains the peer's
        // last advertised limit. A leading zero size update may explicitly
        // resynchronize it on a later block.
        return !state->entry_count && !state->head && !state->table_size &&
               !state->cumulative_size && !state->traceparent_slots_used;
    }
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    return state->entry_count <= k_hpack_max_tracked_dynamic_entries &&
           state->head <= k_hpack_dynamic_entry_mask &&
           state->table_size <= state->max_table_size &&
           state->table_size >= (u32)state->entry_count * k_hpack_dynamic_entry_overhead;
#else
    return state->entry_count <= k_hpack_max_cache_free_dynamic_entries &&
           state->head == ((k_hpack_max_tracked_dynamic_entries - state->entry_count) &
                           k_hpack_dynamic_entry_mask) &&
           state->cumulative_size <= k_hpack_max_cache_free_cumulative_size && !state->table_size &&
           !state->traceparent_slots_used;
#endif
}

static __always_inline u32 hpack_dynamic_entry_pack(u32 entry_size,
                                                    u32 name_size,
                                                    u8 classification) {
    return (entry_size & k_hpack_dynamic_entry_size_mask) |
           ((name_size & k_hpack_dynamic_name_size_mask) << k_hpack_dynamic_name_size_shift) |
           ((u32)classification << k_hpack_dynamic_classification_shift);
}

static __always_inline u32 hpack_dynamic_entry_size(u32 entry) {
    return entry & k_hpack_dynamic_entry_size_mask;
}

static __always_inline u32 hpack_dynamic_entry_encoded(const hpack_dynamic_entry_t *entry) {
    return entry->encoded;
}

static __always_inline u32 hpack_dynamic_name_size(u32 entry) {
    return (entry >> k_hpack_dynamic_name_size_shift) & k_hpack_dynamic_name_size_mask;
}

static __always_inline u8 hpack_dynamic_entry_classification(u32 entry) {
    return entry >> k_hpack_dynamic_classification_shift;
}

static OBI_HPACK_CACHE_HELPER u8 hpack_lookup_dynamic_name(const hpack_dynamic_name_state_t *state,
                                                           u32 index,
                                                           u16 *name_size,
                                                           u8 *classification) {
    const u32 dynamic_index = index - k_hpack_static_table_size;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    if (state->valid != 1 || state->entry_count > k_hpack_max_tracked_dynamic_entries ||
        state->head > k_hpack_dynamic_entry_mask ||
        state->max_table_size > k_hpack_default_dynamic_table_size || !dynamic_index ||
        dynamic_index > state->entry_count || dynamic_index > k_hpack_max_tracked_dynamic_entries) {
        return 0;
    }
#else
    if (!hpack_dynamic_name_state_bounds_valid(state) || !dynamic_index ||
        dynamic_index > state->entry_count ||
        dynamic_index > k_hpack_max_cache_free_dynamic_entries) {
        return 0;
    }
#endif
    u32 head = state->head;

    u32 slot = head + dynamic_index - 1;
    slot &= k_hpack_dynamic_entry_mask;
    const hpack_dynamic_entry_t *dynamic_entry = &state->entries[slot];
    const u32 entry = hpack_dynamic_entry_encoded(dynamic_entry);
    const u32 entry_size = hpack_dynamic_entry_size(entry);
    const u32 decoded_name_size = hpack_dynamic_name_size(entry);
    if (entry_size < k_hpack_dynamic_entry_overhead ||
        hpack_dynamic_entry_classification(entry) > k_hpack_name_non_traceparent ||
        decoded_name_size > entry_size - k_hpack_dynamic_entry_overhead) {
        return 0;
    }
#if !OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    // The injector remembers only entries inserted in this bounded block. An
    // entry is still active exactly when it and every newer insertion fit the
    // peer's current table limit. Older/pre-block entries remain unresolved.
    const u32 cumulative_size = state->cumulative_size;
    const u32 cumulative_start = dynamic_entry->cumulative_start;
    if (cumulative_start > cumulative_size ||
        cumulative_size - cumulative_start > state->max_table_size) {
        return 0;
    }
#endif

    if (name_size) {
        *name_size = decoded_name_size;
    }
    if (classification) {
        *classification = hpack_dynamic_entry_classification(entry);
    }
    return 1;
}

static __always_inline u8 hpack_classify_dynamic_name(const hpack_dynamic_name_state_t *state,
                                                      u32 index) {
    u8 classification = k_hpack_name_unknown;
    return hpack_lookup_dynamic_name(state, index, NULL, &classification) ? classification
                                                                          : k_hpack_name_unknown;
}

static __always_inline u8 hpack_lookup_dynamic_traceparent(
    const hpack_dynamic_name_state_t *state, u32 index, hpack_cached_traceparent_t *traceparent) {
    u8 classification = k_hpack_name_unknown;
    if (!traceparent || !hpack_lookup_dynamic_name(state, index, NULL, &classification) ||
        classification != k_hpack_name_traceparent) {
        return 0;
    }
    const u32 dynamic_index = index - k_hpack_static_table_size;
    u32 entry_slot = state->head + dynamic_index - 1;
    entry_slot &= k_hpack_dynamic_entry_mask;
    const u8 cache_slot = state->entries[entry_slot].traceparent_slot;
    if (!cache_slot || cache_slot > k_hpack_max_cached_traceparents) {
        return 0;
    }
    const u32 cache_index = cache_slot - 1;
    if (!(state->traceparent_slots_used & (1ULL << cache_index))) {
        return 0;
    }
    u32 bounded = cache_index;
    bpf_clamp_umax(bounded, k_hpack_max_cached_traceparents - 1);
    const hpack_cached_traceparent_t *cached = &state->traceparents[bounded];
    if (cached->owner_entry_slot != entry_slot + 1 ||
        cached->owner_generation != state->entries[entry_slot].generation) {
        return 0;
    }
    *traceparent = *cached;
    return 1;
}

static __always_inline u8 hpack_dynamic_entry_is_active(const hpack_dynamic_name_state_t *state,
                                                        u32 entry_slot) {
    if (entry_slot >= k_hpack_max_tracked_dynamic_entries) {
        return 0;
    }
    // Active entries occupy the circular interval beginning at head. Slots
    // outside it can contain stale generations and cache references left by a
    // table clear, and must never be treated as owners.
    const u32 distance = (entry_slot - state->head) & k_hpack_dynamic_entry_mask;
    return distance < state->entry_count;
}

// Returns 1 when the insertion is still present and cached, 2 when it was
// evicted later in the same bounded block, and 0 when authority cannot be
// retained (notably cache exhaustion).
static __always_inline u8 hpack_dynamic_store_traceparent(hpack_dynamic_name_state_t *state,
                                                          u8 entry_slot,
                                                          u8 entry_generation,
                                                          const tp_info_t *traceparent) {
    if (!state || !traceparent) {
        return 0;
    }
    if (!hpack_dynamic_entry_is_active(state, entry_slot)) {
        return 2;
    }
    u32 bounded_entry = entry_slot;
    bpf_clamp_umax(bounded_entry, k_hpack_max_tracked_dynamic_entries - 1);
    hpack_dynamic_entry_t *entry = &state->entries[bounded_entry];
    if (entry->generation != entry_generation ||
        hpack_dynamic_entry_classification(entry->encoded) != k_hpack_name_traceparent) {
        return 2;
    }
    if (entry->traceparent_slot) {
        return 0;
    }

#pragma clang loop unroll(disable)
    for (u8 i = 0; i < k_hpack_max_cached_traceparents; i++) {
        const u64 mask = 1ULL << i;
        if (state->traceparent_slots_used & mask) {
            u32 cache_index = i;
            bpf_clamp_umax(cache_index, k_hpack_max_cached_traceparents - 1);
            const hpack_cached_traceparent_t *cached = &state->traceparents[cache_index];
            const u8 owner_slot = cached->owner_entry_slot;
            if (owner_slot) {
                const u32 owner_entry_slot = owner_slot - 1;
                if (hpack_dynamic_entry_is_active(state, owner_entry_slot)) {
                    u32 bounded_owner = owner_entry_slot;
                    bpf_clamp_umax(bounded_owner, k_hpack_max_tracked_dynamic_entries - 1);
                    const hpack_dynamic_entry_t *owner = &state->entries[bounded_owner];
                    if (owner->generation == cached->owner_generation &&
                        owner->traceparent_slot == i + 1) {
                        continue;
                    }
                }
            }
            state->traceparent_slots_used &= ~mask;
        }
        u32 cache_index = i;
        bpf_clamp_umax(cache_index, k_hpack_max_cached_traceparents - 1);
        __builtin_memcpy(
            state->traceparents[cache_index].trace_id, traceparent->trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(
            state->traceparents[cache_index].parent_id, traceparent->parent_id, SPAN_ID_SIZE_BYTES);
        state->traceparents[cache_index].flags = traceparent->flags;
        state->traceparents[cache_index].owner_entry_slot = bounded_entry + 1;
        state->traceparents[cache_index].owner_generation = entry_generation;
        state->traceparent_slots_used |= mask;
        entry->traceparent_slot = i + 1;
        return 1;
    }
    return 0;
}

static __always_inline u16
hpack_dynamic_suffix_size_unchecked(const hpack_dynamic_name_state_t *state, u32 entry_count) {
    u32 slot = state->head + entry_count - 1;
    slot &= k_hpack_dynamic_entry_mask;
    return (u16)(state->cumulative_size - state->entries[slot].cumulative_start);
}

static __always_inline u16 hpack_dynamic_suffix_size(const hpack_dynamic_name_state_t *state,
                                                     u32 entry_count) {
    return entry_count && entry_count <= k_hpack_max_tracked_dynamic_entries
               ? hpack_dynamic_suffix_size_unchecked(state, entry_count)
               : 0;
}

#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
static __noinline u8 hpack_dynamic_evict_to(hpack_dynamic_name_state_t *state, u32 target_size) {
    u32 entry_count = state->entry_count;
    u32 table_size = state->table_size;
    if (target_size > k_hpack_default_dynamic_table_size ||
        entry_count > k_hpack_max_tracked_dynamic_entries ||
        table_size > k_hpack_default_dynamic_table_size) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
    // Preserve the checked u32 bound in the register consumed below. Older
    // verifiers otherwise retain the caller's sign-extended scalar metadata
    // across this subprogram boundary even though the guard proved the low
    // 32 bits are within the HPACK table limit.
    bpf_clamp_umax(target_size, k_hpack_default_dynamic_table_size);
    if (table_size <= target_size) {
        return 1;
    }
    if (!entry_count || hpack_dynamic_suffix_size(state, entry_count) != table_size) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }

    // Active entry sizes total at most 4096 bytes, so cumulative u16
    // subtraction is exact even across wrap. Seven bounded probes find the
    // largest newest prefix that fits. Every candidate is in 1..127, so its
    // ring read is always memory-safe; arithmetic masks prevent candidates
    // beyond entry_count from winning. The empty assembly barriers keep LLVM
    // from turning the underflow masks back into verifier-splitting branches.
    u32 retained_count = 0;
#pragma clang loop unroll(full)
    for (u32 probe = k_hpack_max_tracked_dynamic_entries / 2; probe; probe >>= 1) {
        const u32 candidate = retained_count + probe;
        u32 suffix_size = hpack_dynamic_suffix_size_unchecked(state, candidate);
        u32 count_difference = entry_count - candidate;
        u32 size_difference = target_size - suffix_size;
        asm volatile("" : "+r"(count_difference));
        asm volatile("" : "+r"(size_difference));
        count_difference >>= 31;
        size_difference >>= 31;
        asm volatile("" : "+r"(count_difference));
        asm volatile("" : "+r"(size_difference));
        u32 count_ok = count_difference ^ 1U;
        u32 size_ok = size_difference ^ 1U;
        asm volatile("" : "+r"(count_ok));
        asm volatile("" : "+r"(size_ok));
        retained_count += probe * (count_ok & size_ok);
    }

    u32 retained_size = hpack_dynamic_suffix_size(state, retained_count);
    if (retained_size > target_size || retained_size > table_size ||
        (retained_count < entry_count &&
         hpack_dynamic_suffix_size(state, retained_count + 1) <= target_size)) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }

    state->entry_count = retained_count;
    state->table_size = retained_size;
    return 1;
}
#endif

#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
static __always_inline u8 hpack_dynamic_table_resize(hpack_dynamic_name_state_t *state,
                                                     u32 max_table_size) {
    if (max_table_size > k_hpack_default_dynamic_table_size) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
    if (!state->valid) {
        if (max_table_size) {
            return 0;
        }
        hpack_dynamic_name_state_clear(state);
        state->valid = 1;
    }

    state->max_table_size = max_table_size;
    return hpack_dynamic_evict_to(state, max_table_size);
}
#endif

static OBI_HPACK_CACHE_HELPER u8 hpack_dynamic_insert(hpack_dynamic_name_state_t *state,
                                                      u32 name_size,
                                                      u32 value_size,
                                                      u8 classification,
                                                      u8 *inserted_slot,
                                                      u8 *inserted_generation) {
    if (!state->valid || name_size > k_hpack_dynamic_name_size_mask ||
        value_size > ~(u32)0 - name_size - k_hpack_dynamic_entry_overhead) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
    const u32 entry_size = name_size + value_size + k_hpack_dynamic_entry_overhead;
    u32 max_table_size = state->max_table_size;
    if (max_table_size > k_hpack_default_dynamic_table_size) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
    if (entry_size > max_table_size) {
        hpack_dynamic_name_state_clear(state);
        return 1;
    }
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    if (!hpack_dynamic_evict_to(state, max_table_size - entry_size) ||
        state->entry_count >= k_hpack_max_tracked_dynamic_entries) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
#else
    // A complete block can contain at most 123 insertions. Keep append-only
    // history for this block and decide eviction lazily at lookup time; this
    // avoids verifier-expensive random ring probes on every insertion.
    if (state->entry_count >= k_hpack_max_cache_free_dynamic_entries ||
        state->cumulative_size > k_hpack_max_cache_free_cumulative_size ||
        entry_size > k_hpack_max_cache_free_cumulative_size - state->cumulative_size) {
        hpack_dynamic_name_state_invalidate(state);
        return 0;
    }
#endif
    state->head = (state->head - 1) & k_hpack_dynamic_entry_mask;
    // entry_count is strictly below the ring capacity, so the new head is an
    // inactive slot. Do not release its stale cache reference: after a table
    // clear that reference can name a slot now owned by another live entry.
    state->entries[state->head].encoded =
        hpack_dynamic_entry_pack(entry_size, name_size, classification);
    state->entries[state->head].cumulative_start = state->cumulative_size;
    state->cumulative_size += entry_size;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    state->next_generation++;
    state->entries[state->head].generation = state->next_generation;
    state->entries[state->head].traceparent_slot = 0;
    if (inserted_slot) {
        *inserted_slot = state->head;
    }
    if (inserted_generation) {
        *inserted_generation = state->next_generation;
    }
#else
    (void)inserted_slot;
    (void)inserted_generation;
#endif
    state->entry_count++;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    state->table_size += entry_size;
#endif
    return 1;
}

enum hpack_traceparent_scan_phase : u8 {
    k_hpack_scan_field,
    k_hpack_scan_name_string,
    k_hpack_scan_value_string,
    k_hpack_scan_name_huffman,
    k_hpack_scan_value_huffman,
    k_hpack_scan_integer_indexed,
    k_hpack_scan_integer_table_size,
    k_hpack_scan_integer_name_index,
    k_hpack_scan_integer_name_length,
    k_hpack_scan_integer_value_length,
};

enum hpack_traceparent_integer_target : u8 {
    k_hpack_integer_indexed,
    k_hpack_integer_table_size,
    k_hpack_integer_name_index,
    k_hpack_integer_name_length,
    k_hpack_integer_value_length,
};

typedef struct hpack_traceparent_scan_state {
    u32 integer_value;
    u16 pending_name_size;
    u16 pending_string_decoded_size;
    u8 pos;
    u8 data_len;
    u8 phase;
    u8 integer_shift;
    u8 pending_representation;
    u8 pending_name_classification;
    u8 pending_name_size_known;
    u8 pending_huffman;
    u8 pending_string_start;
    u8 pending_string_end;
    u8 pending_huffman_state;
    u8 table_size_updates;
    u8 complete;
    u8 unknown;
    u8 dynamic_invalid;
    u8 saw_header;
    u8 traceparent_fields;
    u8 done;
    u8 status;
    u8 value_offset;
    u8 encoded_value_len;
    u8 value_huffman;
    u8 representation;
    unsigned char cached_trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char cached_parent_id[SPAN_ID_SIZE_BYTES];
    u8 value_cached;
    u8 cached_flags;
    u8 inserted_slot;
    u8 inserted_generation;
    u8 inserted_identity_valid;
    u8 value_cache_unavailable;
    u8 _pad[7];
} hpack_traceparent_scan_state_t;

static __noinline u16 hpack_huffman_count_byte(u8 byte, u8 huffman_state);
static __noinline u8 hpack_huffman_state_accepts(u8 huffman_state);

enum {
    k_hpack_huffman_step_valid = 0x8000,
    k_hpack_huffman_step_count_shift = 8,
    // An encoded byte can finish at most two symbols: after completing a
    // partial code, the seven remaining bits contain at most one five-bit
    // HPACK code. Keep that exact bound visible to the BPF verifier.
    k_hpack_huffman_step_count_mask = 0x03,
};

static __always_inline u8 hpack_traceparent_scan_fail(hpack_traceparent_scan_state_t *state) {
    state->status = k_hpack_traceparent_unknown;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    state->dynamic_invalid = 1;
#endif
    state->done = 1;
    return 1;
}

static __always_inline u8
hpack_traceparent_scan_unknown_fail(hpack_traceparent_scan_state_t *state) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    state->unknown = 1;
#endif
    return hpack_traceparent_scan_fail(state);
}

static __always_inline u8 hpack_traceparent_scan_finish(hpack_traceparent_scan_state_t *state) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    if (!state->complete || state->unknown || state->traceparent_fields > 1) {
        state->status = k_hpack_traceparent_unknown;
    } else if (state->traceparent_fields == 1) {
        state->status = k_hpack_traceparent_found;
    } else {
        state->status = k_hpack_traceparent_absent;
    }
    if (!state->complete) {
        state->dynamic_invalid = 1;
    }
#else
    state->status =
        state->traceparent_fields == 1 ? k_hpack_traceparent_found : k_hpack_traceparent_absent;
#endif
    state->done = 1;
    return 1;
}

static __always_inline void
hpack_traceparent_scan_init(hpack_traceparent_scan_state_t *state, u32 data_len, u8 complete) {
    __builtin_memset(state, 0, sizeof(*state));
    if (data_len > k_hpack_tp_max_scan) {
        hpack_traceparent_scan_fail(state);
        return;
    }

    state->data_len = data_len;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    state->complete = complete;
#else
    (void)complete;
#endif
}

static __always_inline hpack_traceparent_result_t
hpack_traceparent_scan_result(const hpack_traceparent_scan_state_t *state) {
    hpack_traceparent_result_t result = {
        .value_offset = state->value_offset,
        .encoded_value_len = state->encoded_value_len,
        .status = state->status,
        .value_huffman = state->value_huffman,
        .representation = state->representation,
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        .value_cached = state->value_cached,
        .cached_flags = state->cached_flags,
        .inserted_slot = state->inserted_slot,
        .inserted_generation = state->inserted_generation,
        .inserted_identity_valid = state->inserted_identity_valid,
        .value_cache_unavailable = state->value_cache_unavailable,
#endif
    };
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    __builtin_memcpy(result.cached_trace_id, state->cached_trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(result.cached_parent_id, state->cached_parent_id, SPAN_ID_SIZE_BYTES);
#endif
    return result;
}

static __always_inline u8
hpack_traceparent_scan_complete_field(hpack_traceparent_scan_state_t *state) {
    state->saw_header = 1;
    state->phase = k_hpack_scan_field;
    if (state->pos == state->data_len) {
        return hpack_traceparent_scan_finish(state);
    }
    return 0;
}

static __always_inline u8
hpack_traceparent_scan_complete_value(hpack_traceparent_scan_state_t *state,
                                      hpack_dynamic_name_state_t *dynamic_names,
                                      u32 value_offset,
                                      u32 encoded_value_len,
                                      u16 decoded_value_size) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    u8 inserted_slot = 0xff;
    u8 inserted_generation = 0;
    if (state->pending_representation == k_hpack_representation_incremental) {
        if (!state->pending_name_size_known ||
            !hpack_dynamic_insert(dynamic_names,
                                  state->pending_name_size,
                                  decoded_value_size,
                                  state->pending_name_classification,
                                  &inserted_slot,
                                  &inserted_generation)) {
            state->unknown = 1;
        }
    }
#else
    if (state->pending_representation == k_hpack_representation_incremental &&
        (!state->pending_name_size_known ||
         !hpack_dynamic_insert(dynamic_names,
                               state->pending_name_size,
                               decoded_value_size,
                               state->pending_name_classification,
                               NULL,
                               NULL))) {
        return hpack_traceparent_scan_unknown_fail(state);
    }
#endif
    if (state->pending_name_classification == k_hpack_name_unknown) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        state->unknown = 1;
#else
        return hpack_traceparent_scan_unknown_fail(state);
#endif
    } else if (state->pending_name_classification == k_hpack_name_traceparent) {
        state->traceparent_fields++;
#if !OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        if (state->traceparent_fields > 1) {
            return hpack_traceparent_scan_unknown_fail(state);
        }
#endif
        if (state->traceparent_fields == 1) {
            state->value_offset = value_offset;
            state->encoded_value_len = encoded_value_len;
            state->value_huffman = !!state->pending_huffman;
            state->representation = state->pending_representation;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
            if (state->pending_representation == k_hpack_representation_incremental &&
                inserted_slot != 0xff) {
                state->inserted_slot = inserted_slot;
                state->inserted_generation = inserted_generation;
                state->inserted_identity_valid = 1;
            }
#endif
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        } else if (state->pending_representation == k_hpack_representation_incremental &&
                   inserted_slot != 0xff) {
            // Only one value is decoded by the bounded server path. If a
            // second traceparent was inserted, later indexed lookup must
            // not silently use an incomplete cache.
            state->value_cache_unavailable = 1;
#endif
        }
    }

    return hpack_traceparent_scan_complete_field(state);
}

static __always_inline u8
hpack_traceparent_scan_complete_integer(const unsigned char *data,
                                        hpack_traceparent_scan_state_t *state,
                                        hpack_dynamic_name_state_t *dynamic_names,
                                        u8 target,
                                        u32 value) {
    switch (target) {
    case k_hpack_integer_indexed:
        if (!value) {
            return hpack_traceparent_scan_fail(state);
        }
        if (value > k_hpack_static_table_size) {
            const u8 classification = hpack_classify_dynamic_name(dynamic_names, value);
            if (classification == k_hpack_name_unknown) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
                state->unknown = 1;
                state->dynamic_invalid = 1;
#else
                return hpack_traceparent_scan_unknown_fail(state);
#endif
            } else if (classification == k_hpack_name_traceparent) {
                state->traceparent_fields++;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
                hpack_cached_traceparent_t cached = {};
                if (!hpack_lookup_dynamic_traceparent(dynamic_names, value, &cached)) {
                    state->unknown = 1;
                    state->dynamic_invalid = 1;
                } else if (state->traceparent_fields == 1) {
                    __builtin_memcpy(state->cached_trace_id, cached.trace_id, TRACE_ID_SIZE_BYTES);
                    __builtin_memcpy(state->cached_parent_id, cached.parent_id, SPAN_ID_SIZE_BYTES);
                    state->cached_flags = cached.flags;
                    state->value_cached = 1;
                    state->representation = k_hpack_representation_indexed;
                }
#else
                // The packet injector creates a fresh mirror for each block
                // and never fills the decoded-value cache. A dynamic indexed
                // traceparent therefore has no authoritative value there.
                return hpack_traceparent_scan_unknown_fail(state);
#endif
            }
        }
        return hpack_traceparent_scan_complete_field(state);
    case k_hpack_integer_table_size:
        state->table_size_updates++;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        if (state->table_size_updates > 2 || !hpack_dynamic_table_resize(dynamic_names, value)) {
            state->unknown = 1;
        }
#else
        // The injector creates an empty mirror for this complete block, and
        // RFC 7541 permits size updates only before the first header field.
        // Therefore no accepted update can evict an entry in this mode.
        if (state->table_size_updates > 2 || value > k_hpack_default_dynamic_table_size) {
            hpack_traceparent_scan_unknown_fail(state);
            hpack_dynamic_name_state_invalidate(dynamic_names);
            return 1;
        }
        dynamic_names->max_table_size = value;
#endif
        state->phase = k_hpack_scan_field;
        if (state->pos == state->data_len) {
            return hpack_traceparent_scan_finish(state);
        }
        return 0;
    case k_hpack_integer_name_index:
        if (!value) {
            state->phase = k_hpack_scan_name_string;
            return 0;
        }
        state->pending_name_classification = k_hpack_name_non_traceparent;
        state->pending_name_size_known = 1;
        if (value > k_hpack_static_table_size) {
            state->pending_name_classification = k_hpack_name_unknown;
            state->pending_name_size_known =
                hpack_lookup_dynamic_name(dynamic_names,
                                          value,
                                          &state->pending_name_size,
                                          &state->pending_name_classification);
            if (!state->pending_name_size_known) {
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
                state->dynamic_invalid = 1;
#else
                return hpack_traceparent_scan_unknown_fail(state);
#endif
            }
        } else {
            // The branch above proves value is a valid 0..61 static index.
            // A padded power-of-two table and identity mask preserve that
            // value while making the access bound branch-free for old
            // verifiers that forget the comparison's scalar correlation.
            u32 static_index = value;
            asm volatile("" : "+r"(static_index));
            static_index &= 63;
            state->pending_name_size = k_hpack_static_name_lengths[static_index];
        }
        state->phase = k_hpack_scan_value_string;
        return 0;
    case k_hpack_integer_name_length: {
        const u32 pos = state->pos;
        const u32 data_len = state->data_len;
        if (pos > data_len || value > data_len - pos) {
            return hpack_traceparent_scan_fail(state);
        }
        const u32 next = pos + value;
        const u8 pending_huffman = state->pending_huffman;
        if (pending_huffman) {
            state->pending_name_classification =
                value == k_hpack_tp_name_huffman_len && hpack_is_traceparent_huffman_name(data, pos)
                    ? k_hpack_name_traceparent
                    : k_hpack_name_non_traceparent;
            if (!value) {
                state->pending_name_size = 0;
                state->pending_name_size_known = 1;
                state->phase = k_hpack_scan_value_string;
                return 0;
            }

            state->pending_string_decoded_size = 0;
            state->pending_string_start = pos;
            state->pending_string_end = next;
            state->pending_huffman_state = 0;
            state->phase = k_hpack_scan_name_huffman;
            return 0;
        }

        state->pending_name_classification =
            value == k_hpack_tp_name_len && hpack_is_traceparent_raw_name(data, pos)
                ? k_hpack_name_traceparent
                : k_hpack_name_non_traceparent;
        state->pending_name_size = value;
        state->pending_name_size_known = 1;
        state->pos = next;
        state->phase = k_hpack_scan_value_string;
        return 0;
    }
    case k_hpack_integer_value_length: {
        const u32 pos = state->pos;
        const u32 data_len = state->data_len;
        if (pos > data_len || value > data_len - pos) {
            return hpack_traceparent_scan_fail(state);
        }
        const u32 next = pos + value;

        if (!state->pending_huffman || !value) {
            state->pos = next;
            const u32 value_offset = pos;
            const u32 encoded_value_len = value;
            const u16 decoded_value_size = (u16)value;
            return hpack_traceparent_scan_complete_value(
                state, dynamic_names, value_offset, encoded_value_len, decoded_value_size);
        }

        state->pending_string_decoded_size = 0;
        state->pending_string_start = pos;
        state->pending_string_end = next;
        state->pending_huffman_state = 0;
        state->phase = k_hpack_scan_value_huffman;
        return 0;
    }
    default:
        return hpack_traceparent_scan_fail(state);
    }
}

static __always_inline u8
hpack_traceparent_scan_start_integer(const unsigned char *data,
                                     hpack_traceparent_scan_state_t *state,
                                     hpack_dynamic_name_state_t *dynamic_names,
                                     u8 first,
                                     u8 prefix_bits,
                                     u8 target) {
    const u32 prefix_max = (1U << prefix_bits) - 1;
    const u32 value = first & prefix_max;

    if (value < prefix_max) {
        return hpack_traceparent_scan_complete_integer(data, state, dynamic_names, target, value);
    }

    state->integer_value = value;
    state->integer_shift = 0;
    state->phase = k_hpack_scan_integer_indexed + target;
    return 0;
}

static OBI_HPACK_CACHE_HELPER u8
hpack_traceparent_scan_step(const unsigned char *data,
                            hpack_traceparent_scan_state_t *state,
                            hpack_dynamic_name_state_t *dynamic_names) {
    if (!data || !state || !dynamic_names
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        || state->done
#endif
    ) {
        return 1;
    }
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    // Persistent mirrors are map-backed, so reassert the compact RFC/ring
    // invariants that older verifiers forget across rolled-loop iterations.
    // The cache-free injector initializes a private mirror immediately before
    // this bounded scan and never exposes it across program invocations.
    if (!hpack_dynamic_name_state_bounds_valid(dynamic_names)) {
        hpack_traceparent_scan_fail(state);
        hpack_dynamic_name_state_invalidate(dynamic_names);
        return 1;
    }
#endif

    u32 pos = state->pos;
    const u32 data_len = state->data_len;
    // The state lives in map-backed scratch memory, so older verifiers lose
    // the bound established by hpack_traceparent_scan_init between calls. Make
    // it explicit here: otherwise they can invent data_len values above the
    // scan limit while pos is clamped at the limit and explore a non-progress
    // loop. Such a state is corrupt and must revoke the dynamic-table mirror.
    if (data_len > k_hpack_tp_max_scan) {
        hpack_traceparent_scan_fail(state);
        hpack_dynamic_name_state_invalidate(dynamic_names);
        return 1;
    }
    if (pos >= data_len) {
        if (pos == data_len && state->phase == k_hpack_scan_field) {
            hpack_traceparent_scan_finish(state);
        } else {
            hpack_traceparent_scan_fail(state);
        }
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
        if (state->dynamic_invalid) {
            hpack_dynamic_name_state_invalidate(dynamic_names);
        }
#endif
        return 1;
    }

    u32 data_pos = pos;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
#endif
    const u8 byte = data[data_pos];
    pos++;
#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    bpf_clamp_umax(pos, k_hpack_tp_max_scan);
#endif
    state->pos = pos;

    u8 done = 0;
    const u32 phase = state->phase;
    if (phase > k_hpack_scan_integer_value_length) {
        return hpack_traceparent_scan_fail(state);
    }
    switch (phase) {
    case k_hpack_scan_field:
        if (byte & 0x80) {
            done = hpack_traceparent_scan_start_integer(
                data, state, dynamic_names, byte, 7, k_hpack_integer_indexed);
            break;
        }

        state->pending_representation = k_hpack_representation_without_indexing;
        state->pending_name_classification = k_hpack_name_unknown;
        state->pending_name_size = 0;
        state->pending_name_size_known = 0;
        u8 prefix_bits = 4;
        if (byte & 0x40) {
            prefix_bits = 6;
            state->pending_representation = k_hpack_representation_incremental;
        } else if (byte & 0x20) {
            if (state->saw_header) {
                done = hpack_traceparent_scan_fail(state);
                break;
            }
            done = hpack_traceparent_scan_start_integer(
                data, state, dynamic_names, byte, 5, k_hpack_integer_table_size);
            break;
        } else if (byte & 0x10) {
            state->pending_representation = k_hpack_representation_never_indexed;
        }
        done = hpack_traceparent_scan_start_integer(
            data, state, dynamic_names, byte, prefix_bits, k_hpack_integer_name_index);
        break;
    case k_hpack_scan_integer_indexed:
    case k_hpack_scan_integer_table_size:
    case k_hpack_scan_integer_name_index:
    case k_hpack_scan_integer_name_length:
    case k_hpack_scan_integer_value_length: {
        const u8 target = state->phase - k_hpack_scan_integer_indexed;
        const u32 chunk = byte & 0x7f;
        const u8 shift = state->integer_shift;
        if ((shift == 28 && chunk > 0x0f) || shift > 28) {
            done = hpack_traceparent_scan_fail(state);
            break;
        }
        const u32 increment = chunk << shift;
        if (increment > ~(u32)0 - state->integer_value) {
            done = hpack_traceparent_scan_fail(state);
            break;
        }
        state->integer_value += increment;
        if (byte & 0x80) {
            if (shift == 28) {
                done = hpack_traceparent_scan_fail(state);
            } else {
                state->integer_shift = shift + 7;
            }
            break;
        }
        done = hpack_traceparent_scan_complete_integer(
            data, state, dynamic_names, target, state->integer_value);
        break;
    }
    case k_hpack_scan_name_string:
        state->pending_huffman = !!(byte & 0x80);
        done = hpack_traceparent_scan_start_integer(
            data, state, dynamic_names, byte, 7, k_hpack_integer_name_length);
        break;
    case k_hpack_scan_value_string:
        state->pending_huffman = !!(byte & 0x80);
        done = hpack_traceparent_scan_start_integer(
            data, state, dynamic_names, byte, 7, k_hpack_integer_value_length);
        break;
    case k_hpack_scan_name_huffman:
    case k_hpack_scan_value_huffman: {
        const u8 phase = state->phase;
        const u16 decoded = hpack_huffman_count_byte(byte, state->pending_huffman_state);
        if (!(decoded & k_hpack_huffman_step_valid)) {
            done = hpack_traceparent_scan_fail(state);
            break;
        }
        state->pending_huffman_state = decoded & 0xff;
        state->pending_string_decoded_size +=
            (decoded >> k_hpack_huffman_step_count_shift) & k_hpack_huffman_step_count_mask;

        if (state->pos > state->pending_string_end) {
            done = hpack_traceparent_scan_fail(state);
            break;
        }
        if (state->pos != state->pending_string_end) {
            break;
        }
        if (!hpack_huffman_state_accepts(state->pending_huffman_state)) {
            done = hpack_traceparent_scan_fail(state);
            break;
        }

        if (phase == k_hpack_scan_name_huffman) {
            state->pending_name_size = state->pending_string_decoded_size;
            state->pending_name_size_known = 1;
            state->phase = k_hpack_scan_value_string;
            break;
        }

        done = hpack_traceparent_scan_complete_value(state,
                                                     dynamic_names,
                                                     state->pending_string_start,
                                                     state->pending_string_end -
                                                         state->pending_string_start,
                                                     state->pending_string_decoded_size);
        break;
    }
    default:
        done = hpack_traceparent_scan_fail(state);
    }

#if OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE
    if (state->dynamic_invalid) {
        // No later field can make an unresolved dynamic-table reference
        // authoritative again. Every caller treats this block as unknown and
        // discards the mirror, so terminate immediately instead of carrying
        // invalid map-backed state through the remaining bounded scan.
        done = hpack_traceparent_scan_fail(state);
        hpack_dynamic_name_state_invalidate(dynamic_names);
    }
#endif
    return done;
}

// Generated from the RFC 7541 Appendix B code table. Internal states occupy
// 0x0000..0x00ff, emitted octets have bit 15 set, and 0xffff is invalid.
// A bitwise DFA keeps verifier-visible bounds small and avoids pointer-based
// trees or unbounded code-length searches.
static const u16 k_hpack_huffman_transitions[512] = {
    0x0042, 0x0001, 0x005d, 0x0002, 0x0068, 0x0003, 0x0077, 0x0004, 0x0090, 0x0005, 0x004b, 0x0006,
    0x007b, 0x0007, 0x0047, 0x0008, 0x004d, 0x0009, 0x0049, 0x000a, 0x000b, 0x000d, 0x000c, 0x0066,
    0x8000, 0x8024, 0x007f, 0x000e, 0x0080, 0x000f, 0x0062, 0x0010, 0x807b, 0x0011, 0x007c, 0x0012,
    0x0096, 0x0013, 0x0014, 0x0019, 0x00c7, 0x0015, 0x00d8, 0x0016, 0x0017, 0x00a2, 0x0018, 0x00a1,
    0x8001, 0x8087, 0x00a7, 0x001a, 0x0029, 0x001b, 0x00bf, 0x001c, 0x00d3, 0x001d, 0x00e5, 0x001e,
    0x001f, 0x002d, 0x0020, 0x0026, 0x0021, 0x0023, 0x80fe, 0x0022, 0x8002, 0x8003, 0x0024, 0x0025,
    0x8004, 0x8005, 0x8006, 0x8007, 0x0027, 0x0034, 0x0028, 0x0033, 0x8008, 0x800b, 0x00d0, 0x002a,
    0x002b, 0x00a5, 0x80ef, 0x002c, 0x8009, 0x808e, 0x0037, 0x002e, 0x003f, 0x002f, 0x0093, 0x0030,
    0x80f9, 0x0031, 0x0032, 0x003b, 0x800a, 0x800d, 0x800c, 0x800e, 0x0035, 0x0036, 0x800f, 0x8010,
    0x8011, 0x8012, 0x0038, 0x003c, 0x0039, 0x003a, 0x8013, 0x8014, 0x8015, 0x8017, 0x8016, 0xffff,
    0x003d, 0x003e, 0x8018, 0x8019, 0x801a, 0x801b, 0x0040, 0x0041, 0x801c, 0x801d, 0x801e, 0x801f,
    0x0055, 0x0043, 0x0044, 0x0052, 0x008f, 0x0045, 0x0046, 0x0051, 0x8020, 0x8025, 0x0048, 0x004f,
    0x8021, 0x8022, 0x807c, 0x004a, 0x8023, 0x803e, 0x004c, 0x0050, 0x8026, 0x802a, 0x803f, 0x004e,
    0x8027, 0x802b, 0x8028, 0x8029, 0x802c, 0x803b, 0x802d, 0x802e, 0x0053, 0x005a, 0x0054, 0x0059,
    0x802f, 0x8033, 0x0056, 0x0082, 0x0057, 0x0058, 0x8030, 0x8031, 0x8032, 0x8061, 0x8034, 0x8035,
    0x005b, 0x005c, 0x8036, 0x8037, 0x8038, 0x8039, 0x0063, 0x005e, 0x008a, 0x005f, 0x008e, 0x0060,
    0x0061, 0x0067, 0x803a, 0x8042, 0x803c, 0x8060, 0x0064, 0x0084, 0x0065, 0x0081, 0x803d, 0x8041,
    0x8040, 0x805b, 0x8043, 0x8044, 0x0069, 0x0070, 0x006a, 0x006d, 0x006b, 0x006c, 0x8045, 0x8046,
    0x8047, 0x8048, 0x006e, 0x006f, 0x8049, 0x804a, 0x804b, 0x804c, 0x0071, 0x0074, 0x0072, 0x0073,
    0x804d, 0x804e, 0x804f, 0x8050, 0x0075, 0x0076, 0x8051, 0x8052, 0x8053, 0x8054, 0x0078, 0x0088,
    0x0079, 0x007a, 0x8055, 0x8056, 0x8057, 0x8059, 0x8058, 0x805a, 0x007d, 0x009b, 0x007e, 0x0094,
    0x805c, 0x80c3, 0x805d, 0x807e, 0x805e, 0x807d, 0x805f, 0x8062, 0x0083, 0x0087, 0x8063, 0x8065,
    0x0085, 0x0086, 0x8064, 0x8066, 0x8067, 0x8068, 0x8069, 0x806f, 0x0089, 0x008d, 0x806a, 0x806b,
    0x008b, 0x008c, 0x806c, 0x806d, 0x806e, 0x8070, 0x8071, 0x8076, 0x8072, 0x8075, 0x8073, 0x8074,
    0x0091, 0x0092, 0x8077, 0x8078, 0x8079, 0x807a, 0x807f, 0x80dc, 0x80d0, 0x0095, 0x8080, 0x8082,
    0x00c4, 0x0097, 0x0098, 0x00b2, 0x0099, 0x009e, 0x80e6, 0x009a, 0x8081, 0x8084, 0x009c, 0x00af,
    0x009d, 0x00cc, 0x8083, 0x80a2, 0x009f, 0x00a0, 0x8085, 0x8086, 0x8088, 0x8092, 0x8089, 0x808a,
    0x00a3, 0x00a4, 0x808b, 0x808c, 0x808d, 0x808f, 0x00a6, 0x00ab, 0x8090, 0x8091, 0x00a8, 0x00b9,
    0x00a9, 0x00ad, 0x00aa, 0x00ac, 0x8093, 0x8095, 0x8094, 0x809f, 0x8096, 0x8097, 0x00ae, 0x00b5,
    0x8098, 0x809b, 0x00f1, 0x00b0, 0x00b1, 0x00bc, 0x8099, 0x80a1, 0x00b3, 0x00b7, 0x00b4, 0x00b6,
    0x809a, 0x809c, 0x809d, 0x809e, 0x80a0, 0x80a3, 0x00b8, 0x00be, 0x80a4, 0x80a9, 0x00ba, 0x00c2,
    0x00bb, 0x00bd, 0x80a5, 0x80a6, 0x80a7, 0x80ac, 0x80a8, 0x80ae, 0x80aa, 0x80ad, 0x00c0, 0x00da,
    0x00c1, 0x00ea, 0x80ab, 0x80ce, 0x00c3, 0x00cb, 0x80af, 0x80b4, 0x00c5, 0x00eb, 0x00c6, 0x00ca,
    0x80b0, 0x80b1, 0x00c8, 0x00ce, 0x00c9, 0x00cd, 0x80b2, 0x80b5, 0x80b3, 0x80d1, 0x80b6, 0x80b7,
    0x80b8, 0x80c2, 0x80b9, 0x80ba, 0x00cf, 0x00d2, 0x80bb, 0x80bd, 0x00d1, 0x00d7, 0x80bc, 0x80bf,
    0x80be, 0x80c4, 0x00d4, 0x00e0, 0x00d5, 0x00de, 0x00d6, 0x00dd, 0x80c0, 0x80c1, 0x80c5, 0x80e7,
    0x00d9, 0x00f3, 0x80c6, 0x80e4, 0x00f5, 0x00db, 0x00dc, 0x00f4, 0x80c7, 0x80cf, 0x80c8, 0x80c9,
    0x00df, 0x00e4, 0x80ca, 0x80cd, 0x00ed, 0x00e1, 0x00f8, 0x00e2, 0x80ff, 0x00e3, 0x80cb, 0x80cc,
    0x80d2, 0x80d5, 0x00e6, 0x00f9, 0x00e7, 0x00ef, 0x00e8, 0x00e9, 0x80d3, 0x80d4, 0x80d6, 0x80dd,
    0x80d7, 0x80e1, 0x00ec, 0x00f2, 0x80d8, 0x80d9, 0x00ee, 0x00f6, 0x80da, 0x80db, 0x00f0, 0x00f7,
    0x80de, 0x80df, 0x80e0, 0x80e2, 0x80e3, 0x80e5, 0x80e8, 0x80e9, 0x80ea, 0x80eb, 0x80ec, 0x80ed,
    0x80ee, 0x80f0, 0x80f1, 0x80f4, 0x80f2, 0x80f3, 0x00fa, 0x00fd, 0x00fb, 0x00fc, 0x80f5, 0x80f6,
    0x80f7, 0x80f8, 0x00fe, 0x00ff, 0x80fa, 0x80fb, 0x80fc, 0x80fd,
};

// Four-bit closure of k_hpack_huffman_transitions for verifier-friendly
// decoded-size accounting. Valid entries encode the emitted-octet count in
// bits 14..8 and the next DFA state in bits 7..0; zero is an invalid poison
// transition whose state still makes the following nibble lookup safe.
static const u16 k_hpack_huffman_nibble_transitions[4096] = {
    0x8057, 0x8058, 0x8083, 0x8087, 0x808f, 0x8045, 0x8053, 0x805a, 0x8064, 0x8084, 0x808a, 0x805f,
    0x8069, 0x8070, 0x8077, 0x8004, 0x8065, 0x8081, 0x8085, 0x8086, 0x808b, 0x808c, 0x808e, 0x8060,
    0x806a, 0x806d, 0x8071, 0x8074, 0x8078, 0x8088, 0x8090, 0x8005, 0x806b, 0x806c, 0x806e, 0x806f,
    0x8072, 0x8073, 0x8075, 0x8076, 0x8079, 0x807a, 0x8089, 0x808d, 0x8091, 0x8092, 0x804b, 0x8006,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x804c, 0x8050, 0x807b, 0x8007, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8047, 0x8008, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8048, 0x804f, 0x804d, 0x8009,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x804e, 0x8049, 0x800a, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x804a, 0x800b, 0x800d, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x800c, 0x8066, 0x807f, 0x800e,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8080, 0x800f, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8062, 0x8010, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8011, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x807c, 0x8012,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x807d, 0x809b, 0x8096, 0x8013, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x807e, 0x8094, 0x809c, 0x80af, 0x80c4, 0x8097, 0x8014, 0x8019, 0x8100, 0x8100, 0x8100, 0x8095,
    0x809d, 0x80cc, 0x80f1, 0x80b0, 0x80c5, 0x80eb, 0x8098, 0x80b2, 0x80c7, 0x8015, 0x80a7, 0x801a,
    0x80c6, 0x80ca, 0x80ec, 0x80f2, 0x8099, 0x809e, 0x80b3, 0x80b7, 0x80c8, 0x80ce, 0x80d8, 0x8016,
    0x80a8, 0x80b9, 0x8029, 0x801b, 0x80c9, 0x80cd, 0x80cf, 0x80d2, 0x80d9, 0x80f3, 0x8017, 0x80a2,
    0x80a9, 0x80ad, 0x80ba, 0x80c2, 0x80d0, 0x802a, 0x80bf, 0x801c, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8018, 0x80a1, 0x80a3, 0x80a4,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x80aa, 0x80ac, 0x80ae, 0x80b5, 0x80bb, 0x80bd, 0x80c3, 0x80cb,
    0x80d1, 0x80d7, 0x802b, 0x80a5, 0x80c0, 0x80da, 0x80d3, 0x801d, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x802c, 0x80a6, 0x80ab, 0x80c1, 0x80ea, 0x80f5, 0x80db, 0x80d4, 0x80e0, 0x80e5, 0x801e,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x80dc, 0x80f4, 0x80d5, 0x80de, 0x80ed, 0x80e1,
    0x80e6, 0x80f9, 0x801f, 0x802d, 0x80d6, 0x80dd, 0x80df, 0x80e4, 0x80ee, 0x80f6, 0x80f8, 0x80e2,
    0x80e7, 0x80ef, 0x80fa, 0x80fd, 0x8020, 0x8026, 0x8037, 0x802e, 0x80e8, 0x80e9, 0x80f0, 0x80f7,
    0x80fb, 0x80fc, 0x80fe, 0x80ff, 0x8021, 0x8023, 0x8027, 0x8034, 0x8038, 0x803c, 0x803f, 0x802f,
    0x8100, 0x8022, 0x8024, 0x8025, 0x8028, 0x8033, 0x8035, 0x8036, 0x8039, 0x803a, 0x803d, 0x803e,
    0x8040, 0x8041, 0x8093, 0x8030, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8031, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8032, 0x803b, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8100, 0x8100, 0x8100, 0x0000,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x0000, 0x0000, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x0000, 0x0000, 0x0000, 0x0000, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8046, 0x8051,
    0x8054, 0x8059, 0x805b, 0x805c, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8061, 0x8067, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x80b1, 0x80bc, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x809a, 0x809f, 0x80a0,
    0x80b4, 0x80b6, 0x80b8, 0x80be, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x80e3, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8100, 0x8100,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100,
    0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8100, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101, 0x8142, 0x8101,
    0x8142, 0x8101, 0x8142, 0x8101, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102,
    0x8155, 0x8143, 0x815d, 0x8102, 0x8155, 0x8143, 0x815d, 0x8102, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103,
    0x8156, 0x8182, 0x8144, 0x8152, 0x8163, 0x815e, 0x8168, 0x8103, 0x8156, 0x8182, 0x8144, 0x8152,
    0x8163, 0x815e, 0x8168, 0x8103,
};

static __noinline u16 hpack_huffman_count_byte(u8 byte, u8 huffman_state) {
    const u16 high = k_hpack_huffman_nibble_transitions[((u16)huffman_state << 4) | (byte >> 4)];
    const u16 low = k_hpack_huffman_nibble_transitions[((high & 0xff) << 4) | (byte & 0x0f)];
    return ((high & low) & k_hpack_huffman_step_valid) | ((high & 0x0100) + (low & 0x0100)) |
           (low & 0xff);
}

static __noinline u8 hpack_huffman_state_accepts(u8 huffman_state) {
    // States 0..7 are the root and the one-to-seven-bit prefixes of EOS.
    return huffman_state < 8;
}

typedef struct hpack_traceparent_decode_state {
    u16 value_len;
    u8 version;
    u8 flags;
    u8 trace_nonzero;
    u8 span_nonzero;
    u8 valid_base;
    u8 extension_dash;
} hpack_traceparent_decode_state_t;

typedef struct hpack_traceparent_decoder_state {
    hpack_traceparent_decode_state_t value;
    u8 encoded_pos;
    u8 encoded_len;
    u8 huffman_state;
    u8 huffman;
    u8 parent_id;
    u8 done;
    u8 valid;
    u8 initialized;
} hpack_traceparent_decoder_state_t;

static __always_inline u8 hpack_lower_hex_value(u8 c, u8 *value) {
    if (c >= '0' && c <= '9') {
        *value = c - '0';
        return 1;
    }
    if (c >= 'a' && c <= 'f') {
        *value = c - 'a' + 10;
        return 1;
    }
    return 0;
}

static __always_inline void hpack_store_nibble(unsigned char *id, u32 pos, u8 nibble) {
    const u32 index = pos >> 1;
    if (index >= TRACE_ID_SIZE_BYTES) {
        return;
    }
    if (pos & 1) {
        id[index] |= nibble;
    } else {
        id[index] = nibble << 4;
    }
}

static __always_inline void hpack_store_span_nibble(unsigned char *id, u32 pos, u8 nibble) {
    const u32 index = pos >> 1;
    if (index >= SPAN_ID_SIZE_BYTES) {
        return;
    }
    if (pos & 1) {
        id[index] |= nibble;
    } else {
        id[index] = nibble << 4;
    }
}

static __always_inline void hpack_traceparent_consume(hpack_traceparent_decode_state_t *state,
                                                      tp_info_t *tp,
                                                      u8 parent_id,
                                                      u8 c) {
    u32 pos = state->value_len++;
    if (pos == k_hpack_value_len_tp) {
        state->extension_dash = c == '-';
        return;
    }
    if (pos > k_hpack_value_len_tp) {
        return;
    }
    bpf_clamp_umax(pos, k_hpack_value_len_tp);

    if (pos == k_tp_val_dash1 || pos == k_tp_val_dash2 || pos == k_tp_val_dash3) {
        state->valid_base &= c == '-';
        return;
    }

    u8 nibble = 0;
    if (!hpack_lower_hex_value(c, &nibble)) {
        state->valid_base = 0;
        return;
    }

    if (pos < k_tp_val_dash1) {
        if (pos == 0) {
            state->version = nibble << 4;
        } else {
            state->version |= nibble;
        }
        return;
    }

    if (pos > k_tp_val_dash1 && pos < k_tp_val_dash2) {
        u32 id_pos = pos - k_tp_val_trace_id_start;
        bpf_clamp_umax(id_pos, (TRACE_ID_SIZE_BYTES * 2) - 1);
        state->trace_nonzero |= nibble;
        hpack_store_nibble(tp->trace_id, id_pos, nibble);
        return;
    }

    if (pos > k_tp_val_dash2 && pos < k_tp_val_dash3) {
        u32 id_pos = pos - k_tp_val_span_id_start;
        bpf_clamp_umax(id_pos, (SPAN_ID_SIZE_BYTES * 2) - 1);
        state->span_nonzero |= nibble;
        if (parent_id) {
            hpack_store_span_nibble(tp->parent_id, id_pos, nibble);
        } else {
            hpack_store_span_nibble(tp->span_id, id_pos, nibble);
        }
        return;
    }

    if (pos >= k_tp_val_flags_start && pos < k_hpack_value_len_tp) {
        if (pos == k_tp_val_flags_start) {
            state->flags = nibble << 4;
        } else {
            state->flags |= nibble;
        }
    }
}

static __noinline u16 hpack_decode_huffman_byte(hpack_traceparent_decode_state_t *state,
                                                tp_info_t *tp,
                                                u8 parent_id,
                                                u8 byte,
                                                u8 huffman_state) {
#pragma unroll
    for (u8 bit = 0; bit < 8; bit++) {
        const u16 transition =
            k_hpack_huffman_transitions[((u16)huffman_state << 1) | ((byte >> (7 - bit)) & 1)];
        if (transition == 0xffff) {
            return 0;
        }
        if (transition & 0x8000) {
            hpack_traceparent_consume(state, tp, parent_id, transition & 0xff);
            huffman_state = 0;
        } else {
            huffman_state = transition & 0xff;
        }
    }

    return 0x100 | huffman_state;
}

static __always_inline void
hpack_traceparent_decoder_finish(hpack_traceparent_decoder_state_t *state, tp_info_t *tp) {
    if (state->done) {
        return;
    }

    if (state->huffman && state->huffman_state >= 8) {
        state->value.valid_base = 0;
    }

    state->valid =
        state->value.valid_base && state->value.value_len >= k_hpack_value_len_tp &&
        state->value.version != 0xff && state->value.trace_nonzero && state->value.span_nonzero &&
        ((state->value.version == 0 && state->value.value_len == k_hpack_value_len_tp) ||
         (state->value.version != 0 &&
          (state->value.value_len == k_hpack_value_len_tp ||
           (state->value.value_len > k_hpack_value_len_tp && state->value.extension_dash))));
    if (!state->valid) {
        __builtin_memset(tp->trace_id, 0, sizeof(tp->trace_id));
        if (state->parent_id) {
            __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
        } else {
            __builtin_memset(tp->span_id, 0, sizeof(tp->span_id));
        }
    } else {
        tp->flags = state->value.flags & (state->value.version == 0 ? k_flag_mask : k_flag_sampled);
    }
    state->done = 1;
}

static __always_inline void hpack_traceparent_decoder_init(hpack_traceparent_decoder_state_t *state,
                                                           u32 encoded_len,
                                                           u8 huffman,
                                                           u8 parent_id,
                                                           tp_info_t *tp) {
    __builtin_memset(state, 0, sizeof(*state));
    state->initialized = 1;
    if (encoded_len > k_hpack_tp_max_scan) {
        state->done = 1;
        return;
    }

    state->value.valid_base = 1;
    state->encoded_len = encoded_len;
    state->huffman = !!huffman;
    state->parent_id = !!parent_id;

    __builtin_memset(tp->trace_id, 0, sizeof(tp->trace_id));
    if (parent_id) {
        __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
    } else {
        __builtin_memset(tp->span_id, 0, sizeof(tp->span_id));
    }
}

static __noinline __attribute__((unused)) void hpack_traceparent_skip_huffman_suffix(
    const unsigned char *data, hpack_traceparent_decoder_state_t *state, tp_info_t *tp) {
    u32 pos = state->encoded_pos;
    const u32 encoded_len = state->encoded_len;
    if (encoded_len > k_hpack_tp_max_scan || pos > encoded_len ||
        state->value.value_len <= k_hpack_value_len_tp ||
        state->value.value_len > k_hpack_max_ephemeral_decoded_string) {
        state->value.valid_base = 0;
        hpack_traceparent_decoder_finish(state, tp);
        return;
    }

    // Once the future-version extension dash has been decoded, its remaining
    // characters are deliberately opaque to the W3C parser. Continue walking
    // the Huffman automaton so malformed coding or padding still fails, but
    // count emitted symbols without re-running the trace-ID state machine.
#pragma clang loop unroll(disable)
    for (u16 step = 0; step < k_hpack_tp_max_scan; step++) {
        if (pos >= encoded_len) {
            break;
        }
        u32 data_pos = pos;
        bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
        const u16 decoded = hpack_huffman_count_byte(data[data_pos], state->huffman_state);
        if (!(decoded & k_hpack_huffman_step_valid)) {
            state->value.valid_base = 0;
            hpack_traceparent_decoder_finish(state, tp);
            return;
        }
        state->huffman_state = decoded & 0xff;
        state->value.value_len +=
            (decoded >> k_hpack_huffman_step_count_shift) & k_hpack_huffman_step_count_mask;
        pos++;
        bpf_clamp_umax(pos, k_hpack_tp_max_scan);
        state->encoded_pos = pos;
    }

    if (pos != encoded_len || state->value.value_len > k_hpack_max_ephemeral_decoded_string) {
        state->value.valid_base = 0;
    }
    hpack_traceparent_decoder_finish(state, tp);
}

static __always_inline u8 hpack_traceparent_decoder_step(const unsigned char *data,
                                                         hpack_traceparent_decoder_state_t *state,
                                                         tp_info_t *tp) {
    if (!data || !state || !tp || !state->initialized || state->done) {
        return 1;
    }

    u32 pos = state->encoded_pos;
    const u32 encoded_len = state->encoded_len;
    // Reassert the initializer's bound after loading map-backed decoder state.
    // Without it, older verifiers can model encoded_len above the scan limit
    // while encoded_pos is clamped at that limit and explore a non-progress
    // loop. Corrupt state is invalid and must clear the partially decoded ID.
    if (encoded_len > k_hpack_tp_max_scan || pos > encoded_len ||
        state->value.value_len > k_hpack_max_ephemeral_decoded_string) {
        state->value.valid_base = 0;
        hpack_traceparent_decoder_finish(state, tp);
        return 1;
    }
    if (pos >= encoded_len) {
        hpack_traceparent_decoder_finish(state, tp);
        return 1;
    }

    u32 data_pos = pos;
    bpf_clamp_umax(data_pos, k_hpack_tp_max_scan - 1);
    const u8 byte = data[data_pos];
    pos++;
    bpf_clamp_umax(pos, k_hpack_tp_max_scan);
    state->encoded_pos = pos;

    if (state->huffman) {
        const u16 decoded = hpack_decode_huffman_byte(
            &state->value, tp, state->parent_id, byte, state->huffman_state);
        if (!(decoded & 0x100)) {
            state->value.valid_base = 0;
            hpack_traceparent_decoder_finish(state, tp);
            return 1;
        }
        state->huffman_state = decoded & 0xff;
    } else {
        hpack_traceparent_consume(&state->value, tp, state->parent_id, byte);
        // The W3C future-version grammar, and the validation above, only
        // require the first extension byte to be '-'. The current decoder
        // deliberately ignores the remaining extension bytes. For a raw
        // string their decoded length is the encoded length, so account for
        // that ignored suffix at once instead of carrying it through more
        // verifier-heavy validation passes.
        if (state->value.value_len > k_hpack_value_len_tp &&
            state->encoded_pos < state->encoded_len) {
            state->value.value_len = state->encoded_len;
            state->encoded_pos = state->encoded_len;
        }
    }

    if (state->encoded_pos == state->encoded_len) {
        hpack_traceparent_decoder_finish(state, tp);
    }
    return state->done;
}

static __always_inline hpack_traceparent_decode_result_t
hpack_traceparent_decoder_result(const hpack_traceparent_decoder_state_t *state) {
    hpack_traceparent_decode_result_t result = {
        .value_len = state->value.value_len,
        .valid = state->valid,
        .version = state->value.version,
    };
    return result;
}

static __always_inline hpack_traceparent_decode_result_t hpack_decode_traceparent_value(
    const unsigned char *data, u32 encoded_len, u8 huffman, tp_info_t *tp, u8 parent_id) {
    hpack_traceparent_decode_result_t result = {};
    if (!data || !tp || encoded_len > k_hpack_tp_max_scan) {
        return result;
    }

    hpack_traceparent_decoder_state_t state = {};
    hpack_traceparent_decoder_init(&state, encoded_len, huffman, parent_id, tp);
#pragma clang loop unroll(disable)
    for (u32 step = 0; step < k_hpack_tp_max_scan && !state.done; step++) {
        hpack_traceparent_decoder_step(data, &state, tp);
    }
    if (!state.done) {
        state.value.valid_base = 0;
        hpack_traceparent_decoder_finish(&state, tp);
    }
    return hpack_traceparent_decoder_result(&state);
}

static __always_inline hpack_traceparent_result_t hpack_find_traceparent(const unsigned char *data,
                                                                         u32 data_len,
                                                                         u8 complete) {
    hpack_traceparent_scan_state_t state = {};
    hpack_dynamic_name_state_t dynamic_names = {};
    hpack_dynamic_name_state_init(&dynamic_names);
    hpack_traceparent_scan_init(&state, data_len, complete);
    if (!data) {
        hpack_traceparent_scan_fail(&state);
    }

#pragma clang loop unroll(disable)
    for (u32 step = 0; step < k_hpack_tp_max_scan && !state.done; step++) {
        hpack_traceparent_scan_step(data, &state, &dynamic_names);
    }
    if (!state.done) {
        hpack_traceparent_scan_fail(&state);
    }
    return hpack_traceparent_scan_result(&state);
}

#undef OBI_HPACK_CACHE_HELPER

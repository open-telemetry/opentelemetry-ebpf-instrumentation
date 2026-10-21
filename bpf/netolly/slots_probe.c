// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Probe for kernels without d3bec0138bfb ("bpf: zero-fill re-used per-cpu map element", Linux
// 5.10), which keep the other CPUs' values of a reused per-CPU map element when a BPF program
// inserts it. User space fills and deletes every element of slots_probe, runs this program and
// checks the other CPUs' values of the entries it inserted (probeReusedSlotsStale in
// pkg/internal/netolly/ebpf).

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Not OBI_PIN_INTERNAL: the probe needs a map of its own, created fresh for each run, because it fills
// and empties it to check how the kernel reuses its elements, so it is loaded without
// convenience.ResolveMaps, which would share it by name.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u64);
} slots_probe SEC(".maps");

// Inserts the packet length as a new key, with 1 as this CPU's value.
SEC("socket")
int obi_slots_probe(struct __sk_buff *skb) {
    u32 key = skb->len;
    u64 value = 1;
    bpf_map_update_elem(&slots_probe, &key, &value, BPF_NOEXIST);
    return 0;
}

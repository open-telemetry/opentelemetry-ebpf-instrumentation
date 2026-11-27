# Network flow accounting

How the network flow programs (`bpf/netolly/`) count packets and bytes, and where the counts can
still be off.

## Design

Both sources, `tc` (`flows.c`) and `socket_filter` (`flows_sock.c`), add the packets they see to
one entry per flow in the `aggregated_flows` map. The map is a plain `BPF_MAP_TYPE_HASH` created
with `BPF_F_NO_PREALLOC`, shared by all CPUs, and sized by `CacheMaxFlows`. It is not an LRU map:
a full map sends the new flow through the `direct_flows` ring buffer instead of evicting flows
that user space has not read yet.

The shared code is in `flows_common.h`:

- `add_to_flow()` updates an existing entry in place. It never writes the entry back with
  `bpf_map_update_elem()`, which would resurrect an entry that user space just deleted.
- `insert_flow()` inserts a new flow with `BPF_NOEXIST`. If another CPU inserted the same flow
  first (`-EEXIST`), the packet is added to that entry with `add_to_flow()`, and the `collisions`
  counter of `flow_packet_stats` is incremented. Any other error sends the packet through the ring
  buffer.

User space reads the map with `lookupAndDeleteMap()` (batch or legacy reader), merging the entries
it reads with the ring buffer records.

## TC and socket filter

The verifier rejects a socket filter that uses a map whose value contains a `bpf_spin_lock`, even
if the program never takes the lock. So `flow_metrics` has a lock field that differs by program,
with the same size and offset in both (`FLOW_LOCK`, asserted in `flows_common.h`). `flow_lock.h`
provides both variants, and `flows_sock.c` selects the second by defining `FLOW_LOCK_PLACEHOLDER`
before including `flows_common.h`:

- The default is a real `struct bpf_spin_lock`. `add_to_flow()` takes it, and the `tc` reader
  copies entries with `BPF_F_LOCK`, so it gets a consistent snapshot of each entry.
- The placeholder is a 4-byte field with empty lock functions. The socket filter reader must not
  pass `BPF_F_LOCK`, which fails on a map without a lock.

`packets` and `bytes` are added atomically in both programs, so they are exact in the socket filter
too. The two fields that are updated with plain stores, `end_mono_time_ns` and `flags`, can lose an
update when two CPUs update them at the same instant in the socket filter: a TCP flag bit, or a
slightly older end time.

The atomic adds must compile to plain `XADD` instructions, which every supported kernel runs.
Building with `-mcpu=v3` makes clang emit fetch atomics, which need Linux 5.12. Generate the
objects with `make docker-generate`.

## Known limits

- **Read and delete.** A packet added to an entry after user space copied it and before the entry is
  deleted is not counted. The batch reader copies and deletes in one system call and loses a few
  packets per million. The legacy reader, used where batch operations are missing, looks up and
  deletes in two steps and loses more, about 0.01% in the concurrency test.
- **Memory reuse.** A program that looked up an entry can add its packet after user space deleted
  that entry and the kernel gave the memory to a new flow. The packet is then counted for the wrong
  flow. The memory stays valid, and it affects at most the packets that are in flight at the time of
  the delete.
- **Full map.** New flows that do not fit are sent through the ring buffer, and dropped, with
  `packet_stats->ignored` incremented, if the ring buffer is full too.

`TestConcurrentFlowCounts_SocketFilter` and `TestConcurrentFlowCounts_TC`
(`pkg/internal/netolly/ebpf`, privileged) send one flow from four CPUs while the map is read every
100 ms, and fail if packets are counted twice or the loss goes over a threshold.

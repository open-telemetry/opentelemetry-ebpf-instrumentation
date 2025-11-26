# BPF print format

This document explains a uniform standard for all BPF print debug statements across the project.

The goal is to ensure that our logs are not just data dumps, but more structured and useful.

## Table Of Contents

- [Formatting data](#formatting-data)
  - [Multiple variables (key-value pairs)](#multiple-variables-key-value-pairs)
  - [Single result or status](#single-result-or-status)
  - [Avoiding concatenation](#avoiding-concatenation)
- [Function name in log messages](#function-name-in-log-messages)
  - [Function name in eBPF probe](#function-name-in-ebpf-probe)
  - [Function name in generic functions](#function-name-in-generic-functions)
- [Compatibility and workarounds](#compatibility-and-workarounds)

### Formatting data

This section will cover the difference between using **`=`** and **`:`**.

#### Multiple variables (key-value pairs)

The equals sign **`=`** is best for creating clear key-value pairs, especially when logging multiple variables. Example:

```c
bpf_dbg_printk("%s: id=%d, size=%d", __FUNCTION__, id, msg->size);
```

Log output: `protocol_detector: id=12, size=33`.

#### Single result or status

The colon **`:`** is best for introducing a single, consequential piece of information that completes or explains the preceding human-readable sentence. Example:

```c
bpf_d_printk("%s: failed to push data: %d", __FUNCTION__, err);
```

Log output: `extend_and_write_tp: failed to push data: -1`.

#### Avoiding concatenation

Addressing issues like logging multiple variables without a separator (e.g., avoiding `%x%x`). Example:

```c
bpf_dbg_printk("%s: found HTTP info, resetting the span id to seq=%x, ack=%x", __FUNCTION__, tcp->seq, tcp->ack);
```

Log output: `update_outgoing_request_span_id: found HTTP info, resetting the span id to seq=5a3b9c1d, ack=0e2f`.

For logging the contents of a buffer like `msg->data`, it is best to use a key like `BUF=` followed by brackets **`[]`** around the string. Example:

```c
bpf_dbg_printk("%s: BUF=[%s]", __FUNCTION__, msg->data);
```

Log output: `obi_packet_extender_write_msg_tp: BUF=[Hello]`

### Function name in log messages

This section ensures every log message is contextualized.

We use **`__FUNCTION__`** which is a compile-time string literal (not a runtime function call) to print the function name.

#### Function name in eBPF probe

At the beginning of an eBPF probe (not every probe, as it can be too verbose\!), print the function name in the following way:

```c
bpf_dbg_printk("=== %s ===", __FUNCTION__);
```

Log output: `=== obi_kprobe_do_vfs_ioctl ===`.

Note that **`at the beginning`** does not mean as the first instruction, but you need to find the best place, like after some initial checks (example: after `if (!valid_pid(id)) {...}`).

The rest of the print statements in the eBPF probe function will be without **`===`** with the **`:`** after the eBPF probe function name. Example:

```c
bpf_d_printk("%s: tailcall failed", __FUNCTION__);
```

Log output: `obi_packet_extender: tailcall failed`.

#### Function name in generic functions

To print the function name in a generic function, use the **`__FUNCTION__`** identifier in **every log statement** without the bounding **`===`**. The triple equals signs are reserved exclusively for entry points of eBPF probes. Example:

```c
bpf_dbg_printk("%s: found IPv6 header", __FUNCTION__);
```

Log output: `encode_data_in_ip_options: found IPv6 header`.

**Special case**: there can be certain functions that are only called by an eBPF probe, and it can be useful to have both the eBPF probe function name and the function name of the current function. Example:

```c
bpf_dbg_printk("=== obi_packet_extender(%s) ===", __FUNCTION__);
```

Log output: `=== obi_packet_extender(create_trace_info) ===`.

In this case the rest of the print statements in the function will be without **`===`** with the **`:`** after the eBPF probe function name and current function name. Example:

```c
bpf_dbg_printk("obi_packet_extender(%s): generating tp info", __FUNCTION__);
```

Log output: `obi_packet_extender(create_trace_info): generating tp info`.

### Compatibility and workarounds

It can happen, sometimes, that the number of arguments to print is 3, but when `__FUNCTION__` is included, the total reaches 4. In these cases, `bpf_dbg_printk` calls `bpf_printk`, which subsequently calls `___bpf_pick_printk`. This chain then selects and calls `__bpf_vprintk` (for 4+ arguments), which finally invokes `bpf_trace_vprintk`. Since `bpf_trace_vprintk` is only available starting in [kernel version 5.16](https://docs.ebpf.io/linux/helper-function/bpf_trace_vprintk/), two options are available to avoid errors when loading the eBPF program:

1. Split the print into two separate calls: one with one argument and one with two arguments, where `__FUNCTION__` is added to both.
2. Hardcode the function name instead of using `__FUNCTION__`, so that the total number of arguments remains three.

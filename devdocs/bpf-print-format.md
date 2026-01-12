# BPF print format

This document explains a uniform standard for all BPF print debug statements across the project.

The goal is to ensure that our logs are not just data dumps, but more structured and useful.

## Table Of Contents

- [Print functions](#print-functions)
- [Formatting data](#formatting-data)
  - [Multiple variables (key-value pairs)](#multiple-variables-key-value-pairs)
  - [Single result or status](#single-result-or-status)
  - [Buffer](#buffer)
- [eBPF probe name](#ebpf-probe-name)
- [Generic function name](#generic-function-name)

### Print functions

There are two macros to print debug information:

- `bpf_dbg_printk`: calls `bpf_printk` and then uses [bpf_snprintf](https://docs.ebpf.io/linux/helper-function/bpf_snprintf/) to automatically print the name of the calling function. Finally use a ringbuf to send everything to userspace. Note: `bpf_snprintf` is available since **kernel version 5.13**.
- `bpf_d_printk`: calls `bpf_printk`.

The preferred version is `bpf_dbg_printk`, but there are also cases where `bpf_d_printk` is used. In the latter case, remember to use `__FUNCTION__` which is a compile-time string literal (not a runtime function call) to get the name of the current function.

### Formatting data

This section will cover the difference between using **`=`** and **`:`**.

#### Multiple variables (key-value pairs)

The equals sign **`=`** is best for creating clear key-value pairs, especially when logging multiple variables. Example:

```c
bpf_dbg_printk("id=%d, size=%d", id, msg->size);
```

Log output: `id=12, size=33 [protocol_detector]`.

#### Single result or status

The colon **`:`** is best for introducing a single, consequential piece of information that completes or explains the preceding human-readable sentence. Example:

```c
bpf_dbg_printk("failed to store option: %d", ret);
```

Log output: `failed to store option: -1 [bpf_sock_ops_write_hdr_cb]`.

#### Buffer

For logging the contents of a buffer like `msg->data`, it is best to use a key like `buf=` (or other name) followed by brackets **`[]`** around the string. Example:

```c
bpf_dbg_printk("buf=[%s]", msg->data);
```

Log output: `BUF=[Hello OBI!] [protocol_detector]`

### eBPF probe name

At the beginning of an eBPF probe (not every probe, as it can be too verbose\!) write the probe name between **`===`**:

```c
bpf_dbg_printk("=== sk_msg ===");
```

Log output: `=== sk_msg === [obi_packet_extender_write_msg_tp]`.

Notes:

- **`At the beginning`** does not mean as the first instruction, but you need to find the best place, like after some initial checks (example: after `if (!valid_pid(id)) {...}`).
- The triple equals signs are reserved exclusively for entry points of eBPF probes.

### Generic function name

The rest of the print statements in the eBPF probe function will be without **`===`** with the **`:`** after the eBPF probe function name. Example:

```c
bpf_dbg_printk("tcp event...");
```

Log output: `tcp event... [obi_protocol_tcp]`.

Note that the function name of an eBPF probe may differ slightly from the one written in the code. For example, `obi_kprobe_tcp_recvmsg` may appear as `____obi_kprobe_tcp_recvmsg`.

Same procedure is used in a generic function. Example:

```c
bpf_dbg_printk("setting up request to be extended");
```

Log output: `setting up request to be extended [protocol_detector]`.

As said before there are cases where it is ok to use `bpf_d_printk`, in those cases just do as follows:

```c
bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
```

Log output: `tailcall failed [write_http_traceparent]`.
